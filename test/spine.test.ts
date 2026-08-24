/**
 * Spine tests. These cover the three properties the whole society rests on:
 * canonicalization is stable, signatures verify, and the chain cannot fork or
 * be written around.
 *
 * If a change breaks a test in this file, the change is wrong — every published
 * checkpoint depends on these exact behaviours.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import { canonicalize, signingString, SIGNING_PREFIX } from '../src/core/canonical';
import {
  b64uDecode,
  b64uEncode,
  citizenIdFromPubkey,
  hexDecode,
  hexEncode,
  isValidPubkey,
  newId,
  sha256Hex,
  verifySig,
} from '../src/core/crypto';
import {
  GENESIS_PREV_HASH,
  appendEvent,
  computeEventHash,
  eventHashInput,
  readHead,
  utcDay,
  ChainConflictError,
  GuardFailedError,
} from '../src/core/events';
import { HEADERS, nonceGuard, verifyRequest, AuthError } from '../src/core/auth';
import { notFrozenGuard } from '../src/services/quotas';
import { bookLegs } from '../src/services/ledger';
import { GENESIS_POLICY, EVENT_TYPES, ACCOUNTS } from '../src/core/constitution';
import { formatUsdc, parseUsdcToMicro } from '../src/core/db';

const db = env.DB as D1Database;

// A fixed keypair so the expected signatures below never drift.
async function makeKeypair() {
  const kp = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  // exportKey is typed to return JsonWebKey for the 'jwk' format; 'raw' always
  // yields bytes.
  const rawPub = new Uint8Array(
    (await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer,
  );
  return { kp, pubkey: b64uEncode(rawPub) };
}

async function signWith(kp: CryptoKeyPair, message: string): Promise<string> {
  const sig = await crypto.subtle.sign(
    'Ed25519',
    kp.privateKey,
    new TextEncoder().encode(message),
  );
  return b64uEncode(new Uint8Array(sig));
}

async function resetDb() {
  // Tables that the spine touches. Order matters for foreign keys.
  for (const t of ['nonces', 'events', 'chain_head', 'quota_usage']) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
    .bind(GENESIS_PREV_HASH)
    .run();
}

beforeEach(async () => {
  await resetDb();
});

// ------------------------------------------------------------ canonicalization

describe('canonicalize', () => {
  it('sorts keys and ignores input order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ a: 2, b: 1 })).toBe(canonicalize({ b: 1, a: 2 }));
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('drops undefined but keeps null', () => {
    expect(canonicalize({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it('refuses floats, because no two languages agree on their decimal form', () => {
    expect(() => canonicalize({ a: 1.5 })).toThrow(/non-integer/);
  });

  it('refuses non-finite and unsafe integers', () => {
    expect(() => canonicalize({ a: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalize({ a: Number.MAX_SAFE_INTEGER + 2 })).toThrow(
      /unsafe/,
    );
  });

  it('escapes strings as JSON does', () => {
    expect(canonicalize({ a: 'x"y\n' })).toBe('{"a":"x\\"y\\n"}');
  });

  it('handles nesting deterministically', () => {
    const a = canonicalize({ z: [{ b: 1, a: 2 }], y: 'k' });
    const b = canonicalize({ y: 'k', z: [{ a: 2, b: 1 }] });
    expect(a).toBe(b);
  });

  it('distinguishes payloads that differ only in key placement of equal values', () => {
    expect(canonicalize({ a: 1, b: 2 })).not.toBe(canonicalize({ a: 2, b: 1 }));
  });
});

describe('signingString', () => {
  it('is the documented line-based format', () => {
    const s = signingString({
      method: 'post',
      path: '/api/posts',
      bodyHash: 'abc',
      ts: 1700000000,
      nonce: 'n1',
    });
    expect(s).toBe(`${SIGNING_PREFIX}\nPOST\n/api/posts\nabc\n1700000000\nn1`);
  });

  it('binds the path, so a signature cannot be replayed on another endpoint', () => {
    const base = { bodyHash: 'h', ts: 1, nonce: 'n' };
    expect(signingString({ ...base, method: 'POST', path: '/api/posts' })).not.toBe(
      signingString({ ...base, method: 'POST', path: '/api/votes' }),
    );
  });
});

// -------------------------------------------------------------------- crypto

describe('crypto primitives', () => {
  it('round-trips base64url without padding', () => {
    const bytes = new Uint8Array([0, 1, 250, 255, 128]);
    const enc = b64uEncode(bytes);
    expect(enc).not.toMatch(/[+/=]/);
    expect([...b64uDecode(enc)]).toEqual([...bytes]);
  });

  it('round-trips hex', () => {
    const bytes = new Uint8Array([0, 15, 16, 255]);
    expect(hexEncode(bytes)).toBe('000f10ff');
    expect([...hexDecode('0x000f10ff')]).toEqual([...bytes]);
  });

  it('derives a citizen id that cannot be chosen', async () => {
    const { pubkey } = await makeKeypair();
    const id = await citizenIdFromPubkey(pubkey);
    expect(id).toMatch(/^ct_[0-9a-f]{32}$/);
    // Deterministic: same key, same citizen, forever.
    expect(await citizenIdFromPubkey(pubkey)).toBe(id);
  });

  it('rejects malformed pubkeys', () => {
    expect(isValidPubkey('short')).toBe(false);
    expect(isValidPubkey(b64uEncode(new Uint8Array(31)))).toBe(false);
    expect(isValidPubkey(b64uEncode(new Uint8Array(32)))).toBe(true);
  });

  it('verifies a real signature and rejects tampering', async () => {
    const { kp, pubkey } = await makeKeypair();
    const msg = 'KEYHOLD1\nPOST\n/api/posts\ndeadbeef\n1700000000\nnonce123';
    const sig = await signWith(kp, msg);

    expect(await verifySig(pubkey, sig, msg)).toBe(true);
    expect(await verifySig(pubkey, sig, msg + 'x')).toBe(false);

    const other = await makeKeypair();
    expect(await verifySig(other.pubkey, sig, msg)).toBe(false);
  });

  it('rejects a signature of the wrong length rather than throwing', async () => {
    const { pubkey } = await makeKeypair();
    expect(await verifySig(pubkey, b64uEncode(new Uint8Array(10)), 'm')).toBe(false);
    expect(await verifySig(pubkey, 'not!base64!!', 'm')).toBe(false);
  });

  it('newId is prefixed and unique', () => {
    const a = newId('po');
    const b = newId('po');
    expect(a).toMatch(/^po_[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});

// --------------------------------------------------------------- money math

describe('micro-USDC handling', () => {
  it('formats and parses without float drift', () => {
    expect(formatUsdc(2_000_000)).toBe('2');
    expect(formatUsdc(2_000_001)).toBe('2.000001');
    expect(formatUsdc(-1_500_000)).toBe('-1.5');
    expect(parseUsdcToMicro('2.000001')).toBe(2_000_001);
    expect(parseUsdcToMicro('0.5')).toBe(500_000);
  });

  it('round-trips fingerprint amounts exactly', () => {
    for (const nonce of [1, 37, 999]) {
      const micro = GENESIS_POLICY['citizenship.bond_amount'] + nonce;
      expect(parseUsdcToMicro(formatUsdc(micro))).toBe(micro);
    }
  });

  it('refuses amounts it cannot represent exactly', () => {
    expect(() => parseUsdcToMicro('1.0000001')).toThrow();
    expect(() => parseUsdcToMicro('abc')).toThrow();
  });
});

// ---------------------------------------------------------------- the chain

describe('event chain', () => {
  it('starts empty at the all-zeros previous hash', async () => {
    const head = await readHead(db);
    expect(head).toEqual({ seq: 0, hash: GENESIS_PREV_HASH });
  });

  it('hash input is prev_hash + newline + canonical body', () => {
    const input = eventHashInput({
      seq: 1,
      ts: 5,
      type: 'genesis',
      actor: null,
      payload: { b: 1, a: 2 },
      prevHash: GENESIS_PREV_HASH,
    });
    expect(input).toBe(
      GENESIS_PREV_HASH +
        '\n{"actor":null,"payload":{"a":2,"b":1},"seq":1,"ts":5,"type":"genesis"}',
    );
  });

  it('appends and links events', async () => {
    const first = await appendEvent(db, {
      type: 'genesis',
      actor: null,
      payload: { instance: 'test' },
    });
    expect(first.seq).toBe(1);

    const second = await appendEvent(db, {
      type: 'post.created',
      actor: 'ct_x',
      payload: { id: 'po_1' },
    });
    expect(second.seq).toBe(2);

    const rows = await db
      .prepare('SELECT seq, prev_hash, hash FROM events ORDER BY seq')
      .all<{ seq: number; prev_hash: string; hash: string }>();
    const chain = rows.results;
    expect(chain).toHaveLength(2);
    const [e1, e2] = chain as [
      { seq: number; prev_hash: string; hash: string },
      { seq: number; prev_hash: string; hash: string },
    ];
    expect(e1.prev_hash).toBe(GENESIS_PREV_HASH);
    expect(e2.prev_hash).toBe(e1.hash);

    const head = await readHead(db);
    expect(head).toEqual({ seq: 2, hash: e2.hash });
  });

  it('produces the hash an independent verifier would recompute', async () => {
    const r = await appendEvent(db, {
      type: 'post.created',
      actor: 'ct_a',
      payload: { id: 'po_1', body_hash: 'ff' },
      ts: 1700000000,
    });
    const expected = await computeEventHash({
      seq: 1,
      ts: 1700000000,
      type: 'post.created',
      actor: 'ct_a',
      payload: { id: 'po_1', body_hash: 'ff' },
      prevHash: GENESIS_PREV_HASH,
    });
    expect(r.hash).toBe(expected);

    const stored = await db
      .prepare('SELECT hash, payload FROM events WHERE seq = 1')
      .first<{ hash: string; payload: string }>();
    expect(stored?.hash).toBe(expected);
    // The stored payload must be the canonical form, or the verifier diverges.
    expect(stored?.payload).toBe('{"body_hash":"ff","id":"po_1"}');
  });

  it('commits domain writes atomically with the event', async () => {
    await appendEvent(db, {
      type: 'quota.denied',
      actor: 'ct_a',
      payload: { action: 'post' },
      writes: [
        db
          .prepare(
            'INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,?)',
          )
          .bind('ct_a', utcDay(), 'post', 1),
      ],
    });
    const row = await db
      .prepare('SELECT used FROM quota_usage WHERE citizen_id = ?')
      .bind('ct_a')
      .first<{ used: number }>();
    expect(row?.used).toBe(1);
  });

  it('rejects the whole append when a guard refuses', async () => {
    const limit = 1;
    const day = utcDay();
    const spend = () =>
      appendEvent(db, {
        type: 'post.created',
        actor: 'ct_a',
        payload: { id: newId('po') },
        guards: [
          db
            .prepare(
              `INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,1)
               ON CONFLICT (citizen_id, day, action)
               DO UPDATE SET used = used + 1 WHERE quota_usage.used < ?`,
            )
            .bind('ct_a', day, 'post', limit),
        ],
      });

    await spend();
    await expect(spend()).rejects.toThrow(GuardFailedError);

    // The refused attempt left nothing behind: still one event, quota still 1.
    const count = await db
      .prepare('SELECT COUNT(*) AS n FROM events')
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
    const used = await db
      .prepare('SELECT used FROM quota_usage WHERE citizen_id = ?')
      .bind('ct_a')
      .first<{ used: number }>();
    expect(used?.used).toBe(1);
  });

  it('cannot be written around: a stale head is refused', async () => {
    await appendEvent(db, { type: 'genesis', actor: null, payload: {} });

    // Simulate a racing writer by moving the head after a read.
    const stale = await readHead(db);
    await appendEvent(db, {
      type: 'post.created',
      actor: 'ct_b',
      payload: { id: 'po_2' },
    });

    // An append built on the stale head must fail rather than fork the chain.
    const hash = await computeEventHash({
      seq: stale.seq + 1,
      ts: 1,
      type: 'post.created',
      actor: 'ct_c',
      payload: {},
      prevHash: stale.hash,
    });
    const result = await db
      .prepare(
        'UPDATE chain_head SET seq = ?, hash = ? WHERE id = 1 AND seq = ? AND hash = ?',
      )
      .bind(stale.seq + 1, hash, stale.seq, stale.hash)
      .run();
    expect(result.meta.changes).toBe(0);
  });

  it('refuses a duplicate hash', async () => {
    await appendEvent(db, { type: 'genesis', actor: null, payload: {} });
    const head = await readHead(db);
    await expect(
      db
        .prepare(
          'INSERT INTO events (seq, ts, type, actor, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?)',
        )
        .bind(99, 1, 'genesis', null, '{}', GENESIS_PREV_HASH, head.hash)
        .run(),
    ).rejects.toThrow();
  });

  it('utcDay is a UTC calendar date', () => {
    expect(utcDay(0)).toBe('1970-01-01');
    expect(utcDay(1700000000)).toBe('2023-11-14');
  });

  // The refusal has to name which limit stopped it, or every quota denial
  // becomes an indistinguishable 409 and the caller cannot tell "you are
  // frozen" from "you are out of posts for today".
  it('reports the index of the first guard that refused', async () => {
    const day = utcDay();
    const passes = () =>
      db.prepare("UPDATE chain_head SET seq = seq WHERE id = 1");
    const refuses = () =>
      db
        .prepare(
          `INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,1)
           ON CONFLICT (citizen_id, day, action)
           DO UPDATE SET used = used + 1 WHERE quota_usage.used < 0`,
        )
        .bind('ct_idx', day, 'post');

    // Spend it once so the conditional upsert refuses from here on.
    await db
      .prepare(
        'INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,1)',
      )
      .bind('ct_idx', day, 'post')
      .run();

    const attempt = (guards: D1PreparedStatement[]) =>
      appendEvent(db, {
        type: 'post.created',
        actor: 'ct_idx',
        payload: { id: newId('po') },
        guards,
      });

    await expect(attempt([refuses(), passes()])).rejects.toMatchObject({ index: 0 });
    await expect(attempt([passes(), refuses()])).rejects.toMatchObject({ index: 1 });
    await expect(
      attempt([passes(), passes(), refuses()]),
    ).rejects.toMatchObject({ index: 2 });

    // Every one of those was refused, so the chain never moved and the probe
    // that identified the guard left nothing behind either.
    const n = await db.prepare('SELECT COUNT(*) AS n FROM events').first<{ n: number }>();
    expect(n?.n).toBe(0);
    const used = await db
      .prepare('SELECT used FROM quota_usage WHERE citizen_id = ?')
      .bind('ct_idx')
      .first<{ used: number }>();
    expect(used?.used).toBe(1);
    const head = await readHead(db);
    expect(head.seq).toBe(0);
  });
});

// ------------------------------------------------------------------- auth

describe('request verification', () => {
  const path = '/api/posts';

  // The door's two limits are governed parameters, so verifyRequest takes them
  // as arguments instead of reading GENESIS_POLICY itself. Handlers pass what
  // the policy table currently says; these tests pass the genesis values,
  // except where the point of the test is that a different number binds.
  const DOOR = {
    maxSkewSeconds: GENESIS_POLICY['request.max_skew_seconds'],
    maxBodyBytes: GENESIS_POLICY['request.max_body_bytes'],
  };

  async function signedHeaders(
    kp: CryptoKeyPair,
    pubkey: string,
    body: Uint8Array,
    over: { method?: string; path?: string; ts?: number; nonce?: string } = {},
  ) {
    const citizenId = await citizenIdFromPubkey(pubkey);
    const ts = over.ts ?? Math.floor(Date.now() / 1000);
    const nonce = over.nonce ?? newId('n');
    const bodyHash = body.byteLength ? await sha256Hex(body) : await sha256Hex('');
    const sig = await signWith(
      kp,
      signingString({
        method: over.method ?? 'POST',
        path: over.path ?? path,
        bodyHash,
        ts,
        nonce,
      }),
    );
    const h = new Headers();
    h.set(HEADERS.citizen, citizenId);
    h.set(HEADERS.ts, String(ts));
    h.set(HEADERS.nonce, nonce);
    h.set(HEADERS.sig, sig);
    return { h, citizenId, ts, nonce };
  }

  it('accepts a correctly signed request when the key is on file', async () => {
    const { kp, pubkey } = await makeKeypair();
    const body = new TextEncoder().encode('{"body":"hello"}');
    const { h, citizenId } = await signedHeaders(kp, pubkey, body);

    const signed = await verifyRequest(h, body, {
      ...DOOR,
      method: 'POST',
      path,
      lookupPubkey: async (id) => (id === citizenId ? pubkey : null),
    });
    expect(signed.citizenId).toBe(citizenId);
  });

  it('accepts registration where the key travels with the request', async () => {
    const { kp, pubkey } = await makeKeypair();
    const body = new TextEncoder().encode('{"display_name":"a"}');
    const { h } = await signedHeaders(kp, pubkey, body, { path: '/api/register' });
    h.set(HEADERS.pubkey, pubkey);

    const signed = await verifyRequest(h, body, {
      ...DOOR,
      method: 'POST',
      path: '/api/register',
    });
    expect(signed.pubkey).toBe(pubkey);
  });

  it('refuses a pubkey that does not derive the claimed citizen id', async () => {
    const a = await makeKeypair();
    const b = await makeKeypair();
    const body = new Uint8Array();
    const { h } = await signedHeaders(a.kp, a.pubkey, body, {
      path: '/api/register',
    });
    h.set(HEADERS.pubkey, b.pubkey); // mismatched key

    await expect(
      verifyRequest(h, body, { ...DOOR, method: 'POST', path: '/api/register' }),
    ).rejects.toMatchObject({ reason: 'id_mismatch' });
  });

  it('refuses a signature made over a different path', async () => {
    const { kp, pubkey } = await makeKeypair();
    const body = new Uint8Array();
    const { h, citizenId } = await signedHeaders(kp, pubkey, body, {
      path: '/api/votes',
    });

    await expect(
      verifyRequest(h, body, {
        ...DOOR,
        method: 'POST',
        path: '/api/posts',
        lookupPubkey: async () => pubkey,
      }),
    ).rejects.toMatchObject({ reason: 'bad_signature' });
    expect(citizenId).toMatch(/^ct_/);
  });

  it('refuses a signature made over a different body', async () => {
    const { kp, pubkey } = await makeKeypair();
    const signedBody = new TextEncoder().encode('{"body":"original"}');
    const { h } = await signedHeaders(kp, pubkey, signedBody);

    const tampered = new TextEncoder().encode('{"body":"swapped"}');
    await expect(
      verifyRequest(h, tampered, {
        ...DOOR,
        method: 'POST',
        path,
        lookupPubkey: async () => pubkey,
      }),
    ).rejects.toMatchObject({ reason: 'bad_signature' });
  });

  it('refuses stale and future timestamps', async () => {
    const { kp, pubkey } = await makeKeypair();
    const body = new Uint8Array();
    const skew = GENESIS_POLICY['request.max_skew_seconds'];
    const now = Math.floor(Date.now() / 1000);

    for (const ts of [now - skew - 5, now + skew + 5]) {
      const { h } = await signedHeaders(kp, pubkey, body, { ts });
      await expect(
        verifyRequest(h, body, {
          ...DOOR,
          method: 'POST',
          path,
          lookupPubkey: async () => pubkey,
          now,
        }),
      ).rejects.toMatchObject({ reason: 'clock_skew' });
    }
  });

  it('refuses an unknown citizen', async () => {
    const { kp, pubkey } = await makeKeypair();
    const body = new Uint8Array();
    const { h } = await signedHeaders(kp, pubkey, body);
    await expect(
      verifyRequest(h, body, {
        ...DOOR,
        method: 'POST',
        path,
        lookupPubkey: async () => null,
      }),
    ).rejects.toMatchObject({ reason: 'unknown_citizen' });
  });

  it('refuses missing headers rather than defaulting to anonymous', async () => {
    await expect(
      verifyRequest(new Headers(), new Uint8Array(), { ...DOOR, method: 'POST', path }),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it('refuses a body over the size cap', async () => {
    const { kp, pubkey } = await makeKeypair();
    const big = new Uint8Array(GENESIS_POLICY['request.max_body_bytes'] + 1);
    const { h } = await signedHeaders(kp, pubkey, big);
    await expect(
      verifyRequest(h, big, {
        ...DOOR,
        method: 'POST',
        path,
        lookupPubkey: async () => pubkey,
      }),
    ).rejects.toMatchObject({ reason: 'body_too_large' });
  });

  it('replay is stopped by the nonce guard inside the batch, not by a pre-check', async () => {
    const citizen = 'ct_replay';
    const nonce = 'nonce-used-once';
    const ts = Math.floor(Date.now() / 1000);

    const append = () =>
      appendEvent(db, {
        type: 'post.created',
        actor: citizen,
        payload: { id: newId('po') },
        guards: [nonceGuard(db, citizen, nonce, ts)],
      });

    await append();
    await expect(append()).rejects.toThrow(GuardFailedError);

    const n = await db
      .prepare('SELECT COUNT(*) AS n FROM events')
      .first<{ n: number }>();
    expect(n?.n).toBe(1);
  });
});

// ------------------------------------------------------------- constitution

describe('constitution invariants', () => {
  it('the surplus split sums to 100 percent', () => {
    const sum =
      GENESIS_POLICY['treasury.split_compute_pct'] +
      GENESIS_POLICY['treasury.split_operator_pct'] +
      GENESIS_POLICY['treasury.split_reserve_pct'];
    expect(sum).toBe(100);
  });

  it('a substantial share of surplus is reinvested in compute', () => {
    expect(GENESIS_POLICY['treasury.split_compute_pct']).toBeGreaterThanOrEqual(50);
  });

  it('amendments need a higher bar than parameters', () => {
    expect(GENESIS_POLICY['gov.amendment_pct']).toBeGreaterThan(
      GENESIS_POLICY['gov.pass_pct'],
    );
    expect(GENESIS_POLICY['gov.amendment_timelock_hours']).toBeGreaterThan(
      GENESIS_POLICY['gov.timelock_hours'],
    );
  });

  it('quotas are small enough to force choices', () => {
    expect(GENESIS_POLICY['quota.post']).toBeLessThanOrEqual(10);
    expect(GENESIS_POLICY['probation.quota_factor_pct']).toBeLessThan(100);
  });

  it('event types are unique', () => {
    expect(new Set(EVENT_TYPES).size).toBe(EVENT_TYPES.length);
  });

  it('ledger account names are unique', () => {
    const values = Object.values(ACCOUNTS);
    expect(new Set(values).size).toBe(values.length);
  });

  it('the fingerprint nonce space is large enough to be collision-free in practice', () => {
    expect(GENESIS_POLICY['payment.nonce_max_units']).toBeGreaterThanOrEqual(999);
  });
});

// ---------------------------------------------------- the governed door

/**
 * `request.max_skew_seconds` and `request.max_body_bytes` are governed
 * parameters, so the door has to read them from the policy table at the call
 * site rather than from GENESIS_POLICY. These check that the numbers passed in
 * are the numbers that bind — a proposal tightening either one has to change
 * behaviour, not just the value shown by /api/policy.
 */
describe('the door obeys the values it is given, not the genesis constants', () => {
  const path = '/api/posts';

  async function signed(over: { ts?: number; bytes?: number } = {}) {
    const { kp, pubkey } = await makeKeypair();
    const body = new Uint8Array(over.bytes ?? 0);
    const ts = over.ts ?? Math.floor(Date.now() / 1000);
    const nonce = newId('n');
    const bodyHash = await sha256Hex(body.byteLength ? body : '');
    const sig = await signWith(
      kp,
      signingString({ method: 'POST', path, bodyHash, ts, nonce }),
    );
    const h = new Headers();
    h.set(HEADERS.citizen, await citizenIdFromPubkey(pubkey));
    h.set(HEADERS.ts, String(ts));
    h.set(HEADERS.nonce, nonce);
    h.set(HEADERS.sig, sig);
    return { h, body, pubkey };
  }

  it('refuses a timestamp a tightened skew forbids but genesis would allow', async () => {
    const now = Math.floor(Date.now() / 1000);
    const drift = 30;
    expect(drift).toBeLessThan(GENESIS_POLICY['request.max_skew_seconds']);
    const { h, body, pubkey } = await signed({ ts: now - drift });

    await expect(
      verifyRequest(h, body, {
        method: 'POST',
        path,
        maxSkewSeconds: 5,
        maxBodyBytes: GENESIS_POLICY['request.max_body_bytes'],
        lookupPubkey: async () => pubkey,
        now,
      }),
    ).rejects.toMatchObject({ reason: 'clock_skew' });
  });

  it('accepts a timestamp a widened skew allows but genesis would refuse', async () => {
    const now = Math.floor(Date.now() / 1000);
    const drift = GENESIS_POLICY['request.max_skew_seconds'] + 60;
    const { h, body, pubkey } = await signed({ ts: now - drift });

    const ok = await verifyRequest(h, body, {
      method: 'POST',
      path,
      maxSkewSeconds: drift + 60,
      maxBodyBytes: GENESIS_POLICY['request.max_body_bytes'],
      lookupPubkey: async () => pubkey,
      now,
    });
    expect(ok.ts).toBe(now - drift);
  });

  it('refuses a body a tightened cap forbids but genesis would allow', async () => {
    const { h, body, pubkey } = await signed({ bytes: 1024 });
    expect(body.byteLength).toBeLessThan(GENESIS_POLICY['request.max_body_bytes']);

    await expect(
      verifyRequest(h, body, {
        method: 'POST',
        path,
        maxSkewSeconds: GENESIS_POLICY['request.max_skew_seconds'],
        maxBodyBytes: 512,
        lookupPubkey: async () => pubkey,
      }),
    ).rejects.toMatchObject({ reason: 'body_too_large' });
  });
});

// ------------------------------------------------------------ the freeze

/**
 * A freeze is `frozen_until`, and only `frozen_until`. Nothing writes
 * status = 'frozen' any more, because a freeze expressed as a status is a
 * freeze nothing ever lifts — which is how a 72-hour cap became permanent.
 */
describe('notFrozenGuard', () => {
  const ids = ['ct_free', 'ct_frozen', 'ct_thawed', 'ct_gone', 'ct_status_frozen'];

  async function seed(id: string, status: string, frozenUntil: number | null) {
    await db
      .prepare(
        `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks,
                               frozen_until, created_at, event_seq)
         VALUES (?, ?, ?, ?, 'vouched', 0, ?, 0, 1)`,
      )
      .bind(id, `pk_${id}`, id, status, frozenUntil)
      .run();
  }

  const now = 1_800_000_000;

  beforeEach(async () => {
    for (const id of ids) {
      await db.prepare('DELETE FROM citizens WHERE id = ?').bind(id).run();
    }
    await seed('ct_free', 'active', null);
    await seed('ct_frozen', 'active', now + 3600);
    await seed('ct_thawed', 'active', now - 1);
    await seed('ct_gone', 'departed', null);
    await seed('ct_status_frozen', 'frozen', null);
  });

  async function passes(id: string): Promise<boolean> {
    const r = await notFrozenGuard(db, id, now).run();
    return (r.meta?.changes ?? 0) >= 1;
  }

  it('passes a citizen with no freeze', async () => {
    expect(await passes('ct_free')).toBe(true);
  });

  it('refuses while the deadline is in the future', async () => {
    expect(await passes('ct_frozen')).toBe(false);
  });

  it('passes the moment the deadline has run, with no cron in the path', async () => {
    expect(await passes('ct_thawed')).toBe(true);
  });

  it('refuses a departed key', async () => {
    expect(await passes('ct_gone')).toBe(false);
  });

  it('fails closed on a status nothing writes any more', async () => {
    // No route sets status = 'frozen'; a row that carries it is either a
    // migration artefact or a bug, and either way it is not a citizen in good
    // standing. It must not write, and — the original defect — it must not be
    // rescued by a special case that also made every freeze permanent.
    expect(await passes('ct_status_frozen')).toBe(false);
  });
});

// -------------------------------------------------------------- the books

/**
 * A ledger row is only as checkable as the event that named it. `bookLegs`
 * returns the row and the payload record together, sharing one id, which is
 * what lets scripts/verify.mjs match them one to one instead of only comparing
 * totals. A leg written any other way is a book entry with no cause.
 */
describe('bookLegs', () => {
  beforeEach(async () => {
    await db.prepare('DELETE FROM ledger_entries').run();
  });

  it('writes exactly the row its payload record describes', async () => {
    const book = bookLegs(db, [
      {
        ts: 1_800_000_000,
        debit: ACCOUNTS.ESCROW,
        credit: ACCOUNTS.OBLIGATIONS,
        amount: 1_800_000,
        memo: 'bounty accepted',
        refType: 'bounty',
        refId: 'bo_x',
      },
    ]);

    await appendEvent(db, {
      type: 'bounty.accepted',
      actor: null,
      payload: { bounty_id: 'bo_x', legs: book.legs },
      writes: book.writes,
    });

    const leg = book.legs[0]!;
    const row = await db
      .prepare(
        'SELECT id, ts, debit, credit, amount, memo, ref_type, ref_id, event_seq FROM ledger_entries WHERE id = ?',
      )
      .bind(leg.id)
      .first<Record<string, unknown>>();

    expect(row).toBeTruthy();
    for (const f of ['ts', 'debit', 'credit', 'amount', 'memo', 'ref_type', 'ref_id'] as const) {
      expect(row?.[f]).toBe(leg[f]);
    }
    // The row cites the event that booked it, not the one before it.
    expect(row?.['event_seq']).toBe((await readHead(db)).seq);
  });

  it('refuses a leg that would put a wrong number in the books', () => {
    const bad = { ts: 1, debit: ACCOUNTS.ESCROW, credit: ACCOUNTS.TREASURY };
    expect(() => bookLegs(db, [{ ...bad, amount: 0 }])).toThrow(/positive integer/);
    expect(() => bookLegs(db, [{ ...bad, amount: -5 }])).toThrow(/positive integer/);
    expect(() =>
      bookLegs(db, [{ ts: 1, debit: ACCOUNTS.ESCROW, credit: ACCOUNTS.ESCROW, amount: 1 }]),
    ).toThrow(/same account/);
  });
});
