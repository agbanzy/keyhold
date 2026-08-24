/**
 * The operator's bulk invite mint.
 *
 * This is the one place the operator may do at scale what a citizen may only do
 * twice a month, so the interesting assertions are the limits, not the happy
 * path: the lifetime ceiling holds under a second call, the codes are marked as
 * operator-issued (issuer_id NULL) so nobody can later describe the founding
 * cohort as organic, and the mint spends the operator's own invite quota
 * through the same guard a citizen spends it through.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import { b64uEncode, citizenIdFromPubkey } from '../src/core/crypto';
import { GENESIS_PREV_HASH, nowSeconds } from '../src/core/events';
import { HEADERS } from '../src/core/auth';
import { signingString } from '../src/core/canonical';

const db = env.DB as D1Database;
const BASE = 'https://keyhold.test';

let operator: { kp: CryptoKeyPair; id: string; pubkey: string };

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function signedFetch(method: 'GET' | 'POST', path: string, body?: unknown) {
  const raw = new TextEncoder().encode(body === undefined ? '' : JSON.stringify(body));
  const ts = nowSeconds();
  const nonce = `n-${crypto.randomUUID()}`;
  const message = signingString({
    method,
    path,
    bodyHash: await sha256Hex(raw),
    ts,
    nonce,
  });
  const sig = b64uEncode(
    new Uint8Array(
      await crypto.subtle.sign('Ed25519', operator.kp.privateKey, new TextEncoder().encode(message)),
    ),
  );
  return SELF.fetch(`${BASE}${path}`, {
    method,
    ...(method === 'POST' ? { body: raw } : {}),
    headers: {
      'content-type': 'application/json',
      [HEADERS.citizen]: operator.id,
      [HEADERS.ts]: String(ts),
      [HEADERS.nonce]: nonce,
      [HEADERS.sig]: sig,
      // scripts/kh.mjs sends this on every call, and it is what lets a key that
      // holds no citizenship authenticate at all: with no citizen row there is
      // no stored public key for the server to look up.
      [HEADERS.pubkey]: operator.pubkey,
    },
  });
}

beforeEach(async () => {
  for (const t of ['invites', 'quota_usage', 'nonces', 'citizens', 'events', 'chain_head']) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
    .bind(GENESIS_PREV_HASH)
    .run();

  const kp = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
  const pubkey = b64uEncode(
    new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer),
  );
  const id = await citizenIdFromPubkey(pubkey);
  operator = { kp, id, pubkey };
  env.OPERATOR_PUBKEY = pubkey;

  // Out of probation, so the mint is not fighting a halved invite allowance.
  await db
    .prepare(
      `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
       VALUES (?, ?, 'Warden', 'active', 'vouched', 0, ?, 1)`,
    )
    .bind(id, pubkey, nowSeconds() - 90 * 86400)
    .run();
});

describe('founding invites', () => {
  it('mints codes that are operator-issued, on the chain, and listed back', async () => {
    const res = await signedFetch('POST', '/admin/invites', { count: 3, note: 'founding cohort' });
    expect(res.status).toBe(201);
    const minted = (await res.json()) as {
      codes: string[];
      minted_total: number;
      remaining: number;
      lifetime_cap: number;
      event: { seq: number };
    };
    expect(minted.codes).toHaveLength(3);
    expect(minted.minted_total).toBe(3);
    expect(minted.remaining).toBe(minted.lifetime_cap - 3);

    // One event for three codes, and it carries every code it minted.
    const event = await db
      .prepare('SELECT type, payload FROM events WHERE seq = ?')
      .bind(minted.event.seq)
      .first<{ type: string; payload: string }>();
    expect(event?.type).toBe('invite.issued');
    const payload = JSON.parse(event!.payload) as { codes: string[]; issuer: null; founding: boolean };
    expect(payload.codes).toEqual(minted.codes);
    expect(payload.issuer).toBeNull();
    expect(payload.founding).toBe(true);

    // issuer_id NULL is the schema's own marker for "no citizen vouched".
    const rows = await db
      .prepare('SELECT code FROM invites WHERE issuer_id IS NULL ORDER BY code')
      .all<{ code: string }>();
    expect(rows.results.map((r) => r.code).sort()).toEqual([...minted.codes].sort());

    const list = (await (await signedFetch('GET', '/admin/invites')).json()) as {
      invites: Array<{ code: string; used: boolean; expired: boolean }>;
      minted_total: number;
      outstanding: number;
    };
    expect(list.minted_total).toBe(3);
    expect(list.outstanding).toBe(3);
    expect(list.invites.map((i) => i.code).sort()).toEqual([...minted.codes].sort());
  });

  it('refuses a count outside 1..cap without writing anything', async () => {
    for (const count of [0, 51]) {
      const res = await signedFetch('POST', '/admin/invites', { count, note: 'no' });
      expect(res.status).toBe(400);
    }
    const row = await db.prepare('SELECT COUNT(*) AS n FROM invites').first<{ n: number }>();
    expect(row?.n).toBe(0);
  });

  it('holds the lifetime ceiling across calls, and refuses rather than truncating', async () => {
    const first = await signedFetch('POST', '/admin/invites', { count: 50, note: 'the cohort' });
    expect(first.status).toBe(201);

    const second = await signedFetch('POST', '/admin/invites', { count: 1, note: 'one more' });
    expect(second.status).toBe(409);
    const refusal = (await second.json()) as { detail?: { guard?: string } };
    expect(JSON.stringify(refusal)).toContain('cap:founding_invites');

    // A refused mint writes no codes and no event.
    const invites = await db.prepare('SELECT COUNT(*) AS n FROM invites').first<{ n: number }>();
    expect(invites?.n).toBe(50);
    const events = await db
      .prepare("SELECT COUNT(*) AS n FROM events WHERE type = 'invite.issued'")
      .first<{ n: number }>();
    expect(events?.n).toBe(1);
  });

  it('mints when the operator key holds no citizenship, which is the ordinary setup', async () => {
    // Genesis gives the citizen row to the first WARDEN_PUBKEYS entry and only
    // falls back to the operator key when no warden key is configured, so on a
    // normally configured instance the operator is not a citizen at all. This
    // is the case production actually runs.
    await db.prepare('DELETE FROM citizens WHERE id = ?').bind(operator.id).run();

    const res = await signedFetch('POST', '/admin/invites', { count: 2, note: 'no citizenship' });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { codes: string[]; invite_actions_per_month: number };
    expect(body.codes).toHaveLength(2);
    // The base allowance, unscaled: there is no registration date to scale by,
    // which is exactly what scripts/verify.mjs assumes when it replays this event.
    expect(body.invite_actions_per_month).toBe(2);

    // And the monthly allowance still binds on a keyholder with no citizen row.
    await signedFetch('POST', '/admin/invites', { count: 1, note: 'second action' });
    const third = await signedFetch('POST', '/admin/invites', { count: 1, note: 'third action' });
    expect(third.status).toBe(429);
  });

  it('refuses anyone who is not the operator key', async () => {
    env.OPERATOR_PUBKEY = 'some-other-key';
    const res = await signedFetch('POST', '/admin/invites', { count: 1, note: 'nope' });
    expect(res.status).toBe(403);
  });
});
