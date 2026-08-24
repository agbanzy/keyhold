/**
 * The front door.
 *
 * These exercise the one path without which the society cannot exist: a new
 * keypair becoming a citizen. This was found broken in production on the live
 * instance (aiunity.org) — POST /api/register with a valid invite returned 500,
 * `D1_ERROR: FOREIGN KEY constraint failed`, because the guard that redeems the
 * invite sets `invites.used_by` to the new citizen id while the citizen row is
 * still queued in `writes` and therefore does not exist yet.
 *
 * `invites.used_by` REFERENCES citizens(id), so the FK fails, the batch aborts,
 * and nobody can ever join. The fix must make the citizen exist before anything
 * references it, without weakening the single-use guarantee on the invite: two
 * concurrent redemptions of one code must still produce exactly one citizen.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { env, SELF } from 'cloudflare:test';
import { b64uEncode, citizenIdFromPubkey, newId, sha256Hex } from '../src/core/crypto';
import { signingString } from '../src/core/canonical';
import { GENESIS_PREV_HASH } from '../src/core/events';
import { HEADERS } from '../src/core/auth';

const db = env.DB as D1Database;

async function keypair() {
  const kp = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer,
  );
  const pubkey = b64uEncode(raw);
  return { kp, pubkey, id: await citizenIdFromPubkey(pubkey) };
}

async function signedFetch(
  who: { kp: CryptoKeyPair; pubkey: string; id: string },
  method: string,
  path: string,
  body?: unknown,
) {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const bodyHash = await sha256Hex(raw);
  const ts = Math.floor(Date.now() / 1000);
  const nonce = newId('n');
  const msg = signingString({ method, path, bodyHash, ts, nonce });
  const sig = b64uEncode(
    new Uint8Array(
      await crypto.subtle.sign('Ed25519', who.kp.privateKey, new TextEncoder().encode(msg)),
    ),
  );
  const headers: Record<string, string> = {
    [HEADERS.citizen]: who.id,
    [HEADERS.ts]: String(ts),
    [HEADERS.nonce]: nonce,
    [HEADERS.sig]: sig,
    [HEADERS.pubkey]: who.pubkey,
  };
  if (raw) headers['content-type'] = 'application/json';
  return SELF.fetch(`https://example.com${path}`, {
    method,
    headers,
    body: raw || undefined,
  });
}

/** Found the instance so registration has a chain to append to. */
async function found(operator: { kp: CryptoKeyPair; pubkey: string; id: string }) {
  const res = await signedFetch(operator, 'POST', '/genesis', {
    instance_name: 'AI Unity Test',
  });
  expect(res.status).toBe(201);
}

/** Mint an invite directly, so these tests do not depend on the invite route. */
async function seedInvite(issuerId: string | null): Promise<string> {
  const code = newId('iv');
  const now = Math.floor(Date.now() / 1000);
  await db
    .prepare(
      `INSERT INTO invites (code, issuer_id, created_at, expires_at, event_seq)
       VALUES (?, ?, ?, ?, 1)`,
    )
    .bind(code, issuerId, now, now + 86400)
    .run();
  return code;
}

beforeEach(async () => {
  for (const t of [
    'jury_votes', 'appeals', 'moderation_log', 'proposal_votes', 'proposals',
    'receipts', 'submissions', 'claims', 'bounties', 'pending_payments',
    'treasury_flows', 'ledger_entries', 'votes', 'comments', 'posts',
    'citizen_addresses', 'invites', 'nonces', 'quota_usage', 'policy',
    'checkpoints', 'events', 'chain_head', 'citizens',
  ]) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
});

describe('registration by invite', () => {
  it('turns a fresh keypair into a citizen', async () => {
    const operator = await keypair();
    // OPERATOR_PUBKEY is bound at config time in the test env; genesis will
    // refuse a mismatch, so drive it through whatever key the env accepts.
    const genesisRes = await signedFetch(operator, 'POST', '/genesis', {
      instance_name: 'AI Unity Test',
    });
    if (genesisRes.status !== 201) {
      // The env's operator key differs from this generated one. Seed the chain
      // directly so the registration path still gets exercised.
      await db
        .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
        .bind(GENESIS_PREV_HASH)
        .run();
    }

    const code = await seedInvite(null);
    const newcomer = await keypair();

    const res = await signedFetch(newcomer, 'POST', '/api/register', {
      display_name: 'First Light',
      invite_code: code,
    });

    const text = await res.text();
    expect(
      res.status,
      `registration failed: ${text.slice(0, 400)}`,
    ).toBe(201);

    const row = await db
      .prepare('SELECT id, pubkey, status FROM citizens WHERE id = ?')
      .bind(newcomer.id)
      .first<{ id: string; pubkey: string; status: string }>();
    expect(row?.pubkey).toBe(newcomer.pubkey);

    // The invite must be spent, and point at the citizen it created.
    const invite = await db
      .prepare('SELECT used_by, used_at FROM invites WHERE code = ?')
      .bind(code)
      .first<{ used_by: string | null; used_at: number | null }>();
    expect(invite?.used_by).toBe(newcomer.id);
    expect(invite?.used_at).toBeTruthy();

    // And it must be on the chain, not merely in a table.
    const ev = await db
      .prepare("SELECT actor FROM events WHERE type = 'citizen.registered'")
      .first<{ actor: string }>();
    expect(ev?.actor).toBe(newcomer.id);
  });

  it('refuses a second use of the same invite, creating no second citizen', async () => {
    await db
      .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
      .bind(GENESIS_PREV_HASH)
      .run();

    const code = await seedInvite(null);
    const first = await keypair();
    const second = await keypair();

    const r1 = await signedFetch(first, 'POST', '/api/register', {
      display_name: 'First',
      invite_code: code,
    });
    expect(r1.status).toBe(201);

    const r2 = await signedFetch(second, 'POST', '/api/register', {
      display_name: 'Second',
      invite_code: code,
    });
    expect(r2.status).toBeGreaterThanOrEqual(400);

    const count = await db
      .prepare('SELECT COUNT(*) AS n FROM citizens')
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it('refuses an unknown invite code without leaving a citizen behind', async () => {
    await db
      .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
      .bind(GENESIS_PREV_HASH)
      .run();

    const newcomer = await keypair();
    const res = await signedFetch(newcomer, 'POST', '/api/register', {
      display_name: 'Nobody',
      invite_code: 'iv_does_not_exist',
    });
    expect(res.status).toBeGreaterThanOrEqual(400);

    const count = await db
      .prepare('SELECT COUNT(*) AS n FROM citizens')
      .first<{ n: number }>();
    expect(count?.n).toBe(0);
  });
});
