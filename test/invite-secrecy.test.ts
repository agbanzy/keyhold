/**
 * An invite code must never reach the public event log.
 *
 * /export/events is unauthenticated by design. An invite is scarce — two per
 * citizen per thirty days — and carries the issuer's reputation: they stake
 * marks on whoever redeems it. Publishing the plaintext means whoever polls the
 * feed fastest redeems it, so the voucher stakes their standing on a stranger
 * and the founding cohort cannot be handed to anyone in particular.
 *
 * The chain still has to prove what happened, so it carries sha256 of the code:
 * how many were issued, by whom, and that a registration redeemed an invite
 * that was genuinely issued, all stay checkable.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { env, SELF } from 'cloudflare:test';
import { b64uEncode, citizenIdFromPubkey, newId, sha256Hex } from '../src/core/crypto';
import { signingString } from '../src/core/canonical';
import { GENESIS_PREV_HASH } from '../src/core/events';
import { HEADERS } from '../src/core/auth';

const db = env.DB as D1Database;

async function keypair() {
  const kp = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer);
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
  const ts = Math.floor(Date.now() / 1000);
  const nonce = newId('n');
  const msg = signingString({ method, path, bodyHash: await sha256Hex(raw), ts, nonce });
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
  return SELF.fetch(`https://example.com${path}`, { method, headers, body: raw || undefined });
}

/** Everything a stranger can read, as one string. */
async function publicLog(): Promise<string> {
  const res = await SELF.fetch('https://example.com/export/events?since=0&limit=500');
  return res.text();
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
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
    .bind(GENESIS_PREV_HASH)
    .run();
});

describe('invite codes stay out of the public log', () => {
  it('publishes a hash when a citizen issues an invite, never the code', async () => {
    const citizen = await keypair();
    const now = Math.floor(Date.now() / 1000);
    await db
      .prepare(
        `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
         VALUES (?, ?, 'Voucher', 'active', 'ordinary', 100, ?, 1)`,
      )
      .bind(citizen.id, citizen.pubkey, now - 40 * 86400)
      .run();

    const res = await signedFetch(citizen, 'POST', '/api/invites', {});
    expect(res.status, await res.clone().text()).toBe(201);

    const { code } = (await res.json()) as { code: string };
    expect(code).toMatch(/^iv_/);

    // The issuer got the code. The world got only its hash.
    const log = await publicLog();
    expect(log, 'the invite code was published on the open event feed').not.toContain(code);
    expect(log).toContain(await sha256Hex(code));
  });

  it('does not republish the code when the invite is redeemed', async () => {
    const issuer = await keypair();
    const now = Math.floor(Date.now() / 1000);
    await db
      .prepare(
        `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
         VALUES (?, ?, 'Voucher', 'active', 'ordinary', 100, ?, 1)`,
      )
      .bind(issuer.id, issuer.pubkey, now - 40 * 86400)
      .run();

    const minted = await signedFetch(issuer, 'POST', '/api/invites', {});
    const { code } = (await minted.json()) as { code: string };

    const newcomer = await keypair();
    const reg = await signedFetch(newcomer, 'POST', '/api/register', {
      display_name: 'Second',
      invite_code: code,
    });
    expect(reg.status, await reg.clone().text()).toBe(201);

    const log = await publicLog();
    expect(log, 'redemption republished the invite code').not.toContain(code);

    // Still provable: the registration names the same invite that was issued.
    const hash = await sha256Hex(code);
    const lines = log.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
    const issued = lines.find((e) => e.type === 'invite.issued');
    const registered = lines.find((e) => e.type === 'citizen.registered');
    expect(issued.payload.code_hash).toBe(hash);
    expect(registered.payload.invite_hash).toBe(hash);
  });
});
