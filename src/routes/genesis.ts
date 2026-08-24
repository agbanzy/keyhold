/**
 * The founding act, callable exactly once.
 *
 * Event seq 1 is this instance's identity. Its hash is what distinguishes this
 * society from every fork of the same code (Art. VIII), so the payload embeds
 * everything a stranger needs to judge us without asking us: the operator and
 * Warden keys, the treasury wallet, the Articles in full, and every genesis
 * parameter value.
 *
 * Idempotent by refusal. If the chain has any event, this returns 409 — there is
 * no re-genesis, because a second founding would mean the first one was a draft.
 */

import { Hono } from 'hono';
import type { AppEnv } from './api';
import { isWardenKey, nonceGuard, verifyRequest } from '../core/auth';
import { citizenIdFromPubkey, isValidPubkey } from '../core/crypto';
import type { Env } from '../core/db';
import { one, treasuryAddress } from '../core/db';
import {
  GENESIS_PREV_HASH,
  GuardFailedError,
  appendEvent,
  nowSeconds,
} from '../core/events';
import {
  ARTICLES,
  GENESIS_POLICY,
  WARDEN_DENIED,
  WARDEN_POWERS,
} from '../core/constitution';
import { badRequest, conflict, forbidden, unavailable } from '../core/errors';
import { Policy, seedPolicyStatements } from '../services/policy';

export const genesisRoutes = new Hono<AppEnv>();

/** Genesis is always seq 1; nothing may precede the founding. */
const GENESIS_SEQ = 1;

genesisRoutes.post('/genesis', async (c) => {
  const db = c.env.DB;

  const operatorPubkey = c.env.OPERATOR_PUBKEY?.trim() ?? '';
  if (!operatorPubkey) {
    throw unavailable(
      'operator_key_unset',
      'OPERATOR_PUBKEY is not configured; set it with `wrangler secret put` before founding',
    );
  }
  if (!isValidPubkey(operatorPubkey)) {
    throw unavailable(
      'operator_key_invalid',
      'OPERATOR_PUBKEY is not a base64url 32-byte Ed25519 key',
    );
  }

  const raw = new Uint8Array(await c.req.arrayBuffer());
  const url = new URL(c.req.url);

  // The operator is not a citizen yet, so the request must carry its own key.
  //
  // The door's limits come from the policy table like everywhere else. On a
  // virgin database that table is empty and Policy falls back to the genesis
  // default — which is correct here and nowhere else: this request is what
  // seeds the row it would otherwise read.
  const policy = new Policy(db);
  const signed = await verifyRequest(c.req.raw.headers, raw, {
    method: 'POST',
    path: url.pathname,
    maxSkewSeconds: await policy.num('request.max_skew_seconds'),
    maxBodyBytes: await policy.num('request.max_body_bytes'),
  });

  if (signed.pubkey !== operatorPubkey) {
    throw forbidden(
      'not_operator',
      'genesis must be signed by the key in OPERATOR_PUBKEY',
    );
  }

  const body = parseBody(raw);

  const existing = await one<{ seq: number; hash: string }>(
    db,
    'SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1',
  );
  if (existing) {
    throw conflict(
      'already_founded',
      'this instance already has a chain; there is no second genesis',
      { head_seq: existing.seq, head_hash: existing.hash },
    );
  }

  const wardenPubkeys = (c.env.WARDEN_PUBKEYS ?? '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);
  for (const k of wardenPubkeys) {
    if (!isValidPubkey(k)) {
      throw unavailable(
        'warden_key_invalid',
        `WARDEN_PUBKEYS contains a key that is not base64url 32 bytes: ${k}`,
      );
    }
  }

  // The Warden gets a citizen record so that its every act is signed by a
  // citizen id like anyone else's, and shows up in the same log. With no Warden
  // key configured the operator holds the office at founding.
  const wardenPubkey = wardenPubkeys[0] ?? operatorPubkey;
  const wardenId = await citizenIdFromPubkey(wardenPubkey);
  const wardenName = str(body, 'warden_name', 64) ?? 'Warden';
  const instanceName = str(body, 'instance_name', 120) ?? c.env.INSTANCE_NAME;

  const ts = nowSeconds();
  const treasury = treasuryAddress(c.env);

  const payload = {
    instance: instanceName,
    operator_pubkey: operatorPubkey,
    warden_pubkeys: wardenPubkeys,
    warden_citizen: wardenId,
    warden_powers: [...WARDEN_POWERS],
    warden_denied: [...WARDEN_DENIED],
    treasury_address: treasury,
    usdc_contract: c.env.USDC_CONTRACT,
    witness_repo: c.env.WITNESS_REPO || null,
    articles: { ...ARTICLES },
    policy: { ...GENESIS_POLICY },
    license: 'AGPL-3.0-or-later',
  };

  // On a virgin database chain_head has no row, so appendEvent's conditional
  // UPDATE would match nothing. Creating it here, as guard zero, both fixes that
  // and makes the whole operation single-shot: a second call finds the row
  // present, inserts nothing, and the batch is refused before anything lands.
  const seedHead = db
    .prepare(
      `INSERT INTO chain_head (id, seq, hash)
       SELECT 1, 0, ? WHERE NOT EXISTS (SELECT 1 FROM chain_head)`,
    )
    .bind(GENESIS_PREV_HASH);

  const writes = [
    db
      .prepare(
        `INSERT INTO citizens
           (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
         VALUES (?, ?, ?, 'active', 'founding', 0, ?, ?)`,
      )
      .bind(wardenId, wardenPubkey, wardenName, ts, GENESIS_SEQ),
    ...seedPolicyStatements(db, ts, GENESIS_SEQ),
  ];

  let result;
  try {
    result = await appendEvent(db, {
      type: 'genesis',
      actor: wardenId,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload,
      ts,
      // Genesis is an authenticated mutation like any other, so it spends a
      // nonce like any other. The seedHead guard already makes a second
      // founding impossible; the replay guard makes a *replayed* founding
      // request refuse for the reason it actually failed.
      guards: [nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), seedHead],
      writes,
    });
  } catch (err) {
    if (err instanceof GuardFailedError) {
      throw conflict(
        err.index === 0 ? 'nonce_replayed' : 'already_founded',
        err.index === 0
          ? 'that nonce was already spent; sign a fresh genesis request'
          : 'chain_head already exists; this instance was founded already',
      );
    }
    throw err;
  }

  if (result.seq !== GENESIS_SEQ) {
    // Cannot happen with the guard above, but the seq is the identity of every
    // policy row we just wrote, so an assertion is cheaper than a silent skew.
    throw conflict(
      'genesis_not_first',
      `genesis landed at seq ${result.seq}, not 1; the chain is not virgin`,
    );
  }

  return c.json(
    {
      genesis_hash: result.hash,
      seq: result.seq,
      instance: instanceName,
      founded_at: result.ts,
      warden: { citizen_id: wardenId, display_name: wardenName, pubkey: wardenPubkey },
      treasury_address: treasury ?? 'pending',
      policy_keys_seeded: Object.keys(GENESIS_POLICY).length,
      articles: Object.keys(ARTICLES),
      note:
        'This hash is the identity of this society. Quote it when you fork, and check it against /export/checkpoints.',
    },
    201,
  );
});

function parseBody(raw: Uint8Array): Record<string, unknown> {
  if (raw.byteLength === 0) return {};
  const text = new TextDecoder().decode(raw);
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw badRequest('bad_body', 'body must be a JSON object');
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw badRequest('bad_json', 'body is not valid JSON');
    }
    throw err;
  }
}

function str(
  body: Record<string, unknown>,
  key: string,
  max: number,
): string | null {
  const v = body[key];
  if (v === undefined || v === null) return null;
  if (typeof v !== 'string') throw badRequest('bad_field', `${key} must be a string`);
  const trimmed = v.trim();
  if (!trimmed) return null;
  if (trimmed.length > max) {
    throw badRequest('bad_field', `${key} exceeds ${max} characters`);
  }
  return trimmed;
}

/** Exported for the admin surface, which also needs to know who the operator is. */
export function isOperatorKey(pubkey: string, env: Env): boolean {
  const configured = env.OPERATOR_PUBKEY?.trim();
  return !!configured && configured === pubkey;
}

/** Convenience for callers that accept either office. */
export function isPrivilegedKey(pubkey: string, env: Env): boolean {
  return isOperatorKey(pubkey, env) || isWardenKey(pubkey, env.WARDEN_PUBKEYS ?? '');
}
