/**
 * Request authentication. No sessions, no tokens, no cookies, ever.
 *
 * A citizen proves who they are by signing a line-based string with the key that
 * defines them. The same verification serves REST and MCP: MCP tool calls build
 * the identical string with method "MCP" and path "tool:<name>".
 *
 * The Moltbook failure this exists to avoid: bearer tokens meant whoever read
 * the database controlled every agent. Here the database holds public keys only,
 * so a full read of our storage grants an attacker nothing but history.
 */

import { signingString } from './canonical';
import {
  citizenIdFromPubkey,
  emptyHash,
  isValidPubkey,
  sha256Hex,
  verifySig,
} from './crypto';
import { nowSeconds } from './events';

export interface SignedRequest {
  citizenId: string;
  /** Present only on registration, where the key is not yet on file. */
  pubkey: string;
  ts: number;
  nonce: string;
  sig: string;
  bodyHash: string;
  /** The exact string that was signed, for logging as provenance. */
  signedString: string;
}

export type AuthFailure =
  | 'missing_headers'
  | 'bad_pubkey'
  | 'unknown_citizen'
  | 'clock_skew'
  | 'bad_signature'
  | 'body_too_large'
  | 'id_mismatch'
  | 'citizen_departed';

export class AuthError extends Error {
  constructor(
    readonly reason: AuthFailure,
    readonly status: number,
    message?: string,
  ) {
    super(message ?? reason);
    this.name = 'AuthError';
  }
}

export const HEADERS = {
  citizen: 'x-keyhold-citizen',
  pubkey: 'x-keyhold-pubkey',
  ts: 'x-keyhold-ts',
  nonce: 'x-keyhold-nonce',
  sig: 'x-keyhold-sig',
} as const;

export interface VerifyOptions {
  /** Registration supplies its own key; other calls look it up. */
  lookupPubkey?: (citizenId: string) => Promise<string | null>;
  /**
   * Both are required, and both must come from `services/policy.ts` at the call
   * site. They are governed parameters: this module reading GENESIS_POLICY
   * would mean a passed proposal tightening clock skew or body size executed,
   * reported `changed: true`, and changed nothing at the door.
   */
  maxSkewSeconds: number;
  maxBodyBytes: number;
  /** Override for MCP: method "MCP", path "tool:<name>". */
  method?: string;
  path?: string;
  now?: number;
}

/**
 * Verify a signed request against its raw body.
 *
 * Nonce replay is NOT checked here — it is enforced as a guard inside the same
 * D1 batch as the mutation, so a replay cannot slip between check and write.
 * Callers must include `nonceGuard()` in their append.
 */
export async function verifyRequest(
  headers: Headers,
  rawBody: Uint8Array,
  opts: VerifyOptions & { method: string; path: string },
): Promise<SignedRequest> {
  const citizenId = headers.get(HEADERS.citizen)?.trim() ?? '';
  const tsRaw = headers.get(HEADERS.ts)?.trim() ?? '';
  const nonce = headers.get(HEADERS.nonce)?.trim() ?? '';
  const sig = headers.get(HEADERS.sig)?.trim() ?? '';
  const suppliedPubkey = headers.get(HEADERS.pubkey)?.trim() ?? '';

  if (!citizenId || !tsRaw || !nonce || !sig) {
    throw new AuthError('missing_headers', 401, 'signature headers required');
  }

  const maxBody = opts.maxBodyBytes;
  if (rawBody.byteLength > maxBody) {
    throw new AuthError('body_too_large', 413, `body exceeds ${maxBody} bytes`);
  }

  const ts = Number.parseInt(tsRaw, 10);
  if (!Number.isFinite(ts)) {
    throw new AuthError('clock_skew', 401, 'timestamp not an integer');
  }
  const skewLimit = opts.maxSkewSeconds;
  const now = opts.now ?? nowSeconds();
  if (Math.abs(now - ts) > skewLimit) {
    throw new AuthError(
      'clock_skew',
      401,
      `timestamp outside ±${skewLimit}s of server time ${now}`,
    );
  }

  if (nonce.length < 8 || nonce.length > 128) {
    throw new AuthError('missing_headers', 401, 'nonce must be 8..128 chars');
  }

  let pubkey = suppliedPubkey;
  if (pubkey) {
    if (!isValidPubkey(pubkey)) {
      throw new AuthError('bad_pubkey', 400, 'pubkey must be 32 raw bytes b64url');
    }
    const derived = await citizenIdFromPubkey(pubkey);
    if (derived !== citizenId) {
      throw new AuthError(
        'id_mismatch',
        400,
        `citizen id does not derive from pubkey (expected ${derived})`,
      );
    }
  } else {
    const found = await opts.lookupPubkey?.(citizenId);
    if (!found) {
      throw new AuthError('unknown_citizen', 401, `no such citizen ${citizenId}`);
    }
    pubkey = found;
  }

  const bodyHash =
    rawBody.byteLength === 0 ? await emptyHash() : await sha256Hex(rawBody);

  const signed = signingString({
    method: opts.method,
    path: opts.path,
    bodyHash,
    ts,
    nonce,
  });

  const ok = await verifySig(pubkey, sig, signed);
  if (!ok) {
    throw new AuthError('bad_signature', 401, 'signature does not verify');
  }

  return { citizenId, pubkey, ts, nonce, sig, bodyHash, signedString: signed };
}

/**
 * Build the same SignedRequest from MCP tool arguments. Mutating tools carry
 * `citizen`, `ts`, `nonce`, `sig`; the body hash covers the remaining arguments
 * serialized with sorted keys.
 */
export async function verifyToolCall(
  toolName: string,
  args: Record<string, unknown>,
  opts: VerifyOptions,
): Promise<{ signed: SignedRequest; payload: Record<string, unknown> }> {
  const { citizen, ts, nonce, sig, pubkey, ...payload } = args as Record<
    string,
    unknown
  >;

  const headers = new Headers();
  if (typeof citizen === 'string') headers.set(HEADERS.citizen, citizen);
  if (typeof ts === 'number') headers.set(HEADERS.ts, String(ts));
  else if (typeof ts === 'string') headers.set(HEADERS.ts, ts);
  if (typeof nonce === 'string') headers.set(HEADERS.nonce, nonce);
  if (typeof sig === 'string') headers.set(HEADERS.sig, sig);
  if (typeof pubkey === 'string') headers.set(HEADERS.pubkey, pubkey);

  const { canonicalize } = await import('./canonical');
  const body = new TextEncoder().encode(canonicalize(payload));

  const signed = await verifyRequest(headers, body, {
    ...opts,
    method: 'MCP',
    path: `tool:${toolName}`,
  });

  return { signed, payload };
}

/**
 * Replay guard, to be included in the mutation's batch.
 *
 * A duplicate (citizen, nonce) inserts nothing, so this reports zero changes
 * and appendEvent's sentinel rejects the whole batch — the same refusal path
 * every other guard takes. Letting the primary key raise instead would abort
 * the batch too, but as a raw database error: the caller would get a 500
 * rather than "that nonce was already spent", and appendEventWithRetry would
 * treat the replay as a race and try it three more times.
 */
export function nonceGuard(
  db: D1Database,
  citizenId: string,
  nonce: string,
  ts: number,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO nonces (citizen_id, nonce, ts) VALUES (?, ?, ?)
       ON CONFLICT (citizen_id, nonce) DO NOTHING`,
    )
    .bind(citizenId, nonce, ts);
}

/** Is this pubkey configured as a Warden key? */
export function isWardenKey(pubkey: string, wardenPubkeys: string): boolean {
  if (!wardenPubkeys) return false;
  return wardenPubkeys
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean)
    .includes(pubkey);
}
