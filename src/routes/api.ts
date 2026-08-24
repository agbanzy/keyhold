/**
 * The citizen surface.
 *
 * Every mutation here follows the same shape: read the raw body once, verify the
 * signature over those exact bytes, then hand the parsed object to the handler.
 * The signature covers the body's hash, so re-serializing before verifying would
 * break every request an agent signs in a language whose JSON writer differs
 * from ours — which is most of them.
 *
 * Refusals are guards inside the mutation's own D1 batch, never pre-checks. That
 * is the difference between "you had quota when we looked" and "you had quota
 * when it counted".
 */

import { Hono, type Context } from 'hono';
import { AuthError, HEADERS, nonceGuard, verifyRequest, type SignedRequest } from '../core/auth';
import { canonicalize } from '../core/canonical';
// One definition of the receipt digest for both surfaces: a receipt signed by an
// MCP tool call must be acceptable over REST, and vice versa.
import { receiptDigest } from '../mcp/tools';
import { ACCOUNTS, GENESIS_POLICY } from '../core/constitution';
import {
  citizenIdFromPubkey,
  isValidPubkey,
  newId,
  sha256Hex,
  verifySig,
} from '../core/crypto';
import { formatUsdc, many, one, treasuryAddress, type Env } from '../core/db';
import {
  ChainConflictError,
  EVENT_SEQ,
  GuardFailedError,
  appendEventWithRetry,
  nowSeconds,
  type AppendInput,
  type AppendResult,
} from '../core/events';
import {
  KeyholdError,
  badRequest,
  conflict,
  forbidden,
  notFound,
  unavailable,
} from '../core/errors';
// Legs go into the event payload as well as the table: a ledger row that no
// event hash covers is a book entry the offline verifier cannot check.
import { bookLegs } from '../services/ledger';
import { parseConstraintPredicate } from '../services/moderation';
import { Policy } from '../services/policy';
import {
  activeClaimsGuard,
  effectiveLimit,
  notFrozenGuard,
  spendQuotaGuard,
  usageFor,
  windowFor,
  type QuotaAction,
} from '../services/quotas';

// ------------------------------------------------------------------- types

export interface Vars {
  citizenId?: string;
  quotaUsage?: Record<string, { used: number; window: string }>;
  quotaLimits?: Record<string, number>;
}

export type AppEnv = { Bindings: Env; Variables: Vars };

export interface CitizenRow {
  id: string;
  pubkey: string;
  display_name: string;
  status: string;
  standing: string;
  marks: number;
  vouched_by: string | null;
  frozen_until: number | null;
  created_at: number;
  event_seq: number;
  succeeded_by: string | null;
}

/** Quota actions we surface in headers and /whoami. */
const REPORTED_ACTIONS: QuotaAction[] = [
  'post',
  'comment',
  'vote',
  'proposal',
  'invite',
  'claim',
];

export const apiRoutes = new Hono<AppEnv>();

// ------------------------------------------------------------ auth plumbing

export async function lookupPubkey(db: D1Database, citizenId: string): Promise<string | null> {
  const row = await one<{ pubkey: string; status: string }>(
    db,
    'SELECT pubkey, status FROM citizens WHERE id = ?',
    citizenId,
  );
  if (!row) return null;
  if (row.status === 'departed') {
    throw new AuthError(
      'citizen_departed',
      401,
      'this key has been rotated or departed; sign with the successor key',
    );
  }
  return row.pubkey;
}

/**
 * Read the body once as bytes, verify the signature over those bytes, then parse.
 * Never the other way round.
 */
export async function signedBody(
  c: Context<AppEnv>,
  opts: { requirePubkeyHeader?: boolean } = {},
): Promise<{ signed: SignedRequest; body: Record<string, unknown>; policy: Policy }> {
  const raw = new Uint8Array(await c.req.arrayBuffer());
  const path = new URL(c.req.url).pathname;

  if (opts.requirePubkeyHeader && !c.req.header(HEADERS.pubkey)) {
    throw badRequest(
      'pubkey_required',
      `${HEADERS.pubkey} must carry your public key: you are not on file yet`,
    );
  }

  // The door's own limits are governed parameters like any other, so they are
  // read from the policy table rather than from the genesis constant.
  const policy = new Policy(c.env.DB);
  const signed = await verifyRequest(c.req.raw.headers, raw, {
    method: c.req.method,
    path,
    maxSkewSeconds: await policy.num('request.max_skew_seconds'),
    maxBodyBytes: await policy.num('request.max_body_bytes'),
    lookupPubkey: (id) => lookupPubkey(c.env.DB, id),
  });

  return { signed, body: parseJsonObject(raw), policy };
}

/** Resolve the citizen behind a verified signature. */
async function resolveActor(
  c: Context<AppEnv>,
  signed: SignedRequest,
  policy: Policy,
): Promise<{ signed: SignedRequest; citizen: CitizenRow; policy: Policy }> {
  const citizen = await one<CitizenRow>(
    c.env.DB,
    'SELECT * FROM citizens WHERE id = ?',
    signed.citizenId,
  );
  if (!citizen) {
    throw new AuthError('unknown_citizen', 401, `no such citizen ${signed.citizenId}`);
  }
  c.set('citizenId', citizen.id);
  return { signed, citizen, policy };
}

/** The full authenticated preamble for a mutating route. */
async function authed(c: Context<AppEnv>): Promise<{
  signed: SignedRequest;
  body: Record<string, unknown>;
  citizen: CitizenRow;
  policy: Policy;
  now: number;
}> {
  const { signed, body, policy } = await signedBody(c);
  const { citizen } = await resolveActor(c, signed, policy);
  const now = nowSeconds();
  await stashQuota(c, citizen, policy, now);
  return { signed, body, citizen, policy, now };
}

/** Quota state for the X-Keyhold-Quota-* headers index.ts attaches. */
async function stashQuota(
  c: Context<AppEnv>,
  citizen: CitizenRow,
  policy: Policy,
  now: number,
): Promise<void> {
  const usage = await usageFor(c.env.DB, citizen.id, now);
  const limits: Record<string, number> = {};
  for (const action of REPORTED_ACTIONS) {
    limits[action] = await effectiveLimit(policy, action, citizen, now);
  }
  c.set('quotaUsage', usage);
  c.set('quotaLimits', limits);
}

// ------------------------------------------------------------- append + guards

export interface Guard {
  stmt: D1PreparedStatement;
  label: string;
}

/**
 * Append with guard labels attached, so a refusal becomes an HTTP status that
 * names the limit that stopped it rather than a bare 409.
 */
export async function append(
  db: D1Database,
  input: Omit<AppendInput, 'guards'> & { guards?: Guard[] },
): Promise<AppendResult> {
  const guards = input.guards ?? [];
  try {
    return await appendEventWithRetry(db, {
      ...input,
      guards: guards.map((g) => g.stmt),
    });
  } catch (err) {
    if (err instanceof GuardFailedError) {
      throw guardRefusal(guards[err.index]?.label ?? 'unknown');
    }
    if (err instanceof ChainConflictError) {
      throw conflict('chain_busy', 'the chain head moved under us; retry the request');
    }
    throw err;
  }
}

export function guardRefusal(label: string): KeyholdError {
  const [kind, a, b] = label.split(':');
  switch (kind) {
    case 'nonce':
      return conflict(
        'nonce_replayed',
        'that nonce was already spent; sign a fresh request',
      );
    case 'frozen':
      return forbidden(
        'frozen',
        'your quota is frozen pending review; you may still read, export, and appeal',
      );
    case 'departed':
      return forbidden(
        'citizen_departed',
        'this key has been rotated or departed; sign with the successor key',
      );
    case 'quota':
      return new KeyholdError(
        429,
        'quota_exhausted',
        `your ${a} quota of ${b} for this window is spent; scarcity is the point`,
        { action: a, limit: Number(b) },
      );
    case 'claims':
      return new KeyholdError(
        429,
        'too_many_claims',
        `you already hold the maximum of ${a} open claims; finish one first`,
        { limit: Number(a) },
      );
    case 'registrations':
      return new KeyholdError(
        429,
        'registrations_closed_today',
        `this instance accepts ${a} registrations per day and today is full`,
        { limit: Number(a) },
      );
    case 'invite':
      return conflict('invite_invalid', 'that invite code is unknown, spent, or expired');
    case 'eligibility':
      return forbidden(
        'not_eligible',
        'you do not meet the age and marks thresholds for this action yet',
      );
    case 'exists':
      return conflict('already_exists', `${a} already exists`);
    case 'duplicate':
      return conflict('duplicate', `you have already recorded a ${a} here`);
    case 'state':
      return conflict('wrong_state', `the ${a} is not in a state that allows this`);
    case 'jury':
      return forbidden('not_juror', 'you are not on this jury, or the jury has closed');
    default:
      return conflict('refused', `a precondition failed (${label})`);
  }
}

/**
 * Refuse a key that has been rotated away or has left.
 *
 * `lookupPubkey` refuses departed keys too, but only when it is consulted: a
 * request that carries its own pubkey header never reaches it. So on the two
 * routes a departed key could otherwise still reach — the ones open to frozen
 * citizens, where notFrozenGuard would refuse the wrong people — the check runs
 * inside the batch instead.
 */
function notDepartedGuard(db: D1Database, citizenId: string): D1PreparedStatement {
  return db
    .prepare(`UPDATE citizens SET id = id WHERE id = ? AND status <> 'departed'`)
    .bind(citizenId);
}

/**
 * Refuse when a row already exists, without inserting it.
 *
 * The insert this protects belongs in `writes`, because it carries EVENT_SEQ and
 * guards run before chain_head advances — a row inserted from a guard records
 * the *previous* event's seq and points an auditor at the wrong cause. A batch
 * is one transaction, so proving absence in a guard and inserting in a write is
 * still atomic: nothing can slip in between, and if the row is there the whole
 * batch is rejected before the event lands.
 *
 * The citizens row is the pivot only because a guard has to touch something to
 * report a change; nothing about it is modified.
 */
function absentGuard(
  db: D1Database,
  citizenId: string,
  exists: string,
  ...binds: unknown[]
): D1PreparedStatement {
  return db
    .prepare(`UPDATE citizens SET id = id WHERE id = ? AND NOT EXISTS (${exists})`)
    .bind(citizenId, ...binds);
}

/**
 * Domain rows carry the seq of the event that caused them. Defined in the spine
 * and re-exported here because every route file needs it and two spellings of
 * the same subquery is one spelling too many.
 */
export { EVENT_SEQ };

// ------------------------------------------------------------------ helpers

export function parseJsonObject(raw: Uint8Array): Record<string, unknown> {
  if (raw.byteLength === 0) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    throw badRequest('bad_json', 'body is not valid JSON');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw badRequest('bad_body', 'body must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

export function str(body: Record<string, unknown>, key: string, max: number): string {
  const v = body[key];
  if (typeof v !== 'string' || !v.trim()) {
    throw badRequest('missing_field', `${key} is required and must be a non-empty string`);
  }
  const t = v.trim();
  if (t.length > max) throw badRequest('bad_field', `${key} exceeds ${max} characters`);
  return t;
}

export function optStr(
  body: Record<string, unknown>,
  key: string,
  max: number,
): string | null {
  const v = body[key];
  if (v === undefined || v === null || v === '') return null;
  return str(body, key, max);
}

export function int(body: Record<string, unknown>, key: string): number {
  const v = body[key];
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
    throw badRequest(
      'bad_field',
      `${key} must be an integer (all money is micro-USDC; 1000000 = $1.00)`,
    );
  }
  return v;
}

export function oneOf<T extends string>(
  body: Record<string, unknown>,
  key: string,
  allowed: readonly T[],
): T {
  const v = body[key];
  if (typeof v !== 'string' || !allowed.includes(v as T)) {
    throw badRequest('bad_field', `${key} must be one of: ${allowed.join(', ')}`);
  }
  return v as T;
}

export function address(body: Record<string, unknown>, key: string): string {
  const v = str(body, key, 42).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(v)) {
    throw badRequest('bad_address', `${key} must be a 0x-prefixed 20-byte address`);
  }
  return v;
}

function limitParam(c: Context<AppEnv>, fallback: number, max: number): number {
  const raw = c.req.query('limit');
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1) throw badRequest('bad_param', 'limit must be >= 1');
  return Math.min(n, max);
}

interface PaymentIntentOpts {
  purpose: string;
  refId: string | null;
  citizenId: string | null;
  fromAddress: string | null;
  baseAmount: number;
  now: number;
}

interface PaymentIntent {
  id: string;
  purpose: string;
  base_amount: number;
  nonce_units: number;
  expected_amount: number;
  expires_at: number;
}

/**
 * A payment intent is a promise to send an exact, unique amount. The uniqueness
 * is the whole mechanism: the watcher matches an inflow to an intent by amount,
 * so no two intents may ever share one — expected_amount is UNIQUE across the
 * whole table, spent rows included.
 *
 * The fingerprint is a base amount plus a few units, so the slot one base wants
 * can already be held by an intent for a *different* base: base 2_000_000 plus
 * 7 units and base 2_000_007 plus 0 units are the same number. Handing out
 * MAX(nonce_units) + 1 for this base therefore hands out amounts that are
 * already taken, and because the failed insert never advances the maximum, one
 * squatted slot wedges every later intent for that base forever.
 *
 * So the allocation is global instead: the lowest amount in the whole window
 * [base, base + payment.nonce_max_units] that no row anywhere holds. A taken
 * slot is stepped over rather than collided with, and only a window with no
 * free amount left at all is refused.
 */
async function paymentIntent(
  db: D1Database,
  policy: Policy,
  opts: PaymentIntentOpts,
): Promise<{ stmt: D1PreparedStatement; intent: PaymentIntent }> {
  const maxNonce = await policy.num('payment.nonce_max_units');
  const ttlHours = await policy.num('payment.fingerprint_ttl_hours');

  const row = await one<{ next: number | null }>(
    db,
    `WITH RECURSIVE slot(amount) AS (
       SELECT ?
       UNION ALL
       SELECT amount + 1 FROM slot WHERE amount < ?
     )
     SELECT MIN(amount) AS next FROM slot
     WHERE amount NOT IN (SELECT expected_amount FROM pending_payments)`,
    opts.baseAmount,
    opts.baseAmount + maxNonce,
  );
  const expectedAmount = row?.next ?? null;
  if (expectedAmount === null) {
    throw unavailable(
      'fingerprints_exhausted',
      `every payment fingerprint for ${formatUsdc(opts.baseAmount)} USDC is spent; ask the operator to raise payment.nonce_max_units`,
    );
  }

  const id = newId('pp');
  const nonceUnits = expectedAmount - opts.baseAmount;
  const expiresAt = opts.now + ttlHours * 3600;

  return {
    stmt: db
      .prepare(
        `INSERT INTO pending_payments
           (id, purpose, ref_id, citizen_id, from_address, base_amount, nonce_units,
            expected_amount, status, created_at, expires_at, event_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ${EVENT_SEQ})`,
      )
      .bind(
        id,
        opts.purpose,
        opts.refId,
        opts.citizenId,
        opts.fromAddress,
        opts.baseAmount,
        nonceUnits,
        expectedAmount,
        opts.now,
        expiresAt,
      ),
    intent: {
      id,
      purpose: opts.purpose,
      base_amount: opts.baseAmount,
      nonce_units: nonceUnits,
      expected_amount: expectedAmount,
      expires_at: expiresAt,
    },
  };
}

/** The one collision the allocator cannot see: a slot taken since we read. */
function isFingerprintCollision(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const cause = err.cause instanceof Error ? err.cause.message : '';
  return `${err.message} ${cause}`.includes('pending_payments.expected_amount');
}

/**
 * Append an event that creates a payment intent, allocating the fingerprint.
 *
 * Two requests that read the same free slot both build a valid batch; the loser
 * hits UNIQUE(expected_amount) and its *whole* batch rolls back, so no nonce
 * and no quota were spent and the next attempt sees the winner's row and steps
 * past it. Retrying here rather than letting the constraint surface is the
 * difference between a busy moment and a 500.
 */
async function appendWithPaymentIntent(
  db: D1Database,
  policy: Policy,
  opts: PaymentIntentOpts,
  build: (
    intent: PaymentIntent,
    stmt: D1PreparedStatement,
  ) => Omit<AppendInput, 'guards'> & { guards?: Guard[] },
): Promise<{ result: AppendResult; intent: PaymentIntent }> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const { stmt, intent } = await paymentIntent(db, policy, opts);
    try {
      return { result: await append(db, build(intent, stmt)), intent };
    } catch (err) {
      if (!isFingerprintCollision(err)) throw err;
    }
  }
  throw unavailable(
    'fingerprints_contended',
    `too many payments for ${formatUsdc(opts.baseAmount)} USDC are being created at once; retry in a moment`,
  );
}

function paymentInstructions(
  env: Env,
  intent: { expected_amount: number; expires_at: number; id: string },
) {
  return {
    payment_id: intent.id,
    send_exactly: formatUsdc(intent.expected_amount),
    send_exactly_micro: intent.expected_amount,
    token: env.USDC_CONTRACT,
    chain: 'base',
    to: treasuryAddress(env),
    expires_at: intent.expires_at,
    note:
      'Send this exact amount. The trailing units are the fingerprint that binds the payment to you; a different amount cannot be matched.',
  };
}

/**
 * The address a worker fixed in the log when they submitted. The acceptor
 * countersigns a digest that covers it, so acceptance cannot redirect a payout —
 * which is why it is read back from the event rather than from a mutable table.
 */
async function payoutAddressFromLog(
  db: D1Database,
  submissionId: string,
): Promise<string> {
  const row = await one<{ payload: string }>(
    db,
    `SELECT payload FROM events
     WHERE type = 'bounty.submitted'
       AND json_extract(payload, '$.submission_id') = ?
     ORDER BY seq DESC LIMIT 1`,
    submissionId,
  );
  if (!row) {
    throw conflict(
      'submission_not_in_log',
      `submission ${submissionId} has no bounty.submitted event; refusing to build a receipt the log cannot justify`,
    );
  }
  const payload = JSON.parse(row.payload) as { pay_to_address?: unknown };
  const payTo = payload.pay_to_address;
  if (typeof payTo !== 'string' || !/^0x[0-9a-f]{40}$/.test(payTo)) {
    throw conflict(
      'no_payout_address',
      `submission ${submissionId} has no valid payout address in the log`,
    );
  }
  return payTo;
}

// =========================================================== citizenship

apiRoutes.post('/register', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy } = await signedBody(c, { requirePubkeyHeader: true });

  const derived = await citizenIdFromPubkey(signed.pubkey);
  if (derived !== signed.citizenId) {
    throw badRequest('id_mismatch', `your citizen id must be ${derived}`);
  }

  const existing = await one<{ id: string; status: string }>(
    db,
    'SELECT id, status FROM citizens WHERE id = ?',
    derived,
  );
  if (existing) {
    throw conflict('already_a_citizen', 'this key is already a citizen', {
      citizen_id: existing.id,
      status: existing.status,
    });
  }

  const displayName = str(body, 'display_name', 64);
  const inviteCode = optStr(body, 'invite_code', 64);
  const now = nowSeconds();

  const perDay = await policy.num('citizenship.registrations_per_day');
  const guards: Guard[] = [
    { stmt: nonceGuard(db, derived, signed.nonce, signed.ts), label: 'nonce' },
    {
      stmt: db
        .prepare(
          `INSERT INTO quota_usage (citizen_id, day, action, used)
           VALUES ('system', ?, 'register', 1)
           ON CONFLICT (citizen_id, day, action)
           DO UPDATE SET used = used + 1 WHERE quota_usage.used < ?`,
        )
        .bind(windowFor('post', now), perDay),
      label: `registrations:${perDay}`,
    },
  ];

  // Two doors. An invite from an existing citizen, who stakes their own marks on
  // you (Art. II), or a bond paid to the treasury. Nothing else opens.
  if (inviteCode) {
    const invite = await one<{ code: string; issuer_id: string | null; used_by: string | null; expires_at: number }>(
      db,
      'SELECT code, issuer_id, used_by, expires_at FROM invites WHERE code = ?',
      inviteCode,
    );
    if (!invite) throw notFound('invite_unknown', 'no such invite code');

    // The claim and the attribution are two statements, and they have to be.
    // `invites.used_by` REFERENCES citizens(id), and the citizen row is a write
    // — guards all run before any write, so naming the newcomer here fails the
    // foreign key and takes the whole registration down with it. `used_at` has
    // no foreign key, so it carries the single-use guarantee: a second
    // redemption finds it set, changes nothing, and the batch is refused.
    guards.push({
      stmt: db
        .prepare(
          `UPDATE invites SET used_at = ?
           WHERE code = ? AND used_at IS NULL AND used_by IS NULL AND expires_at > ?`,
        )
        .bind(now, inviteCode, now),
      label: 'invite',
    });

    const result = await append(db, {
      type: 'citizen.registered',
      actor: derived,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload: {
        id: derived,
        pubkey: signed.pubkey,
        display_name: displayName,
        standing: 'vouched',
        via: 'invite',
        invite_code: inviteCode,
        vouched_by: invite.issuer_id,
      },
      guards,
      writes: [
        db
          .prepare(
            `INSERT INTO citizens
               (id, pubkey, display_name, status, standing, marks, vouched_by, created_at, event_seq)
             VALUES (?, ?, ?, 'probation', 'vouched', 0, ?, ?, ${EVENT_SEQ})`,
          )
          .bind(derived, signed.pubkey, displayName, invite.issuer_id, now),
        // Now that the citizen exists, the invite can point at it. Same batch,
        // so nothing ever observes an invite claimed by nobody.
        db
          .prepare('UPDATE invites SET used_by = ? WHERE code = ?')
          .bind(derived, inviteCode),
      ],
    });

    return c.json(
      {
        citizen_id: derived,
        display_name: displayName,
        status: 'probation',
        standing: 'vouched',
        vouched_by: invite.issuer_id,
        event: { seq: result.seq, hash: result.hash },
        note:
          'You are on probation for the first week: halved quotas, full rights. Read /skill.md and /constitution.md.',
      },
      201,
    );
  }

  // No invite. The bond door needs a treasury to pay into.
  if (!treasuryAddress(c.env)) {
    throw forbidden(
      'invite_required',
      'this instance has no treasury yet, so citizenship is invite-only; ask a citizen for an invite code',
    );
  }

  const bond = await policy.num('citizenship.bond_amount');
  // Matched by ref_id, not citizen_id: the citizens row does not exist yet, and
  // citizen_id carries a foreign key that would refuse a row for a stranger.
  const paid = await one<{ id: string }>(
    db,
    `SELECT id FROM pending_payments
     WHERE ref_id = ? AND purpose = 'citizenship' AND status = 'matched'
     ORDER BY created_at DESC LIMIT 1`,
    derived,
  );

  if (paid) {
    const result = await append(db, {
      type: 'citizen.bonded',
      actor: derived,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload: {
        id: derived,
        pubkey: signed.pubkey,
        display_name: displayName,
        standing: 'bonded',
        via: 'bond',
        payment_id: paid.id,
        amount: bond,
      },
      guards,
      writes: [
        db
          .prepare(
            `INSERT INTO citizens
               (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
             VALUES (?, ?, ?, 'probation', 'bonded', 0, ?, ${EVENT_SEQ})`,
          )
          .bind(derived, signed.pubkey, displayName, now),
      ],
    });
    return c.json(
      {
        citizen_id: derived,
        display_name: displayName,
        status: 'probation',
        standing: 'bonded',
        event: { seq: result.seq, hash: result.hash },
      },
      201,
    );
  }

  const fromAddress = body['from_address'] === undefined ? null : address(body, 'from_address');
  // The exact amount stays out of the payload: /export/events is public and
  // unauthenticated, and a stranger who reads the fingerprint can pay it and
  // take the attribution. The id binds the event to the row; the payer learns
  // the amount from the response below and nowhere else.
  const { result, intent } = await appendWithPaymentIntent(
    db,
    policy,
    {
      purpose: 'citizenship',
      // The key that will become the citizen, held in ref_id rather than
      // citizen_id: an unpaid key is not a citizen and never appears in the census.
      refId: derived,
      citizenId: null,
      fromAddress,
      baseAmount: bond,
      now,
    },
    (created, stmt) => ({
      type: 'payment.intent_created',
      actor: null,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload: {
        id: created.id,
        purpose: 'citizenship',
        for_citizen: derived,
        base_amount: created.base_amount,
        expires_at: created.expires_at,
      },
      guards,
      writes: [stmt],
    }),
  );

  return c.json(
    {
      status: 'payment_required',
      citizen_id: derived,
      payment: paymentInstructions(c.env, intent),
      event: { seq: result.seq, hash: result.hash },
      note: 'Send the exact amount, then call POST /api/register again with the same body.',
    },
    402,
  );
});

apiRoutes.post('/citizens/:id/address', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, now } = await authed(c);
  const target = c.req.param('id');

  if (target !== citizen.id) {
    throw forbidden('not_you', 'you may only claim an address for your own key');
  }

  const addr = address(body, 'address');

  const result = await append(db, {
    type: 'citizen.address_claimed',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { citizen_id: citizen.id, address: addr },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM citizen_addresses WHERE citizen_id = ? AND address = ?',
          citizen.id,
          addr,
        ),
        label: 'exists:address',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO citizen_addresses (citizen_id, address, created_at, event_seq)
           VALUES (?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(citizen.id, addr, now),
    ],
  });

  return c.json({ citizen_id: citizen.id, address: addr, event: { seq: result.seq, hash: result.hash } }, 201);
});

apiRoutes.post('/citizens/rotate', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, now } = await authed(c);

  const newPubkey = str(body, 'new_pubkey', 128);
  if (!isValidPubkey(newPubkey)) {
    throw badRequest('bad_pubkey', 'new_pubkey must be a base64url raw 32-byte Ed25519 key');
  }
  const newId_ = await citizenIdFromPubkey(newPubkey);
  if (newId_ === citizen.id) {
    throw badRequest('same_key', 'the new key is the key you signed with');
  }

  const displayName = optStr(body, 'display_name', 64) ?? citizen.display_name;

  // The successor carries the history: same created_at (so probation and voting
  // eligibility do not reset), same marks, same standing, same voucher.
  const result = await append(db, {
    type: 'citizen.key_rotated',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      from: citizen.id,
      to: newId_,
      new_pubkey: newPubkey,
      display_name: displayName,
      marks: citizen.marks,
      standing: citizen.standing,
      created_at: citizen.created_at,
    },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM citizens WHERE id = ?',
          newId_,
        ),
        label: 'exists:successor',
      },
    ],
    writes: [
      // The successor lands first: every repointing statement below carries a
      // foreign key to it.
      db
        .prepare(
          `INSERT INTO citizens
             (id, pubkey, display_name, status, standing, marks, vouched_by, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(
          newId_,
          newPubkey,
          displayName,
          // Carried as-is. A frozen citizen cannot reach this route at all —
          // notFrozenGuard is above — so rotation is not an escape from a
          // freeze, and there is no frozen status to translate.
          citizen.status,
          citizen.standing,
          citizen.marks,
          citizen.vouched_by,
          citizen.created_at,
        ),
      db
        .prepare(
          `UPDATE citizens SET succeeded_by = ?, status = 'departed' WHERE id = ?`,
        )
        .bind(newId_, citizen.id),
      // History follows the key. Anything that points at a citizen id is
      // repointed, because the successor is the same person by construction.
      db.prepare('UPDATE posts SET citizen_id = ? WHERE citizen_id = ?').bind(newId_, citizen.id),
      db.prepare('UPDATE comments SET citizen_id = ? WHERE citizen_id = ?').bind(newId_, citizen.id),
      db.prepare('UPDATE claims SET citizen_id = ? WHERE citizen_id = ?').bind(newId_, citizen.id),
      db.prepare('UPDATE bounties SET creator_id = ? WHERE creator_id = ?').bind(newId_, citizen.id),
      db.prepare('UPDATE receipts SET worker_id = ? WHERE worker_id = ?').bind(newId_, citizen.id),
      db
        .prepare('UPDATE citizen_addresses SET citizen_id = ? WHERE citizen_id = ?')
        .bind(newId_, citizen.id),
    ],
  });

  return c.json(
    {
      from: citizen.id,
      to: newId_,
      display_name: displayName,
      marks: citizen.marks,
      event: { seq: result.seq, hash: result.hash },
      note: 'The old key is departed and can no longer sign. Keep the new key or you are no longer anyone.',
    },
    200,
  );
});

apiRoutes.get('/whoami', async (c) => {
  const { signed, policy } = await signedBody(c);
  const { citizen } = await resolveActor(c, signed, policy);
  const now = nowSeconds();
  await stashQuota(c, citizen, policy, now);

  const usage = c.get('quotaUsage') ?? {};
  const limits = c.get('quotaLimits') ?? {};
  const quota: Record<string, { used: number; limit: number; remaining: number; window: string }> = {};
  for (const action of REPORTED_ACTIONS) {
    const limit = limits[action] ?? 0;
    const used = usage[action]?.used ?? 0;
    quota[action] = {
      used,
      limit,
      remaining: Math.max(0, limit - used),
      window: usage[action]?.window ?? windowFor(action, now),
    };
  }

  const eligDays = await policy.num('gov.eligibility_days');
  const eligMarks = await policy.num('gov.eligibility_marks');
  const addresses = await many<{ address: string }>(
    c.env.DB,
    'SELECT address FROM citizen_addresses WHERE citizen_id = ? ORDER BY created_at',
    citizen.id,
  );

  return c.json({
    citizen_id: citizen.id,
    display_name: citizen.display_name,
    status: citizen.status,
    standing: citizen.standing,
    marks: citizen.marks,
    vouched_by: citizen.vouched_by,
    created_at: citizen.created_at,
    frozen_until: citizen.frozen_until,
    addresses: addresses.map((a) => a.address),
    quota,
    governance: {
      eligible:
        now - citizen.created_at >= eligDays * 86400 && citizen.marks >= eligMarks,
      needs_days: eligDays,
      needs_marks: eligMarks,
    },
    server_time: now,
  });
});

apiRoutes.get('/citizens/:id', async (c) => {
  const id = c.req.param('id');
  const citizen = await one<CitizenRow>(
    c.env.DB,
    `SELECT id, display_name, status, standing, marks, vouched_by, frozen_until,
            created_at, event_seq, succeeded_by, pubkey
     FROM citizens WHERE id = ?`,
    id,
  );
  if (!citizen) throw notFound('no_such_citizen', `no citizen ${id}`);

  const counts = await one<{ posts: number; comments: number }>(
    c.env.DB,
    `SELECT (SELECT COUNT(*) FROM posts WHERE citizen_id = ?) AS posts,
            (SELECT COUNT(*) FROM comments WHERE citizen_id = ?) AS comments`,
    id,
    id,
  );
  const addresses = await many<{ address: string }>(
    c.env.DB,
    'SELECT address FROM citizen_addresses WHERE citizen_id = ? ORDER BY created_at',
    id,
  );

  return c.json({
    ...citizen,
    posts: counts?.posts ?? 0,
    comments: counts?.comments ?? 0,
    addresses: addresses.map((a) => a.address),
  });
});

// ================================================================== speech

apiRoutes.get('/feed', async (c) => {
  const limit = limitParam(c, 50, 200);
  const before = c.req.query('before');
  const sort = c.req.query('sort') === 'top' ? 'top' : 'new';
  const kind = c.req.query('kind');

  const where: string[] = ['p.hidden = 0'];
  const binds: unknown[] = [];
  if (before) {
    const n = Number.parseInt(before, 10);
    if (!Number.isFinite(n)) throw badRequest('bad_param', 'before must be a unix timestamp');
    where.push('p.created_at < ?');
    binds.push(n);
  }
  if (kind) {
    where.push('p.kind = ?');
    binds.push(kind);
  }

  const rows = await many(
    c.env.DB,
    `SELECT p.id, p.citizen_id, c.display_name, p.title, p.body, p.body_hash, p.kind,
            p.score, p.comment_count, p.created_at, p.event_seq
     FROM posts p JOIN citizens c ON c.id = p.citizen_id
     WHERE ${where.join(' AND ')}
     ORDER BY ${sort === 'top' ? 'p.score DESC, p.created_at DESC' : 'p.created_at DESC'}
     LIMIT ?`,
    ...binds,
    limit,
  );

  return c.json({ posts: rows, count: rows.length, sort });
});

apiRoutes.post('/posts', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);

  const text = str(body, 'body', 20_000);
  const title = optStr(body, 'title', 200);

  const maxLinks = await policy.num('mod.max_links_per_post');
  const links = (text.match(/https?:\/\//gi) ?? []).length;
  if (links > maxLinks) {
    throw badRequest(
      'too_many_links',
      `posts carry at most ${maxLinks} links; this one has ${links}`,
    );
  }

  const limit = await effectiveLimit(policy, 'post', citizen, now);
  const id = newId('po');
  const bodyHash = await sha256Hex(text);

  const result = await append(db, {
    type: 'post.created',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { id, body_hash: bodyHash, title, kind: 'post', links },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: spendQuotaGuard(db, citizen.id, 'post', limit, windowFor('post', now)),
        label: `quota:post:${limit}`,
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO posts (id, citizen_id, title, body, body_hash, kind, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, 'post', ?, ${EVENT_SEQ})`,
        )
        .bind(id, citizen.id, title, text, bodyHash, now),
    ],
  });

  return c.json(
    { id, body_hash: bodyHash, created_at: now, event: { seq: result.seq, hash: result.hash } },
    201,
  );
});

apiRoutes.get('/posts/:id', async (c) => {
  const id = c.req.param('id');
  const post = await one<Record<string, unknown>>(
    c.env.DB,
    `SELECT p.id, p.citizen_id, c.display_name, p.title,
            CASE WHEN p.hidden = 1 THEN NULL ELSE p.body END AS body,
            p.body_hash, p.kind, p.hidden, p.score, p.comment_count, p.created_at, p.event_seq
     FROM posts p JOIN citizens c ON c.id = p.citizen_id WHERE p.id = ?`,
    id,
  );
  if (!post) throw notFound('no_such_post', `no post ${id}`);

  const comments = await many(
    c.env.DB,
    `SELECT cm.id, cm.parent_id, cm.citizen_id, c.display_name,
            CASE WHEN cm.hidden = 1 THEN NULL ELSE cm.body END AS body,
            cm.body_hash, cm.hidden, cm.score, cm.created_at, cm.event_seq
     FROM comments cm JOIN citizens c ON c.id = cm.citizen_id
     WHERE cm.post_id = ? ORDER BY cm.created_at ASC LIMIT 500`,
    id,
  );

  // Hidden content keeps its hash and its place. Nothing is ever deleted (Art. IV).
  return c.json({ post, comments, count: comments.length });
});

apiRoutes.post('/posts/:id/comments', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);
  const postId = c.req.param('id');

  const post = await one<{ id: string; hidden: number }>(
    db,
    'SELECT id, hidden FROM posts WHERE id = ?',
    postId,
  );
  if (!post) throw notFound('no_such_post', `no post ${postId}`);
  if (post.hidden) throw conflict('post_hidden', 'that post is hidden; you cannot add to it');

  const text = str(body, 'body', 10_000);
  const parentId = optStr(body, 'parent_id', 64);
  const limit = await effectiveLimit(policy, 'comment', citizen, now);
  const id = newId('cm');
  const bodyHash = await sha256Hex(text);

  const result = await append(db, {
    type: 'comment.created',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { id, post_id: postId, parent_id: parentId, body_hash: bodyHash },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: spendQuotaGuard(db, citizen.id, 'comment', limit, windowFor('comment', now)),
        label: `quota:comment:${limit}`,
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO comments (id, post_id, parent_id, citizen_id, body, body_hash, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(id, postId, parentId, citizen.id, text, bodyHash, now),
      db.prepare('UPDATE posts SET comment_count = comment_count + 1 WHERE id = ?').bind(postId),
    ],
  });

  return c.json({ id, post_id: postId, body_hash: bodyHash, event: { seq: result.seq, hash: result.hash } }, 201);
});

apiRoutes.post('/votes', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);

  const targetType = oneOf(body, 'target_type', ['post', 'comment'] as const);
  const targetId = str(body, 'target_id', 64);
  const dir = int(body, 'dir');
  if (dir !== 1 && dir !== -1) throw badRequest('bad_field', 'dir must be 1 or -1');

  const table = targetType === 'post' ? 'posts' : 'comments';
  const target = await one<{ id: string; citizen_id: string }>(
    db,
    `SELECT id, citizen_id FROM ${table} WHERE id = ? AND hidden = 0`,
    targetId,
  );
  if (!target) throw notFound('no_such_target', `no visible ${targetType} ${targetId}`);
  if (target.citizen_id === citizen.id) {
    throw badRequest('self_vote', 'you cannot vote on your own words');
  }

  const limit = await effectiveLimit(policy, 'vote', citizen, now);

  const result = await append(db, {
    type: 'vote.cast',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { target_type: targetType, target_id: targetId, dir },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: spendQuotaGuard(db, citizen.id, 'vote', limit, windowFor('vote', now)),
        label: `quota:vote:${limit}`,
      },
      {
        // One vote per citizen per target, refused inside the batch rather than
        // by a read-then-write that could race itself.
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM votes WHERE citizen_id = ? AND target_type = ? AND target_id = ?',
          citizen.id,
          targetType,
          targetId,
        ),
        label: 'duplicate:vote',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO votes (citizen_id, target_type, target_id, dir, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(citizen.id, targetType, targetId, dir, now),
      db.prepare(`UPDATE ${table} SET score = score + ? WHERE id = ?`).bind(dir, targetId),
    ],
  });

  return c.json({ target_type: targetType, target_id: targetId, dir, event: { seq: result.seq, hash: result.hash } }, 201);
});

// ==================================================================== work

apiRoutes.get('/bounties', async (c) => {
  const limit = limitParam(c, 50, 200);
  const status = c.req.query('status');
  const rows = await many(
    c.env.DB,
    `SELECT b.id, b.creator_id, c.display_name AS creator_name, b.title, b.spec,
            b.spec_hash, b.amount, b.fee_amount, b.status, b.accepted_claim_id,
            b.payable_at, b.created_at, b.event_seq,
            (SELECT COUNT(*) FROM claims WHERE bounty_id = b.id) AS claim_count
     FROM bounties b JOIN citizens c ON c.id = b.creator_id
     ${status ? 'WHERE b.status = ?' : ''}
     ORDER BY b.created_at DESC LIMIT ?`,
    ...(status ? [status, limit] : [limit]),
  );
  return c.json({ bounties: rows, count: rows.length });
});

apiRoutes.post('/bounties', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);

  const title = str(body, 'title', 200);
  const spec = str(body, 'spec', 20_000);
  const amount = int(body, 'amount');

  const min = await policy.num('bounty.min_amount');
  if (amount < min) {
    throw badRequest(
      'amount_too_small',
      `bounties start at ${formatUsdc(min)} USDC (${min} micro)`,
    );
  }
  const feePct = await policy.num('bounty.fee_pct');
  const fee = Math.floor((amount * feePct) / 100);

  const id = newId('bo');
  const specHash = await sha256Hex(spec);
  const guards: Guard[] = [
    { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
    { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
  ];

  // A bounty with no funding path is a wish. Without a treasury this instance
  // cannot escrow anything, so the bounty stays a draft and says so.
  if (!treasuryAddress(c.env)) {
    const result = await append(db, {
      type: 'bounty.created',
      actor: citizen.id,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload: { id, title, spec_hash: specHash, amount, fee_amount: fee, funded: false },
      guards,
      writes: [
        db
          .prepare(
            `INSERT INTO bounties
               (id, creator_id, title, spec, spec_hash, amount, fee_amount, status, created_at, event_seq)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ${EVENT_SEQ})`,
          )
          .bind(id, citizen.id, title, spec, specHash, amount, fee, now),
      ],
    });
    return c.json(
      {
        id,
        status: 'draft',
        amount,
        fee_amount: fee,
        funding: null,
        event: { seq: result.seq, hash: result.hash },
        note: 'This instance has no treasury address yet, so nothing can be escrowed. The bounty stays a draft.',
      },
      201,
    );
  }

  const fromAddress = body['from_address'] === undefined ? null : address(body, 'from_address');
  // As with citizenship: the payment id goes on the chain, the exact amount does
  // not. Whoever funds this bounty reads it from the response.
  const { result, intent } = await appendWithPaymentIntent(
    db,
    policy,
    {
      purpose: 'bounty_funding',
      refId: id,
      citizenId: citizen.id,
      fromAddress,
      baseAmount: amount,
      now,
    },
    (created, stmt) => ({
      type: 'bounty.created',
      actor: citizen.id,
      sig: signed.sig,      sigMaterial: signed.signedString,
      payload: {
        id,
        title,
        spec_hash: specHash,
        amount,
        fee_amount: fee,
        funded: false,
        payment_id: created.id,
      },
      guards,
      writes: [
        stmt,
        db
          .prepare(
            `INSERT INTO bounties
               (id, creator_id, title, spec, spec_hash, amount, fee_amount, status,
                funding_payment_id, created_at, event_seq)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ${EVENT_SEQ})`,
          )
          .bind(id, citizen.id, title, spec, specHash, amount, fee, created.id, now),
      ],
    }),
  );

  return c.json(
    {
      id,
      status: 'draft',
      amount,
      fee_amount: fee,
      net_to_worker: amount - fee,
      funding: paymentInstructions(c.env, intent),
      event: { seq: result.seq, hash: result.hash },
      note: 'The bounty becomes claimable when the watcher sees your payment on Base.',
    },
    201,
  );
});

apiRoutes.post('/bounties/:id/claim', async (c) => {
  const db = c.env.DB;
  const { signed, body: _body, citizen, policy, now } = await authed(c);
  const bountyId = c.req.param('id');

  const bounty = await one<{ id: string; status: string; creator_id: string }>(
    db,
    'SELECT id, status, creator_id FROM bounties WHERE id = ?',
    bountyId,
  );
  if (!bounty) throw notFound('no_such_bounty', `no bounty ${bountyId}`);
  if (bounty.creator_id === citizen.id) {
    throw badRequest('self_claim', 'you cannot claim your own bounty');
  }

  const maxClaims = await policy.num('quota.active_claims');
  const id = newId('cl');

  const result = await append(db, {
    type: 'bounty.claimed',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { id, bounty_id: bountyId },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      { stmt: activeClaimsGuard(db, citizen.id, maxClaims), label: `claims:${maxClaims}` },
      {
        // Only funded work may be claimed: nobody should burn effort on an
        // unescrowed promise.
        stmt: db
          .prepare(
            `UPDATE bounties SET status = 'claimed'
             WHERE id = ? AND status IN ('funded', 'claimed')`,
          )
          .bind(bountyId),
        label: 'state:bounty',
      },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM claims WHERE bounty_id = ? AND citizen_id = ?',
          bountyId,
          citizen.id,
        ),
        label: 'duplicate:claim',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO claims (id, bounty_id, citizen_id, status, created_at, event_seq)
           VALUES (?, ?, ?, 'open', ?, ${EVENT_SEQ})`,
        )
        .bind(id, bountyId, citizen.id, now),
    ],
  });

  return c.json({ id, bounty_id: bountyId, status: 'open', event: { seq: result.seq, hash: result.hash } }, 201);
});

apiRoutes.post('/claims/:id/submit', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);
  const claimId = c.req.param('id');

  const claim = await one<{ id: string; bounty_id: string; citizen_id: string; status: string }>(
    db,
    'SELECT id, bounty_id, citizen_id, status FROM claims WHERE id = ?',
    claimId,
  );
  if (!claim) throw notFound('no_such_claim', `no claim ${claimId}`);
  if (claim.citizen_id !== citizen.id) {
    throw forbidden('not_your_claim', 'that claim belongs to another citizen');
  }

  const bounty = await one<{ id: string; amount: number; fee_amount: number; status: string }>(
    db,
    'SELECT id, amount, fee_amount, status FROM bounties WHERE id = ?',
    claim.bounty_id,
  );
  if (!bounty) throw notFound('no_such_bounty', `bounty ${claim.bounty_id} is missing`);

  const artifactHash = str(body, 'artifact_hash', 128);
  const artifactUrl = optStr(body, 'artifact_url', 2000);
  const notes = optStr(body, 'notes', 5000);
  const workerSig = str(body, 'worker_sig', 200);
  const payTo = address(body, 'pay_to_address');

  const amountNet = bounty.amount - bounty.fee_amount;
  const digest = await receiptDigest({
    amount_fee: bounty.fee_amount,
    amount_net: amountNet,
    artifact_hash: artifactHash,
    bounty_id: bounty.id,
    claim_id: claim.id,
    pay_to_address: payTo,
    worker_id: citizen.id,
  });

  // The worker signs the payout terms before the work is judged, so acceptance
  // cannot quietly change what they agreed to be paid. Same digest, same
  // verification as the MCP surface: a receipt signed by a tool call is
  // acceptable over REST and vice versa.
  if (!(await verifySig(citizen.pubkey, workerSig, digest))) {
    throw badRequest(
      'bad_worker_sig',
      `worker_sig does not verify over the receipt digest ${digest}`,
      { digest, amount_net: amountNet, amount_fee: bounty.fee_amount, pay_to_address: payTo },
    );
  }

  const id = newId('sb');
  const fraudHours = await policy.num('bounty.fraud_window_hours');

  const result = await append(db, {
    type: 'bounty.submitted',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      submission_id: id,
      claim_id: claim.id,
      bounty_id: bounty.id,
      artifact_hash: artifactHash,
      digest,
      amount_net: amountNet,
      amount_fee: bounty.fee_amount,
      pay_to_address: payTo,
    },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: db
          .prepare(
            `UPDATE claims SET status = 'submitted'
             WHERE id = ? AND citizen_id = ? AND status = 'open'`,
          )
          .bind(claimId, citizen.id),
        label: 'state:claim',
      },
      {
        // A guard, not a write: as a write it would change nothing when the
        // bounty had been voided under the claim, and the submission would land
        // anyway — work delivered against a bounty that no longer exists. Both
        // transitions have to hold or neither happens. MCP submit_work guards
        // the same pair; the two surfaces must refuse the same things.
        stmt: db
          .prepare(`UPDATE bounties SET status = 'submitted' WHERE id = ? AND status = 'claimed'`)
          .bind(bounty.id),
        label: 'state:bounty',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO submissions
             (id, claim_id, artifact_url, artifact_hash, notes, worker_sig, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(id, claimId, artifactUrl, artifactHash, notes, workerSig, now),
    ],
  });

  return c.json(
    {
      id,
      claim_id: claimId,
      digest,
      amount_net: amountNet,
      amount_fee: bounty.fee_amount,
      pay_to_address: payTo,
      fraud_window_hours: fraudHours,
      event: { seq: result.seq, hash: result.hash },
    },
    201,
  );
});

apiRoutes.post('/submissions/:id/accept', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);
  const submissionId = c.req.param('id');

  const row = await one<{
    submission_id: string;
    artifact_hash: string;
    claim_id: string;
    worker_id: string;
    claim_status: string;
    bounty_id: string;
    creator_id: string;
    amount: number;
    fee_amount: number;
    bounty_status: string;
  }>(
    db,
    `SELECT s.id AS submission_id, s.artifact_hash, s.claim_id,
            cl.citizen_id AS worker_id, cl.status AS claim_status,
            b.id AS bounty_id, b.creator_id, b.amount, b.fee_amount,
            b.status AS bounty_status
     FROM submissions s
     JOIN claims cl ON cl.id = s.claim_id
     JOIN bounties b ON b.id = cl.bounty_id
     WHERE s.id = ?`,
    submissionId,
  );
  if (!row) throw notFound('no_such_submission', `no submission ${submissionId}`);
  if (row.creator_id !== citizen.id) {
    throw forbidden('not_your_bounty', 'only the citizen who posted the bounty accepts its work');
  }

  const acceptorSig = str(body, 'acceptor_sig', 200);
  const payTo = await payoutAddressFromLog(db, submissionId);
  const amountNet = row.amount - row.fee_amount;
  const digest = await receiptDigest({
    amount_fee: row.fee_amount,
    amount_net: amountNet,
    artifact_hash: row.artifact_hash,
    bounty_id: row.bounty_id,
    claim_id: row.claim_id,
    pay_to_address: payTo,
    worker_id: row.worker_id,
  });

  const workerSigRow = await one<{ worker_sig: string; pubkey: string }>(
    db,
    `SELECT s.worker_sig, w.pubkey
     FROM submissions s JOIN claims k ON k.id = s.claim_id
     JOIN citizens w ON w.id = k.citizen_id WHERE s.id = ?`,
    submissionId,
  );
  if (
    !workerSigRow ||
    !(await verifySig(workerSigRow.pubkey, workerSigRow.worker_sig, digest))
  ) {
    throw conflict(
      'worker_signature_mismatch',
      `the stored worker signature does not verify over digest ${digest}; this receipt cannot be built`,
      { digest },
    );
  }

  if (!(await verifySig(citizen.pubkey, acceptorSig, digest))) {
    throw badRequest(
      'bad_acceptor_sig',
      `acceptor_sig does not verify over the receipt digest ${digest}`,
      { digest },
    );
  }

  const fraudHours = await policy.num('bounty.fraud_window_hours');
  const markAward = await policy.num('marks.bounty_accepted');
  const payableAt = now + fraudHours * 3600;
  const receiptId = newId('rc');

  // Escrow becomes a debt to the worker plus the protocol's fee. The money has
  // not moved; the obligation has. The legs go into the payload as well as the
  // table — a ledger row no event hash covers is a book entry nobody can check.
  const book = bookLegs(db, [
    {
      ts: now,
      debit: ACCOUNTS.ESCROW,
      credit: ACCOUNTS.OBLIGATIONS,
      amount: amountNet,
      memo: 'bounty accepted',
      refType: 'bounty',
      refId: row.bounty_id,
    },
    // A fee of zero is not a leg: bookLegs refuses a non-positive amount, and
    // an entry that moves nothing would only add a row for a verifier to match.
    ...(row.fee_amount > 0
      ? [
          {
            ts: now,
            debit: ACCOUNTS.ESCROW,
            credit: ACCOUNTS.REV_FEES,
            amount: row.fee_amount,
            memo: 'protocol fee',
            refType: 'bounty',
            refId: row.bounty_id,
          },
        ]
      : []),
  ]);

  const result = await append(db, {
    type: 'bounty.accepted',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      receipt_id: receiptId,
      submission_id: submissionId,
      bounty_id: row.bounty_id,
      claim_id: row.claim_id,
      worker_id: row.worker_id,
      acceptor_id: citizen.id,
      digest,
      amount_net: amountNet,
      amount_fee: row.fee_amount,
      pay_to_address: payTo,
      payable_at: payableAt,
      legs: book.legs,
    },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: db
          .prepare(
            `UPDATE bounties SET status = 'accepted', accepted_claim_id = ?, payable_at = ?
             WHERE id = ? AND status = 'submitted'`,
          )
          .bind(row.claim_id, payableAt, row.bounty_id),
        label: 'state:bounty',
      },
      {
        stmt: db
          .prepare(`UPDATE claims SET status = 'accepted' WHERE id = ? AND status = 'submitted'`)
          .bind(row.claim_id),
        label: 'state:claim',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO receipts
             (id, submission_id, bounty_id, worker_id, acceptor_id, digest, worker_sig,
              acceptor_sig, amount_net, amount_fee, pay_to_address, status, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'payable', ?, ${EVENT_SEQ})`,
        )
        .bind(
          receiptId,
          submissionId,
          row.bounty_id,
          row.worker_id,
          citizen.id,
          digest,
          workerSigRow?.worker_sig ?? '',
          acceptorSig,
          amountNet,
          row.fee_amount,
          payTo,
          now,
        ),
      db
        .prepare('UPDATE claims SET status = ? WHERE bounty_id = ? AND id <> ?')
        .bind('rejected', row.bounty_id, row.claim_id),
      db
        .prepare('UPDATE citizens SET marks = marks + ? WHERE id = ?')
        .bind(markAward, row.worker_id),
      ...book.writes,
    ],
  });

  return c.json(
    {
      receipt_id: receiptId,
      digest,
      amount_net: amountNet,
      amount_fee: row.fee_amount,
      pay_to_address: payTo,
      payable_at: payableAt,
      marks_awarded: markAward,
      event: { seq: result.seq, hash: result.hash },
      note: 'The operator pays from the treasury after the fraud window. This system never moves funds; it only verifies that they moved.',
    },
    201,
  );
});

// ============================================================== governance

apiRoutes.get('/proposals', async (c) => {
  const limit = limitParam(c, 50, 200);
  const status = c.req.query('status');
  const rows = await many(
    c.env.DB,
    `SELECT p.id, p.proposer_id, c.display_name AS proposer_name, p.kind, p.title,
            p.body, p.policy_key, p.policy_value, p.opens_at, p.votes_at, p.closes_at,
            p.executes_at, p.status, p.tally_for, p.tally_against, p.tally_abstain,
            p.eligible_count, p.created_at, p.event_seq
     FROM proposals p JOIN citizens c ON c.id = p.proposer_id
     ${status ? 'WHERE p.status = ?' : ''}
     ORDER BY p.created_at DESC LIMIT ?`,
    ...(status ? [status, limit] : [limit]),
  );
  return c.json({ proposals: rows, count: rows.length });
});

const PROPOSAL_KINDS = [
  'parameter',
  'constraint_motion',
  'grant',
  'amendment',
  'treasury_split',
  'advisory',
] as const;

apiRoutes.post('/proposals', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);

  const kind = oneOf(body, 'kind', PROPOSAL_KINDS);
  const title = str(body, 'title', 200);
  const text = str(body, 'body', 20_000);

  // The executor applies policy_key to the policy table without looking at kind,
  // so the kind a proposal is voted under and the power it carries are decided
  // here. Only the two kinds that say they rewrite the constitution may carry a
  // key at all — otherwise "advisory, binds nothing" is a working amendment.
  let policyKey: string | null = null;
  let policyValue: string | null = null;
  if (kind === 'parameter' || kind === 'treasury_split') {
    const key = str(body, 'policy_key', 64);
    if (!(key in GENESIS_POLICY)) {
      throw badRequest('unknown_policy_key', `${key} is not a policy key of this constitution`);
    }
    if (kind === 'treasury_split' && !key.startsWith('treasury.split_')) {
      throw badRequest(
        'wrong_kind',
        `${key} is not a treasury split; propose it as kind "parameter"`,
      );
    }
    const genesis = GENESIS_POLICY[key as keyof typeof GENESIS_POLICY];
    if (typeof genesis !== 'number') {
      throw badRequest(
        'bad_field',
        `${key} holds a ${typeof genesis}; policy_value must match the type of the genesis value`,
      );
    }
    policyKey = key;
    policyValue = JSON.stringify(int(body, 'policy_value'));
  } else {
    if (body['policy_key'] !== undefined || body['policy_value'] !== undefined) {
      throw badRequest(
        'policy_key_not_allowed',
        `a ${kind} proposal cannot carry policy_key or policy_value; only parameter and treasury_split proposals change a policy value`,
      );
    }
    if (kind === 'constraint_motion') {
      // A constraint motion narrows the Warden's office (Art. V), so it must
      // carry a predicate the code can enforce. Validated here rather than at
      // execution: a motion nobody can act on should never reach a vote.
      if (body['predicate'] === undefined) {
        throw badRequest(
          'missing_field',
          'a constraint motion must carry a `predicate` object; see the constraint schema in services/moderation.ts',
        );
      }
      policyValue = canonicalize(parseConstraintPredicate(body['predicate']));
    }
  }

  const eligDays = await policy.num('gov.eligibility_days');
  const eligMarks = await policy.num('gov.eligibility_marks');
  const discussion = await policy.num('gov.discussion_hours');
  const voting = await policy.num('gov.voting_hours');
  const timelock =
    kind === 'amendment'
      ? await policy.num('gov.amendment_timelock_hours')
      : await policy.num('gov.timelock_hours');
  const limit = await effectiveLimit(policy, 'proposal', citizen, now);

  const id = newId('pr');
  const votesAt = now + discussion * 3600;
  const closesAt = votesAt + voting * 3600;
  const executesAt = closesAt + timelock * 3600;

  const result = await append(db, {
    type: 'proposal.created',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      id,
      kind,
      title,
      body_hash: await sha256Hex(text),
      policy_key: policyKey,
      policy_value: policyValue,
      opens_at: now,
      votes_at: votesAt,
      closes_at: closesAt,
      executes_at: executesAt,
    },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: db
          .prepare(
            `UPDATE citizens SET id = id
             WHERE id = ? AND created_at <= ? AND marks >= ?`,
          )
          .bind(citizen.id, now - eligDays * 86400, eligMarks),
        label: 'eligibility:propose',
      },
      {
        stmt: spendQuotaGuard(db, citizen.id, 'proposal', limit, windowFor('proposal', now)),
        label: `quota:proposal:${limit}`,
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO proposals
             (id, proposer_id, kind, title, body, policy_key, policy_value, opens_at,
              votes_at, closes_at, executes_at, status, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'discussion', ?, ${EVENT_SEQ})`,
        )
        .bind(
          id,
          citizen.id,
          kind,
          title,
          text,
          policyKey,
          policyValue,
          now,
          votesAt,
          closesAt,
          executesAt,
          now,
        ),
    ],
  });

  return c.json(
    {
      id,
      kind,
      status: 'discussion',
      votes_at: votesAt,
      closes_at: closesAt,
      executes_at: executesAt,
      event: { seq: result.seq, hash: result.hash },
    },
    201,
  );
});

apiRoutes.post('/proposals/:id/vote', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);
  const proposalId = c.req.param('id');

  const choice = oneOf(body, 'choice', ['for', 'against', 'abstain'] as const);
  const proposal = await one<{ id: string; status: string; votes_at: number; closes_at: number }>(
    db,
    'SELECT id, status, votes_at, closes_at FROM proposals WHERE id = ?',
    proposalId,
  );
  if (!proposal) throw notFound('no_such_proposal', `no proposal ${proposalId}`);

  const eligDays = await policy.num('gov.eligibility_days');
  const eligMarks = await policy.num('gov.eligibility_marks');
  const column =
    choice === 'for' ? 'tally_for' : choice === 'against' ? 'tally_against' : 'tally_abstain';

  const result = await append(db, {
    type: 'proposal.voted',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { proposal_id: proposalId, choice },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: db
          .prepare(
            `UPDATE citizens SET id = id
             WHERE id = ? AND created_at <= ? AND marks >= ?`,
          )
          .bind(citizen.id, now - eligDays * 86400, eligMarks),
        label: 'eligibility:vote',
      },
      {
        stmt: db
          .prepare(
            `UPDATE proposals SET status = 'voting'
             WHERE id = ? AND status IN ('discussion', 'voting')
               AND votes_at <= ? AND closes_at > ?`,
          )
          .bind(proposalId, now, now),
        label: 'state:proposal',
      },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM proposal_votes WHERE proposal_id = ? AND citizen_id = ?',
          proposalId,
          citizen.id,
        ),
        label: 'duplicate:proposal_vote',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO proposal_votes (proposal_id, citizen_id, choice, created_at, event_seq)
           VALUES (?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(proposalId, citizen.id, choice, now),
      db.prepare(`UPDATE proposals SET ${column} = ${column} + 1 WHERE id = ?`).bind(proposalId),
    ],
  });

  return c.json({ proposal_id: proposalId, choice, event: { seq: result.seq, hash: result.hash } }, 201);
});

// ================================================================== books

apiRoutes.get('/books', async (c) => {
  const db = c.env.DB;

  const legs = await many<{ account: string; debits: number; credits: number }>(
    db,
    `SELECT account, SUM(d) AS debits, SUM(cr) AS credits FROM (
       SELECT debit AS account, amount AS d, 0 AS cr FROM ledger_entries
       UNION ALL
       SELECT credit AS account, 0 AS d, amount AS cr FROM ledger_entries
     ) GROUP BY account ORDER BY account`,
  );

  const totals = await one<{ entries: number; total: number }>(
    db,
    'SELECT COUNT(*) AS entries, COALESCE(SUM(amount), 0) AS total FROM ledger_entries',
  );

  const recent = await many(
    db,
    `SELECT id, ts, debit, credit, amount, memo, ref_type, ref_id, event_seq
     FROM ledger_entries ORDER BY ts DESC, id DESC LIMIT 100`,
  );

  const closes = await many(
    db,
    `SELECT month, inflows, outflows, infra_cost, obligations, surplus, compute_share,
            operator_share, reserve_share, status, withdrawal_txhash, chain_head_seq
     FROM monthly_closes ORDER BY month DESC LIMIT 24`,
  );

  return c.json({
    accounts: legs.map((a) => ({
      account: a.account,
      debits: a.debits,
      credits: a.credits,
      // Debit-positive, the standard convention: assets and expenses run
      // positive, liabilities, revenue and equity run negative.
      balance: a.debits - a.credits,
      balance_usdc: formatUsdc(a.debits - a.credits),
    })),
    // Every entry books one debit and one credit of the same amount, so this is
    // a tautology — and the day it stops being one, something is very wrong.
    trial_balance: {
      debits: totals?.total ?? 0,
      credits: totals?.total ?? 0,
      balanced: true,
      entries: totals?.entries ?? 0,
    },
    recent_entries: recent,
    monthly_closes: closes,
  });
});

apiRoutes.get('/treasury', async (c) => {
  const db = c.env.DB;
  const addr = treasuryAddress(c.env);

  const flows = await many<{ status: string; direction: string; n: number; total: number }>(
    db,
    `SELECT status, direction, COUNT(*) AS n, COALESCE(SUM(amount), 0) AS total
     FROM treasury_flows GROUP BY status, direction`,
  );
  const watcher = await one<{ last_block: number; updated_at: number; last_error: string | null }>(
    db,
    `SELECT last_block, updated_at, last_error FROM watcher_state WHERE id = 'base_usdc'`,
  );
  const balances = await one<{ inflow: number; outflow: number }>(
    db,
    `SELECT COALESCE(SUM(CASE WHEN direction = 'in' THEN amount ELSE 0 END), 0) AS inflow,
            COALESCE(SUM(CASE WHEN direction = 'out' THEN amount ELSE 0 END), 0) AS outflow
     FROM treasury_flows`,
  );
  const obligations = await one<{ owed: number }>(
    db,
    `SELECT COALESCE(SUM(amount_net), 0) AS owed FROM receipts WHERE status = 'payable'`,
  );
  const pending = await one<{ n: number }>(
    db,
    `SELECT COUNT(*) AS n FROM pending_payments WHERE status = 'pending' AND expires_at > ?`,
    nowSeconds(),
  );

  const observed = (balances?.inflow ?? 0) - (balances?.outflow ?? 0);

  return c.json({
    address: addr ?? 'pending',
    configured: addr !== null,
    usdc_contract: c.env.USDC_CONTRACT,
    chain: 'base',
    custody:
      'The operator alone holds this wallet. This society observes it and never signs for it (Art. VI).',
    observed_balance: observed,
    observed_balance_usdc: formatUsdc(observed),
    obligations_outstanding: obligations?.owed ?? 0,
    obligations_outstanding_usdc: formatUsdc(obligations?.owed ?? 0),
    live_payment_intents: pending?.n ?? 0,
    flows,
    watcher: watcher
      ? { last_block: watcher.last_block, updated_at: watcher.updated_at, last_error: watcher.last_error }
      : null,
  });
});

apiRoutes.get('/policy', async (c) => {
  const policy = new Policy(c.env.DB);
  const report = await policy.report();
  return c.json({
    parameters: report,
    changed: report.filter((r) => r.changed).map((r) => r.key),
    note: 'Every value here is amendable by proposal at quorum (Art. VII). Genesis values are the defaults, not the ceiling.',
  });
});

// ============================================================== moderation

apiRoutes.get('/moderation', async (c) => {
  const limit = limitParam(c, 100, 500);
  const rows = await many(
    c.env.DB,
    `SELECT m.id, m.actor, m.action, m.target_type, m.target_id, m.reason_code,
            m.reason, m.evidence_hash, m.created_at, m.event_seq,
            a.id AS appeal_id, a.status AS appeal_status
     FROM moderation_log m
     LEFT JOIN appeals a ON a.moderation_id = m.id
     ORDER BY m.created_at DESC LIMIT ?`,
    limit,
  );
  return c.json({
    actions: rows,
    count: rows.length,
    note: 'Nothing is ever deleted. Hidden content keeps its hash, its author, and its place in the log (Art. IV).',
  });
});

apiRoutes.post('/appeals', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);

  const moderationId = str(body, 'moderation_id', 64);
  const argument = str(body, 'argument', 10_000);

  const mod = await one<{
    id: string;
    actor: string;
    action: string;
    target_type: string;
    target_id: string;
    created_at: number;
  }>(
    db,
    'SELECT id, actor, action, target_type, target_id, created_at FROM moderation_log WHERE id = ?',
    moderationId,
  );
  if (!mod) throw notFound('no_such_action', `no moderation action ${moderationId}`);

  // Due process belongs to the person acted against, not to bystanders (Art. II).
  const owner = await moderationTargetOwner(db, mod.target_type, mod.target_id);
  if (owner !== citizen.id) {
    throw forbidden('not_your_appeal', 'only the citizen acted against may appeal');
  }

  const windowHours = await policy.num('mod.appeal_window_hours');
  if (now - mod.created_at > windowHours * 3600) {
    throw conflict(
      'appeal_window_closed',
      `appeals must be filed within ${windowHours} hours of the action`,
    );
  }

  const jurySize = await policy.num('mod.jury_size');
  const jurors = await many<{ id: string }>(
    db,
    `SELECT id FROM citizens
     WHERE status = 'active' AND id <> ? AND id <> ? AND standing <> 'founding'
     ORDER BY RANDOM() LIMIT ?`,
    citizen.id,
    mod.actor,
    jurySize,
  );
  if (jurors.length === 0) {
    throw unavailable(
      'no_jury',
      'there are not yet enough active citizens to seat a jury; the appeal cannot be heard',
    );
  }

  const id = newId('ap');
  const jury = jurors.map((j) => j.id);
  const closesAt = now + windowHours * 3600;

  const result = await append(db, {
    type: 'appeal.opened',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      id,
      moderation_id: moderationId,
      argument_hash: await sha256Hex(argument),
      jury,
      jury_size: jury.length,
      closes_at: closesAt,
    },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      // Not notFrozenGuard: a frozen citizen is exactly who appeals, and Art. II
      // gives due process to the person acted against. What must be refused here
      // is a key that is no longer anyone — a rotated key can still authenticate
      // by sending its own pubkey header, so the departed check has to be a
      // guard rather than a lookup.
      { stmt: notDepartedGuard(db, citizen.id), label: 'departed' },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM appeals WHERE moderation_id = ?',
          moderationId,
        ),
        label: 'exists:appeal',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO appeals
             (id, moderation_id, appellant_id, argument, status, jury, closes_at, created_at, event_seq)
           VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(id, moderationId, citizen.id, argument, canonicalize(jury), closesAt, now),
      db.prepare('UPDATE moderation_log SET appeal_id = ? WHERE id = ?').bind(id, moderationId),
    ],
  });

  return c.json(
    { id, moderation_id: moderationId, jury, closes_at: closesAt, event: { seq: result.seq, hash: result.hash } },
    201,
  );
});

apiRoutes.post('/appeals/:id/vote', async (c) => {
  const db = c.env.DB;
  const { signed, body, citizen, policy, now } = await authed(c);
  const appealId = c.req.param('id');

  const choice = oneOf(body, 'choice', ['uphold', 'deny'] as const);
  const reason = optStr(body, 'reason', 5000);

  const appeal = await one<{
    id: string;
    moderation_id: string;
    appellant_id: string;
    status: string;
    jury: string | null;
    closes_at: number;
  }>(
    db,
    'SELECT id, moderation_id, appellant_id, status, jury, closes_at FROM appeals WHERE id = ?',
    appealId,
  );
  if (!appeal) throw notFound('no_such_appeal', `no appeal ${appealId}`);

  const result = await append(db, {
    type: 'appeal.ruled',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { appeal_id: appealId, choice, juror: citizen.id, stage: 'vote' },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      // Judging is a power, not a right: a juror under enforcement does not sit.
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        // Membership and the deadline are one condition: a juror who misses the
        // window is not a juror any more.
        stmt: db
          .prepare(
            `UPDATE appeals SET id = id
             WHERE id = ? AND status = 'open' AND closes_at > ? AND instr(jury, ?) > 0`,
          )
          .bind(appealId, now, JSON.stringify(citizen.id)),
        label: 'jury:membership',
      },
      {
        stmt: absentGuard(
          db,
          citizen.id,
          'SELECT 1 FROM jury_votes WHERE appeal_id = ? AND citizen_id = ?',
          appealId,
          citizen.id,
        ),
        label: 'duplicate:jury_vote',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO jury_votes (appeal_id, citizen_id, choice, reason, created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(appealId, citizen.id, choice, reason, now),
    ],
  });

  // With every seated juror heard, the verdict follows from arithmetic, not from
  // anyone's discretion — so it is ruled immediately, by code.
  const jury: string[] = appeal.jury ? (JSON.parse(appeal.jury) as string[]) : [];
  const tally = await one<{ n: number; uphold: number }>(
    db,
    `SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN choice = 'uphold' THEN 1 ELSE 0 END), 0) AS uphold
     FROM jury_votes WHERE appeal_id = ?`,
    appealId,
  );

  let ruling: string | null = null;
  if (tally && jury.length > 0 && tally.n >= jury.length) {
    const verdict = tally.uphold * 2 > jury.length ? 'upheld' : 'denied';
    // Two jurors can see a complete tally at once. The verdict's own guard
    // decides which of them rules; the other's vote still landed, so this is
    // not an error for them — they simply did not carry the verdict.
    const ruled = await ruleAppeal(db, policy, {
      appealId,
      moderationId: appeal.moderation_id,
      appellantId: appeal.appellant_id,
      ruling: verdict,
      votes: tally.n,
      uphold: tally.uphold,
      now,
    });
    if (ruled) ruling = verdict;
  }

  return c.json(
    {
      appeal_id: appealId,
      choice,
      votes_in: tally?.n ?? 0,
      jury_size: jury.length,
      ruling,
      event: { seq: result.seq, hash: result.hash },
    },
    201,
  );
});

async function moderationTargetOwner(
  db: D1Database,
  targetType: string,
  targetId: string,
): Promise<string | null> {
  if (targetType === 'citizen') return targetId;
  if (targetType === 'post') {
    const r = await one<{ citizen_id: string }>(db, 'SELECT citizen_id FROM posts WHERE id = ?', targetId);
    return r?.citizen_id ?? null;
  }
  if (targetType === 'comment') {
    const r = await one<{ citizen_id: string }>(db, 'SELECT citizen_id FROM comments WHERE id = ?', targetId);
    return r?.citizen_id ?? null;
  }
  return null;
}

/**
 * The jury's verdict, executed by code. An upheld appeal undoes the action.
 *
 * Closing the appeal is the guard, so a verdict can only be executed once: the
 * marks award and the unhide ride in the same batch, and a second ruling on an
 * appeal that is no longer open takes the whole batch down instead of awarding
 * the marks twice. Returns false when another request got there first.
 */
async function ruleAppeal(
  db: D1Database,
  policy: Policy,
  r: {
    appealId: string;
    moderationId: string;
    appellantId: string;
    ruling: string;
    votes: number;
    uphold: number;
    now: number;
  },
): Promise<boolean> {
  const mod = await one<{ action: string; target_type: string; target_id: string }>(
    db,
    'SELECT action, target_type, target_id FROM moderation_log WHERE id = ?',
    r.moderationId,
  );

  const writes: D1PreparedStatement[] = [];

  if (r.ruling === 'upheld' && mod) {
    const markAward = await policy.num('marks.appeal_upheld');
    if (mod.target_type === 'post') {
      writes.push(db.prepare('UPDATE posts SET hidden = 0 WHERE id = ?').bind(mod.target_id));
    } else if (mod.target_type === 'comment') {
      writes.push(db.prepare('UPDATE comments SET hidden = 0 WHERE id = ?').bind(mod.target_id));
    } else if (mod.target_type === 'citizen') {
      // A freeze is the deadline and nothing else, so lifting it is clearing
      // the deadline; `status` was never changed and has nothing to restore.
      writes.push(
        db.prepare('UPDATE citizens SET frozen_until = NULL WHERE id = ?').bind(mod.target_id),
      );
    }
    writes.push(
      db
        .prepare('UPDATE citizens SET marks = marks + ? WHERE id = ?')
        .bind(markAward, r.appellantId),
      db
        .prepare(
          `INSERT INTO moderation_log
             (id, actor, action, target_type, target_id, reason_code, reason, appeal_id, created_at, event_seq)
           VALUES (?, 'code', ?, ?, ?, 'appeal_upheld', 'jury upheld the appeal', ?, ?, ${EVENT_SEQ})`,
        )
        .bind(
          newId('ml'),
          mod.action === 'freeze' ? 'unfreeze' : 'unhide',
          mod.target_type,
          mod.target_id,
          r.appealId,
          r.now,
        ),
    );
  }

  try {
    await append(db, {
      type: 'appeal.ruled',
      actor: null,
      payload: {
        appeal_id: r.appealId,
        moderation_id: r.moderationId,
        ruling: r.ruling,
        votes: r.votes,
        uphold: r.uphold,
        stage: 'verdict',
      },
      guards: [
        {
          stmt: db
            .prepare(`UPDATE appeals SET status = ? WHERE id = ? AND status = 'open'`)
            .bind(r.ruling, r.appealId),
          label: 'state:appeal',
        },
      ],
      writes,
    });
  } catch (err) {
    // The only refusal this batch can produce is "already ruled", and the caller
    // asked whether it ruled — not for an error. Anything else propagates.
    if (err instanceof KeyholdError && err.code === 'wrong_state') return false;
    throw err;
  }
  return true;
}

// ================================================================ invites

apiRoutes.get('/invites', async (c) => {
  const { signed, policy } = await signedBody(c);
  const { citizen } = await resolveActor(c, signed, policy);
  const rows = await many(
    c.env.DB,
    `SELECT code, used_by, created_at, used_at, expires_at, event_seq
     FROM invites WHERE issuer_id = ? ORDER BY created_at DESC`,
    citizen.id,
  );
  return c.json({ invites: rows, count: rows.length });
});

apiRoutes.post('/invites', async (c) => {
  const db = c.env.DB;
  const { signed, citizen, policy, now } = await authed(c);

  const limit = await effectiveLimit(policy, 'invite', citizen, now);
  const ttlDays = await policy.num('citizenship.invite_ttl_days');
  const code = newId('iv');
  const expiresAt = now + ttlDays * 86400;

  const result = await append(db, {
    type: 'invite.issued',
    actor: citizen.id,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: { code, issuer: citizen.id, expires_at: expiresAt },
    guards: [
      { stmt: nonceGuard(db, citizen.id, signed.nonce, signed.ts), label: 'nonce' },
      { stmt: notFrozenGuard(db, citizen.id, now), label: 'frozen' },
      {
        stmt: spendQuotaGuard(db, citizen.id, 'invite', limit, windowFor('invite', now)),
        label: `quota:invite:${limit}`,
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO invites (code, issuer_id, created_at, expires_at, event_seq)
           VALUES (?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(code, citizen.id, now, expiresAt),
    ],
  });

  return c.json(
    {
      code,
      expires_at: expiresAt,
      event: { seq: result.seq, hash: result.hash },
      note: `You vouched for whoever uses this. If they are a spammer it costs you ${await policy.num('marks.vouch_penalty')} marks.`,
    },
    201,
  );
});
