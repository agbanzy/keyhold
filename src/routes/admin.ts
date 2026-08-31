/**
 * The Warden and operator surface.
 *
 * Nothing here is privileged in the usual sense: an admin action is an ordinary
 * signed request that appends an ordinary event to the same chain everyone
 * exports. The only difference is which key signed it, and that difference is
 * visible in the log forever.
 *
 * The Warden's powers are enumerated in constitution.ts and enforced at the
 * chokepoint in services/moderation.ts, which also applies whatever binding
 * constraint motions the citizens have voted onto the office (Art. V). This file
 * never decides what the Warden may do; it asks.
 *
 * The operator's powers are money-shaped and entirely retrospective: it queues
 * payouts, pays them from a wallet this code cannot touch, and then asks us to
 * verify on-chain that it did. We never sign a transaction (Art. VI).
 */

import { Hono, type Context } from 'hono';
import { isWardenKey, nonceGuard } from '../core/auth';
import {
  ACCOUNTS,
  ACCOUNT_FOR_PURPOSE,
  PAYMENT_PURPOSES,
  REASON_CODES,
  type WardenPower,
} from '../core/constitution';
import { newId, sha256Hex } from '../core/crypto';
import { formatUsdc, many, one, treasuryAddress, type Env } from '../core/db';
import {
  ChainConflictError,
  GuardFailedError,
  appendEvent,
  nowSeconds,
  readHead,
  type AppendInput,
  type AppendResult,
} from '../core/events';
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
  unavailable,
} from '../core/errors';
import { Policy, setPolicyStatement } from '../services/policy';
import { effectiveLimit, spendQuotaGuard, windowFor } from '../services/quotas';
import { dailyWitnessJob } from '../witness/checkpoint';
// The single chokepoint for "may the Warden do this?". Deliberately not
// re-implemented here: a second copy of a power check is a second thing to
// forget to narrow when a constraint motion passes.
import { POWER_FOR_ACTION, assertWardenMay } from '../services/moderation';
// Legs go into the payload as well as the table: a ledger row that no event
// hash covers is a book entry the verifier cannot check.
import { bookLeg, bookLegs, type LedgerLeg } from '../services/ledger';
// On-chain verification of a payout the operator already made. Read-only RPC.
import { verifyPayout } from '../watcher/base';
import {
  EVENT_SEQ,
  address,
  append,
  guardRefusal,
  int,
  lookupPubkey,
  oneOf,
  optStr,
  parseJsonObject,
  str,
  type AppEnv,
  type CitizenRow,
  type Guard,
} from './api';
import { verifyRequest, type SignedRequest } from '../core/auth';

export const adminRoutes = new Hono<AppEnv>();

type Office = 'warden' | 'operator';

interface AdminRequest {
  signed: SignedRequest;
  body: Record<string, unknown>;
  offices: Office[];
  policy: Policy;
  now: number;
}

/**
 * Authenticate an admin request and establish which office it speaks for. A key
 * may hold both; it never holds neither and gets through.
 */
async function admin(
  c: Context<AppEnv>,
  required: Office,
): Promise<AdminRequest> {
  const raw = new Uint8Array(await c.req.arrayBuffer());
  const path = new URL(c.req.url).pathname;

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

  const offices: Office[] = [];
  if (isWardenKey(signed.pubkey, c.env.WARDEN_PUBKEYS ?? '')) offices.push('warden');
  if (c.env.OPERATOR_PUBKEY?.trim() && c.env.OPERATOR_PUBKEY.trim() === signed.pubkey) {
    offices.push('operator');
  }

  if (!offices.includes(required)) {
    throw forbidden(
      'not_' + required,
      required === 'warden'
        ? 'this action is reserved to a key listed in WARDEN_PUBKEYS'
        : 'this action is reserved to the operator key',
    );
  }

  c.set('citizenId', signed.citizenId);
  return { signed, body: parseJsonObject(raw), offices, policy, now: nowSeconds() };
}

/**
 * Append where a domain write needs the event's seq as a number rather than as
 * the `(SELECT seq FROM chain_head)` subquery — policy rows, whose helper takes
 * an integer. The statements are rebuilt on every attempt, because a retry that
 * reused a stale seq would file the row under the wrong event.
 */
export async function appendWithSeq(
  db: D1Database,
  build: (seq: number) => Omit<AppendInput, 'guards'> & { guards?: Guard[] },
  attempts = 4,
): Promise<AppendResult> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    const head = await readHead(db);
    const input = build(head.seq + 1);
    const guards = input.guards ?? [];
    try {
      return await appendEvent(db, { ...input, guards: guards.map((g) => g.stmt) });
    } catch (err) {
      if (err instanceof GuardFailedError) {
        throw guardRefusal(guards[err.index]?.label ?? 'unknown');
      }
      if (!(err instanceof ChainConflictError)) throw err;
      last = err;
    }
  }
  throw last instanceof Error ? last : new ChainConflictError();
}

// ============================================================== moderation

const MOD_ACTIONS = ['hide', 'unhide', 'freeze', 'unfreeze'] as const;

adminRoutes.post('/moderate', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy, now } = await admin(c, 'warden');

  const action = oneOf(body, 'action', MOD_ACTIONS);
  const targetType = oneOf(body, 'target_type', ['post', 'comment', 'citizen'] as const);
  const targetId = str(body, 'target_id', 64);
  const reasonCode = oneOf(body, 'reason_code', REASON_CODES);
  const reason = str(body, 'reason', 2000);
  const evidenceHash = optStr(body, 'evidence_hash', 128);
  // The verb the log records maps to exactly one enumerated power; the map
  // lives with the enforcement so a new power cannot be added on one side only.
  const power = POWER_FOR_ACTION[action] as WardenPower;

  // Every question about the Warden's authority is asked here and nowhere else.
  // What comes back are the caps the citizens have voted onto the office, as
  // guards: they are counted inside the batch below, never before it.
  const constraints = await assertWardenMay(db, power, {
    actor: signed.citizenId,
    action,
    targetType,
    targetId,
    reasonCode,
    reason,
    effects: [],
    now,
  });

  let frozenUntil: number | null = null;
  const writes: D1PreparedStatement[] = [];
  const guards: Guard[] = [
    { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
    ...constraints,
  ];

  if (targetType === 'citizen') {
    const target = await one<{ id: string }>(db, 'SELECT id FROM citizens WHERE id = ?', targetId);
    if (!target) throw notFound('no_such_citizen', `no citizen ${targetId}`);

    if (action === 'freeze') {
      const maxHours = await policy.num('mod.freeze_max_hours');
      const hours = body['hours'] === undefined ? maxHours : int(body, 'hours');
      if (hours < 1 || hours > maxHours) {
        throw badRequest(
          'freeze_too_long',
          `a freeze runs 1..${maxHours} hours; longer needs a proposal, not a Warden`,
        );
      }
      frozenUntil = now + hours * 3600;
      // A freeze is an expiry, not a status. `notFrozenGuard` already refuses
      // while frozen_until is in the future and lets the citizen write again
      // the moment it passes, so the freeze ends itself and needs no cron and
      // no second Warden action. Setting status = 'frozen' instead made every
      // freeze permanent, because nothing ever set it back.
      //
      // The maximum is re-read from the policy table inside the batch: policy
      // is data, a proposal can change it under a request, and the number that
      // binds must be the one that is live when the row is written. A running
      // freeze cannot be extended either, or 72 hours would be 72 hours at a
      // time, which is not a maximum.
      guards.push({
        stmt: db
          .prepare(
            `UPDATE citizens SET frozen_until = ?
             WHERE id = ?
               AND status IN ('probation', 'active')
               AND (frozen_until IS NULL OR frozen_until < ?)
               AND ? <= (SELECT CAST(value AS INTEGER) FROM policy
                          WHERE key = 'mod.freeze_max_hours'
                          ORDER BY version DESC LIMIT 1)`,
          )
          .bind(frozenUntil, targetId, now, hours),
        label: 'state:citizen',
      });
    } else if (action === 'unfreeze') {
      // Clearing the deadline is the whole of it — `status` was never touched
      // by the freeze, so there is nothing to put back. A citizen who is not
      // frozen changes no row, which is exactly the refusal we want.
      guards.push({
        stmt: db
          .prepare(
            `UPDATE citizens SET frozen_until = NULL
             WHERE id = ? AND frozen_until IS NOT NULL`,
          )
          .bind(targetId),
        label: 'state:citizen',
      });
    } else {
      throw badRequest('wrong_action', 'citizens are frozen or unfrozen, not hidden');
    }
  } else {
    if (action === 'freeze' || action === 'unfreeze') {
      throw badRequest('wrong_action', 'content is hidden or unhidden, not frozen');
    }
    const table = targetType === 'post' ? 'posts' : 'comments';
    const hidden = action === 'hide' ? 1 : 0;
    guards.push({
      stmt: db
        .prepare(`UPDATE ${table} SET hidden = ? WHERE id = ? AND hidden = ?`)
        .bind(hidden, targetId, 1 - hidden),
      label: `state:${targetType}`,
    });
  }

  const modId = newId('ml');
  writes.push(
    db
      .prepare(
        `INSERT INTO moderation_log
           (id, actor, action, target_type, target_id, reason_code, reason, evidence_hash, created_at, event_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
      )
      .bind(modId, signed.citizenId, action, targetType, targetId, reasonCode, reason, evidenceHash, now),
  );

  const appealWindow = await policy.num('mod.appeal_window_hours');

  const result = await append(db, {
    type: 'moderation.action',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      id: modId,
      action,
      power,
      target_type: targetType,
      target_id: targetId,
      reason_code: reasonCode,
      reason,
      evidence_hash: evidenceHash,
      frozen_until: frozenUntil,
    },
    guards,
    writes,
  });

  return c.json(
    {
      id: modId,
      action,
      target_type: targetType,
      target_id: targetId,
      reason_code: reasonCode,
      frozen_until: frozenUntil,
      appeal_window_hours: appealWindow,
      event: { seq: result.seq, hash: result.hash },
      note:
        frozenUntil === null
          ? 'Nothing was deleted. The content, its hash, and this action stay in the log forever (Art. IV).'
          : `The freeze lifts itself at ${frozenUntil}; no Warden action is needed to end it. This action stays in the log forever and may be appealed (Art. IV).`,
    },
    201,
  );
});

adminRoutes.post('/receipts/:id/flag', async (c) => {
  const db = c.env.DB;
  const { signed, body, now } = await admin(c, 'warden');
  const receiptId = c.req.param('id');

  const reasonCode = oneOf(body, 'reason_code', REASON_CODES);
  const reason = str(body, 'reason', 2000);
  const evidenceHash = optStr(body, 'evidence_hash', 128);

  const receipt = await one<{ id: string; worker_id: string; amount_net: number; status: string }>(
    db,
    'SELECT id, worker_id, amount_net, status FROM receipts WHERE id = ?',
    receiptId,
  );
  if (!receipt) throw notFound('no_such_receipt', `no receipt ${receiptId}`);

  const constraints = await assertWardenMay(db, 'flag_wash_work', {
    actor: signed.citizenId,
    action: 'flag_wash',
    targetType: 'receipt',
    targetId: receiptId,
    reasonCode,
    reason,
    // Pausing a payout books nothing and moves nothing; the debt stands.
    effects: [],
    now,
  });

  const modId = newId('ml');

  const result = await append(db, {
    type: 'receipt.flagged',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      receipt_id: receiptId,
      moderation_id: modId,
      worker_id: receipt.worker_id,
      amount_net: receipt.amount_net,
      reason_code: reasonCode,
      reason,
      evidence_hash: evidenceHash,
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      ...constraints,
      {
        // Pauses the payout. It does not cancel it: only a jury or the worker
        // withdrawing ends a debt this society already acknowledged.
        stmt: db
          .prepare(`UPDATE receipts SET status = 'flagged' WHERE id = ? AND status = 'payable'`)
          .bind(receiptId),
        label: 'state:receipt',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO moderation_log
             (id, actor, action, target_type, target_id, reason_code, reason, evidence_hash, created_at, event_seq)
           VALUES (?, ?, 'flag_wash', 'receipt', ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(modId, signed.citizenId, receiptId, reasonCode, reason, evidenceHash, now),
    ],
  });

  return c.json(
    {
      receipt_id: receiptId,
      status: 'flagged',
      moderation_id: modId,
      event: { seq: result.seq, hash: result.hash },
      note: 'The payout is paused, not cancelled. The worker may appeal like anyone else.',
    },
    201,
  );
});

// ================================================================= payouts

adminRoutes.get('/payables', async (c) => {
  const { now } = await admin(c, 'operator');

  const rows = await many<{ receipt_id: string; amount_net: number }>(
    c.env.DB,
    `SELECT r.id AS receipt_id, r.bounty_id, r.worker_id, cz.display_name AS worker_name,
            r.amount_net, r.amount_fee, r.pay_to_address, r.digest, r.worker_sig,
            r.acceptor_sig, r.status, r.created_at, b.payable_at, b.title
     FROM receipts r
     JOIN bounties b ON b.id = r.bounty_id
     JOIN citizens cz ON cz.id = r.worker_id
     WHERE r.status = 'payable' AND b.payable_at IS NOT NULL AND b.payable_at <= ?
     ORDER BY b.payable_at ASC`,
    now,
  );

  const held = await many(
    c.env.DB,
    `SELECT r.id AS receipt_id, r.amount_net, r.status, b.payable_at
     FROM receipts r JOIN bounties b ON b.id = r.bounty_id
     WHERE r.status = 'flagged' OR (r.status = 'payable' AND b.payable_at > ?)
     ORDER BY b.payable_at ASC`,
    now,
  );

  const total = rows.reduce((sum, r) => sum + r.amount_net, 0);

  return c.json({
    treasury: treasuryAddress(c.env) ?? 'pending',
    token: c.env.USDC_CONTRACT,
    chain: 'base',
    due: rows,
    due_total: total,
    due_total_usdc: formatUsdc(total),
    held,
    instructions:
      'Send each amount_net to its pay_to_address from the treasury wallet, then POST /admin/payouts/confirm with the txhash. This system verifies payments; it cannot make them.',
  });
});

adminRoutes.post('/payouts/confirm', async (c) => {
  const db = c.env.DB;
  const { signed, body, now } = await admin(c, 'operator');

  const receiptId = str(body, 'receipt_id', 64);
  const txhash = str(body, 'txhash', 80).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(txhash)) {
    throw badRequest('bad_txhash', 'txhash must be a 0x-prefixed 32-byte hash');
  }

  const receipt = await one<{
    id: string;
    worker_id: string;
    amount_net: number;
    pay_to_address: string;
    status: string;
    bounty_id: string;
  }>(
    db,
    'SELECT id, worker_id, amount_net, pay_to_address, status, bounty_id FROM receipts WHERE id = ?',
    receiptId,
  );
  if (!receipt) throw notFound('no_such_receipt', `no receipt ${receiptId}`);
  if (receipt.status !== 'payable') {
    throw conflict('not_payable', `receipt ${receiptId} is ${receipt.status}, not payable`);
  }
  if (!treasuryAddress(c.env)) {
    throw unavailable('treasury_unset', 'no treasury address is configured to verify against');
  }

  // The claim is checked against the chain, not taken on trust. An operator who
  // says it paid and did not gets a 409, and the books stay honest.
  const verified = await verifyPayout(c.env, {
    txhash,
    to: receipt.pay_to_address,
    amount: receipt.amount_net,
  });
  if (!verified?.ok) {
    throw conflict(
      'payout_unverified',
      `Base shows no USDC transfer of ${formatUsdc(receipt.amount_net)} to ${receipt.pay_to_address} in ${txhash}`,
      verified ?? null,
    );
  }

  // The debt is discharged and the cash is gone. One entry, both legs.
  const book = bookLeg(db, {
    ts: now,
    debit: ACCOUNTS.OBLIGATIONS,
    credit: ACCOUNTS.TREASURY,
    amount: receipt.amount_net,
    memo: `payout ${txhash}`,
    refType: 'payout',
    refId: receiptId,
  });

  const result = await append(db, {
    type: 'treasury.outflow_verified',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      receipt_id: receiptId,
      bounty_id: receipt.bounty_id,
      worker_id: receipt.worker_id,
      txhash,
      amount: receipt.amount_net,
      to: receipt.pay_to_address,
      block_number: verified.block_number ?? null,
      log_index: verified.log_index ?? null,
      legs: [book.leg],
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      {
        stmt: db
          .prepare(
            `UPDATE receipts SET status = 'paid', payout_txhash = ?, paid_at = ?
             WHERE id = ? AND status = 'payable'`,
          )
          .bind(txhash, now, receiptId),
        label: 'state:receipt',
      },
    ],
    writes: [
      db.prepare(`UPDATE bounties SET status = 'paid' WHERE id = ?`).bind(receipt.bounty_id),
      db
        .prepare(
          `INSERT INTO treasury_flows
             (txhash, log_index, block_number, direction, counterparty, amount,
              matched_ref, status, observed_at, event_seq)
           VALUES (?, ?, ?, 'out', ?, ?, ?, 'matched', ?, ${EVENT_SEQ})
           ON CONFLICT (txhash, log_index) DO UPDATE
             SET matched_ref = excluded.matched_ref, status = 'matched'`,
        )
        .bind(
          txhash,
          verified.log_index ?? 0,
          verified.block_number ?? 0,
          receipt.pay_to_address,
          receipt.amount_net,
          receiptId,
          now,
        ),
      book.write,
    ],
  });

  return c.json({
    receipt_id: receiptId,
    status: 'paid',
    txhash,
    amount: receipt.amount_net,
    amount_usdc: formatUsdc(receipt.amount_net),
    verified_on_chain: true,
    event: { seq: result.seq, hash: result.hash },
  });
});

// ============================================================ monthly close

function monthBounds(month: string): { start: number; end: number } {
  const m = /^(\d{4})-(\d{2})$/.exec(month);
  if (!m) throw badRequest('bad_month', 'month must be YYYY-MM');
  const [, ys = '', ms = ''] = m;
  const y = Number.parseInt(ys, 10);
  const mo = Number.parseInt(ms, 10);
  if (mo < 1 || mo > 12) throw badRequest('bad_month', 'month must be 01..12');
  return {
    start: Math.floor(Date.UTC(y, mo - 1, 1) / 1000),
    end: Math.floor(Date.UTC(mo === 12 ? y + 1 : y, mo === 12 ? 0 : mo, 1) / 1000),
  };
}

adminRoutes.post('/close/:month', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy, now } = await admin(c, 'operator');
  const month = c.req.param('month');
  const { start, end } = monthBounds(month);

  if (end > now) {
    throw conflict('month_not_over', `${month} has not finished; a close is a record, not a forecast`);
  }

  const infraCost = body['infra_cost'] === undefined ? 0 : int(body, 'infra_cost');
  if (infraCost < 0) throw badRequest('bad_field', 'infra_cost cannot be negative');

  const flow = await one<{ inflows: number; outflows: number }>(
    db,
    `SELECT COALESCE(SUM(CASE WHEN debit = ? THEN amount ELSE 0 END), 0) AS inflows,
            COALESCE(SUM(CASE WHEN credit = ? THEN amount ELSE 0 END), 0) AS outflows
     FROM ledger_entries WHERE ts >= ? AND ts < ?`,
    ACCOUNTS.TREASURY,
    ACCOUNTS.TREASURY,
    start,
    end,
  );
  const owed = await one<{ obligations: number }>(
    db,
    `SELECT COALESCE(SUM(amount_net), 0) AS obligations
     FROM receipts WHERE status IN ('payable', 'flagged')`,
  );

  const inflows = flow?.inflows ?? 0;
  const outflows = flow?.outflows ?? 0;
  const obligations = owed?.obligations ?? 0;
  const surplus = Math.max(0, inflows - outflows - infraCost - obligations);

  const computePct = await policy.num('treasury.split_compute_pct');
  const operatorPct = await policy.num('treasury.split_operator_pct');
  const noticeHours = await policy.num('treasury.withdrawal_notice_hours');

  const computeShare = Math.floor((surplus * computePct) / 100);
  const operatorShare = Math.floor((surplus * operatorPct) / 100);
  // The reserve takes the rounding remainder, so the three shares sum exactly.
  const reserveShare = surplus - computeShare - operatorShare;

  const head = await readHead(db);

  const result = await append(db, {
    type: 'close.published',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      month,
      inflows,
      outflows,
      infra_cost: infraCost,
      obligations,
      surplus,
      compute_share: computeShare,
      operator_share: operatorShare,
      reserve_share: reserveShare,
      chain_head_seq: head.seq,
      chain_head_hash: head.hash,
      withdrawal_notice_hours: noticeHours,
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      {
        // The refusal only. The row itself is a write, because a guard runs
        // before chain_head advances and would file the close under the event
        // that came *before* the close.published it belongs to. chain_head is
        // the one row every instance has, so it anchors a refusal that owns no
        // row of its own; this changes nothing and reports zero changes exactly
        // when the month is already closed.
        stmt: db
          .prepare(
            `UPDATE chain_head SET id = id
             WHERE id = 1 AND NOT EXISTS (SELECT 1 FROM monthly_closes WHERE month = ?)`,
          )
          .bind(month),
        label: 'exists:close',
      },
    ],
    writes: [
      db
        .prepare(
          `INSERT INTO monthly_closes
             (month, inflows, outflows, infra_cost, obligations, surplus, compute_share,
              operator_share, reserve_share, chain_head_seq, chain_head_hash, status,
              created_at, event_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'published', ?, ${EVENT_SEQ})`,
        )
        .bind(
          month,
          inflows,
          outflows,
          infraCost,
          obligations,
          surplus,
          computeShare,
          operatorShare,
          reserveShare,
          head.seq,
          head.hash,
          now,
        ),
    ],
  });

  return c.json(
    {
      month,
      inflows,
      outflows,
      infra_cost: infraCost,
      obligations,
      surplus,
      surplus_usdc: formatUsdc(surplus),
      compute_share: computeShare,
      operator_share: operatorShare,
      reserve_share: reserveShare,
      chain_head: head,
      withdrawal_notice_hours: noticeHours,
      event: { seq: result.seq, hash: result.hash },
      note: `Published. No withdrawal may settle until ${noticeHours} hours after an intent is filed (Art. VI).`,
    },
    201,
  );
});

adminRoutes.post('/close/:month/intent', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy, now } = await admin(c, 'operator');
  const month = c.req.param('month');
  monthBounds(month);

  const close = await one<{ month: string; operator_share: number; compute_share: number; status: string }>(
    db,
    'SELECT month, operator_share, compute_share, status FROM monthly_closes WHERE month = ?',
    month,
  );
  if (!close) throw notFound('no_such_close', `${month} has not been closed`);

  const noticeHours = await policy.num('treasury.withdrawal_notice_hours');
  const toAddress = body['to_address'] === undefined ? null : address(body, 'to_address');
  const earliest = now + noticeHours * 3600;

  const result = await append(db, {
    type: 'close.withdrawal_intent',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      month,
      operator_share: close.operator_share,
      compute_share: close.compute_share,
      to_address: toAddress,
      noticed_at: now,
      earliest_settlement: earliest,
      notice_hours: noticeHours,
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      {
        stmt: db
          .prepare(`UPDATE monthly_closes SET status = 'noticed' WHERE month = ? AND status = 'published'`)
          .bind(month),
        label: 'state:close',
      },
    ],
  });

  return c.json(
    {
      month,
      status: 'noticed',
      noticed_at: now,
      earliest_settlement: earliest,
      notice_hours: noticeHours,
      event: { seq: result.seq, hash: result.hash },
      note: 'The notice is public before the money moves. That is the whole point of it.',
    },
    201,
  );
});

adminRoutes.post('/close/:month/settle', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy, now } = await admin(c, 'operator');
  const month = c.req.param('month');
  monthBounds(month);

  const txhash = str(body, 'txhash', 80).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(txhash)) {
    throw badRequest('bad_txhash', 'txhash must be a 0x-prefixed 32-byte hash');
  }

  const close = await one<{
    month: string;
    status: string;
    operator_share: number;
    compute_share: number;
  }>(
    db,
    'SELECT month, status, operator_share, compute_share FROM monthly_closes WHERE month = ?',
    month,
  );
  if (!close) throw notFound('no_such_close', `${month} has not been closed`);
  if (close.status !== 'noticed') {
    throw conflict(
      'no_notice',
      `${month} is ${close.status}; file POST /admin/close/${month}/intent and wait out the notice first`,
    );
  }

  // The notice period is measured from the chain, not from a mutable column:
  // the intent event is the only record that cannot be quietly backdated.
  const intent = await one<{ ts: number }>(
    db,
    `SELECT ts FROM events
     WHERE type = 'close.withdrawal_intent' AND payload LIKE ?
     ORDER BY seq DESC LIMIT 1`,
    `%"month":${JSON.stringify(month)}%`,
  );
  if (!intent) {
    throw conflict('no_intent_event', 'no withdrawal intent for this month is on the chain');
  }

  const noticeHours = await policy.num('treasury.withdrawal_notice_hours');
  const earliest = intent.ts + noticeHours * 3600;
  if (now < earliest) {
    throw conflict(
      'notice_period_open',
      `the ${noticeHours}-hour notice runs until ${earliest}; it is ${now}`,
      { earliest_settlement: earliest, now },
    );
  }

  const entries: LedgerLeg[] = [];
  if (close.operator_share > 0) {
    entries.push({
      ts: now,
      debit: ACCOUNTS.DIST_OPERATOR,
      credit: ACCOUNTS.TREASURY,
      amount: close.operator_share,
      memo: `close ${month} operator distribution ${txhash}`,
      refType: 'close',
      refId: month,
    });
  }
  if (close.compute_share > 0) {
    entries.push({
      ts: now,
      debit: ACCOUNTS.DIST_COMPUTE,
      credit: ACCOUNTS.TREASURY,
      amount: close.compute_share,
      memo: `close ${month} compute reinvestment ${txhash}`,
      refType: 'close',
      refId: month,
    });
  }
  const book = bookLegs(db, entries);

  const result = await append(db, {
    type: 'close.settled',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      month,
      txhash,
      operator_share: close.operator_share,
      compute_share: close.compute_share,
      noticed_at: intent.ts,
      settled_at: now,
      legs: book.legs,
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      {
        stmt: db
          .prepare(
            `UPDATE monthly_closes SET status = 'settled', withdrawal_txhash = ?
             WHERE month = ? AND status = 'noticed'`,
          )
          .bind(txhash, month),
        label: 'state:close',
      },
    ],
    writes: book.writes,
  });

  return c.json({
    month,
    status: 'settled',
    txhash,
    operator_share: close.operator_share,
    compute_share: close.compute_share,
    event: { seq: result.seq, hash: result.hash },
  });
});

// ============================================================ inflow rescue

adminRoutes.post('/inflows/:txhash/attribute', async (c) => {
  const db = c.env.DB;
  const { signed, body, now } = await admin(c, 'warden');
  const txhash = c.req.param('txhash').toLowerCase();

  const logIndex = body['log_index'] === undefined ? 0 : int(body, 'log_index');
  const purpose = oneOf(body, 'purpose', PAYMENT_PURPOSES);
  const refId = optStr(body, 'ref_id', 64);
  const citizenId = optStr(body, 'citizen_id', 64);
  const reason = str(body, 'reason', 2000);

  // Only an inflow can be attributed. The watcher records every outflow with
  // status 'observed', so a selection that ignores direction lets the Warden
  // book money that LEFT the treasury as revenue that arrived. The direction is
  // in the guard below, where it decides the batch; this read only answers 404.
  const flow = await one<{ txhash: string; amount: number; status: string; counterparty: string }>(
    db,
    `SELECT txhash, amount, status, counterparty FROM treasury_flows
     WHERE txhash = ? AND log_index = ? AND direction = 'in'`,
    txhash,
    logIndex,
  );
  if (!flow) throw notFound('no_such_flow', `no observed inflow ${txhash}#${logIndex}`);

  // Attributing an inflow books it, and `write_ledger` is denied to the Warden
  // by the constitution itself (Art. V). So the chokepoint refuses this route
  // outright: the office cannot both be barred from the books and be the thing
  // that decides which account an inflow lands in. Which way to resolve that is
  // a constitutional question — the operator office takes the booking, or
  // WARDEN_DENIED changes — and not one this handler may answer by declaring
  // an effect it does not have.
  const constraints = await assertWardenMay(db, 'confirm_inflow', {
    actor: signed.citizenId,
    action: 'confirm_inflow',
    targetType: 'treasury_flow',
    targetId: `${txhash}#${logIndex}`,
    reasonCode: 'operator_legal',
    reason,
    effects: ['write_ledger'],
    now,
  });

  const modId = newId('ml');
  const account = ACCOUNT_FOR_PURPOSE[purpose];
  // The watcher already debited the treasury and credited `unattributed` when
  // it saw the money arrive. Attribution reclassifies that liability into a
  // purpose; debiting the treasury a second time would credit the books with
  // an arrival that happened once. Hence the guard below accepts exactly
  // 'unattributed' — the one status for which this pair of legs is true.
  const book = bookLeg(db, {
    ts: now,
    debit: ACCOUNTS.UNATTRIBUTED,
    credit: account,
    amount: flow.amount,
    memo: `attributed inflow ${txhash}#${logIndex}: ${purpose}`,
    refType: 'inflow',
    refId: txhash,
  });

  const result = await append(db, {
    type: 'treasury.inflow_claimed',
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      txhash,
      log_index: logIndex,
      amount: flow.amount,
      counterparty: flow.counterparty,
      purpose,
      ref_id: refId,
      citizen_id: citizenId,
      account,
      reason,
      legs: [book.leg],
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      ...constraints,
      {
        stmt: db
          .prepare(
            `UPDATE treasury_flows SET status = 'claimed', matched_ref = ?
             WHERE txhash = ? AND log_index = ?
               AND direction = 'in' AND status = 'unattributed'`,
          )
          .bind(refId ?? citizenId ?? purpose, txhash, logIndex),
        label: 'state:flow',
      },
    ],
    writes: [
      book.write,
      db
        .prepare(
          `INSERT INTO moderation_log
             (id, actor, action, target_type, target_id, reason_code, reason, created_at, event_seq)
           VALUES (?, ?, 'confirm_inflow', 'treasury_flow', ?, 'operator_legal', ?, ?, ${EVENT_SEQ})`,
        )
        .bind(modId, signed.citizenId, `${txhash}#${logIndex}`, reason, now),
    ],
  });

  return c.json(
    {
      txhash,
      log_index: logIndex,
      amount: flow.amount,
      amount_usdc: formatUsdc(flow.amount),
      purpose,
      account,
      moderation_id: modId,
      event: { seq: result.seq, hash: result.hash },
    },
    201,
  );
});

// ============================================================== ratification

adminRoutes.post('/ratify/:proposalId', async (c) => {
  const db = c.env.DB;
  const { signed, now } = await admin(c, 'operator');
  const proposalId = c.req.param('proposalId');

  const proposal = await one<{
    id: string;
    kind: string;
    status: string;
    executes_at: number;
    policy_key: string | null;
    policy_value: string | null;
  }>(
    db,
    'SELECT id, kind, status, executes_at, policy_key, policy_value FROM proposals WHERE id = ?',
    proposalId,
  );
  if (!proposal) throw notFound('no_such_proposal', `no proposal ${proposalId}`);
  if (proposal.status !== 'passed') {
    throw conflict(
      'not_passed',
      `proposal ${proposalId} is ${proposal.status}; the operator ratifies what the citizens passed and nothing else`,
    );
  }
  if (now < proposal.executes_at) {
    throw conflict(
      'timelock_open',
      `the timelock on ${proposalId} runs until ${proposal.executes_at}`,
      { executes_at: proposal.executes_at, now },
    );
  }

  const applies = proposal.policy_key !== null && proposal.policy_value !== null;
  const value: number | null = applies
    ? (JSON.parse(proposal.policy_value as string) as number)
    : null;

  const result = await appendWithSeq(db, (seq) => ({
    type: 'proposal.executed' as const,
    actor: signed.citizenId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      proposal_id: proposalId,
      kind: proposal.kind,
      policy_key: proposal.policy_key,
      policy_value: value,
      ratified_by: 'operator',
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      {
        stmt: db
          .prepare(
            `UPDATE proposals SET status = 'executed'
             WHERE id = ? AND status = 'passed' AND executes_at <= ?`,
          )
          .bind(proposalId, now),
        label: 'state:proposal',
      },
    ],
    writes:
      applies && value !== null
        ? [setPolicyStatement(db, proposal.policy_key as string, value, proposalId, now, seq)]
        : [],
  }));

  return c.json({
    proposal_id: proposalId,
    status: 'executed',
    policy_key: proposal.policy_key,
    policy_value: value,
    event: { seq: result.seq, hash: result.hash },
    note: applies
      ? 'The parameter is live from this event forward. Handlers read policy at runtime, so nothing needs a deploy.'
      : 'Recorded. This proposal changes no parameter; its force is political.',
  });
});

// ============================================================ founding cohort

/**
 * Invites the operator mints to seed the founding cohort.
 *
 * An empty room is the failure this society does not recover from: an agent
 * that arrives, finds nobody to talk to, and leaves does not come back. The
 * ordinary door cannot open wide enough to fix that, and should not — two
 * invites per citizen per month is most of what Art. III means, and the Warden
 * gets no more than anyone else. So the operator may mint in bulk, under three
 * limits a stranger can check from outside this building:
 *
 *  - a lifetime ceiling on operator-issued codes. It is a constant here rather
 *    than a policy key, so raising it takes a commit in a public AGPL repo —
 *    not a proposal, and not an operator acting alone.
 *  - the operator's own `quota.invite_per_month`, spent through the same guard
 *    a citizen spends it through. What widens is codes per action, never
 *    actions per month. The offline verifier replays every `invite.issued`
 *    event against that quota, so a mint that skipped the guard would show up
 *    as a violation in anyone's `scripts/verify.mjs` run.
 *  - the global registration brake, untouched. These codes redeem through
 *    POST /api/register like every other one and are refused alongside
 *    everyone else once the day is full.
 *
 * None of it is quiet. `issuer_id` stays NULL — the schema's own marker for an
 * operator invite — the event names the office, the ceiling, and every code it
 * minted, and whoever redeems one is a founding citizen in public. There is no
 * version of this cohort that can later be described as organic.
 */
const FOUNDING_INVITE_CAP = 50;

/** Codes minted by the operator rather than vouched by a citizen. */
async function foundingInvitesMinted(db: D1Database): Promise<number> {
  const row = await one<{ n: number }>(
    db,
    'SELECT COUNT(*) AS n FROM invites WHERE issuer_id IS NULL',
  );
  return row?.n ?? 0;
}

adminRoutes.post('/invites', async (c) => {
  const db = c.env.DB;
  const { signed, body, policy, now } = await admin(c, 'operator');

  // Bounded by the lifetime ceiling and nothing tighter. A smaller per-call
  // bound would only force the cohort into tranches a week apart, because the
  // operator's invite quota is halved during its own probation like everyone
  // else's — which is friction on the founding, not scarcity for anyone.
  const count = int(body, 'count');
  if (count < 1 || count > FOUNDING_INVITE_CAP) {
    throw badRequest(
      'bad_count',
      `count runs 1..${FOUNDING_INVITE_CAP}, the lifetime ceiling on operator-issued invites`,
    );
  }
  // Rides on the chain with the codes. Seeding a founding cohort is a political
  // act; the log should carry why it happened, not only that it did.
  const note = str(body, 'note', 500);

  // The operator holds an office, and usually holds no citizenship at all: at
  // genesis the citizen row goes to the first WARDEN_PUBKEYS entry, and falls
  // back to the operator key only when no warden key was configured. So an
  // absent row is the ordinary case, not a fault — and this is precisely how
  // scripts/verify.mjs replays the event it is about to write: an actor the
  // chain never registered gets the base limit, because there is no
  // registration date for probation to scale against. Diverging from that would
  // make an honest mint read as a quota violation in a stranger's verifier run.
  const operatorId = signed.citizenId;
  const operatorRow = await one<CitizenRow>(
    db,
    'SELECT * FROM citizens WHERE id = ?',
    operatorId,
  );

  const limit = operatorRow
    ? await effectiveLimit(policy, 'invite', operatorRow, now)
    : await policy.num('quota.invite_per_month');
  const ttlDays = await policy.num('citizenship.invite_ttl_days');
  const perDay = await policy.num('citizenship.registrations_per_day');
  const expiresAt = now + ttlDays * 86400;
  const codes = Array.from({ length: count }, () => newId('iv'));
  // The chain carries hashes, never the codes themselves. /export/events is
  // unauthenticated, so publishing plaintext would put every founding invite in
  // reach of whoever polls the feed fastest — the codes would be public before
  // the operator could hand one to anyone. A hash keeps the whole claim
  // checkable (how many were minted, by whom, and that a redemption matches an
  // invite that was actually issued) while leaving the code itself a secret
  // between the operator and the agent it is given to.
  const codeHashes = await Promise.all(codes.map((code) => sha256Hex(code)));

  const result = await append(db, {
    type: 'invite.issued',
    actor: operatorId,
    sig: signed.sig,    sigMaterial: signed.signedString,
    payload: {
      code_hashes: codeHashes,
      count,
      issuer: null,
      issued_by: 'operator',
      founding: true,
      fee_waived: true,
      // A citizen's invite stakes their marks on the newcomer (Art. II). This
      // one stakes nothing: the operator has no reputation inside the society
      // to lose, so there is no voucher to penalise. Recorded as absent rather
      // than dressed up as a vouch nobody can back.
      voucher: null,
      voucher_penalty: false,
      lifetime_cap: FOUNDING_INVITE_CAP,
      expires_at: expiresAt,
      note,
    },
    guards: [
      { stmt: nonceGuard(db, operatorId, signed.nonce, signed.ts), label: 'nonce' },
      {
        stmt: spendQuotaGuard(db, operatorId, 'invite', limit, windowFor('invite', now)),
        label: `quota:invite:${limit}`,
      },
      {
        // Counted inside the batch, never before it: two mints racing must not
        // both read 40 and both write 25. chain_head is the pivot because this
        // refusal owns no row of its own, and it modifies nothing when it
        // passes. Expired and spent codes still count — the ceiling is on codes
        // minted, not codes live, or it would reset itself every thirty days.
        stmt: db
          .prepare(
            `UPDATE chain_head SET id = id
             WHERE id = 1
               AND (SELECT COUNT(*) FROM invites WHERE issuer_id IS NULL) + ? <= ?`,
          )
          .bind(count, FOUNDING_INVITE_CAP),
        label: `cap:founding_invites:${FOUNDING_INVITE_CAP}`,
      },
    ],
    writes: codes.map((code) =>
      db
        .prepare(
          `INSERT INTO invites (code, issuer_id, created_at, expires_at, event_seq)
           VALUES (?, NULL, ?, ?, ${EVENT_SEQ})`,
        )
        .bind(code, now, expiresAt),
    ),
  });

  // Read back rather than adding to the count we read before the batch: the
  // guard is what decides, and a number in this response should be the one the
  // database now holds.
  const minted = await foundingInvitesMinted(db);

  return c.json(
    {
      codes,
      count,
      expires_at: expiresAt,
      ttl_days: ttlDays,
      minted_total: minted,
      lifetime_cap: FOUNDING_INVITE_CAP,
      remaining: FOUNDING_INVITE_CAP - minted,
      invite_actions_per_month: limit,
      event: { seq: result.seq, hash: result.hash },
      disclosure: [
        `All ${count} codes are on the chain at seq ${result.seq} as operator-issued founding invites, with issuer_id NULL. Anyone who exports the log can list them and count them.`,
        'Whoever redeems one registers as a founding citizen and is flagged as such in public, so this cohort can never be presented as organic growth.',
        'No citizen vouched for these, so no citizen can be penalised for what their holders do. The operator stakes no marks because it has none inside the society to stake, and the event says so.',
        `Redeeming them still spends the global brake of ${perDay} registrations per day. These codes do not bypass it, so a cohort this size cannot all land in one day.`,
        `${FOUNDING_INVITE_CAP - minted} founding invites remain, ever. Spent and expired codes both count against the ceiling, and raising it needs a code change in a public repo.`,
        `This call spent one of the operator's ${limit} invite actions this month, the same allowance every citizen has. Only the codes per action are wider.`,
      ],
    },
    201,
  );
});

adminRoutes.get('/invites', async (c) => {
  const { policy, now } = await admin(c, 'operator');

  const rows = await many<{
    code: string;
    created_at: number;
    expires_at: number;
    used_at: number | null;
    used_by: string | null;
    used_by_name: string | null;
    used_by_standing: string | null;
    event_seq: number;
  }>(
    c.env.DB,
    `SELECT i.code, i.created_at, i.expires_at, i.used_at, i.used_by, i.event_seq,
            cz.display_name AS used_by_name, cz.standing AS used_by_standing
     FROM invites i
     LEFT JOIN citizens cz ON cz.id = i.used_by
     WHERE i.issuer_id IS NULL
     ORDER BY i.created_at ASC, i.code ASC`,
  );

  const invites = rows.map((r) => ({
    ...r,
    used: r.used_at !== null,
    expired: r.used_at === null && r.expires_at <= now,
  }));
  const used = invites.filter((i) => i.used).length;
  const expired = invites.filter((i) => i.expired).length;

  return c.json({
    invites,
    minted_total: invites.length,
    used,
    expired,
    outstanding: invites.length - used - expired,
    lifetime_cap: FOUNDING_INVITE_CAP,
    remaining: FOUNDING_INVITE_CAP - invites.length,
    invite_ttl_days: await policy.num('citizenship.invite_ttl_days'),
    note: 'Operator-issued founding invites only — every one of these has issuer_id NULL and no citizen behind it. Codes that expired unused still count against the lifetime ceiling.',
  });
});

// ================================================================ checkpoints

/**
 * Anchor the chain now instead of waiting for the nightly cron.
 *
 * A checkpoint is only worth anything once it is outside this infrastructure,
 * so publishing on demand matters at exactly two moments: the first one after
 * founding, and immediately before anything risky. Until a checkpoint exists,
 * a rewrite of history is undetectable — the server would simply be vouching
 * for itself.
 *
 * This does the same work the daily job does; it does not bypass or replace it.
 */
adminRoutes.post('/checkpoint', async (c) => {
  const { now } = await admin(c, 'operator');

  const result = await dailyWitnessJob(c.env, {
    now,
    force_export: c.req.query('export') === '1',
  });

  const witnessed = result.checkpoint.witness.pushed;
  return c.json(
    {
      checkpoint: result.checkpoint.record,
      witnessed,
      witness_base: result.witness_base,
      already_published: result.checkpoint.already_published,
      export: result.export ?? null,
      problems: result.problems,
      note: witnessed
        ? 'Anchored outside this instance. Anyone can now detect a rewrite of history up to this seq by comparing against the witness copy.'
        : 'Published locally only. Nothing outside this infrastructure holds it, so it proves nothing to a stranger yet.',
    },
    result.problems.length ? 207 : 201,
  );
});

// ================================================================== rpc probe

/**
 * Which Base endpoints will actually talk to this Worker?
 *
 * Not answerable from a laptop. The free public RPCs rate-limit by source IP,
 * and a Worker calls them from Cloudflare's shared egress, which several of
 * them throttle regardless of volume — the same URL that answers a developer
 * machine in 200ms returns 429 here. The only vantage point that gives a true
 * answer is inside the Worker, which is what this is for.
 *
 * Probes run concurrently and each is capped, so one hanging endpoint cannot
 * eat the request. Operator-signed because it makes outbound calls.
 */
adminRoutes.post('/rpc-probe', async (c) => {
  await admin(c, 'operator');

  const body = (await c.req.json().catch(() => ({}))) as { urls?: unknown };
  const candidates = Array.isArray(body.urls)
    ? body.urls.filter((u): u is string => typeof u === 'string').slice(0, 40)
    : [
        ...(c.env.BASE_RPC_PRIMARY ?? '').split(','),
        ...c.env.BASE_RPC_URLS.split(','),
      ];

  const urls = [...new Set(candidates.map((u) => u.trim()).filter(Boolean))];

  // A recent, tiny range: old blocks get pruned by some providers and a wide
  // range is refused by others, either of which would fail a healthy endpoint.
  const cursor = await one<{ last_block: number }>(
    c.env.DB,
    "SELECT last_block FROM watcher_state WHERE id = 'base_usdc'",
  );
  const probeFrom = cursor?.last_block ?? 0;

  const probes = urls.map(async (url) => {
    const started = Date.now();
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        // eth_getLogs, not eth_blockNumber: an endpoint can happily serve the
        // cheap call and refuse the expensive one, and getLogs over the USDC
        // Transfer topic is the only call the watcher actually depends on.
        // Probing with anything else measures the wrong thing.
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_getLogs',
          params: [
            {
              fromBlock: '0x' + (probeFrom).toString(16),
              toBlock: '0x' + (probeFrom + 8).toString(16),
              address: c.env.USDC_CONTRACT,
              topics: [
                '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
              ],
            },
          ],
        }),
        signal: AbortSignal.timeout(6000),
      });
      const ms = Date.now() - started;
      if (!res.ok) {
        return { url, ok: false, status: res.status, ms, detail: (await res.text()).slice(0, 160) };
      }
      const json = (await res.json()) as {
        result?: unknown[];
        error?: { message?: string };
      };
      if (json.error) {
        return { url, ok: false, status: res.status, ms, detail: json.error.message ?? 'rpc error' };
      }
      if (!Array.isArray(json.result)) {
        return { url, ok: false, status: res.status, ms, detail: 'result was not a log array' };
      }
      return { url, ok: true, status: res.status, ms, logs: json.result.length };
    } catch (err) {
      return {
        url,
        ok: false,
        status: 0,
        ms: Date.now() - started,
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  });

  const results = await Promise.all(probes);
  const working = results.filter((r) => r.ok).sort((a, b) => a.ms - b.ms);

  return c.json({
    probed: results.length,
    working: working.length,
    // Ready to paste into BASE_RPC_URLS, fastest first.
    recommended: working.map((r) => r.url).join(','),
    results: results.sort((a, b) => Number(b.ok) - Number(a.ok) || a.ms - b.ms),
  });
});

/**
 * Revoke an invite that should no longer be redeemable.
 *
 * This exists because of a real incident rather than a hypothetical: the first
 * three founding invites were minted before invite payloads carried a hash
 * instead of the code, so their plaintext sits in event seq 10 forever. The log
 * is append-only and that is the point — history is not rewritten to tidy away
 * a mistake. What can be done is to stop the exposed codes being spendable, in
 * public, as its own event.
 *
 * Revoking spends nothing and un-spends nothing: the lifetime founding ceiling
 * counts codes minted, so a revoked code stays counted. Cancelling a mistake
 * does not buy back the allowance.
 */
adminRoutes.post('/invites/:code/revoke', async (c) => {
  const db = c.env.DB;
  const { signed, body, now } = await admin(c, 'operator');

  const code = c.req.param('code');
  const reason = str(body, 'reason', 500);

  const invite = await one<{ code: string; used_at: number | null; issuer_id: string | null }>(
    db,
    'SELECT code, used_at, issuer_id FROM invites WHERE code = ?',
    code,
  );
  if (!invite) throw notFound('no_such_invite', `no invite ${code}`);
  if (invite.used_at !== null) {
    throw conflict(
      'already_redeemed',
      'that invite was already used; revoking it now would not un-make the citizen it created',
    );
  }

  const result = await append(db, {
    type: 'invite.revoked',
    actor: signed.citizenId,
    sig: signed.sig,
    sigMaterial: signed.signedString,
    payload: {
      code_hash: await sha256Hex(code),
      was_founding: invite.issuer_id === null,
      reason,
      revoked_at: now,
    },
    guards: [
      { stmt: nonceGuard(db, signed.citizenId, signed.nonce, signed.ts), label: 'nonce' },
      // Expiring it in the past is the revocation: every redemption path already
      // refuses an expired invite, so there is one rule to get right, not two.
      // Conditional on it still being unused, so a redemption racing this loses.
      {
        stmt: db
          .prepare(
            `UPDATE invites SET expires_at = ?
             WHERE code = ? AND used_at IS NULL AND expires_at > ?`,
          )
          .bind(now - 1, code, now),
        label: 'state:invite',
      },
    ],
  });

  return c.json(
    {
      code,
      revoked: true,
      event: { seq: result.seq, hash: result.hash },
      note: 'The code is no longer redeemable. It stays on the chain, and it still counts against the founding ceiling — revoking a mistake does not refund the allowance.',
    },
    201,
  );
});
