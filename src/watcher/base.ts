/**
 * The treasury observer.
 *
 * This society has no keys to the wallet it is named after. It watches one
 * address on Base over public JSON-RPC, reads USDC Transfer logs, and writes
 * down what it saw. It never signs, never sends, and never holds anything
 * (Art. VI) — every method used here is a read.
 *
 * Matching is by fingerprint, not by guesswork. A payment intent reserves a
 * globally unique exact amount (`pending_payments.expected_amount`), so an
 * inflow of that amount is that intent and nothing else. An inflow that matches
 * no live fingerprint is booked to `treasury:unattributed` and left for a
 * Warden to attribute through /admin/inflows/:txhash/attribute; it is never
 * quietly assigned to whoever seems likeliest.
 *
 * Every row this module writes — treasury_flows, pending_payments, bounties,
 * ledger_entries — goes into an appendEvent batch. The one exception is
 * `watcher_state`, which is a scan cursor with no event_seq column: it records
 * where the reader has got to, not anything that happened in the society.
 */

import { ACCOUNTS, accountForPurpose } from '../core/constitution';
import { many, one, treasuryAddress, type Env } from '../core/db';
import { GuardFailedError, appendEventWithRetry, nowSeconds } from '../core/events';
// Legs go into the event payload as well as the table: a ledger row that no
// event hash covers is a book entry the offline verifier cannot check.
import { bookLegs } from '../services/ledger';
import { Policy } from '../services/policy';

/** keccak256("Transfer(address,address,uint256)") */
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

const WATCHER_ID = 'base_usdc';

/** Per-call RPC ceiling. A slow endpoint must not eat the whole cron budget. */
const RPC_TIMEOUT_MS = 8000;

/**
 * How long to stop calling out after every endpoint refused us.
 *
 * Not a governed parameter: this is etiquette toward someone else's free
 * infrastructure, not a value the society should get to vote itself out of.
 */
const RPC_COOLDOWN_SECONDS = 900;

/** Rate limiting, as the free endpoints express it. */
function isRateLimited(lastError: string | null): boolean {
  if (!lastError) return false;
  return /\b(429|403)\b|rate limit|usage limit|too many requests/i.test(lastError);
}

export interface WatcherResult {
  /** Set when the watcher declined to run, with the reason. */
  skipped?: string;
  from_block: number;
  to_block: number;
  chunks: number;
  observed: number;
  matched: number;
  unattributed: number;
  outflows: number;
  /** Flows another run (or the operator) had already recorded. */
  already_recorded: number;
}

// ------------------------------------------------------------------- RPC

interface RpcLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex: string;
}

/**
 * One JSON-RPC call, trying each configured endpoint in turn.
 *
 * Public RPC is unreliable by nature, so a single dead host must not stop the
 * society observing its own treasury. All endpoints failing does throw: a
 * watcher that cannot see the chain must say so rather than report "nothing
 * happened", which is what a silent fallback would amount to.
 */
async function rpc<T>(env: Env, method: string, params: unknown[]): Promise<T> {
  // A keyed endpoint, if the operator has one, is tried before the public
  // pool and kept out of the config file because its URL contains the key.
  //
  // This is not a nicety. The free public endpoints rate-limit by source IP,
  // and a Worker calls them from Cloudflare's shared egress, which those
  // providers throttle hard regardless of how little this instance asks for —
  // the same URLs that answer a laptop instantly return 429 here. Without a
  // keyed endpoint the watcher cannot see the chain, and an unseeing watcher
  // means no payment is ever matched and the whole economy stalls.
  const urls = [
    ...(env.BASE_RPC_PRIMARY ?? '').split(','),
    ...env.BASE_RPC_URLS.split(','),
  ]
    .map((u) => u.trim())
    .filter(Boolean);
  if (urls.length === 0) {
    throw new Error('BASE_RPC_URLS is empty; this instance cannot observe Base');
  }

  const failures: string[] = [];
  for (const url of urls) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
      });
      if (!response.ok) {
        failures.push(`${url}: HTTP ${response.status}`);
        continue;
      }
      const body = (await response.json()) as {
        result?: unknown;
        error?: { code?: number; message?: string };
      };
      if (body.error) {
        failures.push(`${url}: ${body.error.message ?? `rpc error ${body.error.code}`}`);
        continue;
      }
      return body.result as T;
    } catch (err) {
      failures.push(`${url}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  throw new Error(`every Base RPC endpoint failed for ${method} — ${failures.join('; ')}`);
}

function hexToNumber(hex: string): number {
  const n = Number.parseInt(hex, 16);
  if (!Number.isFinite(n)) throw new Error(`not a hex quantity: ${hex}`);
  return n;
}

function toHex(n: number): string {
  return '0x' + n.toString(16);
}

/** A 32-byte log topic back to a 20-byte address. */
function addressFromTopic(topic: string | undefined): string {
  if (typeof topic !== 'string' || topic.length < 42) {
    throw new Error(`topic is not an address: ${topic}`);
  }
  return '0x' + topic.slice(-40).toLowerCase();
}

function topicForAddress(address: string): string {
  return '0x' + address.replace(/^0x/, '').toLowerCase().padStart(64, '0');
}

/**
 * USDC has six decimals, so a raw Transfer value is already micro-USDC. It is
 * a uint256 on the wire and a JS integer here, which is only safe below 2^53 —
 * about nine billion dollars. Anything larger is not a payment we can book.
 */
function amountFromData(data: string): number {
  const raw = BigInt(data);
  if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`transfer amount ${raw} exceeds what can be held as an exact integer`);
  }
  return Number(raw);
}

// -------------------------------------------------------------- the run

/**
 * Scan whatever is new and confirmed, and record it.
 *
 * Bounded on purpose: `watcher.max_blocks_per_chunk` blocks per eth_getLogs
 * call and `watcher.max_chunks_per_run` calls per invocation, so a long
 * backlog is caught up over several cron ticks rather than in one request that
 * times out and makes no progress at all.
 */
export async function runWatcher(env: Env): Promise<WatcherResult> {
  const db = env.DB;
  const treasury = treasuryAddress(env);
  const empty: WatcherResult = {
    from_block: 0,
    to_block: 0,
    chunks: 0,
    observed: 0,
    matched: 0,
    unattributed: 0,
    outflows: 0,
    already_recorded: 0,
  };

  if (!treasury) {
    return { ...empty, skipped: 'TREASURY_ADDRESS is not a 0x address; nothing to observe' };
  }
  const usdc = env.USDC_CONTRACT?.trim().toLowerCase() ?? '';
  if (!/^0x[0-9a-f]{40}$/.test(usdc)) {
    return { ...empty, skipped: 'USDC_CONTRACT is not a 0x address; nothing to observe' };
  }

  const policy = new Policy(db);
  const confirmations = await policy.num('watcher.confirmations');
  const chunkSize = await policy.num('watcher.max_blocks_per_chunk');
  const maxChunks = await policy.num('watcher.max_chunks_per_run');
  const now = nowSeconds();

  // Read the cursor before spending an RPC call, so a backed-off run costs
  // nothing at all.
  const cursor = await one<{
    last_block: number;
    updated_at: number;
    last_error: string | null;
  }>(
    db,
    'SELECT last_block, updated_at, last_error FROM watcher_state WHERE id = ?',
    WATCHER_ID,
  );

  // Every endpoint we use is a free public one, and they answer rate limiting
  // with 429/403. Retrying on the next tick is how a temporary limit becomes a
  // permanent one: the cooldown lets the budget recover instead of spending the
  // next request re-learning that we are throttled. Nothing is lost by waiting —
  // the cursor does not move, payment intents live for 72 hours, and the scan
  // resumes exactly where it stopped.
  if (cursor && isRateLimited(cursor.last_error) && now - cursor.updated_at < RPC_COOLDOWN_SECONDS) {
    return {
      ...empty,
      from_block: cursor.last_block + 1,
      to_block: cursor.last_block,
      skipped: `every RPC endpoint was rate limited ${now - cursor.updated_at}s ago; backing off for ${RPC_COOLDOWN_SECONDS}s`,
    };
  }

  const head = hexToNumber(await rpc<string>(env, 'eth_blockNumber', []));
  const safeHead = head - confirmations;
  if (safeHead < 0) return { ...empty, skipped: `chain head ${head} is below the confirmation depth` };

  // First run starts at the confirmed head, not at block zero: this society
  // begins observing when it is founded, and anything before that is not its
  // history to claim. An operator wanting an earlier start sets last_block by
  // hand before the first tick.
  if (!cursor) {
    await db
      .prepare(
        `INSERT INTO watcher_state (id, last_block, updated_at, last_error)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT (id) DO NOTHING`,
      )
      .bind(WATCHER_ID, safeHead, now)
      .run();
    return { ...empty, from_block: safeHead, to_block: safeHead, skipped: 'watcher initialised at the confirmed head' };
  }

  const from = cursor.last_block + 1;
  if (from > safeHead) {
    await noteProgress(db, cursor.last_block, now, null);
    return { ...empty, from_block: from, to_block: cursor.last_block };
  }

  const result: WatcherResult = { ...empty, from_block: from };
  let chunkStart = from;
  let scannedTo = cursor.last_block;

  try {
    for (let chunk = 0; chunk < maxChunks && chunkStart <= safeHead; chunk++) {
      const chunkEnd = Math.min(chunkStart + chunkSize - 1, safeHead);
      const treasuryTopic = topicForAddress(treasury);

      const inflows = await rpc<RpcLog[]>(env, 'eth_getLogs', [
        {
          fromBlock: toHex(chunkStart),
          toBlock: toHex(chunkEnd),
          address: usdc,
          topics: [TRANSFER_TOPIC, null, treasuryTopic],
        },
      ]);
      const outflows = await rpc<RpcLog[]>(env, 'eth_getLogs', [
        {
          fromBlock: toHex(chunkStart),
          toBlock: toHex(chunkEnd),
          address: usdc,
          topics: [TRANSFER_TOPIC, treasuryTopic],
        },
      ]);

      // Ordered so the log reads the way the chain happened.
      const logs = [...(inflows ?? []), ...(outflows ?? [])].sort(
        (a, b) =>
          hexToNumber(a.blockNumber) - hexToNumber(b.blockNumber) ||
          hexToNumber(a.logIndex) - hexToNumber(b.logIndex),
      );

      for (const log of logs) {
        const outcome = await recordTransfer(db, policy, treasury, log, now);
        result.observed++;
        if (outcome === 'matched') result.matched++;
        else if (outcome === 'unattributed') result.unattributed++;
        else if (outcome === 'outflow') result.outflows++;
        else result.already_recorded++;
      }

      result.chunks++;
      scannedTo = chunkEnd;
      chunkStart = chunkEnd + 1;
    }
  } catch (err) {
    // Whatever was recorded before the failure stays recorded, and the cursor
    // advances only over the blocks fully scanned. The error is stored so
    // /api/treasury shows a stalled watcher rather than a silent one.
    const message = err instanceof Error ? err.message : String(err);
    await noteProgress(db, scannedTo, now, message);
    throw err;
  }

  await noteProgress(db, scannedTo, now, null);
  result.to_block = scannedTo;
  return result;
}

/** The scan cursor. Not a domain table: it has no event_seq and causes nothing. */
async function noteProgress(
  db: D1Database,
  lastBlock: number,
  now: number,
  error: string | null,
): Promise<void> {
  await db
    .prepare('UPDATE watcher_state SET last_block = ?, updated_at = ?, last_error = ? WHERE id = ?')
    .bind(lastBlock, now, error, WATCHER_ID)
    .run();
}

type TransferOutcome = 'matched' | 'unattributed' | 'outflow' | 'already_recorded';

interface PendingRow {
  id: string;
  purpose: string;
  ref_id: string | null;
  citizen_id: string | null;
  from_address: string | null;
  status: string;
  expires_at: number;
}

/**
 * Record one Transfer as one event.
 *
 * The flow row is a guard rather than a write, so a transfer another run
 * already recorded reports zero changes and the whole batch is refused — which
 * is exactly right, because the second sighting is not a second payment.
 */
async function recordTransfer(
  db: D1Database,
  policy: Policy,
  treasury: string,
  log: RpcLog,
  now: number,
): Promise<TransferOutcome> {
  const txhash = log.transactionHash.toLowerCase();
  const logIndex = hexToNumber(log.logIndex);
  const blockNumber = hexToNumber(log.blockNumber);
  const from = addressFromTopic(log.topics[1]);
  const to = addressFromTopic(log.topics[2]);
  const amount = amountFromData(log.data);
  const direction: 'in' | 'out' = to === treasury ? 'in' : 'out';
  const counterparty = direction === 'in' ? from : to;

  // A transfer from the treasury to itself moves nothing and would book two
  // legs against one account.
  if (from === to) return 'already_recorded';

  const flowGuard = (status: string, matchedRef: string | null): D1PreparedStatement =>
    db
      .prepare(
        `INSERT INTO treasury_flows
           (txhash, log_index, block_number, direction, counterparty, amount,
            matched_ref, status, observed_at, event_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT seq FROM chain_head WHERE id = 1))
         ON CONFLICT (txhash, log_index) DO NOTHING`,
      )
      .bind(txhash, logIndex, blockNumber, direction, counterparty, amount, matchedRef, status, now);

  if (direction === 'out') {
    // An outflow the operator has not confirmed against a receipt. It is
    // recorded because it happened, and left unbooked because nothing in the
    // society justifies it yet — the gap between the observed balance and the
    // books is the signal, and hiding it would be the bug.
    return runAppend(db, {
      type: 'treasury.outflow_observed',
      payload: {
        txhash,
        log_index: logIndex,
        block_number: blockNumber,
        direction: 'out',
        counterparty,
        to_address: to,
        amount,
        booked: false,
        note: 'observed leaving the treasury; not yet tied to a receipt or a close',
      },
      guards: [flowGuard('observed', null)],
      writes: [],
      outcome: 'outflow',
    });
  }

  // The fingerprint. expected_amount is globally unique, so this is a lookup,
  // not a search over candidates.
  const intent = await one<PendingRow>(
    db,
    `SELECT id, purpose, ref_id, citizen_id, from_address, status, expires_at
       FROM pending_payments WHERE expected_amount = ?`,
    amount,
  );

  const usable =
    intent !== null &&
    intent.status === 'pending' &&
    intent.expires_at > now &&
    // A pre-declared sender is a promise about who pays. A different address
    // paying the same amount is not that citizen, and matching it would let a
    // stranger buy someone else's citizenship.
    (intent.from_address === null || intent.from_address === counterparty);

  if (!usable) {
    const claimDays = await policy.num('unattributed.claim_window_days');
    // Money arrived that nothing reserved. It is booked as a liability rather
    // than as revenue, and the legs ride in the payload so the chain — not the
    // table — is what a verifier rebuilds the books from.
    const book = bookLegs(db, [
      {
        ts: now,
        debit: ACCOUNTS.TREASURY,
        credit: ACCOUNTS.UNATTRIBUTED,
        amount,
        memo: `unattributed inflow ${txhash}#${logIndex}`,
        refType: 'inflow',
        refId: txhash,
      },
    ]);
    return runAppend(db, {
      type: 'treasury.inflow_unattributed',
      payload: {
        txhash,
        log_index: logIndex,
        block_number: blockNumber,
        direction: 'in',
        counterparty,
        amount,
        matched: false,
        reason: intent === null
          ? 'no payment intent reserves this exact amount'
          : intent.status !== 'pending'
            ? `intent ${intent.id} is ${intent.status}`
            : intent.expires_at <= now
              ? `intent ${intent.id} expired at ${intent.expires_at}`
              : `intent ${intent.id} expected a payment from ${intent.from_address}`,
        claim_window_days: claimDays,
        legs: book.legs,
      },
      guards: [flowGuard('unattributed', null)],
      writes: book.writes,
      outcome: 'unattributed',
    });
  }

  const matched = intent as PendingRow;
  const account = accountForPurpose(matched.purpose);
  if (account === null) {
    // The fingerprint matched an intent whose purpose books nowhere. Refusing
    // is the only honest option: booking it to a plausible account would put a
    // wrong number in the books, which is worse than a failed cron tick.
    throw new Error(
      `payment intent ${matched.id} has purpose "${matched.purpose}", which maps to no ledger account`,
    );
  }
  const book = bookLegs(db, [
    {
      ts: now,
      debit: ACCOUNTS.TREASURY,
      credit: account,
      amount,
      memo: `${matched.purpose} payment ${txhash}#${logIndex}`,
      refType: matched.purpose,
      refId: matched.ref_id ?? matched.id,
    },
  ]);
  const writes: D1PreparedStatement[] = [...book.writes];

  // Funding a bounty is what makes it claimable. It rides in this batch rather
  // than in an event of its own so that the money and the state it unlocks
  // land together or not at all.
  if (matched.purpose === 'bounty_funding' && matched.ref_id) {
    writes.push(
      db
        .prepare(`UPDATE bounties SET status = 'funded' WHERE id = ? AND status = 'draft'`)
        .bind(matched.ref_id),
    );
  }

  return runAppend(db, {
    type: 'treasury.inflow_matched',
    payload: {
      txhash,
      log_index: logIndex,
      block_number: blockNumber,
      direction: 'in',
      counterparty,
      amount,
      matched: true,
      payment_id: matched.id,
      purpose: matched.purpose,
      ref_id: matched.ref_id,
      citizen_id: matched.citizen_id,
      account,
      bounty_funded: matched.purpose === 'bounty_funding' ? matched.ref_id : null,
      legs: book.legs,
    },
    guards: [
      flowGuard('matched', matched.id),
      db
        .prepare(
          `UPDATE pending_payments SET status = 'matched', matched_txhash = ?
             WHERE id = ? AND status = 'pending'`,
        )
        .bind(txhash, matched.id),
    ],
    writes,
    outcome: 'matched',
  });
}

/**
 * Append, treating a refused guard as "someone already recorded this".
 *
 * The watcher's guards do not enforce anyone's rights; they enforce
 * idempotence. A cron tick overlapping the previous one must not book the same
 * dollar twice, and must not raise an alarm about not having done so.
 */
async function runAppend(
  db: D1Database,
  input: {
    type: 'treasury.inflow_matched' | 'treasury.inflow_unattributed' | 'treasury.outflow_observed';
    payload: Record<string, unknown>;
    guards: D1PreparedStatement[];
    writes: D1PreparedStatement[];
    outcome: TransferOutcome;
  },
): Promise<TransferOutcome> {
  try {
    await appendEventWithRetry(db, {
      type: input.type,
      actor: null,
      payload: input.payload,
      guards: input.guards,
      writes: input.writes,
    });
    return input.outcome;
  } catch (err) {
    if (err instanceof GuardFailedError) return 'already_recorded';
    throw err;
  }
}

// ------------------------------------------------------- payout verification

export interface PayoutCheck {
  ok: boolean;
  /** Why it did not verify, when it did not. */
  reason?: string;
  block_number?: number;
  log_index?: number;
  /** What the chain actually showed, when it disagreed with the claim. */
  observed?: Array<{ to: string; amount: number; log_index: number }>;
}

/**
 * Confirm that a payout the operator says it made actually happened.
 *
 * Read-only: it fetches the receipt for one transaction and looks for a USDC
 * Transfer of the exact amount to the exact address the worker fixed in the
 * log. The operator's word is not evidence; the transaction is.
 */
export async function verifyPayout(
  env: Env,
  claim: { txhash: string; to: string; amount: number },
): Promise<PayoutCheck> {
  const treasury = treasuryAddress(env);
  if (!treasury) return { ok: false, reason: 'no treasury address is configured to verify against' };

  const usdc = env.USDC_CONTRACT?.trim().toLowerCase() ?? '';
  if (!/^0x[0-9a-f]{40}$/.test(usdc)) {
    return { ok: false, reason: 'USDC_CONTRACT is not a 0x address' };
  }

  const receipt = await rpc<{
    status?: string;
    blockNumber?: string;
    logs?: RpcLog[];
  } | null>(env, 'eth_getTransactionReceipt', [claim.txhash.toLowerCase()]);

  if (!receipt) {
    return { ok: false, reason: `Base has no receipt for ${claim.txhash}; it is not mined or does not exist` };
  }
  if (receipt.status !== undefined && hexToNumber(receipt.status) !== 1) {
    return { ok: false, reason: `transaction ${claim.txhash} reverted` };
  }

  const to = claim.to.toLowerCase();
  const observed: Array<{ to: string; amount: number; log_index: number }> = [];

  for (const log of receipt.logs ?? []) {
    if (log.address.toLowerCase() !== usdc) continue;
    if (log.topics[0]?.toLowerCase() !== TRANSFER_TOPIC) continue;
    const sender = addressFromTopic(log.topics[1]);
    if (sender !== treasury) continue;

    const recipient = addressFromTopic(log.topics[2]);
    const amount = amountFromData(log.data);
    const logIndex = hexToNumber(log.logIndex);
    observed.push({ to: recipient, amount, log_index: logIndex });

    if (recipient === to && amount === claim.amount) {
      return {
        ok: true,
        block_number: receipt.blockNumber ? hexToNumber(receipt.blockNumber) : undefined,
        log_index: logIndex,
      };
    }
  }

  return {
    ok: false,
    reason:
      observed.length === 0
        ? `${claim.txhash} carries no USDC transfer out of the treasury`
        : `${claim.txhash} moves USDC out of the treasury, but not ${claim.amount} to ${to}`,
    block_number: receipt.blockNumber ? hexToNumber(receipt.blockNumber) : undefined,
    observed,
  };
}

/**
 * What the chain says the treasury holds right now. Read-only and unauthenticated;
 * used to show the observed balance next to the books rather than instead of them.
 */
export async function treasuryBalance(env: Env): Promise<number | null> {
  const treasury = treasuryAddress(env);
  const usdc = env.USDC_CONTRACT?.trim().toLowerCase() ?? '';
  if (!treasury || !/^0x[0-9a-f]{40}$/.test(usdc)) return null;

  // balanceOf(address) — selector 0x70a08231, argument left-padded to 32 bytes.
  const data = '0x70a08231' + treasury.replace(/^0x/, '').padStart(64, '0');
  const result = await rpc<string>(env, 'eth_call', [{ to: usdc, data }, 'latest']);
  return amountFromData(result);
}

/** Read-only view of where the scan has got to, for /api/treasury. */
export async function watcherState(
  db: D1Database,
): Promise<{ last_block: number; updated_at: number; last_error: string | null } | null> {
  const rows = await many<{ last_block: number; updated_at: number; last_error: string | null }>(
    db,
    'SELECT last_block, updated_at, last_error FROM watcher_state WHERE id = ?',
    WATCHER_ID,
  );
  return rows[0] ?? null;
}
