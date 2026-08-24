/**
 * The spine.
 *
 * Every material mutation in this society appends exactly one event, in the same
 * D1 batch as its domain writes. If it did not go through appendEvent, it did
 * not happen — and the offline verifier will say so.
 *
 * D1 gives us a single writer per database and `batch()` runs as one implicit
 * transaction, so read-head → compute-hash → write-head is safe here: two
 * concurrent appends serialize, and the loser's UNIQUE(hash) / stale-head
 * condition fails its whole batch rather than forking the chain.
 */

import { canonicalize } from './canonical';
import { sha256Hex } from './crypto';
import type { EventType } from './constitution';

export const GENESIS_PREV_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * The seq of the event being appended, as SQL, for domain rows that carry an
 * `event_seq` column.
 *
 * Only a `writes` statement may use it. Guards run before the event is
 * inserted, so inside a guard this still reads the previous head; by the time
 * writes run, appendEvent has already advanced chain_head to this event.
 */
export const EVENT_SEQ = '(SELECT seq FROM chain_head WHERE id = 1)';

export interface AppendInput {
  type: EventType;
  actor: string | null;
  payload: Record<string, unknown>;
  /** The request signature that authorised this, for provenance. */
  sig?: string | null;
  /**
   * The exact string that signature covers. Without it an auditor can verify
   * the chain's integrity but cannot confirm any event was authorised by the
   * citizen it names, because the signed string cannot be reconstructed from
   * the row. Pass `signed.signedString` wherever you pass `signed.sig`.
   */
  sigMaterial?: string | null;
  /** Extra statements to commit atomically with the event. */
  writes?: D1PreparedStatement[];
  /** Statements that must each report changes === 1, or the batch is rejected. */
  guards?: D1PreparedStatement[];
  ts?: number;
}

export interface AppendResult {
  seq: number;
  hash: string;
  ts: number;
}

export interface ChainHead {
  seq: number;
  hash: string;
}

export class ChainConflictError extends Error {
  constructor(message = 'chain head moved during append') {
    super(message);
    this.name = 'ChainConflictError';
  }
}

export class GuardFailedError extends Error {
  constructor(
    message: string,
    readonly index: number,
  ) {
    super(message);
    this.name = 'GuardFailedError';
  }
}

/**
 * Make a guard actually guard.
 *
 * D1 rolls a batch back when a statement *errors*, not when it merely changes
 * no rows — so a guard that refuses by reporting `changes = 0` does not stop
 * anything on its own. Inspecting the results afterwards is too late: by then
 * the batch has committed, and the caller would get a 429 for a post that is
 * already live.
 *
 * So every guard is followed by this. `changes()` reports what the immediately
 * preceding statement did, and `chain_head` carries `CHECK (id = 1)`, so when
 * the guard refused this tries to insert id 2, the CHECK fails, and D1 rolls
 * the whole batch back. When the guard passed, the SELECT yields no row and
 * this does nothing at all.
 */
function guardSentinel(db: D1Database): D1PreparedStatement {
  return db.prepare(
    `INSERT INTO chain_head (id, seq, hash)
     SELECT 2, 0, 'guard refused' WHERE changes() = 0`,
  );
}

/** Ends a probe batch so it can never commit, with a distinguishable error. */
function probeAbort(db: D1Database): D1PreparedStatement {
  return db.prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, NULL)');
}

/** chain_head's CHECK is the only one in the schema, so this is unambiguous. */
function isGuardAbort(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const cause = err.cause instanceof Error ? err.cause.message : '';
  return `${err.message} ${cause}`.includes('CHECK constraint failed');
}

/**
 * Which guard refused, for the caller's error message.
 *
 * The sentinel aborts the batch but cannot say which one it was, so each guard
 * is replayed alone, followed by its sentinel and then an unconditional abort.
 * The abort guarantees the probe commits nothing; the error that comes back
 * says whether it was the sentinel (this guard refuses) or the abort (this
 * guard would have passed). Only ever runs on the refusal path.
 */
async function firstRefusingGuard(
  db: D1Database,
  guards: D1PreparedStatement[],
): Promise<number> {
  for (let i = 0; i < guards.length; i++) {
    const guard = guards[i];
    if (!guard) continue;
    try {
      await db.batch([guard, guardSentinel(db), probeAbort(db)]);
    } catch (err) {
      if (isGuardAbort(err)) return i;
    }
  }
  // Every guard passed on replay, so the refusal was a race rather than a
  // standing condition. Report the first guard: the caller needs some label,
  // and guards run in the order they were passed.
  return 0;
}

export async function readHead(db: D1Database): Promise<ChainHead> {
  const row = await db
    .prepare('SELECT seq, hash FROM chain_head WHERE id = 1')
    .first<{ seq: number; hash: string }>();
  if (!row) return { seq: 0, hash: GENESIS_PREV_HASH };
  return { seq: row.seq, hash: row.hash };
}

/**
 * The canonical bytes an event's hash covers. The offline verifier recomputes
 * this exactly; changing it invalidates every prior checkpoint.
 */
export function eventHashInput(e: {
  seq: number;
  ts: number;
  type: string;
  actor: string | null;
  payload: Record<string, unknown>;
  prevHash: string;
}): string {
  const body = canonicalize({
    seq: e.seq,
    ts: e.ts,
    type: e.type,
    actor: e.actor,
    payload: e.payload,
  });
  return e.prevHash + '\n' + body;
}

export async function computeEventHash(e: {
  seq: number;
  ts: number;
  type: string;
  actor: string | null;
  payload: Record<string, unknown>;
  prevHash: string;
}): Promise<string> {
  return sha256Hex(eventHashInput(e));
}

/**
 * Append one event plus its domain writes atomically.
 *
 * Ordering inside the batch matters: guards run first so a quota denial or a
 * replayed nonce aborts before anything else lands.
 */
export async function appendEvent(
  db: D1Database,
  input: AppendInput,
): Promise<AppendResult> {
  const head = await readHead(db);
  const seq = head.seq + 1;
  const ts = input.ts ?? nowSeconds();
  const payloadJson = canonicalize(input.payload);

  const hash = await computeEventHash({
    seq,
    ts,
    type: input.type,
    actor: input.actor,
    payload: input.payload,
    prevHash: head.hash,
  });

  const guards = input.guards ?? [];
  const writes = input.writes ?? [];

  const insertEvent = db
    .prepare(
      `INSERT INTO events (seq, ts, type, actor, payload, sig, sig_material, prev_hash, hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      seq,
      ts,
      input.type,
      input.actor,
      payloadJson,
      input.sig ?? null,
      input.sigMaterial ?? null,
      head.hash,
      hash,
    );

  // Conditional on the head we read. If another append won the race, this
  // updates zero rows and we reject the whole batch rather than fork.
  const advanceHead = db
    .prepare(
      `UPDATE chain_head SET seq = ?, hash = ?
       WHERE id = 1 AND seq = ? AND hash = ?`,
    )
    .bind(seq, hash, head.seq, head.hash);

  // Each guard is immediately followed by its sentinel, so the first guard to
  // refuse takes the whole batch down with it rather than letting the event
  // land and being reported afterwards.
  const statements: D1PreparedStatement[] = [];
  for (const guard of guards) statements.push(guard, guardSentinel(db));
  statements.push(insertEvent, advanceHead, ...writes);

  let results: D1Result[];
  try {
    results = await db.batch(statements);
  } catch (err) {
    if (isGuardAbort(err)) {
      const index = await firstRefusingGuard(db, guards);
      throw new GuardFailedError(`guard ${index} rejected the append`, index);
    }
    throw err;
  }

  // The batch committed, so every guard must have changed a row. If one did
  // not, the sentinel above failed to fire — which means the mechanism that
  // makes refusals real is broken, and a mutation just landed that should not
  // have. Say so loudly; a silent version of this is how books stop balancing.
  for (let i = 0; i < guards.length; i++) {
    const r = results[i * 2];
    if (!r || (r.meta?.changes ?? 0) < 1) {
      throw new Error(
        `guard ${i} reported no change yet the batch committed at seq ${seq}: the guard sentinel did not fire`,
      );
    }
  }

  const headResult = results[guards.length * 2 + 1];
  if (!headResult || (headResult.meta?.changes ?? 0) !== 1) {
    throw new ChainConflictError();
  }

  return { seq, hash, ts };
}

/**
 * Retry wrapper for head contention. D1 serializes writers, so a conflict means
 * someone else appended between our read and write — recompute and try again.
 */
export async function appendEventWithRetry(
  db: D1Database,
  input: AppendInput,
  attempts = 4,
): Promise<AppendResult> {
  let lastError: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await appendEvent(db, input);
    } catch (err) {
      if (err instanceof GuardFailedError) throw err; // not a race; a real refusal
      lastError = err;
      // Small jittered backoff. Workers has no setTimeout-free sleep, and this
      // is bounded by the batch cost anyway.
      await sleep(5 + Math.floor(Math.random() * 20));
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new ChainConflictError('append failed after retries');
}

/** Rebuild statements need a fresh head each attempt; this helps callers. */
export async function withHead<T>(
  db: D1Database,
  fn: (head: ChainHead) => Promise<T>,
): Promise<T> {
  return fn(await readHead(db));
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function utcDay(ts: number = nowSeconds()): string {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
