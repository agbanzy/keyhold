/**
 * Double-entry, one place.
 *
 * Every ledger row is written as part of some other event's batch — a bounty
 * accepted, an inflow matched, a payout verified — never on its own, because a
 * book entry with no cause is a book entry nobody can check. The statement is
 * built here so all four surfaces (REST, MCP, admin, watcher) book money the
 * same way and use the account names from constitution.ts rather than strings.
 *
 * A row in `ledger_entries` is not, on its own, covered by anything: the event
 * hash covers the payload, not the domain writes. So `bookLegs` returns the
 * writes *and* the same legs as canonical payload records, and the caller must
 * put those records under `legs` in the event payload. Replaying the chain then
 * reconstructs the books exactly, and scripts/verify.mjs fails if the table and
 * the chain disagree by so much as one row.
 *
 *   const book = bookLegs(db, [{ ts: now, debit: ACCOUNTS.ESCROW, ... }]);
 *   await appendEventWithRetry(db, {
 *     type: 'bounty.accepted',
 *     payload: { ..., legs: book.legs },
 *     writes: [...otherWrites, ...book.writes],
 *   });
 *
 * `bookLegs`/`bookLeg` are the only way to book money, and there is deliberately
 * no export that returns a bare INSERT: a leg written that way is invisible to
 * the chain, and the verifier reports it as a book entry with no cause — the
 * whole failure this module exists to make impossible. If you find yourself
 * wanting one, you want a `legs` key in your payload instead.
 */

import { ACCOUNTS } from '../core/constitution';
import { newId } from '../core/crypto';
import { EVENT_SEQ } from '../core/events';

export interface LedgerLeg {
  ts: number;
  /** Where the value goes. */
  debit: string;
  /** Where it comes from. */
  credit: string;
  /** Micro-USDC, always positive. */
  amount: number;
  memo?: string;
  refType?: string;
  refId?: string;
}

/**
 * A leg as it appears in an event payload: snake_case like every other payload
 * field, every column present, absent values explicitly null. The row and this
 * record carry the same `id`, which is what lets a verifier match them one to
 * one rather than only comparing totals.
 */
export interface LedgerLegRecord {
  id: string;
  ts: number;
  debit: string;
  credit: string;
  amount: number;
  memo: string | null;
  ref_type: string | null;
  ref_id: string | null;
}

export interface BookedLegs {
  /** For the event's `writes`. */
  writes: D1PreparedStatement[];
  /** For the event's payload, under the key `legs`. */
  legs: LedgerLegRecord[];
}

/**
 * Book one or more legs. Amounts are positive by construction: a negative or
 * zero entry means the caller worked out the direction wrong, and a wrong
 * number in the books is worse than a 500.
 */
export function bookLegs(db: D1Database, entries: LedgerLeg[]): BookedLegs {
  const legs = entries.map(legRecord);
  return { writes: legs.map((leg) => legStatement(db, leg)), legs };
}

/** The single-leg case, so a caller with one entry does not build an array. */
export function bookLeg(
  db: D1Database,
  entry: LedgerLeg,
): { write: D1PreparedStatement; leg: LedgerLegRecord } {
  const leg = legRecord(entry);
  return { write: legStatement(db, leg), leg };
}

function legRecord(e: LedgerLeg): LedgerLegRecord {
  if (!Number.isSafeInteger(e.amount) || e.amount <= 0) {
    throw new Error(`ledger entry amount must be a positive integer, got ${e.amount}`);
  }
  if (e.debit === e.credit) {
    throw new Error(`ledger entry debits and credits the same account: ${e.debit}`);
  }
  if (!Number.isSafeInteger(e.ts)) {
    throw new Error(`ledger entry ts must be an integer, got ${e.ts}`);
  }
  return {
    id: newId('le'),
    ts: e.ts,
    debit: e.debit,
    credit: e.credit,
    amount: e.amount,
    memo: e.memo ?? null,
    ref_type: e.refType ?? null,
    ref_id: e.refId ?? null,
  };
}

function legStatement(db: D1Database, leg: LedgerLegRecord): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO ledger_entries
         (id, ts, debit, credit, amount, memo, ref_type, ref_id, event_seq)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ${EVENT_SEQ})`,
    )
    .bind(
      leg.id,
      leg.ts,
      leg.debit,
      leg.credit,
      leg.amount,
      leg.memo,
      leg.ref_type,
      leg.ref_id,
    );
}

/** Re-exported so call sites never spell an account name as a literal. */
export { ACCOUNTS };
