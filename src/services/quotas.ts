/**
 * Scarcity enforcement.
 *
 * The check and the spend are the same statement: a conditional upsert that only
 * increments while `used < limit`. It rides inside the mutation's D1 batch as a
 * guard, so there is no window between "you may post" and "you posted". If the
 * statement reports zero changes, the batch is rejected and the caller gets 429.
 *
 * Quotas do not accumulate. Unspent quota is gone at 00:00 UTC, which is what
 * stops a quota market forming.
 */

import { utcDay } from '../core/events';
import type { Policy } from './policy';
import type { PolicyKey } from '../core/constitution';

export type QuotaAction =
  | 'post'
  | 'comment'
  | 'vote'
  | 'proposal'
  | 'invite'
  | 'claim';

const POLICY_KEY: Record<QuotaAction, PolicyKey> = {
  post: 'quota.post',
  comment: 'quota.comment',
  vote: 'quota.vote',
  proposal: 'quota.proposal_per_week',
  invite: 'quota.invite_per_month',
  claim: 'quota.active_claims',
};

export interface CitizenQuotaContext {
  status: string;
  created_at: number;
  frozen_until: number | null;
}

/**
 * The effective limit for one citizen and action, after probation scaling.
 * Probation halves quotas for the first week so a fresh key cannot arrive at
 * full volume.
 */
export async function effectiveLimit(
  policy: Policy,
  action: QuotaAction,
  citizen: CitizenQuotaContext,
  now: number,
): Promise<number> {
  const base = await policy.num(POLICY_KEY[action]);
  const probationDays = await policy.num('probation.days');
  const inProbation = now - citizen.created_at < probationDays * 86400;
  if (!inProbation) return base;
  const factor = await policy.num('probation.quota_factor_pct');
  return Math.max(1, Math.floor((base * factor) / 100));
}

/**
 * The guard statement. Include it in appendEvent({ guards: [...] }).
 *
 * `window` lets weekly and monthly allowances share the table: the day column
 * holds the window identifier, not necessarily a calendar day.
 */
export function spendQuotaGuard(
  db: D1Database,
  citizenId: string,
  action: QuotaAction,
  limit: number,
  window: string,
): D1PreparedStatement {
  // The limit binds on both branches. `VALUES` would insert the first row of a
  // window unconditionally, so a limit voted to 0 still bought one action per
  // citizen per window; the SELECT makes the first spend obey the limit too.
  return db
    .prepare(
      `INSERT INTO quota_usage (citizen_id, day, action, used)
       SELECT ?, ?, ?, 1 WHERE ? >= 1
       ON CONFLICT (citizen_id, day, action)
       DO UPDATE SET used = used + 1
       WHERE quota_usage.used < ?`,
    )
    .bind(citizenId, window, action, limit, limit);
}

/** Daily actions use the UTC date. */
export function dailyWindow(now: number): string {
  return utcDay(now);
}

/** Proposals are per 7 days: bucket by ISO week-ish index since epoch. */
export function weeklyWindow(now: number): string {
  return `w${Math.floor(now / (7 * 86400))}`;
}

/** Invites are per 30 days. */
export function monthlyWindow(now: number): string {
  return `m${Math.floor(now / (30 * 86400))}`;
}

export function windowFor(action: QuotaAction, now: number): string {
  switch (action) {
    case 'proposal':
      return weeklyWindow(now);
    case 'invite':
      return monthlyWindow(now);
    default:
      return dailyWindow(now);
  }
}

/** Read-only view of what a citizen has spent, for /whoami and headers. */
export async function usageFor(
  db: D1Database,
  citizenId: string,
  now: number,
): Promise<Record<string, { used: number; window: string }>> {
  const windows = new Set<string>([
    dailyWindow(now),
    weeklyWindow(now),
    monthlyWindow(now),
  ]);
  const placeholders = [...windows].map(() => '?').join(',');
  const rows = await db
    .prepare(
      `SELECT action, day, used FROM quota_usage
       WHERE citizen_id = ? AND day IN (${placeholders})`,
    )
    .bind(citizenId, ...[...windows])
    .all<{ action: string; day: string; used: number }>();

  const out: Record<string, { used: number; window: string }> = {};
  for (const r of rows.results ?? []) {
    out[r.action] = { used: r.used, window: r.day };
  }
  return out;
}

/**
 * Active claims are a concurrency cap rather than a rate: count open claims
 * directly instead of consuming a daily counter.
 */
export function activeClaimsGuard(
  db: D1Database,
  citizenId: string,
  limit: number,
): D1PreparedStatement {
  // A no-op UPDATE that only "changes" a row when the citizen is under the cap.
  return db
    .prepare(
      `UPDATE citizens SET id = id
       WHERE id = ?
         AND (SELECT COUNT(*) FROM claims
              WHERE citizen_id = ? AND status IN ('open','submitted')) < ?`,
    )
    .bind(citizenId, citizenId, limit);
}

/**
 * Frozen citizens cannot write. Enforced as a guard, not a pre-check.
 *
 * `frozen_until` is the freeze — the whole of it. `status` says what a citizen
 * is (probation, active, departed); the deadline says whether they are silenced
 * right now. Nothing in the system writes status = 'frozen' any more, and that
 * is deliberate: a freeze expressed as a status is a freeze nothing ever lifts,
 * which is how the Warden's 72-hour cap became permanent silencing.
 *
 * So the office sets a deadline (routes/admin.ts), this statement refuses until
 * it passes, and the citizen writes again the moment it does — with no cron and
 * no second Warden action in the path. The sweep in index.ts only clears the
 * spent deadline so /api/whoami and the viewer stop showing a freeze that is
 * over; it is bookkeeping, and this statement is the authority.
 */
export function notFrozenGuard(
  db: D1Database,
  citizenId: string,
  now: number,
): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE citizens SET id = id
       WHERE id = ?
         AND status IN ('probation','active')
         AND (frozen_until IS NULL OR frozen_until <= ?)`,
    )
    .bind(citizenId, now);
}
