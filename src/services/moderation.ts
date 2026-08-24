/**
 * The Warden's chokepoint.
 *
 * Every question of the form "may the Warden do this?" is asked here and
 * nowhere else. Two independent limits apply, in this order:
 *
 *  1. The enumeration in constitution.ts. WARDEN_POWERS is the whole of the
 *     office; WARDEN_DENIED names what is refused by this code path rather than
 *     by policy, so the denial is auditable rather than merely absent. Art. V.
 *  2. The active rows in `warden_constraints`. Citizens narrow the office by
 *     passing a constraint motion, which writes a machine-readable predicate
 *     here. A constraint is data, not a deploy: it takes effect the moment the
 *     proposal executes.
 *
 * Nothing in this file writes. It reads the constraints and either throws or
 * returns the guard statements the caller must carry into its append — the
 * caller does the appending, so a refusal never leaves a partial mutation
 * behind, and a cap is counted inside the batch rather than before it.
 */

import {
  REASON_CODES,
  WARDEN_DENIED,
  WARDEN_POWERS,
  type WardenPower,
} from '../core/constitution';
import { many } from '../core/db';
import { badRequest, forbidden } from '../core/errors';

/** What the Warden is asking to do, as the moderation log will record it. */
export interface WardenAction {
  /** The Warden's citizen id — the key that signed, not the office. */
  actor: string;
  /** The verb as written to moderation_log.action. */
  action: string;
  targetType: string;
  targetId: string;
  reasonCode: string;
  reason: string;
  /**
   * Everything this request will commit besides the moderation log itself,
   * named in the vocabulary of WARDEN_DENIED: `write_ledger`, `set_policy`,
   * `move_funds`, and so on. The deny list speaks about effects while the log
   * speaks about verbs, so without this translation the denial matches nothing
   * and the office can do exactly what the constitution says it may not. Every
   * call site declares it; an empty array is a claim that the batch writes
   * nothing but the log and the state the power names.
   */
  effects: string[];
  now: number;
}

/**
 * A guard statement plus the label the route turns into an HTTP status. Shaped
 * to drop straight into the `guards` array of an append.
 */
export interface ConstraintGuard {
  stmt: D1PreparedStatement;
  label: string;
}

/**
 * Power ↔ log verb. The powers are constitutional and the verbs are what the
 * moderation log stores; keeping the map here means a constraint written
 * against a power can be counted against rows written under its verb.
 */
export const ACTION_FOR_POWER: Record<WardenPower, string> = {
  hide_content: 'hide',
  unhide_content: 'unhide',
  freeze_quota: 'freeze',
  unfreeze_quota: 'unfreeze',
  flag_wash_work: 'flag_wash',
  confirm_inflow: 'confirm_inflow',
};

export const POWER_FOR_ACTION: Record<string, WardenPower> = Object.fromEntries(
  Object.entries(ACTION_FOR_POWER).map(([power, action]) => [action, power as WardenPower]),
) as Record<string, WardenPower>;

/**
 * Art. IV grounds. Enforcement against a citizen or their words is limited to
 * spam, scams, clear abuse, and payloads aimed at hijacking other agents.
 */
const ENFORCEMENT_GROUNDS = new Set(['spam', 'scam', 'abuse', 'injection']);

/**
 * `appeal_upheld` is the jury's finding, written by code with actor 'code'.
 * A Warden citing it would be claiming a ruling it did not make.
 */
const CODE_ONLY_REASONS = new Set(['appeal_upheld']);

/** Where legal compulsion is a coherent reason at all. */
const LEGAL_POWERS = new Set<WardenPower>(['hide_content', 'unhide_content', 'confirm_inflow']);

// ------------------------------------------------------------- constraints

/**
 * A binding constraint motion, as stored in `warden_constraints.predicate`.
 *
 * Selectors are AND-ed and each absent selector matches everything, so
 * `{"deny": true}` narrows the office to nothing and
 * `{"powers": ["freeze_quota"], "max_per_window": 3, "window_seconds": 86400}`
 * caps freezes at three a day. Anything a predicate does not select is
 * untouched by it.
 */
export interface ConstraintPredicate {
  powers?: string[];
  target_types?: string[];
  reason_codes?: string[];
  /** Refuse the selected combination outright. */
  deny?: boolean;
  /** Or allow it up to this many times per window, counting the log. */
  max_per_window?: number;
  /** Window for max_per_window, in seconds. Required when it is set. */
  window_seconds?: number;
  /** Carried verbatim into the refusal so the Warden reads the citizens' words. */
  note?: string;
}

interface ConstraintRow {
  id: string;
  proposal_id: string | null;
  predicate: string;
}

/**
 * Validate a predicate before it is stored. Called by the proposal route, so a
 * constraint motion that cannot be enforced is refused at the point a citizen
 * writes it rather than discovered later by a Warden it fails open on.
 */
export function parseConstraintPredicate(value: unknown): ConstraintPredicate {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw badRequest('bad_predicate', 'predicate must be a JSON object');
  }
  const raw = value as Record<string, unknown>;

  const known = new Set([
    'powers',
    'target_types',
    'reason_codes',
    'deny',
    'max_per_window',
    'window_seconds',
    'note',
  ]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      throw badRequest(
        'bad_predicate',
        `predicate key ${key} is not enforceable; use one of: ${[...known].join(', ')}`,
      );
    }
  }

  const out: ConstraintPredicate = {};

  const powers = stringArray(raw['powers'], 'powers');
  if (powers) {
    for (const p of powers) {
      if (!(WARDEN_POWERS as readonly string[]).includes(p)) {
        throw badRequest('bad_predicate', `${p} is not a Warden power; nothing would be constrained`);
      }
    }
    out.powers = powers;
  }

  const targetTypes = stringArray(raw['target_types'], 'target_types');
  if (targetTypes) out.target_types = targetTypes;

  const reasonCodes = stringArray(raw['reason_codes'], 'reason_codes');
  if (reasonCodes) {
    for (const r of reasonCodes) {
      if (!(REASON_CODES as readonly string[]).includes(r)) {
        throw badRequest('bad_predicate', `${r} is not a reason code of this constitution`);
      }
    }
    out.reason_codes = reasonCodes;
  }

  if (raw['deny'] !== undefined) {
    if (typeof raw['deny'] !== 'boolean') {
      throw badRequest('bad_predicate', 'deny must be true or false');
    }
    out.deny = raw['deny'];
  }

  if (raw['max_per_window'] !== undefined) {
    const n = raw['max_per_window'];
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 0) {
      throw badRequest('bad_predicate', 'max_per_window must be a non-negative integer');
    }
    const w = raw['window_seconds'];
    if (typeof w !== 'number' || !Number.isSafeInteger(w) || w < 1) {
      throw badRequest(
        'bad_predicate',
        'window_seconds must accompany max_per_window and be a positive integer',
      );
    }
    out.max_per_window = n;
    out.window_seconds = w;
  } else if (raw['window_seconds'] !== undefined) {
    throw badRequest('bad_predicate', 'window_seconds means nothing without max_per_window');
  }

  if (raw['note'] !== undefined) {
    if (typeof raw['note'] !== 'string' || raw['note'].length > 500) {
      throw badRequest('bad_predicate', 'note must be a string of at most 500 characters');
    }
    out.note = raw['note'];
  }

  if (out.deny === undefined && out.max_per_window === undefined) {
    throw badRequest(
      'bad_predicate',
      'a constraint must either deny or cap: set deny, or max_per_window with window_seconds',
    );
  }

  return out;
}

function stringArray(value: unknown, key: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length === 0) {
    throw badRequest('bad_predicate', `${key} must be a non-empty array of strings`);
  }
  return value.map((v) => {
    if (typeof v !== 'string' || !v.trim()) {
      throw badRequest('bad_predicate', `${key} must contain only non-empty strings`);
    }
    return v.trim();
  });
}

/** Does this predicate speak to this action at all? */
function selects(p: ConstraintPredicate, power: WardenPower, act: WardenAction): boolean {
  if (p.powers && !p.powers.includes(power)) return false;
  if (p.target_types && !p.target_types.includes(act.targetType)) return false;
  if (p.reason_codes && !p.reason_codes.includes(act.reasonCode)) return false;
  return true;
}

// ------------------------------------------------------------- the question

/**
 * Refuse anything the office does not hold, and anything the citizens have
 * taken back from it.
 *
 * Returns the guards for every cap that selects this action. They must be
 * passed into the same `appendEvent({ guards })` that writes the moderation
 * log: a cap counted here and appended afterwards is the check-then-act the
 * whole system is built to avoid, and fifty concurrent requests would all read
 * the same count and all land.
 *
 * Throws KeyholdError — 403 for a power the Warden does not have or an effect
 * the constitution denies it, 400 for a reason code that is not grounds for the
 * action it is attached to.
 */
export async function assertWardenMay(
  db: D1Database,
  power: WardenPower,
  act: WardenAction,
): Promise<ConstraintGuard[]> {
  // 1. The enumeration. A power not on the list does not exist, and an effect
  //    on the denied list is refused here rather than by any policy row.
  if (!(WARDEN_POWERS as readonly string[]).includes(power)) {
    throw forbidden(
      'power_not_enumerated',
      `${power} is not a Warden power; the office holds only: ${WARDEN_POWERS.join(', ')} (Art. V)`,
    );
  }
  for (const effect of act.effects) {
    if ((WARDEN_DENIED as readonly string[]).includes(effect)) {
      throw forbidden(
        'power_denied',
        `${act.action} would ${effect}, and ${effect} is denied to the Warden by the constitution itself, not by policy (Art. V)`,
      );
    }
  }

  // 2. Grounds. Art. IV limits what may be acted against, and the reason code
  //    is the machine-readable half of that limit.
  if (!(REASON_CODES as readonly string[]).includes(act.reasonCode)) {
    throw badRequest(
      'bad_reason_code',
      `reason_code must be one of: ${REASON_CODES.join(', ')}`,
    );
  }
  if (CODE_ONLY_REASONS.has(act.reasonCode)) {
    throw forbidden(
      'reason_reserved',
      `${act.reasonCode} is written by code when a jury rules; a Warden may not cite it`,
    );
  }
  if (act.reasonCode === 'operator_legal' && !LEGAL_POWERS.has(power)) {
    throw badRequest(
      'bad_reason_code',
      `operator_legal is not grounds for ${act.action}; legal compulsion can hide content or attribute an inflow, nothing else`,
    );
  }
  if (
    act.reasonCode !== 'operator_legal' &&
    !ENFORCEMENT_GROUNDS.has(act.reasonCode) &&
    power !== 'confirm_inflow'
  ) {
    throw badRequest(
      'bad_reason_code',
      `only ${[...ENFORCEMENT_GROUNDS].join(', ')} are grounds for enforcement (Art. IV)`,
    );
  }
  if (!act.reason.trim()) {
    throw badRequest('missing_reason', 'every Warden action carries a written reason; the log keeps it forever');
  }

  // 3. The constraints the citizens have voted on. Read every active row: a
  //    later motion narrows the office further, it never widens it.
  const rows = await many<ConstraintRow>(
    db,
    'SELECT id, proposal_id, predicate FROM warden_constraints WHERE active = 1',
  );

  const guards: ConstraintGuard[] = [];

  for (const row of rows) {
    let predicate: ConstraintPredicate;
    try {
      predicate = parseConstraintPredicate(JSON.parse(row.predicate));
    } catch {
      // A stored predicate that no longer parses is a constraint we cannot
      // honour. Fail closed: the citizens narrowed the office, and an
      // unreadable narrowing is not permission.
      throw forbidden(
        'constraint_unreadable',
        `warden constraint ${row.id} cannot be read, so nothing may be done under it; repeal or replace it by proposal`,
      );
    }

    if (!selects(predicate, power, act)) continue;

    if (predicate.deny) {
      throw forbidden(
        'warden_constrained',
        constraintMessage(row, predicate, `${act.action} is withdrawn from the Warden`),
      );
    }

    if (predicate.max_per_window !== undefined && predicate.window_seconds !== undefined) {
      guards.push({
        stmt: capGuard(
          db,
          row,
          predicate,
          power,
          act,
          predicate.max_per_window,
          predicate.window_seconds,
        ),
        label: `warden_constrained:${row.id}`,
      });
    }
  }

  return guards;
}

function constraintMessage(
  row: ConstraintRow,
  predicate: ConstraintPredicate,
  what: string,
): string {
  const source = row.proposal_id ? `by proposal ${row.proposal_id}` : 'by binding constraint';
  return `${what} ${source} (${row.id})${predicate.note ? `: ${predicate.note}` : ''}`;
}

/**
 * The cap, as a statement that only "changes" a row while the Warden is under
 * it. It updates nothing — `active = active` — so its only effect is the row
 * count the guard sentinel reads, and it re-reads `active = 1` inside the batch
 * so a constraint repealed mid-request stops binding at the same instant.
 *
 * The window is counted from moderation_log rather than from the event chain
 * because the log is the indexed projection of exactly these events, and every
 * row in it was written inside an appendEvent batch, so the two cannot
 * disagree. This action's own log row is a `writes` statement and lands after
 * the guards, so it is not counted against itself.
 */
function capGuard(
  db: D1Database,
  row: ConstraintRow,
  predicate: ConstraintPredicate,
  power: WardenPower,
  act: WardenAction,
  maxPerWindow: number,
  windowSeconds: number,
): D1PreparedStatement {
  const where: string[] = ['actor = ?', 'created_at >= ?'];
  const binds: unknown[] = [act.actor, act.now - windowSeconds];

  const actions = predicate.powers
    ? predicate.powers.map((p) => ACTION_FOR_POWER[p as WardenPower] ?? p)
    : [ACTION_FOR_POWER[power]];
  where.push(`action IN (${actions.map(() => '?').join(',')})`);
  binds.push(...actions);

  if (predicate.target_types) {
    where.push(`target_type IN (${predicate.target_types.map(() => '?').join(',')})`);
    binds.push(...predicate.target_types);
  }
  if (predicate.reason_codes) {
    where.push(`reason_code IN (${predicate.reason_codes.map(() => '?').join(',')})`);
    binds.push(...predicate.reason_codes);
  }

  return db
    .prepare(
      `UPDATE warden_constraints SET active = active
        WHERE id = ? AND active = 1
          AND (SELECT COUNT(*) FROM moderation_log WHERE ${where.join(' AND ')}) < ?`,
    )
    .bind(row.id, ...binds, maxPerWindow);
}

/**
 * The share of this Warden's actions that a jury has overturned, as a
 * percentage. `mod.overturn_alarm_pct` is the threshold at which the citizens
 * are expected to move a replacement; this reports the number, it does not act
 * on it — the office is not removed by code.
 */
export async function overturnRate(
  db: D1Database,
  wardenId: string,
): Promise<{ actions: number; overturned: number; pct: number }> {
  const rows = await many<{ actions: number; overturned: number }>(
    db,
    `SELECT COUNT(*) AS actions,
            COALESCE(SUM(CASE WHEN a.status = 'upheld' THEN 1 ELSE 0 END), 0) AS overturned
       FROM moderation_log m
       LEFT JOIN appeals a ON a.moderation_id = m.id
      WHERE m.actor = ?`,
    wardenId,
  );
  const actions = rows[0]?.actions ?? 0;
  const overturned = rows[0]?.overturned ?? 0;
  return {
    actions,
    overturned,
    pct: actions === 0 ? 0 : Math.floor((overturned * 100) / actions),
  };
}
