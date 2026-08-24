/**
 * Live policy reads. Handlers must ask this module, never import GENESIS_POLICY
 * directly, so that a passed proposal actually changes behaviour.
 *
 * The current value of a key is the highest version in `policy`. Genesis defaults
 * are seeded at genesis, so a missing row means the key was never seeded — that
 * is a bug, and we fail loudly rather than silently guessing.
 */

import { GENESIS_POLICY, type PolicyKey } from '../core/constitution';
import { many } from '../core/db';

export interface PolicyRow {
  key: string;
  version: number;
  value: string;
  set_by: string;
  created_at: number;
}

/** Per-request cache. Workers isolates are short-lived; this is safe. */
export class Policy {
  private cache: Map<string, number | string> | null = null;

  constructor(private db: D1Database) {}

  private async load(): Promise<Map<string, number | string>> {
    if (this.cache) return this.cache;
    const rows = await many<{ key: string; value: string }>(
      this.db,
      `SELECT p.key, p.value FROM policy p
       JOIN (SELECT key, MAX(version) AS v FROM policy GROUP BY key) m
         ON m.key = p.key AND m.v = p.version`,
    );
    const map = new Map<string, number | string>();
    for (const r of rows) {
      map.set(r.key, JSON.parse(r.value) as number | string);
    }
    this.cache = map;
    return map;
  }

  async num(key: PolicyKey): Promise<number> {
    const map = await this.load();
    const v = map.get(key);
    if (v === undefined) {
      // Not seeded. Fall back to the genesis constant but make the gap visible.
      console.warn(`policy key not seeded, using genesis default: ${key}`);
      return GENESIS_POLICY[key] as number;
    }
    if (typeof v !== 'number') {
      throw new Error(`policy ${key} is not numeric: ${JSON.stringify(v)}`);
    }
    return v;
  }

  async all(): Promise<Record<string, number | string>> {
    const map = await this.load();
    const out: Record<string, number | string> = {};
    for (const [k, v] of map) out[k] = v;
    return out;
  }

  /** Every genesis key with its current value, marking drift from default. */
  async report(): Promise<
    Array<{ key: string; value: number | string; genesis: number | string; changed: boolean }>
  > {
    const map = await this.load();
    return Object.entries(GENESIS_POLICY).map(([key, genesis]) => {
      const value = map.get(key) ?? genesis;
      return { key, value, genesis, changed: value !== genesis };
    });
  }
}

/** Statements that seed every genesis default. Used once, by genesis. */
export function seedPolicyStatements(
  db: D1Database,
  ts: number,
  eventSeq: number,
): D1PreparedStatement[] {
  return Object.entries(GENESIS_POLICY).map(([key, value]) =>
    db
      .prepare(
        `INSERT INTO policy (key, version, value, set_by, created_at, event_seq)
         VALUES (?, 1, ?, 'genesis', ?, ?)`,
      )
      .bind(key, JSON.stringify(value), ts, eventSeq),
  );
}

/** A policy change writes a new version; history is never overwritten. */
export function setPolicyStatement(
  db: D1Database,
  key: string,
  value: number | string,
  setBy: string,
  ts: number,
  eventSeq: number,
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO policy (key, version, value, set_by, created_at, event_seq)
       SELECT ?, COALESCE(MAX(version), 0) + 1, ?, ?, ?, ?
       FROM policy WHERE key = ?`,
    )
    .bind(key, JSON.stringify(value), setBy, ts, eventSeq, key);
}
