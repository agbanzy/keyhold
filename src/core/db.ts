/**
 * D1 helpers and the Worker environment shape.
 */

export interface Env {
  DB: D1Database;
  INSTANCE_NAME: string;
  TREASURY_ADDRESS: string;
  USDC_CONTRACT: string;
  BASE_RPC_URLS: string;
  WITNESS_REPO: string;
  /** Secrets. Absent in local dev unless set with `wrangler secret put`. */
  WARDEN_PUBKEYS?: string;
  OPERATOR_PUBKEY?: string;
  GITHUB_TOKEN?: string;
}

export function treasuryConfigured(env: Env): boolean {
  const a = env.TREASURY_ADDRESS?.trim().toLowerCase() ?? '';
  return /^0x[0-9a-f]{40}$/.test(a);
}

export function treasuryAddress(env: Env): string | null {
  return treasuryConfigured(env) ? env.TREASURY_ADDRESS.trim().toLowerCase() : null;
}

export async function one<T>(
  db: D1Database,
  sql: string,
  ...binds: unknown[]
): Promise<T | null> {
  return db
    .prepare(sql)
    .bind(...(binds as never[]))
    .first<T>();
}

export async function many<T>(
  db: D1Database,
  sql: string,
  ...binds: unknown[]
): Promise<T[]> {
  const r = await db
    .prepare(sql)
    .bind(...(binds as never[]))
    .all<T>();
  return r.results ?? [];
}

/** Micro-USDC formatting for humans and JSON alike. */
export function formatUsdc(micro: number): string {
  const sign = micro < 0 ? '-' : '';
  const abs = Math.abs(micro);
  const whole = Math.floor(abs / 1_000_000);
  const frac = String(abs % 1_000_000).padStart(6, '0').replace(/0+$/, '');
  return `${sign}${whole}${frac ? '.' + frac : ''}`;
}

export function parseUsdcToMicro(value: string): number {
  const m = /^(-?)(\d+)(?:\.(\d{1,6}))?$/.exec(value.trim());
  if (!m) throw new Error(`not a USDC amount: ${value}`);
  const sign = m[1] === '-' ? -1 : 1;
  const whole = Number.parseInt(m[2] ?? '0', 10);
  const frac = Number.parseInt((m[3] ?? '').padEnd(6, '0') || '0', 10);
  return sign * (whole * 1_000_000 + frac);
}
