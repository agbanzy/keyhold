/**
 * The daily notarisation.
 *
 * Once a day the society writes down where its chain has got to — last seq,
 * last hash, how many events exist — and pushes that statement into a public
 * repo it does not control the history of. From then on, rewriting any event at
 * or below that seq changes the recomputed hash and stops matching the published
 * one. scripts/verify.mjs compares the two and reports the divergence.
 *
 * Two properties matter and are easy to get wrong:
 *
 *  - The recorded head is the head *before* the checkpoint event is appended.
 *    A checkpoint that included itself would be unverifiable, since its hash
 *    cannot be known before it is written.
 *  - The event count is taken as `COUNT(*) WHERE seq <= head.seq`, not a bare
 *    COUNT(*), so a concurrent append between the two reads cannot skew it.
 *    Seq gaps are legal (AUTOINCREMENT never reuses), so count and seq differ.
 *
 * The witness push is best-effort by design: GitHub being down must not stop
 * the society recording its own checkpoint. When the push fails the row lands
 * with a null witness_url and the next run repairs it — with its own event, so
 * the repair is on the record too.
 */

import { one } from '../core/db';
import { KeyholdError } from '../core/errors';
import {
  GuardFailedError,
  appendEventWithRetry,
  nowSeconds,
  readHead,
  utcDay,
} from '../core/events';
import type { Env } from '../core/db';
import { pushFile, readJson, witnessBaseUrl, witnessTarget, type PushResult } from './github';

/** Exactly what gets published to the witness repo. */
export interface CheckpointRecord {
  date: string;
  last_seq: number;
  last_hash: string;
  event_count: number;
  genesis_hash: string;
  instance: string;
}

export interface CheckpointResult {
  record: CheckpointRecord;
  /** Seq of the checkpoint.published event, or null when nothing was appended. */
  event_seq: number | null;
  witness: PushResult;
  /** True when this day already had a complete, witnessed checkpoint. */
  already_published: boolean;
  /** True when this run only re-pushed a previously unwitnessed day. */
  repaired: boolean;
}

export interface ExportResult {
  pushed: boolean;
  reason?: string;
  path?: string;
  url?: string;
  events: number;
  raw_bytes: number;
  gzip_bytes: number;
}

/** Uncompressed JSONL ceiling. The Contents API is not a bulk transport. */
const MAX_EXPORT_RAW_BYTES = 48 * 1024 * 1024;
const EXPORT_PAGE = 1000;
/** Ten years of daily entries. Beyond that the index is not the right tool. */
const INDEX_CAP = 4000;

// ------------------------------------------------------------------ snapshot

export interface ChainSnapshot {
  last_seq: number;
  last_hash: string;
  event_count: number;
  genesis_hash: string;
}

/**
 * The chain as it stands right now. Read the head first, then count against it,
 * so the two numbers describe the same instant even if an append lands between.
 */
export async function chainSnapshot(db: D1Database): Promise<ChainSnapshot> {
  const head = await readHead(db);
  if (head.seq === 0) {
    throw new KeyholdError(
      409,
      'chain_empty',
      'nothing to checkpoint: the chain has no events, not even genesis',
    );
  }

  const counted = await one<{ n: number }>(
    db,
    'SELECT COUNT(*) AS n FROM events WHERE seq <= ?',
    head.seq,
  );
  const genesis = await one<{ hash: string }>(
    db,
    'SELECT hash FROM events ORDER BY seq LIMIT 1',
  );
  if (!genesis) {
    throw new KeyholdError(500, 'chain_headless', 'chain_head points at an empty events table');
  }

  return {
    last_seq: head.seq,
    last_hash: head.hash,
    event_count: counted?.n ?? 0,
    genesis_hash: genesis.hash,
  };
}

// ------------------------------------------------------------- daily job

/**
 * Publish today's checkpoint: record it in the chain, then witness it publicly.
 *
 * Idempotent per UTC day. Called again on a day that already has a witnessed
 * checkpoint it does nothing; called again on a day whose push failed it
 * re-pushes and records the repair.
 */
export async function publishCheckpoint(
  env: Env,
  opts: { day?: string; now?: number } = {},
): Promise<CheckpointResult> {
  const db = env.DB;
  const now = opts.now ?? nowSeconds();
  const day = opts.day ?? utcDay(now);

  const existing = await one<{
    day: string;
    last_seq: number;
    last_hash: string;
    event_count: number;
    witness_url: string | null;
  }>(db, 'SELECT day, last_seq, last_hash, event_count, witness_url FROM checkpoints WHERE day = ?', day);

  if (existing?.witness_url) {
    const record = await recordFor(db, env, existing);
    return { record, event_seq: null, witness: { pushed: true, unchanged: true, url: existing.witness_url }, already_published: true, repaired: false };
  }

  if (existing) {
    // The day is on the chain but never reached the public repo. Re-push the
    // record exactly as it was recorded — not a fresh snapshot, or the witness
    // would disagree with the checkpoint event that is already in the log.
    const record = await recordFor(db, env, existing);
    const witness = await witnessCheckpoint(env, record);
    if (!witness.pushed || !witness.url) {
      return { record, event_seq: null, witness, already_published: false, repaired: false };
    }
    // The repair is the guard. Two runs that both see a null witness_url would
    // otherwise both append a repair event for the same day; as a guard the
    // loser's UPDATE changes nothing, the batch is refused, and there is one
    // repair on the record instead of two.
    let appended;
    try {
      appended = await appendEventWithRetry(db, {
        type: 'checkpoint.published',
        actor: null,
        ts: now,
        payload: { ...toPayload(record), witness_url: witness.url, repair: true },
        guards: [
          db
            .prepare('UPDATE checkpoints SET witness_url = ? WHERE day = ? AND witness_url IS NULL')
            .bind(witness.url, day),
        ],
      });
    } catch (err) {
      if (err instanceof GuardFailedError) {
        return {
          record,
          event_seq: null,
          witness: { ...witness, unchanged: true },
          already_published: true,
          repaired: false,
        };
      }
      throw err;
    }
    return { record, event_seq: appended.seq, witness, already_published: false, repaired: true };
  }

  const snapshot = await chainSnapshot(db);
  const record: CheckpointRecord = {
    date: day,
    last_seq: snapshot.last_seq,
    last_hash: snapshot.last_hash,
    event_count: snapshot.event_count,
    genesis_hash: snapshot.genesis_hash,
    instance: env.INSTANCE_NAME,
  };

  // Push before appending so the public URL can live inside the event itself,
  // rather than being patched in by a write with no event behind it.
  const witness = await witnessCheckpoint(env, record);

  // The row is the guard, not a write. Reading "no checkpoint for today" and
  // then inserting unconditionally is check-then-act: two overlapping cron ticks
  // both read no row, and the loser's INSERT would hit the primary key and
  // surface as a raw database error four retries later. `DO NOTHING` makes the
  // second one a refusal instead — one checkpoint per day, said once.
  let appended;
  try {
    appended = await appendEventWithRetry(db, {
      type: 'checkpoint.published',
      actor: null,
      ts: now,
      payload: { ...toPayload(record), witness_url: witness.url ?? null },
      guards: [
        db
          .prepare(
            `INSERT INTO checkpoints (day, last_seq, last_hash, event_count, witness_url, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (day) DO NOTHING`,
          )
          .bind(day, record.last_seq, record.last_hash, record.event_count, witness.url ?? null, now),
      ],
    });
  } catch (err) {
    if (err instanceof GuardFailedError) {
      return {
        record,
        event_seq: null,
        witness: { ...witness, unchanged: true },
        already_published: true,
        repaired: false,
      };
    }
    throw err;
  }

  return { record, event_seq: appended.seq, witness, already_published: false, repaired: false };
}

/**
 * Push one checkpoint and refresh the index the verifier enumerates from.
 *
 * A GitHub failure is reported, never thrown: the checkpoint must reach the
 * chain whether or not the witness is reachable. `pushed: false` plus a reason
 * is the honest answer, and the next run repairs it.
 */
async function witnessCheckpoint(env: Env, record: CheckpointRecord): Promise<PushResult> {
  if (!witnessTarget(env)) {
    return { pushed: false, reason: 'WITNESS_REPO is not set; this instance publishes no public witness' };
  }
  if (!env.GITHUB_TOKEN?.trim()) {
    return { pushed: false, reason: 'GITHUB_TOKEN is not set; the witness repo cannot be written' };
  }

  const path = `checkpoints/${record.date}.json`;
  let result: PushResult;
  try {
    result = await pushFile(
      env,
      path,
      JSON.stringify(record, null, 2) + '\n',
      `checkpoint ${record.date}: seq ${record.last_seq} @ ${record.last_hash.slice(0, 12)}`,
    );
  } catch (err) {
    return { pushed: false, reason: `witness push failed: ${errText(err)}` };
  }

  if (result.pushed) {
    try {
      await updateIndex(env, record);
    } catch (err) {
      // The day file is what proves the chain; the index is only a directory
      // listing for verifiers. Say it failed, keep the successful push.
      result = { ...result, reason: `day file pushed, index.json not updated: ${errText(err)}` };
    }
  }
  return result;
}

/**
 * checkpoints/index.json exists because raw.githubusercontent cannot list a
 * directory, and a verifier should not need a GitHub token to enumerate what
 * has been published. Run the verifier with --full and it re-fetches every day
 * file, so a doctored index cannot hide a doctored day.
 */
async function updateIndex(env: Env, record: CheckpointRecord): Promise<void> {
  const path = 'checkpoints/index.json';
  const existing = await readJson<{ checkpoints?: CheckpointRecord[] }>(env, path);
  const rows = (existing?.checkpoints ?? []).filter((r) => r.date !== record.date);
  rows.push(record);
  rows.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

  const body = {
    instance: record.instance,
    genesis_hash: record.genesis_hash,
    updated_at: record.date,
    checkpoints: rows.slice(-INDEX_CAP),
  };
  await pushFile(env, path, JSON.stringify(body, null, 2) + '\n', `index: ${record.date}`);
}

// -------------------------------------------------------------- weekly export

/**
 * A gzipped JSONL of the whole chain, so a verifier can check us without
 * hammering the Worker with thousands of paged requests. Derived data: it is
 * fully recomputable from the chain, so it carries no event of its own.
 *
 * Streamed and compressed on the fly; the only thing held whole in memory is
 * the compressed result, which the Contents API requires as one body anyway.
 */
export async function pushWeeklyExport(
  env: Env,
  opts: { day?: string; now?: number } = {},
): Promise<ExportResult> {
  const db = env.DB;
  const now = opts.now ?? nowSeconds();
  const day = opts.day ?? utcDay(now);
  const path = `exports/events-${day}.jsonl.gz`;

  if (!witnessTarget(env) || !env.GITHUB_TOKEN?.trim()) {
    return {
      pushed: false,
      reason: 'witness repo or GITHUB_TOKEN absent; no export published',
      events: 0,
      raw_bytes: 0,
      gzip_bytes: 0,
    };
  }

  const encoder = new TextEncoder();
  let events = 0;
  let rawBytes = 0;
  let cursor = 0;

  const source = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const page = await db
        .prepare(
          `SELECT seq, ts, type, actor, payload, sig, prev_hash, hash
             FROM events WHERE seq > ? ORDER BY seq LIMIT ?`,
        )
        .bind(cursor, EXPORT_PAGE)
        .all<EventRow>();

      const rows = page.results ?? [];
      if (rows.length === 0) {
        controller.close();
        return;
      }

      let chunk = '';
      for (const row of rows) {
        // payload stays the stored canonical JSON string, verbatim: an exporter
        // that re-serialises it would change the bytes the hash covers.
        chunk += JSON.stringify(row) + '\n';
        cursor = row.seq;
      }
      events += rows.length;

      const bytes = encoder.encode(chunk);
      rawBytes += bytes.byteLength;
      if (rawBytes > MAX_EXPORT_RAW_BYTES) {
        throw new KeyholdError(
          413,
          'export_too_large',
          `chain export exceeds ${MAX_EXPORT_RAW_BYTES} bytes at seq ${cursor}; publish it out of band rather than through the Contents API`,
        );
      }
      controller.enqueue(bytes);
    },
  });

  const gzipped = new Uint8Array(
    await new Response(source.pipeThrough(new CompressionStream('gzip'))).arrayBuffer(),
  );

  const result = await pushFile(
    env,
    path,
    gzipped,
    `export ${day}: ${events} events through seq ${cursor}`,
  );

  if (result.pushed) {
    await pushExportIndex(env, { day, path, events, last_seq: cursor, bytes: gzipped.byteLength });
  }

  return {
    pushed: result.pushed,
    reason: result.reason,
    path,
    url: result.url,
    events,
    raw_bytes: rawBytes,
    gzip_bytes: gzipped.byteLength,
  };
}

interface ExportIndexEntry {
  day: string;
  path: string;
  events: number;
  last_seq: number;
  bytes: number;
}

async function pushExportIndex(env: Env, entry: ExportIndexEntry): Promise<void> {
  const path = 'exports/index.json';
  const existing = await readJson<{ exports?: ExportIndexEntry[] }>(env, path);
  const rows = (existing?.exports ?? []).filter((r) => r.day !== entry.day);
  rows.push(entry);
  rows.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
  await pushFile(
    env,
    path,
    JSON.stringify({ exports: rows.slice(-INDEX_CAP) }, null, 2) + '\n',
    `export index: ${entry.day}`,
  );
}

// ------------------------------------------------------------------ cron entry

export interface WitnessJobResult {
  checkpoint: CheckpointResult;
  export?: ExportResult;
  /** Everything that did not work, for the cron log. Empty means clean. */
  problems: string[];
  /** What a verifier should be pointed at, when there is one. */
  witness_base: string | null;
}

/**
 * The 00:07 UTC job. Checkpoint every day; push the full export once a week.
 *
 * Returns its problems rather than throwing them, so one failing half does not
 * silently cancel the other. The caller logs the result; anything with a
 * non-empty `problems` deserves an alarm.
 */
export async function dailyWitnessJob(
  env: Env,
  opts: { now?: number; weeklyOn?: number; force_export?: boolean } = {},
): Promise<WitnessJobResult> {
  const now = opts.now ?? nowSeconds();
  const problems: string[] = [];

  const checkpoint = await publishCheckpoint(env, { now });
  if (!checkpoint.witness.pushed) {
    problems.push(checkpoint.witness.reason ?? 'witness push did not report success');
  } else if (checkpoint.witness.reason) {
    problems.push(checkpoint.witness.reason);
  }

  // Sunday by default, so the export and the checkpoint describe the same head.
  const weekday = new Date(now * 1000).getUTCDay();
  const wanted = opts.weeklyOn ?? 0;
  let exported: ExportResult | undefined;
  if (opts.force_export || weekday === wanted) {
    try {
      exported = await pushWeeklyExport(env, { now });
      if (!exported.pushed) problems.push(exported.reason ?? 'export push did not report success');
    } catch (err) {
      problems.push(`weekly export failed: ${errText(err)}`);
    }
  }

  return { checkpoint, export: exported, problems, witness_base: witnessBaseUrl(env) };
}

// ------------------------------------------------------------------ internals

interface EventRow {
  seq: number;
  ts: number;
  type: string;
  actor: string | null;
  payload: string;
  sig: string | null;
  prev_hash: string;
  hash: string;
}

/** Rebuild the published record from a stored row, so a repair republishes the
 *  same statement rather than a newer one. */
async function recordFor(
  db: D1Database,
  env: Env,
  row: { day: string; last_seq: number; last_hash: string; event_count: number },
): Promise<CheckpointRecord> {
  const genesis = await one<{ hash: string }>(db, 'SELECT hash FROM events ORDER BY seq LIMIT 1');
  return {
    date: row.day,
    last_seq: row.last_seq,
    last_hash: row.last_hash,
    event_count: row.event_count,
    genesis_hash: genesis?.hash ?? '',
    instance: env.INSTANCE_NAME,
  };
}

/** The event payload. Integers only — canonicalize() throws on anything else. */
function toPayload(record: CheckpointRecord): Record<string, unknown> {
  return {
    day: record.date,
    last_seq: record.last_seq,
    last_hash: record.last_hash,
    event_count: record.event_count,
    genesis_hash: record.genesis_hash,
    instance: record.instance,
  };
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
