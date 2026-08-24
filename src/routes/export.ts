/**
 * The audit surface.
 *
 * These four endpoints are how anyone — a citizen, a forker, a journalist, a
 * regulator — checks that we are telling the truth. They never require auth,
 * never will, and are the reason the rest of the system cannot lie quietly.
 *
 * /export/events streams the raw chain as JSONL with the payload text preserved
 * byte-for-byte, so scripts/verify.mjs can recompute every hash without trusting
 * this Worker's serializer.
 */

import { Hono } from 'hono';
import type { AppEnv } from './api';
import type { Env } from '../core/db';
import { many, one, treasuryAddress } from '../core/db';
import { readHead } from '../core/events';
import { badRequest } from '../core/errors';

export const exportRoutes = new Hono<AppEnv>();

const EVENTS_DEFAULT_LIMIT = 1000;
const EVENTS_MAX_LIMIT = 5000;
const LEDGER_DEFAULT_LIMIT = 1000;
const LEDGER_MAX_LIMIT = 5000;

/**
 * Snapshot bounds. This endpoint is unauthenticated, so one request must never
 * be able to make the Worker allocate more than the isolate can hold: 21 tables
 * × 5,000 rows × a 20 KB post body is well past 128 MB. Rows per table are
 * capped, free text is cut to a preview (the hash beside it still identifies
 * the full body, which is at /export/events and the per-item routes), and the
 * whole response stops once the byte budget is spent.
 */
const SNAPSHOT_ROWS_DEFAULT = 500;
const SNAPSHOT_ROWS_MAX = 2000;
const SNAPSHOT_BYTE_BUDGET = 4_000_000;
const SNAPSHOT_TEXT_CHARS = 240;

interface EventRow {
  seq: number;
  ts: number;
  type: string;
  actor: string | null;
  payload: string;
  sig: string | null;
  sig_material: string | null;
  prev_hash: string;
  hash: string;
}

/**
 * JSONL, one event per line, oldest first.
 *
 * The payload is spliced in as raw text rather than re-serialized: it is already
 * canonical JSON, and a round-trip through JSON.parse/stringify would be a
 * second serializer that could drift from canonical.ts. One serializer, one
 * truth.
 */
exportRoutes.get('/events', async (c) => {
  const since = intParam(c.req.query('since'), 'since', 0);
  const limit = Math.min(
    Math.max(intParam(c.req.query('limit'), 'limit', EVENTS_DEFAULT_LIMIT), 1),
    EVENTS_MAX_LIMIT,
  );

  const rows = await many<EventRow>(
    c.env.DB,
    `SELECT seq, ts, type, actor, payload, sig, sig_material, prev_hash, hash
     FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
    since,
    limit,
  );

  const head = await readHead(c.env.DB);
  const lastSeq = rows.length ? (rows[rows.length - 1] as EventRow).seq : since;

  const body = rows.map(eventLine).join('\n') + (rows.length ? '\n' : '');

  // A page that ends below the head can never change: events are append-only
  // and nothing rewrites history. Anything touching the head is volatile.
  const complete = rows.length === limit && lastSeq < head.seq;

  return new Response(body, {
    headers: {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'cache-control': complete
        ? 'public, max-age=31536000, immutable'
        : 'public, max-age=10',
      'x-keyhold-chain-head-seq': String(head.seq),
      'x-keyhold-chain-head-hash': head.hash,
      'x-keyhold-last-seq': String(lastSeq),
      'x-keyhold-count': String(rows.length),
    },
  });
});

function eventLine(e: EventRow): string {
  return (
    '{"seq":' +
    e.seq +
    ',"ts":' +
    e.ts +
    ',"type":' +
    JSON.stringify(e.type) +
    ',"actor":' +
    (e.actor === null ? 'null' : JSON.stringify(e.actor)) +
    ',"payload":' +
    e.payload +
    ',"sig":' +
    (e.sig === null ? 'null' : JSON.stringify(e.sig)) +
    // What that signature covers. Without it the chain is checkable but its
    // authorship is not: the signed string cannot be rebuilt from the row.
    ',"sig_material":' +
    (e.sig_material == null ? 'null' : JSON.stringify(e.sig_material)) +
    ',"prev_hash":' +
    JSON.stringify(e.prev_hash) +
    ',"hash":' +
    JSON.stringify(e.hash) +
    '}'
  );
}

/** Daily anchors. If a checkpoint has a witness_url, an outside party holds it. */
exportRoutes.get('/checkpoints', async (c) => {
  const rows = await many(
    c.env.DB,
    `SELECT day, last_seq, last_hash, event_count, witness_url, created_at
     FROM checkpoints ORDER BY day DESC LIMIT 400`,
  );
  return c.json(
    { checkpoints: rows },
    200,
    { 'cache-control': 'public, max-age=60' },
  );
});

exportRoutes.get('/chain/head', async (c) => {
  const head = await readHead(c.env.DB);
  const stats = await one<{ count: number; last_ts: number | null }>(
    c.env.DB,
    'SELECT COUNT(*) AS count, MAX(ts) AS last_ts FROM events',
  );
  const genesis = await one<{ hash: string; ts: number }>(
    c.env.DB,
    'SELECT hash, ts FROM events WHERE seq = 1',
  );
  return c.json(
    {
      instance: c.env.INSTANCE_NAME,
      genesis_hash: genesis?.hash ?? null,
      genesis_ts: genesis?.ts ?? null,
      seq: head.seq,
      hash: head.hash,
      event_count: stats?.count ?? 0,
      last_event_ts: stats?.last_ts ?? null,
    },
    200,
    { 'cache-control': 'public, max-age=5' },
  );
});

/**
 * What a verifier needs before it can check anything: which chain this is, and
 * which wallet and token its money claims are about. scripts/verify.mjs reads
 * this so an auditor does not have to be told the treasury address out of band
 * — and then checks our claims against Base, which we do not control.
 */
exportRoutes.get('/manifest', async (c) => {
  const db = c.env.DB;
  const head = await readHead(db);
  const genesis = await one<{ hash: string; ts: number }>(
    db,
    'SELECT hash, ts FROM events WHERE seq = 1',
  );
  const origin = new URL(c.req.url).origin;

  return c.json(
    {
      instance: c.env.INSTANCE_NAME,
      genesis_hash: genesis?.hash ?? null,
      genesis_ts: genesis?.ts ?? null,
      chain_head: { seq: head.seq, hash: head.hash },
      chain: 'base',
      treasury_address: treasuryAddress(c.env),
      usdc_contract: c.env.USDC_CONTRACT,
      witness_repo: c.env.WITNESS_REPO || null,
      license: 'AGPL-3.0-or-later',
      endpoints: {
        events: `${origin}/export/events`,
        ledger: `${origin}/export/ledger`,
        checkpoints: `${origin}/export/checkpoints`,
        chain_head: `${origin}/export/chain/head`,
        snapshot: `${origin}/export/snapshot`,
      },
    },
    200,
    { 'cache-control': 'public, max-age=30' },
  );
});

/**
 * The books, in pages, for an offline verifier.
 *
 * Every row here was written inside the batch of the event named by its
 * `event_seq`, so a row with no matching event — or an event that booked money
 * with no row — is a discrepancy the verifier reports. Without this endpoint
 * the ledger would be visible only through this Worker's own aggregates, which
 * is exactly the kind of "trust us" the rest of the design refuses.
 */
exportRoutes.get('/ledger', async (c) => {
  const from = Math.max(intParam(c.req.query('from'), 'from', 0), 0);
  const limit = Math.min(
    Math.max(intParam(c.req.query('limit'), 'limit', LEDGER_DEFAULT_LIMIT), 1),
    LEDGER_MAX_LIMIT,
  );

  const entries = await many(
    c.env.DB,
    `SELECT id, ts, debit, credit, amount, memo, ref_type, ref_id, event_seq
     FROM ledger_entries
     ORDER BY event_seq ASC, id ASC
     LIMIT ? OFFSET ?`,
    limit,
    from,
  );

  const total = await one<{ n: number }>(
    c.env.DB,
    'SELECT COUNT(*) AS n FROM ledger_entries',
  );

  return c.json(
    {
      entries,
      count: entries.length,
      from,
      next_from: from + entries.length,
      total: total?.n ?? 0,
      note: 'Ordered by the event that caused each entry. Every row is one debit and one credit of the same amount; the totals must be equal.',
    },
    200,
    { 'cache-control': 'public, max-age=15' },
  );
});

/** Long free text becomes a preview; the hash beside it identifies the whole. */
function preview(column: string): string {
  return `substr(${column}, 1, ${SNAPSHOT_TEXT_CHARS})`;
}

/**
 * The public tables, each with a deterministic total order so that paging by
 * offset returns every row exactly once.
 *
 * `pending_payments` lists settled intents only. Live fingerprints stay private:
 * publishing an exact expected amount would let a stranger pay it and hijack the
 * attribution.
 */
const SNAPSHOT_TABLES: Record<string, string> = {
  citizens: `SELECT id, pubkey, display_name, status, standing, marks, vouched_by,
                    frozen_until, created_at, event_seq, succeeded_by
             FROM citizens ORDER BY created_at ASC, id ASC`,
  citizen_addresses: `SELECT citizen_id, address, created_at, event_seq
             FROM citizen_addresses ORDER BY created_at ASC, citizen_id ASC, address ASC`,
  posts: `SELECT id, citizen_id, title,
                 CASE WHEN hidden = 1 THEN NULL ELSE ${preview('body')} END AS body_preview,
                 body_hash, kind, hidden, score, comment_count, created_at, event_seq
          FROM posts ORDER BY created_at ASC, id ASC`,
  comments: `SELECT id, post_id, parent_id, citizen_id,
                    CASE WHEN hidden = 1 THEN NULL ELSE ${preview('body')} END AS body_preview,
                    body_hash, hidden, score, created_at, event_seq
             FROM comments ORDER BY created_at ASC, id ASC`,
  votes: `SELECT citizen_id, target_type, target_id, dir, created_at, event_seq
          FROM votes ORDER BY created_at ASC, citizen_id ASC, target_type ASC, target_id ASC`,
  bounties: `SELECT id, creator_id, title, ${preview('spec')} AS spec_preview, spec_hash,
                    amount, fee_amount, status, accepted_claim_id, payable_at,
                    created_at, event_seq
             FROM bounties ORDER BY created_at ASC, id ASC`,
  claims: `SELECT id, bounty_id, citizen_id, status, created_at, event_seq
           FROM claims ORDER BY created_at ASC, id ASC`,
  submissions: `SELECT id, claim_id, artifact_url, artifact_hash,
                       ${preview('notes')} AS notes_preview, worker_sig, created_at, event_seq
                FROM submissions ORDER BY created_at ASC, id ASC`,
  receipts: `SELECT id, submission_id, bounty_id, worker_id, acceptor_id, digest,
                    worker_sig, acceptor_sig, amount_net, amount_fee, pay_to_address,
                    payout_txhash, status, created_at, paid_at, event_seq
             FROM receipts ORDER BY created_at ASC, id ASC`,
  ledger_entries: `SELECT id, ts, debit, credit, amount, memo, ref_type, ref_id, event_seq
                   FROM ledger_entries ORDER BY event_seq ASC, id ASC`,
  treasury_flows: `SELECT txhash, log_index, block_number, direction, counterparty, amount,
                          matched_ref, status, observed_at, event_seq
                   FROM treasury_flows ORDER BY block_number ASC, txhash ASC, log_index ASC`,
  pending_payments: `SELECT id, purpose, ref_id, citizen_id, expected_amount, status,
                            matched_txhash, created_at, expires_at, event_seq
                     FROM pending_payments WHERE status <> 'pending'
                     ORDER BY created_at ASC, id ASC`,
  proposals: `SELECT id, proposer_id, kind, title, ${preview('body')} AS body_preview,
                     policy_key, policy_value, opens_at, votes_at, closes_at, executes_at,
                     status, tally_for, tally_against, tally_abstain, eligible_count,
                     created_at, event_seq
              FROM proposals ORDER BY created_at ASC, id ASC`,
  proposal_votes: `SELECT proposal_id, citizen_id, choice, created_at, event_seq
                   FROM proposal_votes ORDER BY created_at ASC, proposal_id ASC, citizen_id ASC`,
  warden_constraints: `SELECT id, proposal_id, ${preview('predicate')} AS predicate_preview,
                              active, created_at, event_seq
                       FROM warden_constraints ORDER BY created_at ASC, id ASC`,
  moderation_log: `SELECT id, actor, action, target_type, target_id, reason_code,
                          ${preview('reason')} AS reason_preview, evidence_hash, appeal_id,
                          created_at, event_seq
                   FROM moderation_log ORDER BY created_at ASC, id ASC`,
  appeals: `SELECT id, moderation_id, appellant_id, ${preview('argument')} AS argument_preview,
                   status, jury, closes_at, created_at, event_seq
            FROM appeals ORDER BY created_at ASC, id ASC`,
  jury_votes: `SELECT appeal_id, citizen_id, choice, ${preview('reason')} AS reason_preview,
                      created_at, event_seq
               FROM jury_votes ORDER BY created_at ASC, appeal_id ASC, citizen_id ASC`,
  policy: `SELECT key, version, value, set_by, created_at, event_seq
           FROM policy ORDER BY key ASC, version ASC`,
  monthly_closes: `SELECT month, inflows, outflows, infra_cost, obligations, surplus,
                          compute_share, operator_share, reserve_share, chain_head_seq,
                          chain_head_hash, withdrawal_txhash, status, created_at, event_seq
                   FROM monthly_closes ORDER BY month ASC`,
  checkpoints: `SELECT day, last_seq, last_hash, event_count, witness_url, created_at
                FROM checkpoints ORDER BY day ASC`,
};

const SNAPSHOT_NOTE =
  'Convenience dump, bounded so one request cannot exhaust the Worker: rows are capped per table and long text is cut to a preview beside its hash. ' +
  'Page one table with ?table=<name>&from=<offset>&limit=<n>. The chain at /export/events is the authority and carries every body in full; replay it if you do not trust this file.';

/**
 * A forker's starting state: the public tables as they stand now.
 *
 * This is a convenience, not the authority — the chain is. Anything here can be
 * rebuilt from /export/events by replaying it, which is exactly what a fork
 * should do if it does not trust us.
 */
exportRoutes.get('/snapshot', async (c) => {
  const db = c.env.DB;
  const head = await readHead(db);

  const table = c.req.query('table');
  const from = Math.max(intParam(c.req.query('from'), 'from', 0), 0);
  const limit = Math.min(
    Math.max(intParam(c.req.query('limit'), 'limit', SNAPSHOT_ROWS_DEFAULT), 1),
    SNAPSHOT_ROWS_MAX,
  );

  if (table !== undefined && SNAPSHOT_TABLES[table] === undefined) {
    throw badRequest(
      'no_such_table',
      `unknown table "${table}"; one of: ${Object.keys(SNAPSHOT_TABLES).join(', ')}`,
    );
  }
  const names = table === undefined ? Object.keys(SNAPSHOT_TABLES) : [table];

  const tables: Record<string, unknown[]> = {};
  const more: string[] = [];
  const omitted: string[] = [];
  let budget = SNAPSHOT_BYTE_BUDGET;

  for (const name of names) {
    if (budget <= 0) {
      omitted.push(name);
      continue;
    }
    // One row past the limit tells us whether a further page exists without a
    // second COUNT(*) over the table.
    const rows = await many(
      db,
      `${SNAPSHOT_TABLES[name]} LIMIT ? OFFSET ?`,
      limit + 1,
      from,
    );
    if (rows.length > limit) {
      more.push(name);
      rows.length = limit;
    }
    // The serializer runs on this object again in c.json; measuring here is the
    // only way to stop before the isolate is committed to holding all of it.
    budget -= JSON.stringify(rows).length;
    tables[name] = rows;
  }

  const genesis = await one<{ hash: string }>(
    db,
    'SELECT hash FROM events WHERE seq = 1',
  );

  return c.json(
    {
      instance: c.env.INSTANCE_NAME,
      genesis_hash: genesis?.hash ?? null,
      treasury_address: treasuryAddress(c.env) ?? 'pending',
      chain_head: head,
      taken_at: Math.floor(Date.now() / 1000),
      from,
      limit,
      text_preview_chars: SNAPSHOT_TEXT_CHARS,
      /** These tables have further rows past `from + limit`. */
      more,
      /** Dropped from this response for the byte budget; fetch with ?table=. */
      omitted,
      note: SNAPSHOT_NOTE,
      tables,
    },
    200,
    { 'cache-control': 'public, max-age=30' },
  );
});

function intParam(raw: string | undefined, name: string, fallback: number): number {
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw badRequest('bad_param', `${name} must be an integer`);
  return n;
}
