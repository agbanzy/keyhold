/**
 * The witness outage that outlives its UTC day.
 *
 * A fine-grained GitHub token expires; every nightly push fails; the
 * checkpoints still land on the chain with a null witness_url. Renewing the
 * token must then publish the backlog, oldest first, each as the record the
 * chain holds for that day — not a fresh snapshot backdated to it — and say in
 * the commit that it is late.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { GENESIS_PREV_HASH, appendEvent } from '../src/core/events';
import type { Env } from '../src/core/db';
import { dailyWitnessJob } from '../src/witness/checkpoint';

const db = env.DB as D1Database;
const witnessEnv = {
  ...(env as unknown as Env),
  WITNESS_REPO: 'agbanzy/witness-test',
  GITHUB_TOKEN: 'test-token',
} as Env;

const at = (day: string): number => Date.parse(`${day}T00:07:00Z`) / 1000;
// Never a weekday, so no run here also pushes the weekly export.
const NO_EXPORT = 7;

interface Commit {
  path: string;
  message: string;
  content: string;
}

/** The Contents API, in memory. `down` answers everything with 401. */
function fakeGitHub() {
  const files = new Map<string, { sha: string; content: string }>();
  const commits: Commit[] = [];
  const state = { down: true };
  let n = 0;

  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : (input as Request).url);
    const prefix = '/repos/agbanzy/witness-test/contents/';
    if (!url.pathname.startsWith(prefix)) throw new Error(`unexpected fetch ${url}`);
    if (state.down) return new Response('{"message":"Bad credentials"}', { status: 401 });

    const path = decodeURIComponent(url.pathname.slice(prefix.length));
    if ((init?.method ?? 'GET') === 'GET') {
      const file = files.get(path);
      if (!file) return new Response('{"message":"Not Found"}', { status: 404 });
      return Response.json({ sha: file.sha, content: btoa(file.content), encoding: 'base64' });
    }

    const body = JSON.parse(String(init!.body)) as { message: string; content: string; sha?: string };
    if (files.has(path) && body.sha !== files.get(path)!.sha) {
      return new Response('{"message":"sha mismatch"}', { status: 409 });
    }
    const content = atob(body.content);
    const sha = `blob${++n}`;
    files.set(path, { sha, content });
    commits.push({ path, message: body.message, content });
    return Response.json({
      content: { sha, download_url: `https://raw.example/${path}` },
      commit: { sha: `commit${n}` },
    });
  });

  return { files, commits, state };
}

beforeEach(async () => {
  for (const t of ['checkpoints', 'nonces', 'events', 'chain_head']) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
    .bind(GENESIS_PREV_HASH)
    .run();
  await appendEvent(db, { type: 'genesis', actor: null, payload: { instance: 'test' } });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('witness backlog after an outage', () => {
  it('re-pushes every unwitnessed past day once the witness answers again', async () => {
    const gh = fakeGitHub();
    const outage = ['2026-09-24', '2026-09-25', '2026-09-26'];

    for (const day of outage) {
      const run = await dailyWitnessJob(witnessEnv, { now: at(day), weeklyOn: NO_EXPORT });
      expect(run.checkpoint.witness.pushed).toBe(false);
      expect(run.problems.join()).toMatch(/401/);
      // Nothing to gain from walking the backlog against a witness that is down.
      expect(run.repairs).toBeUndefined();
    }
    const recorded = (
      await db
        .prepare('SELECT day, last_seq, last_hash, event_count, witness_url FROM checkpoints ORDER BY day')
        .all<{ day: string; last_seq: number; last_hash: string; event_count: number; witness_url: string | null }>()
    ).results;
    expect(recorded.map((r) => r.day)).toEqual(outage);
    expect(recorded.every((r) => r.witness_url === null)).toBe(true);

    // Token renewed.
    gh.state.down = false;
    const first = await dailyWitnessJob(witnessEnv, {
      now: at('2026-10-24'),
      weeklyOn: NO_EXPORT,
      repair_limit: 2,
    });
    expect(first.problems).toEqual([]);
    expect(first.checkpoint.witness.pushed).toBe(true);
    expect(first.repairs).toEqual({ repaired: ['2026-09-24', '2026-09-25'], remaining: 1, problems: [] });

    // The published file is the record the chain holds for that day.
    for (const row of recorded.slice(0, 2)) {
      const published = JSON.parse(gh.files.get(`checkpoints/${row.day}.json`)!.content);
      expect(published).toMatchObject({
        date: row.day,
        last_seq: row.last_seq,
        last_hash: row.last_hash,
        event_count: row.event_count,
      });
    }
    const late = gh.commits.find((c) => c.path === 'checkpoints/2026-09-24.json')!;
    expect(late.message).toContain('witnessed late, 2026-10-24');
    const onTime = gh.commits.find((c) => c.path === 'checkpoints/2026-10-24.json')!;
    expect(onTime.message).not.toContain('late');

    const second = await dailyWitnessJob(witnessEnv, { now: at('2026-10-25'), weeklyOn: NO_EXPORT });
    expect(second.repairs).toEqual({ repaired: ['2026-09-26'], remaining: 0, problems: [] });

    const unwitnessed = await db
      .prepare('SELECT COUNT(*) AS n FROM checkpoints WHERE witness_url IS NULL')
      .first<{ n: number }>();
    expect(unwitnessed?.n).toBe(0);

    // Every repair is on the chain as its own event.
    const repairs = (
      await db.prepare("SELECT payload FROM events WHERE type = 'checkpoint.published'").all<{ payload: string }>()
    ).results
      .map((r) => JSON.parse(r.payload) as { day: string; repair?: boolean })
      .filter((p) => p.repair)
      .map((p) => p.day);
    expect(repairs).toEqual(outage);

    const index = JSON.parse(gh.files.get('checkpoints/index.json')!.content) as {
      checkpoints: { date: string }[];
    };
    expect(index.checkpoints.map((c) => c.date)).toEqual([...outage, '2026-10-24', '2026-10-25']);
  });
});
