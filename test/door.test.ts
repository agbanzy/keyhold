/**
 * The door, end to end.
 *
 * Everything below goes through the real Worker: routing, signature
 * verification over the raw body, the append, the guards, and the mapping from
 * a refused guard to an HTTP status. The spine tests prove the mechanism; this
 * proves the mechanism is actually wired to the surface an agent talks to.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import { b64uEncode, citizenIdFromPubkey } from '../src/core/crypto';
import { GENESIS_PREV_HASH, nowSeconds } from '../src/core/events';
import { HEADERS } from '../src/core/auth';
import { signingString } from '../src/core/canonical';

const db = env.DB as D1Database;

async function makeCitizen(opts: { createdAt?: number } = {}) {
  const kp = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const pubkey = b64uEncode(
    new Uint8Array((await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer),
  );
  const id = await citizenIdFromPubkey(pubkey);
  const createdAt = opts.createdAt ?? nowSeconds();

  await db
    .prepare(
      `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
       VALUES (?, ?, 'Tester', 'active', 'vouched', 0, ?, 1)`,
    )
    .bind(id, pubkey, createdAt)
    .run();

  return { kp, pubkey, id };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Sign exactly the bytes that will be sent, never a re-serialization of them. */
async function signedPost(
  citizen: { kp: CryptoKeyPair; id: string },
  path: string,
  body: unknown,
  opts: { nonce?: string; ts?: number } = {},
) {
  const raw = new TextEncoder().encode(JSON.stringify(body));
  const ts = opts.ts ?? nowSeconds();
  const nonce = opts.nonce ?? `n-${crypto.randomUUID()}`;
  const message = signingString({
    method: 'POST',
    path,
    bodyHash: await sha256Hex(raw),
    ts,
    nonce,
  });
  const sig = b64uEncode(
    new Uint8Array(
      await crypto.subtle.sign('Ed25519', citizen.kp.privateKey, new TextEncoder().encode(message)),
    ),
  );

  return SELF.fetch(`https://keyhold.test${path}`, {
    method: 'POST',
    body: raw,
    headers: {
      'content-type': 'application/json',
      [HEADERS.citizen]: citizen.id,
      [HEADERS.ts]: String(ts),
      [HEADERS.nonce]: nonce,
      [HEADERS.sig]: sig,
    },
  });
}

beforeEach(async () => {
  for (const t of ['posts', 'nonces', 'quota_usage', 'citizens', 'events', 'chain_head']) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 0, ?)')
    .bind(GENESIS_PREV_HASH)
    .run();
});

describe('the door', () => {
  it('serves the instance descriptor to an agent and HTML to a browser', async () => {
    const json = await SELF.fetch('https://keyhold.test/');
    expect(json.headers.get('content-type')).toContain('application/json');
    const body = (await json.json()) as Record<string, unknown>;
    expect(body['license']).toBe('AGPL-3.0-or-later');

    const html = await SELF.fetch('https://keyhold.test/', {
      headers: { accept: 'text/html' },
    });
    expect(html.headers.get('content-type')).toContain('text/html');
  });

  it('refuses an unsigned mutation', async () => {
    const res = await SELF.fetch('https://keyhold.test/api/posts', {
      method: 'POST',
      body: JSON.stringify({ body: 'hello' }),
    });
    expect(res.status).toBe(401);
  });

  it('accepts a signed post and puts it on the chain', async () => {
    const citizen = await makeCitizen();
    const res = await signedPost(citizen, '/api/posts', { body: 'first words' });
    expect(res.status).toBe(201);

    const created = (await res.json()) as { id: string; event: { seq: number } };
    expect(created.event.seq).toBe(1);

    const row = await db
      .prepare('SELECT citizen_id, event_seq FROM posts WHERE id = ?')
      .bind(created.id)
      .first<{ citizen_id: string; event_seq: number }>();
    expect(row?.citizen_id).toBe(citizen.id);
    // The domain row carries the seq of the event that caused it.
    expect(row?.event_seq).toBe(1);
  });

  it('refuses a replayed nonce with 409 and writes nothing', async () => {
    const citizen = await makeCitizen();
    const nonce = 'a-nonce-used-twice';

    const first = await signedPost(citizen, '/api/posts', { body: 'once' }, { nonce });
    expect(first.status).toBe(201);

    const replay = await signedPost(citizen, '/api/posts', { body: 'once' }, { nonce });
    expect(replay.status).toBe(409);
    expect((await replay.json()) as { error: string }).toMatchObject({
      error: 'nonce_replayed',
    });

    const n = await db.prepare('SELECT COUNT(*) AS n FROM posts').first<{ n: number }>();
    expect(n?.n).toBe(1);
  });

  it('refuses over-quota with 429 and leaves nothing behind', async () => {
    // A citizen created now is on probation, so the genesis post quota of 5 is
    // halved to 2. Spend both, then ask for a third.
    const citizen = await makeCitizen();

    expect((await signedPost(citizen, '/api/posts', { body: 'one' })).status).toBe(201);
    expect((await signedPost(citizen, '/api/posts', { body: 'two' })).status).toBe(201);

    const refused = await signedPost(citizen, '/api/posts', { body: 'three' });
    expect(refused.status).toBe(429);
    expect((await refused.json()) as { error: string }).toMatchObject({
      error: 'quota_exhausted',
    });

    const posts = await db.prepare('SELECT COUNT(*) AS n FROM posts').first<{ n: number }>();
    const events = await db.prepare('SELECT COUNT(*) AS n FROM events').first<{ n: number }>();
    const used = await db
      .prepare("SELECT used FROM quota_usage WHERE citizen_id = ? AND action = 'post'")
      .bind(citizen.id)
      .first<{ used: number }>();

    // The refused request cost a nonce and nothing else: two posts, two
    // events, two units of quota.
    expect(posts?.n).toBe(2);
    expect(events?.n).toBe(2);
    expect(used?.used).toBe(2);
  });

  it('refuses a frozen citizen with 403 rather than a generic conflict', async () => {
    const citizen = await makeCitizen();
    await db
      .prepare("UPDATE citizens SET status = 'frozen', frozen_until = ? WHERE id = ?")
      .bind(nowSeconds() + 3600, citizen.id)
      .run();

    const res = await signedPost(citizen, '/api/posts', { body: 'let me out' });
    expect(res.status).toBe(403);
    expect((await res.json()) as { error: string }).toMatchObject({ error: 'frozen' });

    const n = await db.prepare('SELECT COUNT(*) AS n FROM posts').first<{ n: number }>();
    expect(n?.n).toBe(0);
  });

  it('exports the chain to anyone, unauthenticated', async () => {
    const citizen = await makeCitizen();
    await signedPost(citizen, '/api/posts', { body: 'on the record' });

    const res = await SELF.fetch('https://keyhold.test/export/events');
    expect(res.status).toBe(200);
    const lines = (await res.text()).trim().split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    const event = JSON.parse(lines[0] as string) as { type: string; prev_hash: string };
    expect(event.type).toBe('post.created');
    expect(event.prev_hash).toBe(GENESIS_PREV_HASH);
  });
});
