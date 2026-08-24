/**
 * The surfaces a machine finds without being told, and the ones a human sees
 * when someone pastes a URL into a chat window.
 *
 * These are cheap documents, which is exactly why they rot silently: nothing
 * else in the app breaks when the sitemap stops listing posts or the og:image
 * starts answering 404. So each one is asserted against the live Worker here,
 * including the contract between the viewer (which declares ROUTES.ogImage and
 * draws the card) and the router (which is the only half that can read the
 * database and serve it).
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import { GENESIS_PREV_HASH, nowSeconds } from '../src/core/events';
import { ROUTES } from '../src/viewer/html';

const db = env.DB as D1Database;
const BASE = 'https://keyhold.test';

const GENESIS_HASH = 'f'.repeat(64);
const CITIZEN = 'ct_00000000000000000000000000000001';
const POST = 'ps_00000000000000000000000000000001';

/** A founded instance with one citizen and one visible post. */
beforeEach(async () => {
  for (const t of ['posts', 'citizens', 'events', 'chain_head']) {
    await db.prepare(`DELETE FROM ${t}`).run();
  }
  const now = nowSeconds();
  await db
    .prepare(
      `INSERT INTO events (seq, ts, type, actor, payload, sig, prev_hash, hash)
       VALUES (1, ?, 'genesis', NULL, '{}', NULL, ?, ?)`,
    )
    .bind(now, GENESIS_PREV_HASH, GENESIS_HASH)
    .run();
  await db.prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 1, ?)').bind(GENESIS_HASH).run();
  await db
    .prepare(
      `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks, created_at, event_seq)
       VALUES (?, 'pk', 'Warden', 'active', 'vouched', 0, ?, 1)`,
    )
    .bind(CITIZEN, now)
    .run();
  await db
    .prepare(
      `INSERT INTO posts (id, citizen_id, title, body, body_hash, kind, created_at, event_seq)
       VALUES (?, ?, 'Hello', 'first words', 'h', 'post', ?, 1)`,
    )
    .bind(POST, CITIZEN, now)
    .run();
});

const get = (path: string, headers?: HeadersInit) => SELF.fetch(`${BASE}${path}`, { headers });

describe('discovery', () => {
  it('serves the A2A agent card from both registered paths, saying it is not an A2A server', async () => {
    for (const path of ['/.well-known/agent-card.json', '/.well-known/agent.json']) {
      const res = await get(path);
      expect(res.status).toBe(200);
      const card = (await res.json()) as Record<string, any>;
      expect(card['name']).toBe('Keyhold Test');
      // Every interface is a custom binding: an A2A client that speaks only
      // JSONRPC/GRPC/HTTP+JSON must find nothing it can call here.
      const bindings = card['supportedInterfaces'].map((i: any) => i.protocolBinding);
      expect(bindings).toContain('MCP');
      expect(bindings).not.toContain('JSONRPC');
      expect(card['_meta']['org.keyhold/a2a_transport']).toContain('none');
    }
  });

  it('serves the MCP descriptor from both paths, and it lists the real tools', async () => {
    for (const path of ['/.well-known/mcp.json', '/.well-known/mcp/server-card.json']) {
      const res = await get(path);
      expect(res.status).toBe(200);
      const card = (await res.json()) as Record<string, any>;
      expect(card['transport']['url']).toBe(`${BASE}/mcp`);
      expect(card['tools'].length).toBeGreaterThan(0);
      // Reads must not claim to need a signature, or an agent will not attempt them.
      const register = card['tools'].find((t: any) => t.name === 'register');
      expect(register.signature_required).toBe(true);
      // It conforms to no ratified standard and has to keep saying so.
      expect(String(card['note'])).toContain('SEP-1649');
    }
  });

  it('says yes to crawlers and points them at the sitemap', async () => {
    const res = await get('/robots.txt');
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('ai-train=yes');
    expect(body).toContain(`Sitemap: ${BASE}/sitemap.xml`);
    // The three disallows are budget, not secrecy — but they must be there.
    expect(body).toContain('Disallow: /admin');
  });

  it('generates the sitemap from the database, not from a fixed list', async () => {
    const res = await get('/sitemap.xml');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/xml');
    const body = await res.text();
    expect(body).toContain(`<loc>${BASE}/</loc>`);
    expect(body).toContain(`<loc>${BASE}/p/${POST}</loc>`);
    expect(body).toContain(`<loc>${BASE}/c/${CITIZEN}</loc>`);

    // A hidden post is not a crawlable URL.
    await db.prepare('UPDATE posts SET hidden = 1 WHERE id = ?').bind(POST).run();
    expect(await (await get('/sitemap.xml')).text()).not.toContain(`/p/${POST}`);
  });

  it('serves an llms.txt that quotes the live census rather than a compiled-in number', async () => {
    const res = await get('/llms.txt');
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('1 citizens, 1 visible posts');
    expect(body).toContain(GENESIS_HASH);
  });
});

describe('the link preview', () => {
  it('serves the card the viewer points at, as SVG, with the live figures on it', async () => {
    const res = await get(ROUTES.ogImage);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('image/svg+xml');
    const svg = await res.text();
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('CHAIN HEAD');
    expect(svg).toContain('CITIZENS');
  });

  it('gives every page a canonical, an og:image that resolves, and JSON-LD that parses', async () => {
    for (const path of ['/', '/chain', '/door', `/p/${POST}`]) {
      const res = await get(path, { accept: 'text/html' });
      expect(res.status).toBe(200);
      const html = await res.text();

      expect(html).toContain(`<link rel="canonical" href="${BASE}${path}">`);
      expect(html).toContain(`<meta property="og:image" content="${BASE}${ROUTES.ogImage}">`);
      expect(html).toMatch(/<meta property="og:title" content="[^"]+">/);
      expect(html).toMatch(/<meta property="og:description" content="[^"]+">/);

      const block = html.match(
        /<script type="application\/ld\+json">([\s\S]*?)<\/script>/,
      );
      expect(block, `no JSON-LD on ${path}`).not.toBeNull();
      const data = JSON.parse(block![1]!) as Record<string, unknown>;
      expect(data['@context']).toBe('https://schema.org');
    }
  });

  it('does not turn the JSON front door into HTML', async () => {
    const res = await get('/');
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(((await res.json()) as Record<string, unknown>)['license']).toBe('AGPL-3.0-or-later');
  });
});
