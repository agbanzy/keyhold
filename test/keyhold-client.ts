/**
 * A minimal citizen, in test form.
 *
 * Deliberately re-implements the client side of the protocol rather than
 * importing helpers from src: if a test signs its requests with the same code
 * the server verifies them with, the test proves the two halves of one function
 * agree and nothing else. This builds the signing string from the documented
 * recipe, so a change to that recipe breaks these tests — which is the point,
 * because the published chain depends on it never changing.
 */

import { SELF, env } from 'cloudflare:test';
import { b64uEncode, citizenIdFromPubkey, newId, sha256Hex } from '../src/core/crypto';
import { canonicalize } from '../src/core/canonical';
import { GENESIS_PREV_HASH, nowSeconds } from '../src/core/events';

export const BASE = 'https://keyhold.test';
export const GENESIS_HASH = 'a'.repeat(64);

export interface Citizen {
  kp: CryptoKeyPair;
  pubkey: string;
  id: string;
}

export async function keypair(): Promise<Citizen> {
  const kp = (await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey('raw', kp.publicKey)) as ArrayBuffer,
  );
  const pubkey = b64uEncode(raw);
  return { kp, pubkey, id: await citizenIdFromPubkey(pubkey) };
}

export async function signMessage(who: Citizen, message: string): Promise<string> {
  return sign(who, message);
}

async function sign(who: Citizen, message: string): Promise<string> {
  return b64uEncode(
    new Uint8Array(
      await crypto.subtle.sign(
        'Ed25519',
        who.kp.privateKey,
        new TextEncoder().encode(message),
      ),
    ),
  );
}

/** The signing string, spelled out rather than imported. */
function signingLines(parts: {
  method: string;
  path: string;
  bodyHash: string;
  ts: number;
  nonce: string;
}): string {
  return [
    'KEYHOLD1',
    parts.method,
    parts.path,
    parts.bodyHash,
    String(parts.ts),
    parts.nonce,
  ].join('\n');
}

export async function signedFetch(
  who: Citizen,
  method: string,
  path: string,
  body?: unknown,
  opts: { ts?: number } = {},
): Promise<Response> {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const bodyHash = await sha256Hex(raw);
  const ts = opts.ts ?? nowSeconds();
  const nonce = newId('n');
  const sig = await sign(who, signingLines({ method, path, bodyHash, ts, nonce }));
  const headers: Record<string, string> = {
    'x-keyhold-citizen': who.id,
    'x-keyhold-ts': String(ts),
    'x-keyhold-nonce': nonce,
    'x-keyhold-sig': sig,
  };
  if (raw) headers['content-type'] = 'application/json';
  return SELF.fetch(`${BASE}${path}`, { method, headers, body: raw || undefined });
}

/**
 * Sign whatever bytes the caller says, rather than JSON.stringify of an object.
 * The point of several tests below is that the raw body and the parsed object
 * are not the same thing, which a helper that serialises for you cannot express.
 */
export async function signedFetchRaw(
  who: Citizen,
  method: string,
  path: string,
  raw: string,
): Promise<Response> {
  const bodyHash = await sha256Hex(raw);
  const ts = nowSeconds();
  const nonce = newId('n');
  const sig = await sign(who, signingLines({ method, path, bodyHash, ts, nonce }));
  return SELF.fetch(`${BASE}${path}`, {
    method,
    headers: {
      'x-keyhold-citizen': who.id,
      'x-keyhold-ts': String(ts),
      'x-keyhold-nonce': nonce,
      'x-keyhold-sig': sig,
      'content-type': 'application/json',
    },
    body: raw,
  });
}

export function get(path: string): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`);
}

export function post(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

let rpcId = 0;

/** Call an MCP tool, signing it exactly as skill.md says to. */
export async function callTool(
  name: string,
  args: Record<string, unknown>,
  who?: Citizen,
): Promise<{ status: number; result?: any; error?: any; structured?: any }> {
  let full = { ...args };
  if (who) {
    const bodyHash = await sha256Hex(canonicalize(args));
    const ts = nowSeconds();
    const nonce = newId('n');
    const sig = await sign(
      who,
      signingLines({ method: 'MCP', path: `tool:${name}`, bodyHash, ts, nonce }),
    );
    full = { citizen: who.id, ts, nonce, sig, ...args };
  }
  const res = await SELF.fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: ++rpcId,
      method: 'tools/call',
      params: { name, arguments: full },
    }),
  });
  const json = (await res.json()) as any;
  const structured = json?.result?.structuredContent;
  return { status: res.status, result: json?.result, error: json?.error, structured };
}

/** Whatever a tool returned, as an object, error or not. */
export function toolPayload(out: { result?: any; structured?: any }): any {
  if (out.structured !== undefined) return out.structured;
  const text = out.result?.content?.[0]?.text;
  return text ? JSON.parse(text) : undefined;
}

const TABLES = [
  'citizen_capabilities',
  'citizen_profiles',
  'credentials',
  'nonces',
  'quota_usage',
  'receipts',
  'proposals',
  'comments',
  'posts',
  'citizens',
  'events',
  'chain_head',
  'checkpoints',
];

/**
 * A founded instance holding exactly the citizens given. Seeded directly so
 * these tests do not depend on the registration path, which has its own file.
 */
export async function seed(
  citizens: Array<{
    who: Citizen;
    name?: string;
    status?: string;
    standing?: string;
    marks?: number;
    ageDays?: number;
    frozenUntil?: number | null;
  }>,
): Promise<void> {
  const db = env.DB as D1Database;
  for (const t of TABLES) await db.prepare(`DELETE FROM ${t}`).run();
  const now = nowSeconds();
  await db
    .prepare(
      `INSERT INTO events (seq, ts, type, actor, payload, sig, prev_hash, hash)
       VALUES (1, ?, 'genesis', NULL, '{}', NULL, ?, ?)`,
    )
    .bind(now, GENESIS_PREV_HASH, GENESIS_HASH)
    .run();
  await db
    .prepare('INSERT INTO chain_head (id, seq, hash) VALUES (1, 1, ?)')
    .bind(GENESIS_HASH)
    .run();
  for (const c of citizens) {
    await db
      .prepare(
        `INSERT INTO citizens (id, pubkey, display_name, status, standing, marks,
                               frozen_until, created_at, event_seq)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      )
      .bind(
        c.who.id,
        c.who.pubkey,
        c.name ?? 'Test Citizen',
        c.status ?? 'active',
        c.standing ?? 'vouched',
        c.marks ?? 0,
        c.frozenUntil ?? null,
        now - (c.ageDays ?? 30) * 86400,
      )
      .run();
  }
}
