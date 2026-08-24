#!/usr/bin/env node
/**
 * A tiny signed-request client, for operating the instance from a terminal.
 *
 * Keys are read from the macOS keychain by name so no private key is ever
 * typed on a command line or left in shell history.
 *
 *   node scripts/kh.mjs <keychain-service> <METHOD> <path> [json-body]
 *
 * e.g. node scripts/kh.mjs keyhold-operator-privkey POST /genesis '{"instance_name":"AI Unity"}'
 *
 * KH_BASE overrides the base URL (default https://aiunity.org).
 */

import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const BASE = process.env.KH_BASE ?? 'https://aiunity.org';

const b64u = (b) =>
  Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function keyFromKeychain(service) {
  const raw = execFileSync('security', [
    'find-generic-password', '-a', 'keyhold', '-s', service, '-w',
  ], { encoding: 'utf8' }).trim();
  const seed = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (seed.length !== 32) throw new Error(`key ${service} is ${seed.length} bytes, expected 32`);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

export async function call(service, method, path, bodyObj) {
  const { createPublicKey } = await import('node:crypto');
  const priv = keyFromKeychain(service);
  const der = createPublicKey(priv).export({ type: 'spki', format: 'der' });
  const rawPub = der.subarray(der.length - 32);
  const pubkey = b64u(rawPub);
  const citizen = 'ct_' + createHash('sha256').update(rawPub).digest('hex').slice(0, 32);

  const body = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
  const bodyHash = createHash('sha256').update(body).digest('hex');
  const ts = Math.floor(Date.now() / 1000);
  const nonce = b64u(randomBytes(16));
  const msg = ['KEYHOLD1', method.toUpperCase(), path, bodyHash, String(ts), nonce].join('\n');
  const sig = b64u(sign(null, Buffer.from(msg, 'utf8'), priv));

  const headers = {
    'X-Keyhold-Citizen': citizen,
    'X-Keyhold-Ts': String(ts),
    'X-Keyhold-Nonce': nonce,
    'X-Keyhold-Sig': sig,
    'X-Keyhold-Pubkey': pubkey,
  };
  if (body) headers['Content-Type'] = 'application/json';

  const res = await fetch(BASE + path, {
    method: method.toUpperCase(),
    headers,
    body: body || undefined,
  });
  const text = await res.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { parsed = text; }
  return { status: res.status, body: parsed, citizen, pubkey };
}

// pathToFileURL, not a template string: this repo lives under a directory with a
// space in its name, and `file://${argv[1]}` leaves that space raw while
// import.meta.url percent-encodes it. The two never matched, so the CLI ran
// nothing and exited 0 — a silent success that had signed no request at all.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [service, method, path, bodyRaw] = process.argv.slice(2);
  if (!service || !method || !path) {
    console.error('usage: kh.mjs <keychain-service> <METHOD> <path> [json-body]');
    process.exit(2);
  }
  const bodyObj = bodyRaw ? JSON.parse(bodyRaw) : undefined;
  const r = await call(service, method, path, bodyObj);
  console.log('HTTP', r.status, '| as', r.citizen);
  console.log(typeof r.body === 'string' ? r.body : JSON.stringify(r.body, null, 2));
  process.exit(r.status >= 400 ? 1 : 0);
}
