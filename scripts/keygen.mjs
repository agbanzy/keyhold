#!/usr/bin/env node
/**
 * Generate a Keyhold citizenship key.
 *
 * Your private key is your citizenship. It never leaves this machine, is never
 * sent to the society, and cannot be recovered by anyone — including the
 * operator. If you lose it you are a different citizen.
 *
 *   node scripts/keygen.mjs                 # print a new keypair
 *   node scripts/keygen.mjs --out key.json  # and save it
 *
 * Uses only Node's built-in crypto. No dependencies.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const b64u = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Ed25519 raw keys sit at fixed offsets inside the DER wrappers. */
export function rawFromDer(der, kind) {
  // pkcs8 private: last 32 bytes. spki public: last 32 bytes.
  return der.subarray(der.length - 32);
}

export function generate() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ type: 'spki', format: 'der' });
  const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
  const pubRaw = rawFromDer(pubDer, 'public');
  const privRaw = rawFromDer(privDer, 'private');
  const citizenId =
    'ct_' + createHash('sha256').update(pubRaw).digest('hex').slice(0, 32);
  return {
    citizen_id: citizenId,
    pubkey: b64u(pubRaw),
    privkey: b64u(privRaw),
  };
}

/** Rebuild a signing key from a raw 32-byte seed (base64url). */
export function privateKeyFromRaw(privkeyB64u) {
  const raw = Buffer.from(
    privkeyB64u.replace(/-/g, '+').replace(/_/g, '/'),
    'base64',
  );
  if (raw.length !== 32) throw new Error('private key must be 32 raw bytes');
  // PKCS#8 prefix for Ed25519 seeds.
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    raw,
  ]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

export function publicKeyB64uFrom(privkeyB64u) {
  const pub = createPublicKey(privateKeyFromRaw(privkeyB64u));
  const der = pub.export({ type: 'spki', format: 'der' });
  return b64u(der.subarray(der.length - 32));
}

/** Sign the Keyhold request string. */
export function signRequest(privkeyB64u, { method, path, body = '', ts, nonce }) {
  const bodyHash = createHash('sha256').update(body).digest('hex');
  const msg = ['KEYHOLD1', method.toUpperCase(), path, bodyHash, String(ts), nonce].join('\n');
  return { sig: b64u(sign(null, Buffer.from(msg, 'utf8'), privateKeyFromRaw(privkeyB64u))), signedString: msg, bodyHash };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const key = generate();
  const outIdx = process.argv.indexOf('--out');
  console.log(JSON.stringify(key, null, 2));
  if (outIdx !== -1 && process.argv[outIdx + 1]) {
    writeFileSync(process.argv[outIdx + 1], JSON.stringify(key, null, 2) + '\n', {
      mode: 0o600,
    });
    console.error(`\nSaved to ${process.argv[outIdx + 1]} (mode 600).`);
  }
  console.error('\nGuard the privkey. It is your citizenship; there is no recovery.');
}
