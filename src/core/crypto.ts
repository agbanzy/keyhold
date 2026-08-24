/**
 * All hashing and signature verification. One verify path for REST and MCP.
 *
 * Ed25519 is native in the Workers runtime via WebCrypto; @noble/ed25519 is the
 * fallback for runtimes that lack it (and for the test pool). We probe once and
 * cache the answer.
 */

import * as nobleEd from '@noble/ed25519';

const encoder = new TextEncoder();

// -------------------------------------------------------------- base64url

export function b64uEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export function hexEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexDecode(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hexDecode: odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ------------------------------------------------------------------ hashing

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(digest);
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  return hexEncode(await sha256Bytes(bytes));
}

/** The empty-body hash, precomputed on first use. */
let emptyBodyHash: string | null = null;
export async function emptyHash(): Promise<string> {
  if (emptyBodyHash === null) emptyBodyHash = await sha256Hex('');
  return emptyBodyHash;
}

// -------------------------------------------------------------- signatures

let nativeEd25519: boolean | null = null;

async function hasNativeEd25519(): Promise<boolean> {
  if (nativeEd25519 !== null) return nativeEd25519;
  try {
    // Generating a throwaway pair is the cheapest way to learn whether the
    // runtime implements the algorithm at all.
    const kp = (await crypto.subtle.generateKey('Ed25519', false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    nativeEd25519 = !!kp.publicKey;
  } catch {
    nativeEd25519 = false;
  }
  return nativeEd25519;
}

/**
 * Verify an Ed25519 signature.
 * @param pubkeyB64u base64url raw 32-byte public key
 * @param sigB64u    base64url raw 64-byte signature
 * @param message    the signed string (UTF-8)
 */
export async function verifySig(
  pubkeyB64u: string,
  sigB64u: string,
  message: string,
): Promise<boolean> {
  let pubkey: Uint8Array;
  let sig: Uint8Array;
  try {
    pubkey = b64uDecode(pubkeyB64u);
    sig = b64uDecode(sigB64u);
  } catch {
    return false;
  }
  if (pubkey.length !== 32 || sig.length !== 64) return false;

  const msg = encoder.encode(message);

  if (await hasNativeEd25519()) {
    try {
      const key = await crypto.subtle.importKey('raw', pubkey, 'Ed25519', false, [
        'verify',
      ]);
      return await crypto.subtle.verify('Ed25519', key, sig, msg);
    } catch {
      // Fall through to noble rather than failing closed on a runtime quirk.
    }
  }

  try {
    return await nobleEd.verifyAsync(sig, msg, pubkey);
  } catch {
    return false;
  }
}

// --------------------------------------------------------------- identity

/**
 * Citizen id is derived from the public key, so it cannot be chosen, squatted,
 * or reassigned. ct_ + first 32 hex chars of sha256(raw pubkey).
 */
export async function citizenIdFromPubkey(pubkeyB64u: string): Promise<string> {
  const raw = b64uDecode(pubkeyB64u);
  if (raw.length !== 32) throw new Error('pubkey must be 32 raw bytes');
  const hex = await sha256Hex(raw);
  return 'ct_' + hex.slice(0, 32);
}

export function isValidPubkey(pubkeyB64u: string): boolean {
  try {
    return b64uDecode(pubkeyB64u).length === 32;
  } catch {
    return false;
  }
}

/** Random id with a type prefix, e.g. `po_a1b2…`. */
export function newId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `${prefix}_${hexEncode(bytes)}`;
}
