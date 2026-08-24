/**
 * Deterministic serialization. Two independent implementations (this one and
 * scripts/verify.mjs) must agree byte-for-byte forever, or the chain becomes
 * unverifiable. Keep this file boring and never "improve" it.
 *
 * Rules: UTF-8, keys sorted by code unit, no insignificant whitespace,
 * no floats (integers only), no undefined, arrays keep their order.
 */

export type Canonical =
  | string
  | number
  | boolean
  | null
  | Canonical[]
  | { [k: string]: Canonical };

export function canonicalize(value: unknown): string {
  return encode(value);
}

function encode(v: unknown): string {
  if (v === null) return 'null';

  const t = typeof v;

  if (t === 'boolean') return v ? 'true' : 'false';

  if (t === 'number') {
    if (!Number.isFinite(v as number)) {
      throw new Error('canonicalize: non-finite number');
    }
    if (!Number.isInteger(v as number)) {
      // Floats have no single canonical decimal form across languages. All
      // money is micro-USDC integers precisely so this never needs to change.
      throw new Error('canonicalize: non-integer number');
    }
    if (!Number.isSafeInteger(v as number)) {
      throw new Error('canonicalize: unsafe integer');
    }
    return String(v);
  }

  if (t === 'string') return JSON.stringify(v);

  if (Array.isArray(v)) {
    return '[' + v.map(encode).join(',') + ']';
  }

  if (t === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort(compareCodeUnits);
    return (
      '{' +
      keys.map((k) => JSON.stringify(k) + ':' + encode(obj[k])).join(',') +
      '}'
    );
  }

  throw new Error(`canonicalize: unsupported type ${t}`);
}

/** Sort by UTF-16 code unit, which is what JS `<` already does on strings. */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * The request signing string. Line-based on purpose: an agent can build it with
 * string concatenation in any language, and never has to canonicalize JSON to
 * talk to us. Only the body's hash is signed, so body formatting is free.
 */
export const SIGNING_PREFIX = 'KEYHOLD1';

export function signingString(parts: {
  method: string;
  path: string;
  bodyHash: string;
  ts: number;
  nonce: string;
}): string {
  return [
    SIGNING_PREFIX,
    parts.method.toUpperCase(),
    parts.path,
    parts.bodyHash,
    String(parts.ts),
    parts.nonce,
  ].join('\n');
}
