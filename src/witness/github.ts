/**
 * The witness: a public GitHub repo the society pushes its checkpoints to.
 *
 * The point is adversarial. A checkpoint stored only in our own D1 proves
 * nothing — whoever can rewrite the events table can rewrite the checkpoints
 * table alongside it. A checkpoint pushed to a public repo lands in someone
 * else's git history, timestamped by a third party, and can no longer be
 * quietly changed. scripts/verify.mjs reads both and compares them; that
 * comparison is the whole reason this file exists.
 *
 * We only ever write files here. This module holds no key, signs nothing, and
 * cannot touch the chain. The token is a repo-scoped PAT belonging to the
 * operator; losing it costs the society its witness, nothing else.
 */

import { KeyholdError } from '../core/errors';
import type { Env } from '../core/db';

const API = 'https://api.github.com';
const UA = 'keyhold-witness';

export interface WitnessTarget {
  owner: string;
  repo: string;
  branch: string;
}

export interface PushResult {
  /** True only when GitHub confirmed the write. Never optimistic. */
  pushed: boolean;
  /** Set when pushed is false: why nothing happened. */
  reason?: string;
  /** raw.githubusercontent URL of the committed file. */
  url?: string;
  /** Blob sha of the committed content. */
  sha?: string;
  /** Commit sha, so the operator can point at the git history. */
  commit?: string;
  /** True when the content on the branch already matched byte-for-byte. */
  unchanged?: boolean;
}

/**
 * Parse WITNESS_REPO ("owner/repo" or "owner/repo#branch"). Returns null when
 * the witness is not configured, which is a legitimate state: an instance may
 * run without one, it just cannot prove it has not rewritten itself.
 */
export function witnessTarget(env: Env): WitnessTarget | null {
  const raw = env.WITNESS_REPO?.trim() ?? '';
  if (!raw) return null;
  const [path, branch] = raw.split('#');
  const parts = (path ?? '').split('/').filter(Boolean);
  if (parts.length !== 2) return null;
  return { owner: parts[0]!, repo: parts[1]!, branch: (branch ?? 'main').trim() || 'main' };
}

export function witnessConfigured(env: Env): boolean {
  return witnessTarget(env) !== null && !!env.GITHUB_TOKEN?.trim();
}

/** Where the public can read a witnessed file without an API call. */
export function rawUrl(target: WitnessTarget, path: string): string {
  return `https://raw.githubusercontent.com/${target.owner}/${target.repo}/${target.branch}/${path}`;
}

/** The base a verifier should be pointed at: `--witness <this>`. */
export function witnessBaseUrl(env: Env): string | null {
  const target = witnessTarget(env);
  if (!target) return null;
  return `https://raw.githubusercontent.com/${target.owner}/${target.repo}/${target.branch}`;
}

/**
 * Read a file from the witness repo. Returns null for 404 (the file has never
 * been written), which is how the create-vs-update decision is made.
 */
export async function readFile(
  env: Env,
  path: string,
): Promise<{ sha: string; content: string } | null> {
  const target = witnessTarget(env);
  const token = env.GITHUB_TOKEN?.trim();
  if (!target || !token) return null;

  const res = await fetch(contentsUrl(target, path) + `?ref=${encodeURIComponent(target.branch)}`, {
    headers: ghHeaders(token),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw await ghError(res, `GET contents ${path}`);

  const body = (await res.json()) as { sha?: string; content?: string; encoding?: string };
  if (!body.sha) throw new KeyholdError(502, 'witness_bad_response', `no sha in GET ${path}`);
  const content =
    body.encoding === 'base64' && body.content
      ? decodeBase64(body.content.replace(/\n/g, ''))
      : (body.content ?? '');
  return { sha: body.sha, content };
}

export async function readJson<T>(env: Env, path: string): Promise<T | null> {
  const file = await readFile(env, path);
  if (!file) return null;
  try {
    return JSON.parse(file.content) as T;
  } catch {
    // A corrupt witness file is worse than a missing one; say so rather than
    // silently overwriting whatever is there.
    throw new KeyholdError(502, 'witness_corrupt', `${path} in the witness repo is not JSON`);
  }
}

/**
 * Create or update one file. Handles the sha dance the Contents API requires:
 * a create must omit `sha`, an update must supply the blob sha currently on the
 * branch, and a concurrent write invalidates it (409/422) — so on conflict we
 * re-read the sha once and retry.
 *
 * Absent token or repo is a no-op that says so. It never reports success it did
 * not get: a cron that quietly stopped witnessing is exactly the failure this
 * whole module exists to make impossible.
 */
export async function pushFile(
  env: Env,
  path: string,
  content: string | Uint8Array,
  message: string,
): Promise<PushResult> {
  const target = witnessTarget(env);
  if (!target) {
    return { pushed: false, reason: 'WITNESS_REPO is not set; no public witness for this instance' };
  }
  const token = env.GITHUB_TOKEN?.trim();
  if (!token) {
    return {
      pushed: false,
      reason: `GITHUB_TOKEN is not set; cannot write ${target.owner}/${target.repo}`,
    };
  }

  const encoded = encodeBase64(content);

  for (let attempt = 0; attempt < 2; attempt++) {
    const existing = await readFile(env, path);
    if (existing && existing.sha && sameContent(existing.content, content)) {
      return {
        pushed: true,
        unchanged: true,
        sha: existing.sha,
        url: rawUrl(target, path),
      };
    }

    const res = await fetch(contentsUrl(target, path), {
      method: 'PUT',
      headers: { ...ghHeaders(token), 'content-type': 'application/json' },
      body: JSON.stringify({
        message,
        content: encoded,
        branch: target.branch,
        ...(existing ? { sha: existing.sha } : {}),
      }),
    });

    if (res.ok) {
      const body = (await res.json()) as {
        content?: { sha?: string; download_url?: string };
        commit?: { sha?: string };
      };
      return {
        pushed: true,
        sha: body.content?.sha,
        commit: body.commit?.sha,
        url: body.content?.download_url ?? rawUrl(target, path),
      };
    }

    // 409/422 means the blob moved under us. Re-read the sha and try once more.
    if ((res.status === 409 || res.status === 422) && attempt === 0) {
      await res.text();
      continue;
    }

    throw await ghError(res, `PUT contents ${path}`);
  }

  throw new KeyholdError(
    409,
    'witness_conflict',
    `${path} kept changing under us in the witness repo`,
  );
}

// ------------------------------------------------------------------ internals

function contentsUrl(target: WitnessTarget, path: string): string {
  const clean = path.replace(/^\/+/, '');
  const encoded = clean.split('/').map(encodeURIComponent).join('/');
  return `${API}/repos/${target.owner}/${target.repo}/contents/${encoded}`;
}

function ghHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': UA,
  };
}

async function ghError(res: Response, what: string): Promise<KeyholdError> {
  const text = await res.text();
  // GitHub error bodies never contain the token, but they do echo the repo path;
  // that is public information by construction.
  return new KeyholdError(
    502,
    'witness_push_failed',
    `${what}: GitHub returned ${res.status}`,
    text.slice(0, 400),
  );
}

function sameContent(existing: string, next: string | Uint8Array): boolean {
  if (typeof next !== 'string') return false; // binary: always rewrite
  return existing === next;
}

export function encodeBase64(data: string | Uint8Array): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  let binary = '';
  // Chunked so a multi-megabyte export does not blow the argument limit.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function decodeBase64(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
