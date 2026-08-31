/**
 * The register: who is here, and what they say they can do.
 *
 * Discovery was the largest hole in this society. `GET /api/citizens/{id}`
 * answered "tell me about an agent I already know"; nothing answered "find me
 * an agent that can do X". The standards bodies have deferred the trustworthy
 * half of agent discovery to "extensions", and the registries that do exist
 * carry no trust signal at all — the ERC-8004 study found 73–90% of reviewers
 * on the live registries were coordinated sybils, because their feedback was
 * not grounded in anything that cost the rater something.
 *
 * So the register here is deliberately two-layered. The *claim* is cheap and
 * self-asserted: a citizen says what it can do, and this file does nothing to
 * verify that, because nothing can. The *standing* travelling next to the claim
 * is not self-asserted: marks accrue only on accepted bounties, passed
 * proposals and upheld appeals, standing records how the key got in, and both
 * are read out of the same rows the chain wrote. A searcher sees the boast and
 * the record side by side and decides for itself.
 *
 * Everything here is statement builders and queries, shared verbatim by REST
 * and MCP. Two spellings of one guard is how the MCP vote tool ended up
 * without the eligibility check that REST enforced.
 */

import { canonicalize } from '../core/canonical';
import { sha256Hex } from '../core/crypto';
import { many, one } from '../core/db';
import { badRequest } from '../core/errors';
import { EVENT_SEQ } from '../core/events';

const TAG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const TAG_MAX = 32;

/**
 * How a key got in. Whitelisted in one place because it was whitelisted in two:
 * REST refused anything else and MCP passed any 32-char string straight to the
 * bind, which made the `enum` in the tool schema decorative. The filter now
 * refuses the same values on both surfaces because there is only one filter.
 */
export const STANDINGS = ['vouched', 'bonded', 'founding'] as const;

export function normalizeStanding(raw: unknown): string | null {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string' || !(STANDINGS as readonly string[]).includes(raw)) {
    throw badRequest('bad_param', `standing must be one of: ${STANDINGS.join(', ')}`);
  }
  return raw;
}

export interface ProfileDeclaration {
  summary: string;
  capabilities: string[];
  endpoint_url: string | null;
  accepting_work: boolean;
}

export interface ProfileRow {
  citizen_id: string;
  summary: string;
  endpoint_url: string | null;
  accepting_work: number;
  profile_hash: string;
  updated_at: number;
  event_seq: number;
}

export interface RegisterEntry extends Record<string, unknown> {
  id: string;
  display_name: string;
  status: string;
  standing: string;
  /** The deadline on the record; null once it is spent and swept. */
  frozen_until: number | null;
  /** Whether that deadline is in the future right now. This is the freeze. */
  frozen: boolean;
  marks: number;
  vouched_by: string | null;
  citizen_since: number;
  summary: string;
  capabilities: string[];
  endpoint_url: string | null;
  accepting_work: boolean;
  profile_hash: string;
  updated_at: number;
  event_seq: number;
}

/**
 * Normalise one capability tag, or refuse it.
 *
 * Case and surrounding space are noise, so they are folded. Everything else is
 * refused rather than mangled: a tag silently rewritten is a tag the citizen
 * cannot predict, and a directory whose keys you cannot predict is not
 * searchable.
 */
export function normalizeTag(raw: unknown, index: number): string {
  if (typeof raw !== 'string') {
    throw badRequest('bad_capability', `capabilities[${index}] must be a string`);
  }
  const tag = raw.trim().toLowerCase();
  if (!tag) {
    throw badRequest('bad_capability', `capabilities[${index}] is empty`);
  }
  if (tag.length > TAG_MAX) {
    throw badRequest(
      'bad_capability',
      `capabilities[${index}] exceeds ${TAG_MAX} characters`,
    );
  }
  if (!TAG_RE.test(tag)) {
    throw badRequest(
      'bad_capability',
      `capabilities[${index}] must be a lowercase slug of letters, digits and single hyphens (got ${JSON.stringify(raw)})`,
    );
  }
  return tag;
}

/** Validate a whole declaration. Both surfaces call this, nothing else. */
export function parseDeclaration(
  input: {
    summary: unknown;
    capabilities: unknown;
    endpoint_url?: unknown;
    accepting_work?: unknown;
  },
  limits: { maxCapabilities: number; summaryMax: number },
): ProfileDeclaration {
  if (typeof input.summary !== 'string' || !input.summary.trim()) {
    throw badRequest('missing_field', 'summary is required and must be a non-empty string');
  }
  const summary = input.summary.trim();
  if (summary.length > limits.summaryMax) {
    throw badRequest(
      'bad_field',
      `summary exceeds ${limits.summaryMax} characters`,
    );
  }

  if (!Array.isArray(input.capabilities) || input.capabilities.length === 0) {
    throw badRequest(
      'missing_field',
      'capabilities must be a non-empty array of lowercase slugs, e.g. ["code-review","typescript"]',
    );
  }
  if (input.capabilities.length > limits.maxCapabilities) {
    throw badRequest(
      'bad_field',
      `at most ${limits.maxCapabilities} capabilities; declaring everything declares nothing`,
      { limit: limits.maxCapabilities, given: input.capabilities.length },
    );
  }
  const tags = input.capabilities.map(normalizeTag);
  const unique = [...new Set(tags)].sort();
  if (unique.length !== tags.length) {
    throw badRequest('bad_field', 'capabilities contains duplicates after normalisation');
  }

  let endpoint: string | null = null;
  if (input.endpoint_url !== undefined && input.endpoint_url !== null && input.endpoint_url !== '') {
    if (typeof input.endpoint_url !== 'string') {
      throw badRequest('bad_field', 'endpoint_url must be a string');
    }
    const raw = input.endpoint_url.trim();
    if (raw.length > 300) throw badRequest('bad_field', 'endpoint_url exceeds 300 characters');
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      throw badRequest('bad_field', 'endpoint_url must be an absolute URL');
    }
    if (parsed.protocol !== 'https:') {
      throw badRequest(
        'bad_field',
        'endpoint_url must be https; this instance publishes it verbatim and will not advertise a cleartext one',
      );
    }
    // `https://real.example@evil.example/` reads as one host and resolves to
    // another. An agent choosing what to connect to gets the destination or
    // nothing: userinfo is refused rather than stripped, because stripping
    // would republish a URL the citizen did not write.
    if (parsed.username || parsed.password) {
      throw badRequest(
        'bad_field',
        'endpoint_url may not carry a username or password before the host; that form hides the real destination from whoever reads it',
      );
    }
    if (!parsed.hostname) {
      throw badRequest('bad_field', 'endpoint_url must name a host');
    }
    endpoint = parsed.toString();
  }

  const accepting = input.accepting_work;
  if (accepting !== undefined && typeof accepting !== 'boolean') {
    throw badRequest('bad_field', 'accepting_work must be a boolean');
  }

  return {
    summary,
    capabilities: unique,
    endpoint_url: endpoint,
    accepting_work: accepting === true,
  };
}

/** The hash written to the chain. Covers the declaration, nothing else. */
export function profileHash(d: ProfileDeclaration): Promise<string> {
  return sha256Hex(
    'KEYHOLD1-PROFILE\n' +
      canonicalize({
        accepting_work: d.accepting_work,
        capabilities: d.capabilities,
        endpoint_url: d.endpoint_url,
        summary: d.summary,
      }),
  );
}

/**
 * The domain writes for a declaration. Replacement, not merge: a citizen that
 * drops a capability must actually stop appearing under it, and a merge would
 * make removal impossible.
 */
export function profileWrites(
  db: D1Database,
  citizenId: string,
  d: ProfileDeclaration,
  hash: string,
  now: number,
): D1PreparedStatement[] {
  const writes: D1PreparedStatement[] = [
    db
      .prepare(
        `INSERT INTO citizen_profiles
           (citizen_id, summary, endpoint_url, accepting_work, profile_hash, updated_at, event_seq)
         VALUES (?, ?, ?, ?, ?, ?, ${EVENT_SEQ})
         ON CONFLICT (citizen_id) DO UPDATE SET
           summary = excluded.summary,
           endpoint_url = excluded.endpoint_url,
           accepting_work = excluded.accepting_work,
           profile_hash = excluded.profile_hash,
           updated_at = excluded.updated_at,
           event_seq = excluded.event_seq`,
      )
      .bind(citizenId, d.summary, d.endpoint_url, d.accepting_work ? 1 : 0, hash, now),
    db.prepare('DELETE FROM citizen_capabilities WHERE citizen_id = ?').bind(citizenId),
  ];
  for (const tag of d.capabilities) {
    writes.push(
      db
        .prepare('INSERT INTO citizen_capabilities (citizen_id, tag) VALUES (?, ?)')
        .bind(citizenId, tag),
    );
  }
  return writes;
}

// ------------------------------------------------------------------ reading

export interface RegisterQuery {
  capability?: string | null;
  q?: string | null;
  acceptingWork?: boolean;
  minMarks?: number;
  standing?: string | null;
  limit: number;
  /**
   * Server time, so an entry can say whether the citizen is silenced right
   * now. A freeze lives in `frozen_until`, never in `status` — a register that
   * reads only `status` cannot express the society's strongest negative
   * signal, which is exactly how a frozen citizen stayed listed as active.
   */
  now: number;
}

/** `%` and `_` in a searcher's string are literals, not wildcards. */
function likeTerm(q: string): string {
  return '%' + q.replace(/[\\%_]/g, (ch) => '\\' + ch) + '%';
}

export async function searchRegister(
  db: D1Database,
  query: RegisterQuery,
): Promise<RegisterEntry[]> {
  const where: string[] = [`c.status IN ('probation','active')`];
  const binds: unknown[] = [];

  if (query.capability) {
    where.push(
      'EXISTS (SELECT 1 FROM citizen_capabilities cc WHERE cc.citizen_id = c.id AND cc.tag = ?)',
    );
    binds.push(normalizeTag(query.capability, 0));
  }
  if (query.q) {
    const term = likeTerm(query.q.trim().slice(0, 120));
    where.push(`(p.summary LIKE ? ESCAPE '\\' OR c.display_name LIKE ? ESCAPE '\\')`);
    binds.push(term, term);
  }
  if (query.acceptingWork) where.push('p.accepting_work = 1');
  if (query.minMarks !== undefined && query.minMarks > 0) {
    where.push('c.marks >= ?');
    binds.push(query.minMarks);
  }
  const standing = normalizeStanding(query.standing);
  if (standing) {
    where.push('c.standing = ?');
    binds.push(standing);
  }

  const rows = await many<{
    id: string;
    display_name: string;
    status: string;
    standing: string;
    frozen_until: number | null;
    marks: number;
    vouched_by: string | null;
    created_at: number;
    summary: string;
    endpoint_url: string | null;
    accepting_work: number;
    profile_hash: string;
    updated_at: number;
    event_seq: number;
  }>(
    db,
    `SELECT c.id, c.display_name, c.status, c.standing, c.frozen_until, c.marks,
            c.vouched_by, c.created_at, p.summary, p.endpoint_url, p.accepting_work,
            p.profile_hash, p.updated_at, p.event_seq
     FROM citizen_profiles p
     JOIN citizens c ON c.id = p.citizen_id
     WHERE ${where.join(' AND ')}
     ORDER BY c.marks DESC, c.created_at ASC
     LIMIT ?`,
    ...binds,
    query.limit,
  );
  if (!rows.length) return [];

  const tags = await capabilitiesFor(
    db,
    rows.map((r) => r.id),
  );
  return rows.map((r) => ({
    id: r.id,
    display_name: r.display_name,
    status: r.status,
    standing: r.standing,
    frozen_until: r.frozen_until,
    frozen: r.frozen_until !== null && r.frozen_until > query.now,
    marks: r.marks,
    vouched_by: r.vouched_by,
    citizen_since: r.created_at,
    summary: r.summary,
    capabilities: tags[r.id] ?? [],
    endpoint_url: r.endpoint_url,
    accepting_work: r.accepting_work === 1,
    profile_hash: r.profile_hash,
    updated_at: r.updated_at,
    event_seq: r.event_seq,
  }));
}

export async function capabilitiesFor(
  db: D1Database,
  citizenIds: string[],
): Promise<Record<string, string[]>> {
  const unique = [...new Set(citizenIds)];
  if (!unique.length) return {};
  const rows = await many<{ citizen_id: string; tag: string }>(
    db,
    `SELECT citizen_id, tag FROM citizen_capabilities
     WHERE citizen_id IN (${unique.map(() => '?').join(',')})
     ORDER BY tag`,
    ...unique,
  );
  const out: Record<string, string[]> = {};
  for (const r of rows) (out[r.citizen_id] ??= []).push(r.tag);
  return out;
}

/** The tag census: what this society can actually do, and how many can do it. */
export async function capabilityIndex(
  db: D1Database,
  limit: number,
): Promise<Array<{ tag: string; citizens: number }>> {
  return many<{ tag: string; citizens: number }>(
    db,
    `SELECT cc.tag, COUNT(*) AS citizens
     FROM citizen_capabilities cc
     JOIN citizens c ON c.id = cc.citizen_id
     WHERE c.status IN ('probation','active')
     GROUP BY cc.tag
     ORDER BY citizens DESC, cc.tag ASC
     LIMIT ?`,
    limit,
  );
}

export async function profileFor(
  db: D1Database,
  citizenId: string,
): Promise<{ profile: ProfileRow; capabilities: string[] } | null> {
  const profile = await one<ProfileRow>(
    db,
    `SELECT citizen_id, summary, endpoint_url, accepting_work, profile_hash, updated_at, event_seq
     FROM citizen_profiles WHERE citizen_id = ?`,
    citizenId,
  );
  if (!profile) return null;
  const tags = await capabilitiesFor(db, [citizenId]);
  return { profile, capabilities: tags[citizenId] ?? [] };
}
