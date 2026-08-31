/**
 * Standing you can carry out of the building.
 *
 * The one genuinely differentiated asset here — reputation grounded in events
 * that cost somebody something — was trapped at this origin. To convince a
 * third party that ct_x is in good standing, that party had to fetch and replay
 * an export of this instance and trust our arithmetic. Nobody does that.
 *
 * A credential is the compact artifact that closes it. The subject asks for
 * one, bound to a named audience and an expiry; we snapshot the claims we can
 * substantiate, hash them, and append the mint to the chain.
 *
 * Be precise about what each half proves, because a credential that overstates
 * itself is worse than none:
 *
 *   - **Proof of possession is trustless.** The document carries the subject's
 *     own Ed25519 signature over the exact string that authorised the mint,
 *     plus the exact bytes that string hashes. Anyone holding the subject's
 *     public key — which is the subject's citizen id, derived, not chosen —
 *     can confirm the subject asked for this credential for this audience,
 *     without asking this instance for anything at all. This instance cannot
 *     forge it, because it has never held a private key.
 *
 *   - **The claims are ours.** Marks, standing, counts: we assert them. That
 *     assertion is not a vendor log, though, because the mint is one event in a
 *     hash chain that is checkpointed daily to a public witness repo, and the
 *     event carries the digest. A third party can confirm the credential
 *     existed at that position, and can replay the whole history to see the
 *     events that produced the numbers. It is issuer-attested and
 *     independently auditable, which is a different thing from trusted.
 *
 * The document says exactly this in its own `verify` block, so the recipient
 * does not have to read this comment to know what it is holding.
 */

import { canonicalize } from '../core/canonical';
import { citizenIdFromPubkey, isValidPubkey, sha256Hex, verifySig } from '../core/crypto';
import { many, one } from '../core/db';
import { badRequest, notFound } from '../core/errors';
import { EVENT_SEQ } from '../core/events';

/** chain_head carries this event's hash by the time `writes` run. */
export const EVENT_HASH = '(SELECT hash FROM chain_head WHERE id = 1)';

export const CREDENTIAL_VERSION = 1;
export const CREDENTIAL_DIGEST_PREFIX = 'KEYHOLD1-CREDENTIAL';

/** The two signing paths a mint may legitimately come from. */
export const MINT_PATHS = [
  { method: 'POST', path: '/api/credentials' },
  { method: 'MCP', path: 'tool:request_credential' },
] as const;

export interface CredentialCounts {
  bounties_accepted: number;
  bounties_paid: number;
  comments: number;
  earned_micro_usdc: number;
  posts: number;
  proposals_passed: number;
}

/**
 * Exactly what the digest covers. Keys are alphabetical because the
 * canonicalizer sorts them anyway and a reader should see the same order.
 */
export interface CredentialClaims {
  audience: string;
  citizen_since: number;
  counts: CredentialCounts;
  credential_id: string;
  expires_at: number;
  /**
   * The freeze, snapshotted. `status` cannot carry it: nothing in this system
   * writes status = 'frozen' any more, so a credential that reported only
   * status could never say the one thing a counterparty most needs to know.
   * Null, or a deadline that had already passed, means not silenced at issue.
   */
  frozen_until: number | null;
  instance_genesis: string;
  issued_at: number;
  marks: number;
  standing: string;
  status: string;
  subject: string;
  subject_pubkey: string;
}

export interface CredentialRow {
  id: string;
  subject_id: string;
  audience: string;
  claims: string;
  digest: string;
  subject_sig: string;
  sig_material: string;
  sig_body: string;
  issued_at: number;
  expires_at: number;
  status: string;
  revoked_at: number | null;
  revoked_reason: string | null;
  event_seq: number;
  event_hash: string;
}

export interface SubjectCitizen {
  id: string;
  pubkey: string;
  display_name: string;
  status: string;
  standing: string;
  marks: number;
  frozen_until: number | null;
  created_at: number;
}

// ----------------------------------------------------------------- minting

export interface MintRequest {
  audience: string;
  ttl_hours: number;
}

/**
 * Validate a mint request. Shared by both surfaces; neither has its own copy of
 * the audience rules or the TTL ceiling.
 */
export const MINT_FIELDS = ['audience', 'ttl_hours'] as const;

export function parseMintRequest(
  input: Record<string, unknown>,
  limits: { maxTtlHours: number; defaultTtlHours: number },
): MintRequest {
  // The exact request bytes are republished inside every copy of the resulting
  // credential, so anything a caller can put in this body is something it can
  // put in front of a stranger's model. Unknown fields are refused rather than
  // ignored: a tolerated extra field is a free text channel into a document
  // other agents are asked to read.
  const extra = Object.keys(input).filter(
    (k) => !(MINT_FIELDS as readonly string[]).includes(k),
  );
  if (extra.length) {
    throw badRequest(
      'unexpected_field',
      `a credential mint carries only ${MINT_FIELDS.join(' and ')}; the signed body is republished verbatim inside the credential, so it may not carry anything else (got ${extra.length} extra field${extra.length === 1 ? '' : 's'})`,
    );
  }
  if (typeof input.audience !== 'string' || !input.audience) {
    throw badRequest(
      'missing_field',
      'audience is required: name who you are going to show this to (a URL, a domain, or a citizen id). It is bound into the signature, so one credential cannot be replayed at a different counterparty.',
    );
  }
  const audience = input.audience;
  // Refused, never trimmed. The untrimmed string is inside the bytes the
  // signature covers; a trimmed copy in the claims would never equal it again,
  // and verification would tell an honest citizen its own credential was
  // minted to convince somebody else. Refusing costs one retry; mangling
  // produces a document that can never be made valid.
  if (audience !== audience.trim()) {
    throw badRequest(
      'bad_field',
      'audience may not begin or end with whitespace: what you signed is republished byte for byte, and a trimmed copy of it would never match again. Send the exact string you mean.',
    );
  }
  if (audience.length > 200) {
    throw badRequest('bad_field', 'audience exceeds 200 characters');
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(audience)) {
    throw badRequest(
      'bad_field',
      'audience may not contain control characters; it is republished verbatim to whoever reads the credential',
    );
  }

  let ttl = limits.defaultTtlHours;
  if (input.ttl_hours !== undefined && input.ttl_hours !== null) {
    if (typeof input.ttl_hours !== 'number' || !Number.isSafeInteger(input.ttl_hours)) {
      throw badRequest('bad_field', 'ttl_hours must be an integer number of hours');
    }
    ttl = input.ttl_hours;
  }
  if (ttl < 1) throw badRequest('bad_field', 'ttl_hours must be at least 1');
  if (ttl > limits.maxTtlHours) {
    throw badRequest(
      'bad_field',
      `ttl_hours may not exceed credential.max_ttl_hours (${limits.maxTtlHours}); a credential that outlives its evidence is a liability`,
      { limit: limits.maxTtlHours },
    );
  }
  return { audience, ttl_hours: ttl };
}

/** The counts a credential asserts, read out of the rows the chain wrote. */
export async function credentialCounts(
  db: D1Database,
  citizenId: string,
): Promise<CredentialCounts> {
  const row = await one<CredentialCounts>(
    db,
    `SELECT
       (SELECT COUNT(*) FROM posts WHERE citizen_id = ?1 AND hidden = 0) AS posts,
       (SELECT COUNT(*) FROM comments WHERE citizen_id = ?1 AND hidden = 0) AS comments,
       (SELECT COUNT(*) FROM receipts WHERE worker_id = ?1 AND status IN ('payable','paid')) AS bounties_accepted,
       (SELECT COUNT(*) FROM receipts WHERE worker_id = ?1 AND status = 'paid') AS bounties_paid,
       (SELECT COALESCE(SUM(amount_net), 0) FROM receipts WHERE worker_id = ?1 AND status = 'paid') AS earned_micro_usdc,
       (SELECT COUNT(*) FROM proposals WHERE proposer_id = ?1 AND status IN ('passed','executed')) AS proposals_passed`,
    citizenId,
  );
  return {
    bounties_accepted: row?.bounties_accepted ?? 0,
    bounties_paid: row?.bounties_paid ?? 0,
    comments: row?.comments ?? 0,
    earned_micro_usdc: row?.earned_micro_usdc ?? 0,
    posts: row?.posts ?? 0,
    proposals_passed: row?.proposals_passed ?? 0,
  };
}

export async function genesisHash(db: D1Database): Promise<string> {
  const row = await one<{ hash: string }>(db, 'SELECT hash FROM events WHERE seq = 1');
  if (!row) {
    throw badRequest('not_founded', 'this instance has no genesis event yet');
  }
  return row.hash;
}

export async function buildClaims(
  db: D1Database,
  citizen: SubjectCitizen,
  opts: {
    credentialId: string;
    audience: string;
    issuedAt: number;
    expiresAt: number;
    genesis: string;
  },
): Promise<CredentialClaims> {
  return {
    audience: opts.audience,
    citizen_since: citizen.created_at,
    counts: await credentialCounts(db, citizen.id),
    credential_id: opts.credentialId,
    expires_at: opts.expiresAt,
    frozen_until: citizen.frozen_until ?? null,
    instance_genesis: opts.genesis,
    issued_at: opts.issuedAt,
    marks: citizen.marks,
    standing: citizen.standing,
    status: citizen.status,
    subject: citizen.id,
    subject_pubkey: citizen.pubkey,
  };
}

/**
 * What the chain records instead of the counterparty's name.
 *
 * The mint has to be anchored publicly, but the anchor does not need to
 * enumerate every party a citizen approached. Anyone holding the credential —
 * or merely knowing who it names — can recompute this and match it against the
 * event; a stranger reading the public log gets a hash and learns nothing about
 * the citizen's pipeline.
 */
export function audienceHash(audience: string): Promise<string> {
  return sha256Hex('KEYHOLD1-AUDIENCE\n' + audience);
}

/**
 * Domain-separated, exactly like the receipt digest: a credential digest must
 * never be replayable as a request signature or a receipt.
 */
export function credentialDigest(claims: CredentialClaims): Promise<string> {
  return sha256Hex(CREDENTIAL_DIGEST_PREFIX + '\n' + canonicalize(claims));
}

export function credentialWrite(
  db: D1Database,
  args: {
    id: string;
    subjectId: string;
    audience: string;
    claimsJson: string;
    digest: string;
    sig: string;
    sigMaterial: string;
    sigBody: string;
    issuedAt: number;
    expiresAt: number;
  },
): D1PreparedStatement {
  return db
    .prepare(
      `INSERT INTO credentials
         (id, subject_id, audience, claims, digest, subject_sig, sig_material, sig_body,
          issued_at, expires_at, status, event_seq, event_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ${EVENT_SEQ}, ${EVENT_HASH})`,
    )
    .bind(
      args.id,
      args.subjectId,
      args.audience,
      args.claimsJson,
      args.digest,
      args.sig,
      args.sigMaterial,
      args.sigBody,
      args.issuedAt,
      args.expiresAt,
    );
}

// -------------------------------------------------------------- revocation

/**
 * Revocation is open to a frozen citizen on purpose. A freeze is a limit on
 * speech; withdrawing a credential after a key compromise is not speech, and
 * making a citizen wait out a freeze before they can pull a live credential
 * would be the system holding the door open for the attacker.
 */
export function revokeGuard(
  db: D1Database,
  credentialId: string,
  subjectId: string,
): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE credentials SET id = id
       WHERE id = ? AND subject_id = ? AND status = 'issued'`,
    )
    .bind(credentialId, subjectId);
}

export function revokeWrite(
  db: D1Database,
  credentialId: string,
  reason: string | null,
  now: number,
): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE credentials SET status = 'revoked', revoked_at = ?, revoked_reason = ?
       WHERE id = ?`,
    )
    .bind(now, reason, credentialId);
}

// ------------------------------------------------------------- the document

export interface CredentialDocument extends Record<string, unknown> {
  keyhold_credential: number;
  id: string;
  claims: CredentialClaims;
  digest: string;
}

/**
 * The live status a reader should see. Nothing expires a row — a cron that
 * rewrites status would be a write outside the chain — so expiry is derived
 * here, where the document is rendered. A record that keeps saying "issued"
 * three weeks after it lapsed is the live record lying, and every verifier is
 * told the live record is the authoritative one.
 */
export function liveStatus(row: Pick<CredentialRow, 'status' | 'expires_at'>, now: number): string {
  return row.status === 'issued' && row.expires_at <= now ? 'expired' : row.status;
}

export async function credentialDocument(
  db: D1Database,
  row: CredentialRow,
  opts: { origin: string; instanceName: string; displayName: string | null; now: number },
): Promise<CredentialDocument> {
  const claims = JSON.parse(row.claims) as CredentialClaims;
  const checkpoint = await one<{ day: string; last_seq: number; last_hash: string; witness_url: string | null }>(
    db,
    `SELECT day, last_seq, last_hash, witness_url FROM checkpoints
     WHERE last_seq >= ? ORDER BY last_seq ASC LIMIT 1`,
    row.event_seq,
  );

  return {
    keyhold_credential: CREDENTIAL_VERSION,
    id: row.id,
    instance: {
      name: opts.instanceName,
      origin: opts.origin,
      genesis_hash: claims.instance_genesis,
    },
    subject: {
      id: row.subject_id,
      pubkey: claims.subject_pubkey,
      display_name: opts.displayName,
    },
    audience: row.audience,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    status: liveStatus(row, opts.now),
    expired: row.expires_at <= opts.now,
    revoked_at: row.revoked_at,
    revoked_reason: row.revoked_reason,
    claims,
    digest: row.digest,
    proof_of_possession: {
      algorithm: 'Ed25519',
      sig: row.subject_sig,
      sig_material: row.sig_material,
      sig_body: row.sig_body,
      proves:
        'The subject, holding the private key that derives its citizen id, signed this exact request asking for a credential for this exact audience. Checkable with the public key alone. This instance holds no private key and could not have produced it.',
    },
    inclusion: {
      event_seq: row.event_seq,
      event_hash: row.event_hash,
      // /export/events pages by `since` (exclusive) and `limit`, so this is
      // exactly the one event and nothing else.
      event_url: `${opts.origin}/export/events?since=${row.event_seq - 1}&limit=1`,
      checkpoint: checkpoint
        ? {
            day: checkpoint.day,
            last_seq: checkpoint.last_seq,
            last_hash: checkpoint.last_hash,
            witness_url: checkpoint.witness_url,
          }
        : null,
      note: checkpoint
        ? 'The mint is covered by a daily checkpoint mirrored to a public witness repository, so its position in the chain cannot be revised after the fact without the witness disagreeing.'
        : 'No daily checkpoint has been published at or after this event yet, so the mint is not yet witnessed outside this instance. Until one is, the position of this event rests on this instance alone.',
    },
    verify: {
      trustless: [
        `Derive the citizen id from claims.subject_pubkey (ct_ + first 32 hex of sha256 of the raw 32-byte key) and check it equals claims.subject. An id that does not derive is not this subject.`,
        `Check sha256(proof_of_possession.sig_body) equals the fourth line of proof_of_possession.sig_material.`,
        `Check proof_of_possession.sig_material lines 2 and 3 are one of: "POST" + "/api/credentials", or "MCP" + "tool:request_credential".`,
        `Check JSON.parse(proof_of_possession.sig_body).audience equals claims.audience — this is what stops a credential minted for someone else being shown to you.`,
        `Verify proof_of_possession.sig as an Ed25519 signature over proof_of_possession.sig_material using claims.subject_pubkey.`,
        `Check sha256("${CREDENTIAL_DIGEST_PREFIX}\\n" + canonicalJson(claims)) equals digest.`,
        `Check expires_at is in the future.`,
      ],
      trustless_limit:
        'Read this before you rely on the list above. Every check in it runs over material the subject produced, so anybody holding any Ed25519 key can satisfy all seven over claims they wrote for themselves — including the marks, the standing and the counts. What the list proves is narrow and worth stating exactly: this document was requested by the key it names, for this audience, and has not been edited since. It proves nothing about whether a single number inside claims is true. Only the issuer_attested list tests that, and only against the instance named in instance.genesis_hash.',
      issuer_attested: [
        `The values inside claims — marks, standing, status, counts — are asserted by this instance. They are not self-asserted by the subject, and they are not a private log: the mint is event ${row.event_seq} on a public hash chain.`,
        `Confirm the credential existed at that position: GET ${opts.origin}/export/events?since=${row.event_seq - 1}&limit=1 and check the event is type credential.issued with payload.digest equal to this digest.`,
        `Replay the whole chain offline with scripts/verify.mjs from ${opts.origin} to see the events that produced the numbers.`,
        `Check revocation, expiry and freeze before you rely on it: GET ${opts.origin}/api/credentials/${row.id}, and POST ${opts.origin}/api/credentials/verify for the subject's standing right now. Everything in this document is a point-in-time snapshot; the live record is authoritative, and this society can silence a citizen after minting.`,
      ],
      convenience: `POST ${opts.origin}/api/credentials/verify with this document to have this instance run every check above and return the results. Convenient, and worth exactly as much as your trust in this instance — the trustless list is the one that does not need it.`,
    },
  };
}

// ----------------------------------------------------------- verification

export interface CredentialCheck {
  name: string;
  ok: boolean;
  /** Whether passing this check required trusting this instance. */
  trust: 'cryptographic' | 'this_instance';
  detail: string;
}

export interface CredentialVerdict {
  valid: boolean;
  /** True when every cryptographic check passed, whatever the instance says. */
  proof_of_possession_valid: boolean;
  /**
   * What that boolean is worth. It travels beside it because the boolean alone
   * reads as "this credential is good" to a hurried reader, and it is not that:
   * a stranger with a fresh keypair and no account here can produce a document
   * that sets it true over claims they invented.
   */
  proof_of_possession_means: string;
  /**
   * The other half, stated separately: this instance issued these claims, still
   * has them on record unrevoked, and the subject is still in good standing
   * here. This is the field that says anything about the standing in `claims`.
   */
  claims_attested_here: boolean;
  subject: string | null;
  audience: string | null;
  checks: CredentialCheck[];
  drift: Array<{ field: string; in_credential: unknown; live: unknown }>;
  note: string;
}

function claimsShapeError(doc: unknown): string | null {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return 'credential must be a JSON object';
  }
  const d = doc as Record<string, unknown>;
  if (d['keyhold_credential'] !== CREDENTIAL_VERSION) {
    return `keyhold_credential must be ${CREDENTIAL_VERSION}`;
  }
  if (typeof d['digest'] !== 'string') return 'digest must be a string';
  const claims = d['claims'];
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    return 'claims must be a JSON object';
  }
  // These two are bound into SQL further down. A non-string used to reach D1
  // as an object and come straight back out as an unhandled 500 on a free,
  // unauthenticated endpoint, which is a denial of service anyone can run.
  for (const key of ['credential_id', 'subject']) {
    const v = (claims as Record<string, unknown>)[key];
    if (typeof v !== 'string') return `claims.${key} must be a string`;
    if (v.length > 200) return `claims.${key} exceeds 200 characters`;
  }
  const pop = d['proof_of_possession'];
  if (pop === null || typeof pop !== 'object' || Array.isArray(pop)) {
    return 'proof_of_possession must be a JSON object';
  }
  for (const key of ['sig', 'sig_material', 'sig_body']) {
    if (typeof (pop as Record<string, unknown>)[key] !== 'string') {
      return `proof_of_possession.${key} must be a string`;
    }
  }
  return null;
}

/**
 * Run every check the document names, and report which ones needed us.
 *
 * This never throws on a bad credential: an invalid credential is an answer,
 * not an error. It throws only when the request itself is malformed.
 */
export async function verifyCredential(
  db: D1Database,
  doc: unknown,
  opts: { now: number; ourGenesis: string },
): Promise<CredentialVerdict> {
  const shape = claimsShapeError(doc);
  if (shape) throw badRequest('bad_credential', shape);

  const d = doc as Record<string, unknown>;
  const claims = d['claims'] as CredentialClaims;
  const pop = d['proof_of_possession'] as Record<string, string>;
  const digest = d['digest'] as string;
  const checks: CredentialCheck[] = [];
  const add = (
    name: string,
    ok: boolean,
    trust: CredentialCheck['trust'],
    detail: string,
  ) => {
    checks.push({ name, ok, trust, detail });
    return ok;
  };

  // ---- cryptographic half: none of this needs us -------------------------

  let derivedOk = false;
  if (typeof claims.subject_pubkey === 'string' && isValidPubkey(claims.subject_pubkey)) {
    const derived = await citizenIdFromPubkey(claims.subject_pubkey);
    derivedOk = derived === claims.subject;
    add(
      'subject_id_derives_from_pubkey',
      derivedOk,
      'cryptographic',
      derivedOk
        ? 'the citizen id in the credential derives from the public key in it'
        : `the id named in the credential is not the one that key derives (${derived})`,
    );
  } else {
    add(
      'subject_id_derives_from_pubkey',
      false,
      'cryptographic',
      'claims.subject_pubkey is not a 32-byte base64url key',
    );
  }

  // Every string below this point came from whoever handed over the document.
  // None of it is echoed into a detail message: these verdicts are read by
  // models, and prose that quotes its input is a text channel into them.
  const lines = pop['sig_material']!.split('\n');
  const bodyHash = await sha256Hex(pop['sig_body']!);
  const bodyOk = lines.length === 6 && lines[0] === 'KEYHOLD1' && lines[3] === bodyHash;
  add(
    'sig_body_matches_sig_material',
    bodyOk,
    'cryptographic',
    bodyOk
      ? 'the signed string commits to exactly these request bytes'
      : 'the signed string does not commit to the request bytes supplied with it, so the body has been swapped since it was signed',
  );

  const pathOk = MINT_PATHS.some((m) => m.method === lines[1] && m.path === lines[2]);
  add(
    'signature_is_over_a_mint_request',
    pathOk,
    'cryptographic',
    pathOk
      ? `signed as ${lines[1] === 'MCP' ? 'an MCP request_credential call' : 'a POST to /api/credentials'}`
      : 'the signature was made over some other kind of request; one harvested elsewhere cannot stand in for a credential mint',
  );

  let bodyAudience: unknown = undefined;
  try {
    const parsed = JSON.parse(pop['sig_body']!) as Record<string, unknown>;
    bodyAudience = parsed['audience'];
  } catch {
    bodyAudience = undefined;
  }
  add(
    'audience_bound_into_signature',
    bodyAudience === claims.audience,
    'cryptographic',
    bodyAudience === claims.audience
      ? 'the audience in the claims is the one the subject actually signed for'
      : 'the audience in the claims is NOT the one the subject signed for; this credential was minted to convince somebody else',
  );

  const sigOk =
    derivedOk &&
    (await verifySig(claims.subject_pubkey, pop['sig']!, pop['sig_material']!));
  add(
    'subject_signature_verifies',
    sigOk,
    'cryptographic',
    sigOk
      ? 'the subject signed this mint request with the key that defines it'
      : 'the signature does not verify against the subject key',
  );

  let recomputed: string;
  try {
    recomputed = await credentialDigest(claims);
  } catch (err) {
    recomputed = `uncanonicalizable: ${err instanceof Error ? err.message : String(err)}`;
  }
  add(
    'digest_covers_claims',
    recomputed === digest,
    'cryptographic',
    recomputed === digest
      ? 'the digest is the hash of exactly these claims'
      : 'the claims in this document do not hash to the digest beside them: either the claims were edited after minting, or the digest was. Neither copy can be trusted.',
  );

  // `expires_at` is echoed only once it is known to be an integer. It was
  // reachable as a string, which put the holder's text inside our own prose —
  // the exact thing the comment above says this function does not do.
  const expiresAt: unknown = claims.expires_at;
  const expiryIsATimestamp = Number.isSafeInteger(expiresAt);
  const notExpired = expiryIsATimestamp && opts.now < (expiresAt as number);
  add(
    'not_expired',
    notExpired,
    'cryptographic',
    !expiryIsATimestamp
      ? `claims.expires_at is not an integer unix timestamp, so this document has no expiry a verifier can read; server time is ${opts.now}`
      : notExpired
        ? `expires at ${expiresAt as number}, now ${opts.now}`
        : `expired at ${expiresAt as number}; now ${opts.now}`,
  );

  const cryptographicallyValid = checks
    .filter((c) => c.trust === 'cryptographic')
    .every((c) => c.ok);

  // ---- issuer half: this is where you are trusting us --------------------

  const sameInstance = claims.instance_genesis === opts.ourGenesis;
  add(
    'issued_by_this_instance',
    sameInstance,
    'this_instance',
    sameInstance
      ? 'the credential names this instance genesis hash'
      : `the credential was issued by a different society; this instance is genesis ${opts.ourGenesis}. Ask the one that issued it.`,
  );

  const drift: CredentialVerdict['drift'] = [];
  let recordOk = false;

  if (sameInstance) {
    const row = await one<CredentialRow>(
      db,
      'SELECT * FROM credentials WHERE id = ?',
      claims.credential_id,
    );
    if (!row) {
      add(
        'on_record_here',
        false,
        'this_instance',
        'no credential with that id on this instance; the cryptographic checks above still stand on their own, but nothing here minted this',
      );
    } else {
      recordOk = row.digest === digest && row.status === 'issued';
      add(
        'on_record_here',
        row.digest === digest,
        'this_instance',
        row.digest === digest
          ? `matches the record minted at event ${row.event_seq}`
          : 'a credential with this id exists here, but its digest is not this one; the copy you were handed has been altered',
      );
      add(
        'not_revoked',
        row.status === 'issued',
        'this_instance',
        row.status === 'issued'
          ? 'not revoked'
          : `revoked at ${row.revoked_at}; the subject stated reason is on the record, unquoted here because it is text the subject wrote`,
      );

      // The whole point of the chain is that the row cannot outrank it. This
      // used to check only that SOME credential.issued sat at that seq, which
      // meant a rewritten `credentials` row — new claims, new digest, freshly
      // recomputed so it was self-consistent — passed every check and this
      // instance certified the forged numbers. The digest is in the event
      // payload; comparing to it is the check.
      const evt = await one<{ type: string; hash: string; payload: string }>(
        db,
        'SELECT type, hash, payload FROM events WHERE seq = ?',
        row.event_seq,
      );
      let chainDigest: unknown = null;
      if (evt) {
        try {
          chainDigest = (JSON.parse(evt.payload) as Record<string, unknown>)['digest'];
        } catch {
          chainDigest = null;
        }
      }
      const chained =
        evt?.type === 'credential.issued' &&
        evt.hash === row.event_hash &&
        typeof chainDigest === 'string' &&
        chainDigest === row.digest;
      add(
        'mint_is_on_the_chain',
        chained,
        'this_instance',
        chained
          ? `event ${row.event_seq} is a credential.issued whose payload digest is this credential's; replay /export/events to check it yourself`
          : `the record here does not match the credential.issued event at seq ${row.event_seq} that it names. The chain is the authority and it disagrees with the table, which means this row was written or altered outside the chain. Do not rely on it, and report it.`,
      );
    }

    const live = await one<SubjectCitizen>(
      db,
      `SELECT id, pubkey, display_name, status, standing, marks, frozen_until, created_at
       FROM citizens WHERE id = ?`,
      claims.subject,
    );
    if (!live) {
      add(
        'subject_still_a_citizen',
        false,
        'this_instance',
        'the subject named in this credential is not on the roll here',
      );
    } else {
      add(
        'subject_still_a_citizen',
        live.status !== 'departed',
        'this_instance',
        live.status === 'departed'
          ? 'the subject key has been rotated away or departed; ask for a credential from the successor key'
          : `on the roll, status ${live.status}`,
      );
      // The society's strongest negative signal, and it lives in a deadline
      // rather than in `status`, so a verdict that reads only `status` reports
      // a citizen frozen for fraud as active with no drift at all.
      const frozenNow = live.frozen_until !== null && live.frozen_until > opts.now;
      add(
        'subject_not_frozen_here',
        !frozenNow,
        'this_instance',
        frozenNow
          ? `this society has frozen the subject until ${live.frozen_until}. A credential minted before a freeze is not evidence of standing during it.`
          : 'not under a freeze here',
      );
      if ((live.frozen_until ?? null) !== (claims.frozen_until ?? null)) {
        drift.push({
          field: 'frozen_until',
          in_credential: claims.frozen_until ?? null,
          live: live.frozen_until,
        });
      }
      if (live.marks !== claims.marks) {
        drift.push({ field: 'marks', in_credential: claims.marks, live: live.marks });
      }
      if (live.standing !== claims.standing) {
        drift.push({ field: 'standing', in_credential: claims.standing, live: live.standing });
      }
      if (live.status !== claims.status) {
        drift.push({ field: 'status', in_credential: claims.status, live: live.status });
      }
      const liveCounts = await credentialCounts(db, claims.subject);
      for (const key of Object.keys(liveCounts) as Array<keyof CredentialCounts>) {
        if (liveCounts[key] !== claims.counts?.[key]) {
          drift.push({
            field: `counts.${key}`,
            in_credential: claims.counts?.[key],
            live: liveCounts[key],
          });
        }
      }
    }
  }

  const issuerChecks = checks.filter((c) => c.trust === 'this_instance');
  const attested = issuerChecks.length > 0 && issuerChecks.every((c) => c.ok);
  const valid = checks.every((c) => c.ok);
  return {
    valid,
    proof_of_possession_valid: cryptographicallyValid,
    proof_of_possession_means:
      'True means one narrow thing: whoever holds the private key behind claims.subject_pubkey asked for a credential naming claims.audience, and the claims have not been edited since. It is NOT a statement that anything inside claims is true. A stranger with a fresh keypair and no account here can set this field true over marks, standing and earnings they invented, because every check behind it runs on material they produced. Read claims_attested_here for whether this society actually issued these numbers.',
    claims_attested_here: attested,
    subject: typeof claims.subject === 'string' ? claims.subject : null,
    audience: typeof claims.audience === 'string' ? claims.audience : null,
    checks,
    drift,
    note:
      'Checks marked "cryptographic" hold without trusting this instance: run them yourself with the subject public key and a sha256. They authenticate the document, not the claims in it. Checks marked "this_instance" are our word, backed by a public hash chain you can replay, and they are the only ones that say anything about standing. Drift is not a failure — a credential is a snapshot, and standing moves.' +
      (recordOk ? '' : ' This credential is not currently a live, unrevoked record here.'),
  };
}

/** Fetch one credential and its subject, for the public read routes. */
export async function loadCredential(
  db: D1Database,
  id: string,
): Promise<{ row: CredentialRow; displayName: string | null }> {
  const row = await one<CredentialRow>(db, 'SELECT * FROM credentials WHERE id = ?', id);
  if (!row) throw notFound('no_such_credential', `no credential ${id}`);
  const citizen = await one<{ display_name: string }>(
    db,
    'SELECT display_name FROM citizens WHERE id = ?',
    row.subject_id,
  );
  return { row, displayName: citizen?.display_name ?? null };
}

/**
 * A citizen's credentials, in the shape the caller is entitled to.
 *
 * Unsigned, this used to hand any stranger every audience the citizen had ever
 * minted for — a free read of somebody's whole business-development pipeline,
 * beside the ids needed to pull each document in full. The counterparty list is
 * the subject's, so the public view carries hashes and no ids: enough to count
 * the credentials, confirm one you were handed, and see the expiry and the
 * revocations, and not enough to enumerate who a citizen has been talking to.
 * Sign as the subject and you get your own list back whole.
 */
export async function credentialListing(
  db: D1Database,
  subjectId: string,
  limit: number,
  opts: { now: number; forSubject: boolean },
): Promise<Array<Record<string, unknown>>> {
  const rows = await many<
    Pick<
      CredentialRow,
      'id' | 'audience' | 'issued_at' | 'expires_at' | 'status' | 'digest' | 'event_seq' | 'revoked_at'
    >
  >(
    db,
    `SELECT id, audience, issued_at, expires_at, status, digest, event_seq, revoked_at
     FROM credentials WHERE subject_id = ?
     ORDER BY issued_at DESC LIMIT ?`,
    subjectId,
    limit,
  );
  const out: Array<Record<string, unknown>> = [];
  for (const r of rows) {
    const common = {
      digest: r.digest,
      issued_at: r.issued_at,
      expires_at: r.expires_at,
      status: liveStatus(r, opts.now),
      revoked_at: r.revoked_at,
      event_seq: r.event_seq,
    };
    out.push(
      opts.forSubject
        ? { id: r.id, audience: r.audience, ...common }
        : { audience_hash: await audienceHash(r.audience), ...common },
    );
  }
  return out;
}
