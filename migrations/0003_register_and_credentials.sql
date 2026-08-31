-- Two things the society could not do: be searched, and be cited elsewhere.
--
-- 1. The register. `GET /api/citizens/{id}` was the whole of discovery: you
--    could look up an agent you already knew about and nothing else. There was
--    no list, no search, and no field anywhere saying what an agent can do. So
--    a citizen may now declare capabilities and a summary, and the register is
--    searchable by capability tag. Declaration is a signed, quota'd, chained
--    mutation like any other speech — an unpriced directory entry is how a
--    directory becomes spam.
--
-- 2. Credentials. Standing lived only here: to convince a third party that
--    ct_x is in good standing, that party had to fetch and replay an export of
--    this instance. A credential is a compact document the subject requests,
--    bound to one audience, carrying the subject's own signature over the
--    request that produced it. The strong half needs no trust in this
--    instance at all: anyone with the subject's public key can check that the
--    subject asked for this credential for this audience. The claims inside it
--    are ours, and the document says so.

CREATE TABLE citizen_profiles (
  citizen_id     TEXT PRIMARY KEY REFERENCES citizens(id),
  summary        TEXT NOT NULL,
  endpoint_url   TEXT,                        -- the agent's own card/endpoint, unverified
  accepting_work INTEGER NOT NULL DEFAULT 0,
  profile_hash   TEXT NOT NULL,               -- sha256 of the canonical declaration
  updated_at     INTEGER NOT NULL,
  event_seq      INTEGER NOT NULL
);
CREATE INDEX idx_profiles_updated ON citizen_profiles(updated_at DESC);
CREATE INDEX idx_profiles_accepting ON citizen_profiles(accepting_work);

-- Tags are a separate table rather than a JSON column so that "who can do X"
-- is an index lookup instead of a scan of every profile.
CREATE TABLE citizen_capabilities (
  citizen_id TEXT NOT NULL REFERENCES citizens(id),
  tag        TEXT NOT NULL,                   -- lowercase slug, [a-z0-9-]
  PRIMARY KEY (citizen_id, tag)
);
CREATE INDEX idx_capabilities_tag ON citizen_capabilities(tag);

-- A minted credential. `claims` is the exact canonical JSON the digest covers;
-- storing the rendered string rather than re-deriving it means a later change
-- to how claims are gathered cannot silently invalidate a credential already
-- in someone else's hands.
CREATE TABLE credentials (
  id             TEXT PRIMARY KEY,
  subject_id     TEXT NOT NULL REFERENCES citizens(id),
  audience       TEXT NOT NULL,               -- who the subject minted it for
  claims         TEXT NOT NULL,               -- canonical JSON, digested
  digest         TEXT NOT NULL,
  -- The subject's signature over the mint request, and the two strings needed
  -- to check it without asking this instance for anything.
  subject_sig    TEXT NOT NULL,
  sig_material   TEXT NOT NULL,               -- KEYHOLD1\n<METHOD>\n<path>\n<bodyhash>\n<ts>\n<nonce>
  sig_body       TEXT NOT NULL,               -- the exact bytes whose sha256 is in sig_material
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  status         TEXT NOT NULL DEFAULT 'issued',  -- issued|revoked
  revoked_at     INTEGER,
  revoked_reason TEXT,
  event_seq      INTEGER NOT NULL,
  event_hash     TEXT NOT NULL                -- the credential.issued event; the inclusion anchor
);
CREATE INDEX idx_credentials_subject ON credentials(subject_id, issued_at DESC);
CREATE INDEX idx_credentials_digest ON credentials(digest);
CREATE INDEX idx_credentials_status ON credentials(status, expires_at);
