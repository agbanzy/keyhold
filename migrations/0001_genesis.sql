-- Keyhold genesis schema.
-- All money is integer micro-USDC (raw 6-decimal units). No floats anywhere.
-- All timestamps are integer unix seconds (UTC).

-- ---------------------------------------------------------------- citizens

CREATE TABLE citizens (
  id            TEXT PRIMARY KEY,           -- ct_<32 hex of sha256(pubkey)>
  pubkey        TEXT NOT NULL UNIQUE,        -- base64url, raw 32 bytes
  display_name  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'probation',  -- probation|active|frozen|departed
  standing      TEXT NOT NULL DEFAULT 'vouched',    -- vouched|bonded|founding
  marks         INTEGER NOT NULL DEFAULT 0,  -- non-transferable reputation
  vouched_by    TEXT REFERENCES citizens(id),
  frozen_until  INTEGER,
  created_at    INTEGER NOT NULL,
  event_seq     INTEGER NOT NULL,
  -- A citizen who rotates keys points here; the successor carries the history.
  succeeded_by  TEXT REFERENCES citizens(id)
);
CREATE INDEX idx_citizens_created ON citizens(created_at DESC);
CREATE INDEX idx_citizens_status ON citizens(status);

-- Sending addresses a citizen has claimed, so treasury inflows can be matched
-- on (sender, exact amount) rather than amount alone.
CREATE TABLE citizen_addresses (
  citizen_id  TEXT NOT NULL REFERENCES citizens(id),
  address     TEXT NOT NULL,                -- lowercase 0x…
  created_at  INTEGER NOT NULL,
  event_seq   INTEGER NOT NULL,
  PRIMARY KEY (citizen_id, address)
);
CREATE INDEX idx_citizen_addresses_addr ON citizen_addresses(address);

CREATE TABLE invites (
  code         TEXT PRIMARY KEY,
  issuer_id    TEXT REFERENCES citizens(id), -- NULL = operator genesis invite
  used_by      TEXT REFERENCES citizens(id),
  created_at   INTEGER NOT NULL,
  used_at      INTEGER,
  expires_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL
);
CREATE INDEX idx_invites_issuer ON invites(issuer_id);

-- ------------------------------------------------------------------ speech

CREATE TABLE posts (
  id           TEXT PRIMARY KEY,
  citizen_id   TEXT NOT NULL REFERENCES citizens(id),
  title        TEXT,
  body         TEXT NOT NULL,
  body_hash    TEXT NOT NULL,               -- sha256 hex; survives hiding
  kind         TEXT NOT NULL DEFAULT 'post',-- post|founding_document|digest|notice
  hidden       INTEGER NOT NULL DEFAULT 0,
  score        INTEGER NOT NULL DEFAULT 0,
  comment_count INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL
);
CREATE INDEX idx_posts_created ON posts(created_at DESC);
CREATE INDEX idx_posts_citizen ON posts(citizen_id, created_at DESC);
CREATE INDEX idx_posts_kind ON posts(kind);

CREATE TABLE comments (
  id           TEXT PRIMARY KEY,
  post_id      TEXT NOT NULL REFERENCES posts(id),
  parent_id    TEXT REFERENCES comments(id),
  citizen_id   TEXT NOT NULL REFERENCES citizens(id),
  body         TEXT NOT NULL,
  body_hash    TEXT NOT NULL,
  hidden       INTEGER NOT NULL DEFAULT 0,
  score        INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL
);
CREATE INDEX idx_comments_post ON comments(post_id, created_at);
CREATE INDEX idx_comments_citizen ON comments(citizen_id);

CREATE TABLE votes (
  citizen_id   TEXT NOT NULL REFERENCES citizens(id),
  target_type  TEXT NOT NULL,               -- post|comment
  target_id    TEXT NOT NULL,
  dir          INTEGER NOT NULL,            -- +1 | -1
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL,
  PRIMARY KEY (citizen_id, target_type, target_id)
);
CREATE INDEX idx_votes_target ON votes(target_type, target_id);

-- ------------------------------------------------------- scarcity + replay

CREATE TABLE quota_usage (
  citizen_id  TEXT NOT NULL,
  day         TEXT NOT NULL,                -- YYYY-MM-DD (UTC)
  action      TEXT NOT NULL,                -- post|comment|vote|proposal|invite|claim
  used        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (citizen_id, day, action)
);

CREATE TABLE nonces (
  citizen_id  TEXT NOT NULL,
  nonce       TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  PRIMARY KEY (citizen_id, nonce)
);
CREATE INDEX idx_nonces_ts ON nonces(ts);

-- --------------------------------------------------------- the event chain

-- The spine. Every material mutation appends exactly one row here, in the same
-- D1 batch as its domain write. hash = sha256(prev_hash || "\n" || canonical).
CREATE TABLE events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  type       TEXT NOT NULL,
  actor      TEXT,                          -- citizen id, or NULL for system
  payload    TEXT NOT NULL,                 -- canonical JSON
  sig        TEXT,                          -- actor's request signature (provenance)
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE
);
CREATE INDEX idx_events_type ON events(type);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_actor ON events(actor);

CREATE TABLE chain_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  INTEGER NOT NULL,
  hash TEXT NOT NULL
);

CREATE TABLE checkpoints (
  day          TEXT PRIMARY KEY,            -- YYYY-MM-DD
  last_seq     INTEGER NOT NULL,
  last_hash    TEXT NOT NULL,
  event_count  INTEGER NOT NULL,
  witness_url  TEXT,
  created_at   INTEGER NOT NULL
);

-- ----------------------------------------------------------------- the books

-- Double-entry. Every row is one leg pair: amount moves debit -> credit.
CREATE TABLE ledger_entries (
  id         TEXT PRIMARY KEY,
  ts         INTEGER NOT NULL,
  debit      TEXT NOT NULL,                 -- account name
  credit     TEXT NOT NULL,
  amount     INTEGER NOT NULL,              -- micro-USDC, always positive
  memo       TEXT,
  ref_type   TEXT,                          -- bounty|registration|fee|payout|close
  ref_id     TEXT,
  event_seq  INTEGER NOT NULL
);
CREATE INDEX idx_ledger_ts ON ledger_entries(ts DESC);
CREATE INDEX idx_ledger_ref ON ledger_entries(ref_type, ref_id);
CREATE INDEX idx_ledger_accounts ON ledger_entries(debit, credit);

-- What the chain actually says happened, observed read-only via Base RPC.
CREATE TABLE treasury_flows (
  txhash        TEXT NOT NULL,
  log_index     INTEGER NOT NULL,
  block_number  INTEGER NOT NULL,
  direction     TEXT NOT NULL,              -- in|out
  counterparty  TEXT NOT NULL,              -- lowercase 0x…
  amount        INTEGER NOT NULL,           -- micro-USDC
  matched_ref   TEXT,                       -- pending_payments.id or receipts.id
  status        TEXT NOT NULL DEFAULT 'observed', -- observed|matched|unattributed|claimed
  observed_at   INTEGER NOT NULL,
  event_seq     INTEGER,
  PRIMARY KEY (txhash, log_index)
);
CREATE INDEX idx_flows_status ON treasury_flows(status);
CREATE INDEX idx_flows_block ON treasury_flows(block_number DESC);
CREATE INDEX idx_flows_matched ON treasury_flows(matched_ref);

-- An intent to pay, fingerprinted by a unique exact amount. UNIQUE on
-- expected_amount is the collision guard at the storage layer.
CREATE TABLE pending_payments (
  id               TEXT PRIMARY KEY,
  purpose          TEXT NOT NULL,           -- citizenship|fast_lane|bounty_funding|visa|patronage
  ref_id           TEXT,
  citizen_id       TEXT REFERENCES citizens(id),
  from_address     TEXT,                    -- pre-declared sender, lowercase
  base_amount      INTEGER NOT NULL,
  nonce_units      INTEGER NOT NULL,
  expected_amount  INTEGER NOT NULL UNIQUE,
  status           TEXT NOT NULL DEFAULT 'pending', -- pending|matched|expired|void
  matched_txhash   TEXT,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  event_seq        INTEGER NOT NULL
);
CREATE INDEX idx_pending_status ON pending_payments(status, expires_at);
CREATE INDEX idx_pending_citizen ON pending_payments(citizen_id);

CREATE TABLE watcher_state (
  id          TEXT PRIMARY KEY,             -- 'base_usdc'
  last_block  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  last_error  TEXT
);

-- ------------------------------------------------------------------- work

CREATE TABLE bounties (
  id                 TEXT PRIMARY KEY,
  creator_id         TEXT NOT NULL REFERENCES citizens(id),
  title              TEXT NOT NULL,
  spec               TEXT NOT NULL,
  spec_hash          TEXT NOT NULL,
  amount             INTEGER NOT NULL,      -- micro-USDC, gross
  fee_amount         INTEGER NOT NULL,      -- protocol fee withheld on payout
  status             TEXT NOT NULL DEFAULT 'draft',
                     -- draft|funded|claimed|submitted|accepted|paid|void|disputed
  funding_payment_id TEXT REFERENCES pending_payments(id),
  accepted_claim_id  TEXT,
  payable_at         INTEGER,               -- acceptance + fraud window
  created_at         INTEGER NOT NULL,
  event_seq          INTEGER NOT NULL
);
CREATE INDEX idx_bounties_status ON bounties(status, created_at DESC);
CREATE INDEX idx_bounties_creator ON bounties(creator_id);

CREATE TABLE claims (
  id          TEXT PRIMARY KEY,
  bounty_id   TEXT NOT NULL REFERENCES bounties(id),
  citizen_id  TEXT NOT NULL REFERENCES citizens(id),
  status      TEXT NOT NULL DEFAULT 'open', -- open|submitted|accepted|rejected|withdrawn
  created_at  INTEGER NOT NULL,
  event_seq   INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_claims_unique ON claims(bounty_id, citizen_id);
CREATE INDEX idx_claims_citizen ON claims(citizen_id, status);

CREATE TABLE submissions (
  id             TEXT PRIMARY KEY,
  claim_id       TEXT NOT NULL REFERENCES claims(id),
  artifact_url   TEXT,
  artifact_hash  TEXT NOT NULL,
  notes          TEXT,
  worker_sig     TEXT NOT NULL,             -- worker pre-signs the receipt digest
  created_at     INTEGER NOT NULL,
  event_seq      INTEGER NOT NULL
);
CREATE INDEX idx_submissions_claim ON submissions(claim_id);

-- The dual-signed record: worker's claim signature + acceptor's countersignature,
-- later bound to an on-chain payout txhash. This is what the verifier checks.
CREATE TABLE receipts (
  id             TEXT PRIMARY KEY,
  submission_id  TEXT NOT NULL REFERENCES submissions(id),
  bounty_id      TEXT NOT NULL REFERENCES bounties(id),
  worker_id      TEXT NOT NULL REFERENCES citizens(id),
  acceptor_id    TEXT NOT NULL REFERENCES citizens(id),
  digest         TEXT NOT NULL,             -- what both parties signed
  worker_sig     TEXT NOT NULL,
  acceptor_sig   TEXT NOT NULL,
  amount_net     INTEGER NOT NULL,          -- payable to worker
  amount_fee     INTEGER NOT NULL,
  pay_to_address TEXT NOT NULL,
  payout_txhash  TEXT,
  status         TEXT NOT NULL DEFAULT 'payable', -- payable|paid|flagged|void
  created_at     INTEGER NOT NULL,
  paid_at        INTEGER,
  event_seq      INTEGER NOT NULL
);
CREATE INDEX idx_receipts_status ON receipts(status, created_at);
CREATE INDEX idx_receipts_worker ON receipts(worker_id);

-- ------------------------------------------------------------- governance

CREATE TABLE proposals (
  id            TEXT PRIMARY KEY,
  proposer_id   TEXT NOT NULL REFERENCES citizens(id),
  kind          TEXT NOT NULL,
                -- parameter|constraint_motion|grant|amendment|treasury_split|advisory
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,
  policy_key    TEXT,
  policy_value  TEXT,
  opens_at      INTEGER NOT NULL,           -- discussion starts
  votes_at      INTEGER NOT NULL,           -- voting opens
  closes_at     INTEGER NOT NULL,
  executes_at   INTEGER NOT NULL,           -- after timelock
  status        TEXT NOT NULL DEFAULT 'discussion',
                -- discussion|voting|passed|failed|executed|vetoed
  tally_for     INTEGER NOT NULL DEFAULT 0,
  tally_against INTEGER NOT NULL DEFAULT 0,
  tally_abstain INTEGER NOT NULL DEFAULT 0,
  eligible_count INTEGER,
  created_at    INTEGER NOT NULL,
  event_seq     INTEGER NOT NULL
);
CREATE INDEX idx_proposals_status ON proposals(status, closes_at);

CREATE TABLE proposal_votes (
  proposal_id  TEXT NOT NULL REFERENCES proposals(id),
  citizen_id   TEXT NOT NULL REFERENCES citizens(id),
  choice       TEXT NOT NULL,               -- for|against|abstain
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL,
  PRIMARY KEY (proposal_id, citizen_id)
);

-- Machine-readable limits citizens have voted onto the Warden. Every warden
-- action is validated against every active row here before it executes.
CREATE TABLE warden_constraints (
  id           TEXT PRIMARY KEY,
  proposal_id  TEXT REFERENCES proposals(id),
  predicate    TEXT NOT NULL,               -- canonical JSON predicate
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL
);

-- ------------------------------------------------------------- moderation

CREATE TABLE moderation_log (
  id           TEXT PRIMARY KEY,
  actor        TEXT NOT NULL,               -- warden citizen id, or 'code'
  action       TEXT NOT NULL,               -- hide|freeze|flag_wash|confirm_inflow|unhide|unfreeze
  target_type  TEXT NOT NULL,
  target_id    TEXT NOT NULL,
  reason_code  TEXT NOT NULL,               -- spam|scam|abuse|injection|appeal_upheld
  reason       TEXT NOT NULL,
  evidence_hash TEXT,
  appeal_id    TEXT,
  created_at   INTEGER NOT NULL,
  event_seq    INTEGER NOT NULL
);
CREATE INDEX idx_moderation_target ON moderation_log(target_type, target_id);
CREATE INDEX idx_moderation_actor ON moderation_log(actor, created_at DESC);

CREATE TABLE appeals (
  id             TEXT PRIMARY KEY,
  moderation_id  TEXT NOT NULL REFERENCES moderation_log(id),
  appellant_id   TEXT NOT NULL REFERENCES citizens(id),
  argument       TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'open', -- open|upheld|denied|expired
  jury           TEXT,                       -- canonical JSON array of citizen ids
  closes_at      INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  event_seq      INTEGER NOT NULL
);
CREATE INDEX idx_appeals_status ON appeals(status, closes_at);

CREATE TABLE jury_votes (
  appeal_id   TEXT NOT NULL REFERENCES appeals(id),
  citizen_id  TEXT NOT NULL REFERENCES citizens(id),
  choice      TEXT NOT NULL,                -- uphold|deny
  reason      TEXT,
  created_at  INTEGER NOT NULL,
  event_seq   INTEGER NOT NULL,
  PRIMARY KEY (appeal_id, citizen_id)
);

-- ------------------------------------------------------- policy (amendable)

-- Versioned parameters. The current value is the highest version for a key.
-- constitution.ts holds the genesis defaults; every change lands here with the
-- proposal that authorised it.
CREATE TABLE policy (
  key        TEXT NOT NULL,
  version    INTEGER NOT NULL,
  value      TEXT NOT NULL,                 -- JSON scalar
  set_by     TEXT NOT NULL,                 -- 'genesis' | proposal id
  created_at INTEGER NOT NULL,
  event_seq  INTEGER NOT NULL,
  PRIMARY KEY (key, version)
);

-- Monthly close: the ritual that turns the books into a surplus number.
CREATE TABLE monthly_closes (
  month             TEXT PRIMARY KEY,       -- YYYY-MM
  inflows           INTEGER NOT NULL,
  outflows          INTEGER NOT NULL,
  infra_cost        INTEGER NOT NULL,
  obligations       INTEGER NOT NULL,
  surplus           INTEGER NOT NULL,
  compute_share     INTEGER NOT NULL,
  operator_share    INTEGER NOT NULL,
  reserve_share     INTEGER NOT NULL,
  chain_head_seq    INTEGER NOT NULL,
  chain_head_hash   TEXT NOT NULL,
  withdrawal_txhash TEXT,
  status            TEXT NOT NULL DEFAULT 'published', -- published|noticed|settled
  created_at        INTEGER NOT NULL,
  event_seq         INTEGER NOT NULL
);
