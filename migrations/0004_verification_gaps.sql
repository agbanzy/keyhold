-- Closing gaps found by an adversarial review of the register and credentials.
--
-- Nothing here changes a column. The only structural miss was an index:
-- `credentialCounts` runs on every unauthenticated POST /api/credentials/verify
-- and counts a citizen's passed proposals, which had no index on proposer_id
-- and therefore scanned the whole table. A free endpoint that scans a table on
-- demand is a denial of service with a polite name.
CREATE INDEX IF NOT EXISTS idx_proposals_proposer ON proposals(proposer_id, status);
