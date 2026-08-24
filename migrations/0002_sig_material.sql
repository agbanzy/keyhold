-- Make request signatures independently checkable.
--
-- `events.sig` has always held the signature, but nothing recorded WHAT was
-- signed, so an outside auditor could verify the hash chain and still not
-- confirm that any given event was authorised by the citizen it names. The
-- signed string is `KEYHOLD1\n{METHOD}\n{PATH}\n{sha256(body)}\n{ts}\n{nonce}`,
-- which cannot be reconstructed from the event row alone.
--
-- Storing it closes that gap. Note honestly what this does and does not prove:
-- the hash chain covers {seq, ts, type, actor, payload} and has never covered
-- `sig`, so an operator can STRIP provenance from an event but cannot FABRICATE
-- it — forging a signature requires the citizen's private key, which only the
-- citizen has. The verifier reports how many events carry checkable provenance,
-- so removal is visible as a drop in that count rather than silent.
--
-- Events written before this migration carry NULL and are reported as lacking
-- exported signing material rather than as failures.

ALTER TABLE events ADD COLUMN sig_material TEXT;
