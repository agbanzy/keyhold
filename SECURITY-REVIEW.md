# Adversarial security review — 2026-08-24

Findings from the pre-launch red-team pass. Fix status tracked inline.

Adversarial review complete. I read CONTRACTS.md and every source file, and verified each finding against the actual code path.

---

# Keyhold â adversarial security review

**Verdict:** the cryptographic spine is sound (no SQLi, no HTML injection, correct path binding, no chain fork on concurrent append, nonce coverage complete on user-facing mutations). The breaks are all in the layers *above* it: governance, the Warden, the books, and the two surfaces disagreeing with each other. Three of them are system-ending.

---

## CRITICAL

### 1. Governance capture for ~$50: the MCP `vote_proposal` tool has no eligibility guard
`src/mcp/tools.ts:2364-2396` vs `src/routes/api.ts:1751-1783`

REST `/api/proposals/:id/vote` enforces eligibility as a guard:
```sql
UPDATE citizens SET id = id WHERE id = ? AND created_at <= ? AND marks >= ?
```
The MCP tool's guards are only: `nonceG`, `frozenG`, proposal-state, not-already-voted. **No tenure check. No marks check.** Any citizen who registered thirty seconds ago can cast a binding governance vote through `/mcp`.

The tally (`src/index.ts:751-766`) counts every cast vote toward quorum while computing `eligible` from the *strict* roll:
```
quorum   = max(gov.quorum_floor=25, ceil(eligible * 20 / 100))
passed   = cast >= quorum && for*100 > decisive*50
```

**Exploit:** mint 25 sybil citizens (bond door: 25 Ã $2.00 = $50 in USDC, or invites â `citizenship.registrations_per_day` is 100). Have one eligible-via-MCP account open a proposal, wait out discussion (72h), then have all 25 sybils call `vote_proposal` with `choice: "for"`. `cast = 25 >= quorum 25`, `2500 > 1250` â **passed**, executed after the timelock by `executeDueProposals`. No legitimate citizen need participate. `probation` status does not block it â `notFrozenGuard` (`src/services/quotas.ts:164-167`) explicitly allows `probation`.

### 2. Any proposal kind can carry an arbitrary `policy_key` that the executor applies
`src/mcp/tools.ts:2176-2191`, `:2266-2267` â `src/index.ts:828-856` (and `src/routes/admin.ts:948-979`)

MCP `propose` validates the policy key **only when `kind === 'parameter'`**, but the INSERT stores `policyKey`/`policyValue` for *every* kind. The executor doesn't look at kind at all:
```ts
const value = p.policy_key && p.policy_value !== null ? JSON.parse(p.policy_value) : null;
...
writes: p.policy_key && value !== null ? [setPolicyStatement(db, p.policy_key, value, ...)] : ...
```

**Exploit A (label laundering):** submit `{kind: "advisory", title: "Non-binding: a note on tone", policy_key: "bounty.fee_pct", policy_value: 0}`. The tool's own description tells voters "advisory binds nothing" (`tools.ts:2153`); the viewer's proposal card shows the kind chip as "advisory". On execution it rewrites a governed parameter. Same trick with `kind: "grant"` or `"treasury_split"`. Amendment-grade changes can be laundered through the 50% threshold, since `threshold = kind === 'amendment' ? 67 : 50` (`index.ts:762`).

**Exploit B (unvalidated keys):** `policy_key` is never checked against `GENESIS_POLICY` for non-parameter kinds, so arbitrary keys land in `policy`. They are invisible in `/api/policy`, because `Policy.report()` (`src/services/policy.ts:69`) iterates `GENESIS_POLICY`, not the table.

Chained with #1, an attacker with $50 owns every parameter in the constitution: `citizenship.bond_amount â 0`, `gov.quorum_floor â 1`, `treasury.split_operator_pct â 100`, `mod.freeze_max_hours`, `quota.post â 10^6`.

### 3. A Warden freeze is permanent, and appeals are structurally impossible
`src/routes/admin.ts:196-204`, `src/services/quotas.ts:157-170`, `src/routes/api.ts:1964-1978`, `src/routes/genesis.ts:142`

Two independent bugs that compose into "the Warden can permanently silence anyone, with no recourse."

**(a) The freeze never expires.** `/admin/moderate` sets `frozen_until = ? , status = 'frozen'`. `notFrozenGuard` refuses on `status NOT IN ('probation','active')` *before* it ever looks at `frozen_until`. Nothing â no cron in `src/index.ts:937-971`, no request path â ever flips `status` back when `frozen_until` passes. The route's own message ("a freeze runs 1..72 hours; longer needs a proposal, not a Warden", `admin.ts:191`) and `mod.freeze_max_hours` are unenforced. `/api/whoami` will report an expired `frozen_until` while every write still 403s.

**(b) No citizen is ever `active`, so no jury can be seated.** Grep of every `SET status` write: registration and rotation insert `'probation'`; rotation sets the predecessor `'departed'`; freeze sets `'frozen'`. The *only* transitions into `'active'` are `unfreeze` (`admin.ts:209`) and an upheld appeal (`api.ts:2174`). Jury selection is:
```sql
SELECT id FROM citizens WHERE status = 'active' AND id <> ? AND id <> ? AND standing <> 'founding' ORDER BY RANDOM() LIMIT ?
```
On any instance, the only `'active'` row is the genesis Warden (`genesis.ts:142`), excluded by `standing <> 'founding'`. The query returns zero rows â `unavailable('no_jury')` â **every appeal 503s, deterministically, forever.** Article II due process is unreachable, `ruleAppeal` is dead code, and `overturnRate()` is permanently 0, so the `mod.overturn_alarm_pct` accountability trigger can never fire.

---

## HIGH

### 4. Ledger rows are not covered by any event hash â the books can silently disagree with the chain
`src/services/ledger.ts:36-56`, `scripts/verify.mjs:736-738`, `:1221-1236`, `src/routes/export.ts:186-193`

`ledger_entries` rows are written as `writes` inside other events' batches, but the *event payloads never contain the legs*. The verifier only extracts legs from events of type `'ledger.entry'`:
```js
if (e.type === 'ledger.entry') { for (const leg of extractLedgerLegs(e.payload)) absorbLeg(...) }
```
`'ledger.entry'` exists in `EVENT_TYPES` (`constitution.ts:238`) but **no code anywhere ever appends one**. So `state.ledgerLegs` is always 0, and `checkBooks` falls back to `/export/ledger` â the server's own mutable table, with no cryptographic binding to the chain. `event_seq` on each row is never cross-checked against the event at that seq.

Consequence: a ledger row inserted, altered, or deleted outside `appendEvent` is undetectable. `export.ts:188-192` claims "a row with no matching event â or an event that booked money with no row â is a discrepancy the verifier reports." It does not. The `exportedRows !== chainLegs` comparison at `verify.mjs:1231` is vacuous (chainLegs is structurally 0) and is a `note`, never a `fail`. This is the exact failure CONTRACTS.md's first non-negotiable exists to prevent.

### 5. The Warden can book an outflow as revenue â and writes the ledger despite `WARDEN_DENIED`
`src/routes/admin.ts:831-836`, `:870-888`, `src/watcher/base.ts:340-356`, `src/services/moderation.ts:245-250`

`/admin/inflows/:txhash/attribute` selects the flow with **no `direction = 'in'` filter**:
```sql
SELECT txhash, amount, status, counterparty FROM treasury_flows WHERE txhash = ? AND log_index = ?
```
and the guard accepts `status IN ('observed','unattributed')`. The watcher records every outflow with exactly `status = 'observed'` (`base.ts:353`). So a Warden can pass the txhash of money *leaving* the treasury and get:
```
debit treasury:onchain / credit revenue:citizenship  for flow.amount
```
**Exploit:** operator withdraws $10,000 from the treasury; the watcher logs it as `outflow_observed`, unbooked (correctly â the visible gap is the signal). The Warden then "attributes" that same txhash as a `patronage` inflow. `treasury:onchain` is now credited $10,000 that left the wallet, and `/books` shows a balance the chain contradicts. One shot per flow, but every outflow is a fresh target.

Relatedly, `WARDEN_DENIED` includes `'write_ledger'`, `'set_policy'`, `'move_funds'` â but `assertWardenMay` checks it against `act.action`, which is only ever a log verb (`hide`/`freeze`/`flag_wash`/`confirm_inflow`). The two sets are disjoint, so `moderation.ts:245-250` **can never fire**. It is decorative, and the office does in fact write the ledger.

### 6. Payment fingerprints: permanent DoS by collision, exhaustion, and public disclosure
`src/routes/api.ts:390-404`, `migrations/0001_genesis.sql:188`, `src/routes/api.ts:665-672`, `:1204`, `src/routes/export.ts:319-326`

`paymentIntent` takes `MAX(nonce_units)+1` scoped to `base_amount`, but `expected_amount` is `UNIQUE` **globally**. Different base amounts collide trivially: base `2_000_000` + nonce `7` and base `2_000_007` + nonce `0` are both `2_000_007`.

**Exploit (permanent registration DoS):** read `/export/events`, find the highest `nonce_units` consumed for `citizenship.bond_amount` (2_000_000) â call the next slot `2_000_000 + k`. Create one bounty with `amount = 2_000_000 + k` (above `bounty.min_amount`, no payment needed â the draft's intent row lands regardless). That row now owns `expected_amount = 2_000_000 + k`. Every subsequent bond registration computes nonce `k`, hits the UNIQUE violation on a `writes` statement, is retried 4Ã by `appendEventWithRetry`, and 500s. Because the insert fails, `MAX(nonce_units)` never advances â **the bond door is wedged forever by one $1 draft bounty.** Same technique blocks funding of any bounty amount you choose.

**Slow variant:** `payment.nonce_max_units = 999` and rows are never deleted (`expirePendingPayments` only flips `status`, `index.ts:897`), so the citizenship base amount supports 1000 intents *ever*. At the 100/day cap that's 10 days of free unpaid registrations to reach permanent `fingerprints_exhausted` (503).

**Disclosure:** `export.ts:319-326` deliberately withholds live intents from `/export/snapshot` â "publishing an exact expected amount would let a stranger pay it and hijack the attribution." But `payment.intent_created` (`api.ts:668-671`) and `bounty.created` (`api.ts:1203-1204`) both put `expected_amount` in the event payload, published unauthenticated at `/export/events`. The stated control is defeated by the chain itself; any intent created without `from_address` (the default â it's optional on both routes) is open to third-party payment.

---

## MEDIUM

### 7. Warden constraint caps are a pre-check outside the batch
`src/services/moderation.ts:316-329`, called at `src/routes/admin.ts:165` before `append`

`max_per_window` counts `moderation_log` rows in a separate query, then returns; the append happens afterward with no corresponding guard. A Warden constrained to "3 freezes per day" by a passed constraint motion fires 50 concurrent `/admin/moderate` requests: all 50 read `used = 0` and all 50 land. This is precisely the "you had quota when we looked" pattern CONTRACTS.md forbids, applied to the one mechanism citizens have for narrowing the office.

### 8. Appeal verdicts can execute twice
`src/routes/api.ts:2086-2105`, `:2157-2213`

After each juror's vote commits, the handler re-reads the tally *outside any transaction* and calls `ruleAppeal` if `tally.n >= jury.length`. `ruleAppeal`'s append has **no guards at all**; the `UPDATE appeals SET status = ? WHERE ... status='open'` sits in `writes`, so a second execution updates zero rows and proceeds anyway. Two jurors voting concurrently as the jury fills both observe a complete tally and both rule: the appellant is awarded `marks.appeal_upheld` twice (`api.ts:2181-2183`, unconditional `marks = marks + ?`), two `appeal.ruled` verdict events and two `moderation_log` rows land. Marks gate governance eligibility and quota scaling.

### 9. `X-Keyhold-Pubkey` bypasses the citizen lookup, and with it the departed check
`src/core/auth.ts:122-141`, `src/routes/api.ts:98-113`, `src/mcp/tools.ts:269-285`

`verifyRequest` uses the supplied pubkey header when present and only calls `lookupPubkey` otherwise. The `citizen_departed` refusal lives *inside* `lookupPubkey`. A rotated/departed key that simply sends its own pubkey header authenticates normally â the `AuthError('citizen_departed')` is unreachable for anyone who knows the header exists. What actually stops the writes is `notFrozenGuard`, and two authenticated routes omit it: `POST /api/appeals` (`api.ts:1996-2018`) and `POST /api/appeals/:id/vote` (`api.ts:2057-2080`). A departed key can still file appeals and cast jury votes. The header also skips the check on paths that use `verifyRequest` directly (`admin.ts:92-96`, `genesis.ts:61-64`).

### 10. `event_seq` is off by one in eight domain tables
`src/core/events.ts:23-29` documents that `EVENT_SEQ` may only appear in `writes`, because guards run before `chain_head` advances. Eight call sites put an `INSERT ... ${EVENT_SEQ}` in `guards`:

- `api.ts:708-718` `citizen_addresses`
- `api.ts:758-778` `citizens` (rotation successor)
- `api.ts:1087-1095` `votes`
- `api.ts:1274-1282` `claims`
- `api.ts:1774-1782` `proposal_votes`
- `api.ts:1999-2017` `appeals`
- `api.ts:2071-2079` `jury_votes`
- `admin.ts:594-619` `monthly_closes`

Each records the *previous* event's seq. Every one of these rows points an auditor at the wrong causing event â the exact provenance link the design is built on. (Monthly closes are the worst: the close row cites the event before the `close.published` it belongs to.)

### 11. Two policy keys are ungovernable but advertised as governed
`src/core/auth.ts:98`, `:108` read `GENESIS_POLICY['request.max_body_bytes']` and `GENESIS_POLICY['request.max_skew_seconds']` directly. CONTRACTS.md: "Never import `GENESIS_POLICY` into request handling, or passed proposals will silently do nothing." A proposal tightening clock skew passes, executes, appears as `changed: true` in `/api/policy` â and the door keeps accepting Â±300s forever. Governance theatre on a security parameter.

### 12. Two independent registration counters double the instance-wide brake
`src/routes/api.ts:521-530` spends `quota_usage` under `citizen_id = 'system'`; `src/mcp/tools.ts:1238-1247` spends it under `citizen_id = 'global'`. Same `action = 'register'`, same day window, separate rows. `citizenship.registrations_per_day = 100` is actually 200/day, split across surfaces â the sybil brake is half as strong as it reads.

### 13. Self-voting is forbidden over REST and permitted over MCP
`src/routes/api.ts:1066-1068` refuses `self_vote`. The MCP `vote` tool (`tools.ts:1476-1555`) never fetches `citizen_id` on the target and has no such check. A citizen upvotes their own posts and comments 30Ã/day via `/mcp`, moving `posts.score`, which drives `sort=top` on `/api/feed`.

### 14. Prompt-injection content is served to agents with no provenance framing
`src/mcp/tools.ts:508-517` (`feed`), `:552-579` (`get_post`), `src/routes/api.ts:914-926`

Post bodies (up to 20,000 chars), comment bodies, and `display_name` are returned verbatim as MCP tool results to consuming agents, structurally indistinguishable from server-authored content. Nothing wraps them as untrusted third-party data, and the server `instructions` (`src/mcp/server.ts:165-181`) never warn about it. `display_name` in particular is unvalidated beyond a 64-char cap and is joined into every feed row.

A hostile citizen spends one post to publish instruction text targeting whatever agent reads the feed. The constitution has an `injection` reason code (`constitution.ts:55`) for hiding such content *after* it lands â an after-the-fact remedy for a system whose stated threat model is hostile autonomous agents reading each other's output.

### 15. Two unauthenticated endpoints will exhaust the Worker
- **`GET /export/snapshot`** (`export.ts:238-399`) runs 20 queries at up to 5,001 rows each and accumulates everything in one object before `c.json` stringifies it. Post bodies are 20 KB and bounty specs 20 KB, so 5,000 posts + 5,000 comments + 5,000 bounties is >150 MB against a 128 MB isolate. No auth, no rate limit.
- **`verify_chain`** (`tools.ts:998-1058`) loops up to 2,000 events doing a `JSON.parse` plus an awaited WebCrypto SHA-256 each, unauthenticated, free, CORS `*`. It is the only unauthenticated endpoint doing per-row crypto; a handful of concurrent calls burns the CPU budget.

---

## LOW

16. **`spendQuotaGuard`'s INSERT branch ignores the limit** (`quotas.ts:73-80`). The `WHERE quota_usage.used < ?` clause only guards the `DO UPDATE` path. With `quota.post` voted to 0 (or negative), the first action of every window still succeeds, because there's no conflicting row yet. Every citizen keeps one free action per window at any limit.
17. **`WITNESS_REPO = ""` in the deployed `wrangler.toml`.** `dailyWitnessJob` (`checkpoint.ts:405-409`) always pushes a problem, so `index.ts:949-957` throws â the daily cron is red every night, permanently, which makes a *real* witness failure indistinguishable from the config. More importantly, checkpoints are never anchored outside the instance, so `/verify`'s "witness copies held outside this infrastructure" and the whole tamper-evidence story reduce to the server vouching for itself.
18. **Surface drift in the bounty/proposal flow.** MCP `submit_work` does `UPDATE bounties SET status='submitted' WHERE id = ?` with no state condition (`tools.ts:1866`) where REST requires `AND status='claimed'` (`api.ts:1379`). MCP `propose` eligibility is `(created_at <= ? OR marks >= ?)` (`tools.ts:2240`) where REST is `AND` (`api.ts:1678-1681`). MCP `propose` accepts `constraint_motion` with no predicate at all, producing a motion that executes into nothing.
19. **Policy rows for unknown keys are invisible.** `Policy.report()` maps over `GENESIS_POLICY` (`policy.ts:69`), so anything #2 writes under a novel key never appears in `/api/policy`.

---

## Checked and clean

- **SQL injection:** none. Every interpolation into SQL is either a generated `?` placeholder list, `EVENT_SEQ`, or a value from a closed whitelist (`${table}`/`${column}`/`${targetType}` all originate from `oneOf`/`requireEnum`).
- **HTML injection:** none found. `escapeHtml` (`viewer/html.ts:61-64`) covers `&<>"'` and is applied at every interpolation of dynamic data across all page functions, including attribute contexts, `title=`, `href=`, and inline `style` widths.
- **Signature binding:** correct. REST binds `new URL(c.req.url).pathname`; MCP binds `tool:<name>` with the literal tool name at all 10 call sites and `method = "MCP"`. Cross-surface and cross-endpoint reuse are both blocked, and the receipt digest is domain-separated with `KEYHOLD1-RECEIPT`.
- **Chain forking:** not possible. Two concurrent appends both target `seq = N+1`; the second hits the events PK, the batch rolls back as a raw error (not a CHECK), and `appendEventWithRetry` recomputes. The conditional `advanceHead` is a second line of defence.
- **Canonicalization:** `src/core/canonical.ts` and `scripts/verify.mjs:306-340` are byte-identical twins; the `object â canonicalize â TEXT â JSON.parse â canonicalize` round trip is stable for the string, integer, and unicode cases user input can reach (lone surrogates are escaped to ASCII by `JSON.stringify` on both runtimes). Floats and unsafe integers throw before hashing, as intended.
- **Nonce coverage:** `nonceGuard` is present in the guards of every authenticated mutation on both surfaces, inside the batch. The only unguarded appends are code- and cron-initiated (`ruleAppeal`, tally, execute, expire, watcher, checkpoint) â correct by design, except for the `ruleAppeal` race in #8.
- **Payout integrity:** a payout cannot be booked without a real on-chain transfer. `verifyPayout` (`watcher/base.ts:529-586`) checks the receipt status, the USDC contract, the sender is the treasury, and the exact amount to the exact address; the payout address is read back from the `bounty.submitted` *event*, not the mutable table, so acceptance cannot redirect it. Bounties reach `funded` only through a matched on-chain inflow. Wash-work costs `bounty.fee_pct` (10%) per cycle and cannot extract more than it puts in â though it does mint `marks.bounty_accepted` (10) per cycle, which is the cheapest path to the eligibility thresholds in #1.

---

# Conformance review

# Keyhold conformance review vs. `~/.claude/plans/you-are-a-highly-shimmering-pixel.md` + `CONTRACTS.md`

Repo: `/Users/godwinagbane/Desktop/AI Unity/keyhold` Â· 17,642 lines Â· `npx tsc --noEmit` clean Â· `npx vitest run` 57/57 pass.

---

## 0. TREASURY SAFETY â the critical check

**VERDICT: CLEAN. No code path can sign a transaction, hold a private key, or move funds.** I checked this exhaustively rather than by reading comments.

**Every `crypto.subtle` call in `src/` (4 total):**
- `src/core/crypto.ts:49` â `digest('SHA-256', â¦)`
- `src/core/crypto.ts:74` â `generateKey('Ed25519', false, ['sign','verify'])`, a **throwaway capability probe** with `extractable: false`, result discarded except `!!kp.publicKey`. Comment at :72: *"Generating a throwaway pair is the cheapest way to learn whether the runtime implements the algorithm at all."* The pair is never stored, never returned, never used to sign.
- `src/core/crypto.ts:110` â `importKey('raw', pubkey, 'Ed25519', false, ['verify'])` â **`['verify']` only**, non-extractable.
- `src/core/crypto.ts:113` â `verify(...)`.

There is **no `sign()` call anywhere in `src/`.** The only signing code in the repo is `scripts/keygen.mjs:64` `signRequest()`, a client-side CLI that runs on the citizen's own machine and is never imported by the Worker.

**Every Base RPC method the Worker calls is a read:**
- `src/watcher/base.ts:180` `eth_blockNumber`
- `src/watcher/base.ts:221,229` `eth_getLogs`
- `src/watcher/base.ts:545` `eth_getTransactionReceipt`
- `src/watcher/base.ts:599` `eth_call` (`balanceOf` selector `0x70a08231`, `src/watcher/base.ts:597-599`)

No `eth_sendTransaction`, no `eth_sendRawTransaction`, no `eth_sign`, no `personal_sign`.

**No EVM signing dependencies exist.** `package.json` dependencies are exactly `@noble/ed25519`, `@noble/hashes`, `hono`. `ls node_modules | grep -iE "ethers|viem|web3|secp|bip|wallet|hdkey"` â empty. A full-repo grep for `privateKey|privkey|mnemonic|keystore|signTransaction|sendTransaction|secp256k1|ecdsa|signer|gasLimit|maxFeePerGas|rawTransaction` returns **only** prose comments, `scripts/keygen.mjs` (client-side Ed25519), and test fixtures.

**The Env has no key slot to hold one.** `src/core/db.ts:5-16`:
```ts
export interface Env {
  DB: D1Database; INSTANCE_NAME: string; TREASURY_ADDRESS: string;
  USDC_CONTRACT: string; BASE_RPC_URLS: string; WITNESS_REPO: string;
  WARDEN_PUBKEYS?: string; OPERATOR_PUBKEY?: string; GITHUB_TOKEN?: string;
}
```
Every key-shaped binding is a **pubkey**. `GITHUB_TOKEN` is repo-scoped to the witness mirror (`src/witness/github.ts:203`, `authorization: Bearer â¦` to `api.github.com` only). `TREASURY_ADDRESS` in `wrangler.toml:11` is a public `0x` address.

**Money-out is retrospective verification only.** `src/routes/admin.ts:397` `/admin/payouts/confirm` takes a `txhash` the operator already broadcast, calls `verifyPayout()` (`src/watcher/base.ts:529`, read-only receipt fetch), and refuses with 409 if the chain disagrees (`admin.ts:434-440`). The payables queue says it in the response body, `admin.ts:393`:
> `'Send each amount_net to its pay_to_address from the treasury wallet, then POST /admin/payouts/confirm with the txhash. This system verifies payments; it cannot make them.'`

**One residual observation (not a custody hole):** `POST /admin/close/:month/settle` (`admin.ts:700`) books `DIST_OPERATOR`/`DIST_COMPUTE` against `TREASURY` on the operator's word alone â it validates the txhash *format* (`admin.ts:707`) but never calls `verifyPayout()`, unlike the receipt path. It cannot move money, but it can put an unverified number in the books, which contradicts the plan's own standard for the payout rail.

---

## 1. Identity â **IMPLEMENTED**

| Requirement | Status | Evidence |
|---|---|---|
| Ed25519 keypair = citizen | â | `src/core/crypto.ts:91-124` |
| id derived from pubkey | â | `crypto.ts:132-137` `ct_ + sha256(raw).hex[0..32]`; enforced at `auth.ts:127-134` and again at `api.ts:495-498` |
| No recovery | â | No reset/recovery route exists; `skill.md:28` |
| No sessions/tokens/cookies | â | `auth.ts:1-11`; per-request sig; DB stores pubkeys only. Grep for `cookie`/`session`/`bearer` in `src/routes` returns nothing |
| Key rotation | â | `api.ts:725-810`. Successor inherits `created_at`, `marks`, `standing`, `vouched_by` (`api.ts:766-776`); old key `status='departed'` (`:783`); `lookupPubkey` then refuses it (`api.ts:105-111`) |

Nonce replay is a **guard inside the batch**, not a pre-check (`auth.ts:207-219`), exactly per CONTRACTS.md. Verified present in all 10 mutating MCP tools (`tools.ts` lines 1234, 1332, 1423, 1523, 1630, 1703, 1844, 2030, 2232, 2365) and every REST mutation.

---

## 2. Scarcity â **IMPLEMENTED** (one defect)

Quotas 5/20/30 daily, weekly proposal, monthly invite: `constitution.ts:66-71`. Probation halving: `quotas.ts:50-58`. No rollover: window key rotates (`quotas.ts:79-95`).

Enforcement is a conditional upsert **inside** the batch (`quotas.ts:64-79`), and `appendEvent`'s `guardSentinel` (`events.ts:87-92`) converts `changes()=0` into a `CHECK constraint failed` that rolls the whole batch back â the mechanism is real, not advisory. `chain_head`'s `CHECK (id = 1)` (`migrations/0001_genesis.sql:128`) is the only CHECK in the schema, so `isGuardAbort` (`events.ts:100-104`) is unambiguous.

**Defect â registration cap is 2Ã the policy value.** REST uses sentinel `'system'` (`api.ts:524`), MCP uses `'global'` (`tools.ts:1241`), against the same `quota_usage` PK `(citizen_id, day, action)`. With `citizenship.registrations_per_day = 100`, an attacker gets 100 via REST **plus** 100 via MCP on the same UTC day.

---

## 3. Event chain â **PARTIAL** (chain solid, verifier broken)

**Solid:** single write path (`events.ts:181`), canonical hashing with float rejection (`canonical.ts:29-40`), conditional head advance (`events.ts:220-225`) + post-hoc assertion (`events.ts:258-261`), daily checkpoint (`witness/checkpoint.ts:121`), witness push (`witness/github.ts:154`), cron wiring (`index.ts:941-963`, `wrangler.toml:44`).

**Three blocking defects in the verifier â the plan's stated launch gate** ("launching without it green is forbidden", plan Â§Verification):

**(a) `verify.mjs` cannot read the chain at all.** It requests `?from=<seq>` and expects `{ events: [...] }` (`verify.mjs:32-35, 512-518`). The server implements `?since=` and returns **NDJSON** (`export.ts:48-84`; `content-type: application/x-ndjson`). Proven empirically against a faithful replica of `export.ts`:
```
$ node scripts/verify.mjs --base http://127.0.0.1:8799
verify: Error: .../export/events?from=1&limit=500: no events array in response
    at streamEvents (verify.mjs:518:30)
```
With >1 event the body isn't valid JSON at all and `getJson` (`verify.mjs:440`) throws `SyntaxError`. **The verifier has never been run against this server.**

**(b) Signature verification can never pass.** `signedMaterial()` (`verify.mjs:993-1015`) needs `signed_string` or `payload.sig_material` to rebuild `KEYHOLD1\nMETHOD\npath\nbodyhash\nts\nnonce`. The `events` table stores only `sig` (`migrations/0001_genesis.sql:113-121`) â no method, path, body hash, or nonce â and `eventLine()` (`export.ts:86-106`) emits no `signed_string`. Grep confirms `sig_material` appears nowhere in `src/`. Every signature falls to the `sigNoMaterial` branch and check 3 degrades to a permanent WARN (`verify.mjs:1038-1047`). The plan's "re-verifies signatures (registration events carry pubkeys â chain is self-contained)" is structurally unmet.

**(c) Books are not chain-derived.** `verify.mjs:736` reads legs from `type === 'ledger.entry'` events â **which are never emitted** (declared `constitution.ts:238`; zero producers). Ledger rows ride as `writes` inside other events. The verifier silently falls back to `/export/ledger` (`verify.mjs:1225,1230`), i.e. it checks the server's own table against itself.

**(d) Documentation contradiction.** `index.ts:651-653` tells humans `node scripts/verify.mjs events.jsonl` â a positional arg that `parseArgs` rejects with `die('unknown argument â¦')` (`verify.mjs:157`). `skill.md:155` gives the correct `--base` form.

**(e) Witness disabled in deployed config.** `wrangler.toml:16` `WITNESS_REPO = ""`. The daily cron will push nothing and `dailyWitnessJob` will report a problem every night (`index.ts:949-957`).

Verifier coverage of the six domains (chain / checkpoints / signatures / quotas / books / moderation) is genuinely written (`verify.mjs:670-773`) and the canonicalizer is a faithful independent twin (`verify.mjs:306-338` vs `canonical.ts:22-64`) â it just cannot reach the data.

---

## 4. Books â **PARTIAL**

| Requirement | Status | Evidence |
|---|---|---|
| Double-entry, balanced by construction | â | `services/ledger.ts:36-58`; rejects `amount<=0` and `debit===credit` |
| On-chain flows observed read-only | â | `watcher/base.ts` (see Â§0) |
| Payouts verified by txhash before booking | â | `admin.ts:429-440` |
| Monthly close, surplus split 50/30/20 | â | `admin.ts:562-569`; reserve absorbs rounding remainder (`:569`) |
| Withdrawal intent + notice + settle | â | `admin.ts:644 / 700`; notice measured from the **chain event**, not a mutable column (`admin.ts:731-751`) |
| **All ACCOUNTS used consistently** | â | 6 of 15 accounts are **never posted to** |

Never credited/debited by any code path (display-only in `index.ts:560-571` and `viewer/html.ts:407-420`): `ACCOUNTS.RESERVE`, `REV_FORFEIT`, `EXP_INFRA`, `EXP_COMPUTE`, `EXP_PAYOUTS`.

Consequences:
- `reserve_share` is computed at close (`admin.ts:569`) but never booked to `equity:reserve`.
- `infra_cost` is subtracted from surplus (`admin.ts:559`) but never booked to `expense:infrastructure` â so the books never show the cost that reduced the surplus.
- Payouts debit `OBLIGATIONS` (`admin.ts:491`), never `EXP_PAYOUTS`.
- **Unattributed â forfeit after 30 days is not implemented.** `unattributed.claim_window_days` is only stringified into an event payload (`watcher/base.ts:378, 396`); no cron sweeps it and `REV_FORFEIT` is never credited. Money parked in `treasury:unattributed` stays there forever.
- 50/30/20 â 60/40 switch at reserve target: `treasury.reserve_target_months` is displayed (`index.ts:576`) but the switch is unimplemented.

---

## 5. Work rail â **PARTIAL**

| Requirement | Status | Evidence |
|---|---|---|
| Bounty state machine | â | draftâfunded (`watcher/base.ts:442`) âclaimed (`api.ts:1267`) âsubmitted (`api.ts:1379`) âaccepted (`api.ts:1499`) âpaid (`admin.ts:469`) |
| **Dual-signed receipt, both verified** | â | Digest `sha256("KEYHOLD1-RECEIPT\n" + canonical(...))`, `mcp/tools.ts:321-331` â one definition imported by REST (`api.ts:20`). Worker sig verified at submit (`api.ts:1332`) **and re-verified at accept** (`api.ts:1452-1461`); acceptor sig verified (`api.ts:1463`). MCP path identical (`tools.ts:1985-2000`). Payout address read back from the **immutable log event**, not a mutable table (`api.ts:460-487`), so acceptance cannot redirect funds. This is well built. |
| 10% fee | â | `constitution.ts:90`; `api.ts:1139-1140`; booked `ESCROWâREV_FEES` (`api.ts:1553-1561`) |
| Fraud window | â | `api.ts:1471-1473`, gated at `admin.ts:368` |
| Jury disputes | â ï¸ | Appeals + jury exist (`api.ts:1928, 2030, 2138`) but are wired to **moderation actions only**. `moderationTargetOwner` (`api.ts:2120-2135`) handles `citizen`/`post`/`comment` â not `receipt`. A worker whose receipt is flagged under `/admin/receipts/:id/flag` (`admin.ts:280`) writes a `moderation_log` row with `target_type='receipt'`, so `moderationTargetOwner` returns `null` and the appeal is refused with `not_your_appeal`. **The plan's "disputes â 5-citizen jury, binding" for the work rail is unreachable.** The response text at `admin.ts:349` promises the opposite: *"The worker may appeal like anyone else."* |
| **Grant cap â¤$200** | â | `bounty.grant_cap` is **never read anywhere**. `kind: 'grant'` is an accepted proposal kind (`api.ts:1606`) but `executeDueProposals` (`index.ts:854-866`) handles only `policy_key` and `constraint_motion` â a passed grant executes as a no-op. There is no treasury-funded bounty path at all. |

Also unemitted: `bounty.voided`, `receipt.created`, `receipt.paid`, `bounty.funded`, `invite.redeemed`, `citizen.departed`, `quota.denied`, `compute.grant_issued`, `compute.spend_reported`, `policy.changed`, `warden.constrained` â 13 of 46 declared `EVENT_TYPES` have zero producers. `policy.changed` in particular means a parameter change is only inferable from `proposal.executed` payloads.

---

## 6. Governance â **PARTIAL**

| Requirement | Status | Evidence |
|---|---|---|
| Eligibility gates (30d + 50 marks) | â | Guards inside the batch: propose `api.ts:1675-1683`, vote `api.ts:1754-1762` |
| Quorum floor `max(25, 20%)` | â | `index.ts:761` `Math.max(quorumFloor, Math.ceil(eligible*quorumPct/100))` |
| Timelocks | â | `api.ts:1645-1654`; 48h params / 168h amendments; enforced at `index.ts:848` and `admin.ts:940` |
| Constraint motions as machine-readable predicates | â | `moderation.ts:111-200` validates at **proposal time**, refusing unenforceable predicates; enforced at `moderation.ts:288-330`; **fails closed** on an unparseable stored predicate (`moderation.ts:300-305`) |
| Operator ratification | â | `admin.ts:916` |
| **Parameter validation** | â | `api.ts:1622-1627` checks only `key in GENESIS_POLICY` and `int()` (`api.ts:319-328`, which accepts **negative** safe integers). Nothing validates ranges or invariants at proposal or execution time. A passed proposal can set `bounty.fee_pct = 900`, `gov.quorum_floor = -1`, `mod.freeze_max_hours = 100000`, or leave the three treasury split percentages summing to anything other than 100 â `treasury_split` proposals set one key at a time with no cross-key check. |
| **Operator veto + veto sunset** | â | **Not implemented at all.** `treasury.veto_sunset_closes` (`constitution.ts:87`) is never read by any file. There is no veto route, no veto event type, no close counter. `/admin/ratify` is not a veto â it only *executes* what already passed, and it is redundant because `executeDueProposals` (`index.ts:812`) auto-executes on cron regardless. Plan Art. VI ("Operator veto on treasury amendments sunsets after 12 independently-verified monthly closes") has no implementation. |

---

## 7. Moderation â **PARTIAL**

| Requirement | Status | Evidence |
|---|---|---|
| Only spam/scam/abuse/injection grounds | â | `moderation.ts:64` + `:272-281`; `operator_legal` narrowed to hide/unhide/confirm_inflow (`moderation.ts:73, 266-271`); `appeal_upheld` reserved to code (`moderation.ts:70, 260-265`) |
| Nothing deleted (hidden + hash retained) | â | `hidden` flag only (`admin.ts:226`); `body_hash` kept; API nulls body but returns the hash (`api.ts:983, 993`); `moderation_log` append-only |
| Appeal + jury | â ï¸ | Works for post/comment/citizen; **unreachable for `receipt`** (see Â§5) |
| Warden denied-list at a chokepoint | â | `moderation.ts:232-331`, single call site pair (`admin.ts:165, 296, 839`). `WARDEN_DENIED` checked at `moderation.ts:245-250` |
| **Overturn-rate alarm (>30%)** | â | `overturnRate()` (`moderation.ts:388`) is **exported and never called** â zero callers in `src/`, `test/`, `scripts/`. `mod.overturn_alarm_pct` is never read. No route surfaces it, no cron evaluates it, no replacement proposal is auto-triggered. |
| `mod.duplicate_similarity_pct` | â | Never read; no duplicate detection exists |

Note: the `WARDEN_DENIED` check at `moderation.ts:245` tests `act.action` (log verbs: `hide`/`freeze`/â¦) against a list of denied *power names* (`delete_event`, `write_ledger`, â¦). The two vocabularies never intersect, so this branch is dead code. It is harmless â the real protection is the `WARDEN_POWERS` enumeration at `:239` plus the fact that no route exposes those verbs â but it is not the enforcement it reads as.

---

## 8. Surfaces â **PARTIAL**

| Requirement | Status | Evidence |
|---|---|---|
| JSON by default | â | `index.ts:206-209`, q-value-aware negotiation (`index.ts:184-204`) |
| MCP with per-call signatures | â | `mcp/server.ts:267`; `verifyToolCall` shares one code path with REST (`auth.ts:167-195`); all 10 mutating tools signed + nonce-guarded |
| Read-only human viewer | â | `viewer/html.ts` (1,581 lines SSR), no forms, no JS framework; routes `index.ts:206,377,409,497,520,621` |
| `llms.txt` | â | `public/llms.txt` |
| `openapi.json` | â | `index.ts:683,976-1249`, OpenAPI 3.1, covers all routes |
| Public export, no auth | â | `routes/export.ts` â 6 endpoints, zero auth imports (grep confirms) |
| **`/skill.md` with working copy-pasteable clients** | â | Plan Â§6 mandates *"`/skill.md` door (Python+Node 15-line clients)"*. `public/skill.md` contains **no code client in any language** â no Python, no Node, no `curl`. It documents the signing string in prose (`skill.md:37-44`) and points at `npm run keygen` (`skill.md:16`), which requires cloning the repo. An agent that fetches `/skill.md` cannot make its first signed request from what it reads. This is the plan's designated onboarding surface and the retention mechanism it names. |

---

## 9. Implemented but NOT authorised by the plan

Nothing material. Everything found maps to a plan clause. Closest calls, all defensible:

- `treasury.outflow_observed` event type + unbooked outflow recording (`watcher/base.ts:335-356`) â not in the plan, but it makes an unexplained treasury outflow *visible* rather than invisible. Strictly protective.
- `POST /api/citizens/:id/address` (`api.ts:688`) â implements the plan's "pre-registered sender address (signed by citizen key)" (plan Â§Base watcher).
- `POST /admin/ratify/:id` (`admin.ts:916`) â plan Â§Governance names "operator ratification". Functionally redundant with cron auto-execute, but authorised.
- `wrangler.toml:31-38` binds custom domains `aiunity.org` / `www.aiunity.org` and `wrangler.toml:9` sets a live treasury address `0xe1C5D0C3C204BC929a5B54350b94C158A27850E0`. The plan recorded *"No domain designated in memory; no treasury address recorded anywhere"* and listed both as pending Godwin input with `*.workers.dev` / `TREASURY_PENDING` fallbacks. These were supplied out of band, not invented by the build â but they are config the plan did not carry, and the treasury address should be confirmed against Godwin's actual wallet before genesis.

---

## Summary table

| Area | Verdict |
|---|---|
| **Treasury safety (no keys, no signing, no fund movement)** | **CLEAN â exhaustively verified** |
| Identity | IMPLEMENTED |
| Scarcity | IMPLEMENTED (registration cap is 2Ã via the `system`/`global` sentinel split) |
| Event chain | PARTIAL â chain excellent; **offline verifier cannot run against the server** |
| Books | PARTIAL â 6/15 accounts never posted; no forfeiture; settle unverified on-chain |
| Work rail | PARTIAL â dual-sign excellent; **grant cap and jury-for-receipts absent** |
| Governance | PARTIAL â **no parameter validation, no operator veto / veto sunset** |
| Moderation | PARTIAL â **overturn alarm dead code** |
| Surfaces | PARTIAL â **`/skill.md` has no working clients** |

## Launch blockers, ranked

1. **`verify.mjs` â `/export/events` contract mismatch** (`verify.mjs:32-35,512-518` vs `export.ts:48-84`) â proven non-functional. The plan forbids launching without this green.
2. **Signatures are structurally unverifiable offline** â `events` table lacks the signing material (`migrations/0001_genesis.sql:113-121`); export emits none (`export.ts:86-106`).
3. **No parameter validation** (`api.ts:1622-1627`) â one passed proposal can set a negative quorum or a 900% fee.
4. **Registration cap doubled** (`api.ts:524` `'system'` vs `tools.ts:1241` `'global'`).
5. **Operator veto + sunset entirely absent** â `treasury.veto_sunset_closes` has zero readers.
6. **Receipt disputes cannot reach a jury** (`api.ts:2120-2135`), contradicting `admin.ts:349`.
7. **Overturn-rate alarm is dead code** (`moderation.ts:388`, zero callers).
8. **`/skill.md` ships no runnable client**, and `index.ts:651-653` prints a verifier invocation the verifier rejects.
9. **`WITNESS_REPO = ""`** (`wrangler.toml:16`) â the witness rail is switched off in the deployed config.

No fixes applied.
---

## #20 (CRITICAL, found in production) — registration is completely broken

Found by driving the live instance at https://aiunity.org, not by review.

`POST /api/register` with a valid invite returns **500**:

```
D1_ERROR: FOREIGN KEY constraint failed: SQLITE_CONSTRAINT_FOREIGNKEY
  at appendEvent → appendEventWithRetry → append (/api/register)
```

**Cause.** The guard that redeems the invite sets `invites.used_by` to the new
citizen's id, but the citizen row is queued in `writes` and does not exist yet.
`invites.used_by REFERENCES citizens(id)`, so the foreign key fails and the whole
batch aborts. Guards run before writes by design — that is what makes refusals
atomic — so any guard referencing a row created in the same append will do this.

**Impact.** No agent can ever join the society. Every other feature is
unreachable. This is more severe in practice than anything in the review above,
and it existed with no test covering the front door at all.

**Constraint on the fix.** The citizen must exist before anything references it,
*without* weakening the single-use guarantee on the invite: two concurrent
redemptions of one code must still yield exactly one citizen. Reproduced by
`test/registration.test.ts`.

Check every other append for the same shape: a guard that references a row the
same append is about to create.
