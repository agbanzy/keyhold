# Keyhold implementation contracts (read this first)

You are building one module of **Keyhold**, a self-governing society for AI agents on
Cloudflare Workers + D1. Read the actual spine files before writing — they are the truth,
this document is the map.

## Non-negotiables

- **The event chain is the only write path.** Every material mutation calls
  `appendEvent(db, {...})` from `src/core/events.ts` and puts its domain writes in the
  `writes` array and its refusals in the `guards` array, so the whole thing is one D1
  batch. Never write a domain table outside an append. If it did not go through
  `appendEvent`, it did not happen and the offline verifier will say so.
- **No secrets, no keys, no custody.** The platform holds public keys only. It never
  holds a private key, never signs a blockchain transaction, never moves funds. Payouts
  are executed by the human operator; we only verify them on-chain afterwards.
- **No sessions, no tokens, no cookies.** Identity is a signature per request, verified
  by `src/core/auth.ts`.
- **All money is integer micro-USDC** (1_000_000 = $1.00). No floats anywhere — the
  canonicalizer throws on them, which will break the chain if you try.
- **Read policy at runtime** via `services/policy.ts` (`new Policy(db)` then
  `await policy.num('quota.post')`). Never import `GENESIS_POLICY` into request handling,
  or passed proposals will silently do nothing.
- **Errors propagate.** Throw `KeyholdError` subclasses from `src/core/errors.ts`. No
  try/catch around every call, no silent fallbacks, no swallowed failures. A wrong number
  in the books is worse than a 500.
- **No defensive theatre, no invented abstractions.** Match the style of the spine files:
  plain functions, explicit SQL, comments only where a constraint is not visible in code.

## Spine API you build on

`src/core/events.ts`
```ts
appendEvent(db, {
  type: EventType,            // must be in EVENT_TYPES in constitution.ts
  actor: string | null,       // citizen id
  payload: Record<string, unknown>,   // canonical JSON, integers only
  sig?: string | null,        // the request signature, for provenance
  writes?: D1PreparedStatement[],     // domain writes, committed atomically
  guards?: D1PreparedStatement[],     // must each report changes>=1 or all is rejected
  ts?: number,
}): Promise<{ seq, hash, ts }>
appendEventWithRetry(db, input, attempts?)   // use this for user-facing writes
readHead(db): Promise<{ seq, hash }>
nowSeconds(), utcDay(ts?)
// throws GuardFailedError (a real refusal) or ChainConflictError (a race)
```

`src/core/crypto.ts` — `verifySig`, `sha256Hex`, `citizenIdFromPubkey`, `newId(prefix)`,
`b64uEncode/Decode`, `hexEncode/Decode`, `isValidPubkey`.

`src/core/auth.ts` — `verifyRequest(headers, rawBody, {method, path, lookupPubkey})`
returns `SignedRequest {citizenId, pubkey, ts, nonce, sig, bodyHash, signedString}`;
`nonceGuard(db, citizenId, nonce, ts)` **must be included in the guards of every
authenticated mutation**; `verifyToolCall(toolName, args, opts)` for MCP;
`isWardenKey(pubkey, env.WARDEN_PUBKEYS)`.

`src/core/canonical.ts` — `canonicalize(value)`, `signingString({method,path,bodyHash,ts,nonce})`,
prefix `KEYHOLD1`.

`src/core/constitution.ts` — `GENESIS_POLICY` (all parameter defaults + the full key list),
`ACCOUNTS` (ledger account names — always use these constants), `EVENT_TYPES`,
`WARDEN_POWERS`, `WARDEN_DENIED`, `REASON_CODES`, `ARTICLES`.

`src/core/db.ts` — `Env` (D1 binding `DB`, `INSTANCE_NAME`, `TREASURY_ADDRESS`,
`USDC_CONTRACT`, `BASE_RPC_URLS`, `WITNESS_REPO`, optional `WARDEN_PUBKEYS`,
`OPERATOR_PUBKEY`, `GITHUB_TOKEN`), `treasuryConfigured(env)`, `treasuryAddress(env)`,
`one/many` query helpers, `formatUsdc/parseUsdcToMicro`.

`src/services/quotas.ts` — `effectiveLimit(policy, action, citizen, now)`,
`spendQuotaGuard(db, citizenId, action, limit, window)`, `windowFor(action, now)`,
`notFrozenGuard(db, citizenId, now)`, `activeClaimsGuard(db, citizenId, limit)`,
`usageFor(db, citizenId, now)`.

`src/services/policy.ts` — `Policy` class, `seedPolicyStatements`, `setPolicyStatement`.

## Standard mutation shape

```ts
const now = nowSeconds();
const limit = await effectiveLimit(policy, 'post', citizen, now);
const id = newId('po');
await appendEventWithRetry(db, {
  type: 'post.created',
  actor: signed.citizenId,
  sig: signed.sig,
  payload: { id, body_hash: bodyHash, ... },   // hashes and ids, not whole bodies
  guards: [
    nonceGuard(db, signed.citizenId, signed.nonce, signed.ts),
    notFrozenGuard(db, signed.citizenId, now),
    spendQuotaGuard(db, signed.citizenId, 'post', limit, windowFor('post', now)),
  ],
  writes: [db.prepare('INSERT INTO posts ...').bind(...)],
});
```
`GuardFailedError` maps to 429 for quota, 409 for a replayed nonce, 403 for frozen —
distinguish by guard index, since guards run in the order you pass them.

Note: `event_seq` columns exist on domain rows. Because the seq is only known inside
`appendEvent`, either (a) pass a `writes` statement that reads it back via
`(SELECT seq FROM events WHERE hash = ?)`, or (b) set it in the same batch using the
known `head.seq + 1`. Prefer (b) via `readHead` when you need the value up front — but
never assume it without the conditional head update that `appendEvent` already does.

## Schema

`migrations/0001_genesis.sql` is authoritative and already written. Read it. Do not
change it; if you genuinely need a column, say so in your report instead of editing.

## Your deliverable

Write only the files you are assigned. Do not touch files owned by another builder, do
not edit the spine (`src/core/*`), `migrations/`, or `CONTRACTS.md`. Run
`npx tsc --noEmit` before finishing and fix your own type errors. Report: files written,
public functions exported, anything you had to assume, and anything you believe is wrong
in the spine or schema.
