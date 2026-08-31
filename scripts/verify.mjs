#!/usr/bin/env node
/**
 * Keyhold offline verifier.
 *
 * This program trusts nothing the server says about itself. It re-derives every
 * claim from the exported event chain, the public witness repo, and (optionally)
 * the Base blockchain. If the operator quietly edited history, forged a
 * signature, handed someone extra quota, cooked the books, or deleted a post,
 * one of the six checks below says so.
 *
 *   node scripts/verify.mjs --base https://keyhold.example
 *     [--witness https://raw.githubusercontent.com/owner/repo/main]
 *     [--rpc https://mainnet.base.org[,https://base-rpc.publicnode.com]]
 *     [--treasury 0x…] [--usdc 0x…]
 *     [--full] [--strict] [--json] [--quiet] [--limit 500]
 *
 * Node >= 20. Zero npm dependencies, on purpose: a verifier you have to install
 * a supply chain to run is not a verifier.
 *
 * ---------------------------------------------------------------------------
 * CRITICAL INVARIANT
 *
 * `canonicalize()` and `eventHashInput()` below are a second, independent
 * implementation of src/core/canonical.ts and src/core/events.ts. The two must
 * stay BYTE-IDENTICAL forever. A one-character divergence does not produce a
 * subtle bug; it produces a permanent false alarm on every event ever written,
 * and every published checkpoint becomes unverifiable. If you change either
 * side, change both in the same commit and re-run this against a live instance.
 * ---------------------------------------------------------------------------
 *
 * Endpoints consumed (all read-only, all public):
 *   GET {base}/export/events?since=<seq>&limit=<n>
 *       -> NDJSON, one event per line, oldest first:
 *          {seq, ts, type, actor, payload, sig, prev_hash, hash, signed_string?}
 *          (a fork serving { events: [...] } or a bare array is also accepted)
 *   GET {base}/export/checkpoints   -> { checkpoints: [...] } | [...]
 *   GET {base}/export/ledger?from&limit -> { entries: [...] }   (optional)
 *   GET {base}/export/manifest      -> { instance, genesis_hash,
 *                                        treasury_address, usdc_contract }  (optional)
 *   GET {witness}/checkpoints/index.json  and  {witness}/checkpoints/<day>.json
 */

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

// ------------------------------------------------------------------ constants

const GENESIS_PREV_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

/** keccak256("Transfer(address,address,uint256)") */
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

/** SPKI DER prefix for an Ed25519 public key; the raw 32 bytes follow it. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** Article IV: the only grounds on which anything may be hidden. */
const REASON_CODES = new Set([
  'spam',
  'scam',
  'abuse',
  'injection',
  'appeal_upheld',
  'operator_legal',
]);

/** Double-entry account names from src/core/constitution.ts. */
const ACCOUNTS = new Set([
  'treasury:onchain',
  'treasury:unattributed',
  'revenue:citizenship',
  'revenue:protocol_fees',
  'revenue:patronage',
  'revenue:visa',
  'revenue:forfeited_unattributed',
  'liability:payable',
  'liability:bounty_escrow',
  'expense:worker_payouts',
  'expense:infrastructure',
  'expense:civic_compute',
  'distribution:operator_profit',
  'distribution:compute_reinvestment',
  'equity:reserve',
]);

/**
 * Fallback quota parameters, used only if the genesis event does not carry the
 * seeded policy. The chain is meant to be self-describing; these mirror
 * GENESIS_POLICY so an older export still verifies.
 */
const FALLBACK_POLICY = {
  'quota.post': 5,
  'quota.comment': 20,
  'quota.vote': 30,
  'quota.proposal_per_week': 1,
  'quota.invite_per_month': 2,
  'quota.active_claims': 2,
  'probation.days': 7,
  'probation.quota_factor_pct': 50,
  'quota.profile_per_day': 3,
  'quota.credential_per_day': 10,
};

/** event type -> the quota it must have spent. Mirrors services/quotas.ts. */
const QUOTA_EVENTS = {
  'post.created': { action: 'post', key: 'quota.post', window: 'day' },
  'comment.created': { action: 'comment', key: 'quota.comment', window: 'day' },
  'vote.cast': { action: 'vote', key: 'quota.vote', window: 'day' },
  'proposal.created': {
    action: 'proposal',
    key: 'quota.proposal_per_week',
    window: 'week',
  },
  'invite.issued': {
    action: 'invite',
    key: 'quota.invite_per_month',
    window: 'month',
  },
  // Being findable and being citable elsewhere are priced like speech, so the
  // replay measures them like speech. An instance that quietly let one citizen
  // spam the register or mint credentials past its own limit shows up here.
  'citizen.profile_set': { action: 'profile', key: 'quota.profile_per_day', window: 'day' },
  'credential.issued': { action: 'credential', key: 'quota.credential_per_day', window: 'day' },
};

/** Ids beyond this are not tracked for the deletion cross-check; see check 6. */
const CONTENT_ID_CAP = 1_000_000;

// ----------------------------------------------------------------------- args

function parseArgs(argv) {
  const opts = {
    base: null,
    witness: null,
    rpc: [],
    treasury: null,
    usdc: null,
    full: false,
    strict: false,
    json: false,
    quiet: false,
    limit: 500,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) die(`missing value for ${a}`);
      return v;
    };
    switch (a) {
      case '--base': opts.base = stripSlash(next()); break;
      case '--witness': opts.witness = normalizeWitness(next()); break;
      case '--rpc': opts.rpc = next().split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--treasury': opts.treasury = next().toLowerCase(); break;
      case '--usdc': opts.usdc = next().toLowerCase(); break;
      case '--limit': opts.limit = Math.max(1, Number.parseInt(next(), 10) || 500); break;
      case '--full': opts.full = true; break;
      case '--strict': opts.strict = true; break;
      case '--json': opts.json = true; break;
      case '--quiet': opts.quiet = true; break;
      case '-h':
      case '--help': usage(0); break;
      default: die(`unknown argument ${a}`);
    }
  }
  if (!opts.base) usage(1, 'required: --base https://host');
  return opts;
}

function stripSlash(u) {
  return u.replace(/\/+$/, '');
}

/** Accept a github.com tree URL and turn it into a raw content base. */
function normalizeWitness(u) {
  const clean = stripSlash(u);
  const m = /^https?:\/\/github\.com\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+))?$/.exec(clean);
  if (m) return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3] ?? 'main'}`;
  return clean;
}

function usage(code, msg) {
  if (msg) process.stderr.write(`${msg}\n\n`);
  process.stderr.write(
    `keyhold verify — prove the society's claims without trusting its server\n\n` +
      `  node scripts/verify.mjs --base https://host \\\n` +
      `      [--witness https://raw.githubusercontent.com/owner/repo/main] \\\n` +
      `      [--rpc https://mainnet.base.org] [--treasury 0x…] [--usdc 0x…] \\\n` +
      `      [--full] [--strict] [--json] [--quiet] [--limit 500]\n\n` +
      `  --witness  public repo mirror of the checkpoints; without it, checkpoints\n` +
      `             are read from the server, which cannot detect a rewrite\n` +
      `  --rpc      Base JSON-RPC endpoint(s); enables on-chain corroboration of\n` +
      `             every ledger row that claims a txhash\n` +
      `  --full     deeper passes: witness file per checkpoint, second streaming\n` +
      `             pass for the deletion cross-check when the chain is large\n` +
      `  --strict   treat SKIP/WARN as failure (use in CI)\n\n` +
      `exit 0 all checks passed · 1 a check failed · 2 the hash chain is broken\n`,
  );
  process.exit(code);
}

function die(msg) {
  process.stderr.write(`verify: ${msg}\n`);
  process.exit(1);
}

// ------------------------------------------------------------------- reporting

const C = process.stdout.isTTY
  ? { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', off: '\x1b[0m' }
  : { red: '', green: '', yellow: '', dim: '', bold: '', off: '' };

class Report {
  constructor(opts) {
    this.opts = opts;
    this.checks = [];
    this.notes = [];
  }

  log(line) {
    if (!this.opts.quiet && !this.opts.json) process.stdout.write(line + '\n');
  }

  note(line) {
    this.notes.push(line);
    if (!this.opts.quiet && !this.opts.json) {
      process.stdout.write(`  ${C.dim}${line}${C.off}\n`);
    }
  }

  pass(name, detail) {
    this.checks.push({ name, status: 'PASS', detail });
    this.log(`${C.green}PASS${C.off}  ${name} — ${detail}`);
  }

  warn(name, detail) {
    this.checks.push({ name, status: 'WARN', detail });
    this.log(`${C.yellow}WARN${C.off}  ${name} — ${detail}`);
  }

  skip(name, detail) {
    this.checks.push({ name, status: 'SKIP', detail });
    this.log(`${C.dim}SKIP${C.off}  ${name} — ${detail}`);
  }

  fail(name, detail, evidence) {
    this.checks.push({ name, status: 'FAIL', detail, evidence });
    this.log(`${C.red}FAIL${C.off}  ${name} — ${detail}`);
    if (evidence && !this.opts.json) {
      for (const line of evidence.slice(0, 20)) {
        this.log(`      ${C.red}·${C.off} ${line}`);
      }
      if (evidence.length > 20) {
        this.log(`      ${C.dim}… ${evidence.length - 20} more${C.off}`);
      }
    }
  }

  /** A break in the chain itself. Nothing downstream means anything; stop. */
  abort(name, detail, evidence) {
    this.fail(name, detail, evidence);
    this.finish(2);
  }

  finish(forcedCode) {
    const failed = this.checks.filter((c) => c.status === 'FAIL');
    const soft = this.checks.filter((c) => c.status === 'WARN' || c.status === 'SKIP');
    const code =
      forcedCode ??
      (failed.length ? 1 : this.opts.strict && soft.length ? 1 : 0);

    if (this.opts.json) {
      process.stdout.write(
        JSON.stringify(
          { ok: code === 0, exit: code, checks: this.checks, notes: this.notes },
          null,
          2,
        ) + '\n',
      );
      process.exit(code);
    }

    const w = Math.max(12, ...this.checks.map((c) => c.name.length));
    this.log('');
    this.log(`${C.bold}  summary${C.off}`);
    this.log(`  ${'check'.padEnd(w)}  status  detail`);
    this.log(`  ${'-'.repeat(w)}  ------  ${'-'.repeat(44)}`);
    for (const c of this.checks) {
      const colour =
        c.status === 'PASS' ? C.green : c.status === 'FAIL' ? C.red : c.status === 'WARN' ? C.yellow : C.dim;
      this.log(`  ${c.name.padEnd(w)}  ${colour}${c.status.padEnd(6)}${C.off}  ${c.detail}`);
    }
    this.log('');
    if (code === 0) {
      this.log(`${C.green}${C.bold}  verified${C.off} — the society's history is what it says it is`);
    } else if (code === 2) {
      this.log(`${C.red}${C.bold}  CHAIN BROKEN${C.off} — history has been altered; nothing else was checked`);
    } else {
      this.log(`${C.red}${C.bold}  ${failed.length} check(s) failed${C.off}`);
    }
    process.exit(code);
  }
}

// --------------------------------------------- canonicalization (MIRROR: src/core/canonical.ts)

/**
 * Byte-identical twin of canonicalize() in src/core/canonical.ts.
 * Rules: UTF-8, keys sorted by UTF-16 code unit, no insignificant whitespace,
 * integers only (floats throw), undefined dropped, arrays keep order.
 */
function canonicalize(value) {
  return encode(value);
}

function encode(v) {
  if (v === null) return 'null';

  const t = typeof v;

  if (t === 'boolean') return v ? 'true' : 'false';

  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalize: non-finite number');
    if (!Number.isInteger(v)) throw new Error('canonicalize: non-integer number');
    if (!Number.isSafeInteger(v)) throw new Error('canonicalize: unsafe integer');
    return String(v);
  }

  if (t === 'string') return JSON.stringify(v);

  if (Array.isArray(v)) return '[' + v.map(encode).join(',') + ']';

  if (t === 'object') {
    const keys = Object.keys(v)
      .filter((k) => v[k] !== undefined)
      .sort(compareCodeUnits);
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + encode(v[k])).join(',') + '}';
  }

  throw new Error(`canonicalize: unsupported type ${t}`);
}

function compareCodeUnits(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ------------------------------------------- event hashing (MIRROR: src/core/events.ts)

/** Byte-identical twin of eventHashInput() in src/core/events.ts. */
function eventHashInput(e) {
  const body = canonicalize({
    seq: e.seq,
    ts: e.ts,
    type: e.type,
    actor: e.actor,
    payload: e.payload,
  });
  return e.prevHash + '\n' + body;
}

function computeEventHash(e) {
  return sha256Hex(eventHashInput(e));
}

function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

/** Mirrors utcDay() / the window helpers in src/services/quotas.ts. */
function utcDay(ts) {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}
function windowFor(kind, ts) {
  if (kind === 'week') return `w${Math.floor(ts / (7 * 86400))}`;
  if (kind === 'month') return `m${Math.floor(ts / (30 * 86400))}`;
  return utcDay(ts);
}

// ------------------------------------------------------------------ ed25519

const keyCache = new Map();

/** Rebuild an Ed25519 SPKI key from the raw 32 bytes (see scripts/keygen.mjs). */
function publicKeyFromRaw(pubkeyB64u) {
  const cached = keyCache.get(pubkeyB64u);
  if (cached !== undefined) return cached;
  let key = null;
  try {
    const raw = Buffer.from(pubkeyB64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (raw.length === 32) {
      key = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
        format: 'der',
        type: 'spki',
      });
    }
  } catch {
    key = null;
  }
  keyCache.set(pubkeyB64u, key);
  return key;
}

function verifySig(pubkeyB64u, sigB64u, message) {
  const key = publicKeyFromRaw(pubkeyB64u);
  if (!key) return false;
  let sig;
  try {
    sig = Buffer.from(sigB64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return edVerify(null, Buffer.from(message, 'utf8'), key, sig);
  } catch {
    return false;
  }
}

/** The society's citizen id derivation: ct_ + first 32 hex of sha256(raw pubkey). */
function citizenIdFromPubkey(pubkeyB64u) {
  const raw = Buffer.from(pubkeyB64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (raw.length !== 32) return null;
  return 'ct_' + createHash('sha256').update(raw).digest('hex').slice(0, 32);
}

// ---------------------------------------------------------------------- http

async function getJson(url, { optional = false, timeoutMs = 20000, attempts = 3 } = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: ac.signal,
        headers: { accept: 'application/json', 'user-agent': 'keyhold-verify/1' },
      });
      if (res.status === 404) {
        if (optional) return null;
        throw new Error(`404 ${url}`);
      }
      if (!res.ok) throw new Error(`HTTP ${res.status} ${url}`);
      return await res.json();
    } catch (err) {
      lastErr = err;
      if (err instanceof SyntaxError) break; // bad JSON will not fix itself
      await sleep(200 * (i + 1));
    } finally {
      clearTimeout(timer);
    }
  }
  if (optional) return null;
  throw lastErr;
}

async function getText(url, { timeoutMs = 20000, attempts = 3 } = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        signal: ac.signal,
        headers: { accept: 'application/x-ndjson, application/json', 'user-agent': 'keyhold-verify/1' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${url}`);
      return await res.text();
    } catch (err) {
      lastErr = err;
      await sleep(200 * (i + 1));
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastErr;
}

async function rpcCall(urls, method, params, { timeoutMs = 20000 } = {}) {
  let lastErr;
  for (const url of urls) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: 'POST',
        signal: ac.signal,
        headers: { 'content-type': 'application/json', 'user-agent': 'keyhold-verify/1' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
      const body = await res.json();
      if (body.error) throw new Error(`${method}: ${body.error.message ?? 'rpc error'}`);
      return body.result;
    } catch (err) {
      lastErr = err;
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastErr ?? new Error('no rpc endpoint reachable');
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ------------------------------------------------------------------ shapes

function pickArray(data, ...keys) {
  if (data == null) return null;
  if (Array.isArray(data)) return data;
  for (const k of keys) if (Array.isArray(data[k])) return data[k];
  if (Array.isArray(data.results)) return data.results;
  if (Array.isArray(data.items)) return data.items;
  return null;
}

function normalizeEvent(raw) {
  const payload =
    typeof raw.payload === 'string' ? JSON.parse(raw.payload) : (raw.payload ?? {});
  return {
    seq: Number(raw.seq),
    ts: Number(raw.ts),
    type: String(raw.type),
    actor: raw.actor == null ? null : String(raw.actor),
    payload,
    sig: raw.sig == null ? null : String(raw.sig),
    prevHash: String(raw.prev_hash ?? raw.prevHash ?? ''),
    hash: String(raw.hash ?? ''),
    // The exact string the actor signed. Without it a request signature cannot
    // be reconstructed, so authorship is uncheckable even on an intact chain.
    signedString:
      raw.sig_material ?? raw.signed_string ?? raw.signedString ?? null,
  };
}

/**
 * One page of the chain.
 *
 * The native format is NDJSON with the payload spliced in as raw text, so the
 * server never re-serializes what it hashed. A fork wrapping the same rows in a
 * JSON envelope is accepted too — the hash check does not care which shape they
 * arrived in.
 */
async function fetchEventPage(url) {
  const text = await getText(url);
  if (text.trim() === '') return [];

  const lines = text.split('\n').filter((l) => l.trim() !== '');
  const rows = [];
  for (const line of lines) {
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      rows.length = 0;
      break;
    }
    if (row === null || typeof row !== 'object' || row.hash === undefined) {
      rows.length = 0;
      break;
    }
    rows.push(row);
  }
  if (rows.length) return rows;

  const data = JSON.parse(text);
  const arr = pickArray(data, 'events');
  if (arr === null) throw new Error(`${url}: neither NDJSON events nor an events array`);
  return arr;
}

/** Pages the whole chain, one page at a time. Never holds more than a page. */
async function* streamEvents(base, limit) {
  let since = 0;
  for (;;) {
    const url = `${base}/export/events?since=${since}&limit=${limit}`;
    const rows = await fetchEventPage(url);
    if (rows.length === 0) return;
    let last = since;
    for (const raw of rows) {
      const e = normalizeEvent(raw);
      last = e.seq;
      yield e;
    }
    if (last <= since) return; // no forward progress; stop rather than loop
    since = last;
  }
}

// ------------------------------------------------------------- claim extraction

const NUMERIC_KEYS_AMOUNT = ['amount_net', 'amount', 'value', 'micro_amount'];
const KEYS_TX = ['txhash', 'tx_hash', 'payout_txhash', 'matched_txhash', 'withdrawal_txhash', 'hash'];
const KEYS_PARTY = ['counterparty', 'from_address', 'pay_to_address', 'to_address', 'address'];

function firstOf(obj, keys) {
  for (const k of keys) {
    const v = obj?.[k];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

/**
 * Any event that claims money moved on Base. These are the rows the blockchain
 * must corroborate; anything here the chain does not confirm is reported.
 */
function extractChainClaim(e) {
  const inflow = e.type.startsWith('treasury.inflow');
  const outflow =
    e.type === 'treasury.outflow_verified' ||
    e.type === 'treasury.outflow_observed' ||
    e.type === 'receipt.paid' ||
    e.type === 'close.settled';
  if (!inflow && !outflow) return null;

  const txhash = firstOf(e.payload, KEYS_TX);
  if (typeof txhash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(txhash)) return null;

  const amount = Number(firstOf(e.payload, NUMERIC_KEYS_AMOUNT));
  const party = firstOf(e.payload, KEYS_PARTY);
  const declared = e.payload?.direction;

  return {
    seq: e.seq,
    type: e.type,
    txhash: txhash.toLowerCase(),
    logIndex: Number.isFinite(Number(e.payload?.log_index)) ? Number(e.payload.log_index) : null,
    direction: declared === 'in' || declared === 'out' ? declared : inflow ? 'in' : 'out',
    counterparty: typeof party === 'string' ? party.toLowerCase() : null,
    amount: Number.isFinite(amount) ? amount : null,
  };
}

/** One ledger leg, from an /export/ledger row or from an event payload. */
function normalizeLeg(o) {
  const debit = o?.debit;
  const credit = o?.credit;
  const amount = Number(o?.amount);
  if (typeof debit !== 'string' || typeof credit !== 'string' || !Number.isFinite(amount)) {
    return null;
  }
  return {
    id: o?.id == null ? null : String(o.id),
    ts: Number.isFinite(Number(o?.ts)) ? Number(o.ts) : null,
    debit,
    credit,
    amount,
    memo: o?.memo ?? null,
    ref_type: o?.ref_type ?? null,
    ref_id: o?.ref_id ?? null,
  };
}

/**
 * The legs an event booked.
 *
 * Money is booked inside the batch of whatever event caused it — a bounty
 * accepted, an inflow matched, a payout verified — so the legs ride in that
 * event's payload under `legs`, whatever its type. Reading only one dedicated
 * event type would find nothing and quietly leave the books unchecked, which is
 * exactly the hole this replaces.
 */
function eventLegs(e) {
  const raw = Array.isArray(e.payload?.legs)
    ? e.payload.legs
    : e.type === 'ledger.entry'
      ? [e.payload]
      : [];
  const out = [];
  for (const item of raw) {
    const leg = normalizeLeg(item);
    if (leg) out.push(leg);
  }
  return out;
}

// --------------------------------------------------------------------- main

async function main() {
  const opts = parseArgs(process.argv);
  const report = new Report(opts);

  report.log('');
  report.log(`${C.bold}keyhold verify${C.off}  ${C.dim}${opts.base}${C.off}`);
  report.log('');

  // ---------------------------------------------------------- 0. discovery
  const manifest =
    (await getJson(`${opts.base}/export/manifest`, { optional: true })) ??
    (await getJson(`${opts.base}/manifest`, { optional: true })) ??
    {};

  const serverCheckpoints = normalizeCheckpoints(
    pickArray(await getJson(`${opts.base}/export/checkpoints`, { optional: true }), 'checkpoints') ?? [],
  );
  const witnessCheckpoints = opts.witness
    ? await loadWitnessCheckpoints(opts.witness, report, opts.full)
    : null;

  // Checkpoints define the seqs the walk must stop and compare at.
  const checkpointBySeq = new Map();
  for (const cp of [...serverCheckpoints, ...(witnessCheckpoints ?? [])]) {
    if (!checkpointBySeq.has(cp.last_seq)) checkpointBySeq.set(cp.last_seq, []);
    checkpointBySeq.get(cp.last_seq).push(cp);
  }

  // ------------------------------------------------- 1..6 single streaming pass
  const state = {
    count: 0,
    prevHash: GENESIS_PREV_HASH,
    prevSeq: 0,
    headSeq: 0,
    headHash: GENESIS_PREV_HASH,
    genesisHash: null,
    firstSeq: null,

    // check 2
    hashAtSeq: new Map(), // seq -> {hash, countUpTo}
    // check 3
    pubkeys: new Map(), // citizen id -> pubkey b64u
    sigTotal: 0,
    sigVerified: 0,
    sigNoMaterial: 0,
    sigFailures: [],
    sigUnknownActor: [],
    sigAnonymous: [],
    // check 4
    policy: { ...FALLBACK_POLICY },
    policySeeded: false,
    citizenCreated: new Map(), // citizen id -> created_at
    quotaCounters: new Map(), // `${citizen}|${window}|${action}` -> n
    quotaViolations: [],
    openClaims: new Map(), // citizen -> n
    claimViolations: [],
    // check 5
    ledgerLegs: 0,
    chainLegs: new Map(), // ledger row id -> {seq, leg}, for the row cross-check
    debitTotals: new Map(),
    creditTotals: new Map(),
    unknownAccounts: new Set(),
    badAmounts: [],
    chainClaims: new Map(), // txhash|logIndex -> claim
    // check 6
    contentIds: new Set(),
    contentIdsOverflowed: false,
    hidden: new Map(), // target key -> {seq, reason_code}
    modActions: 0,
    modBadReason: [],
    modUnhideWithoutHide: [],
    modOrphanTargets: [],
    hideTargets: new Set(),
    // check 7
    profileHash: new Map(), // citizen id -> {seq, hash, capabilities}
    mintedDigests: new Map(), // digest -> {seq, expires_at, marks, standing}
    revokedDigests: new Map(), // digest -> seq
    revokedIds: new Map(), // credential id -> seq (events minted before the id came off the chain)
  };

  for await (const e of streamEvents(opts.base, opts.limit)) {
    // ---- 1. CHAIN --------------------------------------------------------
    if (state.firstSeq === null) {
      state.firstSeq = e.seq;
      if (e.prevHash !== GENESIS_PREV_HASH) {
        report.abort(
          'chain',
          `first exported event (seq ${e.seq}) does not start at the genesis prev-hash`,
          [`expected ${GENESIS_PREV_HASH}`, `saw      ${e.prevHash}`],
        );
      }
      if (e.seq !== 1) {
        report.note(`export starts at seq ${e.seq}, not 1 — verifying from there`);
      }
      state.genesisHash = e.hash;
    } else if (e.prevHash !== state.prevHash) {
      report.abort('chain', `broken link at seq ${e.seq}`, [
        `seq ${state.prevSeq} hash      ${state.prevHash}`,
        `seq ${e.seq} claims prev_hash ${e.prevHash}`,
        'an event was deleted, edited, or inserted between these two',
      ]);
    }

    if (e.seq <= state.prevSeq) {
      report.abort('chain', `sequence went backwards at ${e.seq}`, [
        `previous seq was ${state.prevSeq}`,
      ]);
    }

    let recomputed;
    try {
      recomputed = computeEventHash(e);
    } catch (err) {
      report.abort('chain', `seq ${e.seq} payload is not canonicalizable`, [
        String(err?.message ?? err),
        'all money must be integer micro-USDC; floats break the chain by design',
      ]);
    }
    if (recomputed !== e.hash) {
      report.abort('chain', `hash mismatch at seq ${e.seq} (${e.type})`, [
        `stored     ${e.hash}`,
        `recomputed ${recomputed}`,
        'the stored event does not hash to its stored hash: it was edited',
      ]);
    }

    state.count += 1;
    state.prevHash = e.hash;
    state.prevSeq = e.seq;
    state.headSeq = e.seq;
    state.headHash = e.hash;

    // ---- 2. CHECKPOINTS: remember hashes at published seqs ----------------
    if (checkpointBySeq.has(e.seq)) {
      state.hashAtSeq.set(e.seq, { hash: e.hash, countUpTo: state.count });
    }

    // ---- 3. SIGNATURES ---------------------------------------------------
    absorbIdentity(state, e);
    if (e.sig) verifyEventSignature(state, e);

    // ---- 4. QUOTAS -------------------------------------------------------
    absorbPolicy(state, e);
    checkQuota(state, e);

    // ---- 5. BOOKS --------------------------------------------------------
    const legs = eventLegs(e);
    if (Array.isArray(e.payload?.legs) && e.payload.legs.length !== legs.length) {
      state.badAmounts.push(
        `seq ${e.seq} (${e.type}): ${e.payload.legs.length - legs.length} entr(y/ies) under "legs" are not ledger legs`,
      );
    }
    for (const leg of legs) absorbLeg(state, leg, e.seq);
    const claim = extractChainClaim(e);
    if (claim) {
      state.chainClaims.set(`${claim.txhash}|${claim.logIndex ?? '*'}`, claim);
    }

    // ---- 6. MODERATION ---------------------------------------------------
    absorbModeration(state, e);

    // ---- 7. REGISTER + CREDENTIALS ---------------------------------------
    absorbRegister(state, e);
  }

  if (state.count === 0) {
    report.abort('chain', 'the export returned no events at all', [
      `${opts.base}/export/events?since=0 is empty — there is nothing to verify`,
    ]);
  }

  report.pass(
    'chain',
    `${state.count} events, seq ${state.firstSeq}..${state.headSeq}, unbroken from genesis to ${short(state.headHash)}`,
  );
  report.note(`genesis hash ${state.genesisHash}`);

  // --------------------------------------------------------- 2. CHECKPOINTS
  checkCheckpoints(report, opts, state, serverCheckpoints, witnessCheckpoints);

  // --------------------------------------------------------- 3. SIGNATURES
  checkSignatures(report, state);

  // ------------------------------------------------------------ 4. QUOTAS
  checkQuotaResults(report, state);

  // ------------------------------------------------------------- 5. BOOKS
  await checkBooks(report, opts, state, manifest);

  // -------------------------------------------------------- 6. MODERATION
  await checkModeration(report, opts, state);

  // -------------------------------------- 7. REGISTER + CREDENTIALS
  await checkRegister(report, opts, state);

  report.finish();
}

// ---------------------------------------------------------- check 2 helpers

function normalizeCheckpoints(rows) {
  return rows
    .map((r) => ({
      day: String(r.day ?? r.date ?? ''),
      last_seq: Number(r.last_seq),
      last_hash: String(r.last_hash ?? ''),
      event_count: Number(r.event_count),
      genesis_hash: r.genesis_hash == null ? null : String(r.genesis_hash),
      witness_url: r.witness_url ?? null,
      source: r.__source ?? 'server',
    }))
    .filter((r) => Number.isFinite(r.last_seq) && r.last_hash)
    .sort((a, b) => a.last_seq - b.last_seq);
}

async function loadWitnessCheckpoints(witness, report, full) {
  const index = await getJson(`${witness}/checkpoints/index.json`, { optional: true });
  const listed = pickArray(index, 'checkpoints');
  if (!listed) {
    report.note(
      `no checkpoints/index.json in the witness repo — checkpoint mirroring cannot be enumerated`,
    );
    return [];
  }
  // The index is a convenience; --full re-fetches every day file so a doctored
  // index cannot hide a doctored day.
  let rows = listed;
  if (full) {
    const fetched = [];
    for (const entry of listed) {
      const day = String(entry.day ?? entry.date ?? '');
      if (!day) continue;
      const file = await getJson(`${witness}/checkpoints/${day}.json`, { optional: true });
      if (!file) {
        report.note(`witness repo is missing checkpoints/${day}.json (listed in index.json)`);
        continue;
      }
      fetched.push(file);
    }
    rows = fetched;
  }
  return normalizeCheckpoints(rows.map((r) => ({ ...r, __source: 'witness' })));
}

function checkCheckpoints(report, opts, state, serverCps, witnessCps) {
  const all = [...serverCps, ...(witnessCps ?? [])];
  if (all.length === 0) {
    report.skip('checkpoints', 'no checkpoints published yet — history rewriting is undetectable');
    return;
  }

  const failures = [];
  let compared = 0;

  for (const cp of all) {
    const label = `${cp.source} ${cp.day || `seq ${cp.last_seq}`}`;
    if (cp.last_seq > state.headSeq) {
      failures.push(
        `${label}: claims seq ${cp.last_seq} but the chain only reaches ${state.headSeq} — events are missing from the export`,
      );
      continue;
    }
    const seen = state.hashAtSeq.get(cp.last_seq);
    if (!seen) {
      failures.push(
        `${label}: seq ${cp.last_seq} is absent from the exported chain — that event was removed`,
      );
      continue;
    }
    compared += 1;
    if (seen.hash !== cp.last_hash) {
      failures.push(
        `${label}: hash at seq ${cp.last_seq} is ${short(seen.hash)} but the checkpoint published ${short(cp.last_hash)} — history was rewritten after publication`,
      );
    }
    if (Number.isFinite(cp.event_count) && cp.event_count !== seen.countUpTo) {
      failures.push(
        `${label}: published event_count ${cp.event_count}, chain has ${seen.countUpTo} events up to seq ${cp.last_seq}`,
      );
    }
    if (cp.genesis_hash && state.genesisHash && cp.genesis_hash !== state.genesisHash) {
      failures.push(
        `${label}: genesis_hash ${short(cp.genesis_hash)} != this chain's genesis ${short(state.genesisHash)} — different society`,
      );
    }
  }

  // The real anti-rewrite test: the server's copy must equal the public copy.
  if (witnessCps && serverCps.length) {
    const byDay = new Map(witnessCps.map((c) => [c.day, c]));
    for (const s of serverCps) {
      const w = byDay.get(s.day);
      if (!w) continue;
      if (w.last_seq !== s.last_seq || w.last_hash !== s.last_hash) {
        failures.push(
          `${s.day}: server says seq ${s.last_seq}/${short(s.last_hash)}, public witness says seq ${w.last_seq}/${short(w.last_hash)}`,
        );
      }
    }
  }

  if (failures.length) {
    report.fail('checkpoints', `${failures.length} checkpoint(s) do not match the chain`, failures);
    return;
  }

  const witnessCount = witnessCps ? witnessCps.length : 0;
  if (!opts.witness) {
    report.warn(
      'checkpoints',
      `${compared} server checkpoint(s) match the chain, but with no --witness this only proves self-consistency`,
    );
    return;
  }
  if (witnessCount === 0) {
    report.warn(
      'checkpoints',
      `${compared} checkpoint(s) match, but the witness repo published none — nothing pins this history publicly`,
    );
    return;
  }
  report.pass(
    'checkpoints',
    `${compared} published record(s) match the chain, ${witnessCount} of them mirrored in the public witness repo`,
  );
}

// ---------------------------------------------------------- check 3 helpers

/**
 * Registration events carry the pubkey, so the chain supplies its own key
 * material and needs no external source. Key rotation moves the identity's key
 * forward from the same self-describing events.
 */
function absorbIdentity(state, e) {
  const p = e.payload ?? {};
  const record = (id, pubkey) => {
    if (typeof id !== 'string' || typeof pubkey !== 'string') return;
    const derived = citizenIdFromPubkey(pubkey);
    if (derived && derived !== id) {
      // Article I: the id must derive from the key, or identity is assignable
      // rather than held. An operator who could choose ids could impersonate.
      state.sigFailures.push(
        `seq ${e.seq}: registered id ${id} does not derive from its pubkey (expected ${derived})`,
      );
      return;
    }
    state.pubkeys.set(id, pubkey);
  };

  if (e.type === 'citizen.registered' || e.type === 'citizen.bonded') {
    record(p.id ?? p.citizen_id ?? e.actor, p.pubkey);
    const id = p.id ?? p.citizen_id ?? e.actor;
    if (typeof id === 'string' && !state.citizenCreated.has(id)) {
      state.citizenCreated.set(id, Number(p.created_at ?? e.ts));
    }
  }
  if (e.type === 'citizen.key_rotated') {
    // The successor is a new id derived from the new key; both stay verifiable.
    record(p.to ?? p.successor ?? p.new_id, p.new_pubkey ?? p.pubkey);
    const succ = p.to ?? p.successor ?? p.new_id;
    if (typeof succ === 'string' && !state.citizenCreated.has(succ)) {
      // A rotated key inherits its predecessor's age; probation is not reset.
      const from = p.from ?? p.predecessor ?? e.actor;
      state.citizenCreated.set(
        succ,
        state.citizenCreated.get(from) ?? Number(p.created_at ?? e.ts),
      );
    }
  }
  if (e.type === 'genesis') {
    // The founding offices are seated by the genesis event itself rather than by
    // registration events, so without this the chain cannot verify its own first
    // signatures — the Warden signs seq 1 with a key no later event introduces.
    // These keys are inside the genesis payload, which the genesis hash already
    // commits to, so learning them here trusts nothing the chain does not state.
    if (typeof p.operator_pubkey === 'string') {
      state.pubkeys.set('operator', p.operator_pubkey);
      const opId = citizenIdFromPubkey(p.operator_pubkey);
      if (opId) state.pubkeys.set(opId, p.operator_pubkey);
    }
    for (const wardenKey of Array.isArray(p.warden_pubkeys) ? p.warden_pubkeys : []) {
      if (typeof wardenKey !== 'string') continue;
      const id = citizenIdFromPubkey(wardenKey);
      if (!id) continue;
      state.pubkeys.set(id, wardenKey);
      // The Warden is a citizen from the first moment, so quota replay and
      // eligibility have an age for it like anyone else.
      if (!state.citizenCreated.has(id)) state.citizenCreated.set(id, Number(e.ts));
    }
  }
}

function verifyEventSignature(state, e) {
  state.sigTotal += 1;

  // Registration signs with a key not yet on file; the payload carries it.
  const pubkey =
    (e.actor && state.pubkeys.get(e.actor)) ||
    (typeof e.payload?.pubkey === 'string' ? e.payload.pubkey : null);

  if (!pubkey) {
    if (!e.actor) {
      // A signed event that names no actor claims no identity, so there is
      // nothing to impersonate — a payment intent raised before its payer is a
      // citizen is the ordinary case. Unverifiable, but not evidence of
      // tampering, so it is reported rather than failed.
      state.sigAnonymous.push(`seq ${e.seq} (${e.type})`);
      return;
    }
    state.sigUnknownActor.push(
      `seq ${e.seq} (${e.type}) is signed by ${e.actor}, who was never registered on this chain`,
    );
    return;
  }

  const message = signedMaterial(e);
  if (message === null) {
    state.sigNoMaterial += 1;
    return;
  }

  if (verifySig(pubkey, e.sig, message)) {
    state.sigVerified += 1;
  } else {
    state.sigFailures.push(
      `seq ${e.seq} (${e.type}) by ${e.actor}: signature does not verify against the registered key`,
    );
  }
}

/**
 * The exact bytes the actor signed. `events.sig` is a request signature over
 * KEYHOLD1\nMETHOD\npath\nbody_hash\nts\nnonce (src/core/canonical.ts), and the
 * events table does not store those parts — so the export must hand them back,
 * either as `signed_string` or as `sig_material` inside the payload. Where it
 * does neither, the signature is counted as unverifiable rather than failed:
 * inventing a guess here would produce false accusations.
 */
function signedMaterial(e) {
  // The exported column, which is the ordinary case.
  if (typeof e.sig_material === 'string' && e.sig_material.startsWith('KEYHOLD1\n')) {
    return e.sig_material;
  }
  if (typeof e.signedString === 'string' && e.signedString.startsWith('KEYHOLD1\n')) {
    return e.signedString;
  }
  const m = e.payload?.sig_material;
  if (m && typeof m === 'object') {
    const method = m.method ?? m.m;
    const path = m.path ?? m.p;
    const bodyHash = m.body_hash ?? m.bodyHash;
    const ts = m.ts;
    const nonce = m.nonce;
    if (
      typeof method === 'string' &&
      typeof path === 'string' &&
      typeof bodyHash === 'string' &&
      Number.isFinite(Number(ts)) &&
      typeof nonce === 'string'
    ) {
      return ['KEYHOLD1', method.toUpperCase(), path, bodyHash, String(Number(ts)), nonce].join('\n');
    }
  }
  return null;
}

function checkSignatures(report, state) {
  if (state.sigFailures.length) {
    report.fail(
      'signatures',
      `${state.sigFailures.length} signature(s) do not verify against the chain's own keys`,
      state.sigFailures,
    );
    return;
  }
  if (state.sigUnknownActor.length) {
    report.fail(
      'signatures',
      `${state.sigUnknownActor.length} signed event(s) name an actor with no registration on this chain`,
      state.sigUnknownActor,
    );
    return;
  }
  if (state.sigAnonymous.length) {
    report.note(
      `${state.sigAnonymous.length} signed event(s) name no actor and so cannot be attributed: ${state.sigAnonymous.join(', ')}`,
    );
  }
  if (state.sigTotal === 0) {
    report.skip('signatures', `no signed events in the chain (${state.pubkeys.size} keys registered)`);
    return;
  }
  if (state.sigVerified === 0) {
    report.warn(
      'signatures',
      `${state.sigTotal} signed events but the export exposes no signed_string / sig_material, so none could be checked`,
    );
    report.note(
      'add `signed_string` to /export/events (or `sig_material` to event payloads) to make request signatures independently verifiable',
    );
    return;
  }
  if (state.sigNoMaterial) {
    report.warn(
      'signatures',
      `${state.sigVerified}/${state.sigTotal} signatures verified; ${state.sigNoMaterial} lack exported signing material`,
    );
    return;
  }
  report.pass(
    'signatures',
    `${state.sigVerified}/${state.sigTotal} Ed25519 signatures verify against keys taken from the chain itself`,
  );
}

// ---------------------------------------------------------- check 4 helpers

/** Policy is itself an event stream, so the limit in force at time T is replayable. */
function absorbPolicy(state, e) {
  if (e.type === 'genesis') {
    const seeded = e.payload?.policy;
    if (seeded && typeof seeded === 'object') {
      for (const [k, v] of Object.entries(seeded)) {
        if (typeof v === 'number' || typeof v === 'string') state.policy[k] = v;
      }
      state.policySeeded = true;
    }
  }
  // A parameter change reaches the chain as the executed proposal that caused
  // it — that event carries the key and the value, and the policy row is
  // written in its batch. Reading only policy.changed would leave this replay
  // stuck on the genesis defaults and every quota check below measured against
  // limits the society no longer uses.
  if (e.type === 'policy.changed' || e.type === 'proposal.executed') {
    const changes = Array.isArray(e.payload?.changes)
      ? e.payload.changes
      : [{ key: e.payload?.key ?? e.payload?.policy_key, value: e.payload?.value ?? e.payload?.policy_value }];
    for (const c of changes) {
      if (typeof c?.key !== 'string') continue;
      // A proposal that changes no parameter still executes; it just has
      // nothing to say here.
      if (c.value === null || c.value === undefined) continue;
      let v = c.value;
      if (typeof v === 'string') {
        try {
          const parsed = JSON.parse(v);
          if (typeof parsed === 'number' || typeof parsed === 'string') v = parsed;
        } catch {
          /* a string value is a legitimate policy value */
        }
      }
      state.policy[c.key] = v;
    }
  }
}

/** Mirrors effectiveLimit() in src/services/quotas.ts, including probation scaling. */
function effectiveLimit(state, key, citizenId, now) {
  const base = Number(state.policy[key]);
  if (!Number.isFinite(base)) return null;
  const created = state.citizenCreated.get(citizenId);
  if (created === undefined) return base;
  const probationDays = Number(state.policy['probation.days'] ?? 7);
  if (now - created >= probationDays * 86400) return base;
  const factor = Number(state.policy['probation.quota_factor_pct'] ?? 50);
  return Math.max(1, Math.floor((base * factor) / 100));
}

function checkQuota(state, e) {
  // Concurrency cap rather than a rate: track open claims directly.
  if (e.type === 'bounty.claimed' && e.actor) {
    const n = (state.openClaims.get(e.actor) ?? 0) + 1;
    state.openClaims.set(e.actor, n);
    const limit = Number(state.policy['quota.active_claims']);
    if (Number.isFinite(limit) && n > limit) {
      state.claimViolations.push(
        `seq ${e.seq}: ${e.actor} holds ${n} open claims, cap is ${limit}`,
      );
    }
    return;
  }
  if (e.type === 'bounty.accepted' || e.type === 'bounty.voided') {
    const who = e.payload?.worker_id ?? e.payload?.citizen_id ?? e.payload?.claimant;
    if (typeof who === 'string') {
      state.openClaims.set(who, Math.max(0, (state.openClaims.get(who) ?? 0) - 1));
    }
    return;
  }

  const rule = QUOTA_EVENTS[e.type];
  if (!rule || !e.actor) return;

  const win = windowFor(rule.window, e.ts);
  const key = `${e.actor}|${win}|${rule.action}`;
  const used = (state.quotaCounters.get(key) ?? 0) + 1;
  state.quotaCounters.set(key, used);

  const limit = effectiveLimit(state, rule.key, e.actor, e.ts);
  if (limit === null) return;
  if (used > limit) {
    state.quotaViolations.push(
      `seq ${e.seq}: ${e.actor} performed ${rule.action} #${used} in window ${win}, but the limit in force was ${limit}`,
    );
  }
}

function checkQuotaResults(report, state) {
  const violations = [...state.quotaViolations, ...state.claimViolations];
  if (violations.length) {
    report.fail(
      'quotas',
      `${violations.length} action(s) exceeded the quota in force at the time`,
      violations,
    );
    return;
  }
  const spends = state.quotaCounters.size;
  if (spends === 0) {
    report.skip('quotas', 'no quota-consuming events in the chain yet');
    return;
  }
  const detail = `${spends} citizen-window-action buckets replayed, none over limit${
    state.policySeeded ? '' : ' (genesis event carried no policy; used genesis defaults)'
  }`;
  if (state.policySeeded) report.pass('quotas', detail);
  else report.warn('quotas', detail);
}

// ---------------------------------------------------------- check 5 helpers

function absorbLeg(state, leg, seq) {
  if (!Number.isInteger(leg.amount) || leg.amount <= 0) {
    state.badAmounts.push(
      `seq ${seq}: ledger amount ${leg.amount} is not a positive integer of micro-USDC`,
    );
    return;
  }
  if (leg.debit === leg.credit) {
    state.badAmounts.push(`seq ${seq}: ledger leg debits and credits the same account ${leg.debit}`);
    return;
  }
  if (!ACCOUNTS.has(leg.debit)) state.unknownAccounts.add(leg.debit);
  if (!ACCOUNTS.has(leg.credit)) state.unknownAccounts.add(leg.credit);
  state.ledgerLegs += 1;
  state.debitTotals.set(leg.debit, (state.debitTotals.get(leg.debit) ?? 0) + leg.amount);
  state.creditTotals.set(leg.credit, (state.creditTotals.get(leg.credit) ?? 0) + leg.amount);

  // Without an id a leg cannot be matched to its row, only totalled. Say so
  // rather than counting it as reconciled.
  if (leg.id === null) {
    state.badAmounts.push(`seq ${seq}: ledger leg carries no id, so no row can be matched to it`);
    return;
  }
  const seen = state.chainLegs.get(leg.id);
  if (seen) {
    state.badAmounts.push(
      `ledger leg ${leg.id} is booked twice, at seq ${seen.seq} and seq ${seq}`,
    );
    return;
  }
  state.chainLegs.set(leg.id, { seq, leg });
}

const LEG_FIELDS = ['ts', 'debit', 'credit', 'amount', 'memo', 'ref_type', 'ref_id'];

/**
 * Reconcile the ledger table against the legs the chain committed.
 *
 * Every row must be named by an event payload, at the seq the row itself cites,
 * with identical values; every leg the chain booked must exist as a row. A row
 * inserted, altered, or deleted outside appendEvent shows up here as one of
 * three problems, and each one is a failure — the whole point of the books being
 * inside the hash chain is that this comparison cannot be waved through.
 *
 * Streams the export a page at a time and matches against the in-memory chain
 * legs, so the memory cost is the chain's, which the single pass already paid.
 */
async function reconcileLedgerExport(opts, state) {
  const PAGE = 2000;
  const unmatched = new Map(state.chainLegs);
  const problems = [];
  let from = 0;
  let rows = 0;

  for (;;) {
    const data = await getJson(`${opts.base}/export/ledger?from=${from}&limit=${PAGE}`, {
      optional: true,
    });
    const page = pickArray(data, 'entries', 'ledger');
    if (page === null) return from === 0 ? null : { rows, problems };
    if (page.length === 0) break;

    for (const r of page) {
      rows += 1;
      const row = normalizeLeg(r);
      if (!row) {
        problems.push(`/export/ledger row ${r?.id ?? '(no id)'} is not a well-formed ledger leg`);
        continue;
      }
      if (row.id === null) {
        problems.push('/export/ledger returned a row with no id; it cannot be tied to any event');
        continue;
      }
      const booked = unmatched.get(row.id);
      if (!booked) {
        problems.push(
          state.chainLegs.has(row.id)
            ? `/export/ledger returns row ${row.id} more than once`
            : `ledger row ${row.id} (event_seq ${r?.event_seq ?? '?'}) is in the table but no event booked it — it was written outside the chain`,
        );
        continue;
      }
      unmatched.delete(row.id);

      const rowSeq = Number(r?.event_seq);
      if (rowSeq !== booked.seq) {
        problems.push(
          `ledger row ${row.id} cites event_seq ${r?.event_seq}, but seq ${booked.seq} is the event that booked it`,
        );
      }
      for (const f of LEG_FIELDS) {
        if (booked.leg[f] !== row[f]) {
          problems.push(
            `ledger row ${row.id} has ${f} ${JSON.stringify(row[f])}, but seq ${booked.seq} booked ${JSON.stringify(booked.leg[f])}`,
          );
        }
      }
    }

    const cursor = Number(data?.next_from ?? data?.next ?? NaN);
    const nextFrom = Number.isFinite(cursor) && cursor > from ? cursor : from + page.length;
    if (nextFrom <= from) break;
    from = nextFrom;
    if (page.length < PAGE && !Number.isFinite(cursor)) break;
  }

  for (const [id, booked] of unmatched) {
    problems.push(
      `seq ${booked.seq} booked ledger leg ${id} (${booked.leg.debit} → ${booked.leg.credit}, ${usd(booked.leg.amount)}) but /export/ledger has no such row — the row was deleted or never written`,
    );
  }

  return { rows, problems };
}

async function checkBooks(report, opts, state, manifest) {
  // Balances come from the chain, never from the table: the payload is what the
  // event hash covers, so replaying it is the only reading nobody can edit.
  const chainLegs = state.ledgerLegs;
  const reconciled = await reconcileLedgerExport(opts, state);
  const booksExposed = chainLegs > 0 || reconciled !== null;

  const failures = [...state.badAmounts];

  if (reconciled === null) {
    report.note(
      'no /export/ledger endpoint; the books were rebuilt from event payloads and could not be cross-checked against the tables',
    );
  } else {
    failures.push(...reconciled.problems);
    if (reconciled.problems.length === 0) {
      report.note(
        `${plural(reconciled.rows, 'ledger row')} in /export/ledger, each matched to the event that booked it`,
      );
    }
  }

  const debits = sum(state.debitTotals.values());
  const credits = sum(state.creditTotals.values());

  if (state.ledgerLegs > 0 && debits !== credits) {
    failures.push(
      `debits total ${usd(debits)} but credits total ${usd(credits)} — the books do not balance`,
    );
  }

  if (state.unknownAccounts.size) {
    report.note(
      `ledger uses ${state.unknownAccounts.size} account name(s) not in ACCOUNTS: ${[...state.unknownAccounts].join(', ')}`,
    );
  }

  // --- on-chain corroboration ----------------------------------------------
  const claims = [...state.chainClaims.values()];
  let onchainDetail = '';

  if (claims.length && opts.rpc.length) {
    const treasury =
      opts.treasury ?? lower(manifest.treasury_address) ?? lower(manifest.treasury) ?? null;
    const usdc = opts.usdc ?? lower(manifest.usdc_contract) ?? lower(manifest.usdc) ?? null;

    if (!treasury) {
      report.note(
        'no treasury address (pass --treasury or expose it in /export/manifest); on-chain match skipped',
      );
      onchainDetail = `, ${claims.length} txhash claim(s) unverified (no treasury address)`;
    } else {
      const problems = await corroborateOnChain(opts.rpc, claims, treasury, usdc, report);
      failures.push(...problems);
      onchainDetail = `, ${claims.length - problems.length}/${claims.length} on-chain claim(s) corroborated on Base`;
    }
  } else if (claims.length) {
    report.note(
      `${claims.length} ledger claim(s) reference a txhash; pass --rpc to confirm them against Base`,
    );
    onchainDetail = `, ${claims.length} txhash claim(s) unverified (no --rpc)`;
  }

  if (failures.length) {
    report.fail('books', `${failures.length} problem(s) in the books`, failures);
    return;
  }
  if (state.ledgerLegs > 0) {
    report.pass(
      'books',
      `${plural(state.ledgerLegs, 'leg')} replayed from the chain balance at ${usd(debits)} across ${
        new Set([...state.debitTotals.keys(), ...state.creditTotals.keys()]).size
      } accounts${reconciled === null ? '' : ', and every ledger row matches'}${onchainDetail}`,
    );
    printTrialBalance(report, state);
    return;
  }
  if (!booksExposed) {
    report.skip('books', 'no ledger entries and no /export/ledger endpoint — the books are not exposed');
    return;
  }
  report.pass('books', `the books are empty and balanced${onchainDetail}`);
}

function printTrialBalance(report, state) {
  const accounts = new Set([...state.debitTotals.keys(), ...state.creditTotals.keys()]);
  const w = Math.max(...[...accounts].map((a) => a.length), 8);
  report.note('trial balance (micro-USDC):');
  for (const a of [...accounts].sort()) {
    const d = state.debitTotals.get(a) ?? 0;
    const c = state.creditTotals.get(a) ?? 0;
    report.note(`  ${a.padEnd(w)}  dr ${usd(d).padStart(14)}  cr ${usd(c).padStart(14)}  net ${usd(d - c).padStart(14)}`);
  }
}

/**
 * Every ledger row that claims money moved must be corroborated by a real USDC
 * Transfer in a real, successful transaction, with the exact amount and the
 * exact counterparty. A row the blockchain does not confirm is reported.
 */
async function corroborateOnChain(rpcUrls, claims, treasury, usdc, report) {
  const problems = [];
  const receipts = new Map();
  const CONCURRENCY = 4;

  const hashes = [...new Set(claims.map((c) => c.txhash))];
  for (let i = 0; i < hashes.length; i += CONCURRENCY) {
    const slice = hashes.slice(i, i + CONCURRENCY);
    const got = await Promise.all(
      slice.map(async (h) => {
        try {
          return [h, await rpcCall(rpcUrls, 'eth_getTransactionReceipt', [h])];
        } catch (err) {
          return [h, { __error: String(err?.message ?? err) }];
        }
      }),
    );
    for (const [h, r] of got) receipts.set(h, r);
  }

  for (const claim of claims) {
    if (!receipts.has(claim.txhash)) {
      problems.push(`seq ${claim.seq}: ${claim.txhash} was never queried`);
      continue;
    }
    const receipt = receipts.get(claim.txhash);
    if (receipt == null) {
      // A null result means the node has no such transaction. The books claim
      // money the blockchain has no record of moving.
      problems.push(
        `seq ${claim.seq}: ${claim.txhash} does not exist on Base — the books claim ${usd(claim.amount)} that the chain never moved`,
      );
      continue;
    }
    if (receipt.__error) {
      problems.push(`seq ${claim.seq}: ${claim.txhash} could not be read from Base (${receipt.__error})`);
      continue;
    }
    if (receipt.status !== undefined && receipt.status !== '0x1') {
      problems.push(`seq ${claim.seq}: ${claim.txhash} reverted (status ${receipt.status}) but the books count it`);
      continue;
    }

    const transfers = (receipt.logs ?? [])
      .filter(
        (l) =>
          (!usdc || lower(l.address) === usdc) &&
          lower(l.topics?.[0]) === TRANSFER_TOPIC,
      )
      .map((l) => ({
        logIndex: Number(l.logIndex),
        from: addrFromTopic(l.topics?.[1]),
        to: addrFromTopic(l.topics?.[2]),
        value: BigInt(l.data ?? '0x0'),
      }));

    if (transfers.length === 0) {
      problems.push(
        `seq ${claim.seq}: ${claim.txhash} contains no USDC transfer${usdc ? ` from ${usdc}` : ''}`,
      );
      continue;
    }

    const wantAmount = claim.amount === null ? null : BigInt(claim.amount);
    const match = transfers.find((t) => {
      const directionOk = claim.direction === 'in' ? t.to === treasury : t.from === treasury;
      if (!directionOk) return false;
      const other = claim.direction === 'in' ? t.from : t.to;
      const partyOk = claim.counterparty === null || other === claim.counterparty;
      const amountOk = wantAmount === null || t.value === wantAmount;
      const indexOk = claim.logIndex === null || t.logIndex === claim.logIndex;
      return partyOk && amountOk && indexOk;
    });

    if (!match) {
      const shown = transfers
        .slice(0, 4)
        .map((t) => `log ${t.logIndex}: ${short(t.from)} -> ${short(t.to)} ${usd(Number(t.value))}`)
        .join('; ');
      problems.push(
        `seq ${claim.seq}: ${claim.type} claims ${claim.direction} ${usd(claim.amount)} with ${short(claim.counterparty ?? 'unknown')} in ${claim.txhash}, but that transaction shows [${shown}]`,
      );
    }
  }

  if (problems.length === 0) {
    report.note(`${claims.length} on-chain claim(s) confirmed against Base`);
  }
  return problems;
}

function addrFromTopic(topic) {
  if (typeof topic !== 'string' || topic.length < 42) return null;
  return '0x' + topic.slice(-40).toLowerCase();
}

// ---------------------------------------------------------- check 6 helpers

function absorbModeration(state, e) {
  // Remember what exists, so a hide can be tied back to a real item.
  const id = e.payload?.id;
  if (typeof id === 'string' && (e.type === 'post.created' || e.type === 'comment.created')) {
    if (state.contentIds.size < CONTENT_ID_CAP) {
      state.contentIds.add(`${e.type === 'post.created' ? 'post' : 'comment'}:${id}`);
    } else {
      state.contentIdsOverflowed = true;
    }
  }

  if (e.type !== 'moderation.action') return;
  state.modActions += 1;

  const p = e.payload ?? {};
  const action = String(p.action ?? '');
  const targetType = String(p.target_type ?? '');
  const targetId = String(p.target_id ?? '');
  const reasonCode = String(p.reason_code ?? '');
  const key = `${targetType}:${targetId}`;

  if (!REASON_CODES.has(reasonCode)) {
    state.modBadReason.push(
      `seq ${e.seq}: moderation on ${key} carries reason_code "${reasonCode}", which is not an Article IV ground`,
    );
  }
  if (!targetType || !targetId) {
    state.modBadReason.push(`seq ${e.seq}: moderation action "${action}" names no target`);
  }

  if (action === 'hide') {
    state.hidden.set(key, { seq: e.seq, reasonCode });
    state.hideTargets.add(key);
    if (
      (targetType === 'post' || targetType === 'comment') &&
      !state.contentIdsOverflowed &&
      !state.contentIds.has(key)
    ) {
      state.modOrphanTargets.push(
        `seq ${e.seq}: hid ${key}, but no creation event for it exists in the chain`,
      );
    }
  } else if (action === 'unhide') {
    if (!state.hidden.has(key)) {
      state.modUnhideWithoutHide.push(`seq ${e.seq}: unhid ${key}, which was never hidden`);
    }
    state.hidden.delete(key);
  }
}

async function checkModeration(report, opts, state) {
  const failures = [
    ...state.modBadReason,
    ...state.modUnhideWithoutHide,
    ...state.modOrphanTargets,
  ];

  // Cross-check: anything the server currently serves as hidden must have a
  // logged reason. A quiet hide with no log entry is the failure this catches.
  const modExport = await getJson(`${opts.base}/export/hidden`, { optional: true });
  const hiddenRows = pickArray(modExport, 'hidden', 'items');
  if (hiddenRows) {
    for (const row of hiddenRows) {
      const key = `${row.target_type ?? row.type ?? 'post'}:${row.id ?? row.target_id}`;
      if (!state.hidden.has(key)) {
        failures.push(
          `${key} is hidden on the server but no moderation.action in the chain hid it — content was suppressed off the record`,
        );
      }
    }
    report.note(`cross-checked ${hiddenRows.length} server-reported hidden item(s)`);
  } else {
    report.note('no /export/hidden endpoint; hidden state derived from the chain alone');
  }

  if (state.contentIdsOverflowed) {
    report.note(
      `more than ${CONTENT_ID_CAP} content ids; the hide-target existence check was relaxed to conserve memory`,
    );
  }

  if (failures.length) {
    report.fail('moderation', `${failures.length} moderation problem(s)`, failures);
    return;
  }
  if (state.modActions === 0) {
    report.pass('moderation', 'nothing has been hidden, nothing was deleted');
    return;
  }
  report.pass(
    'moderation',
    `${state.modActions} moderation action(s), all with Article IV reason codes; ${state.hidden.size} item(s) currently hidden, none deleted`,
  );
}

// ------------------------------------------- check 7: register + credentials

/**
 * The chain publishes hashes; the tables hold the preimages. Neither half
 * proves anything alone, and until these two were compared a `citizen_profiles`
 * row rewritten outside the chain — a redirected `endpoint_url`, which is the
 * field agents actually connect to — was undetectable from out here, and a
 * rewritten `credentials` row with a freshly recomputed digest was certified by
 * the instance's own verify endpoint.
 */
function absorbRegister(state, e) {
  if (e.type === 'citizen.profile_set' && e.actor) {
    state.profileHash.set(e.actor, {
      seq: e.seq,
      hash: e.payload?.profile_hash,
      capabilities: Array.isArray(e.payload?.capabilities) ? e.payload.capabilities : null,
      accepting_work: e.payload?.accepting_work === true,
    });
  }
  if (e.type === 'credential.issued' && typeof e.payload?.digest === 'string') {
    state.mintedDigests.set(e.payload.digest, {
      seq: e.seq,
      expires_at: e.payload.expires_at,
      marks: e.payload.marks,
      standing: e.payload.standing,
    });
  }
  if (e.type === 'credential.revoked') {
    // A chain is append-only, so every shape it has ever carried is permanent.
    // Revocations minted before the credential id came off the public log name
    // the credential by id; ones after it name the digest. Both are read here,
    // because a verifier that only understands today's payload reports the
    // history it cannot parse as a discrepancy.
    if (typeof e.payload?.digest === 'string') {
      state.revokedDigests.set(e.payload.digest, e.seq);
    }
    if (typeof e.payload?.id === 'string') {
      state.revokedIds.set(e.payload.id, e.seq);
    }
  }
}

function profileHashOf(row, capabilities) {
  return sha256Hex(
    'KEYHOLD1-PROFILE\n' +
      canonicalize({
        accepting_work: row.accepting_work === 1 || row.accepting_work === true,
        capabilities,
        endpoint_url: row.endpoint_url ?? null,
        summary: row.summary,
      }),
  );
}

async function snapshotTable(base, name) {
  const data = await getJson(`${base}/export/snapshot?table=${name}&limit=2000`, {
    optional: true,
  });
  const rows = data?.tables?.[name];
  return Array.isArray(rows) ? rows : null;
}

async function checkRegister(report, opts, state) {
  const declared = state.profileHash.size;
  const minted = state.mintedDigests.size;

  if (declared === 0 && minted === 0) {
    report.skip('register', 'nothing declared and nothing minted yet');
    return;
  }

  const profiles = await snapshotTable(opts.base, 'citizen_profiles');
  const capRows = await snapshotTable(opts.base, 'citizen_capabilities');
  const creds = await snapshotTable(opts.base, 'credentials');

  if (profiles === null && creds === null) {
    report.warn(
      'register',
      `${declared} declaration(s) and ${minted} credential(s) on the chain, but /export/snapshot does not serve citizen_profiles or credentials — the preimages of those hashes are not published, so what the register SHOWS cannot be checked against what the chain RECORDED`,
    );
    return;
  }

  const failures = [];
  let profilesChecked = 0;
  let credsChecked = 0;

  if (profiles) {
    const caps = new Map();
    for (const r of capRows ?? []) {
      if (!caps.has(r.citizen_id)) caps.set(r.citizen_id, []);
      caps.get(r.citizen_id).push(r.tag);
    }
    for (const row of profiles) {
      const chain = state.profileHash.get(row.citizen_id);
      if (!chain) {
        failures.push(
          `${row.citizen_id} has a register entry but no citizen.profile_set in the chain wrote it — the declaration was written outside the chain`,
        );
        continue;
      }
      const tags = (caps.get(row.citizen_id) ?? []).slice().sort();
      if (chain.capabilities && chain.capabilities.join(',') !== tags.join(',')) {
        failures.push(
          `${row.citizen_id} is listed under [${tags.join(', ')}] but the chain recorded [${chain.capabilities.join(', ')}] at seq ${chain.seq}`,
        );
      }
      const recomputed = profileHashOf(row, chain.capabilities ?? tags);
      if (row.profile_hash !== chain.hash) {
        failures.push(
          `${row.citizen_id} serves profile_hash ${short(row.profile_hash)} but the chain published ${short(chain.hash)} at seq ${chain.seq}`,
        );
      } else if (recomputed !== chain.hash) {
        failures.push(
          `${row.citizen_id}: the summary/endpoint_url/accepting_work served do NOT hash to the profile_hash the chain published at seq ${chain.seq} — the entry was edited outside the chain (recomputed ${short(recomputed)})`,
        );
      }
      profilesChecked += 1;
    }
  }

  if (creds) {
    for (const row of creds) {
      const chain = state.mintedDigests.get(row.digest);
      if (!chain) {
        failures.push(
          `credential ${row.id} carries digest ${short(row.digest)}, which no credential.issued event in the chain ever minted — the row was written or altered outside the chain`,
        );
        continue;
      }
      let recomputed;
      try {
        recomputed = sha256Hex('KEYHOLD1-CREDENTIAL\n' + canonicalize(JSON.parse(row.claims)));
      } catch (err) {
        failures.push(`credential ${row.id}: claims are not canonical JSON (${String(err?.message ?? err)})`);
        continue;
      }
      if (recomputed !== row.digest) {
        failures.push(
          `credential ${row.id}: the claims served do not hash to the digest beside them (${short(recomputed)} vs ${short(row.digest)})`,
        );
      }
      if (Number(row.event_seq) !== chain.seq) {
        failures.push(
          `credential ${row.id} names event ${row.event_seq}; the chain minted that digest at ${chain.seq}`,
        );
      }
      const revokedAt = state.revokedDigests.get(row.digest) ?? state.revokedIds.get(row.id);
      if (row.status === 'revoked' && revokedAt === undefined) {
        failures.push(`credential ${row.id} is served as revoked but no credential.revoked event withdrew it`);
      }
      if (revokedAt !== undefined && row.status !== 'revoked') {
        failures.push(
          `credential ${row.id} was revoked on the chain at seq ${revokedAt} but is still served as ${row.status}`,
        );
      }
      credsChecked += 1;
    }
  }

  if (failures.length) {
    report.fail(
      'register',
      `${failures.length} register/credential row(s) disagree with the chain`,
      failures,
    );
    return;
  }
  report.pass(
    'register',
    `${profilesChecked} declaration(s) and ${credsChecked} credential(s) hash to exactly what the chain recorded`,
  );
}

// ------------------------------------------------------------------ helpers

function sum(iter) {
  let t = 0;
  for (const v of iter) t += v;
  return t;
}

function lower(v) {
  return typeof v === 'string' && v ? v.toLowerCase() : null;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function short(h) {
  if (typeof h !== 'string') return String(h);
  return h.length > 18 ? `${h.slice(0, 10)}…${h.slice(-6)}` : h;
}

/** micro-USDC to a human string; never used for arithmetic. */
function usd(micro) {
  if (micro === null || micro === undefined) return 'unknown';
  const n = Number(micro);
  const sign = n < 0 ? '-' : '';
  const abs = Math.abs(n);
  const whole = Math.floor(abs / 1_000_000);
  const frac = String(abs % 1_000_000).padStart(6, '0').replace(/0+$/, '');
  return `${sign}$${whole}${frac ? '.' + frac : ''}`;
}

main().catch((err) => {
  process.stderr.write(`\n${C.red}verify: ${err?.stack ?? err}${C.off}\n`);
  process.exit(1);
});
