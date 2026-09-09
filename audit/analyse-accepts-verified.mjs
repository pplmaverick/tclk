#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// How much of the accepted-but-unlocked funnel is abandonment? — the
// signature-verified measurement.
//
// This is the successor to analyse-accepts.mjs. That script answered "did our
// own accepts lose to a rival, or did nobody lock at all?" by counting accept
// frames as they appear on the board. This one asks the same question of the
// board as a whole, and adds the step that turned out to change every number:
//
//   * it VERIFIES each record's Ed25519 signature before counting it. On the
//     sample this was written against, only 51.8% of board records and 38.1% of
//     accept frames carry a valid signature, and including the rest roughly
//     halves the measured lock rate (13.3% -> 26.0%) and doubles the apparent
//     competition (median 4 rivals -> median 1). An unsigned record is not
//     attributable to the DID it names, so it is not a competitor and its
//     absence of a lock proves nothing.
//   * it splits the unlocked remainder into deals a fail-closed payer COULD
//     have locked (>=1 accept carrying `contract`) and deals where every accept
//     omitted the field, which is a different problem with a different fix.
//
// Everything else is carried over from analyse-accepts.mjs, including the two
// traps that make this harder than grepping:
//   1. The export's `text` field is a JSON string containing another JSON
//      document, so it must be decoded twice — splitting on quotes or commas
//      mis-parses it.
//   2. Most accepts omit `contract`, so their deal room cannot be read off the
//      frame. It is re-derived with the library's own contractId(offer,
//      acceptCore); canonical JSON and the domain hash have to match the
//      protocol exactly, which is why the tclk build is imported rather than
//      reimplemented.
//
// Crypto is deliberately dependency-free (node:crypto + a small base58 decoder)
// so this runs anywhere Node does; only the tclk build is needed, for
// contractId/dealRoom. Cross-checked against a @noble/curves implementation:
// identical verdicts on all 16,718 records of the sample export.
//
// Usage:
//   node analyse-accepts-verified.mjs <board-export.jsonl> [--sample N] [--room NAME]
//   TCLK_DIST=/path/to/tclk/dist/index.js   # if the build is not found automatically
//
// Read-only: every venue call is a GET. Nothing is posted, written or signed.

import { readFileSync } from "node:fs";
import { createPublicKey, verify as ed25519Verify } from "node:crypto";

// ── the tclk build (contractId, dealRoom) ────────────────────────────────────

const DIST_CANDIDATES = [
  process.env.TCLK_DIST,
  new URL("../dist/index.js", import.meta.url).href, // script in a subdirectory of the repo
  new URL("./dist/index.js", import.meta.url).href,  // script at the repo root
  "/Users/pplmaverick/tclk-audit/dist/index.js",     // local checkout fallback
].filter(Boolean);

async function loadTclk() {
  const tried = [];
  for (const candidate of DIST_CANDIDATES) {
    try { return await import(candidate); } catch (err) { tried.push(`${candidate} (${err.code ?? err.message})`); }
  }
  throw new Error(`could not load the tclk build. Set TCLK_DIST. Tried:\n  ${tried.join("\n  ")}`);
}
const { contractId, dealRoom } = await loadTclk();

// ── arguments ────────────────────────────────────────────────────────────────

const OPTIONS = { "--sample": "sample", "--room": "room" };
const opts = { sample: "150", room: "tclk-offers" };
let EXPORT_PATH = null;
for (let i = 0; i < process.argv.length - 2; i += 1) {
  const arg = process.argv[i + 2];
  const key = OPTIONS[arg];
  if (key) { opts[key] = process.argv[i + 3]; i += 1; continue; }
  if (!arg.startsWith("--") && EXPORT_PATH === null) EXPORT_PATH = arg;
}
const SAMPLE_N = Number(opts.sample);
const ROOM = opts.room;
const BASE = process.env.TECHNOCORE_URL ?? "https://technocore.chat";

if (!EXPORT_PATH) {
  console.error("usage: node analyse-accepts-verified.mjs <board-export.jsonl> [--sample N] [--room NAME]");
  process.exit(2);
}

// ── Ed25519 record signatures ────────────────────────────────────────────────
//
// A room message is signed over `${room}|${nonce}|${text}` (see mcp/signing.js).
// The DID is multibase base58btc of multicodec ed25519-pub || the raw key.

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/** Bitcoin-alphabet base58 decode. Null on any character outside the alphabet. */
function base58Decode(text) {
  let acc = 0n;
  for (const ch of text) {
    const digit = B58_ALPHABET.indexOf(ch);
    if (digit < 0) return null;
    acc = acc * 58n + BigInt(digit);
  }
  const bytes = [];
  while (acc > 0n) { bytes.unshift(Number(acc & 0xffn)); acc >>= 8n; }
  for (const ch of text) { if (ch !== "1") break; bytes.unshift(0); } // leading zeros
  return Uint8Array.from(bytes);
}

/** DER prefix for an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows. */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
/** Canonical unpadded base64url of 64 bytes: 86 chars, the last carrying 2 bits. */
const CANONICAL_SIG = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** The raw 32-byte Ed25519 public key inside a did:key:z6Mk… string, or null. */
function pubkeyFromDid(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  const multi = base58Decode(did.slice("did:key:z".length));
  if (!multi || multi.length !== 34) return null;
  if (multi[0] !== 0xed || multi[1] !== 0x01) return null; // multicodec ed25519-pub
  return Buffer.from(multi.slice(2));
}

/**
 * True iff the record carries a valid signature by the DID it claims.
 *
 * This is the whole point of the script: the venue accepts unsigned writes, so
 * `from` is a claim until this returns true. An unsigned record is not evidence
 * about the party it names, in either direction.
 */
function verifyRecord(record, room) {
  const { from, sig, nonce, text } = record ?? {};
  if (typeof sig !== "string" || !CANONICAL_SIG.test(sig)) return false;
  const rawKey = pubkeyFromDid(from);
  if (!rawKey) return false;
  const signature = Buffer.from(sig, "base64url");
  if (signature.length !== 64) return false;
  try {
    const key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, rawKey]), format: "der", type: "spki",
    });
    return ed25519Verify(null, Buffer.from(`${room}|${nonce}|${text}`, "utf8"), key, signature);
  } catch {
    return false;
  }
}

// ── export parsing ───────────────────────────────────────────────────────────

/** Records plus the tclk frames inside them, each tagged with its signature verdict. */
function loadExport(path, room) {
  const records = [], frames = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let record; try { record = JSON.parse(line); } catch { continue; }
    const verified = verifyRecord(record, room);
    records.push({ record, verified });
    const text = record.text ?? "";
    if (!text.startsWith("tclk1 ")) continue;
    let frame; try { frame = JSON.parse(text.slice(6)); } catch { continue; }
    if (frame && typeof frame === "object") frames.push({ record, frame, verified });
  }
  return { records, frames };
}

/** One entry per (from, nonce), oldest first — the venue can echo a record twice. */
function uniqueAccepts(list) {
  const seen = new Set(), out = [];
  for (const item of list) {
    const key = `${item.frame.from}|${item.frame.nonce}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out.sort((a, b) => a.record.seq - b.record.seq);
}

/** The contract id an accept names, or re-derived when the frame omits it. */
function contractOf(accept, offer) {
  if (typeof accept.contract === "string") return accept.contract;
  if (!offer) return null;
  try {
    return contractId(offer, {
      from: accept.from, ref: accept.ref, statement: accept.statement,
      paymentKey: accept.paymentKey, nonce: accept.nonce,
    });
  } catch { return null; }
}

// ── venue (read-only) ────────────────────────────────────────────────────────

const roomCache = new Map();
/** Frame types sitting in a contract's derived deal room; null means unknown. */
async function roomFrameKinds(contract) {
  if (roomCache.has(contract)) return roomCache.get(contract);
  let kinds = null;
  try {
    const res = await fetch(`${BASE}/r/${dealRoom(contract)}?format=json`, { signal: AbortSignal.timeout(20_000) });
    if (res.ok) {
      const body = await res.json();
      kinds = (body.messages ?? []).map((m) => {
        const t = m.text ?? "";
        if (!t.startsWith("tclk1 ")) return "(text)";
        try { return JSON.parse(t.slice(6)).type; } catch { return "?"; }
      });
    }
  } catch { /* leave null: unknown, never silently "empty" */ }
  roomCache.set(contract, kinds);
  return kinds;
}

/** Warm the cache concurrently; the venue answers a room read in well under 300ms. */
async function probeMany(contracts, concurrency = 12) {
  const todo = [...new Set(contracts.filter((c) => c && !roomCache.has(c)))];
  for (let i = 0; i < todo.length; i += concurrency) {
    await Promise.all(todo.slice(i, i + concurrency).map(roomFrameKinds));
  }
  return todo.length;
}

// ── statistics ───────────────────────────────────────────────────────────────

/** Wilson score interval — the sane one for proportions this small. */
function wilson(successes, trials, z = 1.96) {
  if (trials === 0) return [0, 0];
  const p = successes / trials;
  const den = 1 + (z * z) / trials;
  const centre = (p + (z * z) / (2 * trials)) / den;
  const half = (z * Math.sqrt((p * (1 - p)) / trials + (z * z) / (4 * trials * trials))) / den;
  return [centre - half, centre + half];
}
const pct = (n, d) => `${((100 * n) / d).toFixed(1)}%`;
function summarise(counts) {
  const sorted = [...counts].sort((a, b) => a - b);
  return {
    n: sorted.length,
    mean: sorted.reduce((s, c) => s + c, 0) / sorted.length,
    median: sorted[sorted.length >> 1],
    max: sorted.at(-1),
    contested: sorted.filter((c) => c > 1).length,
  };
}

// ── main ─────────────────────────────────────────────────────────────────────

const { records, frames } = loadExport(EXPORT_PATH, ROOM);
const verifiedRecords = records.filter((r) => r.verified).length;
const first = records[0]?.record.ts, last = records.at(-1)?.record.ts;

console.log(`export ${EXPORT_PATH}  room ${ROOM}`);
console.log(`  ${records.length} records, ${first} .. ${last}`);
console.log(`  signature-verified: ${verifiedRecords} (${pct(verifiedRecords, records.length)})`);

const accepts = frames.filter((f) => f.frame.type === "accept");
const verifiedAccepts = accepts.filter((f) => f.verified);
const carries = (list) => list.filter((f) => typeof f.frame.contract === "string").length;
console.log(`\naccept frames: ${accepts.length}, verified ${verifiedAccepts.length} (${pct(verifiedAccepts.length, accepts.length)})`);
console.log(`  verified accepts carrying \`contract\`:   ${carries(verifiedAccepts)}/${verifiedAccepts.length} (${pct(carries(verifiedAccepts), verifiedAccepts.length)})`);
const unverifiedAccepts = accepts.filter((f) => !f.verified);
console.log(`  unverified accepts carrying \`contract\`: ${carries(unverifiedAccepts)}/${unverifiedAccepts.length} (${pct(carries(unverifiedAccepts), unverifiedAccepts.length)})`);

// Who actually omits the field? A population rate hides a per-client problem.
const perDid = new Map();
for (const item of verifiedAccepts) {
  const did = item.frame.from;
  if (!perDid.has(did)) perDid.set(did, { total: 0, omitted: 0 });
  const entry = perDid.get(did);
  entry.total += 1;
  if (typeof item.frame.contract !== "string") entry.omitted += 1;
}
const omitters = [...perDid.entries()].filter(([, e]) => e.omitted > 0).sort((a, b) => b[1].omitted - a[1].omitted);
const totalOmitted = verifiedAccepts.length - carries(verifiedAccepts);
console.log(`  distinct DIDs among verified accepts: ${perDid.size}; DIDs that ever omit: ${omitters.length}`);
for (const [did, e] of omitters.slice(0, 5)) {
  console.log(`    ${did.slice(8, 24)}…  omits ${e.omitted}/${e.total} (${pct(e.omitted, e.total)} of its own accepts, ${pct(e.omitted, totalOmitted || 1)} of all omissions)`);
}

// ── competition, both ways of counting ───────────────────────────────────────

const byRefAll = new Map(), byRefVerified = new Map();
const offers = new Map(), verifiedLocks = new Map();
for (const item of frames) {
  const f = item.frame;
  if (f.type === "accept" && f.ref) {
    if (!byRefAll.has(f.ref)) byRefAll.set(f.ref, []);
    byRefAll.get(f.ref).push(item);
    if (item.verified) {
      if (!byRefVerified.has(f.ref)) byRefVerified.set(f.ref, []);
      byRefVerified.get(f.ref).push(item);
    }
  }
  if (f.type === "offer" && f.id && item.verified) offers.set(f.id, f);
  if (f.type === "lock" && f.contract && item.verified) verifiedLocks.set(f.contract, f);
}
const shapeStats = summarise([...byRefAll.values()].map((l) => uniqueAccepts(l).length));
const verifiedStats = summarise([...byRefVerified.values()].map((l) => uniqueAccepts(l).length));
console.log(`\ncompetition per accepted offer`);
console.log(`                        offers    mean  median   max   with 2+`);
for (const [label, s] of [["frame-shape", shapeStats], ["verified", verifiedStats]]) {
  console.log(`  ${label.padEnd(20)} ${String(s.n).padStart(6)}  ${s.mean.toFixed(2).padStart(6)}  ${String(s.median).padStart(6)}  ${String(s.max).padStart(4)}   ${s.contested} (${pct(s.contested, s.n)})`);
}

// ── base rate, over verified records only ────────────────────────────────────

const sample = [...byRefVerified.keys()].filter((ref) => offers.has(ref)).slice(0, SAMPLE_N);
const candidates = sample.flatMap((ref) =>
  uniqueAccepts(byRefVerified.get(ref)).map((a) => contractOf(a.frame, offers.get(ref))));
console.log(`\nsample: first ${sample.length} offers in board order with >=1 verified accept`);
const probed = await probeMany(candidates);
console.log(`probed ${probed} derived deal rooms`);

let locked = 0, abandoned = 0, unlockable = 0, winnerCarried = 0;
for (const ref of sample) {
  const offer = offers.get(ref);
  const list = uniqueAccepts(byRefVerified.get(ref));
  const anyLockable = list.some((a) => typeof a.frame.contract === "string");
  let winner = null;
  for (const a of list) {
    const cid = contractOf(a.frame, offer);
    if (!cid) continue;
    if (verifiedLocks.has(cid) || (await roomFrameKinds(cid))?.includes("lock")) { winner = a; break; }
  }
  if (winner) { locked += 1; if (typeof winner.frame.contract === "string") winnerCarried += 1; }
  else if (anyLockable) abandoned += 1;
  else unlockable += 1;
}

const ci = (k, n) => { const [lo, hi] = wilson(k, n); return `95% CI ${(100 * lo).toFixed(1)}–${(100 * hi).toFixed(1)}%`; };
console.log(`\n  locked by someone                        ${String(locked).padStart(4)}  ${pct(locked, sample.length).padStart(6)}   ${ci(locked, sample.length)}`);
console.log(`    winning accept carried \`contract\`      ${winnerCarried}/${locked}`);
console.log(`  unlocked, >=1 schema-valid accept        ${String(abandoned).padStart(4)}  ${pct(abandoned, sample.length).padStart(6)}   <- genuine abandonment`);
console.log(`  unlocked, every accept omitted contract  ${String(unlockable).padStart(4)}  ${pct(unlockable, sample.length).padStart(6)}   <- nothing a fail-closed payer could lock`);
const lockableDen = locked + abandoned;
console.log(`\n  lock rate given something lockable existed: ${locked}/${lockableDen} = ${pct(locked, lockableDen)}   ${ci(locked, lockableDen)}`);
console.log(`\nCaveat: the board half of the lock check only covers this export's window,`);
console.log(`so a lock posted to the board (not the deal room) after ${last} would be missed;`);
console.log(`derived-room probes are live and cover all time.`);
