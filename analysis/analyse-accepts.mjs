#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Why did our accepts never get locked? — competition vs abandonment.
//
// For every accept-side deal in a live-node log, works out:
//   * whether the board export still covers the moment we accepted;
//   * how many DIFFERENT bots accepted the same offer;
//   * which accept (if any) the payer actually locked against.
//
// Two things make this harder than grepping, and both are handled here:
//   1. The export's `text` field is a JSON string containing another JSON
//      document, so it must be decoded twice — splitting on quotes or commas
//      mis-parses it.
//   2. Most accepts on this board omit the `contract` field (issue #142), so
//      their deal room cannot be read off the frame. It is re-derived with the
//      library's own contractId(offer, acceptCore), which is why this is a Node
//      script and not a Python one: canonical JSON and the domain hash have to
//      match the protocol exactly.
//
// Usage: node analyse-accepts.mjs <board-export.jsonl> <live-node.log> [--sample N]
// Read-only: every venue call is a GET.

import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
// The tclk library, for re-deriving contract ids. Override with TCLK_DIST if the
// checkout lives elsewhere.
const DIST = process.env.TCLK_DIST ?? "/Users/pplmaverick/tclk-audit/dist/index.js";
const { contractId, dealRoom } = await import(DIST);

const OUR_DID = "did:key:z6Mkk9PjEhxbE1HBUvr7bnAAkfBcNT9EhnwFwQkmvUn7VARN";
const REPORT = process.env.REPORT ?? "accept-analysis.txt";
writeFileSync(REPORT, "");
/** Print and flush, so a long run can be watched while it works. */
function say(line = "") { appendFileSync(REPORT, line + "\n"); process.stdout.write(line + "\n"); }
const BASE = "https://technocore.chat";

const [exportPath, logPath] = process.argv.slice(2);
const sampleArg = process.argv.indexOf("--sample");
const SAMPLE_N = sampleArg > -1 ? Number(process.argv[sampleArg + 1]) : 40;

// ── load ─────────────────────────────────────────────────────────────────────

function loadExport(path) {
  const records = [], frames = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.trim()) continue;
    let rec; try { rec = JSON.parse(line); } catch { continue; }
    records.push(rec);
    const text = rec.text ?? "";
    if (!text.startsWith("tclk1 ")) continue;
    let frame; try { frame = JSON.parse(text.slice(6)); } catch { continue; }
    if (frame && typeof frame === "object") frames.push({ rec, frame });
  }
  return { records, frames };
}

function loadOurAccepts(path) {
  const out = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.startsWith("{")) continue;
    let d; try { d = JSON.parse(line); } catch { continue; }
    if (d.step === "accept-side-accept" && d.result === "success") {
      out.push({ ts: d.ts, offer: d.picked_offer_id, contract: d.contract, pattern: d.job_pattern });
    }
  }
  return out;
}

// ── venue (read-only) ────────────────────────────────────────────────────────

const roomCache = new Map();
async function roomFrameKinds(contract) {
  if (roomCache.has(contract)) return roomCache.get(contract);
  let kinds = null;
  try {
    const res = await fetch(`${BASE}/r/${dealRoom(contract)}?format=json`, { signal: AbortSignal.timeout(20_000) });
    if (res.ok) {
      const d = await res.json();
      kinds = (d.messages ?? []).map((m) => {
        const t = m.text ?? "";
        if (!t.startsWith("tclk1 ")) return "(text)";
        try { return JSON.parse(t.slice(6)).type; } catch { return "?"; }
      });
    }
  } catch { /* leave null: unknown, not "empty" */ }
  roomCache.set(contract, kinds);
  return kinds;
}

/** Probe many contracts at once; the venue answers a room read in well under 300ms. */
async function probeMany(contracts, concurrency = 8) {
  const todo = contracts.filter((c) => c && !roomCache.has(c));
  for (let i = 0; i < todo.length; i += concurrency) {
    await Promise.all(todo.slice(i, i + concurrency).map((c) => roomFrameKinds(c)));
  }
}

/** The contract id an accept names, or re-derived when the frame omits it (#142). */
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

// ── main ─────────────────────────────────────────────────────────────────────

const { records, frames } = loadExport(exportPath);
const ours = loadOurAccepts(logPath);
const firstTs = records[0].ts, lastTs = records.at(-1).ts;

const acceptsByRef = new Map();
const offersById = new Map();
const boardLocks = new Map();
for (const { rec, frame } of frames) {
  if (frame.type === "accept" && frame.ref) {
    if (!acceptsByRef.has(frame.ref)) acceptsByRef.set(frame.ref, []);
    acceptsByRef.get(frame.ref).push({ rec, frame });
  }
  if (frame.type === "offer" && frame.id) offersById.set(frame.id, frame);
  if (frame.type === "lock" && frame.contract) boardLocks.set(frame.contract, frame);
}

function uniqueAccepts(list) {
  const seen = new Set(), out = [];
  for (const a of list) {
    const key = `${a.frame.from}|${a.frame.nonce}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out.sort((x, y) => x.rec.seq - y.rec.seq);
}

say(`export: ${records.length} records, ${firstTs} .. ${lastTs}`);
say(`log:    ${ours.length} accept-side accepts\n`);

const rows = [];
for (const [i, a] of ours.entries()) {
  const row = { n: i + 1, ...a, inWindow: a.ts >= firstTs && a.ts <= lastTs };
  if (!row.inWindow) {
    row.ourRoom = a.contract ? await roomFrameKinds(a.contract) : null;
    row.verdict = "no data (rolled out of the board ring)";
    rows.push(row);
    continue;
  }
  const offer = offersById.get(a.offer) ?? null;
  const rivals = uniqueAccepts(acceptsByRef.get(a.offer) ?? []);
  row.offerFrame = offer;
  row.rivals = rivals.length;
  row.detail = [];
  let winner = null, undecidable = 0;
  await probeMany(rivals.map(({ frame }) => contractOf(frame, offer)));
  for (const { rec, frame } of rivals) {
    const cid = contractOf(frame, offer);
    let where = null;
    if (cid && boardLocks.has(cid)) where = "board";
    else if (cid) {
      const kinds = await roomFrameKinds(cid);
      if (kinds === null) where = null;
      else if (kinds.includes("lock")) where = `deal room [${kinds.join(",")}]`;
    }
    if (!cid) undecidable += 1;
    if (where && !winner) winner = frame.from;
    row.detail.push({
      seq: rec.seq, ts: rec.ts, from: frame.from, nonce: frame.nonce,
      carriedContract: typeof frame.contract === "string", cid, where,
      ours: frame.from === OUR_DID,
    });
  }
  row.ourRank = row.detail.findIndex((d) => d.ours) + 1;
  row.winner = winner;
  row.undecidable = undecidable;
  row.verdict = winner
    ? (winner === OUR_DID ? "we won" : "LOST — payer locked with a rival")
    : (undecidable ? `nobody locked (${undecidable} rival(s) undecidable)` : "nobody locked (payer walked away)");
  rows.push(row);
}

say(`${"#".padStart(2)} ${"accepted at".padEnd(24)} ${"offer".padEnd(20)} ${"rivals".padStart(6)} ${"ourRank".padStart(7)} ${"lock?".padEnd(6)} verdict`);
say("-".repeat(115));
for (const r of rows) {
  const rivals = r.rivals ?? "-";
  const rank = r.ourRank ? `${r.ourRank}/${r.rivals}` : "-";
  const lock = r.rivals === undefined ? "-" : (r.winner ? "yes" : "no");
  say(`${String(r.n).padStart(2)} ${r.ts.padEnd(24)} ${r.offer.slice(0, 18).padEnd(20)} ${String(rivals).padStart(6)} ${rank.padStart(7)} ${lock.padEnd(6)} ${r.verdict}`);
}

const tally = (p) => rows.filter((r) => p(r)).length;
say(`\nlost to a rival: ${tally((r) => r.verdict.startsWith("LOST"))}   ` +
  `nobody locked: ${tally((r) => r.verdict.startsWith("nobody"))}   ` +
  `we won: ${tally((r) => r.verdict === "we won")}   ` +
  `no data: ${tally((r) => r.verdict.startsWith("no data"))}`);

for (const r of rows) {
  if (r.detail) {
    say(`\n  #${r.n} offer ${r.offer.slice(0, 18)}…  payer ${(r.offerFrame?.from ?? "?").slice(8, 20)}…  ${r.offerFrame?.amount ?? "?"} ${r.offerFrame?.asset ?? ""}`);
    for (const d of r.detail) {
      say(`     seq ${d.seq} ${d.ts.slice(11, 23)} ${d.from.slice(8, 20)}…  ` +
        `contract:${d.carriedContract ? "carried" : (d.cid ? "re-derived" : "UNKNOWN")}  ` +
        `lock:${d.where ?? "none"}${d.ours ? "   <<< US" : ""}`);
    }
  }
  if (r.ourRoom !== undefined && r.ourRoom !== null && !r.detail) {
    say(`  #${r.n} our deal room ${dealRoom(r.contract)}: ${r.ourRoom.length ? r.ourRoom.join(",") : "empty"}`);
  }
}

// ── board-wide context ───────────────────────────────────────────────────────

say("\n── competition across the whole export ──");
const counts = [...acceptsByRef.values()].map((l) => uniqueAccepts(l).length).sort((a, b) => a - b);
const mean = counts.reduce((s, c) => s + c, 0) / counts.length;
say(`offers that got >=1 accept: ${counts.length}`);
say(`mean accepts per accepted offer: ${mean.toFixed(2)}   median: ${counts[counts.length >> 1]}   max: ${counts.at(-1)}`);
say(`offers with more than one accepting bot: ${counts.filter((c) => c > 1).length} (${(100 * counts.filter((c) => c > 1).length / counts.length).toFixed(1)}%)`);
say(`offers on the board: ${offersById.size}   lock frames on the board: ${boardLocks.size}`);

// Base rate: of a random sample of accepted offers, how many got locked by ANYONE?
const sampleable = [...acceptsByRef.keys()].filter((ref) => offersById.has(ref));
const sample = sampleable.slice(0, SAMPLE_N);
let lockedAny = 0, checked = 0, probes = 0;
const allSampleContracts = sample.flatMap((ref) =>
  uniqueAccepts(acceptsByRef.get(ref)).map(({ frame }) => contractOf(frame, offersById.get(ref))));
say(`\nprobing ${allSampleContracts.filter(Boolean).length} deal rooms for the base rate ...`);
await probeMany(allSampleContracts, 12);
for (const ref of sample) {
  const offer = offersById.get(ref);
  let locked = false;
  for (const { frame } of uniqueAccepts(acceptsByRef.get(ref))) {
    const cid = contractOf(frame, offer);
    if (!cid) continue;
    probes += 1;
    if (boardLocks.has(cid)) { locked = true; break; }
    const kinds = await roomFrameKinds(cid);
    if (kinds?.includes("lock")) { locked = true; break; }
  }
  checked += 1;
  if (locked) lockedAny += 1;
}
say(`\nbase rate — of ${checked} sampled accepted offers (${probes} deal rooms probed), ` +
  `${lockedAny} were locked by anyone: ${(100 * lockedAny / checked).toFixed(1)}%`);
