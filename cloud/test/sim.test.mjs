// What a validator simulation of three guardians (fault proxy, spam, a
// patient attacker, a Floor stop) found the guardian missing (docs/09,
// finding 76), each with the test that fails without its fix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { key, u64le, i64le, FailoverRpc, endpointTrouble } from "../lib/solana.mjs";
import { assess, breach, newState, outflowAlerts, ticketAlreadyGone, afterCancelFailure, freezeAlreadyCovers, replayedBreachTime, ticketScanDue, watchedEvents, DEFAULT_POLICY, DAY_S, HOUR_S } from "../guardian/policy.mjs";
import { ingestBudgeted, ingestLagS, requireTransaction } from "../guardian/follow.mjs";
import { alertFor } from "../guardian/alert.mjs";
import { stateJson, restoreState } from "../guardian/statefile.mjs";

const MINT = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";
const OWNER = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const PROTOCOL = "8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb";
// 10M vault, default limits: worst_1h 4%, worst_24h 10%, worst_72h 20%.
const FIG = { worst1h: 400_000n, worst24h: 1_000_000n, worst72h: 2_000_000n };
const release = (amount, at) => ({ kind: "released", mint: MINT, owner: OWNER, backed: 0n, instant: amount, queued: 0n, ticketId: 0n, etaS: 0, at });

// --- 1. a patient attacker: alerts, and the 72-hour rule --------------------

test("outflow past half the 24h threshold alerts, at most every 6 hours (finding 76, 1a)", () => {
  const s = newState();
  const seen = [];
  // 24h threshold 500,000; the alert bar is 250,000.
  for (const [t, amount] of [[0, 200_000n], [600, 60_000n], [1_200, 10_000n], [7 * HOUR_S, 10_000n]]) {
    assess(s, release(amount, t), { ...FIG, now: t });
    seen.push(...outflowAlerts(s, MINT, { ...FIG, now: t }).map((a) => [t, a.code]));
  }
  assert.deepEqual(seen, [[600, "outflow"], [7 * HOUR_S, "outflow"]]);
  const line = { level: "warn", msg: outflowAlerts(newState(), MINT, { ...FIG, now: 0 })[0]?.msg ?? "unbacked outflow at 52% of the 24h freeze threshold", mint: MINT };
  assert.ok(alertFor(line, new Map(), 0), "an urgent alert, not an info line");
});

test("a sustained drip alerts once it reached the bar on 2 of the last 3 days, and survives a restart (finding 76, 1b)", () => {
  const s = newState();
  const codes = (t) => outflowAlerts(s, MINT, { ...FIG, now: t }).map((a) => a.code);
  assess(s, release(300_000n, 1_000), { ...FIG, now: 1_000 });
  assert.deepEqual(codes(1_000), ["outflow"]);
  // The state file keeps each day's high: a restart with no history keeps it.
  const back = newState();
  restoreState(stateJson({ protocol: PROTOCOL, state: s }), PROTOCOL, back);
  assert.deepEqual([...back.drip.get(MINT).days], [...s.drip.get(MINT).days]);
  const t = DAY_S + 30_000;
  assess(back, release(300_000n, t), { ...FIG, now: t });
  const got = outflowAlerts(back, MINT, { ...FIG, now: t });
  assert.deepEqual(got.map((a) => a.code), ["outflow", "sustained"]);
  assert.match(got[1].msg, /sustained drip/);
  assert.ok(alertFor({ level: "warn", msg: got[1].msg, mint: MINT }, new Map(), 0));
  // A replay records, never alerts.
  const r = newState();
  assess(r, release(300_000n, 5), { ...FIG, now: 5 }, DEFAULT_POLICY, false);
  assert.deepEqual(outflowAlerts(r, MINT, { ...FIG, now: 5 }, DEFAULT_POLICY, false), []);
  assert.equal(r.drip.get(MINT).days.size, 1);
});

test("the 72-hour rule freezes a drip under the 24-hour rule, and waits for its figure (finding 76, 1c)", () => {
  const s = newState();
  // 100,000 every 7 hours: at most 400,000 in a day, under the 24h threshold
  // (500,000), and 1.1M over 72h by hour 70: 0.55 × 2M.
  let froze = null;
  for (let t = 0; t <= 3 * DAY_S && !froze; t += 7 * HOUR_S) {
    const a = assess(s, release(100_000n, t), { ...FIG, now: t });
    if (a.some((x) => x.type === "freeze")) froze = { t, reason: a[0].reason };
  }
  assert.ok(froze, "frozen");
  assert.match(froze.reason, /last 72 hours/);
  assert.ok(froze.t < 3 * DAY_S);
  // Outflows are kept for 72 hours, not one day.
  assert.ok(s.outflows.some((o) => o.t === 0));
  // Without a 72-hour figure the rule waits; with fraction 0 it is off.
  const window = (fig, policy) => {
    const w = newState();
    for (let t = 0; t <= 70 * HOUR_S; t += 7 * HOUR_S) assess(w, release(100_000n, t), { ...fig, now: t }, policy, false);
    return breach(w, MINT, { ...fig, now: 70 * HOUR_S }, policy);
  };
  assert.ok(window(FIG, DEFAULT_POLICY));
  assert.equal(window({ ...FIG, worst72h: undefined }, DEFAULT_POLICY), null);
  assert.equal(window(FIG, { ...DEFAULT_POLICY, freezeFractionOfWorst72h: 0 }), null);
});

// --- 2. spam: bounded ingest, concurrent fetches, the lag alert ------------

/** A fake rpc with `latencyMs` per call and a backlog of `n` transactions. */
function slowRpc(latencyMs, { missing = new Set() } = {}) {
  let inFlight = 0;
  const stats = { maxInFlight: 0, calls: 0 };
  return {
    stats,
    async call(method, [signature]) {
      stats.calls++;
      inFlight++;
      stats.maxInFlight = Math.max(stats.maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, latencyMs));
      inFlight--;
      if (missing.has(signature)) return null;
      return { meta: { logMessages: [] }, blockTime: 1_000 + Number(signature.slice(1)) };
    },
  };
}
const backlog = (n) => Array.from({ length: n }, (_, i) => ({ signature: `s${n - 1 - i}`, slot: n - 1 - i, blockTime: 1_000 + n - 1 - i }));

test("ingest under spam: bounded per pass, fetched 8 at a time, processed in order (finding 76, 2a-b)", async () => {
  const rpc = slowRpc(20);
  const order = [];
  const marks = [];
  const t0 = Date.now();
  const left = await ingestBudgeted(backlog(400), {
    fetchOne: (s) => requireTransaction(rpc, s.signature),
    processOne: async (s) => { order.push(s.signature); },
    checkpoint: (sig) => marks.push(sig),
    concurrency: 8,
    budgetMs: 300,
  });
  const took = Date.now() - t0;
  // Serially, 400 × 20 ms is 8 s in one step. Bounded, the step returns.
  assert.ok(took < 1_000, `one pass took ${took} ms`);
  assert.ok(left.length > 0 && left.length < 400, `${left.length} left`);
  assert.equal(order.length + left.length, 400);
  assert.deepEqual(order, marks);
  assert.deepEqual(order.slice(0, 3), ["s0", "s1", "s2"], "oldest first");
  assert.equal(left.at(-1).signature, `s${order.length}`, "the rest, still newest-first, continues where it stopped");
  assert.ok(rpc.stats.maxInFlight <= 8 && rpc.stats.maxInFlight > 1, `in flight ${rpc.stats.maxInFlight}`);
  // Concurrent: processed several times faster than one at a time.
  assert.ok(order.length > 300 / 20 * 3, `${order.length} done in 300 ms`);
  // The lag the alert reads: the oldest left against the chain's time.
  assert.equal(ingestLagS(left, 1_000 + 399 + 90), 399 + 90 - order.length);
  assert.equal(ingestLagS([], 5_000), 0);
});

test("a transaction the node cannot return stops the pass there, with no unhandled rejection (finding 76, 2)", async () => {
  const rpc = slowRpc(5, { missing: new Set(["s3"]) });
  const done = [];
  let unhandled = null;
  const onUnhandled = (e) => { unhandled = e; };
  process.on("unhandledRejection", onUnhandled);
  try {
    await assert.rejects(ingestBudgeted(backlog(40), {
      fetchOne: (s) => requireTransaction(rpc, s.signature),
      processOne: async (s) => { done.push(s.signature); },
    }), /no transaction metadata for s3/);
    await new Promise((r) => setTimeout(r, 50));
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
  assert.deepEqual(done, ["s0", "s1", "s2"]);
  assert.equal(unhandled, null);
});

// --- 3. failover on successful but wrong answers ---------------------------

function stubFetch(routes) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    const host = new URL(url).host;
    calls.push([host, method]);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...routes[host](method, params) }), { status: 200 });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test("a node that does not serve a method hands the call to a backup (finding 76, 3)", async () => {
  for (const code of [-32010, -32601]) {
    assert.equal(endpointTrouble(Object.assign(new Error("x"), { rpcError: { code } })), true, `${code}`);
    const f = stubFetch({ "a.invalid": () => ({ error: { code, message: "getProgramAccounts is not available" } }), "b.invalid": () => ({ result: [] }) });
    try {
      assert.deepEqual(await new FailoverRpc(["http://a.invalid", "http://b.invalid"]).call("getProgramAccounts", ["x"]), []);
    } finally {
      f.restore();
    }
  }
});

test("the freshness cross-check leaves a primary that answers but is stale (finding 76, 3)", async () => {
  // Slots: the primary 400 behind.
  let f = stubFetch({
    "a.invalid": (m) => ({ result: m === "getSlot" ? 1_000 : [] }),
    "b.invalid": (m) => ({ result: m === "getSlot" ? 1_400 : [] }),
  });
  try {
    const switches = [];
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"], { onSwitch: (from, to) => switches.push([from, to]) });
    const r = await rpc.crossCheck(PROTOCOL);
    assert.equal(r.switched, true);
    assert.match(r.reason, /400 slots behind/);
    assert.deepEqual(switches, [["http://a.invalid", "http://b.invalid"]]);
    assert.equal(alertFor({ level: "warn", msg: `${r.reason}; switched endpoints` }, new Map(), 0) !== null, true, "urgent");
  } finally {
    f.restore();
  }
  // Same slot, but the primary does not list the backup's newest signature.
  f = stubFetch({
    "a.invalid": (m) => ({ result: m === "getSlot" ? 1_000 : [{ signature: "old" }] }),
    "b.invalid": (m) => ({ result: m === "getSlot" ? 1_000 : [{ signature: "new" }] }),
  });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: 0 })).switched, false, "not yet: it may arrive");
    assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: 20_000 })).switched, false);
    const r = await rpc.crossCheck(PROTOCOL, { nowMs: 31_000 });
    assert.equal(r.switched, true);
    assert.match(r.reason, /missing recent transactions/);
    assert.equal(rpc.url, "http://b.invalid");
  } finally {
    f.restore();
  }
  // In step: nothing happens.
  f = stubFetch({
    "a.invalid": (m) => ({ result: m === "getSlot" ? 1_000 : [{ signature: "new" }, { signature: "old" }] }),
    "b.invalid": (m) => ({ result: m === "getSlot" ? 1_100 : [{ signature: "new" }] }),
  });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: 0 })).switched, false);
    assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: 60_000 })).switched, false);
  } finally {
    f.restore();
  }
});

test("on a busy protocol, a signature pushed out of the primary's newest 100 is not missing; a lagging index still is (findings 81, 84)", async () => {
  // The backup's newest is "b1" (slot 1000); 100 newer transactions (slots
  // 1001-1100) fill the primary's newest-100 list.
  const newest100 = Array.from({ length: 100 }, (_, i) => ({ signature: `p${i}`, slot: 1100 - i }));
  let f = stubFetch({
    "a.invalid": (m) => ({ result: m === "getSlot" ? 1_100 : newest100 }),
    "b.invalid": (m) => ({ result: m === "getSlot" ? 1_100 : [{ signature: "b1", slot: 1_000 }] }),
  });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    for (const t of [0, 31_000, 61_000, 120_000]) assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: t })).switched, false, `${t}`);
    assert.equal(rpc.url, "http://a.invalid");
  } finally {
    f.restore();
  }
  // The primary's address index lags (its newest listed is slot 900), though
  // its status cache knows the backup's newest: ingestion reads the index, so
  // that primary is blind, and is left.
  f = stubFetch({
    "a.invalid": (m, params) => ({ result: m === "getSlot" ? 1_000 : m === "getSignatureStatuses" ? { value: params[0].map(() => ({ confirmationStatus: "confirmed" })) } : [{ signature: "old", slot: 900 }] }),
    "b.invalid": (m) => ({ result: m === "getSlot" ? 1_000 : [{ signature: "new", slot: 995 }] }),
  });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    assert.equal((await rpc.crossCheck(PROTOCOL, { nowMs: 0 })).switched, false);
    const r = await rpc.crossCheck(PROTOCOL, { nowMs: 31_000 });
    assert.equal(r.switched, true);
  } finally {
    f.restore();
  }
});

// --- 4. a truncated transaction runs the ticket scan at once ---------------

test("a truncated transaction runs the ticket scan out of its cadence (finding 76, 4)", () => {
  assert.equal(ticketScanDue(1_000, 60_000, false), false);
  assert.equal(ticketScanDue(1_000, 60_000, true), true);
  assert.equal(ticketScanDue(60_000, 60_000, false), true);
});

// --- 5. cancel races and duplicate freezes ---------------------------------

test("a ticket a peer already cancelled is done, not a critical alert (finding 76, 5)", () => {
  const closed = Object.assign(new Error("transaction failed"), { rpcError: { data: { err: { InstructionError: [2, { Custom: 8001 }] } } } });
  assert.equal(ticketAlreadyGone(closed), true);
  assert.equal(ticketAlreadyGone(new Error('{"InstructionError":[2,{"Custom":8001}]}')), true);
  assert.equal(ticketAlreadyGone(new Error('{"InstructionError":[2,{"Custom":8010}]}')), false);
  assert.equal(ticketAlreadyGone(new Error("connection reset")), false);
  // The line logged for it is not an alert; the error line it replaces was critical.
  assert.equal(alertFor({ action: "cancel", skipped: "ticket already closed (cancelled by another guardian, or settled)", ticketId: 3 }, new Map(), 0), null);
  assert.equal(alertFor({ level: "error", action: "cancel", error: "Custom 8001", ticketId: 3 }, new Map(), 0).severity, "critical");
  assert.equal(afterCancelFailure(undefined, closed, 0).final, null, "the backoff never sees it");
});

test("a freeze already on chain for about as long stands for this guardian's (finding 76, 5)", () => {
  const now = 1_000_000;
  assert.equal(freezeAlreadyCovers(now + DAY_S - 5, now, DAY_S), true, "a peer's freeze seconds earlier");
  assert.equal(freezeAlreadyCovers(0, now, DAY_S), false);
  assert.equal(freezeAlreadyCovers(now + 3_000, now, DAY_S), false, "an expiring freeze is extended");
  // An incident-hold renewal shorter than a day is covered by a longer freeze.
  assert.equal(freezeAlreadyCovers(now + 7_200, now, 3_600), true);
});

// --- 6. the incident hold rebuilt from chain --------------------------------

test("with no state file, the replayed window says when the breach began (finding 76, 6)", () => {
  const s = newState();
  for (const [t, a] of [[100, 50_000n], [200, 100_000n], [300, 60_000n], [400, 10_000n]]) assess(s, release(a, t), { ...FIG, now: t }, DEFAULT_POLICY, false);
  // 1h threshold 200,000: crossed at t=300 (210,000).
  assert.equal(replayedBreachTime(s, MINT, FIG, 1_000), 300);
  const quiet = newState();
  assess(quiet, release(10_000n, 100), { ...FIG, now: 100 }, DEFAULT_POLICY, false);
  assert.equal(replayedBreachTime(quiet, MINT, FIG, 1_000), null);
  assert.equal(quiet.outflows.length, 1, "probing leaves the window alone");
});

// --- 7. Floor's stop, ejection, restore and approvals ----------------------

const FLOOR = "F1oor11111111111111111111111111111111111111";
const WATCHED = "6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh";
const OTHER = "Stranger11111111111111111111111111111111111";
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const data = (name, ...fields) => `Program data: ${[b64(Buffer.from(name)), ...fields.map(b64)].join(" ")}`;
const inFloor = (...lines) => [`Program ${FLOOR} invoke [1]`, ...lines, `Program ${FLOOR} success`];

test("Floor's stop, ejection, restore and approval are decoded from their real layouts, for watched programs only (finding 76, 7)", () => {
  // programs/floor/src/: ABORTED [program, who, snapshot_valid u8, t i64] and
  // RESTORED [program, signers u8] in stop.rs, EJECTED [program, removed] in
  // guardians.rs, APPROVED [program, pending_id u64, approvals u8] in proposals.rs.
  const logs = inFloor(
    data("floor:aborted", key(WATCHED), key(OWNER), Uint8Array.of(1), i64le(1_700_000_000)),
    data("floor:ejected", key(WATCHED), key(OTHER)),
    data("floor:restored", key(WATCHED), Uint8Array.of(0b011)),
    data("floor:approved", key(WATCHED), u64le(9), Uint8Array.of(0b101)),
    data("floor:aborted", key(OTHER), key(OWNER), Uint8Array.of(0), i64le(1)),
  );
  const { events } = watchedEvents(logs, { floorProgram: FLOOR, floorPrograms: [WATCHED] });
  assert.deepEqual(events, [
    { kind: "floor_aborted", program: WATCHED, by: OWNER, snapshotValid: true, at: 1_700_000_000 },
    { kind: "floor_ejected", program: WATCHED, removed: OTHER },
    { kind: "floor_restored", program: WATCHED, signers: 0b011 },
    { kind: "floor_approved", program: WATCHED, proposalId: 9n, approvals: 0b101 },
  ]);
  // A layout this guardian does not know is dropped, never misread.
  assert.deepEqual(watchedEvents(inFloor(data("floor:aborted", key(WATCHED), key(OWNER))), { floorProgram: FLOOR, floorPrograms: [WATCHED] }).events, []);
  // Written by another program: not Floor's.
  assert.deepEqual(watchedEvents([`Program ${OTHER} invoke [1]`, logs[1], `Program ${OTHER} success`], { floorProgram: FLOOR, floorPrograms: [WATCHED] }).events, []);
});

test("a Floor stop and an ejection alert urgently; a restore and an approval alert as notices (finding 76, 7)", () => {
  const seen = new Map();
  const stop = alertFor({ level: "warn", msg: `the program was stopped on Floor (by ${OWNER}); a guardian quorum restores the snapshot`, program: WATCHED }, seen, 0);
  const eject = alertFor({ level: "warn", msg: `a guardian was ejected on Floor by a quorum of the others: ${OTHER}`, program: WATCHED }, seen, 0);
  const restore = alertFor({ notify: true, msg: "Floor restored the stopped program's snapshot (guardians 11)", program: WATCHED }, seen, 0);
  const approve = alertFor({ notify: true, msg: "guardians approved Floor restore proposal 9 (approvals 101)", program: WATCHED, proposalId: 9n }, seen, 0);
  for (const a of [stop, eject, restore, approve]) assert.ok(a);
  assert.match(restore.title, /notice/);
  assert.equal(alertFor({ msg: "floor ready", program: WATCHED }, new Map(), 0), null, "a plain info line still does not alert");
});

test("a hold renewal is never mistaken for a duplicate freeze, whatever the freeze length", async () => {
  const { freezeAlreadyCovers } = await import("../guardian/policy.mjs");
  // A 60 s freeze renewed 30 s before it ends: the chain shows 30 s left.
  assert.equal(freezeAlreadyCovers(1_030, 1_000, 60), false);
  // A 24h freeze renewed an hour before it ends.
  assert.equal(freezeAlreadyCovers(1_000 + 3_600, 1_000, 86_400), false);
  // Another guardian's freeze landed seconds ago: covered.
  assert.equal(freezeAlreadyCovers(1_000 + 86_400 - 5, 1_000, 86_400), true);
  assert.equal(freezeAlreadyCovers(1_000 + 59, 1_000, 60), true);
});
