// What a guardian keeps across a restart, how it reads on after one, and how
// it says it is failing (docs/09, finding 71).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, chmodSync, statSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { newState, GENESIS } from "../guardian/policy.mjs";
import { stateJson, restoreState, writeStateFile } from "../guardian/statefile.mjs";
import { followAccount, followConfigs, startSlot } from "../guardian/follow.mjs";
import { stallWatch, scanAll, alertFor } from "../guardian/alert.mjs";
import { Keypair } from "../lib/signer.mjs";

const PROTOCOL = "8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb";

test("the state file keeps the executions seen, Floor cursors and pending proposals, and proposals to read", () => {
  const s = newState();
  s.consumed.set("3:x:@9", "c4");
  s.executedSeen.add("c2").add("c4").add("eP:7");
  s.changeBaseline = true;
  const text = stateJson({
    protocol: PROTOCOL, incidentSince: 100, frozenUntil: 200, state: s,
    floorCursors: new Map([["cfg", { signature: "sig", slot: 42 }]]),
    floorPendingSeen: new Map([["P", { id: 7n, approval: "P:5:t:" }]]),
    changeChecks: new Map([[11n, { sinceS: 300, warned: true }]]),
  });
  const back = newState();
  const r = restoreState(text, PROTOCOL, back);
  assert.deepEqual([r.incidentSince, r.frozenUntil], [100, 200]);
  assert.equal(back.changeBaseline, true);
  assert.deepEqual([...back.executedSeen].sort(), ["c2", "c4", "eP:7"]);
  assert.equal(back.consumed.get("3:x:@9"), "c4");
  assert.deepEqual(r.floorCursors.get("cfg"), { signature: "sig", slot: 42 });
  assert.deepEqual(r.floorPendingSeen.get("P"), { id: 7n, approval: "P:5:t:" });
  assert.deepEqual(r.changeChecks.get(11n), { sinceS: 300, warned: false });
  assert.equal(stateJson({ protocol: PROTOCOL, incidentSince: 100, frozenUntil: 200, state: back, ...r }), text, "saved again unchanged");
  // Another protocol's file, or one from before executions were kept: no baseline.
  const other = newState();
  restoreState(text, "another", other);
  assert.deepEqual([other.changeBaseline, other.executedSeen.size], [false, 0]);
  const old = newState();
  restoreState(JSON.stringify({ protocol: PROTOCOL, incidentSince: null, frozenUntil: 0, consumed: { a: "c1" } }), PROTOCOL, old);
  assert.deepEqual([old.changeBaseline, old.consumed.get("a")], [false, "c1"]);
  // No baseline: no Vault executions saved, Floor ones still are.
  const none = newState();
  none.executedSeen.add("eP:1");
  const again = newState();
  restoreState(stateJson({ protocol: PROTOCOL, state: none }), PROTOCOL, again);
  assert.deepEqual([again.changeBaseline, [...again.executedSeen]], [false, ["eP:1"]]);
});

test("the state file is written owner-only and its directory is left alone", () => {
  const dir = mkdtempSync(`${tmpdir()}/bh-state-`);
  chmodSync(dir, 0o755);
  const path = `${dir}/g.json.state.json`;
  writeFileSync(`${path}.tmp`, "stale", { mode: 0o644 });
  writeStateFile(path, "{}");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(readFileSync(path, "utf8"), "{}");
  assert.equal(statSync(dir).mode & 0o777, 0o755, "not the guardian's directory to change");
});

/** Signature pages for `followAccount`: `history` newest-first; `gone` throws for that cursor. */
function pages(history, { gone = null } = {}) {
  const calls = [];
  const fetchPage = async (q) => {
    calls.push(q);
    if (gone && q.until === gone) throw new Error(`Invalid param: signature ${gone} not found`);
    let list = history;
    if (q.until) list = list.slice(0, list.findIndex((s) => s.signature === q.until));
    if (q.before) list = list.slice(list.findIndex((s) => s.signature === q.before) + 1);
    return list.slice(0, q.limit);
  };
  return { fetchPage, calls };
}
const sig = (i, blockTime) => ({ signature: `s${i}`, slot: i, blockTime });

test("a Floor config with no signature yet gets no cursor, so history is never walked from genesis (finding 71, 9)", async () => {
  const { fetchPage, calls } = pages([]);
  const r = await followAccount(fetchPage, { cursor: null });
  assert.deepEqual([r.status, r.cursor, r.sigs], ["empty", null, []]);
  assert.ok(calls.every((q) => q.limit === 1), "only the newest is asked for");
  const later = pages([sig(3, 30), sig(2, 20), sig(1, 10)]);
  const a = await followAccount(later.fetchPage, { cursor: null });
  assert.deepEqual([a.status, a.cursor, a.sigs], ["anchored", { signature: "s3", slot: 3 }, []]);
});

test("a restart reads a Floor config on from its saved cursor, and says when it could not (finding 71, 3)", async () => {
  const history = Array.from({ length: 10 }, (_, i) => sig(10 - i, 1_000 - i * 100)); // s10 (t 1000) .. s1 (t 100)
  const { fetchPage } = pages(history);
  const ok = await followAccount(fetchPage, { cursor: { signature: "s4", slot: 4 }, oldestWanted: 0, limit: 2 });
  assert.equal(ok.status, "ok");
  assert.deepEqual(ok.sigs.map((s) => s.signature), ["s10", "s9", "s8", "s7", "s6", "s5"], "every execution while down is read");
  // Bounded like the Vault startup: past the bound, the rest is a gap.
  const gap = await followAccount(fetchPage, { cursor: { signature: "s1", slot: 1 }, oldestWanted: 750, limit: 2 });
  assert.equal(gap.status, "gap");
  assert.deepEqual(gap.sigs.map((s) => s.signature), ["s10", "s9", "s8", "s7"]);
  // A cursor the node forgot: re-anchored at the newest, reported.
  const forgot = pages(history, { gone: "s2" });
  const gone = await followAccount(forgot.fetchPage, { cursor: { signature: "s2", slot: 2 }, oldestWanted: 0 });
  assert.deepEqual([gone.status, gone.cursor, gone.sigs], ["gone", { signature: "s10", slot: 10 }, []]);
});

/**
 * Floor configs C1..C3 (programs P1..P3) for `followConfigs`; each ingest and
 * save is recorded. `refuse` by program: "page", "ingest", or "after one"
 * (the oldest is checkpointed, then it throws).
 */
function floorFollow(history, { refuse = {}, cursors = new Map(), followed = new Set() } = {}) {
  const got = { ingested: [], logs: [], saves: 0 };
  const deps = {
    page: async (address, q) => {
      if (refuse[address.replace("C", "P")] === "page") throw new Error("getSignaturesForAddress: fetch failed");
      return pages(history[address] ?? []).fetchPage(q);
    },
    cursors, followed, oldestWanted: () => 0, knows: null,
    ingest: async (sigs, live, checkpoint, program) => {
      if (refuse[program] === "ingest") throw new Error("transaction not returned");
      for (const s of [...sigs].reverse()) {
        checkpoint(s.signature, s);
        if (refuse[program] === "after one") throw new Error("transaction not returned");
      }
      got.ingested.push([program, live, sigs.map((s) => s.signature)]);
    },
    log: (line) => got.logs.push(line),
    saved: () => { got.saves += 1; },
  };
  return { deps, got, configs: ["1", "2", "3"].map((n) => ({ address: `C${n}`, program: `P${n}` })) };
}

test("one Floor config that cannot be followed no longer stops the ones after it", async () => {
  const history = { C1: [sig(9, 900)], C2: [sig(5, 500), sig(4, 400)], C3: [sig(7, 700), sig(6, 600)] };
  const cursors = new Map([["C1", { signature: "s8", slot: 8 }], ["C2", { signature: "s4", slot: 4 }], ["C3", { signature: "s6", slot: 6 }]]);
  const { deps, got, configs } = floorFollow(history, { refuse: { P1: "page", P2: "ingest" }, cursors, followed: new Set(["C1", "C2", "C3"]) });
  await assert.rejects(followConfigs(configs, deps), (e) => e.message === "P1: getSignaturesForAddress: fetch failed; P2: transaction not returned");
  assert.deepEqual([...deps.followed].sort(), ["C1", "C2", "C3"], "a followed config that fails stays followed: a replay would act on nothing");
  assert.deepEqual(got.ingested, [["P3", true, ["s7"]]], "the third is read live, after both failures");
  assert.deepEqual(cursors.get("C3"), { signature: "s7", slot: 7 });
  assert.deepEqual([cursors.get("C1"), cursors.get("C2")], [{ signature: "s8", slot: 8 }, { signature: "s4", slot: 4 }], "a failed config reads on from where it was");
  assert.equal(got.saves, 3, "each config's progress is saved, failed or not");
  // A config that fails part-way keeps, and saves, what it finished.
  const part = floorFollow({ C3: [sig(8, 800), sig(7, 700), sig(6, 600)] }, { refuse: { P3: "after one" }, cursors: new Map([["C3", { signature: "s6", slot: 6 }]]), followed: new Set(["C3"]) });
  await assert.rejects(followConfigs(part.configs.slice(2), part.deps), /^Error: P3: transaction not returned$/);
  assert.deepEqual([part.deps.cursors.get("C3"), part.got.saves], [{ signature: "s7", slot: 7 }, 1]);
  // A restart whose replay fails stays a replay (with no start slot, as here, all of it).
  const replay = floorFollow(history, { refuse: { P2: "ingest" }, cursors: new Map([["C2", { signature: "s4", slot: 4 }]]) });
  await assert.rejects(followConfigs(replay.configs.slice(1, 2), replay.deps), /^Error: P2: transaction not returned$/);
  assert.equal(replay.deps.followed.has("C2"), false);
  replay.deps.page = async () => { throw new Error("fetch failed"); };
  await assert.rejects(followConfigs(replay.configs.slice(1, 2), replay.deps), /P2: fetch failed/);
  assert.deepEqual([replay.deps.followed.has("C2"), replay.deps.cursors.get("C2")], [false, { signature: "s4", slot: 4 }]);
  // Every config followed: no throw.
  const ok = floorFollow(history, { cursors: new Map([["C2", { signature: "s4", slot: 4 }]]), followed: new Set(["C2"]) });
  await followConfigs(ok.configs.slice(1, 2), ok.deps);
  assert.deepEqual(ok.got.ingested, [["P2", true, ["s5"]]]);
});

test("a Floor config resumes as a replay, is live once followed, and with no signature yet is asked again", async () => {
  const history = { C1: [sig(3, 300), sig(2, 200)], C2: [] };
  const cursors = new Map([["C1", { signature: "s2", slot: 2 }]]);
  const followed = new Set();
  const { deps, got, configs } = floorFollow(history, { cursors, followed });
  await followConfigs(configs.slice(0, 2), deps);
  assert.deepEqual(got.ingested, [["P1", false, ["s3"]]], "a restart replays; the empty config ingests nothing");
  assert.deepEqual([[...followed], cursors.has("C2"), got.saves], [["C1"], false, 2]);
  history.C1.unshift(sig(4, 400));
  history.C2.push(sig(1, 100));
  await followConfigs(configs.slice(0, 2), deps);
  assert.deepEqual(got.ingested.slice(1), [["P1", true, ["s4"]]], "followed: live; the anchored config ingests nothing");
  assert.deepEqual([[...followed].sort(), cursors.get("C2")], [["C1", "C2"], { signature: "s1", slot: 1 }]);
  assert.equal(got.logs.length, 0);
  // A cursor the node forgot: said, by program, and re-anchored.
  const forgot = floorFollow({ C3: [sig(6, 600)] }, { cursors: new Map([["C3", { signature: "s5", slot: 5 }]]), followed: new Set(["C3"]) });
  forgot.deps.page = (address, q) => pages([sig(6, 600)], { gone: "s5" }).fetchPage(q);
  await followConfigs(forgot.configs.slice(2), forgot.deps);
  assert.deepEqual([forgot.got.logs.map((l) => [l.level, l.program]), forgot.deps.cursors.get("C3")], [[["error", "P3"]], { signature: "s6", slot: 6 }]);
  // ... and a node that then lists nothing: the cursor is dropped, never kept.
  forgot.deps.page = (address, q) => pages([], { gone: "s6" }).fetchPage(q);
  await followConfigs(forgot.configs.slice(2), forgot.deps);
  assert.equal(forgot.deps.cursors.has("C3"), false);
  // A restart whose cursor is gone cannot replay the gap: it says so, and is live from the next poll.
  const restart = floorFollow({}, { cursors: new Map([["C3", { signature: "s5", slot: 5 }]]) });
  restart.deps.page = (address, q) => pages([sig(6, 600)], { gone: "s5" }).fetchPage(q);
  await followConfigs(restart.configs.slice(2), restart.deps);
  assert.deepEqual([restart.got.logs.map((l) => [l.level, l.program]), restart.got.ingested, [...restart.deps.followed]], [[["error", "P3"]], [], ["C3"]]);
});

test("a Floor config resuming acts on what lands after the slot the process started at", async () => {
  // The process started at slot 4. Its restart replay fails, and then,
  // before a poll succeeds, s5-s7 land (a replaced recovery key, say).
  const history = { C1: [sig(3, 300), sig(2, 200)] };
  const refuse = { P1: "ingest" };
  const { deps, got, configs } = floorFollow(history, { refuse, cursors: new Map([["C1", { signature: "s2", slot: 2 }]]) });
  deps.liveAfterSlot = 4;
  await assert.rejects(followConfigs(configs.slice(0, 1), deps), /^Error: P1: transaction not returned$/);
  // s4 is in the start slot: replayed. Block times do not decide (s6's is earlier).
  history.C1.unshift(sig(7, 700), sig(6, 100), sig(5, 500), sig(4, 400));
  delete refuse.P1;
  await followConfigs(configs.slice(0, 1), deps);
  assert.deepEqual(got.ingested, [["P1", false, ["s4", "s3"]], ["P1", true, ["s7", "s6", "s5"]]], "replayed up to the start, then live");
  assert.deepEqual([[...deps.followed], deps.cursors.get("C1")], [["C1"], { signature: "s7", slot: 7 }]);
  // A restart whose first poll succeeds: the same line, not a replay of all.
  const clean = floorFollow({ C1: [sig(5, 500), sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 2 }]]) });
  clean.deps.liveAfterSlot = 4;
  await followConfigs(clean.configs.slice(0, 1), clean.deps);
  assert.deepEqual(clean.got.ingested, [["P1", false, ["s3"]], ["P1", true, ["s5"]]]);
  assert.deepEqual(clean.got.logs, [], "a replay on a restart is not a lagging node");
  // All of it after the start: all live.
  const after = floorFollow({ C1: [sig(5, 500), sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 2 }]]) });
  after.deps.liveAfterSlot = 2;
  await followConfigs(after.configs.slice(0, 1), after.deps);
  assert.deepEqual(after.got.ingested, [["P1", true, ["s5", "s3"]]], "and no empty replay call");
  // Everything at or before the start slot: all replayed, and an empty live call is not made.
  const old = floorFollow({ C1: [sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 2 }]]) });
  old.deps.liveAfterSlot = 3;
  await followConfigs(old.configs.slice(0, 1), old.deps);
  assert.deepEqual(old.got.ingested, [["P1", false, ["s3"]]]);
  // The line holds on every poll, not only the first: a followed config whose
  // node had not yet listed up to the start replays what it lists later from
  // before it, says so, and acts on the rest.
  const lag = floorFollow({ C1: [sig(5, 500), sig(4, 400), sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 2 }]]), followed: new Set(["C1"]) });
  lag.deps.liveAfterSlot = 4;
  await followConfigs(lag.configs.slice(0, 1), lag.deps);
  assert.deepEqual(lag.got.ingested, [["P1", false, ["s4", "s3"]], ["P1", true, ["s5"]]]);
  assert.deepEqual(lag.got.logs.map((l) => [l.level, l.program, l.rows, l.startSlot, l.slots]), [["warn", "P1", 2, 4, [3, 4]]]);
  // Those rows are never reported, and the line holds for the life of the
  // process, so the line that says so reaches a person (finding 76's rule).
  const alert = alertFor(lag.got.logs[0], new Map(), 0);
  assert.equal(alert?.severity, "warning");
  assert.match(alert.detail, /: 2 rows in slots 3-4, start slot 4 \| program P1$/);
  // A row with no slot last in the replay part (kept by a cursor at slot 0, as
  // below), and the rows out of slot order, the lowest in the middle: the
  // slots are the lowest and highest of the rows that have one, not the
  // first and last.
  const lagNull = floorFollow({ C1: [sig(5, 500), sig(3, 300), sig(1, 100), sig(4, 400), { signature: "sn", slot: null }, sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 0 }]]), followed: new Set(["C1"]) });
  lagNull.deps.liveAfterSlot = 4;
  await followConfigs(lagNull.configs.slice(0, 1), lagNull.deps);
  assert.deepEqual(lagNull.got.ingested, [["P1", false, ["s3", "s1", "s4", "sn"]], ["P1", true, ["s5"]]]);
  assert.deepEqual(lagNull.got.logs.map((l) => [l.rows, l.slots]), [[4, [1, 4]]]);
  // A replay there that fails says nothing (the stall alert covers it), so it is not said each poll.
  const stuck = floorFollow({ C1: [sig(3, 300), sig(2, 200)] }, { refuse: { P1: "ingest" }, cursors: new Map([["C1", { signature: "s2", slot: 2 }]]), followed: new Set(["C1"]) });
  stuck.deps.liveAfterSlot = 4;
  await assert.rejects(followConfigs(stuck.configs.slice(0, 1), stuck.deps), /^Error: P1: transaction not returned$/);
  assert.deepEqual(stuck.got.logs, []);
  // A row with no slot (null over JSON-RPC) among the newest is live: acted on twice at worst, never unsaid.
  const unslotted = floorFollow({ C1: [{ signature: "sn", slot: null }, sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 0 }]]) });
  unslotted.deps.liveAfterSlot = 4;
  await followConfigs(unslotted.configs.slice(0, 1), unslotted.deps);
  assert.deepEqual(unslotted.got.ingested, [["P1", false, ["s3"]], ["P1", true, ["sn"]]]);
  // ... nor does it end the live part: the line is the first row with a
  // slot at or before the start (the node lists newest-first by slot).
  const between = floorFollow({ C1: [sig(7, 700), { signature: "sn", slot: null }, sig(5, 500), sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 0 }]]) });
  between.deps.liveAfterSlot = 4;
  await followConfigs(between.configs.slice(0, 1), between.deps);
  assert.deepEqual([between.got.ingested, between.deps.cursors.get("C1")], [[["P1", false, ["s3"]], ["P1", true, ["s7", "sn", "s5"]]], { signature: "s7", slot: 7 }]);
  // One below the line is older than it: replayed with the rest, in one pass,
  // so nothing is left over to be taken for a lagging node next poll.
  const below = floorFollow({ C1: [sig(4, 400), { signature: "sn", slot: null }, sig(3, 300), sig(2, 200)] }, { cursors: new Map([["C1", { signature: "s2", slot: 0 }]]) });
  below.deps.liveAfterSlot = 4;
  await followConfigs(below.configs.slice(0, 1), below.deps);
  assert.deepEqual([below.got.ingested, below.deps.cursors.get("C1"), [...below.deps.followed]], [[["P1", false, ["s4", "sn", "s3"]]], { signature: "s4", slot: 4 }, ["C1"]]);
});

test("the start slot is the highest confirmed slot any endpoint gives, and none is fatal", async () => {
  const asked = [];
  const endpoint = (slot) => ({ call: async (method, params) => {
    asked.push([method, params]);
    if (slot instanceof Error) throw slot;
    return slot;
  } });
  let own = 0;
  const failover = { call: async () => { own += 1; return 90; }, endpoints: [endpoint(90), endpoint(new Error("fetch failed")), endpoint(120), endpoint(100)] };
  assert.equal(await startSlot(failover), 120, "one endpoint behind or down does not move the line back");
  assert.ok(asked.every(([m, p]) => m === "getSlot" && p[0].commitment === "confirmed"));
  assert.deepEqual([asked.length, own], [4, 0], "every endpoint is asked, and the active one not twice");
  assert.equal(await startSlot(endpoint(7)), 7, "a plain Rpc is asked itself");
  // Every endpoint busy when asked on its own (hurried): FailoverRpc.call waits once and answers.
  const busy = () => endpoint(new Error("429 Too Many Requests"));
  assert.equal(await startSlot({ ...endpoint(130), endpoints: [busy(), busy()] }), 130);
  await assert.rejects(startSlot({ ...busy(), endpoints: [busy(), busy()] }), /no RPC endpoint gave its slot/);
});

test("a Floor config's walk asks the node whether it has the last full page's oldest signature (finding 81)", async () => {
  // Exactly one full page (1000) newer than the cursor s1, so the next page is empty.
  const full = Array.from({ length: 1_001 }, (_, i) => sig(1_001 - i, 1_001 - i));
  const { deps, got, configs } = floorFollow({ C1: full }, { cursors: new Map([["C1", { signature: "s1", slot: 1 }]]), followed: new Set(["C1"]) });
  // A node without it (a failover mid-walk): the walk fails, and nothing moves.
  deps.knows = async (s) => s !== "s2";
  await assert.rejects(followConfigs(configs.slice(0, 1), deps), /^Error: P1: the node returned nothing before s2, .*: walking again$/);
  assert.deepEqual([got.ingested, deps.cursors.get("C1"), [...deps.followed]], [[], { signature: "s1", slot: 1 }, ["C1"]]);
  // The next poll, on a node with it, walks again from s1 and reads the page.
  deps.knows = async () => true;
  await followConfigs(configs.slice(0, 1), deps);
  assert.deepEqual([got.ingested.length, got.ingested[0][1], got.ingested[0][2].length, deps.cursors.get("C1")], [1, true, 1_000, { signature: "s1001", slot: 1_001 }]);
});

test("a Floor config resuming walks back only to the startup bound and says so; a followed one reads it all", async () => {
  // A full page (1000) of history newer than the cursor, older than the bound past the first.
  const long = Array.from({ length: 1_002 }, (_, i) => sig(1_002 - i, 1_002 - i));
  const run = async (followed) => {
    const f = floorFollow({ C1: long }, { cursors: new Map([["C1", { signature: "s1", slot: 1 }]]), followed });
    f.deps.oldestWanted = () => 500;
    await followConfigs(f.configs.slice(0, 1), f.deps);
    return [f.got.logs.map((l) => [l.level, l.program, /older than a day/.test(l.msg)]), f.got.ingested[0][2].length];
  };
  assert.deepEqual(await run(new Set()), [[["error", "P1", true]], 1_000], "resuming: one page, then the gap is said");
  assert.deepEqual(await run(new Set(["C1"])), [[], 1_001], "live: no bound");
});

test("a step that fails once, idles, and fails again much later is not a stall (finding 71, 7)", () => {
  const w = stallWatch({ afterMs: 120_000, everyMs: 600_000 });
  assert.equal(w.failed("veto retry", 0), null);
  w.idle("veto retry");
  assert.equal(w.failed("veto retry", 3_600_000), null, "not 'failing for 3600 s'");
  // Nor without an idle pass in between, when it was not run for that long.
  assert.equal(w.failed("heartbeat", 0), null);
  assert.equal(w.failed("heartbeat", 3_600_000), null);
  // A step retried on its schedule (every minute) still stalls.
  assert.equal(w.failed("pending proposals", 0), null);
  assert.equal(w.failed("pending proposals", 60_000), null);
  assert.equal(w.failed("pending proposals", 120_000), 120_000);
});

test("a refused program-account scan fails its step, after the other scans ran (finding 71, 4)", async () => {
  const ran = [];
  const told = [];
  await assert.rejects(scanAll([
    ["change scan", async () => { throw new Error("getProgramAccounts refused"); }],
    ["exit scan", async () => { ran.push("exit"); }],
  ], (what) => told.push(what)), /change scan: getProgramAccounts refused/);
  assert.deepEqual([ran, told], [["exit"], ["change scan"]]);
  await scanAll([["ok", async () => {}]]);
});

test("a guardian whose key file is refused alerts the webhook before it exits (finding 71, 6)", async () => {
  const dir = mkdtempSync(`${tmpdir()}/bh-start-`);
  const keyPath = `${dir}/guardian.json`;
  Keypair.generate().save(keyPath);
  chmodSync(keyPath, 0o640);
  const bodies = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => { bodies.push(b); res.end("ok"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const cfgPath = `${dir}/g.json`;
    writeFileSync(cfgPath, JSON.stringify({
      rpc: "http://127.0.0.1:9", vaultProgram: "11111111111111111111111111111111", protocolProgram: "11111111111111111111111111111111",
      mints: [], guardianKey: keyPath, alert: { url: `http://127.0.0.1:${server.address().port}/hook`, format: "json" },
    }));
    const main = fileURLToPath(new URL("../guardian/main.mjs", import.meta.url));
    const child = spawn(process.execPath, [main, cfgPath], { stdio: ["ignore", "pipe", "pipe"] });
    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 1);
    assert.equal(bodies.length, 1, "one alert reached the webhook");
    const alert = JSON.parse(bodies[0]);
    assert.equal(alert.severity, "critical");
    assert.match(alert.detail, /guardian stopped: .*open to group or others/);
  } finally {
    server.close();
  }
});

test("a guardian whose config is refused for a misspelt alert format still alerts a Slack hook in Slack's format", async () => {
  const dir = mkdtempSync(`${tmpdir()}/bh-start-`);
  const bodies = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => { bodies.push([req.url, b]); res.end("ok"); });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try {
    const cfgPath = `${dir}/g.json`;
    writeFileSync(cfgPath, JSON.stringify({
      rpc: "http://127.0.0.1:9", vaultProgram: "11111111111111111111111111111111", protocolProgram: "11111111111111111111111111111111",
      mints: [], guardianKey: `${dir}/none.json`, alert: { url: "https://hooks.slack.com/services/T/B/x", format: "slak" },
    }));
    // The guardian's fetch of the Slack URL goes to this server instead
    // (--require: a preload every Node 20 takes).
    writeFileSync(`${dir}/redirect.cjs`, `const f = globalThis.fetch; globalThis.fetch = (u, o) => f(String(u).replace("https://hooks.slack.com", "http://127.0.0.1:${server.address().port}"), o);`);
    const main = fileURLToPath(new URL("../guardian/main.mjs", import.meta.url));
    // A guardian that started instead would retry its dead RPC for ever.
    const child = spawn(process.execPath, ["--require", `${dir}/redirect.cjs`, main, cfgPath], { stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
    let stderr = "";
    child.stderr.on("data", (c) => { stderr += c; });
    const code = await new Promise((r) => { child.on("exit", r); child.on("error", r); });
    assert.equal(code, 1, stderr);
    assert.equal(bodies.length, 1, "one alert reached the webhook");
    assert.equal(bodies[0][0], "/services/T/B/x");
    const body = JSON.parse(bodies[0][1]);
    assert.deepEqual(Object.keys(body), ["text", "unfurl_links", "unfurl_media"]);
    assert.match(body.text, /guardian stopped: config\.alert\.format: "slak" is not one of json, slack, discord/);
  } finally {
    server.close();
  }
});

// A JSON-RPC server answering each method from `answers` (null otherwise);
// an answer `{ error }` is sent as that JSON-RPC error.
async function fakeRpc(answers) {
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => {
      const { id, method } = JSON.parse(b);
      res.setHeader("content-type", "application/json");
      const answer = answers[method];
      res.end(JSON.stringify({ jsonrpc: "2.0", id, ...(answer?.error ? { error: answer.error } : { result: answer ?? null }) }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

// Starts the guardian on `rpc` and `rpcs` for cluster devnet; resolves with
// its exit code and output once it exits, or once `until` matches its output
// (then it is killed, code null).
async function startGuardian(rpc, rpcs, until) {
  const dir = mkdtempSync(`${tmpdir()}/bh-cluster-`);
  const keyPath = `${dir}/guardian.json`;
  Keypair.generate().save(keyPath);
  const cfgPath = `${dir}/g.json`;
  writeFileSync(cfgPath, JSON.stringify({
    rpc, rpcs, cluster: "devnet", vaultProgram: "11111111111111111111111111111111", protocolProgram: "11111111111111111111111111111111",
    mints: [], guardianKey: keyPath, stateFile: `${dir}/state.json`,
  }));
  const main = fileURLToPath(new URL("../guardian/main.mjs", import.meta.url));
  const child = spawn(process.execPath, [main, cfgPath], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const timer = setTimeout(() => child.kill(), 20_000);
  for (const s of [child.stdout, child.stderr]) s.on("data", (c) => { out += c; if (until?.test(out)) child.kill(); });
  const code = await new Promise((r) => child.on("exit", r));
  clearTimeout(timer);
  return { code, out };
}

test("a guardian whose backup endpoint serves another cluster refuses to start (finding 114)", async () => {
  const primary = await fakeRpc({ getGenesisHash: GENESIS.devnet });
  const backup = await fakeRpc({ getGenesisHash: GENESIS.testnet });
  try {
    // The old check asked the active endpoint alone, passed, and went on.
    const { code, out } = await startGuardian(primary.url, [backup.url]);
    assert.equal(code, 1, out);
    const host = new URL(backup.url).host.replaceAll(".", "\\.");
    assert.match(out, new RegExp(`guardian stopped: config.cluster is devnet, but RPC endpoint ${host} \\(rpcs\\[0\\]\\) serves another cluster \\(genesis ${GENESIS.testnet}\\)`));
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

test("a guardian whose backup endpoint does not answer starts, and says its cluster is unchecked (finding 114)", async () => {
  const primary = await fakeRpc({ getGenesisHash: GENESIS.devnet });
  try {
    // Killed at a later startup step: it went on past the check.
    const { code, out } = await startGuardian(primary.url, ["http://127.0.0.1:9"], /no record of executed changes yet/);
    assert.equal(code, null, out);
    assert.match(out, /RPC endpoint 127\.0\.0\.1:9 \(rpcs\[0\]\): getGenesisHash: fetch failed \(.+\): no answer to getGenesisHash, so not used until it answers on devnet/);
    assert.doesNotMatch(out, /guardian stopped/);
  } finally {
    primary.server.close();
  }
});

test("a guardian's log line stays well-formed JSON when its cut of an RPC error halves a surrogate pair", async () => {
  // The backup's error is cut to 160 UTF-16 units; the emoji's first half is unit 159.
  const pre = 'getGenesisHash: {"code":-32005,"message":"';
  const primary = await fakeRpc({ getGenesisHash: GENESIS.devnet });
  const backup = await fakeRpc({ getGenesisHash: { error: { code: -32005, message: `${"x".repeat(159 - pre.length)}😀` } } });
  try {
    const { code, out } = await startGuardian(primary.url, [backup.url], /no record of executed changes yet/);
    assert.equal(code, null, out);
    assert.match(out, /\(rpcs\[0\]\): getGenesisHash: \{\\"code\\":-32005,\\"message\\":\\"x+\uFFFD: no answer to getGenesisHash/);
    assert.doesNotMatch(out, /\\u[dD][89a-fA-F]/);
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

// As before finding 114's change: with no endpoint answering, the start is refused.
test("a guardian none of whose endpoints answers the cluster check refuses to start (finding 114)", async () => {
  const { code, out } = await startGuardian("http://127.0.0.1:9", ["http://127.0.0.1:7"]);
  assert.equal(code, 1, out);
  assert.match(out, /guardian stopped: getGenesisHash: /);
});

test("a guardian whose primary is on another cluster says so, even with its backup down (finding 114)", async () => {
  const primary = await fakeRpc({ getGenesisHash: GENESIS.testnet });
  try {
    const { code, out } = await startGuardian(primary.url, ["http://127.0.0.1:9"]);
    assert.equal(code, 1, out);
    const host = new URL(primary.url).host.replaceAll(".", "\\.");
    assert.match(out, new RegExp(`guardian stopped: config.cluster is devnet, but RPC endpoint ${host} \\(rpc\\) serves another cluster \\(genesis ${GENESIS.testnet}\\)`));
  } finally {
    primary.server.close();
  }
});

test("a guardian whose primary does not answer at start moves to the checked backup at once (finding 114)", async () => {
  const backup = await fakeRpc({ getGenesisHash: GENESIS.devnet });
  const silent = createServer(() => {}); // takes the request, never answers
  await new Promise((r) => silent.listen(0, "127.0.0.1", r));
  try {
    // Without the move, the first read waits out the primary's 10 s timeout.
    const t0 = Date.now();
    const primary = `http://127.0.0.1:${silent.address().port}`;
    const { code, out } = await startGuardian(primary, [backup.url], /no record of executed changes yet/);
    assert.equal(code, null, out);
    assert.ok(Date.now() - t0 < 8_000, `took ${Date.now() - t0} ms`);
    const [from, to] = [new URL(primary).host, new URL(backup.url).host].map((h) => h.replaceAll(".", "\\."));
    assert.match(out, new RegExp(`RPC endpoint ${from} \\(rpc\\) is failing; now using ${to} \\(rpcs\\[0\\]\\)`));
    assert.match(out, new RegExp(`RPC endpoint ${from} \\(rpc\\): no answer within 2 s`));
    // The failover's line says why, and its alert shows it (finding 128).
    const [failover] = out.split("\n").filter((l) => l.includes(" is failing; now using ")).map((l) => JSON.parse(l));
    assert.ok(failover.error, out);
    assert.ok(alertFor(failover, new Map(), 0).detail.endsWith(` | ${failover.error}`), failover.error);
    // It names the entries it moved between, which key its repeats: a move
    // to another backup is news (alert.test.mjs).
    assert.deepEqual([failover.endpointFrom, failover.endpoint], [`${new URL(primary).host} (rpc)`, `${new URL(backup.url).host} (rpcs[0])`]);
  } finally {
    backup.server.close();
    silent.closeAllConnections();
    silent.close();
  }
});

test("a backup that never answers holds the start up for the grace, not its timeout (finding 114)", async () => {
  const primary = await fakeRpc({ getGenesisHash: GENESIS.devnet });
  const silent = createServer(() => {}); // takes the request, never answers
  await new Promise((r) => silent.listen(0, "127.0.0.1", r));
  try {
    const t0 = Date.now();
    const { code, out } = await startGuardian(primary.url, [`http://127.0.0.1:${silent.address().port}`], /did not answer|no answer to getGenesisHash/);
    assert.equal(code, null, out);
    assert.match(out, /\(rpcs\[0\]\): no answer within 2 s: no answer to getGenesisHash/);
    assert.ok(Date.now() - t0 < 8_000, `took ${Date.now() - t0} ms`);
  } finally {
    primary.server.close();
    silent.closeAllConnections();
    silent.close();
  }
});
