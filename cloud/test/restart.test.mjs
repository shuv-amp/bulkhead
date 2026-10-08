// What a guardian keeps across a restart, how it reads on after one, and how
// it says it is failing (docs/09, finding 71).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, chmodSync, statSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { newState } from "../guardian/policy.mjs";
import { stateJson, restoreState, writeStateFile } from "../guardian/statefile.mjs";
import { followAccount } from "../guardian/follow.mjs";
import { stallWatch, scanAll } from "../guardian/alert.mjs";
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
