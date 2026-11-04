// The watchdog (cloud/guardian/watchdog.mjs): a single-shot check of the
// guardian sets from another host, so a dead guardian fleet is heard about
// even when no guardian is running to say so (docs/09, finding 151).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { b58encode, SYSVAR_OWNER, IDS } from "../lib/solana.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { GENESIS } from "../guardian/policy.mjs";
import { aliveOnChain, setHealth, judgeSet, evaluate, vaultPending, floorPending, settings } from "../guardian/watchdog.mjs";
import { protocolBytes, floorBytes, changeBytes, clockBytes, accountInfo, rpcServer } from "./chain-fixtures.mjs";

const DAY = 86_400;
const NOW = 1_000_000;
const KEYS = [1, 2, 3, 4, 5].map((i) => b58encode(new Uint8Array(32).fill(i)));
const VAULT = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
const FLOOR = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
const PROGRAM = KEYS[4];
// A set: `beats` are each key's heartbeat age in seconds.
const set = (threshold, ...beats) => ({ guardians: KEYS.slice(0, beats.length), lastHeartbeat: beats.map((a) => NOW - a), threshold, heartbeatIntervalS: DAY, frozenUntil: 0 });

test("a guardian is live by the chain's rule exactly: within its interval, never ahead of the clock", () => {
  assert.equal(aliveOnChain(NOW - DAY, DAY, NOW), true);
  assert.equal(aliveOnChain(NOW - DAY - 1, DAY, NOW), false);
  assert.equal(aliveOnChain(NOW + 5, DAY, NOW), false, "a heartbeat after the clock does not count on chain");
  assert.equal(aliveOnChain(NOW, DAY - 1, NOW), false, "an interval out of range keeps nobody live");
  assert.equal(aliveOnChain(NOW, 31 * DAY, NOW), false);
});

test("a set's health: who is live, when each stops counting, and when the quorum goes if nobody heartbeats", () => {
  const h = setHealth(set(2, 3_600, 7_200, 20 * 3_600, 2 * DAY), NOW);
  assert.deepEqual([h.count, h.threshold, h.live, h.margin], [4, 2, 3, 4]);
  // Live deadlines: +23h, +22h, +4h; the second largest ends the quorum.
  assert.equal(h.quorumLostAtS, NOW + DAY - 7_200 + 1);
  assert.equal(h.lastLiveUntilS, NOW + DAY - 3_600);
  assert.deepEqual(h.guardians.map((g) => [g.live, g.stopsCountingInS ?? null]), [[true, DAY - 3_600], [true, DAY - 7_200], [true, 4 * 3_600], [false, null]]);
  assert.equal(setHealth(set(2, 3_600, 2 * DAY), NOW).quorumLostInS, 0, "already lost");
});

test("the verdict: ok, warning, critical, unreadable, each for its reason", () => {
  const verdict = (vault, extra = {}) => evaluate({ vault: vault && { protocol: "P", set: vault, pending: extra.pending ?? [] }, floors: extra.floors ?? [], unreadable: extra.unreadable ?? [], notes: extra.notes ?? [] }, NOW, { warnS: 3_600 });
  const ok = verdict(set(2, 60, 120, 180, 240));
  assert.deepEqual([ok.exit, ok.status, ok.critical, ok.warnings], [0, "ok", [], []]);
  assert.equal(ok.sets[0].quorumLostInS, DAY - 120 + 1);
  // Live, but under threshold + 2: one lost key and one rogue lock governance.
  const short = verdict(set(2, 60, 120, 180, 2 * DAY));
  assert.equal(short.exit, 1);
  assert.match(short.warnings.join("\n"), /3 of 4 guardians live, under threshold \+ 2 \(4\)/);
  assert.match(short.warnings.join("\n"), new RegExp(`guardian ${KEYS[3]} is not live`));
  // A key about to stop counting, and so the quorum with it.
  const late = verdict(set(2, 60, DAY - 1_800, DAY - 1_200, 120));
  assert.equal(late.exit, 1);
  assert.match(late.warnings.join("\n"), new RegExp(`guardian ${KEYS[1]} stops counting in 0\\.5h`));
  const quorum = verdict(set(2, DAY - 600, DAY - 300, 2 * DAY, 2 * DAY));
  assert.match(quorum.warnings.join("\n"), /the quorum is lost in 0\.1h unless guardians heartbeat/);
  // Under the threshold: critical.
  const under = verdict(set(2, 60, 2 * DAY, 2 * DAY, 2 * DAY));
  assert.deepEqual([under.exit, under.status], [2, "critical"]);
  assert.match(under.critical[0], /vault: 1 of 4 guardians live, under the threshold 2/);
  // None live with a loosening pending: nobody can veto it (docs/17 §3, 3).
  const pending = [{ what: "loosening #7 (admin)", etaS: NOW + 5 * 3_600 }];
  const unguarded = verdict(set(2, 2 * DAY, 2 * DAY, 2 * DAY, 2 * DAY), { pending });
  assert.equal(unguarded.exit, 2);
  assert.match(unguarded.critical.join("\n"), /loosening #7 \(admin\) executes in 5\.0h with no live guardian to veto it/);
  assert.equal(unguarded.sets[0].pending[0].inS, 5 * 3_600);
  // Unread: 3, unless something read is already critical.
  assert.equal(verdict(null, { unreadable: ["the protocol account: x"] }).exit, 3);
  assert.equal(verdict(set(2, 60, 2 * DAY, 2 * DAY, 2 * DAY), { unreadable: ["the change scan: refused"] }).exit, 2);
  assert.equal(verdict(set(2, 60, 120, 180, 240), { notes: ["endpoint x serves another cluster"] }).exit, 1);
  // A Floor set is judged the same way, and named.
  const floor = verdict(set(2, 60, 120, 180, 240), { floors: [{ program: PROGRAM, set: { ...set(3, 60, 2 * DAY, 2 * DAY, 2 * DAY), status: "live" }, pending: [] }] });
  assert.equal(floor.exit, 2);
  assert.match(floor.critical[0], new RegExp(`floor ${PROGRAM}: 1 of 4 guardians live, under the threshold 3`));
  // No set at all is critical too.
  assert.match(judgeSet("vault", setHealth(set(0), NOW), [], NOW, 3_600).critical[0], /no guardian set/);
});

test("pending loosenings: open changes not stale, the seal, lifeboat exits, a Floor proposal, soonest first", () => {
  const protocol = { abdications: 0, versions: [0, 0, 0, 0, 0], sealed: false, sealExecutableS: NOW + 50, sealExpiresS: NOW + DAY, sealVetoed: false };
  const change = (id, kind, extra = {}) => ({ id: BigInt(id), kind, vetoed: false, executed: false, executableS: NOW + 100 * id, expiresS: NOW + DAY, baseVersion: 0, ...extra });
  const changes = [change(1, 3), change(2, 3, { vetoed: true }), change(3, 4, { baseVersion: 9 }), change(4, 3, { executableS: NOW - 10 })];
  const vaults = [{ mint: KEYS[0], vault: { exitAmount: 500n, exitVetoed: false, exitExecutableS: NOW + 70, exitExpiresS: NOW + DAY } }];
  assert.deepEqual(vaultPending(protocol, changes, vaults, NOW).map((p) => p.what), ["loosening #4 (admin)", "the seal", `a lifeboat exit of 500 (${KEYS[0]})`, "loosening #1 (admin)"]);
  assert.deepEqual(floorPending({ pendingKind: 1, pendingId: 3n, pendingVetoed: false, pendingEta: NOW + 9, pendingExpires: NOW + DAY }, NOW).map((p) => p.what), ["proposal #3 (upgrade)"]);
  assert.deepEqual(floorPending({ pendingKind: 1, pendingVetoed: true, pendingExpires: NOW + DAY }, NOW), []);
});

test("settings come from a guardian config and the flags, the flags winning", () => {
  const dir = mkdtempSync(`${tmpdir()}/bh-wd-`);
  writeFileSync(`${dir}/g.json`, JSON.stringify({ rpc: "http://a", rpcs: ["http://b"], cluster: "devnet", vaultProgram: VAULT, protocolProgram: PROGRAM, mints: [KEYS[0]], alert: { url: "http://hook" }, guardianKey: "/k" }));
  const s = settings(["--config", `${dir}/g.json`, "--warn-hours", "2"]);
  assert.deepEqual([s.rpcs, s.cluster, s.vaultProgram, s.protocolProgram, s.mints, s.warnS, s.alert.url], [["http://a", "http://b"], "devnet", VAULT, PROGRAM, [KEYS[0]], 7_200, "http://hook"]);
  assert.deepEqual(settings(["--config", `${dir}/g.json`, "--rpc", "http://c", "--rpc", "http://d"]).rpcs, ["http://c", "http://d"]);
  assert.throws(() => settings(["--vault-program", VAULT, "--protocol", PROGRAM]), /no endpoint/);
  assert.throws(() => settings(["--rpc", "http://a", "--protocol", PROGRAM]), /--vault-program/);
  assert.throws(() => settings(["--rpc", "http://a", "--vault-program", VAULT, "--protocol", PROGRAM, "--cluster", "mainnet"]), /--cluster must be one of/);
  assert.throws(() => settings(["--rpc", "http://a", "--vault-program", VAULT, "--protocol", PROGRAM, "--warn-hours", "x"]), /positive number/);
});

// The CLI against a node holding `protocol` (bytes, owned by `owner`), an
// optional Floor config and change accounts, on `genesis`.
async function node({ protocol, owner = VAULT, floor = null, changes = [], genesis = GENESIS.devnet, now = NOW }) {
  const vc = await new VaultClient(VAULT, PROGRAM).init();
  const fc = await new FloorClient(FLOOR, PROGRAM).init();
  const [p, f, clock] = [b58encode(vc.protocol), b58encode(fc.config), b58encode(IDS.clock)];
  return rpcServer((method, params) => {
    if (method === "getGenesisHash") return genesis;
    if (method === "getProgramAccounts") return changes.map((c, i) => ({ pubkey: KEYS[i], account: { owner: VAULT, data: [Buffer.from(c).toString("base64"), "base64"] } }));
    if (method !== "getAccountInfo") return null;
    if (params[0] === clock) return accountInfo(clockBytes(now), SYSVAR_OWNER);
    if (params[0] === p) return accountInfo(protocol, owner);
    if (params[0] === f) return accountInfo(floor, FLOOR);
    return accountInfo(null);
  });
}

async function watchdog(args) {
  const file = fileURLToPath(new URL("../guardian/watchdog.mjs", import.meta.url));
  const child = spawn(process.execPath, [file, "--vault-program", VAULT, "--protocol-program", PROGRAM, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", (c) => { err += c; });
  const code = await new Promise((r) => child.on("exit", r));
  const lines = out.trim().split("\n");
  return { code, lines, line: JSON.parse(lines.at(-1) || "{}"), err };
}

test("the watchdog CLI: a healthy Vault and Floor set exit 0 with one JSON line, judged on the chain's clock", async () => {
  const beats = [60, 120, 180, 240].map((a) => NOW - a);
  const n = await node({
    protocol: protocolBytes({ guardians: KEYS.slice(0, 4), heartbeats: beats, threshold: 2, frozenUntil: NOW + 600 }),
    floor: floorBytes({ program: PROGRAM, guardians: KEYS.slice(0, 4), heartbeats: beats, threshold: 2 }),
  });
  try {
    const { code, lines, line } = await watchdog(["--rpc", n.url, "--cluster", "devnet", "--floor-program", FLOOR, "--floor-protected", PROGRAM]);
    assert.equal(code, 0, lines.join("\n"));
    assert.equal(lines.length, 1, "one line");
    assert.deepEqual([line.status, line.exit, line.clock, line.clockS], ["ok", 0, "chain", NOW]);
    assert.deepEqual(line.sets.map((s) => [s.name, s.live, s.threshold]), [["vault", 4, 2], [`floor ${PROGRAM}`, 4, 2]]);
    assert.equal(line.sets[0].frozen, true, "the freeze state is reported");
    assert.equal(line.sets[0].guardians[0].ageS, 60);
  } finally {
    n.close();
  }
});

test("the watchdog CLI: no live guardian with a loosening pending exits 2 and posts the alert", async () => {
  const vc = await new VaultClient(VAULT, PROGRAM).init();
  const n = await node({
    protocol: protocolBytes({ guardians: KEYS.slice(0, 4), heartbeats: [1, 1, 1, 1].map(() => NOW - 2 * DAY), threshold: 2 }),
    changes: [changeBytes({ protocol: b58encode(vc.protocol), id: 7n, kind: 3, target: KEYS[0], executableS: NOW + 3_600, expiresS: NOW + DAY })],
  });
  const bodies = [];
  const hook = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", () => { bodies.push(JSON.parse(b)); res.end("ok"); });
  });
  await new Promise((r) => hook.listen(0, "127.0.0.1", r));
  try {
    const { code, line } = await watchdog(["--rpc", n.url, "--alert-url", `http://127.0.0.1:${hook.address().port}/hook`, "--alert-format", "json"]);
    assert.equal(code, 2, JSON.stringify(line));
    assert.equal(line.status, "critical");
    assert.match(line.critical.join("\n"), /0 of 4 guardians live, under the threshold 2/);
    assert.match(line.critical.join("\n"), /loosening #7 \(admin\) executes in 1\.0h with no live guardian to veto it/);
    assert.equal(bodies.length, 1);
    assert.deepEqual([bodies[0].severity, bodies[0].title], ["critical", "Bulkhead watchdog: critical"]);
    assert.match(bodies[0].detail, /no live guardian to veto it/);
  } finally {
    n.close();
    hook.close();
  }
});

test("the watchdog CLI reads only endpoints on its cluster, and only accounts their programs own", async () => {
  const healthy = protocolBytes({ guardians: KEYS.slice(0, 4), heartbeats: [60, 60, 60, 60].map((a) => NOW - a), threshold: 2 });
  const dead = protocolBytes({ guardians: KEYS.slice(0, 4), heartbeats: [1, 1, 1, 1].map(() => NOW - 2 * DAY), threshold: 2 });
  // The primary is a testnet copy saying everyone is dead; the backup is devnet.
  const other = await node({ protocol: dead, genesis: GENESIS.testnet });
  const backup = await node({ protocol: healthy });
  // A lying endpoint: the right cluster, the protocol owned by another program.
  const lying = await node({ protocol: healthy, owner: FLOOR });
  try {
    const a = await watchdog(["--rpc", other.url, "--rpc", backup.url, "--cluster", "devnet"]);
    assert.equal(a.code, 1, JSON.stringify(a.line));
    assert.equal(a.line.sets[0].live, 4, "read from the backup");
    assert.match(a.line.warnings.join("\n"), new RegExp(`serves another cluster than devnet \\(genesis ${GENESIS.testnet}\\): not read`));
    const b = await watchdog(["--rpc", lying.url]);
    assert.equal(b.code, 3, JSON.stringify(b.line));
    assert.match(b.line.unreadable.join("\n"), /the protocol account: getAccountInfo: answer not believed: account \w+ is owned by cGfHiC6K/);
    assert.match(b.line.warnings.join("\n"), /served an account with the wrong owner/);
    // Nothing answering at all: 3, within the time limit.
    const c = await watchdog(["--rpc", "http://127.0.0.1:9", "--timeout-s", "20"]);
    assert.equal(c.code, 3);
    assert.equal(c.line.status, "unreadable");
  } finally {
    other.close();
    backup.close();
    lying.close();
  }
});
