// Every account the guardian decodes is read only as the program that must
// own it owns it (external audit, F-01): a correctly shaped account with the
// wrong owner is a lying or broken endpoint's, never decoded, and with
// backups the next endpoint is asked. One test per class of read.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Rpc, FailoverRpc, decodeProtocol, decodeFloor, key, b58encode, ownerProblem, SYSVAR_OWNER, TOKEN_PROGRAM_IDS } from "../lib/solana.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { activeTickets, activeChanges } from "../guardian/chain.mjs";
import { GENESIS } from "../guardian/policy.mjs";
import { Keypair } from "../lib/signer.mjs";
import { protocolBytes, floorBytes, changeBytes, clockBytes, accountInfo, rpcServer } from "./chain-fixtures.mjs";

const VAULT = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
const FLOOR = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
const WRONG = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const PROTOCOL = "8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb";
const GUARDIAN = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const shaped = protocolBytes({ guardians: [GUARDIAN], heartbeats: [1_000], threshold: 1, frozenUntil: 9_999 });

test("ownerProblem names the owner found and the one wanted; no account is not a problem", () => {
  assert.equal(ownerProblem(PROTOCOL, { owner: VAULT }, VAULT), null);
  assert.equal(ownerProblem(PROTOCOL, null, VAULT), null);
  assert.equal(ownerProblem("t", { owner: TOKEN_PROGRAM_IDS[1] }, TOKEN_PROGRAM_IDS), null);
  assert.equal(ownerProblem(PROTOCOL, { owner: WRONG }, VAULT), `account ${PROTOCOL} is owned by ${WRONG}, not ${VAULT}`);
  assert.match(ownerProblem(PROTOCOL, {}, VAULT), /owned by \(no owner given\)/);
});

test("a Vault or Floor account with the wrong owner is a bad answer on one endpoint, never decoded (F-01)", async () => {
  const lying = await rpcServer((method, params) => (method === "getAccountInfo" ? accountInfo(params[0] === PROTOCOL ? shaped : floorBytes({ program: GUARDIAN }), WRONG, 7) : null));
  try {
    const told = [];
    const rpc = new Rpc(lying.url, { onBadAnswer: (url, why) => told.push(why) });
    // Unchecked, the bytes decode as a protocol: what the guardian used to act on.
    assert.equal(decodeProtocol((await rpc.account(PROTOCOL)).bytes).frozenUntil, 9_999);
    const err = await rpc.account(PROTOCOL, "confirmed", { owner: VAULT }).then(() => null, (e) => e);
    assert.match(err?.message ?? "", new RegExp(`getAccountInfo: answer not believed: account ${PROTOCOL} is owned by ${WRONG}, not ${VAULT}`));
    assert.equal(err.badAnswer, `account ${PROTOCOL} is owned by ${WRONG}, not ${VAULT}`);
    assert.equal(err.rpcError, undefined, "no JSON-RPC code: endpoint trouble, so a backup is asked");
    // The guardian's protocol read keeps its minContextSlot (finding 137).
    await assert.rejects(rpc.account(PROTOCOL, "confirmed", { owner: VAULT, minContextSlot: 5 }), /answer not believed/);
    assert.equal(lying.calls.at(-1)[1][1].minContextSlot, 5);
    // A Floor config read the same way (readFloor, stop.mjs's readConfig).
    await assert.rejects(rpc.account(GUARDIAN, "confirmed", { owner: FLOOR }), /answer not believed/);
    assert.equal(told.length, 3);
    assert.equal(lying.calls.filter(([m]) => m === "getAccountInfo").length, 4, "an answer is not asked again");
  } finally {
    lying.close();
  }
});

test("with backups, a wrong owner moves the read to the next endpoint and off the lying one (F-01)", async () => {
  const lying = await rpcServer((method) => (method === "getAccountInfo" ? accountInfo(shaped, WRONG) : null));
  const honest = await rpcServer((method) => (method === "getAccountInfo" ? accountInfo(protocolBytes({ frozenUntil: 5 }), VAULT) : null));
  try {
    const told = [];
    const switches = [];
    const rpc = new FailoverRpc([lying.url, honest.url], { onBadAnswer: (url, why, at) => told.push([url, at]), onSwitch: (from, to) => switches.push([from, to]) });
    const acc = await rpc.account(PROTOCOL, "confirmed", { owner: VAULT });
    assert.equal(decodeProtocol(acc.bytes).frozenUntil, 5, "the honest endpoint's account");
    assert.deepEqual(told, [[lying.url, 0]]);
    assert.deepEqual(switches, [[lying.url, honest.url]]);
    assert.equal(rpc.active, 1);
    // A raw read with `accept` (readProtocolAccount's form) falls through too.
    rpc.switchTo(0, new Error("back"));
    const r = await rpc.call("getAccountInfo", [PROTOCOL, { encoding: "base64" }], { accept: (res) => ownerProblem(PROTOCOL, res?.value, VAULT) });
    assert.equal(r.value.owner, VAULT);
    // Every endpoint lying: the read fails; it never returns their bytes.
    const both = new FailoverRpc([lying.url, lying.url]);
    await assert.rejects(both.account(PROTOCOL, "confirmed", { owner: VAULT }), /answer not believed/);
  } finally {
    lying.close();
    honest.close();
  }
});

test("a ticket or change scan listing an account another program owns decodes none of it (F-01)", async () => {
  const ticket = new Uint8Array(200);
  ticket.set(new TextEncoder().encode("BHTICKT1"));
  ticket.set(key(PROTOCOL), 8);
  const change = changeBytes({ protocol: PROTOCOL, target: GUARDIAN, executableS: 10, expiresS: 20 });
  const row = (bytes, owner) => ({ pubkey: GUARDIAN, account: { owner, data: [Buffer.from(bytes).toString("base64"), "base64"] } });
  // An `rpc` that ignores `accept` is still caught.
  for (const [scan, bytes] of [[activeTickets, ticket], [activeChanges, change]]) {
    const plain = { call: async () => [row(bytes, VAULT), row(bytes, WRONG)] };
    await assert.rejects(scan(plain, VAULT, PROTOCOL), new RegExp(`getProgramAccounts: answer not believed: account ${GUARDIAN} is owned by ${WRONG}`));
    const unowned = { call: async () => [{ pubkey: GUARDIAN, account: { data: [Buffer.from(bytes).toString("base64"), "base64"] } }] };
    await assert.rejects(scan(unowned, VAULT, PROTOCOL), /owned by \(no owner given\)/);
  }
  // With backups, the honest endpoint's list is read.
  const lying = await rpcServer(() => [row(change, WRONG)]);
  const honest = await rpcServer(() => [row(change, VAULT)]);
  try {
    const changes = await activeChanges(new FailoverRpc([lying.url, honest.url]), VAULT, PROTOCOL);
    assert.deepEqual(changes.map((c) => c.target), [GUARDIAN]);
  } finally {
    lying.close();
    honest.close();
  }
});

test("the freshness counters never switch to a backup serving another program's account (F-01, finding 138)", async () => {
  // A protocol account whose next ticket id is `n`.
  const at = (n, owner) => {
    const d = protocolBytes();
    new DataView(d.buffer).setBigUint64(8 + 96 + 256 + 64 + 4 + 24 + 8, BigInt(n), true);
    return accountInfo(d, owner);
  };
  const primary = await rpcServer(() => at(7, VAULT));
  const lying = await rpcServer(() => at(9, WRONG));
  const counter = (_address, bytes) => decodeProtocol(bytes).nextTicketId;
  try {
    const told = [];
    const rpc = new FailoverRpc([primary.url, lying.url], { onBadAnswer: (url, why, i) => told.push(i) });
    for (const nowMs of [0, 31_000, 62_000]) assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs, owner: VAULT })).switched, false);
    assert.deepEqual(told, [1, 1, 1]);
    // Unchecked, its larger counter wins the switch: what a lying backup bought.
    const blind = new FailoverRpc([primary.url, lying.url]);
    await blind.crossCheckCounters([PROTOCOL], counter, { nowMs: 0 });
    assert.equal((await blind.crossCheckCounters([PROTOCOL], counter, { nowMs: 31_000 })).switched, true);
  } finally {
    primary.close();
    lying.close();
  }
});

test("attest believes only the Vault's return data and the Clock sysvar, and asks a backup otherwise (F-01)", async () => {
  const vc = await new VaultClient(VAULT, GUARDIAN).init();
  const ret = new Uint8Array(64);
  new DataView(ret.buffer).setBigUint64(8, 400n, true); // worst1h
  const sim = (programId, clockOwner) => (method) => {
    if (method === "getLatestBlockhash") return { value: { blockhash: GUARDIAN, lastValidBlockHeight: 9 } };
    if (method !== "simulateTransaction") return null;
    return { value: { err: null, logs: [], returnData: { programId, data: [Buffer.from(ret).toString("base64"), "base64"] }, accounts: [{ owner: clockOwner, data: [Buffer.from(clockBytes(1_700)).toString("base64"), "base64"] }] } };
  };
  const servers = [];
  const serve = async (h) => { const s = await rpcServer(h); servers.push(s); return s.url; };
  try {
    const payer = key(GUARDIAN);
    await assert.rejects(vc.attest(new Rpc(await serve(sim(WRONG, SYSVAR_OWNER))), payer, GUARDIAN), /return data came from TokenkegQ.*, not the Vault program/);
    await assert.rejects(vc.attest(new Rpc(await serve(sim(VAULT, WRONG))), payer, GUARDIAN), /account SysvarC1ock.* is owned by TokenkegQ/);
    const good = await serve(sim(VAULT, SYSVAR_OWNER));
    const a = await vc.attest(new Rpc(good), payer, GUARDIAN);
    assert.deepEqual([a.worst1h, a.clockS], [400n, 1_700]);
    const failover = new FailoverRpc([await serve(sim(VAULT, WRONG)), good]);
    assert.equal((await vc.attest(failover, payer, GUARDIAN)).worst1h, 400n);
    assert.equal(failover.active, 1);
  } finally {
    for (const s of servers) s.close();
  }
});

test("a Floor config read as Floor owns it decodes; one Floor does not own is refused (F-01)", async () => {
  const bytes = floorBytes({ program: GUARDIAN, guardians: [GUARDIAN], heartbeats: [5], threshold: 1 });
  const s = await rpcServer(() => accountInfo(bytes, FLOOR));
  try {
    const rpc = new Rpc(s.url);
    assert.equal(decodeFloor((await rpc.account(PROTOCOL, "confirmed", { owner: FLOOR })).bytes).program, GUARDIAN);
    await assert.rejects(rpc.account(PROTOCOL, "confirmed", { owner: VAULT }), /is owned by cGfHiC6K.*, not US517G59/);
  } finally {
    s.close();
  }
});

// The guardian itself (main.mjs) against a primary serving the protocol
// account with another owner and a backup serving it as the Vault owns it.
async function runGuardian(rpc, rpcs, until, killMs = 20_000) {
  const dir = mkdtempSync(`${tmpdir()}/bh-owner-`);
  const keyPath = `${dir}/guardian.json`;
  Keypair.generate().save(keyPath);
  const cfgPath = `${dir}/g.json`;
  writeFileSync(cfgPath, JSON.stringify({ rpc, rpcs, cluster: "devnet", vaultProgram: VAULT, protocolProgram: GUARDIAN, mints: [], guardianKey: keyPath, stateFile: `${dir}/state.json` }));
  const main = fileURLToPath(new URL("../guardian/main.mjs", import.meta.url));
  const child = spawn(process.execPath, [main, cfgPath], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const timer = setTimeout(() => child.kill(), killMs);
  for (const s of [child.stdout, child.stderr]) s.on("data", (c) => { out += c; if (until.test(out)) child.kill(); });
  const code = await new Promise((r) => child.on("exit", r));
  clearTimeout(timer);
  return { code, out };
}

test("the guardian reads the protocol from a backup when its primary serves it with the wrong owner, and alerts (F-01)", async () => {
  const vc = await new VaultClient(VAULT, GUARDIAN).init();
  const protocol = b58encode(vc.protocol);
  const node = (owner) => (method, params) => {
    if (method === "getGenesisHash") return GENESIS.devnet;
    if (method === "getAccountInfo") return params[0] === protocol ? accountInfo(protocolBytes({ frozenUntil: 1 }), owner, 3) : accountInfo(null);
    if (method === "getSignaturesForAddress") return [];
    if (method === "getSlot") return 3;
    if (method === "getBalance") return { value: 1e9 };
    return null;
  };
  const lying = await rpcServer(node(WRONG));
  const honest = await rpcServer(node(VAULT));
  try {
    const { code, out } = await runGuardian(lying.url, [honest.url], /"caught up"/);
    assert.equal(code, null, out);
    const lines = out.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
    const bad = lines.find((l) => l.msg?.includes("served an account with the wrong owner"));
    assert.ok(bad, out);
    assert.equal(bad.level, "error", "an error line: it alerts");
    assert.equal(bad.endpoint, `${new URL(lying.url).host} (rpc)`);
    assert.match(bad.error, new RegExp(`account ${protocol} is owned by ${WRONG}, not ${VAULT}`));
    assert.ok(lines.some((l) => /is failing; now using/.test(l.msg ?? "")), "it moved to the backup");
    assert.ok(!lines.some((l) => /startup chain sync failed/.test(l.msg ?? "")), "the read succeeded through the backup");
  } finally {
    lying.close();
    honest.close();
  }
});

test("a guardian whose only endpoint serves the protocol with the wrong owner reads nothing from it (F-01)", async () => {
  const vc = await new VaultClient(VAULT, GUARDIAN).init();
  const protocol = b58encode(vc.protocol);
  const only = await rpcServer((method, params) => {
    if (method === "getGenesisHash") return GENESIS.devnet;
    if (method === "getAccountInfo") return params[0] === protocol ? accountInfo(protocolBytes({ frozenUntil: 1 }), WRONG, 3) : accountInfo(null);
    if (method === "getSignaturesForAddress") return [];
    if (method === "getBalance") return { value: 1e9 };
    return null;
  });
  try {
    const { code, out } = await runGuardian(only.url, undefined, /startup chain sync failed/);
    assert.equal(code, null, out);
    assert.match(out, /served an account with the wrong owner: nothing is read from that answer, and the read fails/);
    assert.match(out, /startup chain sync failed \(attempt 1 of 20\): getAccountInfo: answer not believed/);
    assert.doesNotMatch(out, /"caught up"/);
  } finally {
    only.close();
  }
});
