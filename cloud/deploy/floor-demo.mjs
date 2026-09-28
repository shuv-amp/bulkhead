#!/usr/bin/env node
// Floor on a real program, end to end: on a local validator with a mainnet
// program's bytes (scripts/floor-demo.sh), or on devnet against the deployed
// Floor (scripts/floor-devnet.sh). This script
//   1. calls the program and fingerprints its code;
//   2. registers it with Floor (the team's key moves to Floor; zero code changes);
//   3. stages the canonical abort binary and pins a snapshot of the live code;
//   4. has the owner propose an upgrade, which cannot execute before the delay;
//      one guardian vetoes it and the owner withdraws it;
//   5. has ONE guardian stop the program, and calls it again;
//   6. has TWO guardians restore the snapshot, calls it again, and checks the
//      code is byte-identical to before;
//   7. re-arms: a new abort buffer and a new snapshot, so a stop is ready again.
// Along the way every forbidden action (a stranger stopping, one guardian
// restoring, an early upgrade, ...) is simulated and must fail with its exact
// Floor error. Simulations change nothing on chain.
//
//   node cloud/deploy/floor-demo.mjs <rpc> <dir> <floorProgram> <program> [team.json]
// <dir> holds program.so and abort.so. team.json (default <dir>/team.json) is
// the program's upgrade authority and pays. The owner and guardian keys are
// kept in <dir>/keys.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { Rpc, key, b58encode, IDS, decodeFloor } from "../lib/solana.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { errorName } from "./errors.mjs";

const [url, dir, floorProgram, program, teamPath = `${dir}/team.json`] = process.argv.slice(2);
const rpc = new Rpc(url);
const team = Keypair.load(teamPath);
mkdirSync(`${dir}/keys`, { recursive: true, mode: 0o700 });
const kept = (name) => {
  const p = `${dir}/keys/${name}.json`;
  if (existsSync(p)) return Keypair.load(p);
  const k = Keypair.generate();
  k.save(p);
  return k;
};
const owner = kept("owner");
const guardians = [kept("guardian0"), kept("guardian1"), kept("guardian2")];
const stranger = Keypair.generate(); // appears only in simulations
const f = await new FloorClient(floorProgram, program).init();
const DAY = 86_400;
const UPGRADE = 1;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (s) => console.log(s);
let failures = 0;

async function fund(to, lamports) {
  const data = new Uint8Array(12);
  const v = new DataView(data.buffer);
  v.setUint32(0, 2, true);
  v.setBigUint64(4, BigInt(lamports), true);
  await send(rpc, team, [{ programId: IDS.system, accounts: [{ pubkey: team.publicKey, signer: true, writable: true }, { pubkey: key(to), writable: true }], data }]);
}

/** The program's code region (programdata after its 45-byte header), hashed. */
async function fingerprint() {
  const pd = await rpc.account(f.programdata);
  const code = pd.bytes.subarray(45);
  const authorityTag = pd.bytes[12];
  return {
    sha256: createHash("sha256").update(code).digest("hex"),
    bytes: code.length,
    authority: authorityTag === 1 ? b58encode(pd.bytes.subarray(13, 45)) : null,
  };
}

/** Calls the program with an empty instruction and summarizes what happened. */
async function call() {
  const sim = await rpc.simulate(team.publicKey, [{ programId: key(program), accounts: [], data: new Uint8Array(0) }]);
  const logs = (sim.logs ?? []).filter((l) => !l.includes("consumed") && !l.startsWith(`Program ${program} invoke`));
  return { err: JSON.stringify(sim.err), logs };
}

/**
 * Simulates a forbidden action and requires Floor's exact error. A public
 * endpoint's nodes can lag a slot behind the transaction just confirmed, so a
 * different answer is asked again (a real bug answers the same every time).
 */
async function refused(what, ixs, expected) {
  let got;
  for (let i = 0; i < 4; i++) {
    got = errorName((await rpc.simulate(team.publicKey, ixs)).err);
    if (got === expected) break;
    await sleep(1_500);
  }
  const ok = got === expected;
  failures += ok ? 0 : 1;
  say(`   ${ok ? "refused" : "WRONG  "}  ${what}: ${got}${ok ? "" : ` (expected ${expected})`}`);
}

/** Writes a buffer with the Solana CLI; hands its authority to Floor unless `keep`. */
function buffer(file, keep = false) {
  const cli = (...args) => execFileSync("solana", [...args, "--url", url, "--keypair", teamPath], { encoding: "utf8" });
  const out = JSON.parse(cli("program", "write-buffer", file, "--output", "json"));
  const b = out.buffer ?? out.Buffer;
  if (!keep) cli("program", "set-buffer-authority", b, "--new-buffer-authority", b58encode(f.authority));
  return b;
}
const closeBuffer = (b) => execFileSync("solana", ["program", "close", b, "--url", url, "--keypair", teamPath], { encoding: "utf8" });

async function nextSlot() {
  const s0 = await rpc.call("getSlot", [{ commitment: "confirmed" }]);
  while ((await rpc.call("getSlot", [{ commitment: "confirmed" }])) < s0 + 2) await sleep(200);
}

const config = async () => decodeFloor((await rpc.account(f.config)).bytes);

say(`program ${program}`);
if (await rpc.account(f.config)) {
  say(`it is already registered with Floor (config ${b58encode(f.config)}): run this on a fresh program`);
  process.exit(1);
}
await nextSlot(); // a program deployed moments ago runs only from the next slot
const before = await fingerprint();
const callBefore = await call();
say(`  code: ${before.bytes.toLocaleString()} bytes, sha256 ${before.sha256.slice(0, 16)}…, upgrade authority ${before.authority}`);
say(`  an empty call today: ${callBefore.err === "null" ? "succeeds" : `rejected by its own code (${callBefore.err})`}`);

for (const k of [owner, ...guardians]) {
  const have = (await rpc.account(k.publicKey))?.lamports ?? 0;
  if (have < 20_000_000) await fund(k.publicKey, 20_000_000 - have);
}

say("\n1. register: one transaction, signed by the current upgrade key");
await send(rpc, team, [f.register(team.publicKey, team.publicKey, owner.publicKey, guardians.map((g) => g.publicKey), 2, 7 * DAY, 3 * DAY)]);
const afterRegister = await fingerprint();
say(`   upgrade authority is now Floor's PDA ${afterRegister.authority}; code unchanged: ${afterRegister.sha256 === before.sha256}`);
await refused("the old key registering it again (Floor holds the key now)", [f.register(team.publicKey, team.publicKey, stranger.publicKey, [0, 1, 2].map(() => Keypair.generate().publicKey), 2, 7 * DAY, 3 * DAY)], "NotCurrentAuthority");

say("\n2. stage the stop button and pin a snapshot (anyone can do both)");
const loose = buffer(`${dir}/abort.so`, true);
await refused("staging an abort buffer someone can still write to", [f.stageAbort(loose)], "BufferNotFrozen");
closeBuffer(loose);
const abortBuffer = buffer(`${dir}/abort.so`);
await send(rpc, team, [f.stageAbort(abortBuffer)]);
const snapshot = buffer(`${dir}/program.so`);
await refused("pinning the abort binary as the snapshot", [f.pinSnapshot(abortBuffer)], "SnapshotMismatch");
await send(rpc, team, [f.pinSnapshot(snapshot)]);
say(`   abort buffer ${abortBuffer} and snapshot ${snapshot}: frozen, owned by Floor, verified on-chain`);
await refused("staging a second abort", [f.stageAbort(snapshot)], "AbortAlreadyStaged");
await refused("a stranger stopping the program", [f.abort(stranger.publicKey, abortBuffer, snapshot)], "NotLiveGuardian");
await refused("restoring a program that is running", [f.restoreSnapshot(snapshot, team.publicKey, [guardians[0].publicKey, guardians[1].publicKey])], "NotAborted");

say("\n3. an upgrade waits for the delay (72h), and any one guardian can veto it");
await refused("a stranger proposing an upgrade", [f.propose(stranger.publicKey, UPGRADE, snapshot)], "NotOwner");
await send(rpc, owner, [f.propose(owner.publicKey, UPGRADE, snapshot)]);
const proposed = await config();
say(`   the owner proposed an upgrade; executable from ${new Date(proposed.pendingEta * 1000).toISOString()}`);
await refused("executing it now", [f.executeUpgrade(snapshot, team.publicKey)], "NotExecutable");
await refused("proposing a second one", [f.propose(owner.publicKey, UPGRADE, snapshot)], "ProposalPending");
await refused("a stranger vetoing it", [f.veto(stranger.publicKey)], "NotLiveGuardian");
await send(rpc, guardians[2], [f.veto(guardians[2].publicKey)]);
say("   guardian 2 vetoed it");
await refused("executing the vetoed upgrade", [f.executeUpgrade(snapshot, team.publicKey)], "Vetoed");
await send(rpc, owner, [f.cancel(owner.publicKey)]);
say("   the owner withdrew it");
await refused("cancelling when nothing is pending", [f.cancel(owner.publicKey)], "NoProposal");

say("\n4. ONE guardian stops the program");
const t0 = Date.now();
const stopSig = await send(rpc, guardians[0], [f.abort(guardians[0].publicKey, abortBuffer, snapshot)]);
await nextSlot();
const callStopped = await call();
say(`   stop: ${stopSig} (${Date.now() - t0} ms to confirm)`);
say(`   the same call now: fails with ${callStopped.err}, Floor's code 0x464C4F52 ("FLOR")`);
for (const l of callStopped.logs.filter((l) => l.includes("Bulkhead Floor"))) say(`   log: ${l}`);
await refused("stopping it again", [f.abort(guardians[1].publicKey, abortBuffer, snapshot)], "NotLive");
await refused("the owner proposing an upgrade while stopped", [f.propose(owner.publicKey, UPGRADE, snapshot)], "NotLive");
await refused("one guardian restoring alone", [f.restoreSnapshot(snapshot, team.publicKey, [guardians[0].publicKey])], "NoQuorum");
await refused("a guardian and a stranger restoring", [f.restoreSnapshot(snapshot, team.publicKey, [guardians[0].publicKey, stranger.publicKey])], "NotLiveGuardian");

say("\n5. TWO guardians restore the snapshot");
const restoreSig = await send(rpc, guardians[0], [f.restoreSnapshot(snapshot, team.publicKey, [guardians[0].publicKey, guardians[1].publicKey])], [guardians[1]]);
await nextSlot();
const after = await fingerprint();
const callAfter = await call();
say(`   restore: ${restoreSig}`);
say(`   the same call now: ${callAfter.err === "null" ? "succeeds" : `rejected by its own code again (${callAfter.err})`}; identical to before: ${callAfter.err === callBefore.err}`);
say(`   code sha256 ${after.sha256.slice(0, 16)}…: byte-identical to before: ${after.sha256 === before.sha256}`);

say("\n6. re-arm: a new stop button and a new snapshot");
const snapshot2 = buffer(`${dir}/program.so`);
await refused("staging the program's own code as the abort", [f.stageAbort(snapshot2)], "NotCanonicalAbort");
const abort2 = buffer(`${dir}/abort.so`);
await send(rpc, team, [f.stageAbort(abort2)]);
await send(rpc, team, [f.pinSnapshot(snapshot2)]);
await send(rpc, guardians[2], [f.heartbeat(guardians[2].publicKey)]);
const c = await config();
const armed = c.status === "live" && c.abortStaged && c.snapshotPinned && c.pendingKind === 0;
say(`   status ${c.status}, abort staged ${c.abortStaged}, snapshot pinned ${c.snapshotPinned}, nothing pending ${c.pendingKind === 0}; guardians ${c.guardians.length} (quorum ${c.threshold}), upgrade delay ${c.upgradeDelayS / 3600}h`);

const ok =
  afterRegister.sha256 === before.sha256 &&
  callStopped.err.includes("1179406162") && // Custom(0x464C4F52) "FLOR"
  after.sha256 === before.sha256 &&
  callAfter.err === callBefore.err &&
  armed &&
  failures === 0;
say(ok ? "\nFLOOR DEMO PASSED" : `\nFLOOR DEMO FAILED${failures ? ` (${failures} forbidden actions were not refused as expected)` : ""}`);
process.exit(ok ? 0 : 1);
