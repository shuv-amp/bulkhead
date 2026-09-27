#!/usr/bin/env node
// Floor on a real program (driven by scripts/floor-demo.sh): the program's
// mainnet bytes run on a local validator under a local team key. This script
//   1. calls the program and fingerprints its code;
//   2. registers it with Floor (the team's key moves to Floor; zero code changes);
//   3. stages the canonical abort binary and pins a snapshot of the live code;
//   4. has ONE guardian stop the program, and calls it again;
//   5. has TWO guardians restore the snapshot, calls it again, and checks the
//      code is byte-identical to before.
//
//   node cloud/deploy/floor-demo.mjs <rpc> <dir> <floorProgram> <program>
// <dir> holds team.json (the program's upgrade authority), program.so, abort.so.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { Rpc, key, b58encode, concat, IDS } from "../lib/solana.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";
import { Keypair, send } from "../lib/signer.mjs";

const [url, dir, floorProgram, program] = process.argv.slice(2);
const rpc = new Rpc(url);
const team = Keypair.load(`${dir}/team.json`);
const owner = Keypair.generate();
const guardians = [Keypair.generate(), Keypair.generate(), Keypair.generate()];
const f = await new FloorClient(floorProgram, program).init();
const DAY = 86_400;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (s) => console.log(s);

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

/** Writes a buffer with the Solana CLI and hands its authority to Floor. */
function frozenBuffer(file) {
  const cli = (...args) => execFileSync("solana", [...args, "--url", url, "--keypair", `${dir}/team.json`], { encoding: "utf8" });
  const out = JSON.parse(cli("program", "write-buffer", file, "--output", "json"));
  const buffer = out.buffer ?? out.Buffer;
  cli("program", "set-buffer-authority", buffer, "--new-buffer-authority", b58encode(f.authority));
  return buffer;
}

async function nextSlot() {
  const s0 = await rpc.call("getSlot", [{ commitment: "confirmed" }]);
  while ((await rpc.call("getSlot", [{ commitment: "confirmed" }])) < s0 + 2) await sleep(200);
}

say(`program ${program}`);
const before = await fingerprint();
const callBefore = await call();
say(`  code: ${before.bytes.toLocaleString()} bytes, sha256 ${before.sha256.slice(0, 16)}…, upgrade authority ${before.authority}`);
say(`  an empty call today: ${callBefore.err === "null" ? "succeeds" : `rejected by its own code (${callBefore.err})`}`);

for (const k of [owner, ...guardians]) await fund(k.publicKey, 20_000_000);

say("\n1. register: one transaction, signed by the current upgrade key");
await send(rpc, team, [f.register(team.publicKey, team.publicKey, owner.publicKey, guardians.map((g) => g.publicKey), 2, 7 * DAY, 3 * DAY)]);
const afterRegister = await fingerprint();
say(`   upgrade authority is now Floor's PDA ${afterRegister.authority}; code unchanged: ${afterRegister.sha256 === before.sha256}`);

say("\n2. stage the stop button and pin a snapshot (anyone can do both)");
const abortBuffer = frozenBuffer(`${dir}/abort.so`);
await send(rpc, team, [f.stageAbort(abortBuffer)]);
const snapshot = frozenBuffer(`${dir}/program.so`);
await send(rpc, team, [f.pinSnapshot(snapshot)]);
say(`   abort buffer ${abortBuffer} and snapshot ${snapshot}: frozen, owned by Floor, verified on-chain`);

say("\n3. ONE guardian stops the program");
const t0 = Date.now();
const stopSig = await send(rpc, guardians[0], [f.abort(guardians[0].publicKey, abortBuffer, snapshot)]);
await nextSlot();
const callStopped = await call();
say(`   stop: ${stopSig} (${Date.now() - t0} ms to confirm)`);
say(`   the same call now: fails with ${callStopped.err}, Floor's code 0x464C4F52 ("FLOR")`);
for (const l of callStopped.logs.filter((l) => l.includes("Bulkhead Floor"))) say(`   log: ${l}`);

say("\n4. TWO guardians restore the snapshot");
const restoreSig = await send(rpc, guardians[0], [f.restoreSnapshot(snapshot, team.publicKey, [guardians[0].publicKey, guardians[1].publicKey])], [guardians[1]]);
await nextSlot();
const after = await fingerprint();
const callAfter = await call();
say(`   restore: ${restoreSig}`);
say(`   the same call now: ${callAfter.err === "null" ? "succeeds" : `rejected by its own code again (${callAfter.err})`}; identical to before: ${callAfter.err === callBefore.err}`);
say(`   code sha256 ${after.sha256.slice(0, 16)}…: byte-identical to before: ${after.sha256 === before.sha256}`);

const ok =
  afterRegister.sha256 === before.sha256 &&
  callStopped.err.includes("1179406162") && // Custom(0x464C4F52) "FLOR"
  after.sha256 === before.sha256 &&
  callAfter.err === callBefore.err;
say(ok ? "\nFLOOR DEMO PASSED" : "\nFLOOR DEMO FAILED");
process.exit(ok ? 0 : 1);
