#!/usr/bin/env node
// Finishes the devnet maintenance proposed on 6 Oct 2026 (docs/08): the market's
// guardian renewal (change 0) and recovery key (change 1), and the Floor S10
// target's guardian renewal. Each waited the 72h loosen delay; anyone may
// execute it after. Safe to run any time: a change already executed is
// skipped, and one not yet due is refused by the program and reported.
//
//   node cloud/deploy/finish-renewals.mjs <rpc> <market-dir> <payer.json> [floor-program protected-program]
import { readFileSync } from "node:fs";
import { Rpc, key, findPda, u64le, IDS, decodeFloor } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";
import { vaultIx } from "./market.mjs";

const [url, dir, payerPath, floorProgram, protectedProgram] = process.argv.slice(2);
if (!url || !dir || !payerPath) {
  console.error("usage: finish-renewals.mjs <rpc> <market-dir> <payer.json> [floor-program protected-program]");
  process.exit(2);
}
const rpc = new Rpc(url);
const payer = Keypair.load(payerPath);
const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
const vaultProgram = key(world.vaultProgram);
const w = (k) => ({ pubkey: key(k), writable: true });
const r = (k) => ({ pubkey: key(k) });
const s = (k, writable = false) => ({ pubkey: key(k), signer: true, writable });
let failed = 0;

for (const id of [0n, 1n]) {
  const [change] = await findPda(["change", key(world.protocol), u64le(id)], vaultProgram);
  const acc = await rpc.account(change);
  if (!acc) {
    console.log(`market change ${id}: no such change`);
    continue;
  }
  const d = acc.bytes;
  const [vetoed, executed] = [d[49] !== 0, d[50] !== 0];
  const executableS = Number(new DataView(d.buffer, d.byteOffset + 124, 8).getBigInt64(0, true));
  if (executed) {
    console.log(`market change ${id}: already executed`);
    continue;
  }
  if (vetoed) {
    console.log(`market change ${id}: vetoed; propose it again`);
    failed++;
    continue;
  }
  try {
    const sig = await send(rpc, payer, [vaultIx({ vaultProgram }, 20, new Uint8Array(0), [
      w(world.protocol), w(change), w(world.protocol), s(payer.publicKey, true), r(world.mint), r(IDS.token), r(IDS.system),
    ])]);
    console.log(`market change ${id}: executed ${sig}`);
  } catch (e) {
    console.log(`market change ${id}: not executed (executable from ${new Date(executableS * 1000).toISOString()}): ${e.message.slice(0, 120)}`);
    failed++;
  }
}

if (floorProgram && protectedProgram) {
  const fc = await new FloorClient(floorProgram, protectedProgram).init();
  const f = decodeFloor((await rpc.account(fc.config)).bytes);
  if (!f.pendingKind) {
    console.log("floor: nothing pending");
  } else {
    try {
      const sig = await send(rpc, payer, [fc.executeConfig()]);
      console.log(`floor: pending kind ${f.pendingKind} executed ${sig}`);
    } catch (e) {
      console.log(`floor: not executed (executable from ${new Date(f.pendingEta * 1000).toISOString()}): ${e.message.slice(0, 120)}`);
      failed++;
    }
  }
}
process.exit(failed ? 1 : 0);
