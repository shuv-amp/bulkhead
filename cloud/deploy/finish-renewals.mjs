#!/usr/bin/env node
// Finishes the devnet maintenance proposed on 6 Oct 2026 (docs/08): the market's
// guardian renewal (change 0) and recovery key (change 1), and the Floor S10
// target's guardian renewal. Each waited the 72h loosen delay; anyone may
// execute it after. Safe to run any time. Each one is judged first, by the
// chain's clock: already executed (skipped), vetoed, expired or stale (say
// so: it has to be proposed again), not due yet (nothing sent), or due (sent;
// a refusal is reported by its error name).
//
//   node cloud/deploy/finish-renewals.mjs <rpc> <market-dir> <payer.json> [floor-program protected-program]
//
// Exits 0 only when every one is executed (by this run or before it), 1 when
// any is not, and 3 when the market's are executed but the Floor has nothing
// pending: from the chain alone that cannot tell a renewal already executed
// from one never proposed or withdrawn, so check its guardian set by hand.
import { readFileSync } from "node:fs";
import { Rpc, key, findPda, u64le, IDS, decodeFloor, decodeChange } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";
import { vaultIx } from "./market.mjs";
import { errorName } from "./errors.mjs";

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
const iso = (t) => new Date(t * 1000).toISOString();
// The chain's clock decides, not this machine's.
const slot = await rpc.call("getSlot", [{ commitment: "confirmed" }]);
const now = await rpc.call("getBlockTime", [slot]);
if (typeof now !== "number") {
  console.error(`the RPC has no block time for slot ${slot}; try again, or use an RPC that keeps block times`);
  process.exit(2);
}
let failed = 0;
let floorUnconfirmed = false;

/** The program's error for a refused transaction, by name. */
function refusal(e) {
  const err = e.rpcError?.data?.err ?? null;
  return err ? errorName(err) : e.message.slice(0, 160);
}

// What each renewal is (change kinds: programs/vault/src/state.rs). Anything
// else under that id is not a renewal and is never executed here, nor
// reported as one.
const EXPECTED = new Map([[0n, [2, "SetGuardians"]], [1n, [6, "SetRecovery"]]]);
for (const id of [0n, 1n]) {
  const [address] = await findPda(["change", key(world.protocol), u64le(id)], vaultProgram);
  const acc = await rpc.account(address);
  if (!acc) {
    console.log(`market change ${id}: no such change`);
    failed++;
    continue;
  }
  const c = decodeChange(acc.bytes);
  const [kind, kindName] = EXPECTED.get(id);
  if (c.kind !== kind) {
    console.log(`market change ${id}: kind ${c.kind} (target ${c.target}), not the ${kindName} renewal; not executed`);
    failed++;
    continue;
  }
  if (c.executed) {
    console.log(`market change ${id}: already executed`);
    continue;
  }
  failed++;
  if (c.vetoed) console.log(`market change ${id}: vetoed; propose it again`);
  else if (now >= c.expiresS) console.log(`market change ${id}: expired at ${iso(c.expiresS)}; propose it again`);
  else if (now < c.executableS) console.log(`market change ${id}: not due until ${iso(c.executableS)}`);
  else {
    try {
      const sig = await send(rpc, payer, [vaultIx({ vaultProgram }, 20, new Uint8Array(0), [
        w(world.protocol), w(address), w(world.protocol), s(payer.publicKey, true), r(world.mint), r(IDS.token), r(IDS.system),
      ])]);
      console.log(`market change ${id}: executed ${sig}`);
      failed--;
    } catch (e) {
      // ChangeStale: its target moved since; it can never execute.
      console.log(`market change ${id}: refused (${refusal(e)})${refusal(e) === "ChangeStale" ? "; propose it again" : ""}`);
    }
  }
}

if (floorProgram && protectedProgram) {
  const fc = await new FloorClient(floorProgram, protectedProgram).init();
  const acc = await rpc.account(fc.config);
  const f = acc ? decodeFloor(acc.bytes) : null;
  if (!f) {
    console.log("floor: no Floor config for that program");
    failed++;
  } else if (!f.pendingKind) {
    console.log("floor: nothing pending; executed already, or never proposed? Not confirmed (exit 3)");
    floorUnconfirmed = true;
  } else {
    failed++;
    // This script executes configuration changes; an upgrade or restore
    // (kinds 1 and 2) needs its buffer and is not one of the renewals.
    // The renewal is a new guardian set (kind 4). Anything else pending (an
    // upgrade, a new owner or recovery key) is someone else's, not executed here.
    if (f.pendingKind !== 4) console.log(`floor: the pending proposal is kind ${f.pendingKind}, not the guardian renewal (SetGuardians, 4); not executed here`);
    else if (f.pendingVetoed) console.log(`floor: proposal ${f.pendingId} vetoed; propose it again`);
    else if (now >= f.pendingExpires) console.log(`floor: proposal ${f.pendingId} expired at ${iso(f.pendingExpires)}; propose it again`);
    else if (now < f.pendingEta) console.log(`floor: proposal ${f.pendingId} not due until ${iso(f.pendingEta)}`);
    else {
      try {
        const sig = await send(rpc, payer, [fc.executeConfig()]);
        console.log(`floor: proposal ${f.pendingId} (kind ${f.pendingKind}) executed ${sig}`);
        failed--;
      } catch (e) {
        console.log(`floor: proposal ${f.pendingId} refused (${refusal(e)})`);
      }
    }
  }
}
process.exit(failed ? 1 : floorUnconfirmed ? 3 : 0);
