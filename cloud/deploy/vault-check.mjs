#!/usr/bin/env node
// Checks a live Bulkhead market (set up by cloud/deploy/market.mjs) without
// sending anything:
//   - every account is what setup configured (admin, guardians, delays, limits,
//     lifeboat destination, balance, seal schedule);
//   - the status page's worst case equals the program's own `attest`;
//   - every forbidden action, simulated, fails with its exact error. Before the
//     seal no release of any kind may happen, while guardians can still act.
// Simulations run with signature checks off, so they need no keys and change
// nothing on chain.
//
//   node cloud/deploy/vault-check.mjs <rpc> <market-dir>

import { readFileSync } from "node:fs";
import { Rpc, key, findPda, u64le, IDS, decodeProtocol, decodeVault } from "../lib/solana.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { attestLocal } from "../lib/limits.mjs";
import { Keypair } from "../lib/signer.mjs";
import { errorName } from "./errors.mjs";
import { harborIx, vaultIx, registerArgs, defaultLimits, CAPS } from "./market.mjs";

const [url, dir] = process.argv.slice(2);
if (!dir) {
  console.error("usage: vault-check.mjs <rpc> <market-dir>");
  process.exit(2);
}
const rpc = new Rpc(url);
const wld = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
const kp = (name) => Keypair.load(`${dir}/keys/${name}.json`);
const admin = kp("admin");
const whale = kp("whale");
const guardians = [kp("guardian0"), kp("guardian1"), kp("guardian2")];
const destination = kp("lifeboat-destination");
const stranger = Keypair.generate(); // appears only in simulations
const vc = await new VaultClient(wld.vaultProgram, wld.harbor).init();
const m = { vaultProgram: key(wld.vaultProgram), harbor: key(wld.harbor), caller: key(wld.caller), protocol: key(wld.protocol) };
const TVL = 10_000_000n * 1_000_000n;
const DAY = 86_400;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const w = (pubkey) => ({ pubkey: key(pubkey), writable: true });
const r = (pubkey) => ({ pubkey: key(pubkey) });
const s = (pubkey, writable = false) => ({ pubkey: key(pubkey), signer: true, writable });
const utc = (t) => new Date(t * 1000).toISOString().replace(".000Z", "Z");
let failures = 0;

function check(what, ok, detail = "") {
  failures += ok ? 0 : 1;
  console.log(`   ${ok ? "ok     " : "WRONG  "}  ${what}${detail ? `: ${detail}` : ""}`);
}

/** Simulates `ixs` and requires `expected` ("ok" or an error name); a lagging node is asked again. */
async function expect(what, ixs, expected) {
  let got;
  for (let i = 0; i < 4; i++) {
    got = errorName((await rpc.simulate(admin.publicKey, ixs)).err);
    if (got === expected) break;
    await sleep(1_500);
  }
  failures += got === expected ? 0 : 1;
  const verdict = got !== expected ? "WRONG  " : expected === "ok" ? "allowed" : "refused";
  console.log(`   ${verdict}  ${what}: ${got}${got === expected ? "" : ` (expected ${expected})`}`);
}

/** A release through Harbor: 2 = a user withdrawing to themselves, 3 = the admin paying anyone. */
async function harborRelease(tag, signer, recipientTokens, recipientOwner, amount, p) {
  const [backing] = await findPda(["backing", m.protocol, key(recipientOwner)], m.vaultProgram);
  const [ticket] = await findPda(["ticket", m.protocol, u64le(p.nextTicketId)], m.vaultProgram);
  const [asset] = await findPda(["asset", m.protocol, key(wld.mint)], m.vaultProgram);
  return harborIx(m, tag, u64le(amount), [s(signer)], [
    w(m.protocol), w(wld.vault), w(wld.vaultTokens), r(wld.mint), w(recipientTokens), w(backing), r(wld.tokenProgram),
    s(signer, true), w(ticket), r(IDS.system), r(asset), r(IDS.system), // asset PDA (unlisted) and no price
  ]);
}

const slot = await rpc.call("getSlot", [{ commitment: "confirmed" }]);
const now = await rpc.call("getBlockTime", [slot]);
const p = decodeProtocol((await rpc.account(wld.protocol)).bytes);
const v = decodeVault((await rpc.account(wld.vault)).bytes);
const balance = new DataView((await rpc.account(wld.vaultTokens)).bytes.buffer).getBigUint64(64, true);

console.log(`market ${wld.protocol} on ${url}`);
console.log("\n1. the accounts are what setup configured");
check("protocol program is Harbor, and its caller PDA", p.protocolProgram === wld.harbor && p.caller === wld.caller);
check("admin is keys/admin", p.admin === admin.address, p.admin);
check("guardians are keys/guardian0..2, quorum 2", JSON.stringify(p.guardians) === JSON.stringify(guardians.map((g) => g.address)) && p.threshold === 2);
const live = p.lastHeartbeat.filter((t) => now - t <= p.heartbeatIntervalS).length;
check("every guardian is live (heartbeat within 7 days)", live === 3 && p.heartbeatIntervalS === 7 * DAY, `${live}/3`);
check("loosening waits 72h", p.loosenDelayS === 3 * DAY);
check("lifeboat destination is keys/lifeboat-destination", p.lifeboatDestination === destination.address);
check("one vault: the test USDC mint, 6 decimals, its token account", p.vaultCount === 1 && v.mint === wld.mint && v.decimals === 6 && v.tokenAccount === wld.vaultTokens);
const L = v.limits;
check("limits: 2% per 1h, 5% per 24h, 6h queue delay, no floors",
  L.shortBps === 200 && L.shortWindowS === 3_600 && L.longBps === 500 && L.longWindowS === DAY && L.minQueueDelayS === 6 * 3_600 &&
  L.shortFloor === 0n && L.longFloor === 0n);
// Either none (as set up) or the calibrated caps (market.mjs caps): anything else is wrong.
const noCaps = L.shortCap === 0n && L.longCap === 0n;
const calibrated = L.shortCap === CAPS.short && L.longCap === CAPS.long;
check(noCaps ? "absolute caps: none" : "absolute caps: 2% and 5% of the 10M (docs/07 §4)", noCaps || calibrated,
  noCaps ? "" : `${(Number(L.shortCap) / 1e6).toLocaleString("en-US")} per 1h, ${(Number(L.longCap) / 1e6).toLocaleString("en-US")} per 24h`);
if (p.sealed) {
  console.log(`   (sealed: balance ${(Number(balance) / 1e6).toLocaleString("en-US")} test USDC, pending tickets ${v.pendingTickets})`);
} else {
  check("balance: the whale's 10,000,000 test USDC", balance === TVL, (Number(balance) / 1e6).toLocaleString("en-US"));
  check("seal proposed, not vetoed, executable 72h after its proposal for 7 days",
    p.sealExecutableS > 0 && !p.sealVetoed && p.sealExpiresS - p.sealExecutableS === 7 * DAY,
    `from ${utc(p.sealExecutableS)} until ${utc(p.sealExpiresS)} (${((p.sealExecutableS - now) / 3_600).toFixed(1)}h from now)`);
}

console.log("\n2. the status page's worst case equals the program's own attest");
const onchain = await vc.attest(rpc, admin.publicKey, wld.mint);
const local = attestLocal(v, p, balance, onchain.clockS); // at the simulation's own clock
const same = ["worst1h", "worst24h", "balance", "queued"].every((k) => onchain[k] === local[k]);
check("attest (simulated on chain) == cloud/lib/limits.mjs", same, `1h ${Number(onchain.worst1h) / 1e6}, 24h ${Number(onchain.worst24h) / 1e6}, sealed ${onchain.sealed}`);

console.log("\n3. forbidden actions (simulated; nothing is sent)");
if (!p.sealed) {
  await expect("S1 before the seal: the admin pays the attacker 100,000", [await harborRelease(3, admin.publicKey, wld.attackerTokens, wld.attacker, 100_000n * 1_000_000n, p)], "NotSealed");
  await expect("the whale withdraws its own deposit before the seal", [await harborRelease(2, whale.publicKey, wld.whaleTokens, whale.publicKey, 1_000_000n, p)], "NotSealed");
  await expect("executing the seal before 72h", [vaultIx(m, 5, new Uint8Array(0), [w(m.protocol), r(wld.vault), r(wld.vaultTokens)])], "SealNotExecutable");
}
await expect("a stranger proposing the seal", [vaultIx(m, 4, new Uint8Array(0), [w(m.protocol), s(stranger.publicKey)])], "NotAdmin");
await expect("a stranger vetoing the seal", [vaultIx(m, 6, new Uint8Array(0), [w(m.protocol), s(stranger.publicKey)])], "NotGuardian");
await expect("a stranger freezing the protocol", [vc.freeze(stranger.publicKey, 3_600)], "NotGuardian");
await expect("a guardian freezing for 25h (the maximum is 24h)", [vc.freeze(guardians[0].publicKey, 25 * 3_600)], "FreezeTooLong");
await expect("a stranger registering Harbor again with its own admin", [harborIx(m, 0, registerArgs(stranger.publicKey, [0, 1, 2].map(() => Keypair.generate().publicKey), Keypair.generate().publicKey), [], [
  s(admin.publicKey, true), w(m.protocol), r(m.harbor), r(m.harbor), r(m.caller), r(IDS.system),
])], "AlreadyInitialized");
await expect("a second vault for the same mint", [vaultIx(m, 1, defaultLimits(), [
  s(admin.publicKey, true), s(admin.publicKey), w(m.protocol), w(wld.vault), w(wld.vaultTokens), r(wld.mint), r(IDS.token), r(IDS.system),
])], "AlreadyInitialized");
// Abdication is permanent, so a stolen admin key alone must not be able to give
// up "set admin" and lock the protocol to itself (docs/15, A3).
const abdicate = (...signers) => vaultIx(m, 17, Uint8Array.of(3), [w(m.protocol), ...signers.map((k) => s(k))]);
await expect("the admin alone abdicating \"set admin\"", [abdicate(admin.publicKey)], "NoQuorum");
await expect("the admin and one guardian abdicating \"set admin\"", [abdicate(admin.publicKey, guardians[0].publicKey)], "NoQuorum");

console.log("\n4. guardians can act (simulated; nothing is sent)");
await expect("guardian 0 sends a heartbeat", [vc.heartbeat(guardians[0].publicKey)], "ok");
await expect("guardian 1 freezes the protocol for 1h", [vc.freeze(guardians[1].publicKey, 3_600)], "ok");
if (!p.sealed) await expect("guardian 2 vetoes the seal", [vaultIx(m, 6, new Uint8Array(0), [w(m.protocol), s(guardians[2].publicKey)])], "ok");
await expect("the admin with a live guardian quorum abdicating \"set admin\"", [abdicate(admin.publicKey, guardians[0].publicKey, guardians[1].publicKey)], "ok");

console.log(failures ? `\nVAULT CHECK FAILED (${failures})` : "\nVAULT CHECK PASSED");
process.exit(failures ? 1 : 0);
