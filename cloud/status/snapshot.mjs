#!/usr/bin/env node
// Terminal twin of status/index.html: the same modules, the same numbers.
//   node cloud/status/snapshot.mjs <rpc> <vaultProgram> <protocolProgram> <mint,...> [funded keypair]
// With a funded keypair it also simulates the program's own `attest` and
// asserts that the page's local computation (lib/limits.mjs) agrees exactly.
import { Rpc, decodeProtocol, decodeVault } from "../lib/solana.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { attestLocal } from "../lib/limits.mjs";
import { readOpenChanges, openExit, duration } from "../lib/changes.mjs";
import { Keypair } from "../lib/signer.mjs";

const [url, vaultProgram, protocolProgram, mints, payerPath] = process.argv.slice(2);
const rpc = new Rpc(url);
const vc = await new VaultClient(vaultProgram, protocolProgram).init();
const p = decodeProtocol((await rpc.account(vc.protocol)).bytes);
const slot = await rpc.call("getSlot", [{ commitment: "confirmed" }]);
const now = await rpc.call("getBlockTime", [slot]);
const live = p.guardians.filter((_, i) => now - p.lastHeartbeat[i] <= p.heartbeatIntervalS).length;
const fmt = (raw, d) => (Number(raw) / 10 ** d).toLocaleString("en-US", { maximumFractionDigits: 0 });
console.log(`protocol  sealed ${p.sealed}, frozen ${p.frozenUntil > now ? `for ${((p.frozenUntil - now) / 3600).toFixed(1)}h` : "no"}, live guardians ${live}/${p.guardians.length} (quorum ${p.threshold}), loosening waits ${p.loosenDelayS / 3600}h`);
// Every loosening has a countdown (docs/02 §4).
try {
  const open = await readOpenChanges(rpc, vc, p, now);
  if (!open.length) console.log("          pending loosenings: none");
  for (const c of open) {
    const when = c.state === "stale" ? "stale (can never execute)" : c.state === "waiting" ? `executable in ${duration(c.secondsLeft)}` : `executable NOW, for ${duration(c.secondsLeft)} more`;
    console.log(`          pending loosening #${c.id} ${c.kindName}: ${when}; ${live} live guardian(s) can veto`);
  }
} catch (e) {
  console.log(`          pending loosenings: unknown (${e.message})`);
}
let mismatches = 0;
for (const mint of mints.split(",")) {
  const { vault, vaultTokens } = await vc.vault(mint);
  const v = decodeVault((await rpc.account(vault)).bytes);
  const balance = new DataView((await rpc.account(vaultTokens)).bytes.buffer).getBigUint64(64, true);
  const a = attestLocal(v, p, balance, now);
  const d = v.decimals;
  console.log(`vault     ${mint.slice(0, 8)}… balance ${fmt(a.balance, d)}`);
  console.log(`          worst case right now: ${fmt(a.availableNow, d)} instantly, at most ${fmt(a.worst1h, d)} in 1h, ${fmt(a.worst24h, d)} in 24h`);
  const exit = openExit(v, now);
  if (exit) console.log(`          lifeboat exit of ${fmt(exit.amount, d)}: ${exit.state === "waiting" ? `executable in ${duration(exit.secondsLeft)}` : `executable NOW, for ${duration(exit.secondsLeft)} more`}; any live guardian can veto`);
  console.log(`          pending tickets ${a.pendingTickets} (${fmt(a.queued, d)}); paid out backed ${fmt(v.backedOut, d)} / unbacked ${fmt(v.unbackedOut, d)}; cancelled ${fmt(v.cancelled, d)}`);
  if (payerPath) {
    const onchain = await vc.attest(rpc, Keypair.load(payerPath).publicKey, mint);
    const at = attestLocal(v, p, balance, onchain.clockS); // the page's figures at the simulation's own clock
    for (const k of ["worst1h", "worst24h", "balance", "queued"]) {
      if (onchain[k] !== at[k]) {
        mismatches++;
        console.log(`MISMATCH ${k}: page ${at[k]} vs program ${onchain[k]}`);
      }
    }
    console.log(`          cross-check with the program's attest: ${mismatches ? "MISMATCH" : "identical"}`);
  }
}
process.exit(mismatches ? 1 : 0);
