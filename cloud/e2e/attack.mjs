#!/usr/bin/env node
// The attacker of scenario S1: holds Harbor's admin key and orders payouts to
// itself through Harbor, one per interval, like the Drift withdrawals.
//
//   node cloud/e2e/attack.mjs <world.json> <keys dir> <rpc> <count> <amount> <interval_ms>

import { readFileSync } from "node:fs";
import { Rpc, key, findPda, concat, u64le, IDS } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";

const [worldPath, keys, url, count, amount, interval] = process.argv.slice(2);
const w = JSON.parse(readFileSync(worldPath, "utf8"));
const rpc = new Rpc(url);
const admin = Keypair.load(`${keys}/admin.json`);


const [asset] = await findPda(["asset", key(w.protocol), key(w.mint)], w.vaultProgram);
const [backing] = await findPda(["backing", key(w.protocol), key(w.attacker)], w.vaultProgram);

for (let i = 0; i < Number(count); i++) {
  // The payer (the admin here) names its own ticket with a fresh nonce.
  const nonce = new DataView(crypto.getRandomValues(new Uint8Array(8)).buffer).getBigUint64(0, true);
  const [ticket] = await findPda(["ticket", key(w.protocol), key(admin.publicKey), u64le(nonce)], w.vaultProgram);
  const acc = (pubkey, writable = false, signer = false) => ({ pubkey: key(pubkey), writable, signer });
  const ix = {
    programId: key(w.harbor),
    data: concat(Uint8Array.of(3), u64le(amount), u64le(nonce)), // Harbor ADMIN_PAYOUT: amount, ticket nonce
    accounts: [
      acc(w.vaultProgram), acc(w.caller), acc(admin.publicKey, false, true),
      acc(w.protocol, true), acc(w.vault, true), acc(w.vaultTokens, true), acc(w.mint),
      acc(w.attackerTokens, true), acc(backing, true), acc(w.tokenProgram),
      acc(admin.publicKey, true, true), acc(ticket, true), acc(IDS.system),
      acc(asset), acc(IDS.system), // asset PDA (unlisted) and no price
    ],
  };
  const started = Date.now();
  try {
    const sig = await send(rpc, admin, [ix]);
    const tx = await rpc.call("getTransaction", [sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }]);
    const rd = Uint8Array.from(atob(tx.meta.returnData.data[0]), (c) => c.charCodeAt(0));
    const v = new DataView(rd.buffer);
    console.log(JSON.stringify({ payout: i, amount: Number(amount), instant: Number(v.getBigUint64(8, true)), queued: Number(v.getBigUint64(16, true)), ticket: Number(v.getBigUint64(24, true)), ms: Date.now() - started, signature: sig }));
  } catch (e) {
    console.log(JSON.stringify({ payout: i, amount: Number(amount), refused: e.message.slice(0, 160) }));
  }
  await new Promise((r) => setTimeout(r, Number(interval)));
}

