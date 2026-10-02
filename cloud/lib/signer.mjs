// Ed25519 signing with Node's built-in crypto (no dependencies).
// Keys are standard Solana keypair files: a JSON array of 64 bytes
// (32-byte seed, then the 32-byte public key).

import { createPrivateKey, createPublicKey, sign as edSign, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { b58encode, compileMessage, serializeTransaction, key, concat, u64le } from "./solana.mjs";

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

export class Keypair {
  constructor(seed) {
    this.seed = Buffer.from(seed);
    this.privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, this.seed]), format: "der", type: "pkcs8" });
    const spki = createPublicKey(this.privateKey).export({ format: "der", type: "spki" });
    this.publicKey = Uint8Array.from(spki.subarray(spki.length - 32));
  }
  static generate() {
    return new Keypair(randomBytes(32));
  }
  static load(path) {
    const bytes = JSON.parse(readFileSync(path, "utf8"));
    const kp = new Keypair(Uint8Array.from(bytes.slice(0, 32)));
    if (bytes.length === 64 && b58encode(Uint8Array.from(bytes.slice(32))) !== kp.address) {
      throw new Error(`${path}: public key does not match the seed`);
    }
    return kp;
  }
  save(path) {
    writeFileSync(path, JSON.stringify([...this.seed, ...this.publicKey]), { mode: 0o600 }); // owner-only, like solana-keygen
  }
  get address() {
    return b58encode(this.publicKey);
  }
  sign(message) {
    return Uint8Array.from(edSign(null, Buffer.from(message), this.privateKey));
  }
}

export const COMPUTE_BUDGET = key("ComputeBudget111111111111111111111111111111");

/**
 * `SetComputeUnitLimit(units)` and, when `microLamports` > 0,
 * `SetComputeUnitPrice(microLamports)`: the priority fee is units × price.
 */
export function computeBudget(units, microLamports = 0) {
  const limit = new Uint8Array(5);
  limit[0] = 2;
  new DataView(limit.buffer).setUint32(1, units, true);
  const ixs = [{ programId: COMPUTE_BUDGET, accounts: [], data: limit }];
  if (microLamports > 0) ixs.push({ programId: COMPUTE_BUDGET, accounts: [], data: concat(Uint8Array.of(3), u64le(microLamports)) });
  return ixs;
}

/**
 * A priority price from `getRecentPrioritizationFees` results: the
 * `percentile` of the non-zero fees paid recently on the accounts involved,
 * never above `cap` (micro-lamports per compute unit). 0 when nobody paid.
 */
export function priorityPrice(fees, { percentile = 0.9, cap = 1_000_000 } = {}) {
  const paid = (fees ?? []).map((f) => Number(f.prioritizationFee)).filter((x) => x > 0).sort((a, b) => a - b);
  if (!paid.length) return 0;
  const i = Math.min(paid.length - 1, Math.ceil(percentile * paid.length) - 1);
  return Math.min(cap, paid[Math.max(0, i)]);
}

/**
 * Builds, signs and sends a transaction; returns its signature once confirmed.
 * `computeUnits` adds a compute-budget limit (and `microLamports` a priority
 * price); `rpcs` are extra endpoints the same signed transaction is also sent
 * to, so one slow or censoring endpoint doesn't delay it.
 */
export async function send(rpc, payer, instructions, extraSigners = [], { skipPreflight = false, computeUnits = 0, microLamports = 0, rpcs = [] } = {}) {
  const ixs = computeUnits > 0 ? [...computeBudget(computeUnits, microLamports), ...instructions] : instructions;
  const { message, signers } = compileMessage(payer.publicKey, ixs, await rpc.blockhash());
  const all = [payer, ...extraSigners];
  const sigs = signers.map((k) => {
    const kp = all.find((s) => b58encode(s.publicKey) === b58encode(k));
    if (!kp) throw new Error(`missing signer ${b58encode(k)}`);
    return kp.sign(message);
  });
  const tx = Buffer.from(serializeTransaction(message, sigs)).toString("base64");
  const opts = { encoding: "base64", skipPreflight, preflightCommitment: "confirmed" };
  // Backups go out first and are never awaited: they still carry the
  // transaction when the primary's send fails, and a hanging one cannot delay
  // confirmation. The primary decides.
  void Promise.allSettled(rpcs.map(async (r) => r.call("sendTransaction", [tx, { ...opts, skipPreflight: true }])));
  const signature = await rpc.call("sendTransaction", [tx, opts]);
  for (let i = 0; i < 120; i++) {
    const st = (await rpc.call("getSignatureStatuses", [[signature]])).value[0];
    if (st?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(st.err)}`);
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) return signature;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`transaction ${signature} not confirmed`);
}

export { key };
