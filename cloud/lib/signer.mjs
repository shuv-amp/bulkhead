// Ed25519 signing with Node's built-in crypto (no dependencies).
// Keys are standard Solana keypair files: a JSON array of 64 bytes
// (32-byte seed, then the 32-byte public key).

import { createPrivateKey, createPublicKey, sign as edSign, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { b58encode, compileMessage, serializeTransaction, key } from "./solana.mjs";

/** Compute Budget program. Limit is instruction 2 (u32); price is 3 (u64 micro-lamports). */
export const COMPUTE_BUDGET = key("ComputeBudget11111111111111111111111111111");

export function budgetInstructions({ computeUnits = 0, priorityMicroLamports = 0 } = {}) {
  const out = [];
  if (computeUnits) {
    const data = new Uint8Array(5);
    data[0] = 2;
    new DataView(data.buffer).setUint32(1, computeUnits, true);
    out.push({ programId: COMPUTE_BUDGET, accounts: [], data });
  }
  if (priorityMicroLamports) {
    const data = new Uint8Array(9);
    data[0] = 3;
    new DataView(data.buffer).setBigUint64(1, BigInt(priorityMicroLamports), true);
    out.push({ programId: COMPUTE_BUDGET, accounts: [], data });
  }
  return out;
}

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

/**
 * Builds, signs and sends a transaction; returns its signature once confirmed.
 *
 * `computeUnits` and `priorityMicroLamports` prepend Compute Budget instructions.
 * The signed transaction is submitted to `rpc` and to every entry of `rpcs`.
 * Confirmation is polled on the first endpoint that accepted it.
 */
export async function send(rpc, payer, instructions, extraSigners = [], { skipPreflight = false, computeUnits = 0, priorityMicroLamports = 0, rpcs = [] } = {}) {
  const ixs = [...budgetInstructions({ computeUnits, priorityMicroLamports }), ...instructions];
  const { message, signers } = compileMessage(payer.publicKey, ixs, await rpc.blockhash());
  const all = [payer, ...extraSigners];
  const sigs = signers.map((k) => {
    const kp = all.find((s) => b58encode(s.publicKey) === b58encode(k));
    if (!kp) throw new Error(`missing signer ${b58encode(k)}`);
    return kp.sign(message);
  });
  const tx = Buffer.from(serializeTransaction(message, sigs)).toString("base64");
  const targets = [rpc, ...rpcs.filter((r) => r && r !== rpc)];
  const opts = { encoding: "base64", skipPreflight, preflightCommitment: "confirmed" };
  let signature;
  let confirmOn;
  const errors = [];
  for (const target of targets) {
    try {
      signature = await target.call("sendTransaction", [tx, opts]);
      confirmOn ??= target;
    } catch (e) {
      errors.push(e);
    }
  }
  if (!signature) throw errors[0] ?? new Error("no rpc accepted the transaction");
  for (let i = 0; i < 120; i++) {
    const st = (await confirmOn.call("getSignatureStatuses", [[signature]])).value[0];
    if (st?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(st.err)}`);
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) return signature;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`transaction ${signature} not confirmed`);
}

export { key };
