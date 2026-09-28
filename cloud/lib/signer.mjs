// Ed25519 signing with Node's built-in crypto (no dependencies).
// Keys are standard Solana keypair files: a JSON array of 64 bytes
// (32-byte seed, then the 32-byte public key).

import { createPrivateKey, createPublicKey, sign as edSign, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { b58encode, compileMessage, serializeTransaction, key } from "./solana.mjs";

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

/** Builds, signs and sends a transaction; returns its signature once confirmed. */
export async function send(rpc, payer, instructions, extraSigners = [], { skipPreflight = false } = {}) {
  const { message, signers } = compileMessage(payer.publicKey, instructions, await rpc.blockhash());
  const all = [payer, ...extraSigners];
  const sigs = signers.map((k) => {
    const kp = all.find((s) => b58encode(s.publicKey) === b58encode(k));
    if (!kp) throw new Error(`missing signer ${b58encode(k)}`);
    return kp.sign(message);
  });
  const tx = Buffer.from(serializeTransaction(message, sigs)).toString("base64");
  const signature = await rpc.call("sendTransaction", [tx, { encoding: "base64", skipPreflight, preflightCommitment: "confirmed" }]);
  for (let i = 0; i < 120; i++) {
    const st = (await rpc.call("getSignatureStatuses", [[signature]])).value[0];
    if (st?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(st.err)}`);
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) return signature;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`transaction ${signature} not confirmed`);
}

export { key };
