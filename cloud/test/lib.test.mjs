// Tests for the zero-dependency client (node --test cloud/test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { b58decode, b58encode, key, onCurve, findPda, compileMessage } from "../lib/solana.mjs";

const here = new URL(".", import.meta.url);

test("base58 round-trips well-known ids", () => {
  for (const s of ["11111111111111111111111111111111", "BPFLoaderUpgradeab1e11111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SysvarC1ock11111111111111111111111111111111"]) {
    assert.equal(b58encode(key(s)), s);
  }
  assert.deepEqual(b58decode("1"), Uint8Array.of(0));
});

test("on-curve check agrees with curve25519-dalek on 256 vectors", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../tools/testdata/curve25519_vectors.json", here)));
  let on = 0;
  for (const [hex, want] of vectors) {
    const k = Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
    assert.equal(onCurve(k), want, hex);
    on += want;
  }
  assert.ok(on > 50 && vectors.length - on > 50);
});

test("PDA derivation matches the loader's programdata address", async () => {
  // Known: programdata of the SPL Token program under loader-v3 (mainnet, 2026).
  // The mainnet Token program account stores this programdata address, which
  // the loader derived; ours must match it exactly.
  const [pda] = await findPda([key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")], "BPFLoaderUpgradeab1e11111111111111111111111");
  assert.equal(b58encode(pda), "3gvYRKWyXRR9xKWe1ZjPhLY5ZJRN7KDB4rFZFGoJfFk2");
  assert.equal(onCurve(pda), false);
});

test("legacy messages order signers first, the fee payer at index 0", () => {
  const payer = key("11111111111111111111111111111112");
  const signer = key("11111111111111111111111111111113");
  const other = key("11111111111111111111111111111114");
  const program = key("11111111111111111111111111111115");
  const { message, signers } = compileMessage(payer, [{ programId: program, accounts: [{ pubkey: other, writable: true }, { pubkey: signer, signer: true }], data: Uint8Array.of(7) }], key("11111111111111111111111111111116"));
  assert.deepEqual(message.slice(0, 3), Uint8Array.of(2, 1, 1));
  assert.equal(signers.length, 2);
  assert.deepEqual(signers[0], payer);
});

import { Keypair } from "../lib/signer.mjs";
import { verify, createPublicKey } from "node:crypto";

test("signer: RFC 8032 test vector 1 (empty message)", () => {
  // RFC 8032 §7.1, TEST 1.
  const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
  const kp = new Keypair(seed);
  assert.equal(Buffer.from(kp.publicKey).toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sig = Buffer.from(kp.sign(new Uint8Array(0))).toString("hex");
  assert.equal(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
});
