// Tests for the zero-dependency client (node --test cloud/test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { b58decode, b58encode, key, onCurve, findPda, compileMessage, decodeVault } from "../lib/solana.mjs";
import { FloorClient, VaultClient, floorBufferRole } from "../lib/bulkhead.mjs";

const here = new URL(".", import.meta.url);

test("base58 round-trips well-known ids", () => {
  for (const s of ["11111111111111111111111111111111", "BPFLoaderUpgradeab1e11111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "SysvarC1ock11111111111111111111111111111111"]) {
    assert.equal(b58encode(key(s)), s);
  }
  assert.deepEqual(b58decode("1"), Uint8Array.of(0));
});

test("on-curve check agrees with curve25519-dalek on 268 vectors", () => {
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

test("a floor veto can name the proposal, and still be sent without one", () => {
  const fc = new FloorClient("11111111111111111111111111111111", "11111111111111111111111111111112");
  fc.config = key("11111111111111111111111111111113");
  const guardian = "11111111111111111111111111111114";
  const named = fc.veto(guardian, 4n);
  assert.equal(named.data[0], 5);
  assert.equal(named.data.length, 9);
  assert.equal(named.data[1], 4);
  assert.ok(named.data.subarray(2).every((b) => b === 0));
  assert.deepEqual(fc.veto(guardian).data, Uint8Array.of(5));
});

test("cancel_ticket and extend_ticket name the ticket id the guardian decided on", () => {
  const vc = new VaultClient("11111111111111111111111111111111", "11111111111111111111111111111112");
  vc.protocol = key("11111111111111111111111111111113");
  const [vault, ticket, guardian, payer] = ["11111111111111111111111111111114", "11111111111111111111111111111115", "11111111111111111111111111111116", "11111111111111111111111111111117"];
  const cancel = vc.cancelTicket(vault, ticket, guardian, payer, 0x0102n);
  assert.deepEqual([...cancel.data], [10, 2, 1, 0, 0, 0, 0, 0, 0], "tag, then ticket id u64 LE");
  assert.equal(cancel.accounts.length, 5);
  assert.throws(() => vc.cancelTicket(vault, ticket, guardian, payer), /ticket id/);
  const extend = vc.extendTicket(ticket, guardian, 3_600, 7n);
  assert.deepEqual([...extend.data], [11, 0x10, 0x0e, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0], "tag, secs i64 LE, ticket id u64 LE");
  assert.deepEqual(extend.accounts.map((a) => [Boolean(a.writable), Boolean(a.signer)]), [[false, false], [true, false], [false, true]]);
});

test("signer: RFC 8032 test vector 1 (empty message)", () => {
  // RFC 8032 §7.1, TEST 1.
  const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
  const kp = new Keypair(seed);
  assert.equal(Buffer.from(kp.publicKey).toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const sig = Buffer.from(kp.sign(new Uint8Array(0))).toString("hex");
  assert.equal(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
});

test("a vault account decodes through its lifeboat exit, in the program's field order", () => {
  // programs/vault/src/state.rs Vault::store.
  const parts = [Buffer.from("BHVAULT1")];
  const n = (bytes, v) => {
    const b = Buffer.alloc(bytes);
    if (bytes === 16) { b.writeBigUInt64LE(BigInt(v) & ((1n << 64n) - 1n)); b.writeBigUInt64LE(BigInt(v) >> 64n, 8); }
    else if (bytes === 8) b.writeBigInt64LE(BigInt(v));
    else if (bytes === 4) b.writeUInt32LE(v);
    else if (bytes === 2) b.writeUInt16LE(v);
    else b.writeUInt8(v);
    parts.push(b);
  };
  for (let i = 0; i < 4; i++) parts.push(Buffer.alloc(32, i + 1));
  n(2, 200); n(4, 3600); n(2, 500); n(4, 86400); n(4, 21600); for (let i = 0; i < 4; i++) n(8, 0);
  n(8, 1); n(8, 2); n(8, 3); n(8, 4); n(1, 1); n(1, 6); n(1, 254); n(1, 253); n(4, 5); n(8, 6); n(8, 7); n(8, 8);
  for (let i = 0; i < 5; i++) n(16, 9 + i);
  n(8, 40); n(8, 30); n(8, 1000); n(8, 260_200); n(8, 865_000); n(1, 1);
  const v = decodeVault(new Uint8Array(Buffer.concat(parts)));
  assert.deepEqual([v.decimals, v.pendingTickets, v.cancelled], [6, 5, 13n]);
  assert.deepEqual([v.lifeboatAmount, v.exitAmount, v.exitProposedS, v.exitExecutableS, v.exitExpiresS, v.exitVetoed], [40n, 30n, 1000, 260_200, 865_000, true]);
  // Then the limits version, the low-water balance and the exit's proposer
  // (finding 91), the reserved tail padded to Vault::LEN (433).
  n(4, 12); n(8, 50); n(8, 60); n(8, 70); parts.push(Buffer.alloc(32, 9));
  const full = Buffer.concat(parts);
  const w = decodeVault(new Uint8Array(Buffer.concat([full, Buffer.alloc(433 - full.length)])));
  assert.deepEqual([w.limitsVersion, w.low.prev, w.low.window], [12, 50n, 70n]);
  assert.equal(w.exitProposer, b58encode(new Uint8Array(32).fill(9)));
});

test("onCurve takes a y of p or more mod p, as Solana does", async () => {
  // Checked against solana-address's is_on_curve (curve25519-dalek): p + 1 is
  // the identity point, on the curve (the vectors carry the y >= p edges too).
  const { onCurve } = await import("../lib/solana.mjs");
  const pPlus1 = new Uint8Array(32).fill(0xff);
  pPlus1[31] = 0x7f;
  pPlus1[0] = 0xee;
  assert.equal(onCurve(pPlus1), true);
  const one = new Uint8Array(32);
  one[0] = 1;
  assert.equal(onCurve(one), true);
});

test("a buffer's role matches what close_buffer refuses (docs/09, finding 78)", async () => {
  const [A, S, P, X, O] = [1, 2, 3, 4, 5].map((i) => b58encode(new Uint8Array(32).fill(i)));
  const c = { abortBuffer: A, snapshotBuffer: S, pendingKind: 1, pendingTarget: P };
  assert.deepEqual([A, S, P, X].map((b) => floorBufferRole(c, b)), ["abort", "pin", "pending", "orphan"]);
  // Only an upgrade (1) or a restore (2) names a buffer: another kind's target
  // is a key, and a buffer at that address is an orphan.
  assert.equal(floorBufferRole({ ...c, pendingKind: 4 }, P), "orphan");
  assert.equal(floorBufferRole({ ...c, pendingKind: 2 }, P), "pending");
  // Nothing staged or pinned (decodeFloor gives null): every buffer is an orphan.
  assert.equal(floorBufferRole({ abortBuffer: null, snapshotBuffer: null, pendingKind: 0, pendingTarget: "1".repeat(32) }, X), "orphan");
  // The close carries the owner as a writable signer, then the buffer, the
  // PDA, the loader, and the programdata (finding 85: a buffer identical to
  // the live code is refused while the program is live).
  const fc = await new FloorClient("11111111111111111111111111111111", "11111111111111111111111111111112").init();
  const ix = fc.closeBuffer(O, X);
  assert.equal(ix.data[0], 13);
  assert.deepEqual(ix.accounts.map((a) => [!!a.signer, !!a.writable]), [[false, false], [true, true], [false, true], [false, false], [false, false], [false, false]]);
  assert.equal(b58encode(ix.accounts[5].pubkey), b58encode(fc.programdata));
  // A release to none carries the owner as a writable signer (finding 95); a
  // release to a key carries that key as the signer instead.
  const none = fc.executeRelease(O, null, [A, S]);
  assert.deepEqual([...none.data], [7], "execute, no args");
  assert.deepEqual(none.accounts.map((a) => [!!a.signer, !!a.writable]), [[false, true], [false, true], [false, false], [false, false], [true, true], [false, true], [false, true]]);
  const toKey = fc.executeRelease(O, P, [A]);
  assert.deepEqual(toKey.accounts.map((a) => [!!a.signer, !!a.writable]), [[false, true], [false, true], [false, false], [false, false], [false, true], [true, false], [false, true]]);
});
