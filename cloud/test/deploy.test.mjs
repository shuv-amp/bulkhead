import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { key, b58encode, GUARDIAN_MARGIN, MAX_GUARDIANS } from "../lib/solana.mjs";
import { stepDisposition, marketDirProblem, guardianKeys, guardianMarginProblem } from "../deploy/market.mjs";
import { Keypair } from "../lib/signer.mjs";

const vault = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
const harbor = "6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh";
const world = { vaultProgram: vault, harbor, protocol: "protocol" };

test("a recorded setup step is redone when this cluster does not have it", () => {
  assert.equal(stepDisposition("sig", false), "redo");
  assert.equal(stepDisposition(undefined, false), "run");
  assert.equal(stepDisposition("sig", true), "skip");
  assert.equal(stepDisposition(undefined, true), "skip");
  assert.equal(stepDisposition("sig", undefined), "unreadable");
});

function protocolAccount({ vaultCount = 0, sealExecutableS = 0, sealed = 0 } = {}) {
  const bytes = new Uint8Array(597);
  bytes.set(new TextEncoder().encode("BHPROTv1"));
  bytes.set(key(harbor), 8);
  const view = new DataView(bytes.buffer);
  view.setUint32(456, vaultCount, true);
  view.setBigInt64(516, BigInt(sealExecutableS), true);
  bytes[426] = sealed;
  return { bytes };
}

test("world.json is not a finished market when the protocol is absent or for another program", () => {
  assert.match(marketDirProblem(world, "other-vault", harbor, null), /not other-vault/);
  assert.match(marketDirProblem(world, vault, harbor, null), /not on this cluster/);
  assert.match(marketDirProblem(world, vault, harbor, undefined), /can't read/);
  assert.match(marketDirProblem(world, vault, harbor, { bytes: new Uint8Array(8) }), /not a Bulkhead protocol/);
  assert.match(marketDirProblem(world, vault, harbor, protocolAccount()), /no vault and seal/);
  const proposed = protocolAccount({ vaultCount: 1, sealExecutableS: 1 });
  assert.match(marketDirProblem({ ...world, vault: "vault-addr" }, vault, harbor, proposed, null), /not on this cluster/);
  assert.match(marketDirProblem({ ...world, vault: "vault-addr" }, vault, harbor, proposed, undefined), /can't read the vault/);
  const protocol = b58encode(key(harbor));
  const vaultBytes = new Uint8Array(400);
  vaultBytes.set(new TextEncoder().encode("BHVAULT1"));
  vaultBytes.set(key(protocol), 8);
  assert.equal(marketDirProblem(
    { ...world, protocol, vault: "vault-addr", mint: b58encode(new Uint8Array(32)) },
    vault, harbor, proposed, { bytes: vaultBytes },
  ), null);
});

test("the canonical Harbor build passes the devnet vault and ignores a leftover id", () => {
  const build = readFileSync(new URL("../../scripts/build-programs.sh", import.meta.url), "utf8");
  assert.match(build, /build-harbor\.sh HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b/);
  const harbor = readFileSync(new URL("../../scripts/build-harbor.sh", import.meta.url), "utf8");
  const assign = harbor.match(/^VAULT_ID="([^"]*)"/m)[1];
  assert.equal(assign.includes("BULKHEAD_VAULT_ID"), false);
  const resolve = (arg) => execFileSync("bash", ["-c", `VAULT_ID="${assign}"; printf %s "$VAULT_ID"`, "bash", arg], {
    env: { ...process.env, BULKHEAD_VAULT_ID: "NotTheDevnetVault" },
  }).toString();
  assert.equal(resolve(vault), vault);
  assert.equal(resolve(""), vault);
});

test("a market from before finding 107 keeps its three guardian keys unless a renewal adds one", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-keys-"));
  try {
    mkdirSync(join(dir, "keys"));
    const old = [0, 1, 2].map((i) => {
      const kp = Keypair.generate();
      kp.save(join(dir, "keys", `guardian${i}.json`));
      return kp.address;
    });
    assert.deepEqual(guardianKeys(dir).map((g) => g.address), old);
    assert.equal(existsSync(join(dir, "keys", "guardian3.json")), false);
    const renewed = guardianKeys(dir, true).map((g) => g.address);
    assert.deepEqual(renewed.slice(0, 3), old);
    assert.equal(renewed.length, 4);
    assert.deepEqual(guardianKeys(dir, true).map((g) => g.address), renewed);
    assert.deepEqual(guardianKeys(dir).map((g) => g.address), renewed);
    rmSync(join(dir, "keys", "guardian1.json"));
    for (const create of [false, true]) assert.throws(() => guardianKeys(dir, create), /guardian2\.json exists but .*guardian1\.json does not/);
    assert.equal(existsSync(join(dir, "keys", "guardian1.json")), false); // a gap is never filled with a new key
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the margin check names a set without two keys beyond its quorum", () => {
  assert.equal(guardianMarginProblem(4, 2), null);
  assert.equal(guardianMarginProblem(8, 6), null);
  assert.match(guardianMarginProblem(3, 2), /2-of-3: a new set needs at least 4 keys/);
  assert.match(guardianMarginProblem(7, 6), /6-of-7: a new set needs at least 8 keys/);
});

test("the margin and the set size limit are the programs' own: core governance.rs", () => {
  const core = readFileSync(new URL("../../crates/bulkhead-core/src/governance.rs", import.meta.url), "utf8");
  for (const [name, type, js] of [["GUARDIAN_MARGIN", "u8", GUARDIAN_MARGIN], ["MAX_GUARDIANS", "usize", MAX_GUARDIANS]]) {
    const found = [...core.matchAll(new RegExp(`^pub const ${name}: ${type} = (\\d+);$`, "gm"))];
    assert.equal(found.length, 1, name);
    assert.equal(js, Number(found[0][1]), name);
  }
});

test("an unregistered market gets four guardian keys, made once", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-keys-"));
  try {
    mkdirSync(join(dir, "keys"));
    const made = guardianKeys(dir, true).map((g) => g.address);
    assert.equal(made.length, 4);
    assert.deepEqual(guardianKeys(dir, true).map((g) => g.address), made);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
