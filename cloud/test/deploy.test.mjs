import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { key, b58encode } from "../lib/solana.mjs";
import { stepDisposition, marketDirProblem } from "../deploy/market.mjs";

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
