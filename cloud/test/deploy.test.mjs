import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

test("world.json is not a finished market when the protocol is absent or for another program", () => {
  assert.match(marketDirProblem(world, "other-vault", harbor, null), /not other-vault/);
  assert.match(marketDirProblem(world, vault, harbor, null), /not on this cluster/);
  assert.match(marketDirProblem(world, vault, harbor, undefined), /can't read/);
  assert.match(marketDirProblem(world, vault, harbor, { bytes: new Uint8Array(8) }), /not a Bulkhead protocol/);
});

test("the canonical Harbor build passes the devnet vault and ignores a leftover id", () => {
  const build = readFileSync(new URL("../../scripts/build-programs.sh", import.meta.url), "utf8");
  assert.match(build, /build-harbor\.sh HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b/);
  const got = execFileSync("bash", ["-c", 'VAULT_ID="${1:-${BULKHEAD_VAULT_ID:-HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b}}"; printf %s "$VAULT_ID"', "bash", vault], {
    env: { ...process.env, BULKHEAD_VAULT_ID: "NotTheDevnetVault" },
  }).toString();
  assert.equal(got, vault);
});
