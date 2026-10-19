// The emergency stop (cloud/guardian/stop.mjs) against local stub endpoints:
// which cluster it reads from (docs/09, finding 117).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { GENESIS } from "../guardian/policy.mjs";
import { Keypair } from "../lib/signer.mjs";

const SYSTEM = "11111111111111111111111111111111";
const FLOR = 0x464c4f52;

// A Floor config that says the program is stopped.
const stopped = (() => {
  const d = new Uint8Array(1000);
  d.set(new TextEncoder().encode("FLOORv01"));
  d[426] = 1;
  return btoa(String.fromCharCode(...d));
})();

// An endpoint on `genesis`, or a JSON-RPC error `{ code }` it answers
// getGenesisHash with (undefined: an answer with no hash); `config` is the
// Floor config it holds, if any, read after `readMs`. Every call to the
// program fails with FLOR there.
async function stubRpc(genesis, config, readMs = 0) {
  const answers = {
    getGenesisHash: genesis,
    getSlot: 100,
    getRecentPrioritizationFees: [],
    getLatestBlockhash: { value: { blockhash: SYSTEM, lastValidBlockHeight: 200 } },
    getAccountInfo: { value: config ? { data: [config, "base64"], owner: SYSTEM, lamports: 1, executable: false, space: 1000 } : null },
    simulateTransaction: { value: { err: { InstructionError: [0, { Custom: FLOR }] } } },
  };
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", async () => {
      const { id, method } = JSON.parse(b);
      if (method === "getAccountInfo") await new Promise((r) => setTimeout(r, readMs));
      res.setHeader("content-type", "application/json");
      if (method === "getGenesisHash" && genesis?.code) res.end(JSON.stringify({ jsonrpc: "2.0", id, error: genesis }));
      else res.end(JSON.stringify({ jsonrpc: "2.0", id, result: answers[method] ?? null }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

// Runs stop.mjs (cluster devnet unless given, undefined for none); resolves
// with its exit code and output.
async function runStop(rpc, rpcs, opts = {}) {
  const { maxSeconds = 5 } = opts;
  const cluster = "cluster" in opts ? opts.cluster : "devnet";
  const dir = mkdtempSync(`${tmpdir()}/bh-stop-`);
  const keyPath = `${dir}/guardian.json`;
  Keypair.generate().save(keyPath);
  const cfgPath = `${dir}/g.json`;
  writeFileSync(cfgPath, JSON.stringify({ rpc, rpcs, cluster, floorProgram: SYSTEM, guardianKey: keyPath }));
  const stop = fileURLToPath(new URL("../guardian/stop.mjs", import.meta.url));
  const child = spawn(process.execPath, [stop, cfgPath, SYSTEM, "--max-seconds", String(maxSeconds)], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const timer = setTimeout(() => child.kill(), 20_000);
  for (const s of [child.stdout, child.stderr]) s.on("data", (c) => { out += c; });
  const code = await new Promise((r) => child.on("exit", r));
  clearTimeout(timer);
  rmSync(dir, { recursive: true });
  return { code, out };
}

test("a stop does not read a primary on another cluster: it reads the backup on its own (finding 117)", async () => {
  // The primary is a testnet copy whose program is stopped; on devnet there
  // is no config. The old code read the primary and said "stopped", exit 0.
  const primary = await stubRpc(GENESIS.testnet, stopped);
  const backup = await stubRpc(GENESIS.devnet, null);
  try {
    const { code, out } = await runStop(primary.url, [backup.url]);
    assert.equal(code, 2, out);
    assert.match(out, /no Floor config for this program/);
    assert.doesNotMatch(out, /"stopped/);
    const host = new URL(primary.url).host.replaceAll(".", "\\.");
    assert.match(out, new RegExp(`RPC endpoint ${host} \\(rpc\\) serves another cluster than devnet \\(genesis ${GENESIS.testnet}\\): not read from; remove it from the config`));
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

test("a stop whose primary is on its cluster still reports a backup on another (finding 117)", async () => {
  // The primary reads slowly, so the backup's answer comes before the stop ends.
  const primary = await stubRpc(GENESIS.devnet, stopped, 300);
  const backup = await stubRpc(GENESIS.testnet, stopped);
  try {
    const { code, out } = await runStop(primary.url, [backup.url]);
    assert.equal(code, 0, out);
    assert.match(out, /stopped: calls now fail with FLOR/);
    assert.match(out, /\(rpcs\[0\]\) serves another cluster than devnet \(genesis \w+\): not read from, but copies of the stop still go to it; remove it from the config/);
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

test("a stop with no endpoint on its cluster says so and exits 2 (finding 117)", async () => {
  const primary = await stubRpc(GENESIS.testnet, stopped);
  const backup = await stubRpc(GENESIS.testnet, stopped);
  try {
    const { code, out } = await runStop(primary.url, [backup.url]);
    assert.equal(code, 2, out);
    assert.match(out, /no RPC endpoint serves devnet/);
    // Only a backup gets copies of the stop.
    assert.match(out, /\(rpc\) serves another cluster than devnet \(genesis \w+\): not read from; remove it/);
    assert.match(out, /\(rpcs\[0\]\) serves another cluster than devnet \(genesis \w+\): not read from, but copies of the stop still go to it; remove it/);
    assert.doesNotMatch(out, /"stopped/);
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

test("a stop with one endpoint, on another cluster, says so and exits 2 (finding 117)", async () => {
  const only = await stubRpc(GENESIS.testnet, stopped);
  try {
    const { code, out } = await runStop(only.url);
    assert.equal(code, 2, out);
    assert.match(out, new RegExp(`config.cluster is devnet, but the RPC serves another cluster \\(genesis ${GENESIS.testnet}\\)`));
    assert.doesNotMatch(out, /"stopped/);
  } finally {
    only.server.close();
  }
});

test("a stop on its own cluster still stops, with or without backups (finding 117)", async () => {
  const primary = await stubRpc(GENESIS.devnet, stopped);
  const backup = await stubRpc(GENESIS.devnet, stopped);
  try {
    for (const rpcs of [[backup.url], undefined]) {
      const { code, out } = await runStop(primary.url, rpcs);
      assert.equal(code, 0, out);
      assert.match(out, /stopped: calls now fail with FLOR/);
      // A good endpoint is not reported as on another cluster.
      assert.doesNotMatch(out, /another cluster/);
    }
  } finally {
    primary.server.close();
    backup.server.close();
  }
});

test("a stop with one endpoint that errs for now asks its cluster again, up to the time limit (finding 117)", async () => {
  // Unhealthy, or an internal error: either may pass.
  for (const genesis of [{ code: -32005, message: "Node is unhealthy" }, { code: -32603, message: "Internal error" }]) {
    const only = await stubRpc(genesis, stopped);
    try {
      const { code, out } = await runStop(only.url, undefined, { maxSeconds: 1 });
      assert.equal(code, 1, out);
      assert.match(out, /could not check the RPC's cluster; trying again/);
      assert.match(out, /gave up: the RPC's cluster could not be checked within the time limit/);
      assert.doesNotMatch(out, /"stopped|another cluster/);
    } finally {
      only.server.close();
    }
  }
});

test("a stop with one endpoint that will never say its cluster ends at once with exit 2 (finding 117)", async () => {
  // No such method, or an answer with no hash: a retry gives the same, and
  // waiting out the time limit only delays the operator.
  for (const genesis of [{ code: -32601, message: "Method not found" }, undefined]) {
    const only = await stubRpc(genesis, stopped);
    try {
      const { code, out } = await runStop(only.url, undefined, { maxSeconds: 30 });
      assert.equal(code, 2, out);
      assert.match(out, /the RPC will not give its genesis hash, so its cluster cannot be checked/);
      assert.doesNotMatch(out, /trying again|"stopped|another cluster/);
    } finally {
      only.server.close();
    }
  }
});

test("a stop whose primary is on another cluster and whose backup is down gives up at the time limit (finding 117)", async () => {
  const primary = await stubRpc(GENESIS.testnet, stopped);
  try {
    const { code, out } = await runStop(primary.url, ["http://127.0.0.1:9"], { maxSeconds: 1 });
    assert.equal(code, 1, out);
    assert.match(out, /\(rpc\) serves another cluster than devnet/);
    assert.match(out, /gave up: Floor's config could not be read within the time limit/);
    assert.doesNotMatch(out, /"stopped/);
  } finally {
    primary.server.close();
  }
});

test("a stop refuses a cluster it does not know (finding 117)", async () => {
  // A misspelt cluster used to check nothing.
  const only = await stubRpc(GENESIS.testnet, stopped);
  try {
    for (const cluster of ["mainnet", "constructor"]) {
      const { code, out } = await runStop(only.url, undefined, { cluster });
      assert.equal(code, 2, out);
      assert.match(out, /config.cluster must be one of mainnet-beta, devnet, testnet, localnet/);
    }
  } finally {
    only.server.close();
  }
});

test("a stop on localnet, or with no cluster, checks none, as before; with none it says so (finding 117)", async () => {
  // A local validator has its own genesis hash on every start.
  const only = await stubRpc(GENESIS.testnet, stopped);
  try {
    for (const cluster of ["localnet", undefined]) {
      const { code, out } = await runStop(only.url, undefined, { cluster });
      assert.equal(code, 0, out);
      assert.match(out, /stopped: calls now fail with FLOR/);
      if (cluster === undefined) assert.match(out, /config.cluster is not set: the RPC's cluster is not checked/);
      else assert.doesNotMatch(out, /config.cluster is not set/);
    }
  } finally {
    only.server.close();
  }
});
