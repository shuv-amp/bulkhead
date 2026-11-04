// Accounts in their real layouts and a JSON-RPC server to serve them, for
// the owner checks, fresh recipients and the watchdog (not a test file: the
// suite runs cloud/test/*.test.mjs).
import { createServer } from "node:http";
import { key, u64le } from "../lib/solana.mjs";

const text = (s) => new TextEncoder().encode(s);

/** A Vault protocol account (programs/vault/src/state.rs; decodeProtocol). */
export function protocolBytes({ guardians = [], heartbeats = [], threshold = 0, intervalS = 86_400, frozenUntil = 0, sealed = 0, sealExecutableS = 0, sealExpiresS = 0, sealVetoed = 0 } = {}) {
  const d = new Uint8Array(597);
  const v = new DataView(d.buffer);
  d.set(text("BHPROTv1"), 0);
  let o = 8 + 96;
  guardians.forEach((g, i) => d.set(key(g), o + 32 * i));
  o += 256;
  heartbeats.forEach((h, i) => v.setBigInt64(o + 8 * i, BigInt(h), true));
  o += 64;
  d[o++] = guardians.length;
  d[o++] = threshold;
  d[o++] = sealed;
  d[o++] = 255;
  v.setBigInt64(o, BigInt(intervalS), true);
  o += 8 + 8; // the interval, the loosening delay
  v.setBigInt64(o, BigInt(frozenUntil), true);
  o += 8 + 4 + 4 + 16 + 32 + 8; // frozen until, abdications, vault count, next ids, lifeboat, its time
  v.setBigInt64(o, BigInt(sealExecutableS), true);
  v.setBigInt64(o + 8, BigInt(sealExpiresS), true);
  d[o + 16] = sealVetoed;
  return d;
}

/** A Floor config (programs/floor/src/state.rs; decodeFloor). */
export function floorBytes({ program, guardians = [], heartbeats = [], threshold = 0, intervalS = 86_400, status = 0, pendingKind = 0, pendingId = 0n, pendingEta = 0, pendingExpires = 0 } = {}) {
  const d = new Uint8Array(1000);
  const v = new DataView(d.buffer);
  d.set(text("FLOORv01"), 0);
  if (program) d.set(key(program), 8);
  guardians.forEach((g, i) => d.set(key(g), 104 + 32 * i));
  heartbeats.forEach((h, i) => v.setBigInt64(360 + 8 * i, BigInt(h), true));
  d[424] = guardians.length;
  d[425] = threshold;
  d[426] = status;
  v.setBigInt64(432, BigInt(intervalS), true);
  d[520] = pendingKind;
  v.setBigUint64(528, BigInt(pendingId), true);
  v.setBigInt64(568, BigInt(pendingEta), true);
  v.setBigInt64(576, BigInt(pendingExpires), true);
  return d;
}

/** A Vault change account (decodeChange). */
export function changeBytes({ protocol, id = 1n, kind = 3, target, executableS, expiresS, vetoed = 0, executed = 0 }) {
  const d = new Uint8Array(448);
  const v = new DataView(d.buffer);
  d.set(text("BHCHNG01"), 0);
  d.set(key(protocol), 8);
  d.set(u64le(id), 40);
  d[48] = kind;
  d[49] = vetoed;
  d[50] = executed;
  d.set(key(target), 52);
  v.setBigInt64(52 + 64 + 8, BigInt(executableS), true);
  v.setBigInt64(52 + 64 + 16, BigInt(expiresS), true);
  return d;
}

/** The Clock sysvar at `unixS`. */
export function clockBytes(unixS) {
  const d = new Uint8Array(40);
  new DataView(d.buffer).setBigInt64(32, BigInt(unixS), true);
  return d;
}

/** A getAccountInfo answer holding `bytes`, owned by `owner`. */
export const accountInfo = (bytes, owner, slot = 1) => ({ context: { slot }, value: bytes ? { data: [Buffer.from(bytes).toString("base64"), "base64"], owner, lamports: 1, executable: false, space: bytes.length } : null });

/**
 * A JSON-RPC server: `handler(method, params)` gives the result, or
 * `{ error }` for a JSON-RPC error; undefined answers null. `calls` lists
 * every [method, params] asked.
 */
export async function rpcServer(handler) {
  const calls = [];
  const server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => { b += c; });
    req.on("end", async () => {
      const { id, method, params } = JSON.parse(b);
      calls.push([method, params]);
      const r = await handler(method, params ?? []);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id, ...(r?.error ? { error: r.error } : { result: r ?? null }) }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    calls,
    close: () => { server.closeAllConnections(); server.close(); },
  };
}
