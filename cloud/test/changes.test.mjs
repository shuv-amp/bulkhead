// The status page's view of pending loosenings and lifeboat exits
// (cloud/lib/changes.mjs), and the decoders it reads them with, against the
// layouts in programs/vault/src/state.rs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeChange, assetVersion, decodeVault, b58encode } from "../lib/solana.mjs";
import { openChanges, openExit, protocolVersion, duration } from "../lib/changes.mjs";

// Change::store: disc, protocol, id, kind, vetoed, executed, bump, target,
// proposer, created, executable, expires, payload_len, payload[300],
// base_version, 2 zero bytes. Change::LEN = 448.
function changeBytes({ id = 7n, kind = 0, vetoed = 0, executed = 0, executableS = 1000, expiresS = 2000, baseVersion = 3, payloadLen = 300 } = {}) {
  const d = new Uint8Array(448);
  const v = new DataView(d.buffer);
  d.set(new TextEncoder().encode("BHCHNG01"), 0);
  d.fill(1, 8, 40);
  v.setBigUint64(40, id, true);
  d[48] = kind; d[49] = vetoed; d[50] = executed; d[51] = 254;
  d.fill(2, 52, 84);
  d.fill(3, 84, 116);
  v.setBigInt64(116, 500n, true);
  v.setBigInt64(124, BigInt(executableS), true);
  v.setBigInt64(132, BigInt(expiresS), true);
  v.setUint16(140, payloadLen, true);
  d.fill(0xaa, 142, 442);
  v.setUint32(442, baseVersion, true);
  return d;
}

test("decodeChange reads every field at the program's offsets", () => {
  const c = decodeChange(changeBytes({ id: 9n, kind: 3, vetoed: 1, baseVersion: 0xdeadbeef }));
  assert.deepEqual(c, {
    protocol: b58encode(new Uint8Array(32).fill(1)),
    id: 9n,
    kind: 3,
    vetoed: true,
    executed: false,
    target: b58encode(new Uint8Array(32).fill(2)),
    proposer: b58encode(new Uint8Array(32).fill(3)),
    createdS: 500,
    executableS: 1000,
    expiresS: 2000,
    payload: new Uint8Array(300).fill(0xaa),
    baseVersion: 0xdeadbeef,
  });
  // The payload is its first payload_len bytes, the field the guardian's
  // approvals compare; a length past the field is not a change account.
  assert.deepEqual(decodeChange(changeBytes({ payloadLen: 5 })).payload, new Uint8Array(5).fill(0xaa));
  assert.throws(() => decodeChange(changeBytes({ payloadLen: 301 })), /payload/);
  assert.throws(() => decodeChange(changeBytes().subarray(0, 447)));
  const wrong = changeBytes(); wrong[0] = 0x41;
  assert.throws(() => decodeChange(wrong));
});

test("assetVersion and the vault's limitsVersion sit where the program writes them", () => {
  // Asset: disc, protocol, mint, config (53), decimals, bump, version.
  const a = new Uint8Array(8 + 64 + 53 + 2 + 32);
  a.set(new TextEncoder().encode("BHASSET1"));
  new DataView(a.buffer).setUint32(127, 41, true);
  assert.equal(assetVersion(a), 41);
  // Vault (Vault::store): disc, 4 keys, limits (48), 2 TATs, reference and its
  // time, 4 single bytes, pending, queued, frozen, imported, 5 u128 totals,
  // lifeboat, exit amount and its 3 times, exitVetoed, then limitsVersion at 369.
  const at = 8 + 128 + 48 + 16 + 16 + 4 + 4 + 8 + 8 + 8 + 80 + 16 + 24 + 1;
  assert.equal(at, 369);
  const vault = new Uint8Array(at + 4 + 59);
  vault.set(new TextEncoder().encode("BHVAULT1"));
  new DataView(vault.buffer).setUint32(at, 12, true);
  // An account written before the counter existed ends before it: no version.
  assert.equal(decodeVault(vault.subarray(0, at)).limitsVersion, undefined);
  assert.equal(decodeVault(vault).limitsVersion, 12);
});

test("openChanges: waiting, executable, stale; vetoed, executed, expired and abdicated left out", () => {
  const c = (o) => decodeChange(changeBytes(o));
  const all = [
    c({ id: 1n, executableS: 1000, expiresS: 2000 }),             // waiting at 900
    c({ id: 2n, executableS: 800, expiresS: 2000 }),              // executable
    c({ id: 3n, executableS: 1000, expiresS: 2000, baseVersion: 2 }), // stale
    c({ id: 4n, vetoed: 1 }),
    c({ id: 5n, executed: 1 }),
    c({ id: 6n, executableS: 100, expiresS: 900 }),               // expired exactly at now
    c({ id: 8n, kind: 2 }),                                       // guardians: abdicated
  ];
  const got = openChanges(all, 900, { abdications: 1 << 2, versionOf: () => 3 });
  assert.deepEqual(got.map((x) => [x.id, x.state, x.secondsLeft, x.kindName]), [
    [2n, "executable", 1100, "limits"],
    [1n, "waiting", 100, "limits"],
    [3n, "stale", 0, "limits"],
  ]);
  // The boundaries: executable exactly at executableS, gone exactly at expiresS.
  assert.equal(openChanges([c({ executableS: 900 })], 900)[0].state, "executable");
  assert.equal(openChanges([c({ expiresS: 900, executableS: 100 })], 900).length, 0);
  // An unknown version is not called stale.
  assert.equal(openChanges([c({ baseVersion: 2 })], 900)[0].state, "waiting");
});

test("protocolVersion follows the program's version slots", () => {
  const p = { versions: [10, 11, 12, 13, 14] };
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6].map((k) => protocolVersion(p, k)), [undefined, undefined, 10, 11, 12, 13, 14]);
  assert.equal(protocolVersion({}, 2), undefined);
});

test("openExit: waiting, executable, then gone when vetoed, executed or expired", () => {
  const v = { exitAmount: 5n, exitVetoed: false, exitExecutableS: 1000, exitExpiresS: 2000 };
  assert.deepEqual(openExit(v, 900), { amount: 5n, state: "waiting", secondsLeft: 100 });
  assert.deepEqual(openExit(v, 1000), { amount: 5n, state: "executable", secondsLeft: 1000 });
  assert.equal(openExit(v, 2000), null);
  assert.equal(openExit({ ...v, exitVetoed: true }, 900), null);
  assert.equal(openExit({ ...v, exitAmount: 0n }, 900), null);
});

test("duration", () => {
  assert.equal(duration(3 * 86400 + 4 * 3600 + 59), "3d 4h");
  assert.equal(duration(5 * 3600 + 20 * 60), "5h 20m");
  assert.equal(duration(30), "1m");
  assert.equal(duration(0), "0m");
  assert.equal(duration(-5), "0m");
});
