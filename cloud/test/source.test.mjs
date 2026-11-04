// The status page's read-side trust (cloud/lib/source.mjs): which RPC a link
// may make a reader's browser query (F-03), what the genesis hash and the
// cross-check against the cluster's public RPC say about the numbers (F-11),
// and exact u64 formatting (F-07).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { GENESIS, decodeProtocol } from "../lib/solana.mjs";
import { GENESIS as POLICY_GENESIS } from "../guardian/policy.mjs";
import { privateHost, rpcGate, publicCluster, clusterOf, judgeSource, protocolDisagreements, crossCheck, formatUnits, PUBLIC_RPC } from "../lib/source.mjs";

test("the guardian and the status page pin the same genesis hashes", () => {
  assert.equal(POLICY_GENESIS, GENESIS);
  assert.equal(clusterOf(GENESIS.devnet), "devnet");
  assert.equal(clusterOf(GENESIS["mainnet-beta"]), "mainnet-beta");
  assert.equal(clusterOf("11111111111111111111111111111111"), null);
  assert.equal(clusterOf(undefined), null);
  assert.deepEqual(Object.keys(PUBLIC_RPC).sort(), Object.keys(GENESIS).sort());
});

test("hosts on the reader's own machine or network are named, public ones are not (F-03)", () => {
  // As the URL parser gives `hostname`: every IPv4 spelling normalised, IPv6 in brackets.
  const host = (u) => new URL(u).hostname;
  const local = [
    "http://127.0.0.1:8899", "http://127.1:8899", "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
    "http://10.0.0.1/", "http://172.16.0.1/", "http://172.31.255.254/", "http://192.168.1.1/", "http://169.254.169.254/",
    "http://100.64.0.1/", "http://0.0.0.0/", "http://[::1]/", "http://[::]/", "http://[fd00::1]/", "http://[fc12:3456::1]/",
    "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.1.2.3]/", "http://[::ffff:a9fe:a9fe]/",
    "http://[2002:c0a8:101::]/", "http://[64:ff9b::a00:1]/", "http://localhost:8899", "http://LOCALHOST./",
    "http://rpc.localhost/", "http://node.local/", "http://solana.internal/", "http://box.home.arpa/", "http://router.lan/", "http://intranet/",
  ];
  for (const u of local) assert.ok(privateHost(host(u)), `${u} should be private`);
  const pub = [
    "https://api.devnet.solana.com", "https://8.8.8.8/", "http://172.15.0.1/", "http://172.32.0.1/", "http://100.128.0.1/",
    "http://192.169.0.1/", "https://[2606:4700:4700::1111]/", "http://[::ffff:8.8.8.8]/", "https://rpc.example.com:8899/",
  ];
  for (const u of pub) assert.equal(privateHost(host(u)), null, `${u} should be public`);
  assert.match(privateHost("127.0.0.1"), /loopback/);
  assert.match(privateHost("10.1.1.1"), /RFC 1918/);
  assert.match(privateHost("169.254.169.254"), /link-local/);
  assert.match(privateHost("[fd00::1]"), /unique-local/);
});

test("rpcGate refuses non-http(s) RPCs and asks before a private one", () => {
  assert.match(rpcGate("data:application/json,{}").refuse, /only http\(s\)/);
  assert.match(rpcGate("javascript:alert(1)").refuse, /only http\(s\)/);
  assert.match(rpcGate("not a url").refuse, /not a URL/);
  const local = rpcGate("http://127.0.0.1:8899");
  assert.equal(local.host, "127.0.0.1:8899");
  assert.match(local.confirm, /loopback/);
  // The host only: a path or query string often carries an API key.
  assert.deepEqual(rpcGate("https://rpc.example.com/?api-key=secret"), { host: "rpc.example.com" });
});

test("publicCluster recognises only the clusters' own public RPCs", () => {
  assert.equal(publicCluster("https://api.devnet.solana.com"), "devnet");
  assert.equal(publicCluster("https://api.mainnet-beta.solana.com/"), "mainnet-beta");
  assert.equal(publicCluster("https://api.testnet.solana.com"), "testnet");
  assert.equal(publicCluster("http://api.devnet.solana.com"), null); // not https
  assert.equal(publicCluster("https://api.devnet.solana.com:8443"), null);
  assert.equal(publicCluster("https://api.devnet.solana.com.evil.example"), null);
  assert.equal(publicCluster("https://evil.example/api.devnet.solana.com"), null);
  assert.equal(publicCluster("garbage"), null);
});

test("judgeSource: a known, matching genesis is trusted; unknown, missing or mismatched is not (F-11)", () => {
  const devnetClaim = [{ cluster: "devnet", why: "The Vault program X (the devnet deployment)" }];
  const ok = judgeSource({ url: "https://rpc.example.com/key", genesis: GENESIS.devnet, claims: devnetClaim });
  assert.deepEqual(ok, { host: "rpc.example.com", cluster: "devnet", genesis: GENESIS.devnet, problems: [], trusted: true });
  // No claim: a public cluster is named and trusted as far as the hash goes.
  assert.equal(judgeSource({ url: "https://rpc.example.com", genesis: GENESIS["mainnet-beta"] }).trusted, true);

  const wrong = judgeSource({ url: "https://rpc.example.com", genesis: GENESIS.testnet, claims: devnetClaim });
  assert.equal(wrong.trusted, false);
  assert.equal(wrong.cluster, "testnet");
  assert.match(wrong.problems[0], /is on devnet, but rpc\.example\.com serves testnet \(genesis 4uhcV/);

  const local = judgeSource({ url: "http://127.0.0.1:8899", genesis: "Loca1Genesis111111111111111111111111111111" });
  assert.equal(local.trusted, false);
  assert.match(local.problems[0], /127\.0\.0\.1:8899 serves an unknown chain \(genesis Loca1Genesis/);

  const silent = judgeSource({ url: "https://rpc.example.com", genesis: null, genesisError: "getGenesisHash: 403" });
  assert.equal(silent.trusted, false);
  assert.match(silent.problems[0], /did not give its genesis hash \(getGenesisHash: 403\)/);

  // A link naming the devnet deployment and mainnet's public RPC contradicts itself.
  const mixed = judgeSource({
    url: "https://api.mainnet-beta.solana.com",
    genesis: GENESIS["mainnet-beta"],
    claims: [...devnetClaim, { cluster: "mainnet-beta", why: "The RPC address api.mainnet-beta.solana.com" }],
  });
  assert.equal(mixed.trusted, false);
  assert.equal(mixed.problems.length, 1);
});

// Protocol::store offsets (programs/vault/src/state.rs), as deploy.test.mjs.
function protocolBytes({ admin = 3, threshold = 1, sealed = 1, frozenUntil = 0, heartbeat = 1000, guardians = 1 } = {}) {
  const d = new Uint8Array(597);
  const v = new DataView(d.buffer);
  d.set(new TextEncoder().encode("BHPROTv1"));
  d.fill(1, 8, 40);
  d.fill(2, 40, 72);
  d.fill(admin, 72, 104);
  for (let i = 0; i < guardians; i++) d.fill(10 + i, 104 + 32 * i, 136 + 32 * i);
  v.setBigInt64(360, BigInt(heartbeat), true);
  d[424] = guardians;
  d[425] = threshold;
  d[426] = sealed;
  v.setBigInt64(428, 600n, true);
  v.setBigInt64(436, 259_200n, true);
  v.setBigInt64(444, BigInt(frozenUntil), true);
  v.setUint32(456, 1, true);
  return d;
}

test("protocolDisagreements compares settings, not heartbeats", () => {
  const a = decodeProtocol(protocolBytes());
  assert.deepEqual(protocolDisagreements(a, decodeProtocol(protocolBytes({ heartbeat: 2000 }))), []);
  assert.deepEqual(protocolDisagreements(a, decodeProtocol(protocolBytes({ sealed: 0, frozenUntil: 99 }))), ["sealed", "frozenUntil"]);
  assert.deepEqual(protocolDisagreements(a, decodeProtocol(protocolBytes({ admin: 4, guardians: 2 }))), ["admin", "guardians"]);
});

/** A stand-in for the public RPC: `account` and `call` answer from the table or throw. */
function stubRpc({ bytes = protocolBytes(), slot = 1_000, fail = null } = {}) {
  return {
    async account() {
      if (fail) throw new Error(fail);
      return bytes ? { bytes } : null;
    },
    async call(method) {
      assert.equal(method, "getSlot");
      return slot;
    },
  };
}

test("crossCheck agrees only when the public RPC gives the same settings and a close slot", async () => {
  const linkProtocol = decodeProtocol(protocolBytes());
  const agree = await crossCheck({ publicRpc: stubRpc({ bytes: protocolBytes({ heartbeat: 1234 }), slot: 1_050 }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
  assert.equal(agree.state, "agrees");

  // The lying RPC says sealed, unfrozen; the public one does not.
  const lie = await crossCheck({ publicRpc: stubRpc({ bytes: protocolBytes({ sealed: 0, frozenUntil: 5 }) }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
  assert.equal(lie.state, "disagrees");
  assert.match(lie.detail, /another sealed, frozenUntil/);

  const missing = await crossCheck({ publicRpc: stubRpc({ bytes: null }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
  assert.deepEqual(missing, { state: "disagrees", detail: "it has no protocol account at this address" });

  const notProtocol = await crossCheck({ publicRpc: stubRpc({ bytes: new Uint8Array(597) }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
  assert.equal(notProtocol.state, "disagrees");

  const stale = await crossCheck({ publicRpc: stubRpc({ slot: 2_000 }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
  assert.equal(stale.state, "disagrees");
  assert.match(stale.detail, /1000 slots \(about 400 s\) behind/);

  const ahead = await crossCheck({ publicRpc: stubRpc({ slot: 1_000 }), protocolKey: "k", linkProtocol, linkSlot: 5_000 });
  assert.match(ahead.detail, /4000 slots ahead/);
});

test("crossCheck reports a failed read (CORS, 429, timeout) as failed, never as agreement", async () => {
  const linkProtocol = decodeProtocol(protocolBytes());
  for (const fail of ["Failed to fetch", 'getAccountInfo: {"code":429}', "getAccountInfo: The operation was aborted due to timeout"]) {
    const r = await crossCheck({ publicRpc: stubRpc({ fail }), protocolKey: "k", linkProtocol, linkSlot: 1_000 });
    assert.equal(r.state, "failed");
    assert.equal(r.detail, fail);
  }
  const noSlot = { account: async () => ({ bytes: protocolBytes() }), call: async () => ({ not: "a slot" }) };
  assert.equal((await crossCheck({ publicRpc: noSlot, protocolKey: "k", linkProtocol, linkSlot: 1_000 })).state, "failed");
});

test("formatUnits is exact for any u64 and u128 (F-07)", () => {
  // 2^64 - 1 raw units at 6 decimals: Number() gives 18446744073709.552 and
  // rounds the whole part to ...709 or ...710 depending on the path.
  assert.equal(formatUnits(18_446_744_073_709_551_615n, 6, "en-US"), "18,446,744,073,710");
  assert.equal(formatUnits(18_446_744_073_709_551_615n, 0, "en-US"), "18,446,744,073,709,551,615");
  assert.equal(formatUnits(9_007_199_254_740_993n, 0, "en-US"), "9,007,199,254,740,993"); // 2^53 + 1
  assert.equal(formatUnits(2n ** 128n - 1n, 9, "en-US"), "340,282,366,920,938,463,463,374,607,432");
  // Under 100: two decimals, trailing zeros dropped; from 100: none; half up.
  assert.equal(formatUnits(1_234_567n, 6, "en-US"), "1.23");
  assert.equal(formatUnits(1_235_000n, 6, "en-US"), "1.24");
  assert.equal(formatUnits(1_500_000n, 6, "en-US"), "1.5");
  assert.equal(formatUnits(99_995_000n, 6, "en-US"), "100");
  assert.equal(formatUnits(100_499_999n, 6, "en-US"), "100");
  assert.equal(formatUnits(100_500_000n, 6, "en-US"), "101");
  assert.equal(formatUnits(0n, 6, "en-US"), "0");
  assert.equal(formatUnits(4, 0, "en-US"), "4");
  assert.equal(formatUnits(1n, 9, "en-US"), "0");
  assert.equal(formatUnits(-1_500_000n, 6, "en-US"), "-1.5");
  assert.equal(formatUnits(1_234_500_000n, 6, "de-DE"), "1.235");
  assert.equal(formatUnits(12_340_000n, 6, "de-DE"), "12,34");
});

test("the status page and its terminal twin format amounts exactly, never through Number() (F-07)", () => {
  // Comments stripped: they may name Number() to say why it is not used.
  const code = (f) => readFileSync(new URL(f, import.meta.url), "utf8").replace(/\/\/.*$/gm, "");
  const page = code("../status/index.html");
  assert.ok(!/Number\(/.test(page), "no Number() in the status page's code");
  assert.match(page, /const fmt = \(raw, decimals\) => formatUnits\(raw, decimals\);/);
  const snapshot = code("../status/snapshot.mjs");
  assert.ok(!/Number\(/.test(snapshot), "no Number() in snapshot.mjs");
  assert.match(snapshot, /const fmt = \(raw, d\) => formatUnits\(raw, d, "en-US"\);/);
});
