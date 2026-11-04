// The status page itself (cloud/status/index.html), run in Node: its module
// script with a minimal DOM and stubbed RPCs. A link may name real ids with a
// lying RPC (F-11) or a host on the reader's own network (F-03); the page
// must say so at the top, refuse the healthy styling, and send nothing to a
// private host before the reader confirms.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { GENESIS, b58encode, key } from "../lib/solana.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { formatUnits } from "../lib/source.mjs";

const VAULT = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b"; // the published devnet deployment
const PROTOCOL = "6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh";
const MINT = "CBK36QrH6fzjrDYwkKHF6jeEAEfHcm8iSVN9BZrCxHSB";
const U64_MAX = 2n ** 64n - 1n;

// The page's module script, its imports pointed at cloud/lib.
const html = readFileSync(new URL("../status/index.html", import.meta.url), "utf8");
const script = /<script type="module">([\s\S]*?)<\/script>/.exec(html)[1]
  .replaceAll('"../lib/', `"${new URL("../lib/", import.meta.url).href}`);
const dir = mkdtempSync(join(tmpdir(), "bulkhead-status-"));
const pageFile = join(dir, "page.mjs");
writeFileSync(pageFile, script);

function protocolBytes({ sealed = 1, frozenUntil = 0 } = {}) {
  const d = new Uint8Array(597);
  const v = new DataView(d.buffer);
  d.set(new TextEncoder().encode("BHPROTv1"));
  d.fill(3, 72, 104); // admin
  d.fill(10, 104, 136); // one guardian
  v.setBigInt64(360, 1_000n, true); // its heartbeat
  d[424] = 1; d[425] = 1; d[426] = sealed;
  v.setBigInt64(428, 600n, true);
  v.setBigInt64(436, 259_200n, true);
  v.setBigInt64(444, BigInt(frozenUntil), true);
  v.setUint32(456, 1, true); // one vault
  return d;
}
function vaultBytes() {
  const d = new Uint8Array(400);
  const v = new DataView(d.buffer);
  d.set(new TextEncoder().encode("BHVAULT1"));
  v.setUint16(136, 1_000, true); v.setUint32(138, 3_600, true); // 10% an hour
  v.setUint16(142, 2_000, true); v.setUint32(144, 86_400, true); // 20% a day
  d[217] = 6; // decimals
  return d;
}
function tokenBytes(amount) {
  const d = new Uint8Array(165);
  new DataView(d.buffer).setBigUint64(64, amount, true);
  return d;
}
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

const vc = await new VaultClient(VAULT, PROTOCOL).init();
const { vault, vaultTokens } = await vc.vault(MINT);
const ADDR = { protocol: b58encode(key(vc.protocol)), vault: b58encode(key(vault)), tokens: b58encode(key(vaultTokens)) };

/** An RPC answering from `chain`: its genesis, protocol, slot. */
function node({ genesis = GENESIS.devnet, protocol = protocolBytes(), slot = 5_000, balance = U64_MAX } = {}) {
  const accounts = { [ADDR.protocol]: protocol, [ADDR.vault]: vaultBytes(), [ADDR.tokens]: tokenBytes(balance) };
  return (method, params) => {
    if (method === "getGenesisHash") return { result: genesis };
    if (method === "getSlot") return { result: slot };
    if (method === "getBlockTime") return { result: 1_500 };
    if (method === "getProgramAccounts") return { result: [] };
    if (method === "getAccountInfo") {
      const d = accounts[params[0]];
      return { result: { context: { slot }, value: d ? { data: [b64(d), "base64"], owner: VAULT, lamports: 1 } : null } };
    }
    return { error: { code: -32601, message: "method not found" } };
  };
}

/**
 * Loads the page with `search` as its query string and `hosts` answering
 * fetches (a host missing from it fails like a CORS refusal). Returns the
 * page's output, top line, fetch log and a click on its confirm button.
 */
async function openPage(search, hosts) {
  const fetched = [];
  const values = Object.create(null);
  const elements = Object.create(null);
  for (const k of ["rpc", "vault", "protocol", "mints", "floor", "protected"]) {
    elements[k] = { get value() { return values[k] ?? ""; }, set value(v) { values[k] = v; } };
  }
  const form = { elements, addEventListener() {} };
  const out = { innerHTML: "", listeners: {}, addEventListener(t, fn) { this.listeners[t] = fn; } };
  const src = { className: "", textContent: "", replaceChildren(...n) { this.textContent = n.map((x) => (typeof x === "string" ? x : x.textContent)).join(""); } };
  const saved = { fetch: globalThis.fetch, setInterval: globalThis.setInterval };
  Object.assign(globalThis, {
    document: { getElementById: (id) => ({ f: form, out, src })[id], createElement: () => ({ textContent: "" }) },
    location: { search },
    history: { replaceState() {} },
    FormData: class { constructor(f) { this.pairs = Object.keys(f.elements).map((k) => [k, f.elements[k].value]); } [Symbol.iterator]() { return this.pairs[Symbol.iterator](); } },
    setInterval: () => 0, // no 10 s refresh in a test
    fetch: async (url, init) => {
      const host = new URL(url).host;
      const { method, params } = JSON.parse(init.body);
      fetched.push(`${host} ${method}`);
      if (!hosts[host]) throw new TypeError("Failed to fetch");
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...hosts[host](method, params) }), { status: 200 });
    },
  });
  const settle = async (before) => {
    for (let i = 0; i < 400 && out.innerHTML === before; i++) await new Promise((r) => setTimeout(r, 5));
    await new Promise((r) => setTimeout(r, 20)); // let a refresh in flight finish
  };
  try {
    await import(`${pathToFileURL(pageFile).href}?${Math.random()}`);
    await settle("");
  } finally {
    globalThis.setInterval = saved.setInterval;
  }
  return {
    out, src, fetched,
    async confirm() {
      const before = out.innerHTML;
      out.listeners.click({ target: { closest: (sel) => (sel === "button[data-confirm]" ? {} : null) } });
      await settle(before);
    },
    done() { globalThis.fetch = saved.fetch; },
  };
}

const link = (rpc, extra = "") => `?rpc=${encodeURIComponent(rpc)}&vault=${VAULT}&protocol=${PROTOCOL}&mints=${MINT}${extra}`;

test("status page: the cluster's public RPC, honest, is shown live with exact u64 amounts (F-07, F-11)", async () => {
  const page = await openPage(link("https://api.devnet.solana.com"), { "api.devnet.solana.com": node() });
  try {
    assert.match(page.src.textContent, /^Data from api\.devnet\.solana\.com · devnet \(genesis EtWT.*\), its public RPC$/);
    assert.equal(page.src.className, "source");
    assert.doesNotMatch(page.out.innerHTML, /unverified|Unverified/);
    assert.match(page.out.innerHTML, /It is devnet's public RPC\./);
    // The balance is 2^64 - 1 raw units: shown exactly, not through Number().
    assert.ok(page.out.innerHTML.includes(`<div class="big">${formatUnits(U64_MAX, 6)}</div>`));
    // Its own public RPC is not asked twice over.
    assert.ok(page.fetched.every((f) => f.startsWith("api.devnet.solana.com ")));
  } finally { page.done(); }
});

test("status page: a lying RPC under real ids is caught by the cross-check (F-11)", async () => {
  // It claims devnet's genesis and a sealed, unfrozen protocol; devnet's
  // public RPC says unsealed and frozen.
  const page = await openPage(link("https://lying.example/rpc"), {
    "lying.example": node({ protocol: protocolBytes({ sealed: 1 }) }),
    "api.devnet.solana.com": node({ protocol: protocolBytes({ sealed: 0, frozenUntil: 9_999 }) }),
  });
  try {
    assert.match(page.src.textContent, /^Data from lying\.example · devnet \(genesis EtWT\S+\) · DISAGREES with api\.devnet\.solana\.com$/);
    assert.equal(page.src.className, "source bad");
    assert.match(page.out.innerHTML, /lying\.example disagrees with api\.devnet\.solana\.com, the cluster's public RPC: it reports another sealed, frozenUntil/);
    assert.match(page.out.innerHTML, /<div class="unverified"><p class="headline">Unverified: Worst case right now/);
    assert.ok(page.fetched.includes("api.devnet.solana.com getAccountInfo"));
  } finally { page.done(); }
});

test("status page: an RPC on another chain than the deployment it names is unverified, and not cross-checked (F-11)", async () => {
  const page = await openPage(link("https://lying.example"), { "lying.example": node({ genesis: GENESIS.testnet }) });
  try {
    assert.match(page.src.textContent, /^Data from lying\.example · testnet \(genesis 4uhcV\S+\)$/);
    assert.equal(page.src.className, "source bad");
    assert.match(page.out.innerHTML, /The Vault program HK5F\S+ \(the devnet deployment\) is on devnet, but lying\.example serves testnet/);
    assert.match(page.out.innerHTML, /class="unverified"/);
    assert.ok(!page.fetched.some((f) => f.startsWith("api.")), "nothing asked of a public RPC for a mismatched chain");
  } finally { page.done(); }
});

test("status page: an unknown genesis is unverified, and a hostile one is escaped (F-11)", async () => {
  const evil = '<img src=x onerror="alert(1)">';
  const page = await openPage(link("https://lying.example"), { "lying.example": node({ genesis: evil }) });
  try {
    assert.ok(!page.out.innerHTML.includes("<img"), "the RPC's genesis answer is never markup");
    assert.match(page.out.innerHTML, /serves an unknown chain \(genesis &lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;\)/);
    assert.match(page.out.innerHTML, /Unverified: Worst case/);
    assert.equal(page.src.textContent, `Data from lying.example · unknown chain (genesis ${evil})`); // textContent: inert
  } finally { page.done(); }
});

test("status page: a public RPC that cannot be reached is 'could not cross-check', never verified (F-11)", async () => {
  // api.devnet.solana.com is missing from the hosts: its fetch fails as a CORS refusal does.
  const page = await openPage(link("https://other.example"), { "other.example": node() });
  try {
    assert.match(page.src.textContent, /· could not cross-check with api\.devnet\.solana\.com$/);
    assert.equal(page.src.className, "source warn");
    assert.match(page.out.innerHTML, /Could not cross-check against api\.devnet\.solana\.com \(getAccountInfo: Failed to fetch\): the figures are only as true as other\.example\./);
    assert.doesNotMatch(page.out.innerHTML, /Cross-checked against|agrees/);
  } finally { page.done(); }
});

test("status page: an honest third-party RPC agrees with the public one (F-11)", async () => {
  const page = await openPage(link("https://other.example"), { "other.example": node(), "api.devnet.solana.com": node({ slot: 5_020 }) });
  try {
    assert.match(page.src.textContent, /· agrees with api\.devnet\.solana\.com$/);
    assert.match(page.out.innerHTML, /Cross-checked against api\.devnet\.solana\.com: the protocol's settings agree/);
    assert.doesNotMatch(page.out.innerHTML, /unverified/);
  } finally { page.done(); }
});

test("status page: a link's private RPC is not queried until the reader confirms (F-03)", async () => {
  const page = await openPage(link("http://127.0.0.1:8899"), { "127.0.0.1:8899": node({ genesis: "Loca1Genesis111111111111111111111111111111" }) });
  try {
    assert.deepEqual(page.fetched, [], "nothing sent before the reader confirms");
    assert.match(page.out.innerHTML, /<h2>Confirm the RPC<\/h2>/);
    assert.match(page.out.innerHTML, /query <b class="mono">127\.0\.0\.1:8899<\/b>, a loopback address \(this computer\)/);
    assert.match(page.out.innerHTML, /<button type="button" data-confirm>Query 127\.0\.0\.1:8899<\/button>/);
    assert.equal(page.src.textContent, "Data from 127.0.0.1:8899 · not queried: on your own machine or network");
    await page.confirm();
    assert.ok(page.fetched.includes("127.0.0.1:8899 getGenesisHash"));
    assert.match(page.out.innerHTML, /serves an unknown chain/);
    assert.match(page.out.innerHTML, /Unverified: Worst case/);
  } finally { page.done(); }
});

test("status page: a data: or other non-http RPC is refused outright", async () => {
  const page = await openPage(link('data:application/json,{"result":"x"}'), {});
  try {
    assert.deepEqual(page.fetched, []);
    assert.match(page.out.innerHTML, /Refused to read the RPC data:application\/json,\{&quot;result&quot;:&quot;x&quot;\}: only http\(s\) RPCs are read, not data:/);
  } finally { page.done(); }
});
