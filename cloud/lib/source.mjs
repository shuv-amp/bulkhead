// Where the status page's numbers come from, and how far to trust them.
//
// A link names the RPC the page reads, so a crafted link can pair real
// program ids with an RPC that makes numbers up, or point a reader's browser
// at a host on their own network. Everything here is pure except
// `crossCheck`, which reads through the RPC object it is given; the page
// (cloud/status/index.html) escapes every string it shows from here.

import { GENESIS, SLOT_LAG_SWITCH, decodeProtocol } from "./solana.mjs";

/** Each public cluster's default RPC, the one a link's RPC is checked against. */
export const PUBLIC_RPC = {
  "mainnet-beta": "https://api.mainnet-beta.solana.com",
  devnet: "https://api.devnet.solana.com",
  testnet: "https://api.testnet.solana.com",
};

/** The public cluster a genesis hash is, or null: a local or private chain. */
export function clusterOf(genesis) {
  for (const [name, hash] of Object.entries(GENESIS)) if (hash === genesis) return name;
  return null;
}

/** The cluster whose default public RPC `url` is (https, same host), or null. */
export function publicCluster(url) {
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol !== "https:" || u.port) return null;
  for (const [name, def] of Object.entries(PUBLIC_RPC)) if (new URL(def).hostname === u.hostname.replace(/\.$/, "")) return name;
  return null;
}

/** "1.2.3.4" (as the URL parser normalises every IPv4 form) to its 4 octets. */
function ipv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

/** An IPv6 literal (no brackets) to its 8 groups, or null. */
function ipv6(s) {
  if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(":")) return null;
  let tail = [];
  const dotted = /(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (dotted) {
    const o = ipv4(dotted[1]);
    if (!o) return null;
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    s = s.slice(0, s.length - dotted[1].length);
    if (s.endsWith(":") && !s.endsWith("::")) s = s.slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const part = (h) => (h === "" ? [] : h.split(":").map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN)));
  const head = part(halves[0]);
  const back = halves.length === 2 ? part(halves[1]) : [];
  const given = head.length + back.length + tail.length;
  if ([...head, ...back].some(Number.isNaN)) return null;
  if (halves.length === 1 ? given !== 8 : given > 7) return null;
  return [...head, ...Array(8 - given).fill(0), ...back, ...tail];
}

function privateV4([a, b]) {
  if (a === 127) return "a loopback address (this computer)";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "a private network address (RFC 1918)";
  if (a === 169 && b === 254) return "a link-local address (this network segment; cloud metadata services live here)";
  if (a === 100 && b >= 64 && b <= 127) return "a carrier-grade NAT address (RFC 6598), not a public one";
  if (a === 0) return "an unspecified address (reaches this computer)";
  if (a >= 224) return "a multicast or reserved address";
  return null;
}

/**
 * Why a host (as `URL.hostname` gives it) is on the reader's own machine or
 * network, or null for a public one. Covers loopback, RFC 1918, link-local,
 * CGNAT, unique-local and IPv4-mapped IPv6, `localhost`, `.local`,
 * `.internal`, `.home.arpa` and single-label names. A public name that
 * resolves to a private address cannot be seen from a page (no DNS API).
 */
export function privateHost(hostname) {
  const h = String(hostname).toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") && h.endsWith("]")) {
    const g = ipv6(h.slice(1, -1));
    if (!g) return "an IPv6 address this page cannot read";
    if (g.every((x) => x === 0)) return "an unspecified address (reaches this computer)";
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return "a loopback address (this computer)";
    if ((g[0] & 0xfe00) === 0xfc00) return "a unique-local IPv6 address (a private network)";
    if ((g[0] & 0xffc0) === 0xfe80) return "a link-local IPv6 address (this network segment)";
    if ((g[0] & 0xffc0) === 0xfec0) return "a site-local IPv6 address (a private network)";
    if ((g[0] & 0xff00) === 0xff00) return "a multicast IPv6 address";
    // An IPv4 address inside IPv6: mapped (::ffff:a.b.c.d), compatible
    // (::a.b.c.d), 6to4 (2002:aabb:ccdd::) or NAT64 (64:ff9b::a.b.c.d).
    const v4 = (hi, lo) => privateV4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);
    if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) return v4(g[6], g[7]);
    if (g[0] === 0x2002) return v4(g[1], g[2]);
    if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return v4(g[6], g[7]);
    return null;
  }
  const o = ipv4(h);
  if (o) return privateV4(o);
  if (h === "localhost" || h.endsWith(".localhost")) return "a loopback name (this computer)";
  if (h.endsWith(".local")) return "a .local name (this network, mDNS)";
  if (h.endsWith(".internal") || h.endsWith(".home.arpa") || h.endsWith(".lan")) return "a name for a private network";
  if (!h.includes(".")) return "a single-label name, which resolves only inside a local network";
  return null;
}

/**
 * Whether the page may query `url` as given in a link: `{ refuse }` (never:
 * not an http(s) URL; a data: or blob: "RPC" answers whatever the link
 * says), `{ confirm, host }` (on the reader's machine or network: only once
 * the reader says so), or `{ host }` (a public host).
 */
export function rpcGate(url) {
  let u;
  try { u = new URL(url); } catch { return { refuse: "it is not a URL" }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { refuse: `only http(s) RPCs are read, not ${u.protocol}` };
  const why = privateHost(u.hostname);
  return why ? { confirm: why, host: u.host } : { host: u.host };
}

/**
 * What the genesis hash says about the source. `claims` are clusters the
 * page is told it is on, `{ cluster, why }` (a published deployment's
 * cluster, a public RPC's address). `trusted` is false when the hash is
 * missing, of no public cluster, or of another cluster than a claim; each
 * `problems` entry is plain text. The hash is the RPC's own answer: this
 * catches a wrong cluster, not an RPC that lies (`crossCheck` is for that).
 */
export function judgeSource({ url, genesis, genesisError = null, claims = [] }) {
  const host = rpcGate(url).host ?? String(url);
  const cluster = typeof genesis === "string" ? clusterOf(genesis) : null;
  const problems = [];
  if (typeof genesis !== "string") {
    problems.push(`${host} did not give its genesis hash${genesisError ? ` (${genesisError})` : ""}, so which chain it serves is unknown.`);
  } else if (!cluster) {
    problems.push(`${host} serves an unknown chain (genesis ${genesis}): not mainnet-beta, devnet or testnet. On a local or private chain any account can say anything.`);
  }
  for (const c of claims) {
    if (typeof genesis === "string" && c.cluster !== cluster) problems.push(`${c.why} is on ${c.cluster}, but ${host} serves ${cluster ?? "an unknown chain"} (genesis ${genesis}).`);
  }
  return { host, cluster, genesis: typeof genesis === "string" ? genesis : null, problems, trusted: problems.length === 0 };
}

/** The protocol settings a status reader relies on, by name. */
const PROTOCOL_FIELDS = ["admin", "guardians", "threshold", "sealed", "heartbeatIntervalS", "loosenDelayS", "frozenUntil", "vaultCount", "lifeboatDestination", "sealExecutableS", "sealVetoed", "recovery"];

/** The names of the settings two decoded protocol accounts disagree on. */
export function protocolDisagreements(mine, theirs) {
  return PROTOCOL_FIELDS.filter((k) => JSON.stringify(mine[k] ?? null) !== JSON.stringify(theirs[k] ?? null));
}

/**
 * Reads the protocol account and the slot from `publicRpc` (the cluster's
 * default RPC) and compares them with what the link's RPC gave:
 * `{ state: "agrees" | "disagrees" | "failed", detail }`. Any failure to
 * read (CORS, 429, timeout) is "failed", never "agrees". Heartbeats move
 * between two reads, so they are not compared; a freeze landing between the
 * two reads can show as a disagreement once.
 */
export async function crossCheck({ publicRpc, protocolKey, linkProtocol, linkSlot }) {
  let acc, slot;
  try {
    acc = await publicRpc.account(protocolKey);
    slot = await publicRpc.call("getSlot", [{ commitment: "confirmed" }]);
  } catch (e) {
    return { state: "failed", detail: String(e?.message ?? e).slice(0, 160) };
  }
  if (typeof slot !== "number") return { state: "failed", detail: "getSlot gave no slot" };
  if (!acc) return { state: "disagrees", detail: "it has no protocol account at this address" };
  let theirs;
  try {
    theirs = decodeProtocol(acc.bytes);
  } catch {
    return { state: "disagrees", detail: "its account at this address is not a Bulkhead protocol" };
  }
  const problems = [];
  const diff = protocolDisagreements(linkProtocol, theirs);
  if (diff.length) problems.push(`it reports another ${diff.join(", ")}`);
  const lag = slot - linkSlot;
  if (lag > SLOT_LAG_SWITCH) problems.push(`this RPC is ${lag} slots (about ${Math.round(lag * 0.4)} s) behind it, so its figures are stale`);
  if (lag < -SLOT_LAG_SWITCH) problems.push(`this RPC claims slot ${linkSlot}, ${-lag} slots ahead of it`);
  return problems.length
    ? { state: "disagrees", detail: problems.join("; ") }
    : { state: "agrees", detail: `the protocol's settings agree, and the slot is within ${SLOT_LAG_SWITCH} of it` };
}

/**
 * A raw token amount (u64/u128, bigint or integer) in whole tokens, exactly:
 * two decimals under 100, none from 100 up, rounded half up, grouped as the
 * locale groups. `Number(raw) / 10 ** decimals` is not exact past 2^53.
 */
export function formatUnits(raw, decimals, locale = undefined) {
  const v = typeof raw === "bigint" ? raw : BigInt(raw);
  const neg = v < 0n;
  const a = neg ? -v : v;
  const unit = 10n ** BigInt(decimals);
  const digits = a < 100n * unit ? 2 : 0;
  const keep = 10n ** BigInt(digits);
  const scaled = (2n * a * keep + unit) / (2n * unit);
  const whole = scaled / keep;
  const frac = digits ? String(scaled % keep).padStart(digits, "0").replace(/0+$/, "") : "";
  const sep = new Intl.NumberFormat(locale).formatToParts(1.5).find((p) => p.type === "decimal")?.value ?? ".";
  const out = whole.toLocaleString(locale) + (frac ? sep + frac : "");
  return neg && scaled > 0n ? `-${out}` : out;
}
