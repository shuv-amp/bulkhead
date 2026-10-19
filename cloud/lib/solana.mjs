// Minimal Solana client: no dependencies, runs in Node (>= 20) and browsers.
//
// Base58, compact-u16, legacy transaction messages, program-derived addresses
// (SHA-256 via WebCrypto + an exact ed25519 on-curve check), JSON-RPC, and the
// decoders for Bulkhead's accounts. Signing lives in ./signer.mjs (Node only).
//
// Why no dependencies: the guardian holds keys that can freeze protocols. Its
// supply chain should be as small as the enforcement core's (which has none).

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58decode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`bad base58 character ${c}`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

export function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out;
}

/** A 32-byte public key from base58 or bytes. */
export function key(k) {
  if (typeof k === "string") {
    const b = b58decode(k);
    if (b.length > 32) throw new Error(`not a 32-byte key: ${k}`);
    const out = new Uint8Array(32);
    out.set(b, 32 - b.length);
    return out;
  }
  if (k.length !== 32) throw new Error("not a 32-byte key");
  return Uint8Array.from(k);
}

export const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

export const IDS = {
  system: key("11111111111111111111111111111111"),
  loaderV3: key("BPFLoaderUpgradeab1e11111111111111111111111"),
  token: key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
  token2022: key("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
  rent: key("SysvarRent111111111111111111111111111111111"),
  clock: key("SysvarC1ock11111111111111111111111111111111"),
};

// --- ed25519 on-curve check (RFC 8032 point decoding) ----------------------
const P = 2n ** 255n - 19n;
const modp = (x) => ((x % P) + P) % P;
function powmod(b, e) {
  let r = 1n;
  b = modp(b);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}
const D = modp(-121665n * powmod(121666n, P - 2n));

export function onCurve(k) {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(k[i]);
  // As Solana's is_on_curve (curve25519-dalek): a y of p or more is taken
  // mod p, not refused (p + 1 is the identity point, on the curve).
  y = ((y & ((1n << 255n) - 1n)) % P);
  const u = modp(y * y - 1n);
  const v = modp(D * y * y + 1n);
  const x = modp(u * powmod(v, 3n) * powmod(u * powmod(v, 7n), (P - 5n) / 8n));
  const vx2 = modp(v * x * x);
  return vx2 === u || vx2 === modp(-u);
}

// --- program-derived addresses ----------------------------------------------
async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

export async function findPda(seeds, programId) {
  const program = key(programId);
  for (let bump = 255; bump >= 0; bump--) {
    const parts = [...seeds.map((s) => (typeof s === "string" ? new TextEncoder().encode(s) : s)), Uint8Array.of(bump), program, PDA_MARKER];
    const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
      buf.set(p, o);
      o += p.length;
    }
    const h = await sha256(buf);
    if (!onCurve(h)) return [h, bump];
  }
  throw new Error("no viable bump");
}

// --- little-endian helpers ---------------------------------------------------
export const u64le = (v) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
  return b;
};
export const i64le = (v) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
  return b;
};
export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
export class Reader {
  constructor(bytes, offset = 0) {
    this.b = bytes;
    this.v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.o = offset;
  }
  u8() { return this.b[this.o++]; }
  u16() { const x = this.v.getUint16(this.o, true); this.o += 2; return x; }
  u32() { const x = this.v.getUint32(this.o, true); this.o += 4; return x; }
  u64() { const x = this.v.getBigUint64(this.o, true); this.o += 8; return x; }
  i64() { const x = this.v.getBigInt64(this.o, true); this.o += 8; return x; }
  u128() { const lo = this.u64(); const hi = this.u64(); return (hi << 64n) | lo; }
  i128() { const x = this.u128(); return x >= 1n << 127n ? x - (1n << 128n) : x; }
  key() { const k = this.b.slice(this.o, this.o + 32); this.o += 32; return k; }
  skip(n) { this.o += n; }
}

// --- transactions (legacy message) -------------------------------------------
function shortvec(n) {
  const out = [];
  for (;;) {
    let b = n & 0x7f;
    n >>= 7;
    if (n === 0) { out.push(b); return Uint8Array.from(out); }
    out.push(b | 0x80);
  }
}

/**
 * Compiles instructions into a legacy message.
 * ix: { programId, accounts: [{ pubkey, signer, writable }], data: Uint8Array }
 */
export function compileMessage(feePayer, instructions, recentBlockhash) {
  const metas = new Map();
  const add = (k, signer, writable) => {
    const id = b58encode(k);
    const m = metas.get(id) ?? { key: key(k), signer: false, writable: false };
    m.signer ||= signer;
    m.writable ||= writable;
    metas.set(id, m);
  };
  add(feePayer, true, true);
  for (const ix of instructions) {
    for (const a of ix.accounts) add(a.pubkey, !!a.signer, !!a.writable);
    add(ix.programId, false, false);
  }
  const all = [...metas.values()];
  const payerId = b58encode(key(feePayer));
  const order = (m) => (m.signer ? (m.writable ? 0 : 1) : m.writable ? 2 : 3);
  all.sort((a, b) => {
    const pa = b58encode(a.key) === payerId ? -1 : order(a);
    const pb = b58encode(b.key) === payerId ? -1 : order(b);
    return pa - pb;
  });
  const index = new Map(all.map((m, i) => [b58encode(m.key), i]));
  const header = Uint8Array.of(
    all.filter((m) => m.signer).length,
    all.filter((m) => m.signer && !m.writable).length,
    all.filter((m) => !m.signer && !m.writable).length,
  );
  const compiled = instructions.map((ix) =>
    concat(
      Uint8Array.of(index.get(b58encode(key(ix.programId)))),
      shortvec(ix.accounts.length),
      Uint8Array.from(ix.accounts.map((a) => index.get(b58encode(key(a.pubkey))))),
      shortvec(ix.data.length),
      ix.data,
    ),
  );
  const message = concat(
    header,
    shortvec(all.length),
    ...all.map((m) => m.key),
    key(recentBlockhash),
    shortvec(compiled.length),
    ...compiled,
  );
  return { message, signers: all.filter((m) => m.signer).map((m) => m.key) };
}

/** Wire format: signatures (64 bytes each, in signer order) + message. */
export function serializeTransaction(message, signatures) {
  return concat(shortvec(signatures.length), ...signatures, message);
}

/**
 * How long to wait before retrying a 429 or 5xx: the server's `Retry-After`
 * (seconds) when it gives one, at most 30 s; otherwise 1, 2, 4, 8, 8… s. Either
 * way ±20% jitter, so eight fetches refused together do not all come back in
 * the same instant and be refused again (docs/09, finding 83).
 */
export function retryWaitMs(retryAfter, attempt, random = Math.random) {
  return Math.round(retryBaseMs(retryAfter, attempt) * (0.8 + 0.4 * random()));
}
/** `retryWaitMs` before the jitter. */
export function retryBaseMs(retryAfter, attempt) {
  const s = Number(retryAfter);
  return Number.isFinite(s) && s >= 0 && retryAfter != null && retryAfter !== "" ? Math.min(30_000, s * 1_000) : 1_000 * 2 ** Math.min(attempt, 3);
}

/** The longest busy wait (before jitter) `Rpc.call` takes when it can hurry. */
export const HURRY_WAIT_MS = 2_000;

// --- JSON-RPC ------------------------------------------------------------------
export class Rpc {
  /**
   * `minGapMs` spaces requests out (public endpoints limit each IP to about
   * 100 requests per 10 s); default 0, or BULKHEAD_RPC_GAP_MS. A rate-limited
   * (429), failing (5xx) or dropped request is retried with backoff; a timeout
   * is not, so a stuck method fails instead of looping. A busy answer that
   * is thrown carries its wait in the error's `waitMs`. With `hurry` (another
   * endpoint can be asked), one whose wait before jitter is over
   * `HURRY_WAIT_MS` is thrown at once, marked `hurried`: a long Retry-After
   * (with `retries` over 2, also the backoff).
   */
  constructor(url, { minGapMs = Number(globalThis.process?.env?.BULKHEAD_RPC_GAP_MS ?? 0), timeoutMs = 30_000, retries = 6, hurry = false } = {}) {
    this.url = url;
    this.minGapMs = minGapMs;
    this.timeoutMs = timeoutMs;
    this.retries = retries;
    this.hurry = hurry;
    this.nextAt = 0;
  }
  async call(method, params = []) {
    for (let attempt = 0; ; attempt++) {
      if (this.minGapMs) {
        const at = Math.max(Date.now(), this.nextAt);
        this.nextAt = at + this.minGapMs;
        if (at > Date.now()) await new Promise((r) => setTimeout(r, at - Date.now()));
      }
      let r;
      try {
        r = await fetch(this.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
          signal: AbortSignal.timeout(this.timeoutMs), // never hang on a stuck endpoint
        });
      } catch (e) {
        // The cause (ECONNREFUSED, ENOTFOUND, ...) is what an operator needs.
        // (A host with several addresses fails with each in `cause.errors`.)
        const code = e.cause?.code ?? e.cause?.errors?.[0]?.code ?? e.cause?.message;
        const cause = code ? ` (${code})` : "";
        if (e.name === "TimeoutError" || attempt >= this.retries) throw new Error(`${method}: ${e.message}${cause}`);
        await new Promise((res) => setTimeout(res, 500 * 2 ** attempt)); // dropped connection: back off
        continue;
      }
      // 429 and 5xx (often an HTML page, not JSON) are transient: back off and retry.
      const busy = r.status === 429 || r.status >= 500;
      const j = busy ? { error: { code: r.status } } : await r.json();
      let waitMs;
      if (busy) {
        const retryAfter = r.headers?.get?.("retry-after");
        waitMs = retryWaitMs(retryAfter, attempt);
        if (attempt < this.retries && (!this.hurry || retryBaseMs(retryAfter, attempt) <= HURRY_WAIT_MS)) {
          await new Promise((res) => setTimeout(res, waitMs));
          continue;
        }
      }
      if (j.error) {
        const err = new Error(`${method}: ${JSON.stringify(j.error)}`);
        err.rpcError = j.error; // { code, message, data }: -32002 is a refused preflight
        err.rpcMethod = method;
        if (waitMs != null) err.waitMs = waitMs; // busy: how long it asked to be left alone
        if (waitMs != null && attempt < this.retries) err.hurried = true; // left before its retry
        throw err;
      }
      return j.result;
    }
  }
  /** Reads at "confirmed" by default: guardians must act on what just happened. */
  async account(k, commitment = "confirmed") {
    const v = (await this.call("getAccountInfo", [b58encode(key(k)), { encoding: "base64", commitment }])).value;
    if (!v) return null;
    return { ...v, bytes: Uint8Array.from(atob(v.data[0]), (c) => c.charCodeAt(0)) };
  }
  async blockhash() {
    return (await this.latestBlockhash()).blockhash;
  }
  /** The blockhash, and the last block height a transaction using it can land at. */
  async latestBlockhash() {
    const { blockhash, lastValidBlockHeight } = (await this.call("getLatestBlockhash", [{ commitment: "confirmed" }])).value;
    return { blockhash, lastValidBlockHeight: lastValidBlockHeight ?? null };
  }
  /**
   * Runs a transaction without signatures (sigVerify off) and returns its
   * result. `accounts` (addresses) come back as they are after the run, e.g.
   * the Clock sysvar, to know the exact time the simulation saw.
   */
  async simulate(feePayer, instructions, accounts = []) {
    const { message, signers } = compileMessage(feePayer, instructions, await this.blockhash());
    const tx = serializeTransaction(message, signers.map(() => new Uint8Array(64)));
    const b64 = btoa(String.fromCharCode(...tx));
    const opts = { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true, commitment: "confirmed" };
    if (accounts.length) opts.accounts = { encoding: "base64", addresses: accounts.map((a) => b58encode(key(a))) };
    return (await this.call("simulateTransaction", [b64, opts])).value;
  }
}

/**
 * JSON-RPC errors that are about the endpoint, not the request: another node
 * may answer. Node unhealthy (-32005), min context slot not reached (-32016),
 * long-term storage unreachable (-32019), and HTTP 429 / 5xx. Also a method
 * this node does not serve: -32010 (getProgramAccounts disabled, or the
 * program excluded from its secondary indexes) and -32601 (method not
 * found). Those used to come back as final answers, so a primary that
 * refused the ticket or change scan kept the guardian from them while a
 * backup would have answered (docs/09, finding 76).
 */
export function endpointTrouble(e) {
  const code = e?.rpcError?.code;
  if (code === undefined) return true; // no answer: refused, dropped, timed out
  return code === -32005 || code === -32016 || code === -32019 || code === -32010 || code === -32601 || code === 429 || (code >= 500 && code < 600);
}

/** Slots a primary may trail the best endpoint before it is switched away from (~60 s). */
export const SLOT_LAG_SWITCH = 150;
/** How long a backup may show a signature the primary does not before the switch. */
export const SIGNATURE_LAG_SWITCH_MS = 30_000;

/**
 * An endpoint's host, for logs: RPC URLs often carry an API key. A URL that
 * does not parse, or has no host ("localhost:8899" reads as a scheme), gives
 * "(endpoint)": the stop's own copy parsed it, and a typo in its primary
 * made it read nothing through good backups (docs/09, finding 121).
 */
export const hostOf = (url) => { try { return new URL(url).host || "(endpoint)"; } catch { return "(endpoint)"; } };

/**
 * Several endpoints behind one `Rpc` interface. Each call goes first to the
 * active endpoint; when it cannot answer (`endpointTrouble`), the next one
 * is tried after at most one quick retry instead of the single endpoint's
 * minute of backoff. A busy endpoint asking for a longer wait (Retry-After)
 * is left at once; if no endpoint answers and one was left that way, the
 * call waits once, until the first busy endpoint's wait ends (30 s at
 * most, 36 s with jitter), and asks it again, so with every endpoint busy
 * calls still slow down as the servers asked. An answer is never retried elsewhere: a
 * refused simulation is the same on every node. `onSwitch(from, to, error,
 * fromAt, toAt)` reports a change of endpoint, with both URLs and indexes:
 * a URL listed twice does not name its entry.
 *
 * With `genesis`, an endpoint is used only once its genesis hash has matched
 * it, asked before its first use and again before each cross-check until it
 * answers. One on another cluster is never used. The guardian checked only
 * the active endpoint, and a failover or a cross-check could move it onto a
 * backup on another cluster, blind (docs/09, finding 114).
 * `onCluster(url, genesis, at)` reports each endpoint's hash when first learned.
 */
export class FailoverRpc extends Rpc {
  constructor(urls, { onSwitch = () => {}, genesis = null, onCluster = () => {}, timeoutMs = 10_000, retries = 1, ...opts } = {}) {
    super(urls[0], { timeoutMs, retries, ...opts });
    // Each endpoint hurries: a busy one asking for a long wait is left at
    // once, here and in crossCheck, which the guardian's loop waits for.
    this.endpoints = urls.map((url) => new Rpc(url, { timeoutMs, retries, ...opts, hurry: true }));
    this.active = 0;
    this.switches = 0; // moves of `active`, so a call can tell its evidence is older
    this.restartWaits();
    this.onSwitch = onSwitch;
    this.genesis = genesis;
    this.onCluster = onCluster;
    this.cluster = urls.map(() => (genesis == null ? "ok" : "unknown")); // "ok", "unknown" or "wrong"
    this.asking = urls.map(() => null); // a genesis ask in flight
  }
  /**
   * Whether endpoint `at` may be used: an unchecked one is asked for its
   * genesis hash first, once for all the calls waiting on it. If it cannot
   * answer, throws an error that sends the call on to the next endpoint.
   */
  async admit(at) {
    if (this.cluster[at] !== "unknown") return this.cluster[at] === "ok";
    this.asking[at] ??= this.askGenesis(at).finally(() => { this.asking[at] = null; });
    await this.asking[at];
    return this.cluster[at] === "ok";
  }
  /**
   * Any failure to give a hash, a refusal included, is no answer: the error
   * keeps a busy endpoint's wait but not its JSON-RPC code, so call() goes on.
   */
  async askGenesis(at) {
    let got;
    try {
      got = await this.endpoints[at].call("getGenesisHash", []);
    } catch (e) {
      throw Object.assign(new Error(e.message), { waitMs: e.waitMs, hurried: e.hurried });
    }
    if (typeof got !== "string") throw new Error("getGenesisHash: no hash");
    this.cluster[at] = got === this.genesis ? "ok" : "wrong";
    this.report("onCluster", this.endpoints[at].url, got, at);
  }
  /**
   * Per endpoint index, the signatures crossCheck found missing from lists
   * asked of it while it was active: signature -> { at: first seen missing,
   * from: the backup that had it, slot }. Kept while another endpoint is
   * active, and pruned only when this one is again.
   */
  restartWaits() {
    this.missing = [];
  }
  /**
   * Calls a report hook (`onSwitch`, `onCluster`; synchronous). One that
   * throws is passed over, with a line on stderr: it ran inside call()'s
   * try, so the endpoint that had just answered read as failing, its answer
   * was dropped, and the request, a transaction too, went on to the next
   * endpoint (docs/09, finding 121).
   */
  report(hook, ...args) {
    try {
      this[hook](...args);
    } catch (e) {
      // A log line's own failure says nothing about the endpoint. Nor may
      // the trace's: String() of some thrown values throws too.
      try {
        console.error(`FailoverRpc: ${hook} threw: ${String(e?.message || e).slice(0, 160)}`);
      } catch {
        // nothing more to say
      }
    }
  }
  /** Make endpoint `at` the one asked first, and say so (`onSwitch`). */
  switchTo(at, cause) {
    if (at === this.active) return;
    this.report("onSwitch", this.endpoints[this.active].url, this.endpoints[at].url, cause, this.active, at);
    this.active = at;
    this.switches++;
    this.url = this.endpoints[at].url;
  }

  /**
   * Failover moves only when an endpoint fails to answer. A node that answers
   * successfully but stale (behind on slots, or missing the newest
   * transactions on an account) kept the guardian blind while its backups
   * were current (docs/09, finding 76). This cross-check, run periodically,
   * asks every endpoint for its slot, and every backup for the newest
   * signature on `address`:
   *   - the active endpoint more than `slotLag` slots behind the best: switch
   *     to the best;
   *   - a backup's newest signature that the active endpoint does not list
   *     among its newest `depth` for more than `sigLagMs`: switch to that backup.
   * What each endpoint was found missing is kept per endpoint, and judged
   * only while it is active: a call() failover neither hands the old
   * primary's wait to the new one nor restarts the wait of an endpoint it
   * returns to. A switch by this check starts every wait again.
   * Returns `{ switched, reason, slots }`. An endpoint that does not answer,
   * or is busy and asks for more than `HURRY_WAIT_MS`, is skipped here (the
   * failover handles that): the guardian's loop waits for this check.
   */
  async crossCheck(address, { slotLag = SLOT_LAG_SWITCH, sigLagMs = SIGNATURE_LAG_SWITCH_MS, depth = 100, nowMs = Date.now() } = {}) {
    const quiet = (p) => p.then((v) => v, () => undefined);
    const slots = await Promise.all(this.endpoints.map((e, i) => quiet(this.admit(i).then((ok) => (ok ? e.call("getSlot", [{ commitment: "confirmed" }]) : undefined)))));
    const active = this.active;
    let best = active;
    for (let i = 0; i < slots.length; i++) if (slots[i] != null && (slots[best] == null || slots[i] > slots[best])) best = i;
    if (slots[best] != null && slots[active] != null && slots[best] - slots[active] > slotLag) {
      const reason = `RPC endpoint is behind: ${slots[best] - slots[active]} slots behind the best of ${this.endpoints.length} endpoints`;
      this.switchTo(best, new Error(reason));
      this.restartWaits();
      return { switched: true, reason, slots };
    }
    if (this.endpoints.length < 2) return { switched: false, reason: null, slots };
    const q = (limit) => [address, { limit, commitment: "confirmed" }];
    const [mine, ...theirs] = await Promise.all([
      quiet(this.endpoints[active].call("getSignaturesForAddress", q(depth))),
      ...this.endpoints.map((e, i) => (i === active || this.cluster[i] !== "ok" ? Promise.resolve(undefined) : quiet(e.call("getSignaturesForAddress", q(1))))),
    ]);
    if (!mine) return { switched: false, reason: null, slots };
    const missing = (this.missing[active] ??= new Map());
    const listed = new Set(mine.map((x) => x.signature));
    theirs.forEach((list, i) => {
      const row = list?.[0];
      if (i !== active && row?.signature && !listed.has(row.signature) && !missing.has(row.signature)) missing.set(row.signature, { at: nowMs, from: i, slot: row.slot ?? null });
    });
    // Judged on the list ingestion reads (`getSignaturesForAddress`), by slot:
    // a candidate older than the oldest of a full newest-`depth` list has
    // been pushed out of it by newer transactions (a busy protocol), and is
    // there. Membership alone switched endpoints every few minutes on a busy
    // protocol; asking the status cache instead missed a primary whose
    // address index lags while its status cache is current (docs/09,
    // findings 81 and 84).
    const oldestListed = mine.length >= depth ? mine.at(-1)?.slot : null;
    for (const [sig, m] of missing) if (oldestListed != null && m.slot != null && m.slot < oldestListed) listed.add(sig);
    for (const [sig, m] of missing) {
      if (listed.has(sig) || nowMs - m.at > 600_000) {
        missing.delete(sig);
      } else if (nowMs - m.at > sigLagMs && this.active === active) {
        // Only if `active` is still the endpoint these lists judged: a
        // call() may have failed over while they were in flight.
        const reason = `RPC endpoint is missing recent transactions: a backup has had ${sig} for ${Math.round((nowMs - m.at) / 1000)}s and the primary does not return it`;
        this.switchTo(m.from, new Error(reason));
        this.restartWaits();
        return { switched: true, reason, slots };
      }
    }
    return { switched: false, reason: null, slots };
  }

  /**
   * Ask the active endpoint, then each other one in turn. The order is fixed
   * when the call starts: calls overlap (a sweep sends several at once), and
   * one that re-read `active` after another had moved it retried the dead
   * endpoint and never asked the live one. A call moves `active` to the
   * endpoint that answered only if the active endpoint failed a request this
   * call sent after the last move: older evidence would undo a newer call's
   * move (a slow answer from the old endpoint, or a request sent before
   * another call's switch). The switch reports that endpoint's error.
   */
  async call(method, params = []) {
    const start = this.active;
    const order = this.endpoints.map((_, i) => (start + i) % this.endpoints.length);
    const failedAt = new Map(); // endpoint -> { sentAt: this.switches when sent, error }
    let last;
    let soonest = null; // the busy endpoint whose wait ends first: { at, readyAt }
    let hurried = false; // some endpoint was left before its wait
    let rested = false;
    for (let i = 0; i < order.length; i++) {
      const at = order[i];
      const sentAt = this.switches;
      try {
        if (await this.admit(at)) {
          const result = await this.endpoints[at].call(method, params);
          const evidence = failedAt.get(this.active);
          if (evidence?.sentAt === this.switches) this.switchTo(at, evidence.error);
          else if (this.cluster[this.active] === "wrong") this.switchTo(at, new Error("RPC endpoint serves another cluster"));
          return result;
        }
      } catch (e) {
        if (!endpointTrouble(e)) throw e;
        failedAt.set(at, { sentAt, error: e });
        last = e;
        hurried ||= e.hurried === true;
        const readyAt = e.waitMs != null ? Date.now() + e.waitMs : null;
        if (readyAt != null && (soonest == null || readyAt < soonest.readyAt)) soonest = { at, readyAt };
      }
      if (i === order.length - 1 && hurried && !rested) {
        rested = true; // once: then the last error stands
        await new Promise((res) => setTimeout(res, Math.max(0, soonest.readyAt - Date.now())));
        order.push(soonest.at);
      }
    }
    throw last ?? new Error(`${method}: no RPC endpoint on the expected cluster`);
  }
}

// --- Bulkhead account decoders ----------------------------------------------
/** Keys a new guardian set needs beyond its threshold: core governance.rs
 * GUARDIAN_MARGIN (finding 107). A stored set is not checked again. */
export const GUARDIAN_MARGIN = 2;
/** The most keys a guardian set can have: core governance.rs MAX_GUARDIANS. */
export const MAX_GUARDIANS = 8;

/** Why a guardian set breaks the margin rule (finding 107), or null. */
export function guardianMarginProblem(count, threshold) {
  const need = threshold + GUARDIAN_MARGIN;
  return count >= need ? null : `${threshold}-of-${count}: a new set needs at least ${need} keys (finding 107)`;
}
const text = (b) => new TextDecoder().decode(b);

export function decodeProtocol(d) {
  if (text(d.slice(0, 8)) !== "BHPROTv1") throw new Error("not a Bulkhead protocol account");
  const r = new Reader(d, 8);
  const p = { protocolProgram: b58encode(r.key()), caller: b58encode(r.key()), admin: b58encode(r.key()) };
  const guardians = [];
  for (let i = 0; i < 8; i++) guardians.push(b58encode(r.key()));
  const heartbeats = [];
  for (let i = 0; i < 8; i++) heartbeats.push(Number(r.i64()));
  const count = r.u8();
  Object.assign(p, {
    guardians: guardians.slice(0, count),
    lastHeartbeat: heartbeats.slice(0, count),
    threshold: r.u8(),
    sealed: r.u8() === 1,
    bump: r.u8(),
    heartbeatIntervalS: Number(r.i64()),
    loosenDelayS: Number(r.i64()),
    frozenUntil: Number(r.i64()),
    abdications: r.u32(),
    vaultCount: r.u32(),
    nextTicketId: r.u64(),
    nextChangeId: r.u64(),
    lifeboatDestination: b58encode(r.key()),
    destinationSetS: Number(r.i64()),
    sealExecutableS: Number(r.i64()), // 0 until the seal is proposed
    sealExpiresS: Number(r.i64()),
    sealVetoed: r.u8() === 1,
  });
  // Change-version counters, then the recovery key (all zero: none), both in
  // what older builds left as padding.
  if (d.length >= r.o + 4 * 5 + 32) {
    p.versions = [r.u32(), r.u32(), r.u32(), r.u32(), r.u32()];
    const recovery = r.key();
    p.recovery = recovery.every((b) => b === 0) ? null : b58encode(recovery);
  }
  return p;
}

export function decodeVault(d) {
  if (text(d.slice(0, 8)) !== "BHVAULT1") throw new Error("not a Bulkhead vault account");
  const r = new Reader(d, 8);
  const v = { protocol: b58encode(r.key()), mint: b58encode(r.key()), tokenProgram: b58encode(r.key()), tokenAccount: b58encode(r.key()) };
  v.limits = { shortBps: r.u16(), shortWindowS: r.u32(), longBps: r.u16(), longWindowS: r.u32(), minQueueDelayS: r.u32(), shortFloor: r.u64(), longFloor: r.u64(), shortCap: r.u64(), longCap: r.u64() };
  Object.assign(v, {
    tatShortMs: r.i64(),
    tatLongMs: r.i64(),
    refBalance: r.u64(),
    refUpdatedS: Number(r.i64()),
    refInitialized: r.u8() === 1,
    decimals: r.u8(),
    bump: r.u8(),
    tokenBump: r.u8(),
    pendingTickets: r.u32(),
    queuedAmount: r.u64(),
    frozenUntil: Number(r.i64()),
    imported: r.u64(),
    totalIn: r.u128(),
    backedOut: r.u128(),
    unbackedOut: r.u128(),
    settled: r.u128(),
    cancelled: r.u128(),
  });
  // The lifeboat and its pending exit (an account written by an older build
  // may stop before them).
  if (d.length >= r.o + 8 + 8 + 24 + 1) {
    Object.assign(v, {
      lifeboatAmount: r.u64(),
      exitAmount: r.u64(),
      exitProposedS: Number(r.i64()),
      exitExecutableS: Number(r.i64()),
      exitExpiresS: Number(r.i64()),
      exitVetoed: r.u8() === 1,
    });
    // The limits' change-version counter (older builds: padding, so 0).
    if (d.length >= r.o + 4) v.limitsVersion = r.u32();
    // The low-water balance (finding 65; older builds: zero padding, which
    // the program's first touch replaces since its window is long past).
    if (d.length >= r.o + 24) {
      v.low = { prev: r.u64(), cur: r.u64(), window: r.i64() };
      // Who proposed the pending exit (finding 91; older builds: zeros).
      if (d.length >= r.o + 32) v.exitProposer = b58encode(r.key());
    }
  }
  return v;
}

/** A Vault `Change` account (programs/vault/src/state.rs): a proposed loosening. */
export function decodeChange(d) {
  if (d.length < 448 || text(d.slice(0, 8)) !== "BHCHNG01") throw new Error("not a Bulkhead change account");
  const r = new Reader(d, 8);
  const c = { protocol: b58encode(r.key()), id: r.u64(), kind: r.u8(), vetoed: r.u8() === 1, executed: r.u8() === 1 };
  r.u8(); // bump
  Object.assign(c, {
    target: b58encode(r.key()),
    proposer: b58encode(r.key()),
    createdS: Number(r.i64()),
    executableS: Number(r.i64()),
    expiresS: Number(r.i64()),
  });
  const len = r.u16();
  if (len > 300) throw new Error("malformed change account: payload longer than 300 bytes");
  c.payload = d.slice(r.o, r.o + len);
  r.o += 300;
  c.baseVersion = r.u32();
  return c;
}

/** The change-version counter of a Vault `Asset` account (`["asset", protocol, mint]`). */
export function assetVersion(d) {
  if (text(d.slice(0, 8)) !== "BHASSET1") throw new Error("not a Bulkhead asset account");
  return new DataView(d.buffer, d.byteOffset, d.byteLength).getUint32(8 + 64 + 53 + 2, true);
}

export function decodeFloor(d) {
  if (text(d.slice(0, 8)) !== "FLOORv01") throw new Error("not a Floor config");
  const at = (o) => d.slice(o, o + 32);
  const i64 = (o) => Number(new DataView(d.buffer, d.byteOffset + o, 8).getBigInt64(0, true));
  const count = d[424];
  const guardians = [];
  for (let i = 0; i < count; i++) guardians.push(b58encode(at(104 + 32 * i)));
  const zero = (k) => k.every((x) => x === 0);
  return {
    program: b58encode(at(8)),
    programdata: b58encode(at(40)),
    owner: b58encode(at(72)),
    guardians,
    lastHeartbeat: guardians.map((_, i) => i64(360 + 8 * i)),
    threshold: d[425],
    status: d[426] === 0 ? "live" : "aborted",
    elfIsV3: d[427] === 1,
    snapshotValid: d[430] === 1,
    heartbeatIntervalS: i64(432),
    upgradeDelayS: i64(440),
    abortStaged: !zero(at(448)),
    snapshotPinned: !zero(at(480)),
    abortBuffer: zero(at(448)) ? null : b58encode(at(448)),
    snapshotBuffer: zero(at(480)) ? null : b58encode(at(480)),
    pendingKind: d[520],
    pendingVetoed: d[521] === 1,
    pendingId: new DataView(d.buffer, d.byteOffset + 528, 8).getBigUint64(0, true),
    pendingTarget: b58encode(at(536)),
    pendingEta: i64(568),
    pendingExpires: i64(576),
    pendingPayload: d.slice(586, 586 + Math.min(266, new DataView(d.buffer, d.byteOffset + 584, 2).getUint16(0, true))),
  };
}

/** The 64-byte `attest` return data (programs/vault/src/views.rs). */
export function decodeAttestation(bytes) {
  const r = new Reader(bytes);
  return {
    availableNow: r.u64(),
    worst1h: r.u64(),
    worst24h: r.u64(),
    balance: r.u64(),
    frozenUntil: Number(r.i64()),
    queued: r.u64(),
    loosenDelayS: Number(r.i64()),
    pendingTickets: r.u32(),
    liveGuardians: r.u8(),
    guardianCount: r.u8(),
    sealed: r.u8() === 1,
  };
}

/**
 * Structured events from a transaction's log messages, each attributed to the
 * program that emitted it, and whether the runtime truncated the log.
 *
 * Any program can write a "Program data:" line, so a line only means something
 * when it was emitted inside an invocation of the program you trust. The
 * runtime brackets every invocation with "Program <id> invoke [n]" and
 * "Program <id> success" (or "failed"); the line belongs to the innermost open
 * one. Logs are capped (10,000 bytes per transaction); past the cap the
 * runtime writes "Log truncated" and drops the rest, so a truncated log can't
 * be read as complete.
 */
export function parseLogs(logs) {
  // No log at all (a node that stores none, `logMessages: null`) is not an
  // empty log: whatever ran is unknown, so it reads as truncated and the
  // caller falls back to the balances.
  if (!Array.isArray(logs)) return { events: [], truncated: true };
  const events = [];
  const stack = [];
  let truncated = false;
  for (const line of logs) {
    if (line === "Log truncated") {
      truncated = true;
      continue;
    }
    let m = /^Program (\S+) invoke \[\d+\]$/.exec(line);
    if (m) {
      stack.push(m[1]);
      continue;
    }
    m = /^Program (\S+) (success|failed.*)$/.exec(line);
    if (m && stack[stack.length - 1] === m[1]) {
      stack.pop();
      continue;
    }
    m = /^Program data: (.*)$/.exec(line);
    if (!m) continue;
    let fields;
    try {
      fields = m[1].split(" ").map((b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0)));
    } catch {
      continue; // not base64: nobody's event
    }
    events.push({ program: stack[stack.length - 1] ?? null, name: text(fields[0]), fields: fields.slice(1) });
  }
  return { events, truncated };
}

/** Events emitted by one of `programs` (base58 ids); all events if none given. */
export function parseEvents(logs, programs = null) {
  const { events } = parseLogs(logs);
  return programs ? events.filter((e) => programs.includes(e.program)) : events;
}

/** A Vault `Ticket` account (programs/vault/src/state.rs). */
export function decodeTicket(d) {
  if (text(d.slice(0, 8)) !== "BHTICKT1") throw new Error("not a Bulkhead ticket account");
  const r = new Reader(d, 8);
  return {
    protocol: b58encode(r.key()),
    vault: b58encode(r.key()),
    recipient: b58encode(r.key()),
    recipientOwner: b58encode(r.key()),
    payer: b58encode(r.key()),
    id: r.u64(),
    amount: r.u64(),
    createdS: Number(r.i64()),
    etaS: Number(r.i64()),
  };
}
