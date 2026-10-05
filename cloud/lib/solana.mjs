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
  y &= (1n << 255n) - 1n;
  if (y >= P) return false;
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

// --- JSON-RPC ------------------------------------------------------------------
export class Rpc {
  /**
   * `minGapMs` spaces requests out (public endpoints limit each IP to about
   * 100 requests per 10 s); default 0, or BULKHEAD_RPC_GAP_MS. A rate-limited
   * (429), failing (5xx) or dropped request is retried with backoff; a timeout
   * is not, so a stuck method fails instead of looping.
   */
  constructor(url, { minGapMs = Number(globalThis.process?.env?.BULKHEAD_RPC_GAP_MS ?? 0), timeoutMs = 30_000 } = {}) {
    this.url = url;
    this.minGapMs = minGapMs;
    this.timeoutMs = timeoutMs;
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
        if (e.name === "TimeoutError" || attempt >= 6) throw new Error(`${method}: ${e.message}`);
        await new Promise((res) => setTimeout(res, 500 * 2 ** attempt)); // dropped connection: back off
        continue;
      }
      // 429 and 5xx (often an HTML page, not JSON) are transient: back off and retry.
      const busy = r.status === 429 || r.status >= 500;
      const j = busy ? { error: { code: r.status } } : await r.json();
      if (busy && attempt < 6) {
        await new Promise((res) => setTimeout(res, 1_000 * 2 ** Math.min(attempt, 3)));
        continue;
      }
      if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
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
    return (await this.call("getLatestBlockhash", [{ commitment: "confirmed" }])).value.blockhash;
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

// --- Bulkhead account decoders ----------------------------------------------
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
  }
  return v;
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
    pendingKind: d[520],
    pendingVetoed: d[521] === 1,
    pendingId: new DataView(d.buffer, d.byteOffset + 528, 8).getBigUint64(0, true),
    pendingTarget: b58encode(at(536)),
    pendingEta: i64(568),
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
  const events = [];
  const stack = [];
  let truncated = false;
  for (const line of logs ?? []) {
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
