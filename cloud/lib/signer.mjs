// Ed25519 signing with Node's built-in crypto (no dependencies).
// Keys are standard Solana keypair files: a JSON array of 64 bytes
// (32-byte seed, then the 32-byte public key).

import { createPrivateKey, createPublicKey, sign as edSign, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, statSync, chmodSync } from "node:fs";
import { b58encode, compileMessage, serializeTransaction, key, concat, u64le } from "./solana.mjs";

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

export class Keypair {
  constructor(seed) {
    this.seed = Buffer.from(seed);
    this.privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, this.seed]), format: "der", type: "pkcs8" });
    const spki = createPublicKey(this.privateKey).export({ format: "der", type: "spki" });
    this.publicKey = Uint8Array.from(spki.subarray(spki.length - 32));
  }
  static generate() {
    return new Keypair(randomBytes(32));
  }
  /** Refuses a key file the group or others may read or write: a guardian or
   * admin key anyone on the host can copy is not a key the protocol holds. */
  static load(path) {
    const mode = statSync(path).mode;
    if (process.platform !== "win32" && (mode & 0o077) !== 0) {
      throw new Error(`${path}: key file is open to group or others (mode ${(mode & 0o777).toString(8)}); run chmod 600 ${path}`);
    }
    let bytes;
    try {
      bytes = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      // Never the parser's message: it quotes the file, i.e. key bytes.
      throw new Error(`${path}: not a keypair file (a JSON array of 64 bytes)`);
    }
    if (!Array.isArray(bytes) || bytes.length < 32) throw new Error(`${path}: not a keypair file (a JSON array of 64 bytes)`);
    const kp = new Keypair(Uint8Array.from(bytes.slice(0, 32)));
    if (bytes.length === 64 && b58encode(Uint8Array.from(bytes.slice(32))) !== kp.address) {
      throw new Error(`${path}: public key does not match the seed`);
    }
    return kp;
  }
  save(path) {
    writeFileSync(path, JSON.stringify([...this.seed, ...this.publicKey]), { mode: 0o600 }); // owner-only, like solana-keygen
    chmodSync(path, 0o600); // the mode above applies only to a new file
  }
  get address() {
    return b58encode(this.publicKey);
  }
  sign(message) {
    return Uint8Array.from(edSign(null, Buffer.from(message), this.privateKey));
  }
}

export const COMPUTE_BUDGET = key("ComputeBudget111111111111111111111111111111");

/**
 * `SetComputeUnitLimit(units)` and, when `microLamports` > 0,
 * `SetComputeUnitPrice(microLamports)`: the priority fee is units × price.
 */
export function computeBudget(units, microLamports = 0) {
  const limit = new Uint8Array(5);
  limit[0] = 2;
  new DataView(limit.buffer).setUint32(1, units, true);
  const ixs = [{ programId: COMPUTE_BUDGET, accounts: [], data: limit }];
  if (microLamports > 0) ixs.push({ programId: COMPUTE_BUDGET, accounts: [], data: concat(Uint8Array.of(3), u64le(microLamports)) });
  return ixs;
}

/**
 * A priority price from `getRecentPrioritizationFees` results: the
 * `percentile` of the non-zero fees paid recently on the accounts involved,
 * never above `cap` (micro-lamports per compute unit). 0 when nobody paid.
 */
export function priorityPrice(fees, { percentile = 0.9, cap = 1_000_000 } = {}) {
  const paid = (fees ?? []).map((f) => Number(f.prioritizationFee)).filter((x) => x > 0).sort((a, b) => a - b);
  if (!paid.length) return 0;
  const i = Math.min(paid.length - 1, Math.ceil(percentile * paid.length) - 1);
  return Math.min(cap, paid[Math.max(0, i)]);
}

/**
 * Builds, signs and sends a transaction; returns its signature once confirmed.
 * `computeUnits` adds a compute-budget limit (and `microLamports` a priority
 * price); `rpcs` are extra endpoints the same signed transaction is also sent
 * to, so one slow or censoring endpoint doesn't delay it.
 *
 * Until it confirms, the same signed bytes go out again every `rebroadcastMs`
 * to every endpoint: a leader that dropped the first copy (congestion, a
 * fork) gets another, as wallets do. Sent once, a freeze under load could sit
 * out the whole minute and never land. Once the blockhash has expired it can
 * never land, and that is said at once.
 */
export async function send(rpc, payer, instructions, extraSigners = [], { skipPreflight = false, computeUnits = 0, microLamports = 0, rpcs = [], pollMs = 500, rebroadcastMs = 2_000, confirmMs = 60_000 } = {}) {
  const ixs = computeUnits > 0 ? [...computeBudget(computeUnits, microLamports), ...instructions] : instructions;
  const latest = rpc.latestBlockhash ? await rpc.latestBlockhash() : { blockhash: await rpc.blockhash(), lastValidBlockHeight: null };
  const { message, signers } = compileMessage(payer.publicKey, ixs, latest.blockhash);
  const all = [payer, ...extraSigners];
  const sigs = signers.map((k) => {
    const kp = all.find((s) => b58encode(s.publicKey) === b58encode(k));
    if (!kp) throw new Error(`missing signer ${b58encode(k)}`);
    return kp.sign(message);
  });
  const tx = Buffer.from(serializeTransaction(message, sigs)).toString("base64");
  const opts = { encoding: "base64", skipPreflight, preflightCommitment: "confirmed" };
  // Backups go out first and are never awaited: they still carry the
  // transaction when the primary's send fails, and a hanging one cannot delay
  // confirmation. The primary decides.
  void Promise.allSettled(rpcs.map(async (r) => r.call("sendTransaction", [tx, { ...opts, skipPreflight: true }])));
  let signature;
  try {
    signature = await rpc.call("sendTransaction", [tx, opts]);
  } catch (e) {
    // The transaction's own signature (its first): a backup may still land it.
    e.signature = b58encode(sigs[0]);
    // A backup carried it first and the primary's preflight saw it done: that
    // is the outcome wanted, not a refusal. It was reported as a failed send
    // (an error alert) and retried (docs/09, finding 82).
    if (e.rpcError?.data?.err !== "AlreadyProcessed") throw e;
    signature = e.signature;
  }
  // One failed poll is not an answer: the transaction may still land, and
  // giving up on it here sent a second one later (docs/09, finding 82).
  const status = async () => {
    let st;
    try {
      st = (await rpc.call("getSignatureStatuses", [[signature]])).value?.[0];
    } catch {
      return false;
    }
    if (st?.err) throw Object.assign(new Error(`transaction ${signature} failed: ${JSON.stringify(st.err)}`), { signature, onChainErr: st.err });
    return Boolean(st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized"));
  };
  const again = () => {
    for (const r of [rpc, ...rpcs]) void Promise.resolve().then(() => r.call("sendTransaction", [tx, { ...opts, skipPreflight: true }])).catch(() => {});
  };
  const started = Date.now();
  let sentAt = started;
  for (;;) {
    if (await status()) return signature;
    if (Date.now() - started >= confirmMs) break;
    if (Date.now() - sentAt >= rebroadcastMs) {
      sentAt = Date.now();
      if (latest.lastValidBlockHeight != null) {
        const height = await rpc.call("getBlockHeight", [{ commitment: "confirmed" }]).catch(() => null);
        if (height != null && height > latest.lastValidBlockHeight) {
          if (await status()) return signature;
          throw Object.assign(new Error(`transaction ${signature} expired unconfirmed (its blockhash is no longer valid)`), { signature, expired: true });
        }
      }
      again();
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  throw Object.assign(new Error(`transaction ${signature} not confirmed`), { signature });
}

/**
 * Why a node refused a budgeted transaction in simulation:
 *   "blockhash":    a node behind the blockhash (a load-balanced pool, a
 *                   failover between the blockhash and the send). It used to
 *                   be taken for a budget refusal and resent without any
 *                   priority, at the worst moment (docs/09, finding 82);
 *   "instructions": one of the transaction's own instructions failed (not out
 *                   of compute): dropping the budget changes nothing;
 *   "budget":       anything else, as finding 47 (a mistyped Compute Budget id
 *                   failed every freeze in simulation).
 */
export function refusalCause(e, budgetInstructions = 2) {
  const err = e?.rpcError?.data?.err;
  if (err === "BlockhashNotFound") return "blockhash";
  const ie = err?.InstructionError;
  if (Array.isArray(ie) && ie[0] >= budgetInstructions && ie[1] !== "ComputationalBudgetExceeded") return "instructions";
  return "budget";
}

/** JSON-RPC code for "Transaction simulation failed": the node refused it before it ran. */
export const PREFLIGHT_REFUSED = -32002;

/**
 * `send`, but a compute budget can never be what stops the transaction. If a
 * node refuses it in simulation, the same instructions go once more without
 * the budget, and `onFallback(error)` is told. The budget only buys priority
 * under load. On 1 Oct on devnet, a mistyped Compute Budget id made every
 * guardian freeze fail simulation for 5½ minutes while an attack was queued
 * (`docs/09`, finding 47). When the instructions themselves are refused (a
 * stale guardian, say) the second attempt fails too, and its error is thrown.
 */
export async function sendWithFallback(rpc, payer, instructions, extraSigners = [], opts = {}, onFallback = () => {}) {
  try {
    return await send(rpc, payer, instructions, extraSigners, opts);
  } catch (first) {
    let e = first;
    if (!(opts.computeUnits > 0) || e.rpcError?.code !== PREFLIGHT_REFUSED) throw e;
    const budgetIxs = opts.microLamports > 0 ? 2 : 1;
    if (refusalCause(e, budgetIxs) === "blockhash") {
      // Signed again with a fresh blockhash, budget kept.
      try {
        return await send(rpc, payer, instructions, extraSigners, opts);
      } catch (again) {
        if (!(again.rpcError?.code === PREFLIGHT_REFUSED)) throw again;
        e = again;
      }
    }
    if (refusalCause(e, budgetIxs) === "instructions") throw e;
    // The backups were sent the same transaction without a preflight: if one
    // landed it, that is the answer. A second transaction would freeze twice,
    // or fail as a duplicate veto and be reported as a failure.
    // One that landed with an error (out of compute, say: the very budget the
    // fallback drops) did nothing, so it is no answer: fall back. It used to
    // throw here, and the fallback finding 47 added never ran.
    if (opts.rpcs?.length && e.signature) {
      const landed = await landedBy(rpc, e.signature, opts.landedWaitMs ?? 2_000);
      if (landed === "confirmed") return e.signature;
    }
    const signature = await send(rpc, payer, instructions, extraSigners, { ...opts, computeUnits: 0, microLamports: 0 });
    onFallback(e);
    return signature;
  }
}

/** Whether `signature` "confirmed", "failed" (landed with an error), or did not show up within `waitMs` (null). */
async function landedBy(rpc, signature, waitMs) {
  const until = Date.now() + waitMs;
  for (;;) {
    let st = null;
    try {
      st = (await rpc.call("getSignatureStatuses", [[signature], { searchTransactionHistory: false }])).value?.[0];
    } catch {
      st = null;
    }
    if (st?.err) return "failed";
    if (st && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized")) return "confirmed";
    if (Date.now() >= until) return null;
    await new Promise((r) => setTimeout(r, 400));
  }
}

export { key };

/**
 * A transaction that has to land now (a freeze): sent without preflight to
 * every endpoint, rebroadcast every `rebroadcastMs`, and given `attemptMs` to
 * confirm. Each attempt that does not is signed again with a fresh blockhash
 * at twice the price (from `price`, at least `floor`, at most `cap`), until
 * `deadlineMs`. `settled()` is asked between attempts (has the outcome already
 * happened, by an earlier attempt or by someone else?), and so are the earlier
 * attempts' signatures, since one can still land. `send`'s single signed copy
 * sat out a minute at one price: under congestion a freeze never got a better
 * slot (docs/09, finding 82). An attempt that lands with an error in its
 * compute budget (finding 47) is retried without one.
 * Returns `{ signature, attempts, price }`; `signature` is null when
 * `settled()` said so first.
 */
export async function sendEscalating(rpc, payer, instructions, { computeUnits = 50_000, price = 0, floor = 0, cap = 1_000_000, rpcs = [], attemptMs = 6_000, rebroadcastMs = 400, pollMs = 400, deadlineMs = 90_000, settled = async () => false, onAttempt = () => {}, onFallback = () => {} } = {}) {
  const started = Date.now();
  let p = Math.min(cap, Math.max(floor, price));
  let units = computeUnits;
  const sent = [];
  for (let attempt = 1; ; attempt++) {
    try {
      const signature = await send(rpc, payer, instructions, [], { skipPreflight: true, computeUnits: units, microLamports: units > 0 ? p : 0, rpcs, rebroadcastMs, pollMs, confirmMs: attemptMs });
      return { signature, attempts: attempt, price: p };
    } catch (e) {
      if (e.signature) sent.push(e.signature);
      const ie = e.onChainErr?.InstructionError;
      if (e.onChainErr) {
        // It ran and failed: only a refused budget is worth another try.
        if (!(units > 0 && Array.isArray(ie) && (ie[0] < (p > 0 ? 2 : 1) || ie[1] === "ComputationalBudgetExceeded"))) throw e;
        units = 0;
        onFallback(e);
      }
      const landed = sent.length ? await rpc.call("getSignatureStatuses", [sent, { searchTransactionHistory: false }]).catch(() => null) : null;
      const ok = landed?.value?.findIndex((st) => st && !st.err && (st.confirmationStatus === "confirmed" || st.confirmationStatus === "finalized"));
      if (ok != null && ok >= 0) return { signature: sent[ok], attempts: attempt, price: p };
      if (await settled().catch(() => false)) return { signature: null, attempts: attempt, price: p };
      if (Date.now() - started >= deadlineMs) throw e;
      p = Math.min(cap, Math.max(p * 2, floor, 1));
      onAttempt({ attempt, error: e, nextPrice: p });
    }
  }
}
