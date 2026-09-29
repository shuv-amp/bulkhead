// The worst-case figures from raw account data, for pages that hold no key
// (simulating `attest` needs a funded fee payer). A JavaScript statement of
// four core functions (crates/bulkhead-core/src/{ema,limiter}.rs), checked
// against the Python reference on random edge cases (cloud/test/limits.test.mjs)
// and against the program's own `attest` in the end-to-end run.
// All arithmetic is BigInt: the core uses u64/u128/i64.

const U64_MAX = (1n << 64n) - 1n;
const BPS = 10_000n;
const TAU_S = 86_400n;
const QUEUE_HORIZON_S = 604_800n;

export function emaUpdate(reference, lastS, balance, nowS, initialized) {
  if (!initialized) return BigInt(balance);
  const ref = BigInt(reference);
  const bal = BigInt(balance);
  let dt = BigInt(nowS) - BigInt(lastS);
  if (dt < 0n) dt = 0n;
  const f = dt < TAU_S ? dt : TAU_S;
  return bal >= ref ? ref + ((bal - ref) * f) / TAU_S : ref - ((ref - bal) * f) / TAU_S;
}

export function capacityFromRef(reference, bps, floor, cap) {
  let c = (BigInt(reference) * BigInt(bps)) / BPS;
  if (c > U64_MAX) c = U64_MAX;
  if (c < BigInt(floor)) c = BigInt(floor);
  if (BigInt(cap) > 0n && c > BigInt(cap)) c = BigInt(cap);
  return c;
}

export function paramsFromConfig(limits, reference) {
  return {
    short: { capacity: capacityFromRef(reference, limits.shortBps, limits.shortFloor, limits.shortCap), windowMs: BigInt(limits.shortWindowS) * 1000n },
    long: { capacity: capacityFromRef(reference, limits.longBps, limits.longFloor, limits.longCap), windowMs: BigInt(limits.longWindowS) * 1000n },
    minQueueDelayMs: BigInt(limits.minQueueDelayS) * 1000n,
    horizonMs: QUEUE_HORIZON_S * 1000n,
  };
}

export function availableNow(tatShortMs, tatLongMs, params, nowMs) {
  const now = BigInt(nowMs);
  const one = (tat, b) => {
    const t = BigInt(tat);
    const backlog = (t > now ? t : now) - now;
    const room = b.windowMs - backlog;
    return room <= 0n ? 0n : (room * b.capacity) / b.windowMs;
  };
  const a = [one(tatShortMs, params.short), one(tatLongMs, params.long)].reduce((x, y) => (x < y ? x : y));
  return a > U64_MAX ? U64_MAX : a;
}

export function maxUnbackedOver(params, tMs) {
  const t = BigInt(tMs) > 0n ? BigInt(tMs) : 0n;
  const one = (b) => (b.capacity * (b.windowMs + t)) / b.windowMs;
  const a = one(params.short);
  const b = one(params.long);
  return a < b ? a : b;
}

/** What `attest` returns, computed from a decoded vault and protocol. */
export function attestLocal(vault, protocol, balance, nowS) {
  const reference = emaUpdate(vault.refBalance, vault.refUpdatedS, balance, nowS, vault.refInitialized);
  // Same base as the program: min(reference, live balance) (docs/15, A1).
  const live = BigInt(balance);
  const params = paramsFromConfig(vault.limits, reference < live ? reference : live);
  const frozenUntil = Math.max(protocol.frozenUntil, vault.frozenUntil);
  const nowMs = BigInt(nowS) * 1000n;
  const cap = (x) => (x > U64_MAX ? U64_MAX : x);
  return {
    availableNow: nowS < frozenUntil ? 0n : availableNow(vault.tatShortMs, vault.tatLongMs, params, nowMs),
    worst1h: cap(maxUnbackedOver(params, 3_600_000n)),
    worst24h: cap(maxUnbackedOver(params, 86_400_000n)),
    balance: BigInt(balance),
    frozenUntil,
    queued: vault.queuedAmount,
    pendingTickets: vault.pendingTickets,
  };
}
