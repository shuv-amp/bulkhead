// The worst-case figures from raw account data, for pages that hold no key
// (simulating `attest` needs a funded fee payer). A JavaScript statement of
// four core functions (crates/bulkhead-core/src/{ema,limiter}.rs), checked
// against the Python reference and the Rust core on random edge cases
// (cloud/test/limits.test.mjs) and against the program's own `attest` in the
// end-to-end run.
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

const LOW_WINDOW_S = 1_800n;

/**
 * The program's low-water balance (core `WindowLow::touch`): the least balance
 * any touch saw, before its operation, in the current and the previous
 * 30-minute window. Capacity uses min(reference, balance, low), so capital
 * deposited and taken back around a payout, or parked under a window, cannot
 * lift the base (docs/09, finding 65). `low` is { prev, cur, window }.
 */
export function windowLowTouch(low, balance, nowS, initialized) {
  const bal = BigInt(balance);
  const now = BigInt(nowS);
  // div_euclid: floor division, also for a negative time.
  const w = now >= 0n ? now / LOW_WINDOW_S : -((-now + LOW_WINDOW_S - 1n) / LOW_WINDOW_S);
  const window = BigInt(low.window);
  if (!initialized || w > window + 1n) return { prev: bal, cur: bal, window: w };
  if (w === window + 1n) return { prev: BigInt(low.cur), cur: bal, window: w };
  const cur = BigInt(low.cur);
  return { prev: BigInt(low.prev), cur: bal < cur ? bal : cur, window };
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
  // Same base as the program (`unbacked_base`): min(EMA, live balance,
  // low-water balance) after a touch (docs/15, A1; docs/09, finding 65). An
  // account from an older build has no low-water balance: the touch starts it.
  const reference = emaUpdate(vault.refBalance, vault.refUpdatedS, balance, nowS, vault.refInitialized);
  const live = BigInt(balance);
  const l = windowLowTouch(vault.low ?? { prev: 0n, cur: 0n, window: 0n }, balance, nowS, vault.refInitialized && vault.low !== undefined);
  const low = l.prev < l.cur ? l.prev : l.cur;
  let base = reference < live ? reference : live;
  if (low < base) base = low;
  const params = paramsFromConfig(vault.limits, base);
  const frozenUntil = Math.max(protocol.frozenUntil, vault.frozenUntil);
  const nowMs = BigInt(nowS) * 1000n;
  const cap = (x) => (x > U64_MAX ? U64_MAX : x);
  const min64 = (a, b) => (a < b ? a : b);
  return {
    availableNow: nowS < frozenUntil ? 0n : min64(availableNow(vault.tatShortMs, vault.tatLongMs, params, nowMs), live),
    worst1h: cap(maxUnbackedOver(params, 3_600_000n)),
    worst24h: cap(maxUnbackedOver(params, 86_400_000n)),
    // Not an `attest` figure: the guardian's 72-hour rule (docs/09, finding 76).
    worst72h: cap(maxUnbackedOver(params, 259_200_000n)),
    balance: BigInt(balance),
    frozenUntil,
    queued: vault.queuedAmount,
    pendingTickets: vault.pendingTickets,
  };
}
