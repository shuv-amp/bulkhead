// Adversarial runs against the guardian policy: an attacker who knows the
// policy paces unbacked payouts to stay under its thresholds. Each payout is
// sized with the JavaScript limiter port (lib/limits.mjs), so the attacker
// only ever takes what the program itself would pay instantly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, newState, DEFAULT_POLICY } from "../guardian/policy.mjs";
import { availableNow, emaUpdate, maxUnbackedOver, paramsFromConfig } from "../lib/limits.mjs";

const USDC = 1_000_000n;
const VAULT = 10_000_000n * USDC;
const LIMITS = { shortBps: 200, shortWindowS: 3_600, shortFloor: 0, shortCap: 0, longBps: 500, longWindowS: 86_400, longFloor: 0, longCap: 0, minQueueDelayS: 21_600 };
const TICK_S = 300;
const owner = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const mint = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";

const ceilDiv = (a, b) => (a + b - 1n) / b;

/**
 * Runs `hours` of 5-minute ticks. Each tick `want(ctx)` names an unbacked
 * amount; the limiter pays at most what is instantly available, the vault
 * pays it out, and the payout is fed to the guardian policy.
 * Returns the total paid before the first freeze, and when it came.
 */
function run({ hours, policy, want }) {
  const s = newState();
  let balance = VAULT;
  let ref = VAULT;
  let refAt = 0;
  let tatS = 0n;
  let tatL = 0n;
  const paid = [];
  let taken = 0n;
  for (let now = 0; now < hours * 3_600; now += TICK_S) {
    ref = emaUpdate(ref, refAt, balance, now, true);
    refAt = now;
    const p = paramsFromConfig(LIMITS, ref);
    const nowMs = BigInt(now) * 1000n;
    const hourPaid = paid.filter((x) => now - x.t <= 3_600).reduce((a, x) => a + x.u, 0n);
    const dayPaid = paid.filter((x) => now - x.t <= 86_400).reduce((a, x) => a + x.u, 0n);
    const ctx = { worst1h: maxUnbackedOver(p, 3_600_000n), worst24h: maxUnbackedOver(p, 86_400_000n), now, hourPaid, dayPaid };
    let u = want(ctx);
    const avail = availableNow(tatS, tatL, p, nowMs);
    if (u > avail) u = avail;
    if (u <= 0n) continue;
    tatS = (tatS > nowMs ? tatS : nowMs) + ceilDiv(u * p.short.windowMs, p.short.capacity);
    tatL = (tatL > nowMs ? tatL : nowMs) + ceilDiv(u * p.long.windowMs, p.long.capacity);
    balance -= u;
    taken += u;
    paid.push({ t: now, u });
    const e = { kind: "released", mint, owner, backed: 0n, instant: u, queued: 0n, ticketId: 0n, etaS: 0 };
    const actions = assess(s, e, { worst1h: ctx.worst1h, worst24h: ctx.worst24h, now }, policy);
    if (actions.some((a) => a.type === "freeze")) return { frozenAtS: now, taken, reason: actions[0].reason };
  }
  return { frozenAtS: null, taken };
}

/** Stays one unit under the 1-hour rule in every rolling hour. */
const underHourlyRule = (fraction) => (ctx) => {
  const limit = BigInt(Math.round(Number(ctx.worst1h) * fraction));
  return limit - 1n - ctx.hourPaid;
};

test("finding: with only the 1-hour rule, a paced attacker is never frozen and drains ~5% a day", () => {
  const policy = { ...DEFAULT_POLICY, freezeFractionOfWorst24h: 0 };
  const r = run({ hours: 72, policy, want: underHourlyRule(policy.freezeFractionOfWorst1h) });
  assert.equal(r.frozenAtS, null);
  // Three days of the daily bucket plus the first burst: well over 14% of the vault.
  assert.ok(r.taken * 100n >= VAULT * 14n, `taken ${r.taken / USDC} USDC`);
});

test("the 24-hour rule freezes the same paced attacker within hours, not days", () => {
  const r = run({ hours: 72, policy: DEFAULT_POLICY, want: underHourlyRule(DEFAULT_POLICY.freezeFractionOfWorst1h) });
  assert.notEqual(r.frozenAtS, null);
  assert.match(r.reason, /last 24 hours/);
  // The freeze follows the payout that crosses 0.5 × worst_24h (5% of the
  // vault), and that payout is at most 0.5 × worst_1h (2%): under 7% in all.
  assert.ok(r.taken * 100n <= VAULT * 7n, `taken ${r.taken / USDC} USDC`);
  assert.ok(r.frozenAtS < 6 * 3_600, `frozen after ${r.frozenAtS}s`);
});

test("residual: an attacker who also stays under the 24-hour rule is capped at that rule's threshold per day", () => {
  const f = DEFAULT_POLICY.freezeFractionOfWorst24h;
  const want = (ctx) => {
    const day = BigInt(Math.round(Number(ctx.worst24h) * f)) - 1n - ctx.dayPaid;
    const hour = underHourlyRule(DEFAULT_POLICY.freezeFractionOfWorst1h)(ctx);
    return day < hour ? day : hour;
  };
  const r = run({ hours: 72, policy: DEFAULT_POLICY, want });
  assert.equal(r.frozenAtS, null);
  // ≤ 5% of the vault per rolling day (0.5 × worst_24h of 10%): three days ≤ 15%.
  // A threshold bot bounds the drip; it cannot end it. Humans reading the
  // alerts, and calibrated limits, still have to.
  assert.ok(r.taken * 100n <= VAULT * 15n, `taken ${r.taken / USDC} USDC`);
});

test("honest unbacked flow at the calibration ceiling (3.3% a day, evenly) never trips either rule", () => {
  const perTick = (VAULT * 33n) / 1000n / BigInt(86_400 / TICK_S);
  const r = run({ hours: 7 * 24, policy: DEFAULT_POLICY, want: () => perTick });
  assert.equal(r.frozenAtS, null);
});
