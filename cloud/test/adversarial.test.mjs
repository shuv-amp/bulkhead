// Adversarial runs against the guardian policy: an attacker who knows the
// policy paces unbacked payouts to stay under its thresholds. Each payout is
// sized with the JavaScript limiter port (lib/limits.mjs), so the attacker
// only ever takes what the program itself would pay instantly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, newState, outflowAlerts, DEFAULT_POLICY } from "../guardian/policy.mjs";
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
 * pays it out, and the payout is fed to the guardian policy, and to its
 * outflow alerts (`outflowAlerts`, docs/09, finding 76). `refill`: honest
 * deposits put back what left, so the base stays put (a protocol in steady
 * state). Returns the total paid before the first freeze, when it came, and
 * the alerts raised before it.
 */
function run({ hours, policy, want, refill = false }) {
  const s = newState();
  let balance = VAULT;
  let ref = VAULT;
  let refAt = 0;
  let tatS = 0n;
  let tatL = 0n;
  const paid = [];
  const alerts = [];
  let taken = 0n;
  for (let now = 0; now < hours * 3_600; now += TICK_S) {
    ref = emaUpdate(ref, refAt, balance, now, true); // the program's touch_reference
    refAt = now;
    // The program's base: min(reference, balance, low-water). Only outflows
    // here, so the balance is never above the low-water balance.
    const p = paramsFromConfig(LIMITS, ref < balance ? ref : balance);
    const nowMs = BigInt(now) * 1000n;
    const sum = (secs) => paid.filter((x) => now - x.t <= secs).reduce((a, x) => a + x.u, 0n);
    const ctx = {
      worst1h: maxUnbackedOver(p, 3_600_000n), worst24h: maxUnbackedOver(p, 86_400_000n), worst72h: maxUnbackedOver(p, 259_200_000n),
      now, hourPaid: sum(3_600), dayPaid: sum(86_400), threeDayPaid: sum(259_200), base: ref < balance ? ref : balance,
    };
    let u = want(ctx);
    const avail = availableNow(tatS, tatL, p, nowMs);
    if (u > avail) u = avail;
    if (u <= 0n) continue;
    tatS = (tatS > nowMs ? tatS : nowMs) + ceilDiv(u * p.short.windowMs, p.short.capacity);
    tatL = (tatL > nowMs ? tatL : nowMs) + ceilDiv(u * p.long.windowMs, p.long.capacity);
    if (!refill) balance -= u;
    taken += u;
    paid.push({ t: now, u });
    while (paid.length && now - paid[0].t > 259_200) paid.shift(); // nothing older than 72h is read
    const e = { kind: "released", mint, owner, backed: 0n, instant: u, queued: 0n, ticketId: 0n, etaS: 0 };
    const figures = { worst1h: ctx.worst1h, worst24h: ctx.worst24h, worst72h: ctx.worst72h, now };
    const actions = assess(s, e, figures, policy);
    for (const a of outflowAlerts(s, mint, figures, policy)) alerts.push({ ...a, t: now });
    if (actions.some((a) => a.type === "freeze")) return { frozenAtS: now, taken, reason: actions[0].reason, alerts };
  }
  return { frozenAtS: null, taken, alerts };
}

/** Stays one unit under the 1-hour rule in every rolling hour. */
const underHourlyRule = (fraction) => (ctx) => {
  const limit = BigInt(Math.round(Number(ctx.worst1h) * fraction));
  return limit - 1n - ctx.hourPaid;
};

test("finding: with only the 1-hour rule, a paced attacker is never frozen and drains ~5% a day", () => {
  const policy = { ...DEFAULT_POLICY, freezeFractionOfWorst24h: 0, freezeFractionOfWorst72h: 0 };
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

/** Stays one unit under the 1-hour rule and under `fr24` × worst_24h in
 * every rolling day, and, when `fr72` > 0, under `fr72` × worst_72h in every
 * rolling 72 hours: the patient attacker of docs/09, finding 76. */
const patient = (fr24, fr72 = 0) => (ctx) => {
  let m = underHourlyRule(DEFAULT_POLICY.freezeFractionOfWorst1h)(ctx);
  const day = BigInt(Math.round(Number(ctx.worst24h) * fr24)) - 1n - ctx.dayPaid;
  if (day < m) m = day;
  if (fr72 > 0) {
    const three = BigInt(Math.round(Number(ctx.worst72h) * fr72)) - 1n - ctx.threeDayPaid;
    if (three < m) m = three;
  }
  return m;
};
const pct = (x) => Number((x * 10_000n) / VAULT) / 100;

test("finding 76 (before): under the 1h and 24h rules alone, a patient attacker takes ~77% of the vault in 30 days, unfrozen and unalerted", () => {
  const before = { ...DEFAULT_POLICY, freezeFractionOfWorst72h: 0, alertFractionOfThreshold: 0 };
  const r = run({ hours: 30 * 24, policy: before, want: patient(DEFAULT_POLICY.freezeFractionOfWorst24h) });
  assert.equal(r.frozenAtS, null);
  assert.equal(r.alerts.length, 0);
  // 0.5 × worst_24h is 5% of the base a day: the program's own sustained rate.
  assert.ok(pct(r.taken) > 75, `taken ${pct(r.taken)}%`);
});

test("finding 76: the 72-hour rule freezes the attacker who stays under the 24-hour rule alone", () => {
  const r = run({ hours: 30 * 24, policy: DEFAULT_POLICY, want: patient(DEFAULT_POLICY.freezeFractionOfWorst24h) });
  assert.notEqual(r.frozenAtS, null);
  assert.match(r.reason, /last 72 hours/);
  assert.ok(r.frozenAtS < 3 * 86_400, `frozen after ${r.frozenAtS}s`);
  // Frozen once 72h of it reach 0.55 × worst_72h (11% of a base that has
  // shrunk by then): ~11% taken, against 77% over 30 days unfrozen.
  assert.ok(pct(r.taken) < 12, `taken ${pct(r.taken)}%`);
  assert.ok(r.alerts.some((a) => a.code === "outflow"), "people heard about it before the freeze");
});

test("finding 76 (residual): one who also stays under the 72-hour rule is bounded, not stopped, and the alerts say so", () => {
  const r = run({ hours: 30 * 24, policy: DEFAULT_POLICY, want: patient(DEFAULT_POLICY.freezeFractionOfWorst24h, DEFAULT_POLICY.freezeFractionOfWorst72h) });
  assert.equal(r.frozenAtS, null);
  // 0.55 × worst_72h (20% of the base) a 72 hours: ~3.7% of the base a day,
  // against 5% before. Over 30 days the shrinking base compounds it: ~65%
  // against ~77%. A threshold bot cannot do better without freezing honest
  // flow at the ceiling; the on-chain limits are the bound.
  assert.ok(pct(r.taken) < 67, `taken ${pct(r.taken)}%`);
  const first = r.alerts.find((a) => a.code === "outflow");
  const sustained = r.alerts.find((a) => a.code === "sustained");
  assert.ok(first && first.t < 2 * 3_600, `first alert at ${first?.t}s`);
  assert.match(first.msg, /unbacked outflow at \d+% of the 24h freeze threshold/);
  assert.ok(sustained && sustained.t < 2 * 86_400, `sustained-drip alert at ${sustained?.t}s`);
  // Rate-limited: at most every 6 hours, the sustained one daily.
  assert.ok(r.alerts.filter((a) => a.code === "outflow").length <= 30 * 4);
  assert.ok(r.alerts.filter((a) => a.code === "sustained").length <= 30);
});

/** Honest unbacked flow at the calibration ceiling: 3.3% of the base a day
 * (docs/07 §4 measures it as a fraction of the capacity base at the time),
 * spread evenly. */
const honest = (ctx) => (ctx.base * 33n) / 1000n / BigInt(86_400 / TICK_S);

test("honest flow at the calibration ceiling never freezes over 30 days, on a shrinking vault or a steady one", () => {
  // No deposits at all: the worst case for the 72-hour rule, whose window
  // looks back at a larger base. At 0.5 × worst_72h this froze after ~69h,
  // so the default is 0.55 (docs/09, finding 76).
  const shrinking = run({ hours: 30 * 24, policy: DEFAULT_POLICY, want: honest });
  assert.equal(shrinking.frozenAtS, null, shrinking.reason);
  assert.equal(run({ hours: 30 * 24, policy: { ...DEFAULT_POLICY, freezeFractionOfWorst72h: 0.5 }, want: honest }).frozenAtS !== null, true, "0.5 would freeze it");
  const steady = run({ hours: 30 * 24, policy: DEFAULT_POLICY, want: honest, refill: true });
  assert.equal(steady.frozenAtS, null, steady.reason);
  // At the ceiling it is 66% of the 24h threshold: the alerts fire, rate-limited.
  assert.ok(steady.alerts.length > 0 && steady.alerts.length <= 30 * 5);
});
