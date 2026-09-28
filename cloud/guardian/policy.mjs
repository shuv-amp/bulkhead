// The guardian's decision rules: pure functions from on-chain events to
// actions. No I/O here, so every rule is unit-tested (cloud/test).
//
// A guardian can only stop things: freeze (≤ 24h, repeatable), cancel tickets,
// veto proposals, and (under Floor) abort. It can never move funds or choose a
// recipient; the programs enforce that, not this file.

import { b58encode, Reader } from "../lib/solana.mjs";

export const DEFAULT_POLICY = {
  /** Freeze when unbacked outflow to non-allowlisted owners within the last
   * hour reaches this fraction of the program's own `worst_1h` figure. */
  freezeFractionOfWorst1h: 0.5,
  /** Freeze when unbacked outflow to non-allowlisted owners within the last
   * 24 hours reaches this fraction of the program's own `worst_24h` figure.
   * Without it, an attacker who keeps every rolling hour just under the
   * 1-hour rule drips out the daily bucket (5%/day by default) forever
   * (cloud/test/adversarial.test.mjs). 0 disables the rule. Keep it above the
   * calibrated honest daily unbacked flow (docs/07 §5). */
  freezeFractionOfWorst24h: 0.5,
  freezeSecs: 86_400,
  /** Owners whose unbacked payouts are expected (fee collectors, market makers). */
  allowlistedOwners: [],
  /** While frozen, cancel tickets to non-allowlisted owners. */
  cancelTicketsWhenFrozen: true,
  /** Veto every loosening that isn't pre-approved by id. */
  vetoLoosenings: true,
  approvedChangeIds: [],
  /** Floor: veto upgrade proposals whose buffer isn't pre-approved. */
  approvedUpgradeBuffers: [],
  heartbeatEveryS: 86_400,
};

export function newState() {
  return { outflows: [], frozenUntil: 0, cancelled: new Set(), vetoed: new Set(), freezing: false };
}

const u64 = (b) => new Reader(b).u64();

/** Decodes the events the guardian acts on. */
export function decode(ev) {
  const f = ev.fields;
  switch (ev.name) {
    case "vault:released": {
      const r = new Reader(f[2]);
      return { kind: "released", mint: b58encode(f[0]), owner: b58encode(f[1]), backed: r.u64(), instant: r.u64(), queued: r.u64(), ticketId: r.u64(), etaS: Number(r.i64()) };
    }
    case "vault:frozen":
      return { kind: "frozen", until: Number(new Reader(f[2]).i64()) };
    case "vault:unfrozen":
      return { kind: "unfrozen" };
    case "vault:change_proposed":
      return { kind: "change_proposed", id: u64(f[0]), changeKind: f[1][0], target: b58encode(f[2]) };
    case "floor:proposed":
      return { kind: "floor_proposed", program: b58encode(f[0]), proposalKind: f[1][0], id: u64(f[2]), target: b58encode(f[3]) };
    default:
      return { kind: "other", name: ev.name };
  }
}

/**
 * One event in, zero or more actions out. `ctx.worst1h` and `ctx.worst24h`
 * are the vault's current 1-hour and 24-hour worst cases from `attest` (base
 * units, BigInt; the 24-hour rule is skipped when `worst24h` is absent);
 * `ctx.now` is unix seconds.
 */
export function assess(state, e, ctx, policy = DEFAULT_POLICY) {
  const actions = [];
  const frozen = state.freezing || ctx.now < state.frozenUntil;
  switch (e.kind) {
    case "released": {
      const unbacked = e.instant + e.queued;
      if (unbacked === 0n || policy.allowlistedOwners.includes(e.owner)) break;
      state.outflows.push({ t: ctx.now, amount: unbacked, owner: e.owner, ticketId: e.queued > 0n ? e.ticketId : null });
      state.outflows = state.outflows.filter((o) => ctx.now - o.t <= 86_400);
      const sumSince = (secs) => state.outflows.filter((o) => ctx.now - o.t <= secs).reduce((s, o) => s + o.amount, 0n);
      const lastHour = sumSince(3_600);
      const limit = BigInt(Math.round(Number(ctx.worst1h) * policy.freezeFractionOfWorst1h));
      const fraction24h = policy.freezeFractionOfWorst24h ?? 0;
      const lastDay = sumSince(86_400);
      const limit24h = ctx.worst24h !== undefined && fraction24h > 0 ? BigInt(Math.round(Number(ctx.worst24h) * fraction24h)) : null;
      if (!frozen && lastHour >= limit) {
        state.freezing = true;
        actions.push({ type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last hour: ${lastHour} ≥ ${limit} (${policy.freezeFractionOfWorst1h} × worst_1h)` });
      } else if (!frozen && limit24h !== null && lastDay >= limit24h) {
        state.freezing = true;
        actions.push({ type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last 24 hours: ${lastDay} ≥ ${limit24h} (${fraction24h} × worst_24h)` });
      }
      if ((frozen || state.freezing) && policy.cancelTicketsWhenFrozen) {
        for (const o of state.outflows) {
          if (o.ticketId !== null && !state.cancelled.has(o.ticketId)) {
            state.cancelled.add(o.ticketId);
            actions.push({ type: "cancel", ticketId: o.ticketId, reason: `incident: ticket to ${o.owner}` });
          }
        }
      }
      break;
    }
    case "frozen":
      state.frozenUntil = Math.max(state.frozenUntil, e.until);
      state.freezing = false;
      break;
    case "unfrozen":
      state.frozenUntil = 0;
      state.freezing = false;
      break;
    case "change_proposed":
      if (policy.vetoLoosenings && !policy.approvedChangeIds.map(BigInt).includes(e.id) && !state.vetoed.has(`c${e.id}`)) {
        state.vetoed.add(`c${e.id}`);
        actions.push({ type: "veto_change", changeId: e.id, reason: `loosening ${e.id} (kind ${e.changeKind}) is not pre-approved` });
      }
      break;
    case "floor_proposed":
      if (e.proposalKind === 1 && !policy.approvedUpgradeBuffers.includes(e.target) && !state.vetoed.has(`f${e.program}:${e.id}`)) {
        state.vetoed.add(`f${e.program}:${e.id}`);
        actions.push({ type: "floor_veto", program: e.program, reason: `upgrade to unapproved buffer ${e.target}` });
      }
      break;
  }
  return actions;
}
