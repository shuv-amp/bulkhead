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
   * calibrated honest daily unbacked flow (docs/07 §4: defaults are 1.5× that
   * ceiling, so 5% / 1.5 ≈ 3.3% a day). */
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
  /** Compute-unit limit on every guardian transaction (a freeze, cancel,
   * veto or heartbeat uses a small fraction of it). */
  computeUnits: 50_000,
  /** Priority price in micro-lamports per compute unit, or "auto": the 90th
   * percentile of recent fees paid on the protocol account, capped below. A
   * freeze is only as good as the slot it lands in. */
  priorityMicroLamports: "auto",
  maxPriorityMicroLamports: 1_000_000,
};

export const HOUR_S = 3_600;
export const DAY_S = 86_400;

/**
 * What is not ready under Floor, from a decoded Floor config (docs/15, A5).
 * Every abort consumes the staged abort buffer, and every upgrade or restore
 * unpins the snapshot; until someone stages and pins new ones, the program is
 * live with no stop button or no instant restore. Both steps are
 * permissionless, so the fix is a runbook step, and this is its alarm.
 */
export function floorAlerts(fl) {
  if (fl.status === "aborted") {
    return [{ code: "stopped", msg: "the program is stopped: restore the snapshot or approve a fix" }];
  }
  const alerts = [];
  if (!fl.abortStaged) {
    alerts.push({ code: "unarmed", msg: "no abort buffer staged: no guardian can stop the program until one is" });
  }
  if (!fl.snapshotPinned) {
    alerts.push({ code: "no_snapshot", msg: "no snapshot pinned: after a stop, restoring needs a new frozen buffer and a quorum" });
  }
  return alerts;
}

export function newState() {
  return { outflows: [], frozenUntil: 0, cancelled: new Set(), vetoed: new Set(), tickets: new Set(), pendingTickets: new Map(), freezing: false };
}

/** Keep ticket cancellation state outside the rolling outflow windows. */
export function rememberTicket(state, ticket) {
  const id = BigInt(ticket.ticketId ?? ticket.id);
  state.tickets.add(id);
  const old = state.pendingTickets.get(id) ?? {};
  state.pendingTickets.set(id, {
    ticketId: id,
    mint: ticket.mint ?? old.mint ?? null,
    vault: ticket.vault ?? old.vault ?? null,
    owner: ticket.owner ?? ticket.recipientOwner ?? old.owner ?? "(unknown)",
    amount: ticket.amount ?? old.amount ?? null,
  });
}

/**
 * `amount * fraction`, rounded half away from zero, in integers.
 * `Number(amount)` is not exact past 2^53, and a vault's worst case can be.
 */
export function scaleBy(amount, fraction) {
  const a = typeof amount === "bigint" ? amount : BigInt(amount ?? 0);
  if (!(fraction > 0) || a <= 0n) return 0n;
  const scale = 1_000_000n;
  const num = BigInt(Math.round(Number(fraction) * 1_000_000));
  if (num <= 0n) return 0n;
  return (a * num + scale / 2n) / scale;
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
    // Scope 0 is the whole protocol, 1 a single vault. The event does not say
    // which vault, so a vault-scoped freeze must not be read as protocol-wide.
    case "vault:frozen":
      return { kind: "frozen", scope: f[0]?.[0] ?? 0, until: Number(new Reader(f[2]).i64()) };
    case "vault:unfrozen":
      return { kind: "unfrozen", scope: f[0]?.[0] ?? 0 };
    case "vault:change_proposed":
      return { kind: "change_proposed", id: u64(f[0]), changeKind: f[1][0], target: b58encode(f[2]) };
    case "floor:proposed":
      return { kind: "floor_proposed", program: b58encode(f[0]), proposalKind: f[1][0], id: u64(f[2]), target: b58encode(f[3]) };
    case "vault:settled":
    case "vault:ticket_cancelled":
      return { kind: "ticket_closed", ticketId: u64(f[0]) };
    default:
      return { kind: "other", name: ev.name };
  }
}

function sumsFor(state, mint, now) {
  // Drop only what is already older than a day. An outflow dated after `now`
  // stays: a decision made at an earlier timestamp must not erase it, and it
  // does not count until `now` catches up.
  state.outflows = state.outflows.filter((o) => o.t > now || now - o.t <= DAY_S);
  const rows = state.outflows.filter((o) => o.mint === mint);
  const sumSince = (secs) => rows.filter((o) => o.t <= now && now - o.t <= secs).reduce((s, o) => s + o.amount, 0n);
  return { lastHour: sumSince(HOUR_S), lastDay: sumSince(DAY_S) };
}

function limitsFor(ctx, policy) {
  const fraction24h = policy.freezeFractionOfWorst24h ?? 0;
  return {
    limit: scaleBy(ctx.worst1h ?? 0n, policy.freezeFractionOfWorst1h),
    limit24h: ctx.worst24h !== undefined && fraction24h > 0 ? scaleBy(ctx.worst24h, fraction24h) : null,
    fraction24h,
  };
}

/**
 * Whether `mint`'s recorded window is already over a threshold. Used after
 * replaying history: `assess` only decides on a new release.
 * An empty window is not a breach, even when the limit is 0.
 */
export function breach(state, mint, ctx, policy = DEFAULT_POLICY) {
  const { lastHour, lastDay } = sumsFor(state, mint, ctx.now);
  const { limit, limit24h, fraction24h } = limitsFor(ctx, policy);
  if (lastHour > 0n && lastHour >= limit) {
    return { type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last hour: ${lastHour} ≥ ${limit} (${policy.freezeFractionOfWorst1h} × worst_1h)` };
  }
  if (lastDay > 0n && limit24h !== null && lastDay >= limit24h) {
    return { type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last 24 hours: ${lastDay} ≥ ${limit24h} (${fraction24h} × worst_24h)` };
  }
  return null;
}

/**
 * Cancels for every recorded queued ticket not yet cancelled. Run after any
 * freeze that succeeds: a late freeze (after a restart, or a retry after a
 * failed freeze) is not followed by the release event that would otherwise
 * trigger the cancels, and a ticket left alone pays out when the freeze
 * expires. Marks them cancelled so they are sent once.
 */
export function pendingCancels(state, policy = DEFAULT_POLICY) {
  if (!policy.cancelTicketsWhenFrozen) return [];
  const actions = [];
  for (const ticket of state.pendingTickets.values()) {
    if (policy.allowlistedOwners.includes(ticket.owner)) continue;
    if (!state.cancelled.has(ticket.ticketId)) {
      state.cancelled.add(ticket.ticketId);
      actions.push({
        type: "cancel",
        ticketId: ticket.ticketId,
        mint: ticket.mint,
        vault: ticket.vault,
        reason: `incident: ticket to ${ticket.owner}`,
      });
    }
  }
  return actions;
}

/**
 * A freeze that is already on chain retires a local send that failed or timed
 * out. Leaving it queued would freeze the protocol again when that freeze thaws,
 * with no new breach.
 */
export function retirePendingFreeze(pending, chainFrozenUntil, now) {
  return pending && chainFrozenUntil > now ? null : pending;
}

/**
 * Whether a failed freeze is still worth sending, after this cycle's chain
 * read. The retry has to see that read: `frozenUntil` still 0 locally while
 * the freeze already landed, and a second freeze extends the lockout
 * (`freeze_until` takes the later deadline).
 */
export function pendingFreezeAfterSync(pending, chainFrozenUntil, now) {
  const still = retirePendingFreeze(pending, chainFrozenUntil, now);
  if (!still || now < chainFrozenUntil) return null;
  return still;
}

/** Judge the startup window at the later of the wall clock and the newest outflow. */
export function decisionTime(wall, outflows) {
  let now = wall;
  for (const o of outflows) if (o.t > now) now = o.t;
  return now;
}

/**
 * One null account read is not proof the ticket is gone. Dropping it from
 * the cancellation set lets the next sweep try again.
 */
export function noteMissingTicket(state, ticketId) {
  state.cancelled.delete(ticketId);
}

export function vetoKey(action) {
  if (action.type === "veto_change") return `c${action.changeId}`;
  if (action.type === "floor_veto") return `f${action.program}:${action.proposalId}`;
  return null;
}

/** Keep one retry for a veto whose send failed. The event is not seen again. */
export function queueFailedVeto(pending, action) {
  const key = vetoKey(action);
  if (!key) return pending;
  if (pending.some((a) => vetoKey(a) === key)) return pending;
  return [...pending, action];
}

/**
 * What a *retry* should do with a veto. The first send follows the event.
 * A retry has to look again. Floor refuses a veto whose id is not the one
 * still pending, and a change that already executed or was vetoed must not
 * be sent forever.
 * `chain` null means the account could not be read.
 * Returns "send", "drop", or "keep".
 */
export function vetoRetryDisposition(action, chain) {
  if (action.type === "floor_veto") {
    if (!chain) return "keep";
    if (chain.pendingKind !== 1 || chain.pendingVetoed) return "drop";
    if (BigInt(chain.pendingId) !== BigInt(action.proposalId)) return "drop";
    return "send";
  }
  if (action.type === "veto_change") {
    if (!chain) return "keep";
    if (chain.vetoed || chain.executed) return "drop";
    return "send";
  }
  return "drop";
}

/** Vetoed and executed flags of a `BHCHNG01` account. Null if it is not one. */
export function readChangeVeto(bytes) {
  if (!bytes || bytes.length < 51) return null;
  if (new TextDecoder().decode(bytes.slice(0, 8)) !== "BHCHNG01") return null;
  return { vetoed: bytes[49] !== 0, executed: bytes[50] !== 0 };
}

/**
 * When the next heartbeat may be sent. A success waits out the interval.
 * A failure is retried on the short delay: treating it as a success schedules
 * the next one a full interval later, and a dead guardian cannot revive itself.
 */
export function nextHeartbeatAt(succeeded, now, everyMs, retryMs) {
  return now + (succeeded ? everyMs : retryMs);
}

/** Record a protocol-wide freeze observed on chain and cancel known queued tickets. */
export function observeProtocolFreeze(state, until, now, policy = DEFAULT_POLICY, act = true) {
  state.frozenUntil = Math.max(state.frozenUntil, until);
  state.freezing = false;
  return act && now < state.frozenUntil ? pendingCancels(state, policy) : [];
}

/**
 * One event in, zero or more actions out. `ctx.worst1h` and `ctx.worst24h`
 * are that mint's current worst cases from `attest` (base units, BigInt; the
 * 24-hour rule is skipped when `worst24h` is absent); `ctx.now` is unix
 * seconds. Windows are per mint: one vault's drip does not fill another's.
 * `act` false records releases and freeze bookkeeping and returns no actions,
 * so a restart can rebuild the window without re-sending old vetoes.
 */
export function assess(state, e, ctx, policy = DEFAULT_POLICY, act = true) {
  const actions = [];
  const frozen = state.freezing || ctx.now < state.frozenUntil;
  switch (e.kind) {
    case "released": {
      // A ticket can reach the guardian twice (its event, and the chain scan
      // for tickets whose event was missed): its queued amount counts once.
      const ticket = e.queued > 0n ? e.ticketId : null;
      const queued = ticket !== null && state.tickets.has(ticket) ? 0n : e.queued;
      if (ticket !== null) rememberTicket(state, { ticketId: ticket, mint: e.mint, vault: e.vault, owner: e.owner, amount: e.queued });
      const unbacked = e.instant + queued;
      if (unbacked === 0n || policy.allowlistedOwners.includes(e.owner)) break;
      // `e.at` is when the outflow happened. `ctx.now` is when the decision is made.
      state.outflows.push({ t: e.at ?? ctx.now, amount: unbacked, owner: e.owner, mint: e.mint, ticketId: queued > 0n ? ticket : null });
      const { lastHour, lastDay } = sumsFor(state, e.mint, ctx.now);
      const { limit, limit24h, fraction24h } = limitsFor(ctx, policy);
      // An empty sum is not a breach. A future-dated outflow is kept but not
      // counted yet, and `0 ≥ 0` would freeze whenever the worst case is 0.
      if (act && !frozen && lastHour > 0n && lastHour >= limit) {
        state.freezing = true;
        actions.push({ type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last hour: ${lastHour} ≥ ${limit} (${policy.freezeFractionOfWorst1h} × worst_1h)` });
      } else if (act && !frozen && lastDay > 0n && limit24h !== null && lastDay >= limit24h) {
        state.freezing = true;
        actions.push({ type: "freeze", secs: policy.freezeSecs, reason: `unbacked outflow to non-allowlisted owners in the last 24 hours: ${lastDay} ≥ ${limit24h} (${fraction24h} × worst_24h)` });
      }
      if (act && (frozen || state.freezing) && policy.cancelTicketsWhenFrozen) {
        actions.push(...pendingCancels(state, policy));
      }
      break;
    }
    case "frozen":
      if ((e.scope ?? 0) !== 0) break; // one vault frozen: the protocol is not
      actions.push(...observeProtocolFreeze(state, e.until, ctx.now, policy, act));
      break;
    case "unfrozen":
      if ((e.scope ?? 0) !== 0) break;
      state.frozenUntil = 0;
      state.freezing = false;
      break;
    case "ticket_closed":
      state.pendingTickets.delete(e.ticketId);
      state.cancelled.delete(e.ticketId);
      break;
    case "change_proposed":
      if (!act) break;
      if (policy.vetoLoosenings && !policy.approvedChangeIds.map(BigInt).includes(e.id) && !state.vetoed.has(`c${e.id}`)) {
        state.vetoed.add(`c${e.id}`);
        actions.push({ type: "veto_change", changeId: e.id, reason: `loosening ${e.id} (kind ${e.changeKind}) is not pre-approved` });
      }
      break;
    case "floor_proposed":
      if (!act) break;
      if (e.proposalKind === 1 && !policy.approvedUpgradeBuffers.includes(e.target) && !state.vetoed.has(`f${e.program}:${e.id}`)) {
        state.vetoed.add(`f${e.program}:${e.id}`);
        actions.push({ type: "floor_veto", program: e.program, proposalId: e.id, reason: `upgrade to unapproved buffer ${e.target}` });
      }
      break;
  }
  return actions;
}
