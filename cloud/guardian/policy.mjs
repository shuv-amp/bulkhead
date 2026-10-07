// The guardian's decision rules: pure functions from on-chain events to
// actions. No I/O here, so every rule is unit-tested (cloud/test).
//
// A guardian can only stop things: freeze (≤ 24h, repeatable), cancel tickets,
// veto proposals, and (under Floor) abort. It can never move funds or choose a
// recipient; the programs enforce that, not this file.

import { b58encode, Reader, decodeChange } from "../lib/solana.mjs";

const hex = (bytes) => Array.from(bytes ?? [], (x) => x.toString(16).padStart(2, "0")).join("");

/** How a Vault change is approved in `approvedChanges`: the kind, target and
 * payload of its `propose_change`, exactly as proposed. */
export function changeApproval({ kind, target, payload }) {
  return `${kind}:${target}:${hex(payload)}`;
}

/** How a Floor proposal other than code is approved in `approvedFloorProposals`. */
export function floorApproval({ program, kind, target, payload }) {
  return `${program}:${kind}:${target}:${hex(payload)}`;
}

const B58 = "[1-9A-HJ-NP-Za-km-z]{32,44}";
const CHANGE_APPROVAL = new RegExp(`^\\d+:${B58}:([0-9a-f]{2})*$`);
const FLOOR_APPROVAL = new RegExp(`^${B58}:\\d+:${B58}:([0-9a-f]{2})*$`);

/**
 * Refuses a policy whose approvals could not mean what the operators think.
 * Approvals by id (`approvedChangeIds`, "program:id") were replaced: an id
 * names whatever is proposed under it, so a guardian still reading one would
 * let a thief's change through and execute it.
 */
export function checkPolicy(policy) {
  if ("approvedChangeIds" in policy) {
    throw new Error('policy.approvedChangeIds is no longer read: approve a change by what it does, in approvedChanges as "kind:target:payloadHex" (docs/07)');
  }
  for (const a of policy.approvedChanges ?? []) {
    if (typeof a !== "string" || !CHANGE_APPROVAL.test(a)) throw new Error(`policy.approvedChanges: ${JSON.stringify(a)} is not "kind:target:payloadHex"`);
  }
  for (const a of policy.approvedFloorProposals ?? []) {
    if (typeof a !== "string" || !FLOOR_APPROVAL.test(a)) throw new Error(`policy.approvedFloorProposals: ${JSON.stringify(a)} is not "program:kind:target:payloadHex" (approvals by id were replaced)`);
  }
  return policy;
}

/** A change account (decoded, with its payload) the operators approved. */
function changeApproved(change, policy) {
  return change.payload !== undefined && (policy.approvedChanges ?? []).includes(changeApproval(change));
}

/** A live proposal event names the kind and target but not the payload: it
 * could be an approved change. The account scan then checks the payload. */
function changeMayBeApproved(kind, target, policy) {
  return (policy.approvedChanges ?? []).some((a) => a.startsWith(`${kind}:${target}:`));
}

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
  /** Incident hold: after this guardian freezes for a breach, renew the
   * freeze before it ends, until a guardian quorum unfreezes (the program's
   * only early unfreeze) or this many seconds pass. A stolen admin key stays
   * stolen when a 24h freeze ends; without the hold, a patient attacker takes
   * one more burst every day. Owners withdraw their own deposits while frozen
   * (G2). 0 turns it off. */
  holdIncidentS: 7 * 86_400,
  /** Renew when the freeze has less than this left. */
  holdRenewBeforeS: 3_600,
  /** Owners whose unbacked payouts are expected (fee collectors, market makers). */
  allowlistedOwners: [],
  /** While frozen, cancel tickets to non-allowlisted owners. */
  cancelTicketsWhenFrozen: true,
  /** Veto every loosening that isn't pre-approved. A change is approved by
   * what it does, "kind:target:payloadHex" (`changeApproval`), never by its
   * id: an id is only the protocol's next counter, so whoever proposes first
   * gets it, and a stolen admin key proposing just before the operators would
   * take their approval (and the keeper would execute its change). */
  vetoLoosenings: true,
  approvedChanges: [],
  /** Floor: veto every proposal not pre-approved. Upgrades and restores are
   * approved by buffer; anything else (release authority, owner, guardians, a
   * lower delay) by what it does, "program:kind:target:payloadHex"
   * (`floorApproval`), for the same reason. A quorum's approval still runs an
   * honest restore over a veto. */
  approvedUpgradeBuffers: [],
  approvedFloorProposals: [],
  /** Keeper: once due, execute exactly what is approved above (changes by id,
   * Floor proposals by id or buffer). Execution is open to anyone after the
   * delay; this only makes sure someone does it. Releasing Floor's authority
   * is never executed automatically: it closes the config. */
  executeApproved: true,
  /** Veto every lifeboat exit that isn't pre-approved as "mint:amount" (base
   * units). An exit goes to a destination committed 72h earlier; vetoing it
   * is the guardian's answer to a compromised destination (T18). */
  vetoLifeboatExits: true,
  approvedExits: [],
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
  return { outflows: [], frozenUntil: 0, cancelled: new Set(), vetoed: new Set(), tickets: new Set(), pendingTickets: new Map(), freezing: false, incidentSince: null };
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
    // A ticket is named by its payer and nonce, not its id: keep its address.
    address: ticket.address ?? ticket.ticket ?? old.address ?? null,
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
      // f[3]: the ticket's address when part was queued (all zero otherwise).
      const ticket = f[3]?.length === 32 && f[3].some((b) => b !== 0) ? b58encode(f[3]) : null;
      return { kind: "released", mint: b58encode(f[0]), owner: b58encode(f[1]), backed: r.u64(), instant: r.u64(), queued: r.u64(), ticketId: r.u64(), etaS: Number(r.i64()), ticket };
    }
    // Scope 0 is the whole protocol, 1 a single vault. The event does not say
    // which vault, so a vault-scoped freeze must not be read as protocol-wide.
    case "vault:frozen":
      return { kind: "frozen", scope: f[0]?.[0] ?? 0, until: Number(new Reader(f[2]).i64()) };
    case "vault:unfrozen":
      return { kind: "unfrozen", scope: f[0]?.[0] ?? 0 };
    case "vault:change_proposed":
      return { kind: "change_proposed", id: u64(f[0]), changeKind: f[1][0], target: b58encode(f[2]) };
    case "vault:exit_proposed":
      return { kind: "exit_proposed", mint: b58encode(f[0]), amount: u64(f[1]), executableS: Number(new Reader(f[2]).i64()) };
    case "vault:lifeboat_in":
      return { kind: "lifeboat_in", mint: b58encode(f[0]), amount: u64(f[1]) };
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
        address: ticket.address,
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

/** Judge the startup window at the later of the wall clock and the newest outflow. */
export function decisionTime(wall, outflows) {
  let now = wall;
  for (const o of outflows) if (o.t > now) now = o.t;
  return now;
}

/**
 * Judge the replayed startup window once per mint, as soon as that mint has a
 * worst-case figure (`worst(mint)` returns it, or null while the attest has
 * not been read). Later releases are judged by `assess` as they arrive.
 * Judging the same window again after that would freeze straight after a
 * guardian quorum's unfreeze, for outflows the quorum has already weighed.
 * A protocol already frozen, or a freeze in flight, settles every mint.
 * Returns `{ action, mint, unjudged }`: the freeze to send, if any, and the
 * mints still waiting for a figure.
 */
export function judgeReplayedWindow(state, unjudged, worst, now, policy = DEFAULT_POLICY) {
  const none = new Set();
  if (unjudged.size === 0) return { action: null, mint: null, unjudged: none };
  if (now < state.frozenUntil || state.freezing) return { action: null, mint: null, unjudged: none };
  const left = new Set();
  for (const mint of unjudged) {
    const figure = worst(mint);
    if (!figure) {
      left.add(mint);
      continue;
    }
    const action = breach(state, mint, { ...figure, now }, policy);
    if (action) return { action, mint, unjudged: none };
  }
  return { action: null, mint: null, unjudged: left };
}

export function vetoKey(action) {
  if (action.type === "veto_change") return `c${action.changeId}`;
  if (action.type === "veto_exit") return `x${action.mint}:${action.executableS}`;
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
    if (!chain.pendingKind || chain.pendingVetoed) return "drop";
    if (BigInt(chain.pendingId) !== BigInt(action.proposalId)) return "drop";
    return "send";
  }
  if (action.type === "veto_change") {
    if (!chain) return "keep";
    if (chain.vetoed || chain.executed) return "drop";
    return "send";
  }
  if (action.type === "veto_exit") {
    if (!chain) return "keep";
    // A new proposal has a new executable time and gets its own veto.
    if (!chain.exitAmount || chain.exitVetoed || chain.exitExecutableS !== action.executableS) return "drop";
    return "send";
  }
  return "drop";
}

/** Vetoed and executed flags of a `BHCHNG01` account. Null if it is not one. */
export function readChangeVeto(bytes) {
  const c = readPendingChange(bytes);
  return c && { vetoed: c.vetoed, executed: c.executed };
}

/** bulkhead-core `MIN_HEARTBEAT_INTERVAL_S` and `MAX_HEARTBEAT_INTERVAL_S`. */
const MIN_HEARTBEAT_INTERVAL_S = DAY_S;
const MAX_HEARTBEAT_INTERVAL_S = 30 * DAY_S;
/** How far past its chain deadline a key must be before it is written off. */
const STANDING_GRACE_S = 600;

/**
 * Where this key stands on one account's guardian list (a decoded Vault
 * protocol or Floor config), by bulkhead-core `guardian_alive`. Only a live
 * guardian's heartbeat lands: once the interval has passed, no heartbeat can
 * revive the key, and sending one only spends fees.
 *   undefined account (unreadable) -> "unknown": send, it is the safe guess
 *   null account, or a key not on the list -> "absent"
 * `deadlineS` is when a live guardian stops counting.
 */
export function guardianStanding(account, guardian, nowS) {
  if (account === undefined) return { standing: "unknown" };
  const i = account?.guardians?.indexOf(guardian) ?? -1;
  if (i < 0) return { standing: "absent" };
  const interval = Number(account.heartbeatIntervalS);
  const last = Number(account.lastHeartbeat?.[i]);
  const inRange = interval >= MIN_HEARTBEAT_INTERVAL_S && interval <= MAX_HEARTBEAT_INTERVAL_S;
  // This clock is not the chain's. A heartbeat stamped ahead of it is fresh,
  // and a key is written off only well past its deadline: sending a few
  // heartbeats too many costs little, stopping one too early loses the key.
  if (inRange && nowS - last <= interval + STANDING_GRACE_S) return { standing: "live", deadlineS: last + interval };
  return { standing: "dead", lastS: last, intervalS: interval };
}

export const HEARTBEAT_RETRY_MS = 15_000;
export const HEARTBEAT_RETRY_MAX_MS = 600_000;
/** How often an absent or dead key's standing is read again. Nothing is sent. */
export const HEARTBEAT_RECHECK_MS = 3_600_000;

/**
 * When to look at one heartbeat target again, and its failure count.
 * `outcome`: "sent", "failed", "absent" or "dead". A failure backs off from
 * 15 s, doubling to 10 minutes, but never waits more than a quarter of the
 * time the guardian has left (`deadlineMs`), so it is retried well before it
 * goes stale. A success waits the period (`everyMs`).
 */
export function afterHeartbeat({ outcome, failures = 0, nowMs, everyMs, deadlineMs = null }) {
  if (outcome === "sent") return { nextAt: nowMs + everyMs, failures: 0 };
  if (outcome !== "failed") return { nextAt: nowMs + HEARTBEAT_RECHECK_MS, failures: 0 };
  const n = failures + 1;
  let wait = Math.min(HEARTBEAT_RETRY_MAX_MS, HEARTBEAT_RETRY_MS * 2 ** (n - 1));
  if (deadlineMs !== null && deadlineMs > nowMs) wait = Math.min(wait, Math.floor((deadlineMs - nowMs) / 4));
  return { nextAt: nowMs + Math.max(HEARTBEAT_RETRY_MS, wait), failures: n };
}

/** Period after a protocol-account read. An unreadable account uses the
 * shortest legal chain interval, so a configured period equal to that
 * window is still pulled inside it. */
export function heartbeatEveryAfterAccount(policyEveryS, chainIntervalS) {
  const interval = Number(chainIntervalS);
  return heartbeatEverySeconds(policyEveryS, interval > 0 ? interval : DAY_S);
}

/** Seconds between heartbeats. A period equal to the chain interval lands
 * after the deadline once confirmation is observed, and a stale guardian
 * cannot revive itself. Stay at least an hour, and at least a tenth of the
 * interval, inside the chain window.
 */
export function heartbeatEverySeconds(everyS, chainIntervalS) {
  const every = Number(everyS);
  if (!(every > 0)) return every;
  const interval = Number(chainIntervalS);
  if (!(interval > 0)) return every;
  const slack = Math.max(3_600, Math.floor(interval / 10));
  const ceiling = interval - slack;
  if (ceiling <= 0) return every;
  return Math.min(every, ceiling);
}

/** A `BHCHNG01` account still waiting, or null. */
export function readPendingChange(bytes) {
  if (!bytes) return null;
  try {
    const { protocol, id, kind, vetoed, executed, target, executableS, expiresS, payload } = decodeChange(bytes);
    return { protocol, id, kind, vetoed, executed, target, executableS, expiresS, payload };
  } catch {
    return null;
  }
}

/** Veto a loosening that is still pending. History replay does not send
 * actions, so a restart has to read the account. `already` is `state.vetoed`.
 */
export function pendingChangeVeto(change, policy, now, already) {
  if (!policy.vetoLoosenings || !change || change.vetoed || change.executed) return null;
  if (Number.isFinite(change.expiresS) && now >= change.expiresS) return null;
  const id = BigInt(change.id);
  if (already?.has(`c${id}`)) return null;
  if (changeApproved(change, policy)) return null;
  return { type: "veto_change", changeId: id, reason: `loosening ${id} (kind ${change.kind}) is still pending and not approved` };
}

function exitApproved(policy, mint, amount) {
  return (policy.approvedExits ?? []).includes(`${mint}:${BigInt(amount)}`);
}

/** Veto a lifeboat exit that is still pending (a decoded vault). Same rule as
 * a live `vault:exit_proposed` event. `already` is `state.vetoed`.
 */
export function pendingExitVeto(vault, policy, now, already) {
  if (!policy.vetoLifeboatExits || !vault?.exitAmount || vault.exitVetoed) return null;
  if (Number.isFinite(vault.exitExpiresS) && now >= vault.exitExpiresS) return null;
  if (exitApproved(policy, vault.mint, vault.exitAmount)) return null;
  const action = { type: "veto_exit", mint: vault.mint, executableS: vault.exitExecutableS, reason: `lifeboat exit of ${vault.exitAmount} is still pending` };
  return already?.has(vetoKey(action)) ? null : action;
}

/** A Vault change the keeper should execute now, or null: approved (by what
 * it does), not vetoed or executed, due and not expired. `done` holds ids
 * already sent. */
export function dueApprovedChange(change, policy, now, done) {
  if (!policy.executeApproved || !change || change.vetoed || change.executed) return null;
  const id = BigInt(change.id);
  if (done?.has(`c${id}`)) return null;
  if (!changeApproved(change, policy)) return null;
  if (now < change.executableS || now >= change.expiresS) return null;
  return { type: "execute_change", changeId: id, kind: change.kind, target: change.target };
}

/** A Floor proposal the keeper should execute now, or null: approved (code by
 * buffer, anything else by program:id), not vetoed, due and not expired, and
 * never a release of the upgrade authority. */
export function dueApprovedFloor(floor, policy, now, done) {
  if (!policy.executeApproved || !floor?.pendingKind || floor.pendingVetoed) return null;
  if (floor.pendingKind === 3) return null;
  const id = BigInt(floor.pendingId);
  if (done?.has(`e${floor.program}:${id}`)) return null;
  if (floorProposalVeto({ program: floor.program, kind: floor.pendingKind, id, target: floor.pendingTarget, payload: floor.pendingPayload }, policy)) return null;
  if (now < floor.pendingEta || now >= floor.pendingExpires) return null;
  return { type: "execute_floor", program: floor.program, proposalId: id, kind: floor.pendingKind, target: floor.pendingTarget };
}

/** Floor proposal kinds (programs/floor/src/state.rs `kind`). */
const FLOOR_KINDS = { 1: "upgrade", 2: "restore", 3: "release of the upgrade authority", 4: "new guardian set", 5: "new owner", 6: "lower upgrade delay", 7: "new recovery key" };

/**
 * Why a Floor proposal must be vetoed, or null if it is pre-approved. Every
 * kind waits the delay and is vetoable, and every one can hand the program
 * to whoever holds the owner key: new code, the upgrade authority itself, the
 * owner, the guardians, or a shorter delay for all of those. Code is approved
 * by buffer, anything else by what it does (`floorApproval`). A live event
 * carries no payload (`payload` undefined): a proposal whose kind and target
 * match an approval waits for the account scan, which compares the payload.
 */
export function floorProposalVeto({ program, kind, target, payload }, policy) {
  const what = FLOOR_KINDS[kind] ?? `kind ${kind}`;
  if (kind === 1 || kind === 2) {
    if ((policy.approvedUpgradeBuffers ?? []).includes(target)) return null;
    return `${what} to unapproved buffer ${target}`;
  }
  const approvals = policy.approvedFloorProposals ?? [];
  if (payload === undefined) {
    if (approvals.some((a) => a.startsWith(`${program}:${kind}:${target}:`))) return null;
  } else if (approvals.includes(floorApproval({ program, kind, target, payload }))) {
    return null;
  }
  return `${what} (target ${target}) is not pre-approved`;
}

/** Veto a Floor proposal that is still pending. Same rule as a live
 * `floor:proposed` event (`floorProposalVeto`).
 */
export function pendingUpgradeVeto(floor, policy, already) {
  if (!floor || !floor.pendingKind || floor.pendingVetoed) return null;
  const id = BigInt(floor.pendingId);
  if (already?.has(`f${floor.program}:${id}`)) return null;
  const why = floorProposalVeto({ program: floor.program, kind: floor.pendingKind, target: floor.pendingTarget, payload: floor.pendingPayload ?? new Uint8Array(0) }, policy);
  if (!why) return null;
  return { type: "floor_veto", program: floor.program, proposalId: id, reason: `${why} is still pending` };
}

/** Record a protocol-wide freeze observed on chain and cancel known queued tickets. */
/** A guardian freeze landed: an incident is open from then (renewals keep its start). */
export function openIncident(state, now) {
  if (state.incidentSince == null) state.incidentSince = now;
}

/**
 * The protocol's freeze end moved from `prevUntil` to `until`. A freeze only
 * ever moves the end later (to the later of the two), and only a guardian
 * quorum's unfreeze moves it earlier (to the moment it ran): so an end that
 * moved earlier is a quorum's decision, and closes the incident. A freeze that
 * simply ran out leaves the end where it was. Comparing ends, not clocks, also
 * holds across a restart that missed the unfreeze.
 */
export function observeFreezeEnd(state, prevUntil, until) {
  if (until < prevUntil) state.incidentSince = null;
}

/**
 * The renewal the incident hold needs now, or null: once the freeze has less
 * than `holdRenewBeforeS` left (or has already run out, say while this
 * guardian was down), freeze again, never past the hold's end. The program
 * extends a freeze to the later end, so a renewal never shortens one.
 */
export function incidentHold(state, chainFrozenUntil, now, policy = DEFAULT_POLICY) {
  const holdS = policy.holdIncidentS ?? 0;
  if (!holdS || state.incidentSince == null || state.freezing) return null;
  const end = state.incidentSince + holdS;
  if (now >= end) {
    state.incidentSince = null;
    return null;
  }
  if (chainFrozenUntil - now > (policy.holdRenewBeforeS ?? 3_600)) return null;
  const secs = Math.min(policy.freezeSecs, end - now);
  return { type: "freeze", secs, reason: `incident hold: frozen since ${state.incidentSince}; renewed until a guardian quorum unfreezes, at most until ${end}` };
}

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
      if (ticket !== null) rememberTicket(state, { ticketId: ticket, mint: e.mint, vault: e.vault, owner: e.owner, amount: e.queued, address: e.ticket });
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
      // Only a guardian quorum unfreezes, and it has weighed everything up to
      // then: those outflows no longer count toward a freeze (a restart that
      // replays the last 24h must not freeze again on them), and an incident
      // that started before it is over. One that started later (the replay
      // of an older unfreeze) is not.
      state.outflows = state.outflows.filter((o) => o.t > ctx.now);
      if (state.incidentSince != null && state.incidentSince <= ctx.now) state.incidentSince = null;
      break;
    case "ticket_closed":
      state.pendingTickets.delete(e.ticketId);
      state.cancelled.delete(e.ticketId);
      break;
    case "change_proposed":
      if (!act) break;
      // The event has no payload: a change that may be approved is left to
      // the account scan, which vetoes it unless its payload matches too.
      if (policy.vetoLoosenings && !changeMayBeApproved(e.changeKind, e.target, policy) && !state.vetoed.has(`c${e.id}`)) {
        state.vetoed.add(`c${e.id}`);
        actions.push({ type: "veto_change", changeId: e.id, reason: `loosening ${e.id} (kind ${e.changeKind}) is not pre-approved` });
      }
      break;
    case "exit_proposed": {
      if (!act || !policy.vetoLifeboatExits || exitApproved(policy, e.mint, e.amount)) break;
      const action = { type: "veto_exit", mint: e.mint, executableS: e.executableS, reason: `lifeboat exit of ${e.amount} is not pre-approved` };
      if (state.vetoed.has(vetoKey(action))) break;
      state.vetoed.add(vetoKey(action));
      actions.push(action);
      break;
    }
    case "floor_proposed":
      if (!act) break;
      {
        const why = floorProposalVeto({ program: e.program, kind: e.proposalKind, target: e.target }, policy);
        if (why && !state.vetoed.has(`f${e.program}:${e.id}`)) {
          state.vetoed.add(`f${e.program}:${e.id}`);
          actions.push({ type: "floor_veto", program: e.program, proposalId: e.id, reason: why });
        }
      }
      break;
  }
  return actions;
}
