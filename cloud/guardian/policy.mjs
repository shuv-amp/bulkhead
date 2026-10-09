// The guardian's decision rules: pure functions from on-chain events to
// actions. No I/O here, so every rule is unit-tested (cloud/test).
//
// A guardian can only stop things: freeze (≤ 24h, repeatable), cancel tickets,
// veto proposals, and (under Floor) abort. It can never move funds or choose a
// recipient; the programs enforce that, not this file.

import { b58encode, Reader, decodeChange, parseLogs } from "../lib/solana.mjs";

const hex = (bytes) => Array.from(bytes ?? [], (x) => x.toString(16).padStart(2, "0")).join("");

/** How a Vault change is approved in `approvedChanges`: the kind, target and
 * payload of its `propose_change`, exactly as proposed. An approval may add
 * "#<base version>" (`pinnedChangeApproval`), and may end in "@<unix
 * seconds>": from then on it approves nothing. */
export function changeApproval({ kind, target, payload }) {
  return `${kind}:${target}:${hex(payload)}`;
}

/**
 * The approval of one proposal of a Vault change, pinned to the version of
 * its target it was proposed against ("kind:target:payloadHex#<base
 * version>"). The program records that version in the change account and
 * executes the change only while the target is still at it, and every
 * execution moves the version on: a proposal of the same content made after
 * this one ran carries a newer version, so a pinned approval can never
 * approve a replay, whatever this guardian remembers (docs/09, finding 71).
 * Spending on execution (`spendExecution`) is only for unpinned ones.
 */
export function pinnedChangeApproval(change) {
  return `${changeApproval(change)}#${change.baseVersion}`;
}

/** How a Floor proposal other than code is approved in `approvedFloorProposals`. */
export function floorApproval({ program, kind, target, payload }) {
  return `${program}:${kind}:${target}:${hex(payload)}`;
}

const B58 = "[1-9A-HJ-NP-Za-km-z]{32,44}";
const CHANGE_APPROVAL = new RegExp(`^\\d+:${B58}:([0-9a-f]{2})*(#\\d+)?(@\\d+)?$`);
const FLOOR_APPROVAL = new RegExp(`^${B58}:\\d+:${B58}:([0-9a-f]{2})*(@\\d+)?$`);

/** An approval's content ("kind:target:payloadHex", or Floor's), the base
 * version it is pinned to (null: none) and its expiry (null: none). */
export function parseApproval(a) {
  const at = a.lastIndexOf("@");
  const expiresS = at < 0 ? null : Number(a.slice(at + 1));
  let content = at < 0 ? a : a.slice(0, at);
  const hash = content.lastIndexOf("#");
  const version = hash < 0 ? null : Number(content.slice(hash + 1));
  if (hash >= 0) content = content.slice(0, hash);
  return { content, version, expiresS };
}

/**
 * The configured approvals that still approve at `now`. An unpinned approval
 * is spent once a change matching it has executed (`consumed`: approval ->
 * the execution that spent it, kept across restarts). Before, an approval
 * matched every later proposal of the same content: a thief holding the
 * admin key re-proposed an approved change that had already run, after the
 * operators had moved on (an old admin, guardian set or recovery key), and
 * the guardian let it through and its keeper executed it. To approve the
 * same content again, add it again with an expiry: that is another approval.
 * A pinned approval is never spent: the chain retires it (`pinnedChangeApproval`).
 */
function liveApprovals(list, now, consumed) {
  return (list ?? []).filter((a) => {
    const { expiresS } = parseApproval(a);
    return (expiresS === null || now < expiresS) && !consumed?.has(a);
  });
}

/** Whether an approval in `list` approves `content` at `now`. `baseVersion`
 * is the proposal's (a Vault change account's): a pinned approval approves
 * only that version, and nothing while it is not known. */
function approves(list, content, now, consumed, baseVersion) {
  return liveApprovals(list, now, consumed).some((a) => {
    const p = parseApproval(a);
    return p.content === content && (p.version === null || (baseVersion != null && p.version === Number(baseVersion)));
  });
}
const approvesPrefix = (list, prefix, now, consumed) => liveApprovals(list, now, consumed).some((a) => parseApproval(a).content.startsWith(prefix));

/**
 * Spend one approval of `content` on the execution `by` ("c<id>" for a Vault
 * change, "e<program>:<id>" for Floor) at `now`. Seeing the same execution
 * again (the next scan, its event) spends nothing more. Returns the approval
 * spent, or null.
 *
 * Only an approval still live at `now` is spent, the one that expires first
 * (one without an expiry last), and never a pinned one. The first unspent
 * match used to be spent even when it had already expired: a live approval
 * of the same content stayed unspent and approved a replay of the change
 * that had just run (docs/09, finding 71).
 */
export function consumeApproval(consumed, list, content, by, now) {
  for (const used of consumed.values()) if (used === by) return null;
  const candidates = liveApprovals(list, now, consumed).filter((x) => {
    const p = parseApproval(x);
    return p.content === content && p.version === null;
  });
  if (!candidates.length) return null;
  const order = (x) => parseApproval(x).expiresS ?? Infinity;
  const a = candidates.reduce((best, x) => (order(x) < order(best) ? x : best));
  consumed.set(a, by);
  return a;
}

/**
 * Spend the approval an execution ran on, once per execution ever seen
 * (`state.executedSeen`, kept across restarts). A Vault change spends only
 * once there is a baseline (`state.changeBaseline`): change accounts are
 * never closed, so a guardian with a fresh or lost state file read a change
 * that ran long ago as a new execution, spent today's approval of the same
 * content on it, and vetoed the operators' pending change (one guardian's
 * veto is final). Without a baseline, the first scan (`observeExecutions`)
 * records every change already executed and spends nothing (docs/09,
 * finding 71). An execution seen as it happens (`live`: its event read live,
 * or the keeper's own) is new whatever the baseline, and spends.
 * Returns the approval spent, or null.
 */
export function spendExecution(state, list, content, by, now, { live = false } = {}) {
  if (by.startsWith("c") && !state.changeBaseline && !live) return null;
  if (state.executedSeen.has(by)) return null;
  state.executedSeen.add(by);
  return content ? consumeApproval(state.consumed, list, content, by, now) : null;
}

/**
 * One program-account scan of change accounts: each executed change not seen
 * before spends its approval (`spendExecution`). The first scan without a
 * baseline only records them all. Returns what was spent, by which change.
 */
export function observeExecutions(state, changes, list, now) {
  const executed = changes.filter((c) => c?.executed);
  if (!state.changeBaseline) {
    for (const c of executed) state.executedSeen.add(`c${BigInt(c.id)}`);
    state.changeBaseline = true;
    return [];
  }
  const spent = [];
  for (const c of executed) {
    const a = spendExecution(state, list, changeApproval(c), `c${BigInt(c.id)}`, now);
    if (a) spent.push({ approval: a, change: c });
  }
  return spent;
}

/** The Vault approvals not pinned to a base version: they lean on this
 * guardian's own record of what has executed. Reported at startup. */
export function unpinnedChangeApprovals(policy) {
  return (policy.approvedChanges ?? []).filter((a) => parseApproval(a).version === null);
}

/**
 * Refuses a policy whose approvals could not mean what the operators think.
 * Approvals by id (`approvedChangeIds`, "program:id") were replaced: an id
 * names whatever is proposed under it, so a guardian still reading one would
 * let a thief's change through and execute it.
 */
/** Each policy field's type and range. A typo, a percent for a fraction or a
 * string for a number used to pass and quietly turn a rule off, or send a
 * heartbeat every poll (docs/09, finding 83). */
const POLICY_RULES = {
  freezeFractionOfWorst1h: ["fraction>0"],
  freezeFractionOfWorst24h: ["fraction>0"],
  freezeFractionOfWorst72h: ["fraction"],
  alertFractionOfThreshold: ["fraction"],
  sustainedDays: ["int", 1, 3],
  outflowAlertEveryS: ["int", 60, 7 * 86_400],
  freezeSecs: ["int", 1, 86_400],
  holdIncidentS: ["int", 0, 30 * 86_400],
  holdRenewBeforeS: ["int", 1, 86_400],
  allowlistedOwners: ["keys"],
  cancelTicketsWhenFrozen: ["bool"],
  vetoLoosenings: ["bool"],
  approvedChanges: ["array"],
  approvalCheckGiveUpS: ["int", 1, 86_400],
  approvedUpgradeBuffers: ["keys"],
  approvedFloorProposals: ["array"],
  executeApproved: ["bool"],
  vetoLifeboatExits: ["bool"],
  approvedExits: ["array"],
  heartbeatEveryS: ["int", 3_600, 30 * 86_400],
  computeUnits: ["int", 5_000, 1_400_000],
  priorityMicroLamports: ["price"],
  maxPriorityMicroLamports: ["int", 0, 1e12],
  minPriorityMicroLamports: ["int", 0, 1e12],
  freezeMinPriorityMicroLamports: ["int", 0, 1e12],
  freezeDeadlineS: ["int", 10, 3_600],
};
const BASE58_KEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function checkField(name, v, [kind, lo, hi]) {
  const bad = (what) => { throw new Error(`policy.${name}: ${JSON.stringify(v)} is not ${what}`); };
  switch (kind) {
    case "fraction>0": if (typeof v !== "number" || !(v > 0 && v <= 1)) bad("a fraction in (0, 1] (0.5 is half; not a percent)"); break;
    case "fraction": if (typeof v !== "number" || !(v >= 0 && v <= 1)) bad("a fraction in [0, 1] (0 turns the rule off; not a percent)"); break;
    case "int": if (typeof v !== "number" || !Number.isInteger(v) || v < lo || v > hi) bad(`a whole number from ${lo} to ${hi}`); break;
    case "bool": if (typeof v !== "boolean") bad("true or false"); break;
    case "array": if (!Array.isArray(v)) bad("a list"); break;
    case "keys": if (!Array.isArray(v) || !v.every((k) => typeof k === "string" && BASE58_KEY.test(k))) bad("a list of base58 addresses"); break;
    case "price": if (v !== "auto" && (typeof v !== "number" || !Number.isInteger(v) || v < 0)) bad('"auto" or a whole number of micro-lamports per compute unit'); break;
  }
}

export function checkPolicy(policy) {
  if ("approvedChangeIds" in policy) {
    throw new Error('policy.approvedChangeIds is no longer read: approve a change by what it does, in approvedChanges as "kind:target:payloadHex" (docs/07)');
  }
  for (const name of Object.keys(policy)) {
    if (!(name in POLICY_RULES)) throw new Error(`policy.${name} is not a policy setting (a typo? the settings are DEFAULT_POLICY's, cloud/guardian/policy.mjs)`);
    checkField(name, policy[name], POLICY_RULES[name]);
  }
  if (policy.minPriorityMicroLamports > policy.maxPriorityMicroLamports || policy.freezeMinPriorityMicroLamports > policy.maxPriorityMicroLamports) {
    throw new Error("policy: the minimum priority prices must not exceed maxPriorityMicroLamports");
  }
  if (policy.holdRenewBeforeS >= policy.freezeSecs) throw new Error("policy.holdRenewBeforeS must be shorter than freezeSecs, or the hold renews every pass");
  for (const a of policy.approvedChanges ?? []) {
    if (typeof a !== "string" || !CHANGE_APPROVAL.test(a)) throw new Error(`policy.approvedChanges: ${JSON.stringify(a)} is not "kind:target:payloadHex[#baseVersion][@expiry]"`);
  }
  for (const a of policy.approvedFloorProposals ?? []) {
    if (typeof a !== "string" || !FLOOR_APPROVAL.test(a)) throw new Error(`policy.approvedFloorProposals: ${JSON.stringify(a)} is not "program:kind:target:payloadHex[@expiry]" (approvals by id were replaced)`);
  }
  return policy;
}

/** A change account (decoded, with its payload and base version) the
 * operators approved, by an approval neither expired at `now` nor spent, and
 * pinned to its base version if pinned at all. */
function changeApproved(change, policy, now, consumed) {
  return change.payload !== undefined && approves(policy.approvedChanges, changeApproval(change), now, consumed, change.baseVersion);
}

/** A live proposal event names the kind and target but neither the payload
 * nor the base version: it could be an approved change. The change account is
 * then read by its id, and decides with both (`checkProposedChange`). */
function changeMayBeApproved(kind, target, policy, now, consumed) {
  return approvesPrefix(policy.approvedChanges, `${kind}:${target}:`, now, consumed);
}

export const DEFAULT_POLICY = {
  /** Freeze when unbacked outflow to non-allowlisted owners within the last
   * hour reaches this fraction of the program's own `worst_1h` figure. */
  freezeFractionOfWorst1h: 0.5,
  /** Freeze when unbacked outflow to non-allowlisted owners within the last
   * 24 hours reaches this fraction of the program's own `worst_24h` figure.
   * It stops a greedy drip: an attacker who keeps every rolling hour just
   * under the 1-hour rule is frozen within hours (cloud/test/adversarial.test.mjs).
   * It does not stop a patient one. With the default limits 0.5 × worst_24h
   * is 5% of the base a day, which is the program's own sustained daily rate
   * (longBps 500): an attacker who stays under it in every rolling 24 hours
   * loses nothing but the first day's burst, and took ~77% of a 10M vault in
   * 30 days with no freeze and no alert (docs/09, finding 76). The 72-hour
   * rule and the outflow alerts below are the answer to that, not this rule.
   * 0 disables the rule. Keep it above the calibrated honest daily unbacked
   * flow (docs/07 §4: defaults are 1.5× that ceiling, so 5% / 1.5 ≈ 3.3% a day). */
  freezeFractionOfWorst24h: 0.5,
  /** Freeze when unbacked outflow to non-allowlisted owners within the last
   * 72 hours reaches this fraction of the worst the program allows over 72
   * hours (the limiter port, `maxUnbackedOver(params, 72h)`: 20% of the base
   * with the defaults). At 0.55 that is 11% of the base per 72 hours, ~3.7%
   * a day: just above the honest ceiling (3.3% a day, docs/07 §4). 0.5 is the
   * ceiling itself, and froze honest flow at it on a vault with no deposits
   * after ~69h, since the window looks back at a larger base. A patient
   * attacker is cut from the program's 5% of the base a day to ~3.7%, and no
   * lower: measured over 30 days on a 10M vault, ~65% taken instead of ~77%
   * (cloud/test/adversarial.test.mjs). A threshold bot cannot tell a drip
   * under the honest ceiling from honest flow; the alerts below tell people,
   * who can (docs/09, finding 76). 0 disables. */
  freezeFractionOfWorst72h: 0.55,
  /** Alert (urgent, not a freeze) once unbacked outflow to non-allowlisted
   * owners over 24 hours reaches this fraction of the 24-hour freeze
   * threshold, at most once per `outflowAlertEveryS` per mint; and alert a
   * sustained drip when that happened on at least `sustainedDays` of the
   * last 3 UTC days. Release events alone are info lines and never alerted:
   * a patient attacker used to take most of a vault in silence (finding 76). */
  alertFractionOfThreshold: 0.5,
  sustainedDays: 2,
  outflowAlertEveryS: 6 * 3_600,
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
   * take their approval (and the keeper would execute its change). Pin an
   * approval to the base version its proposal records,
   * "kind:target:payloadHex#<version>" (`pinnedChangeApproval`): it can then
   * never approve a replay. An unpinned one is spent once a matching change
   * executes. Either may carry an expiry, "...@<unix seconds>" (`liveApprovals`). */
  vetoLoosenings: true,
  approvedChanges: [],
  /** A live proposal that may be approved is checked by reading its change
   * account. One still unreadable after this many seconds is vetoed: an
   * unread payload is not an approved one. */
  approvalCheckGiveUpS: 600,
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
  /** The least price for any guardian transaction, and for a freeze, whatever
   * recent fees say: a quiet protocol account shows 0 (docs/09, finding 82).
   * At 50,000 units, 100,000 µL/CU is 5,000 lamports. */
  minPriorityMicroLamports: 10_000,
  freezeMinPriorityMicroLamports: 100_000,
  /** How long a freeze keeps signing again at a doubled price before it is
   * handed to the next loop pass (and alerted). */
  freezeDeadlineS: 90,
};

/** The settings a guardian config may have (cloud/guardian/main.mjs). */
const CONFIG_KEYS = new Set(["rpc", "rpcs", "vaultProgram", "protocolProgram", "mints", "guardianKey", "pollMs", "policy", "floorProgram", "floorProtected", "alert", "stateFile", "stallAlertS", "lagAlertS", "ingestBudgetMs", "ingestConcurrency", "freshnessCheckS", "startupMaxSignatures", "cluster", "minBalanceSol", "liveness"]);
/** Genesis hashes of the clusters a config may name (`cluster`). */
export const GENESIS = { "mainnet-beta": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", devnet: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG", testnet: "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY" };

/**
 * A guardian config, checked before anything runs: unknown settings (typos),
 * wrong types, out-of-range numbers. `cluster: "mainnet-beta"` also requires
 * what production needs: at least one backup endpoint (`rpcs`) and an alert
 * webhook, since a guardian nobody hears is no guardian (docs/09, finding 83).
 * Returns warnings to log; throws on an error.
 */
export function checkConfig(cfg) {
  const warnings = [];
  if (!cfg || typeof cfg !== "object") throw new Error("the config is not a JSON object");
  for (const k of Object.keys(cfg)) if (!CONFIG_KEYS.has(k)) throw new Error(`config.${k} is not a guardian setting (a typo? see the header of cloud/guardian/main.mjs)`);
  const url = (u) => typeof u === "string" && /^https?:\/\//.test(u);
  if (!url(cfg.rpc)) throw new Error("config.rpc must be an http(s) URL");
  if (cfg.rpcs !== undefined && (!Array.isArray(cfg.rpcs) || !cfg.rpcs.every(url))) throw new Error("config.rpcs must be a list of http(s) URLs");
  for (const k of ["vaultProgram", "protocolProgram"]) if (!BASE58_KEY.test(cfg[k] ?? "")) throw new Error(`config.${k} must be a base58 address`);
  if (!Array.isArray(cfg.mints) || !cfg.mints.every((m) => BASE58_KEY.test(m))) throw new Error("config.mints must be a list of base58 mint addresses");
  if (typeof cfg.guardianKey !== "string") throw new Error("config.guardianKey must be the path of the guardian's keypair file");
  for (const [k, lo, hi] of [["pollMs", 100, 10_000], ["stallAlertS", 10, 86_400], ["lagAlertS", 5, 86_400], ["ingestBudgetMs", 200, 60_000], ["ingestConcurrency", 1, 64], ["freshnessCheckS", 10, 3_600], ["startupMaxSignatures", 1_000, 10_000_000], ["minBalanceSol", 0, 1_000]]) {
    const v = cfg[k];
    if (v !== undefined && (typeof v !== "number" || !(v >= lo && v <= hi))) throw new Error(`config.${k}: ${JSON.stringify(v)} is not a number from ${lo} to ${hi}`);
  }
  if (cfg.floorProtected !== undefined && (!Array.isArray(cfg.floorProtected) || !cfg.floorProtected.every((m) => BASE58_KEY.test(m)) || !BASE58_KEY.test(cfg.floorProgram ?? ""))) throw new Error("config.floorProtected must be a list of program addresses, with config.floorProgram set");
  if (cfg.alert !== undefined && !url(cfg.alert?.url)) throw new Error("config.alert.url must be an http(s) URL");
  if (cfg.liveness !== undefined && (!url(cfg.liveness?.url) || (cfg.liveness.everyS !== undefined && !(cfg.liveness.everyS >= 10)))) throw new Error("config.liveness must be { url, everyS ≥ 10 }");
  if (cfg.cluster !== undefined && !(cfg.cluster in GENESIS) && cfg.cluster !== "localnet") throw new Error(`config.cluster must be one of ${[...Object.keys(GENESIS), "localnet"].join(", ")}`);
  if (cfg.cluster === "mainnet-beta") {
    if (!cfg.rpcs?.length) throw new Error("a mainnet guardian needs at least one backup endpoint (config.rpcs) from another provider (docs/07 §6)");
    if (!cfg.alert) throw new Error("a mainnet guardian needs config.alert: without it nobody is told of a freeze, an error or a dead key");
    if (!cfg.liveness) warnings.push("no config.liveness: if this process or its host dies, nothing tells anyone (docs/07 §6)");
  } else if (cfg.cluster === undefined) {
    warnings.push("config.cluster is not set: the RPC's cluster is not checked, and production requirements (backup endpoints, alerts) are not enforced");
  }
  if (!cfg.alert) warnings.push("no config.alert: actions, errors and urgent warnings go to this log only, and page nobody");
  return warnings;
}

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
  return { outflows: [], frozenUntil: 0, cancelled: new Set(), vetoed: new Set(), tickets: new Set(), pendingTickets: new Map(), freezing: false, incidentSince: null, consumed: new Map(), executedSeen: new Set(), changeBaseline: false, drip: new Map() };
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

/**
 * How many fields each Vault event the guardian reads carries before the
 * protocol key the program appends last (programs/vault/src/sys.rs `event`).
 * The count is exact, so an event from a build that appended nothing cannot
 * pass a field of its own (a ticket, a recovery key) off as the protocol.
 */
const VAULT_FIELDS = {
  "vault:released": 4, "vault:frozen": 3, "vault:unfrozen": 2, "vault:change_proposed": 4, "vault:change_executed": 2,
  "vault:exit_proposed": 3, "vault:lifeboat_in": 2, "vault:recovery_replaced": 2, "vault:settled": 2, "vault:ticket_cancelled": 2,
};

/** The protocol a Vault event names, or null when it names none. */
export function eventProtocol(ev) {
  const n = VAULT_FIELDS[ev.name];
  const f = ev.fields ?? [];
  return n !== undefined && f.length === n + 1 && f[n]?.length === 32 ? b58encode(f[n]) : null;
}

/** A recovery key, or null for all zero: the key was removed, not set to 1111…. */
const recoveryKey = (k) => (k?.length === 32 && k.some((b) => b !== 0) ? b58encode(k) : null);

/** Decodes the events the guardian acts on. A Vault event also names its
 * `protocol` (null when it names none). */
export function decode(ev) {
  const e = decodeFields(ev);
  if (ev.name?.startsWith("vault:")) e.protocol = eventProtocol(ev);
  return e;
}

function decodeFields(ev) {
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
    // The admin (Floor: the owner) and a guardian quorum replaced the
    // recovery key: rare, and people should know it happened.
    case "vault:recovery_replaced":
      return { kind: "recovery_replaced", recovery: recoveryKey(f[0]) };
    case "floor:recovery_replaced":
      return { kind: "recovery_replaced", program: b58encode(f[0]), recovery: recoveryKey(f[1]) };
    case "floor:proposed":
      return { kind: "floor_proposed", program: b58encode(f[0]), proposalKind: f[1][0], id: u64(f[2]), target: b58encode(f[3]) };
    // An execution spends the approval it ran on (`consumeApproval`). The
    // event has no payload: the change account (Vault) or the proposal last
    // seen pending (Floor) says which approval that was.
    case "vault:change_executed":
      return { kind: "change_executed", id: u64(f[0]), changeKind: f[1]?.[0] };
    // A stop, a guardian ejected, a restore and a restore approval
    // (programs/floor/src/lib.rs, `ev::ABORTED` and the others). These went
    // to "other" and were dropped: a stop was noticed only by the minute's
    // config check (45 s late on a validator), and one a quorum undid within
    // the minute, an ejection or a restore approval never at all (docs/09,
    // finding 76). Exact field counts, so a layout this guardian does not know
    // is dropped, never misread.
    case "floor:aborted":
      if (f.length !== 4 || f[0]?.length !== 32 || f[1]?.length !== 32 || f[3]?.length !== 8) return { kind: "other", name: ev.name };
      return { kind: "floor_aborted", program: b58encode(f[0]), by: b58encode(f[1]), snapshotValid: f[2]?.[0] === 1, at: Number(new Reader(f[3]).i64()) };
    case "floor:restored":
      if (f.length !== 2 || f[0]?.length !== 32 || f[1]?.length !== 1) return { kind: "other", name: ev.name };
      return { kind: "floor_restored", program: b58encode(f[0]), signers: f[1][0] };
    case "floor:ejected":
      if (f.length !== 2 || f[0]?.length !== 32 || f[1]?.length !== 32) return { kind: "other", name: ev.name };
      return { kind: "floor_ejected", program: b58encode(f[0]), removed: b58encode(f[1]) };
    case "floor:approved":
      if (f.length !== 3 || f[0]?.length !== 32 || f[1]?.length !== 8 || f[2]?.length !== 1) return { kind: "other", name: ev.name };
      return { kind: "floor_approved", program: b58encode(f[0]), proposalId: u64(f[1]), approvals: f[2][0] };
    case "floor:executed":
      // A release of the authority names its target where the others name an id.
      return f[1]?.[0] === 3 ? { kind: "other", name: ev.name } : { kind: "floor_executed", program: b58encode(f[0]), proposalKind: f[1]?.[0], id: u64(f[2]) };
    case "vault:settled":
    case "vault:ticket_cancelled":
      return { kind: "ticket_closed", ticketId: u64(f[0]) };
    default:
      return { kind: "other", name: ev.name };
  }
}

/**
 * The events of one transaction this guardian acts on, decoded, and whether
 * the log was truncated.
 *
 * One Vault program serves every protocol, and a transaction lists whatever
 * accounts its builder likes: one that merely lists this protocol's account
 * shows up in its signature history with another protocol's events. Those
 * used to be read as this protocol's, so a protocol anyone can register
 * could end this one's incident hold (`vault:unfrozen`), force freezes, veto
 * its approved changes by id, close its tickets in the guardian's books, and
 * explain away a truncated outflow (docs/09, finding 64). A Vault event now
 * names its protocol last, and only `protocol`'s count; one that names none
 * (an older build) is dropped, never guessed (`unnamed` counts them).
 * Floor events count only for the programs in `floorPrograms`.
 */
export function watchedEvents(logs, { vaultProgram = null, protocol = null, floorProgram = null, floorPrograms = [] }) {
  const { events, truncated } = parseLogs(logs);
  const out = [];
  let foreign = 0;
  let unnamed = 0;
  for (const raw of events) {
    // Written by another program: not an event (any program can write "Program data:").
    if (vaultProgram && raw.program === vaultProgram && raw.name.startsWith("vault:")) {
      const e = decode(raw);
      if (e.kind === "other") continue;
      if (e.protocol === null) unnamed++;
      else if (e.protocol !== protocol) foreign++;
      else out.push(e);
    } else if (floorProgram && raw.program === floorProgram && raw.name.startsWith("floor:")) {
      const e = decode(raw);
      if (e.kind !== "other" && floorPrograms.includes(e.program)) out.push(e);
    }
  }
  return { events: out, truncated, foreign, unnamed };
}

/** How long outflows are kept: the longest rule's window (the 72-hour rule). */
export const OUTFLOW_KEEP_S = 3 * DAY_S;

function sumsFor(state, mint, now) {
  // Drop only what is already older than the longest window. An outflow
  // dated after `now` stays: a decision made at an earlier timestamp must not
  // erase it, and it does not count until `now` catches up.
  state.outflows = state.outflows.filter((o) => o.t > now || now - o.t <= OUTFLOW_KEEP_S);
  const rows = state.outflows.filter((o) => o.mint === mint);
  const sumSince = (secs) => rows.filter((o) => o.t <= now && now - o.t <= secs).reduce((s, o) => s + o.amount, 0n);
  return { lastHour: sumSince(HOUR_S), lastDay: sumSince(DAY_S), last72h: sumSince(OUTFLOW_KEEP_S) };
}

function limitsFor(ctx, policy) {
  const fraction24h = policy.freezeFractionOfWorst24h ?? 0;
  const fraction72h = policy.freezeFractionOfWorst72h ?? 0;
  return {
    limit: scaleBy(ctx.worst1h ?? 0n, policy.freezeFractionOfWorst1h),
    limit24h: ctx.worst24h !== undefined && fraction24h > 0 ? scaleBy(ctx.worst24h, fraction24h) : null,
    fraction24h,
    // Skipped while the 72-hour figure is unknown (it is computed from the
    // vault account, not returned by `attest`).
    limit72h: ctx.worst72h != null && fraction72h > 0 ? scaleBy(ctx.worst72h, fraction72h) : null,
    fraction72h,
  };
}

/** The freeze rule `sums` breaks under `limits`, or null. An empty sum is not
 * a breach, even when a limit is 0. */
function brokenRule(sums, limits, policy) {
  const { lastHour, lastDay, last72h } = sums;
  const { limit, limit24h, fraction24h, limit72h, fraction72h } = limits;
  if (lastHour > 0n && lastHour >= limit) {
    return `unbacked outflow to non-allowlisted owners in the last hour: ${lastHour} ≥ ${limit} (${policy.freezeFractionOfWorst1h} × worst_1h)`;
  }
  if (lastDay > 0n && limit24h !== null && lastDay >= limit24h) {
    return `unbacked outflow to non-allowlisted owners in the last 24 hours: ${lastDay} ≥ ${limit24h} (${fraction24h} × worst_24h)`;
  }
  if (last72h > 0n && limit72h !== null && last72h >= limit72h) {
    return `unbacked outflow to non-allowlisted owners in the last 72 hours: ${last72h} ≥ ${limit72h} (${fraction72h} × worst_72h; docs/09, finding 76)`;
  }
  return null;
}

/**
 * Whether `mint`'s recorded window is already over a threshold. Used after
 * replaying history: `assess` only decides on a new release.
 * An empty window is not a breach, even when the limit is 0.
 */
export function breach(state, mint, ctx, policy = DEFAULT_POLICY) {
  const reason = brokenRule(sumsFor(state, mint, ctx.now), limitsFor(ctx, policy), policy);
  return reason ? { type: "freeze", secs: policy.freezeSecs, reason } : null;
}

/** UTC day number of a unix time. */
const dayOf = (t) => Math.floor(t / DAY_S);

/**
 * The alerts unbacked outflow of `mint` calls for at `ctx.now`, and the
 * record they are based on (`state.drip`, kept in the state file).
 *
 * A threshold bot cannot tell a drip under the honest ceiling from honest
 * flow, so it does not pretend to: it tells people. With the defaults a
 * patient attacker who stayed under both freeze rules took ~77% of a 10M
 * vault in 30 days, never frozen and with zero alerts, since release events
 * were info lines (docs/09, finding 76). Now:
 *   "outflow":   the 24-hour sum crossed `alertFractionOfThreshold` of the
 *                24-hour freeze threshold (at most once per
 *                `outflowAlertEveryS`);
 *   "sustained": it did on at least `sustainedDays` of the last 3 UTC days
 *                (each day's highest fraction is kept, so a restart, or a
 *                lost day of history, still counts it), at most once a day.
 * `alert` false records the day's maximum and returns nothing (a replay).
 */
export function outflowAlerts(state, mint, ctx, policy = DEFAULT_POLICY, alert = true) {
  const f = policy.alertFractionOfThreshold ?? 0;
  const { limit24h } = limitsFor(ctx, policy);
  if (!(f > 0) || limit24h === null || limit24h <= 0n) return [];
  const { lastDay } = sumsFor(state, mint, ctx.now);
  const rec = state.drip.get(mint) ?? { days: new Map(), alertedS: null, sustainedS: null };
  state.drip.set(mint, rec);
  // Fraction of the threshold, in thousandths (integers: amounts are BigInt).
  const permille = Number((lastDay * 1000n) / limit24h);
  const today = dayOf(ctx.now);
  if (permille > (rec.days.get(today) ?? 0)) rec.days.set(today, permille);
  for (const d of rec.days.keys()) if (d < today - 2) rec.days.delete(d);
  if (!alert) return [];
  const every = policy.outflowAlertEveryS ?? 6 * HOUR_S;
  const due = (at, secs = every) => at === null || ctx.now - at >= secs;
  const bar = Math.round(f * 1000);
  const out = [];
  if (permille >= bar && due(rec.alertedS)) {
    rec.alertedS = ctx.now;
    out.push({ code: "outflow", mint, msg: `unbacked outflow at ${(permille / 10).toFixed(0)}% of the 24h freeze threshold (${lastDay} of ${limit24h} in the last 24 hours, to non-allowlisted owners): check these payouts are honest; the bot freezes only past the threshold` });
  }
  const hot = [...rec.days.entries()].filter(([d, m]) => d >= today - 2 && m >= bar).length;
  // Once a day: it is a judgement for people to make, not news every hour.
  if (hot >= (policy.sustainedDays ?? 2) && due(rec.sustainedS, DAY_S)) {
    rec.sustainedS = ctx.now;
    out.push({ code: "sustained", mint, msg: `sustained drip: unbacked outflow reached ${(f * 100).toFixed(0)}% of the 24h freeze threshold on ${hot} of the last 3 days. A patient attacker under the thresholds is not frozen by this bot; only the on-chain limits bound it. Decide whether to freeze (docs/15, A2)` });
  }
  return out;
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
 *
 * The breach it was sent for is still an incident (`state`). A send reported
 * "not confirmed" can land later, and only a confirmed send used to open the
 * incident, so that freeze ran out after 24h with no hold behind it.
 */
export function retirePendingFreeze(pending, chainFrozenUntil, now, state = null) {
  if (!pending || chainFrozenUntil <= now) return pending;
  if (state) openIncident(state, now);
  return null;
}

/**
 * Whether the active-ticket scan runs this loop pass: on its cadence, or at
 * once after a truncated transaction was read live. A queued release moves
 * no tokens, so the truncated log's balance fallback cannot see it; the scan
 * finds its ticket, judges its release and, while frozen, cancels it
 * (docs/09, finding 76).
 */
export function ticketScanDue(nowMs, nextAtMs, truncatedSeen) {
  return truncatedSeen || nowMs >= nextAtMs;
}

/** How much shorter than intended a freeze already on chain may be and still
 * stand for ours. Independent guardians see the same breach seconds apart. */
export const FREEZE_COVER_SLACK_S = 600;

/**
 * Whether the protocol, read at confirmed commitment just before sending a
 * freeze of `secs`, is already frozen about as long as that freeze would make
 * it. Every guardian used to send its own: duplicate freezes (each one fees,
 * and a later end) and one critical alert per guardian (docs/09, finding 76).
 */
export function freezeAlreadyCovers(chainFrozenUntil, now, secs, slackS = FREEZE_COVER_SLACK_S) {
  // The slack scales with the freeze: an absolute 600 s made every renewal of
  // a short freeze (the incident hold renews it before it ends) look covered,
  // so the hold silently lapsed (the guardian scenarios caught it).
  const slack = Math.min(slackS, Math.floor(secs / 20));
  return chainFrozenUntil > now && chainFrozenUntil >= now + secs - slack;
}

/**
 * The earliest replayed time at which `mint`'s window broke a freeze rule
 * (the current worst-case figures, `figure`), or null. A guardian that lost
 * its state file, starting while the protocol is frozen for a breach, rebuilds
 * its incident hold from it (docs/09, finding 76); before, the hold did not
 * resume and the freeze simply ran out.
 */
export function replayedBreachTime(state, mint, figure, now, policy = DEFAULT_POLICY) {
  const times = [...new Set(state.outflows.filter((o) => o.mint === mint && o.t <= now).map((o) => o.t))].sort((a, b) => a - b);
  for (const t of times) {
    const probe = { outflows: state.outflows.filter((o) => o.mint === mint) };
    if (breach(probe, mint, { ...figure, now: t }, policy)) return t;
  }
  return null;
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

/** The Vault's custom error code in a failed send's error, or null. */
export function programErrorCode(e) {
  const err = e?.rpcError?.data?.err ?? null;
  const code = err?.InstructionError?.[1]?.Custom;
  if (Number.isInteger(code)) return code;
  const m = /"Custom":(\d+)/.exec(e?.message ?? "");
  return m ? Number(m[1]) : null;
}

/**
 * Vault refusals of `cancel_ticket` that no retry gets past
 * (programs/vault/src/error.rs, counted from 8000): the ticket is not this
 * vault's, or the address now holds another ticket (addresses are reused once
 * a ticket closes, so the one decided on is gone).
 */
const CANCEL_FINAL = new Map([[8010, "WrongVault"], [8052, "WrongTicket"]]);
/** WrongAccountType: the ticket account is closed, so the ticket is gone. */
const TICKET_CLOSED = 8001;

/**
 * Whether a cancel failed because the ticket is already gone: a peer guardian
 * cancelled it first, or it settled. That is the outcome a cancel wants, not
 * an error: logged as one, it raised a critical alert per ticket per guardian
 * (14 false critical alerts for 11 tickets in one simulated incident; docs/09,
 * finding 76).
 */
export function ticketAlreadyGone(error) {
  return programErrorCode(error) === TICKET_CLOSED;
}
/** NotGuardian: this key is not a live guardian now. It can be again (a
 * heartbeat while in range, or a quorum adding it back), so the cancel waits
 * the longest backoff instead of being dropped until a restart (docs/09,
 * finding 71). */
const NOT_GUARDIAN = 8006;
export const CANCEL_RETRY_MS = 15_000;
export const CANCEL_RETRY_MAX_MS = 600_000;

/**
 * After a cancel failed: retry later, doubling from 15 s to 10 minutes (at
 * once 10 minutes for NotGuardian), or never (`final`: the refusal's name).
 * Failed cancels used to go out again every poll, each one landing on chain
 * through the backups for a fee.
 */
export function afterCancelFailure(prev, error, nowMs) {
  const code = programErrorCode(error);
  const failures = (prev?.failures ?? 0) + 1;
  if (CANCEL_FINAL.has(code)) return { final: CANCEL_FINAL.get(code), failures, at: Infinity };
  if (code === NOT_GUARDIAN) return { final: null, failures, at: nowMs + CANCEL_RETRY_MAX_MS, refused: "NotGuardian" };
  return { final: null, failures, at: nowMs + Math.min(CANCEL_RETRY_MAX_MS, CANCEL_RETRY_MS * 2 ** (failures - 1)) };
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
/**
 * Failed heartbeats in a row before one is logged as an error, which alerts.
 * A warning does not, so a key whose heartbeats kept failing used to go quiet
 * until it was already dead (the "no longer a live guardian" error).
 */
export const HEARTBEAT_ALERT_AFTER = 3;
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
    const { protocol, id, kind, vetoed, executed, target, executableS, expiresS, payload, baseVersion } = decodeChange(bytes);
    return { protocol, id, kind, vetoed, executed, target, executableS, expiresS, payload, baseVersion };
  } catch {
    return null;
  }
}

/** Veto a loosening that is still pending. History replay does not send
 * actions, so a restart has to read the account. `already` is `state.vetoed`,
 * `consumed` is `state.consumed` (approvals already spent).
 */
export function pendingChangeVeto(change, policy, now, already, consumed) {
  if (!policy.vetoLoosenings || !change || change.vetoed || change.executed) return null;
  if (Number.isFinite(change.expiresS) && now >= change.expiresS) return null;
  const id = BigInt(change.id);
  if (already?.has(`c${id}`)) return null;
  if (changeApproved(change, policy, now, consumed)) return null;
  return { type: "veto_change", changeId: id, reason: `loosening ${id} (kind ${change.kind}) is still pending and not approved` };
}

/**
 * A live `change_proposed` whose kind and target match an approval: its
 * payload decides, so its account is read by id (`changeAddress`), not left to
 * the program-account scan, which may fail for as long as the RPC refuses it.
 * `change` is the decoded account, null when missing, undefined when it could
 * not be read; `sinceS` is when the event was seen. Returns the veto, "ok"
 * (approved, or closed), or "wait" (unreadable, retry). Still unreadable after
 * `approvalCheckGiveUpS`, it is vetoed: an unread payload is not an approved one.
 */
export function checkProposedChange(changeId, change, policy, now, sinceS, already, consumed) {
  const id = BigInt(changeId);
  if (already?.has(`c${id}`)) return "ok";
  if (change) return pendingChangeVeto(change, policy, now, already, consumed) ?? "ok";
  if (now - sinceS < (policy.approvalCheckGiveUpS ?? 600)) return "wait";
  return { type: "veto_change", changeId: id, reason: `loosening ${id} matches an approval's kind and target, but its payload could not be read for ${now - sinceS}s: vetoed` };
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
 * already sent, `consumed` approvals already spent. `approval` is the content
 * to spend (`consumeApproval`) once it has run. */
export function dueApprovedChange(change, policy, now, done, consumed) {
  if (!policy.executeApproved || !change || change.vetoed || change.executed) return null;
  const id = BigInt(change.id);
  if (done?.has(`c${id}`)) return null;
  if (!changeApproved(change, policy, now, consumed)) return null;
  if (now < change.executableS || now >= change.expiresS) return null;
  return { type: "execute_change", changeId: id, kind: change.kind, target: change.target, approval: changeApproval(change) };
}

/** A Floor proposal the keeper should execute now, or null: approved (code by
 * buffer, anything else by what it does), not vetoed, due and not expired,
 * and never a release of the upgrade authority. */
export function dueApprovedFloor(floor, policy, now, done, consumed) {
  if (!policy.executeApproved || !floor?.pendingKind || floor.pendingVetoed) return null;
  if (floor.pendingKind === 3) return null;
  const id = BigInt(floor.pendingId);
  if (done?.has(`e${floor.program}:${id}`)) return null;
  const proposal = { program: floor.program, kind: floor.pendingKind, target: floor.pendingTarget, payload: floor.pendingPayload };
  if (floorProposalVeto(proposal, policy, { now, consumed })) return null;
  if (now < floor.pendingEta || now >= floor.pendingExpires) return null;
  const approval = floor.pendingKind === 1 || floor.pendingKind === 2 ? null : floorApproval(proposal);
  return { type: "execute_floor", program: floor.program, proposalId: id, kind: floor.pendingKind, target: floor.pendingTarget, approval };
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
 * An approval also has to be live at `now` and not yet spent (`consumed`);
 * without a clock an approval with an expiry approves nothing. A buffer is
 * not spent here: an upgrade drains it, so it cannot be proposed twice.
 */
export function floorProposalVeto({ program, kind, target, payload }, policy, { now = Infinity, consumed } = {}) {
  const what = FLOOR_KINDS[kind] ?? `kind ${kind}`;
  if (kind === 1 || kind === 2) {
    if ((policy.approvedUpgradeBuffers ?? []).includes(target)) return null;
    return `${what} to unapproved buffer ${target}`;
  }
  const approvals = policy.approvedFloorProposals;
  if (payload === undefined) {
    if (approvesPrefix(approvals, `${program}:${kind}:${target}:`, now, consumed)) return null;
  } else if (approves(approvals, floorApproval({ program, kind, target, payload }), now, consumed)) {
    return null;
  }
  return `${what} (target ${target}) is not pre-approved`;
}

/** Veto a Floor proposal that is still pending. Same rule as a live
 * `floor:proposed` event (`floorProposalVeto`).
 */
export function pendingUpgradeVeto(floor, policy, already, { now = Infinity, consumed } = {}) {
  if (!floor || !floor.pendingKind || floor.pendingVetoed) return null;
  const id = BigInt(floor.pendingId);
  if (already?.has(`f${floor.program}:${id}`)) return null;
  const why = floorProposalVeto({ program: floor.program, kind: floor.pendingKind, target: floor.pendingTarget, payload: floor.pendingPayload ?? new Uint8Array(0) }, policy, { now, consumed });
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
      // An empty sum is not a breach. A future-dated outflow is kept but not
      // counted yet, and `0 ≥ 0` would freeze whenever the worst case is 0.
      const reason = brokenRule(sumsFor(state, e.mint, ctx.now), limitsFor(ctx, policy), policy);
      if (act && !frozen && reason) {
        state.freezing = true;
        actions.push({ type: "freeze", secs: policy.freezeSecs, reason });
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
      // Its release was counted once; a closed ticket is never released or
      // scanned again, so its id need not be kept: the set grew by one for
      // every ticket ever seen, for as long as the process ran (finding 83).
      state.tickets.delete(e.ticketId);
      break;
    case "change_proposed":
      if (!policy.vetoLoosenings || state.vetoed.has(`c${e.id}`)) break;
      // Replayed at startup: nothing is sent, but the proposal is still read
      // by its id once acting starts (`checkProposedChange` vetoes it unless
      // it is closed or approved). It used to be left to the program-account
      // scan alone, which a node may refuse for as long as it likes (docs/09,
      // finding 71).
      if (!act) {
        actions.push({ type: "check_change", changeId: e.id });
        break;
      }
      // The event has no payload: a change that may be approved is read by
      // its id (`checkProposedChange`), and vetoed unless its payload matches too.
      if (changeMayBeApproved(e.changeKind, e.target, policy, ctx.now, state.consumed)) {
        actions.push({ type: "check_change", changeId: e.id });
      } else {
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
        const why = floorProposalVeto({ program: e.program, kind: e.proposalKind, target: e.target }, policy, { now: ctx.now, consumed: state.consumed });
        if (why && !state.vetoed.has(`f${e.program}:${e.id}`)) {
          state.vetoed.add(`f${e.program}:${e.id}`);
          actions.push({ type: "floor_veto", program: e.program, proposalId: e.id, reason: why });
        }
      }
      break;
  }
  return actions;
}
