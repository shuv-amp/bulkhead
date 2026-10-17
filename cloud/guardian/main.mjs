#!/usr/bin/env node
// Bulkhead Cloud guardian: watches a protocol's Bulkhead events and acts.
//
//   node cloud/guardian/main.mjs <config.json>
//
// config.json:
//   { "rpc": "http://127.0.0.1:8899",
//     "vaultProgram": "...", "protocolProgram": "...",
//     "mints": ["..."], "guardianKey": "path/to/keypair.json",
//     "pollMs": 400, "policy": { ...overrides of DEFAULT_POLICY },
//     "floorProgram": "...", "floorProtected": ["program id", ...],
//     "alert": { "url": "https://hooks.slack.com/...", "format": "slack" } }
//
// With `alert`, every action, every error and the warnings that need a person
// (a lifeboat move, a key no longer live, ...) are also posted to that webhook
// (alert.mjs). Keep the URL secret: it is never logged.
//
// `stallAlertS` (default 120): a loop step failing that long without a break
// raises an urgent alert (a guardian that cannot read is blind).
//
// `ingestBudgetMs` (default 3000), `ingestConcurrency` (default 8),
// `lagAlertS` (default 60): one loop pass ingests for at most the budget,
// fetching transactions that many at a time, and carries the rest to the next
// pass, so a spammed protocol account cannot starve the chain sync, freeze
// retry, ticket scan, vetoes and heartbeats; ingestion more than `lagAlertS`
// behind the chain raises an urgent alert (docs/09, finding 76).
// `freshnessCheckS` (default 60): with backup endpoints, how often they are
// cross-checked for a primary that answers but is stale (FailoverRpc.crossCheck).
//
// Production (docs/07 §6; docs/09, finding 83): `cluster` ("mainnet-beta",
// "devnet", "testnet" or "localnet") is checked against each RPC endpoint's
// genesis hash, and "mainnet-beta" requires `rpcs` and `alert`. `liveness`
// ({ url, everyS: 60 }) is pinged every pass's minute: a dead-man's switch
// for when this process or its host dies. `minBalanceSol` (default 0.05):
// below it, an urgent alert. `startupMaxSignatures` (default 50,000): the
// startup replay's bound, checked between pages of 1,000, so the replay stops
// at the first page boundary at or past it. Every setting and policy value is checked at start;
// an unknown one (a typo) or an out-of-range value refuses to start.
//
// With `floorProtected`, the bot also follows each program's Floor config
// transactions (its proposals, executions and recovery-key changes), and checks it every
// minute and logs a warning whenever what is missing changes: no abort buffer
// staged (nobody can stop it) or no snapshot pinned (docs/15, A5).
//
// Every decision is one JSON line on stdout: the triggering event, the action,
// the reason, the transaction, and the latency from the triggering
// transaction's block time to the guardian's own confirmation.
//
// The 24- and 72-hour rules need the last days of releases. On startup the bot
// replays that window (72 hours with the 72-hour rule on) from chain history (block times, not the wall clock) and, if it
// is already over a threshold and the protocol is not frozen, freezes once.
// A failed freeze is retried; it does not stick in `state.freezing`.
//
// What it believes: an event counts only if the Vault program wrote it (any
// program can write a "Program data:" line) and it names this protocol (one
// Vault serves every protocol: finding 64); a Floor event only if Floor wrote
// it, read from that watched config's own transactions; freeze state is read from
// chain every cycle; active tickets are scanned at startup, on a freeze, and
// periodically; truncated logs use the vault's own transfers and balances.
//
// Keeper: once due, it executes exactly what is approved below (anyone may
// execute after the delay; this makes sure someone does), except a release of
// Floor's upgrade authority.
//
// Vetoes: every loosening not in `approvedChanges` ("kind:target:payloadHex",
// what it does, never its id), every lifeboat exit not in `approvedExits`
// ("mint:amount"), and every Floor proposal not approved (code by buffer in
// `approvedUpgradeBuffers`, anything else as "program:kind:target:payloadHex"
// in `approvedFloorProposals`), live and, after a restart, from the accounts.
// A Vault approval pinned to its proposal's base version
// ("kind:target:payloadHex#<version>") can never match a replay; an unpinned
// one is spent once a matching change executes (kept in the state file). Any
// approval may end in "@<unix seconds>" to expire.
//
// Heartbeats keep this key live on the Vault and on every watched Floor it
// guards, each inside its chain interval. A failed one is retried on a
// backoff; a key that is already stale or absent is reported, not resent.

import { readFileSync, statSync } from "node:fs";
import { basename, dirname } from "node:path";
import { Rpc, FailoverRpc, b58encode, decodeTicket, key, decodeProtocol, decodeFloor, decodeVault } from "../lib/solana.mjs";
import { Keypair, sendWithFallback, sendEscalating, priorityPrice } from "../lib/signer.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { assess, watchedEvents, checkFloors, guardianSetCheck, newState, observeProtocolFreeze, pendingCancels, rememberTicket, retirePendingFreeze, decisionTime, judgeReplayedWindow, queueFailedVeto, openIncident, observeFreezeEnd, incidentHold, guardianStanding, afterHeartbeat, heartbeatEveryAfterAccount, HEARTBEAT_ALERT_AFTER, pendingChangeVeto, pendingExitVeto, pendingUpgradeVeto, dueApprovedChange, dueApprovedFloor, vetoRetryDisposition, readChangeVeto, readPendingChange, checkPolicy, checkConfig, GENESIS, checkProposedChange, spendExecution, observeExecutions, unpinnedChangeApprovals, parseApproval, changeApproval, floorApproval, afterCancelFailure, CANCEL_RETRY_MS, DEFAULT_POLICY, DAY_S, outflowAlerts, OUTFLOW_KEEP_S, ticketAlreadyGone, freezeAlreadyCovers, replayedBreachTime, ticketScanDue } from "./policy.mjs";
import { ingestBudgeted, ingestLagS, signatureWalk, signatureWalkSinceSlot, followConfigs, startSlot, cursorGone, PAGE_LOG_INTERVAL, requireTransaction, transactionOrSkip } from "./follow.mjs";
import { executeChangeIx as executeChangeIxFor } from "./keeper.mjs";
import { alerter, stallWatch, scanAll, actionLine } from "./alert.mjs";
import { activeTickets, activeChanges, ticketRelease, settlementRows, truncatedOutflows, unexplainedOutflow } from "./chain.mjs";
import { stateJson, restoreState, writeStateFile } from "./statefile.mjs";
import { attestLocal } from "../lib/limits.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
// Alerts (alert.mjs) and the fatal path come first, before anything that can
// refuse to start: a key file open to others (Keypair.load), a malformed
// policy. Those used to throw before either existed, so a guardian crash-
// looping on a refused key never reached the webhook (docs/09, finding 71).
// Alerts are never on the guardian's critical path.
let protocolLabel = "";
const sendAlert = alerter({ ...(cfg.alert ?? {}), protocol: () => protocolLabel }, {
  onError: (e) => console.log(JSON.stringify({ t: new Date().toISOString(), level: "warn", msg: `alert not delivered: ${e.message}` })),
});
const log = (o) => {
  const line = { t: new Date().toISOString(), ...o };
  console.log(JSON.stringify(line, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
  sendAlert(line);
};
// A guardian that stops must say so and exit, so its supervisor starts a fresh
// one (cloud/guardian/bulkhead-guardian@.service). Retrying the startup in place
// would replay the 24h window into a half-built state and count outflows twice.
async function fatal(e) {
  log({ level: "error", msg: `guardian stopped: ${e?.message ?? e}; its supervisor must restart it` });
  await sendAlert.flush();
  process.exit(1);
}
process.on("unhandledRejection", fatal);
process.on("uncaughtException", fatal);
/** A startup step: its failure goes through `fatal`, like the loop's. */
async function must(run) {
  try {
    return await run();
  } catch (e) {
    return fatal(e);
  }
}

const configWarnings = await must(() => checkConfig(cfg));
const policy = await must(() => checkPolicy({ ...DEFAULT_POLICY, ...(cfg.policy ?? {}) }));
// With backup endpoints, reads and sends move to the next endpoint when one
// cannot answer (FailoverRpc); one endpoint keeps the patient retry. Hosts
// only in the log: RPC URLs often carry an API key.
const hostOf = (url) => { try { return new URL(url).host; } catch { return "(endpoint)"; } };
// With `cluster`, a backup is used only once its genesis hash matches (finding 114).
const rpcUrls = [cfg.rpc, ...(cfg.rpcs ?? [])];
const endpointName = (i) => `${hostOf(rpcUrls[i])} (${i > 0 ? `rpcs[${i - 1}]` : "rpc"})`;
const genesisSeen = []; // by endpoint: the genesis hash it gave
let clusterChecked = false; // the start's check is over: later news is logged
const rpc = cfg.rpcs?.length
  ? new FailoverRpc(rpcUrls, {
    onSwitch: (from, to, e) => log({ level: "error", msg: `RPC endpoint ${hostOf(from)} is failing; now using ${hostOf(to)}`, cause: e?.message?.slice(0, 160) }),
    genesis: GENESIS[cfg.cluster] ?? null,
    onCluster: (url, got, at) => {
      genesisSeen[at] = got;
      if (!clusterChecked) return;
      if (got !== GENESIS[cfg.cluster]) log({ level: "error", msg: `RPC endpoint ${endpointName(at)} serves another cluster than ${cfg.cluster} (genesis ${got}): nothing is read from it, but copies of guardian transactions still go to it; remove it from the config` });
      else log({ msg: `RPC endpoint ${endpointName(at)} answers on ${cfg.cluster}: it may be used from now on` });
    },
  })
  : new Rpc(cfg.rpc);
// Extra endpoints every guardian transaction is also sent to (optional).
const extraRpcs = (cfg.rpcs ?? []).map((url) => new Rpc(url));
const guardian = await must(() => Keypair.load(cfg.guardianKey));
const vc = await must(() => new VaultClient(cfg.vaultProgram, cfg.protocolProgram).init());
protocolLabel = b58encode(vc.protocol);
// The watched vaults, by vault address and by token account address.
const watched = await must(() => Promise.all(cfg.mints.map(async (mint) => ({ mint, ...(await vc.vault(mint)) }))));
const vaultMints = new Map(watched.map((v) => [b58encode(v.vault), v.mint]));
const tokenMints = new Map(watched.map((v) => [b58encode(v.vaultTokens), v.mint]));
// Each mint's vault PDA. A transfer into a token account it owns is a lifeboat move.
const vaultOf = new Map(watched.map((v) => [v.mint, b58encode(v.vault)]));
// Only the Vault program's events count (any program can write "Program
// data:"), and only those naming this protocol (watchedEvents, finding 64).
const protocolKey = b58encode(vc.protocol);
const state = newState();
// What must survive a restart (statefile.mjs) is kept beside the config, per
// protocol: the incident hold and the freeze end last seen, spent approvals,
// the executions already seen, each watched Floor config's cursor and
// pending proposal, and the live proposals waiting to be read by id.
// Under systemd (cloud/guardian/bulkhead-guardian@.service) the config's
// directory is read-only: the default is then the unit's state directory.
const stateFile = cfg.stateFile
  ?? (process.env.STATE_DIRECTORY
    ? `${process.env.STATE_DIRECTORY.split(":")[0]}/${basename(process.argv[2])}.state.json`
    : `${process.argv[2]}.state.json`);
let saveError = null;
// The protocol's freeze end at the last sync: an end that moves earlier is a
// guardian quorum's unfreeze (observeFreezeEnd).
let lastChainFrozenUntil = 0;
// Proposals waiting for their account to be read (checkProposedChange):
// change id -> when first seen. Kept in the state file: a restart's replay
// covers only the last day.
let changeChecks = new Map();
// Per watched Floor program: the proposal last seen pending and the approval
// it matched, so its `floor:executed` event can spend that approval. Kept in
// the state file, with each config's cursor (`floorCursors`, followFloor):
// an execution while this guardian was down is read on restart and spends.
let floorPendingSeen = new Map();
let floorCursors = new Map();
const persisted = () => stateJson({ protocol: protocolKey, incidentSince: state.incidentSince, frozenUntil: lastChainFrozenUntil, state, floorCursors, floorPendingSeen, changeChecks });
let saved = persisted();
// Whether a state file of this protocol was read: without one, the incident
// hold may have to be rebuilt from chain (`rebuildIncident`).
let restoredState = false;
let stateProblem = null;
{
  let text = null;
  try {
    text = readFileSync(stateFile, "utf8");
  } catch {
    // no saved state: no incident open, and no baseline of executed changes
  }
  if (text !== null) {
    const r = restoreState(text, protocolKey, state);
    if (r.problem) stateProblem = `${r.problem}: nothing was restored from ${stateFile}. An open incident hold, the Floor cursors and spent approvals are forgotten; the hold is rebuilt from chain if the protocol is frozen. Check the file (docs/09, finding 83)`;
    if (r.incidentSince !== null) state.incidentSince = r.incidentSince;
    if (r.frozenUntil !== null) {
      lastChainFrozenUntil = r.frozenUntil;
      restoredState = true;
    }
    ({ floorCursors, floorPendingSeen, changeChecks } = r);
    saved = persisted();
  }
}
let dirChecked = false;
function saveIncident() {
  const now = persisted();
  if (now === saved) return;
  try {
    // A directory others can write lets them swap the file in. That is said,
    // never changed: the directory is not the guardian's (statefile.mjs).
    if (!dirChecked) {
      dirChecked = true;
      const dir = dirname(stateFile);
      try {
        if (statSync(dir).mode & 0o022) log({ level: "warn", msg: `the state directory ${dir} is writable by others, who could replace the state file; give the guardian a directory of its own (stateFile)` });
      } catch {
        // the write below says what is wrong
      }
    }
    writeStateFile(stateFile, now);
    saved = now;
    saveError = null;
  } catch (e) {
    // Said once per cause, not on every poll.
    if (saveError !== e.message) {
      saveError = e.message;
      console.log(JSON.stringify({ t: new Date().toISOString(), level: "error", msg: `could not save the incident state to ${stateFile}: ${e.message}` }));
    }
  }
}

// Programs under Floor whose readiness the bot reports (A5).
const floorWatch = cfg.floorProgram
  ? await must(() => Promise.all((cfg.floorProtected ?? []).map((p) => new FloorClient(cfg.floorProgram, p).init())))
  : [];
const floorReported = new Map();

const worst1h = new Map();
const worst24h = new Map();
// The 72-hour rule's figure, computed from the vault account with the limiter
// port (`attestLocal`): `attest` returns no 72-hour figure (finding 76).
const worst72h = new Map();
const warned = new Set();
let pendingFreeze = null;
let pendingVetoes = [];
let vetoNotBefore = 0;
// Per ticket: failures, when to try again, and a refusal no retry gets past
// (afterCancelFailure).
const cancelRetry = new Map();
const VETO_RETRY_MS = 15_000;
let nextTicketScanAt = 0;
// The minute's Floor config check; a Floor stop or restore event sets it to 0
// so the next pass checks at once (finding 76).
let lastFloorCheck = 0;
const ingestBudgetMs = cfg.ingestBudgetMs ?? 3_000;
const lagAlertS = cfg.lagAlertS ?? 60;
const freshnessEveryMs = (cfg.freshnessCheckS ?? 60) * 1000;
/** At start, how long the other endpoints may take to answer the cluster check once one has (finding 114). */
const CLUSTER_GRACE_MS = 2_000;
let nextChangeScanAt = 0;
let sweptFreezeUntil = 0;

function wallNow() {
  return Math.floor(Date.now() / 1000);
}

/** This mint's own worst case. Missing attest is 0: any unbacked outflow freezes. */
function worstFor(mint) {
  if (worst1h.has(mint)) {
    return { worst1h: worst1h.get(mint), worst24h: worst24h.get(mint) ?? 0n, worst72h: worst72h.get(mint) };
  }
  if (!warned.has(mint)) {
    warned.add(mint);
    log({ level: "warn", msg: `no attest for ${mint}; worst case treated as 0 so any unbacked outflow freezes` });
  }
  return { worst1h: 0n, worst24h: 0n };
}

async function refreshWorstCase() {
  for (const mint of cfg.mints) {
    try {
      const a = await vc.attest(rpc, guardian.publicKey, mint);
      worst1h.set(mint, a.worst1h);
      worst24h.set(mint, a.worst24h);
      if (policy.freezeFractionOfWorst72h > 0) await refreshWorst72h(mint, a.clockS);
      if (!capsChecked.has(mint)) await checkCaps(mint);
    } catch (e) {
      log({ level: "warn", msg: `attest failed for ${mint}: ${e.message}` });
    }
  }
}

/**
 * Once per mint, says so (and alerts) when a watched vault has no absolute
 * caps: without them, capital an attacker parks in the vault first widens the
 * base the percentages apply to, and so the worst case this guardian freezes
 * against (docs/15, A1b; docs/16 §4.5). An unreadable vault is tried again on
 * the next refresh.
 */
const capsChecked = new Set();
async function checkCaps(mint) {
  const { vault } = await vc.vault(mint);
  const v = await rpc.account(vault);
  if (!v) return;
  capsChecked.add(mint);
  const { shortCap, longCap } = decodeVault(v.bytes).limits;
  if (shortCap === 0n || longCap === 0n) {
    log({ level: "warn", notify: true, mint, msg: `the vault for ${mint} has no absolute cap (1h ${shortCap}, 24h ${longCap}): parked capital widens its worst case; set caps (docs/07 §4)` });
  }
}

/**
 * The most the program lets out over 72 hours, by the limiter port on the
 * vault account at the attest's own clock. Unreadable, the last figure
 * stands; never read, the 72-hour rule waits and says so once.
 */
const warned72h = new Set();
async function refreshWorst72h(mint, clockS) {
  try {
    const { vault, vaultTokens } = await vc.vault(mint);
    const [v, t] = await Promise.all([rpc.account(vault), rpc.account(vaultTokens)]);
    if (!v || !t) throw new Error("vault account missing");
    const balance = new DataView(t.bytes.buffer, t.bytes.byteOffset).getBigUint64(64, true);
    worst72h.set(mint, attestLocal(decodeVault(v.bytes), { frozenUntil: 0 }, balance, clockS).worst72h);
  } catch (e) {
    if (!worst72h.has(mint) && !warned72h.has(mint)) {
      warned72h.add(mint);
      log({ level: "warn", msg: `no 72-hour figure for ${mint} yet (${e.message}): the 72-hour rule waits for it`, mint });
    }
  }
}

/** A promise that gives up after `ms` (resolving to `fallback`): no read may hold a freeze back. */
const within = (p, ms, fallback) => Promise.race([p.catch(() => fallback), new Promise((r) => setTimeout(() => r(fallback), ms))]);

/**
 * The priority price: "auto" is the 90th percentile of recent fees on the
 * protocol account, never below `minPriorityMicroLamports`. On a quiet
 * account every slot's fee is 0, and the price was 0, at any congestion; an
 * attacker write-locking the protocol at 1 µL/CU made it 1 (docs/09, finding 82).
 */
async function priorityFor(floor) {
  let microLamports = policy.priorityMicroLamports;
  if (microLamports === "auto") {
    const fees = await within(rpc.call("getRecentPrioritizationFees", [[b58encode(vc.protocol)]]), 1_500, []);
    microLamports = priorityPrice(fees, { cap: policy.maxPriorityMicroLamports });
  }
  return Math.min(policy.maxPriorityMicroLamports, Math.max(Number(microLamports) || 0, floor));
}

/** Compute budget, priority price and extra endpoints for one guardian transaction. */
async function sendOptions() {
  // A send that does not confirm in 20 s is retried by its own step: waiting
  // the old minute held up ingest, and with it the next freeze (finding 82).
  return { computeUnits: policy.computeUnits, microLamports: await priorityFor(policy.minPriorityMicroLamports), rpcs: extraRpcs, confirmMs: 20_000 };
}

/**
 * Every guardian transaction: with the compute budget and priority price, and,
 * if a node refuses that in simulation, again without them (`sendWithFallback`).
 */
async function guardianSend(ixs) {
  return sendWithFallback(rpc, guardian, ixs, [], await sendOptions(), (e) =>
    log({ level: "error", msg: "a node refused this transaction with its compute budget and accepted it without; check the budget settings", refused: e.message.slice(0, 300) }));
}

/**
 * A simulated freeze's error that no retry or price changes: no SOL for the
 * fee, a fee payer that does not exist, or the Vault refusing it (a key no
 * longer a live guardian, say). Null for anything else (a node behind the
 * blockhash, or no error).
 */
function freezeRefusal(err) {
  if (!err) return null;
  if (err === "InsufficientFundsForFee" || err === "AccountNotFound" || err?.InsufficientFundsForRent) return new Error(`the freeze cannot be paid for (${JSON.stringify(err)}): fund the guardian key`);
  const code = err?.InstructionError?.[1]?.Custom;
  if (code != null) return new Error(`the Vault refuses this freeze (custom error ${code}; 8006 is NotGuardian), whatever the price`);
  return null;
}

/**
 * The freeze: its own sending loop, as `stop.mjs` (docs/09, finding 82). No
 * preflight; every endpoint, every 400 ms; a fresh signature at twice the
 * price after each 6 s without confirmation, from at least
 * `freezeMinPriorityMicroLamports`; until the chain shows the protocol frozen
 * for this incident, or `freezeDeadlineS`. `basePrice` was read alongside the
 * pre-freeze account read.
 */
async function freezeSend(ixs, secs, basePrice) {
  const r = await sendEscalating(rpc, guardian, ixs, {
    computeUnits: policy.computeUnits,
    price: basePrice,
    floor: policy.freezeMinPriorityMicroLamports,
    cap: policy.maxPriorityMicroLamports,
    rpcs: extraRpcs,
    deadlineMs: policy.freezeDeadlineS * 1000,
    settled: async () => {
      const acc = await within(readProtocolAccount(), 1_500, null);
      return Boolean(acc) && freezeAlreadyCovers(decodeProtocol(acc.bytes).frozenUntil, wallNow(), secs);
    },
    // Alongside the first attempt: a refusal no price changes ends the loop
    // at the next check, with its cause (finding 84).
    precheck: async () => freezeRefusal((await rpc.simulate(guardian.publicKey, ixs))?.err),
    onAttempt: ({ attempt, error, nextPrice }) => log({ level: "warn", msg: `freeze attempt ${attempt} did not confirm; signing again at ${nextPrice} µL/CU`, error: String(error.message).slice(0, 200) }),
    onFallback: (e) => log({ level: "error", msg: "the freeze ran and failed in its compute budget; sending it without one: check the budget settings", error: String(e.message).slice(0, 300) }),
  });
  if (r.attempts > 1) log({ level: "warn", msg: `the freeze took ${r.attempts} attempts (last at ${r.price} µL/CU)`, attempts: r.attempts });
  return r.signature ?? "already frozen (an earlier attempt or another guardian)";
}

/** Decoded account, null when it does not exist, undefined when it could not be read. */
async function readDecoded(address, decodeBytes) {
  try {
    const acc = await rpc.account(address);
    return acc ? decodeBytes(acc.bytes) : null;
  } catch {
    return undefined;
  }
}

// Per target (the Vault protocol, each watched Floor config): when to look
// again, consecutive failures, and the standing last logged.
const beats = new Map();

/**
 * One heartbeat target. Sends only while this key can still count there, so a
 * stale, ejected or absent key is reported once and costs no transactions. A
 * failure is retried alone, on its own backoff, inside the time left.
 */
async function beatOne(id, read, ix, logged) {
  const b = beats.get(id) ?? { nextAt: 0, failures: 0, standing: null };
  if (Date.now() < b.nextAt) return b.nextAt;
  const account = await read();
  const { standing, deadlineS, lastS, intervalS } = guardianStanding(account, guardian.address, wallNow());
  if (standing !== b.standing && (standing === "dead" || standing === "absent")) {
    log(standing === "dead"
      ? { level: "error", msg: "this key is no longer a live guardian; a heartbeat cannot revive it, and it cannot freeze or veto here. Have the admin or a guardian quorum replace it.", target: logged.target, lastHeartbeatS: lastS, intervalS }
      : { level: "warn", msg: "no heartbeat sent: the account does not exist or this key is not on its guardian list", target: logged.target });
  }
  let outcome = standing;
  if (standing === "live" || standing === "unknown") {
    try {
      const signature = await guardianSend([ix()]);
      log({ ...logged, signature });
      outcome = "sent";
    } catch (e) {
      const failures = b.failures + 1;
      log({ level: failures >= HEARTBEAT_ALERT_AFTER ? "error" : "warn", msg: `${logged.action} failed: ${e.message}`, target: logged.target, failures });
      outcome = "failed";
    }
  }
  const everyMs = heartbeatEveryAfterAccount(policy.heartbeatEveryS, account?.heartbeatIntervalS) * 1000;
  const next = afterHeartbeat({ outcome, failures: b.failures, nowMs: Date.now(), everyMs, deadlineMs: deadlineS ? deadlineS * 1000 : null });
  beats.set(id, { ...next, standing });
  return next.nextAt;
}

/**
 * Heartbeats for the Vault protocol and every watched Floor this key guards,
 * or their vetoes and freezes die when the chain interval ends. Each period
 * stays inside its own chain interval. Returns when the next one is due.
 */
async function beat() {
  let next = await beatOne("vault", () => readDecoded(vc.protocol, decodeProtocol), () => vc.heartbeat(guardian.publicKey), { action: "heartbeat", target: "vault" });
  for (const fc of floorWatch) {
    const program = b58encode(fc.protected);
    const at = await beatOne(`floor:${program}`, () => readDecoded(fc.config, decodeFloor), () => fc.heartbeat(guardian.publicKey), { action: "floor_heartbeat", program, target: `floor ${program}` });
    next = Math.min(next, at);
  }
  return next;
}

async function execute(action, event, eventTime, { retrying = false } = {}) {
  const started = Date.now();
  try {
    let ixs;
    let freezeArgs = null;
    switch (action.type) {
      case "freeze": {
        // Another guardian may have frozen for the same breach seconds ago.
        // A fresh read (confirmed, never older than the last) that already
        // covers this freeze stands for it: no duplicate freeze, no duplicate
        // critical alert (docs/09, finding 76). An unreadable account is no
        // reason to hold a freeze back.
        // The account and the fee data together, each given 1.5 s: on a slow
        // node these reads, one after another, came before every freeze
        // (9 s at 1.5 s a call; docs/09, finding 82).
        const [acc, basePrice] = await Promise.all([within(readProtocolAccount(), 1_500, null), priorityFor(policy.freezeMinPriorityMicroLamports)]);
        const until = acc ? decodeProtocol(acc.bytes).frozenUntil : 0;
        if (freezeAlreadyCovers(until, wallNow(), action.secs)) {
          state.frozenUntil = Math.max(state.frozenUntil, until);
          openIncident(state, wallNow());
          saveIncident();
          log({ action: "freeze", skipped: `already frozen until ${until} by another freeze`, reason: action.reason });
          return true;
        }
        freezeArgs = { secs: action.secs, basePrice };
        ixs = [vc.freeze(guardian.publicKey, action.secs)];
        break;
      }
      case "cancel": {
        // The caller returns a failed cancel to the sweep; this one waits.
        const retry = cancelRetry.get(action.ticketId);
        if (retry && retry.at > Date.now()) return false;
        const vault = action.vault ?? (await vc.vault(action.mint ?? event.mint)).vault;
        // The address comes from the release event or the account scan; a
        // ticket only known by id waits for the next scan to name it.
        const address = action.address ?? state.pendingTickets.get(action.ticketId)?.address;
        const ticket = address ? key(address) : null;
        let acc = ticket ? await rpc.account(ticket) : null;
        if (!acc) {
          // A missing account with history is a ticket that was there and is
          // closed now (a peer cancelled it, or it settled): done, not an
          // error (docs/09, finding 76). Behind a load balancer the two reads
          // can reach different nodes, so the absence counts only when read
          // at or after the ticket's newest transaction.
          const history = ticket ? await rpc.call("getSignaturesForAddress", [b58encode(ticket), { limit: 1, commitment: "confirmed" }]).catch(() => null) : null;
          if (history?.length) {
            const r = await rpc.call("getAccountInfo", [b58encode(ticket), { encoding: "base64", commitment: "confirmed", minContextSlot: history[0].slot }]).catch(() => undefined);
            if (r && !r.value) {
              log({ action: "cancel", skipped: "ticket already closed (cancelled by another guardian, or settled)", ticketId: action.ticketId });
              return true;
            }
            if (r?.value) acc = { ...r.value, bytes: Uint8Array.from(atob(r.value.data[0]), (c) => c.charCodeAt(0)) };
          }
        }
        if (!acc) {
          // No history, or no node caught up to it yet: a lagging read is not
          // proof the ticket settled.
          // Retry; leaving it marked cancelled would let it pay out when the
          // freeze ends.
          log({ action: "cancel", skipped: "ticket account missing; will retry", ticketId: action.ticketId });
          cancelRetry.set(action.ticketId, { failures: retry?.failures ?? 0, at: Date.now() + CANCEL_RETRY_MS, final: null });
          return false;
        }
        const held = decodeTicket(acc.bytes);
        if (held.id !== BigInt(action.ticketId)) {
          // Addresses are reused once a ticket closes: this is another ticket
          // (the scan tracks it by its own id), and the one decided on is gone.
          log({ action: "cancel", skipped: `the address now holds ticket ${held.id}; ticket ${action.ticketId} is gone`, ticketId: action.ticketId });
          cancelRetry.set(action.ticketId, { failures: 0, at: Infinity, final: "WrongTicket" });
          return false;
        }
        ixs = [vc.cancelTicket(vault, ticket, guardian.publicKey, held.payer, action.ticketId)];
        break;
      }
      case "veto_change":
        if (retrying) {
          const acc = await rpc.account(await vc.changeAddress(action.changeId));
          const what = vetoRetryDisposition(action, acc ? readChangeVeto(acc.bytes) : null);
          if (what !== "send") {
            if (what === "drop") log({ action: "veto_change", skipped: "change is already closed", changeId: action.changeId });
            return what === "drop";
          }
        }
        ixs = [vc.vetoChange(await vc.changeAddress(action.changeId), guardian.publicKey)];
        break;
      case "veto_exit": {
        const vault = (watched.find((v) => v.mint === action.mint) ?? {}).vault;
        if (!vault) throw new Error(`no watched vault for ${action.mint}`);
        if (retrying) {
          const acc = await rpc.account(vault);
          let chain = null;
          if (acc) {
            try { chain = decodeVault(acc.bytes); } catch { chain = null; }
          }
          const what = vetoRetryDisposition(action, chain);
          if (what !== "send") {
            if (what === "drop") log({ action: "veto_exit", skipped: "that exit is no longer pending", mint: action.mint });
            return what === "drop";
          }
        }
        ixs = [vc.vetoExit(vault, guardian.publicKey)];
        break;
      }
      case "floor_veto": {
        const fc = floorWatch.find((c) => b58encode(c.protected) === action.program);
        if (!fc) {
          // Any Floor config's event can ride in a transaction that touches
          // this protocol: a program this key does not guard is not ours to veto.
          log({ action: "floor_veto", skipped: "not a program this guardian watches", program: action.program });
          return true;
        }
        if (retrying) {
          const acc = await rpc.account(fc.config);
          let chain = null;
          if (acc) {
            try { chain = decodeFloor(acc.bytes); } catch { chain = null; }
          }
          const what = vetoRetryDisposition(action, chain);
          if (what !== "send") {
            if (what === "drop") log({ action: "floor_veto", skipped: "that proposal is no longer pending", proposalId: action.proposalId });
            return what === "drop";
          }
        }
        ixs = [fc.veto(guardian.publicKey, action.proposalId)];
        break;
      }
      default:
        return false;
    }
    const sig = freezeArgs ? await freezeSend(ixs, freezeArgs.secs, freezeArgs.basePrice) : await guardianSend(ixs);
    const confirmed = Date.now();
    if (action.type === "freeze") {
      openIncident(state, wallNow());
      saveIncident();
    }
    log(actionLine(action, {
      ticketId: action.ticketId,
      signature: sig,
      reaction_ms: confirmed - started,
      since_trigger_s: eventTime ? Math.round(confirmed / 1000 - eventTime) : undefined,
    }));
    return true;
  } catch (e) {
    if (action.type === "cancel" && ticketAlreadyGone(e)) {
      // A peer guardian's cancel landed first: the outcome wanted. Info, no
      // retry, no alert (docs/09, finding 76).
      log({ action: "cancel", skipped: "ticket already closed (cancelled by another guardian, or settled)", ticketId: action.ticketId });
      return true;
    }
    log(actionLine(action, { level: "error", error: e.message, ticketId: action.ticketId }));
    if (action.type === "cancel") {
      const next = afterCancelFailure(cancelRetry.get(action.ticketId), e, Date.now());
      cancelRetry.set(action.ticketId, next);
      if (next.final) log({ level: "error", msg: `the Vault refused to cancel ticket ${action.ticketId} with ${next.final}, which no retry changes: not sending it again`, ticketId: action.ticketId });
    }
    return false;
  }
}

/**
 * A cancel's outcome in the books. A failed one goes back to the sweep (on its
 * backoff); one refused for good stays marked cancelled so it is never sent
 * again, and a ticket that is gone (WrongTicket) is forgotten.
 */
function afterCancel(action, ok) {
  const id = action.ticketId;
  const final = cancelRetry.get(id)?.final;
  if (ok || final === "WrongTicket") {
    state.pendingTickets.delete(id);
    if (!ok) state.cancelled.delete(id);
    cancelRetry.delete(id);
  } else if (!final) {
    state.cancelled.delete(id);
  }
}

/** After a freeze lands: cancel every queued ticket still outstanding. */
async function sweepCancels(event, eventTime, { refresh = true } = {}) {
  for (const id of cancelRetry.keys()) if (!state.pendingTickets.has(id)) cancelRetry.delete(id);
  if (refresh) {
    await tryRefreshPendingTickets();
  }
  // Four at a time: one after another, a sweep of eight tickets took over
  // 15 s with 1.5 s RPC latency, and ingestion waited for it (docs/09, finding 84).
  const queue = pendingCancels(state, policy);
  for (let i = 0; i < queue.length; i += CANCEL_CONCURRENCY) {
    await Promise.all(queue.slice(i, i + CANCEL_CONCURRENCY).map(async (action) => afterCancel(action, await execute(action, event, eventTime))));
  }
}
const CANCEL_CONCURRENCY = 4;

/** A proposal to read by id (checkProposedChange), once; kept in the state file. */
function queueCheck(changeId) {
  if (changeChecks.has(changeId)) return;
  changeChecks.set(changeId, { sinceS: wallNow(), warned: false });
  saveIncident();
}

async function applyActions(actions, event, eventTime) {
  let freezeOk = true;
  let froze = false;
  for (const action of actions) {
    if (action.type === "check_change") {
      queueCheck(action.changeId);
      continue;
    }
    // Cancels in this batch are "while frozen". If the freeze transaction
    // failed and the protocol is not already frozen, don't cancel yet.
    if (action.type === "cancel" && !freezeOk) {
      state.cancelled.delete(action.ticketId);
      continue;
    }
    const ok = await execute(action, event, eventTime);
    if (action.type === "cancel") afterCancel(action, ok);
    if (action.type === "veto_change" || action.type === "floor_veto" || action.type === "veto_exit") {
      if (!ok) pendingVetoes = queueFailedVeto(pendingVetoes, action);
      continue;
    }
    if (action.type !== "freeze") continue;
    freezeOk = ok;
    if (ok) {
      pendingFreeze = null;
      froze = true;
    } else {
      state.freezing = false;
      pendingFreeze = { action, event, eventTime };
    }
  }
  if (froze) await sweepCancels(event, eventTime);
  if (changeChecks.size) await runChangeChecks();
}

/**
 * Read each live proposal that may be approved by its own address and veto it
 * unless its payload is approved too. This used to be left to the
 * program-account scan alone: while getProgramAccounts failed (a node that
 * refuses or times it out), such a change was never vetoed.
 */
let checking = false;
async function runChangeChecks() {
  if (checking) return;
  checking = true;
  try {
    await checkChanges();
  } finally {
    checking = false;
  }
}

async function checkChanges() {
  const now = wallNow();
  const vetoes = [];
  for (const [id, check] of changeChecks) {
    let change;
    try {
      const acc = await rpc.account(await vc.changeAddress(id));
      change = acc ? readPendingChange(acc.bytes) ?? undefined : undefined;
    } catch {
      change = undefined;
    }
    const what = checkProposedChange(id, change, policy, now, check.sinceS, state.vetoed, state.consumed);
    if (what === "wait") {
      if (!check.warned) {
        check.warned = true;
        log({ level: "error", msg: `change ${id} may be approved, but its account could not be read to compare the payload; retrying, and vetoing it if still unreadable after ${policy.approvalCheckGiveUpS}s`, changeId: id });
      }
      continue;
    }
    changeChecks.delete(id);
    saveIncident();
    if (what === "ok") continue;
    state.vetoed.add(`c${what.changeId}`);
    vetoes.push(what);
  }
  if (vetoes.length) await applyActions(vetoes, { reason: "approval check" }, now);
}

/** Newest-first. `oldestWanted` null walks until `until` (live); a number walks the startup window. */
/** Whether the node has this signature (an empty page after a full one; docs/09, finding 81). */
const knowsSignature = async (signature) => {
  const r = await rpc.call("getSignatureStatuses", [[signature], { searchTransactionHistory: true }]);
  return Boolean(r?.value?.[0]);
};

async function signatures(until, oldestWanted, { minSlot = null, seen = null, maxRows = Infinity } = {}) {
  let lastLoggedPage = 0;
  return signatureWalk(
    (query) => rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), query]),
    {
      until,
      oldestWanted,
      minSlot,
      seen,
      knows: knowsSignature,
      maxRows,
      onPage: (count) => {
        if (count % PAGE_LOG_INTERVAL === 0 && count !== lastLoggedPage) {
          lastLoggedPage = count;
          log({ msg: `signature recovery is still paging`, pages: count });
        }
      },
    },
  );
}

/** One fact (a release, freeze or proposal), from an event or from the chain. */
async function consider(e, signature, now, act) {
  // Only a release needs the worst case; other events carry no mint.
  const ctx = e.kind === "released" ? { ...worstFor(e.mint), now } : { now };
  const actions = assess(state, e, ctx, policy, act);
  // Outflow under the freeze thresholds still goes to people once it is a
  // large share of them, or keeps up for days: a patient attacker under the
  // thresholds is not frozen by this bot (docs/09, finding 76). A replay
  // records each day's high only.
  const drip = e.kind === "released" ? outflowAlerts(state, e.mint, ctx, policy, act) : [];
  if (e.kind === "released") saveIncident();
  if (!act) {
    // Replay sends nothing, but a replayed proposal is read by id once
    // acting starts (docs/09, finding 71).
    for (const a of actions) if (a.type === "check_change") queueCheck(a.changeId);
    return;
  }
  log({ event: e.kind, signature, ...e });
  for (const a of drip) log({ level: "warn", msg: a.msg, mint: a.mint, alert: a.code });
  // Floor's stop, ejection, restore and restore approvals, for the programs
  // this guardian watches (watchedEvents drops the rest): a stop used to be
  // seen only by the minute's config check, and the others never (finding 76).
  if (e.kind === "floor_aborted") {
    log({ level: "warn", msg: `the program was stopped on Floor (by ${e.by}); a guardian quorum restores the snapshot${e.snapshotValid ? "" : ", but none is pinned"}`, program: e.program });
    lastFloorCheck = 0; // re-read its config now, not within the minute
  } else if (e.kind === "floor_ejected") {
    log({ level: "warn", msg: `a guardian was ejected on Floor by a quorum of the others: ${e.removed}`, program: e.program });
  } else if (e.kind === "floor_restored") {
    log({ notify: true, msg: `Floor restored the stopped program's snapshot (guardians ${e.signers.toString(2)})`, program: e.program });
    lastFloorCheck = 0;
  } else if (e.kind === "floor_approved") {
    log({ notify: true, msg: `guardians approved Floor restore proposal ${e.proposalId} (approvals ${e.approvals.toString(2)})`, program: e.program, proposalId: e.proposalId });
  }
  if (e.kind === "lifeboat_in") {
    log({ level: "warn", msg: "the admin moved tokens into the lifeboat: depositors may be short until a guardian quorum or the admin returns them", mint: e.mint, amount: e.amount });
  }
  if (e.kind === "recovery_replaced") {
    const where = e.program ? ` on Floor for ${e.program}` : "";
    const by = `by the ${e.program ? "owner" : "admin"} with a guardian quorum`;
    // All zero is no recovery key at all, not the key 1111….
    log(e.recovery
      ? { level: "warn", msg: `the recovery key was replaced${where} ${by}`, recovery: e.recovery }
      : { level: "warn", msg: `the recovery key was removed${where} ${by}: there is no recovery key now` });
  }
  await applyActions(actions, e, now);
}

const spentLine = (what, approval) => ({ msg: `approval spent: ${what} executed; a new proposal of the same content will be vetoed`, approval });

/** Spend the approval an execution ran on, once per execution
 * (`spendExecution`), and keep it. `live`: seen as it happened. */
function spend(list, content, by, what, live) {
  const a = spendExecution(state, list, content, by, wallNow(), { live });
  if (a) log(spentLine(what, a));
  saveIncident();
}

/** A program-account scan of change accounts: an execution not seen before
 * spends its approval, whoever executed it; the first scan without a saved
 * baseline only records them (observeExecutions). */
function noteChangeScan(changes) {
  for (const { approval, change } of observeExecutions(state, changes, policy.approvedChanges, wallNow())) log(spentLine(`change ${change.id}`, approval));
  saveIncident();
}

/** Remember a watched Floor's pending proposal and the approval it would spend. */
function notePendingFloor(fl) {
  const kind = fl?.pendingKind;
  if (!kind || kind === 1 || kind === 2 || kind === 3 || fl.pendingVetoed) return;
  floorPendingSeen.set(fl.program, { id: BigInt(fl.pendingId), approval: floorApproval({ program: fl.program, kind, target: fl.pendingTarget, payload: fl.pendingPayload }) });
}

/** Events that spend an approval: the execution itself. `live`: read as it
 * happened, not replayed. */
async function noteExecution(e, live) {
  if (e.kind === "change_executed") {
    try {
      const acc = await rpc.account(await vc.changeAddress(e.id));
      const change = acc ? readPendingChange(acc.bytes) : null;
      if (change?.executed) spend(policy.approvedChanges, changeApproval(change), `c${BigInt(change.id)}`, `change ${change.id}`, live);
    } catch (err) {
      // The next account scan sees the executed change and spends it then.
      log({ level: "warn", msg: `could not read executed change ${e.id}: ${err.message}` });
    }
  } else if (e.kind === "floor_executed") {
    const by = `e${e.program}:${e.id}`;
    const seen = floorPendingSeen.get(e.program);
    if (seen && seen.id === e.id) {
      spend(policy.approvedFloorProposals, seen.approval, by, `floor ${e.program} proposal ${e.id}`, live);
      return;
    }
    // Proposed and executed with no read of its account in between (this
    // guardian was down for the whole delay): which approval it ran on is not
    // known here, and an unpinned one of that kind may still approve a replay.
    const prefix = `${e.program}:${e.proposalKind}:`;
    const unspent = (policy.approvedFloorProposals ?? []).filter((a) => parseApproval(a).content.startsWith(prefix) && !state.consumed.has(a));
    if (unspent.length && !state.executedSeen.has(by)) {
      state.executedSeen.add(by);
      saveIncident();
      log({ level: "error", msg: `floor ${e.program} proposal ${e.id} executed unseen: an approval it ran on may still be unspent; remove it from approvedFloorProposals`, program: e.program, proposalId: e.id, approvals: unspent });
    }
  }
}

/** Queued tickets already counted, with their addresses, for matching a truncated settlement. */
async function knownTickets() {
  const known = [];
  for (const mint of cfg.mints) {
    for (const row of settlementRows(state.outflows, state.pendingTickets, mint)) {
      const address = state.pendingTickets.get(row.ticketId)?.address;
      if (address) known.push({ mint, ticketId: row.ticketId, ticket: address, amount: row.amount });
    }
  }
  return known;
}

let unnamedLogged = false;

// A truncated transaction seen live: its queued tickets moved no tokens, so
// the balance fallback cannot see them. The ticket scan runs at once, out of
// its cadence, and judges and cancels them (docs/09, finding 76).
let truncatedSeen = false;

/**
 * Transactions on the Vault protocol account: its events and, for a truncated
 * log, its balances. `floor` instead reads one watched Floor config's
 * transactions for that program's events alone (followFloor). Fetched
 * `ingestConcurrency` at a time and processed in order; with `budgetMs`, it
 * stops after that long and returns the signatures left (newest-first).
 */
async function ingest(sigs, act, checkpoint = () => {}, floor = null, budgetMs = Infinity, { skipUnreadable = false } = {}) {
  const onSkip = (signature, e) => log({ level: "error", msg: "startup replay: a transaction the RPC will not return was skipped; an outflow in it is not counted in the rolling windows. Use an RPC with full history (docs/07 §6)", signature, error: String(e?.message ?? e).slice(0, 200) });
  return ingestBudgeted(sigs, {
    concurrency: cfg.ingestConcurrency ?? 8,
    budgetMs,
    checkpoint,
    fetchOne: (s) => (s.err ? null : skipUnreadable ? transactionOrSkip(rpc, s.signature, { onSkip }) : requireTransaction(rpc, s.signature)),
    processOne: (s, tx) => ingestOne(s, tx, act, floor),
  });
}

async function ingestOne(s, tx, act, floor) {
  if (s.err || tx?.skipped) return;
  const now = s.blockTime ?? tx?.blockTime ?? wallNow();
  const { events: decoded, truncated, unnamed } = watchedEvents(tx?.meta?.logMessages, floor
    ? { floorProgram: cfg.floorProgram, floorPrograms: [floor] }
    : { vaultProgram: cfg.vaultProgram, protocol: protocolKey });
  if (unnamed && !unnamedLogged) {
    unnamedLogged = true;
    log({ level: "error", msg: "Vault events that name no protocol were dropped: this Vault build predates finding 64, so this guardian cannot tell this protocol's events from another's. Upgrade the Vault program.", signature: s.signature });
  }
  for (const e of decoded) await noteExecution(e, act);
  if (floor) {
    for (const e of decoded) await consider(e, s.signature, now, act);
    return;
  }
  // Tickets as they were before this transaction: a surviving `settled`
  // event would otherwise drop the ticket its payout is matched against.
  const known = truncated ? await knownTickets() : [];
  for (const e of decoded) await consider(e, s.signature, now, act);
  if (!truncated) return;
  // Events past the log cap are gone; the instructions and balances are not.
  // What left the vaults beyond the events that survived is an unbacked
  // outflow of unknown owner.
  if (act) {
    log({ level: "warn", msg: "log truncated: outflow taken from the vault's transfers and balances", signature: s.signature });
    truncatedSeen = true;
  }
  const seen = truncatedOutflows(tx, { vaultProgram: cfg.vaultProgram, tokenMints, vaultOf, known, allowlist: policy.allowlistedOwners });
  const released = decoded.filter((e) => e.kind === "released");
  for (const [mint, amount] of unexplainedOutflow(seen.outflows, released, policy.allowlistedOwners)) {
    if (amount === 0n) continue;
    const e = { kind: "released", mint, owner: "(truncated log)", backed: 0n, instant: amount, queued: 0n, ticketId: 0n, etaS: 0 };
    await consider(e, s.signature, now, act);
  }
  // Their `vault:settled` events may be among the lost lines.
  for (const ticketId of seen.closed) assess(state, { kind: "ticket_closed", ticketId }, { now }, policy, act);
}

/** Rebuild active cancellation state from the Vault program's ticket accounts. */
async function refreshPendingTickets({ recoverOutflows = false, act = false } = {}) {
  const tickets = await activeTickets(rpc, cfg.vaultProgram, vc.protocol);
  if (recoverOutflows) {
    // As far back as the longest freeze rule reads (72 hours, finding 76).
    const cutoff = wallNow() - OUTFLOW_KEEP_S;
    for (const ticket of tickets) {
      if (ticket.createdS < cutoff) continue;
      if (state.tickets.has(ticket.id)) continue;
      const e = ticketRelease(ticket, vaultMints);
      if (e) {
        e.at = ticket.createdS;
        await consider(e, "chain:ticket", wallNow(), act);
      }
    }
  }
  // Merge positive on-chain observations. Do not discard event-derived tickets
  // that a lagging RPC snapshot may not include yet.
  for (const ticket of tickets) {
    rememberTicket(state, {
      ticketId: ticket.id,
      mint: vaultMints.get(ticket.vault) ?? null,
      vault: ticket.vault,
      owner: ticket.recipientOwner,
      amount: ticket.amount,
      address: ticket.address,
    });
  }
  return tickets.length;
}

/** A stale or unavailable ticket scan must not block known-ticket
 * cancellation. Its outcome is reported as a step of its own ("ticket scan"),
 * so a node that keeps refusing it raises the stall alert (docs/09, finding 71). */
async function tryRefreshPendingTickets(options = {}) {
  try {
    const count = await refreshPendingTickets(options);
    nextTicketScanAt = Date.now() + 60_000;
    stepOutcome("ticket scan", null);
    return count;
  } catch (e) {
    nextTicketScanAt = Date.now() + 5_000;
    stepOutcome("ticket scan", new Error(`active ticket scan failed; retrying: ${e.message}`));
    return null;
  }
}

// The newest slot the protocol account was read at. Reads never go back: a
// lagging node (a backup endpoint behind the others) would show an older freeze
// end, which looks like a quorum's unfreeze and would end an incident hold.
let protocolSlot = 0;
async function readProtocolAccount() {
  const r = await rpc.call("getAccountInfo", [b58encode(vc.protocol), { encoding: "base64", commitment: "confirmed", minContextSlot: protocolSlot }]);
  protocolSlot = Math.max(protocolSlot, r.context?.slot ?? 0);
  return r.value ? { bytes: Uint8Array.from(atob(r.value.data[0]), (c) => c.charCodeAt(0)) } : null;
}

/**
 * The active-ticket scan, on its own cadence (every 60 s, 5 s after a
 * failure) or at once after a truncated transaction: a queued release in a
 * truncated log moves no tokens, so only the scan finds it. Its recovered
 * releases are judged (`consider`), and while the protocol is frozen its
 * tickets are cancelled. It used to run inside the chain sync, behind an
 * ingest step that could take minutes under spam (docs/09, finding 76).
 */
async function scanTickets() {
  truncatedSeen = false;
  if ((await tryRefreshPendingTickets({ recoverOutflows: true, act: true })) === null) return;
  const now = wallNow();
  if (state.frozenUntil > now) {
    await applyActions(observeProtocolFreeze(state, state.frozenUntil, now, policy, true), { reason: "protocol already frozen" }, now);
  }
}

async function syncFromChain(act, { startup = false } = {}) {
  const acc = await readProtocolAccount();
  if (!acc) return;
  const p = decodeProtocol(acc.bytes);
  const now = wallNow();
  checkGuardianSet("protocol", p);
  observeFreezeEnd(state, lastChainFrozenUntil, p.frozenUntil);
  lastChainFrozenUntil = p.frozenUntil;
  state.frozenUntil = p.frozenUntil;
  pendingFreeze = retirePendingFreeze(pendingFreeze, p.frozenUntil, now, state);
  saveIncident();
  if (p.frozenUntil > now) state.freezing = false;
  const frozen = p.frozenUntil > now;
  const newFreeze = frozen && p.frozenUntil !== sweptFreezeUntil;
  if (frozen) {
    const actions = observeProtocolFreeze(state, p.frozenUntil, now, policy, act);
    if (act) await applyActions(actions, { reason: "protocol already frozen" }, now);
  }
  // The periodic scan is a loop step of its own (`scanTickets`), so neither a
  // failed read here nor an ingest backlog holds it up (finding 76).
  if (startup || newFreeze) {
    await tryRefreshPendingTickets({ recoverOutflows: true, act });
  }
  if (frozen) {
    // Apply cancels for tickets discovered by the scan above. Tickets already
    // scheduled before it were drained from `cancelled` on the first pass.
    const actions = observeProtocolFreeze(state, p.frozenUntil, now, policy, act);
    if (act) await applyActions(actions, { reason: "protocol already frozen" }, now);
    if (newFreeze) sweptFreezeUntil = p.frozenUntil;
  } else if (sweptFreezeUntil && sweptFreezeUntil <= now) {
    sweptFreezeUntil = 0;
  }
  const hold = act ? incidentHold(state, p.frozenUntil, now, policy) : null;
  if (hold) {
    state.freezing = true;
    await applyActions([hold], { reason: hold.reason }, now);
  }
  saveIncident();
}


/** Log a guardian set short of the margin, or that it is fixed (`guardianSetCheck`). */
const guardianSets = new Map();
function checkGuardianSet(which, set) {
  const line = guardianSetCheck(guardianSets, which, set, cfg.cluster === "mainnet-beta");
  if (line) log(line);
}

/** Log each Floor program's missing pieces, once per change (A5). */
async function checkFloor() {
  await checkFloors(floorWatch.map((fc) => [b58encode(fc.protected), async () => {
    const acc = await rpc.account(fc.config);
    return acc ? decodeFloor(acc.bytes) : null;
  }]), floorReported, checkGuardianSet, log);
}

/** Veto loosenings, lifeboat exits and Floor upgrades that are still pending. Replay does not
 * send actions, so a proposal that landed while this process was down is read
 * from the account.
 */
async function vetoStillPending(now) {
  const actions = [];
  const scans = [];
  if (policy.vetoLoosenings) {
    scans.push(["change scan", async () => {
      const changes = await activeChanges(rpc, cfg.vaultProgram, vc.protocol);
      // Executed changes first: a thief's copy of an approved change that
      // already ran is vetoed in the same scan.
      noteChangeScan(changes);
      for (const change of changes) {
        const action = pendingChangeVeto(change, policy, now, state.vetoed, state.consumed);
        if (!action) continue;
        state.vetoed.add(`c${action.changeId}`);
        actions.push(action);
      }
    }]);
  }
  for (const v of watched) {
    scans.push([`lifeboat exit scan (${v.mint})`, async () => {
      const acc = await rpc.account(v.vault);
      if (!acc) return;
      const action = pendingExitVeto({ ...decodeVault(acc.bytes), mint: v.mint }, policy, now, state.vetoed);
      if (!action) return;
      state.vetoed.add(`x${action.mint}:${action.executableS}`);
      actions.push(action);
    }]);
  }
  for (const fc of floorWatch) {
    scans.push([`floor proposal scan (${b58encode(fc.protected)})`, async () => {
      const acc = await rpc.account(fc.config);
      if (!acc) return;
      const fl = decodeFloor(acc.bytes);
      notePendingFloor(fl);
      const action = pendingUpgradeVeto(fl, policy, state.vetoed, { now, consumed: state.consumed });
      if (!action) return;
      state.vetoed.add(`f${action.program}:${action.proposalId}`);
      actions.push(action);
    }]);
  }
  nextChangeScanAt = Date.now() + 60_000;
  // A failed scan fails the step (logged there, and counted by stallWatch),
  // after the vetoes the other scans found are sent.
  try {
    await scanAll(scans);
  } finally {
    if (actions.length) await applyActions(actions, { reason: "still pending" }, now);
  }
}

// Keeper: executions already sent ("c<id>" for a change, "e<program>:<id>" for Floor).
const executedByKeeper = new Set();
const keeperErrors = new Map();

/** The execute instruction for an approved change (see keeper.mjs). */
async function executeChangeIx(action) {
  const mintOwner = action.kind === 1 ? (await rpc.account(key(action.target)))?.owner ?? null : null;
  return executeChangeIxFor({
    vaultProgram: cfg.vaultProgram, protocol: vc.protocol, payer: guardian.publicKey, defaultMint: watched[0].mint,
    changeId: action.changeId, kind: action.kind, target: action.target, mintOwner,
  });
}

/**
 * Execute what the operators approved once it is due. Anyone may; this makes
 * sure someone does, so an approved guardian renewal or key rotation does not
 * lapse. A failure is logged once per reason and retried next scan.
 */
async function keepApproved(now) {
  // `ix` may be a function: building the instruction can read the chain, and
  // one failed read must not skip the other approved changes.
  const attempt = async (doneKey, what, ix, spent = () => {}) => {
    try {
      const signature = await guardianSend([typeof ix === "function" ? await ix() : ix]);
      executedByKeeper.add(doneKey);
      log({ action: "execute", what, signature });
      // Spent before the next one is looked at: a duplicate of the same
      // content in the same scan is not executed too.
      spent();
    } catch (e) {
      const reason = e.message.slice(0, 160);
      if (keeperErrors.get(doneKey) !== reason) log({ level: "warn", msg: `keeper could not execute ${what}: ${reason}` });
      keeperErrors.set(doneKey, reason);
    }
  };
  const scans = [["keeper change scan", async () => {
    const changes = await activeChanges(rpc, cfg.vaultProgram, vc.protocol);
    // Also takes the baseline of executed changes, before this executes any.
    noteChangeScan(changes);
    for (const change of changes) {
      const action = dueApprovedChange(change, policy, now, executedByKeeper, state.consumed);
      if (action) {
        await attempt(`c${action.changeId}`, `change ${action.changeId}`, () => executeChangeIx(action),
          () => spend(policy.approvedChanges, action.approval, `c${action.changeId}`, `change ${action.changeId}`, true));
      }
    }
  }]];
  for (const fc of floorWatch) {
    scans.push([`keeper floor scan (${b58encode(fc.protected)})`, async () => {
      const acc = await rpc.account(fc.config);
      if (!acc) return;
      const fl = decodeFloor(acc.bytes);
      notePendingFloor(fl);
      const action = dueApprovedFloor(fl, policy, now, executedByKeeper, state.consumed);
      if (!action) return;
      // The buffer's rent returns to the owner (Floor requires it as spill).
      const ix = action.kind === 1 || action.kind === 2 ? fc.executeUpgrade(key(action.target), key(fl.owner)) : fc.executeConfig();
      const doneKey = `e${action.program}:${action.proposalId}`;
      await attempt(doneKey, `floor ${action.program} proposal ${action.proposalId}`, ix,
        () => spend(policy.approvedFloorProposals, action.approval, doneKey, `floor ${action.program} proposal ${action.proposalId}`, true));
    }]);
  }
  // A failed scan fails the step, so a node refusing it for good raises the
  // stall alert (docs/09, finding 71).
  await scanAll(scans);
}

// Mints whose replayed startup window has not been judged yet (no attest).
let unjudged = new Set();

/** Judge the replayed startup window, once per mint, once it has a figure. */
async function judgeStartupWindow(now) {
  const worst = (mint) => (worst1h.has(mint) ? worstFor(mint) : null);
  const judged = judgeReplayedWindow(state, unjudged, worst, now, policy);
  unjudged = judged.unjudged;
  if (!judged.action) return;
  state.freezing = true;
  log({ msg: "window already over threshold after catch-up", mint: judged.mint, reason: judged.action.reason });
  await applyActions([judged.action], { mint: judged.mint }, now);
}

// A step failing without a break for `stallAlertS` (default 120) is a guardian
// gone quiet, and says so urgently, at most every 10 minutes per step.
const stalls = stallWatch({ afterMs: (cfg.stallAlertS ?? 120) * 1000 });

/** A step's outcome: `e` null for a success. */
function stepOutcome(name, e) {
  if (!e) {
    stalls.ok(name);
    return;
  }
  log({ level: "warn", msg: `${name}: ${e.message}` });
  const failingMs = stalls.failed(name, Date.now());
  if (failingMs !== null) {
    log({ level: "error", msg: `guardian stalled: "${name}" keeps failing; it may be blind to new events until this is fixed`, reason: `failing for ${Math.round(failingMs / 1000)}s: ${e.message.slice(0, 200)}` });
  }
}

/** One step of the loop. A failing step must not hold up the others. */
async function step(name, run) {
  try {
    await run();
    stepOutcome(name, null);
  } catch (e) {
    stepOutcome(name, e);
  }
}

// Watched Floor configs read at least once by this process (followFloor), and
// the slot it started at (main): a replay covers only what landed up to it.
const floorFollowed = new Set();
let floorLiveAfterSlot = null;

/**
 * Floor's events (a proposal, an execution, a replaced recovery key) are
 * written in transactions on the Floor config, which need not touch the Vault
 * protocol: reading only the protocol's signatures, the guardian saw them only
 * when the two shared a transaction. Each watched config is followed on its
 * own, and only that program's Floor events are read from it.
 *
 * Its cursor is kept in the state file. A restart reads on from it, back to
 * at most the Vault startup's day, as a replay of what landed up to the slot
 * this process started at (nothing is sent: the account scans veto what is
 * still pending), and what is newer live, so an execution while this
 * guardian was down still spends its approval. Each restart used to start at
 * the newest signature, and those executions were never seen (docs/09,
 * finding 71).
 * Without a cursor (a first start), it anchors at the newest signature; the
 * account scans cover what came before.
 */
async function followFloor() {
  await followConfigs(floorWatch.map((fc) => ({ address: b58encode(fc.config), program: b58encode(fc.protected) })), {
    page: (address, q) => rpc.call("getSignaturesForAddress", [address, q]),
    cursors: floorCursors,
    followed: floorFollowed,
    liveAfterSlot: floorLiveAfterSlot,
    oldestWanted: () => wallNow() - DAY_S,
    knows: knowsSignature,
    // Live, bounded like the protocol's ingest (finding 76): what is left is
    // listed again from the saved cursor next pass.
    ingest: (sigs, live, checkpoint, program) => ingest(sigs, live, checkpoint, program, live ? ingestBudgetMs : Infinity),
    log,
    saved: saveIncident,
  });
}

/**
 * With no state file read, the incident hold is rebuilt from chain: if the
 * protocol is frozen now and the replayed window breaks a freeze rule, the
 * hold opens at the first replayed breach. With every state file lost, the
 * hold used not to resume, and the freeze simply ran out (docs/09, finding 76).
 */
function rebuildIncident() {
  if (restoredState || state.incidentSince != null || !(lastChainFrozenUntil > wallNow())) return;
  let since = null;
  for (const mint of new Set(state.outflows.map((o) => o.mint))) {
    if (!worst1h.has(mint)) continue;
    const t = replayedBreachTime(state, mint, worstFor(mint), wallNow(), policy);
    if (t !== null && (since === null || t < since)) since = t;
  }
  if (since === null) return;
  state.incidentSince = since;
  saveIncident();
  log({ level: "warn", msg: "incident hold rebuilt from chain: no state file, the protocol is frozen, and the replayed window broke a freeze rule", incidentSince: since });
}

/**
 * A config naming its cluster is checked against the node's genesis hash: a
 * mainnet guardian pointed at a devnet RPC (or the reverse) watched nothing
 * real and looked healthy (docs/09, finding 83). Every endpoint is asked, not
 * only the one that answers first (finding 114). One found on another
 * cluster refuses the start. One that does not answer in time is used only
 * once it answers on the right cluster (FailoverRpc asks it before its first
 * use and before each freshness check), and if it answers from another
 * cluster later, that is logged.
 */
async function checkCluster() {
  if (!cfg.cluster || cfg.cluster === "localnet") return;
  if (!(rpc instanceof FailoverRpc)) {
    const got = await rpc.call("getGenesisHash", []);
    if (got !== GENESIS[cfg.cluster]) throw new Error(`config.cluster is ${cfg.cluster}, but the RPC serves another cluster (genesis ${got})`);
    return;
  }
  const causes = [];
  const asks = rpc.endpoints.map((_, i) => rpc.admit(i).catch((e) => { causes[i] = e.message; }));
  // Once one endpoint is on the right cluster, the rest get CLUSTER_GRACE_MS:
  // a silent backup does not hold up a restart by its timeout.
  const anyOk = Promise.any(asks.map((p, i) => p.then(() => (rpc.cluster[i] === "ok" ? true : Promise.reject()))));
  await Promise.race([Promise.all(asks), anyOk.then(() => new Promise((r) => setTimeout(r, CLUSTER_GRACE_MS)), () => Promise.all(asks))]);
  // None answered: ask once more as any call does (a busy endpoint's wait is
  // waited out once); its error stops the start.
  if (!rpc.cluster.includes("ok") && !rpc.cluster.includes("wrong")) await rpc.call("getGenesisHash", []);
  const wrong = rpcUrls.flatMap((_, i) => (rpc.cluster[i] === "wrong" ? [`${endpointName(i)} serves another cluster (genesis ${genesisSeen[i]})`] : []));
  if (wrong.length) throw new Error(`config.cluster is ${cfg.cluster}, but RPC endpoint ${wrong.join("; ")}`);
  if (rpc.cluster[rpc.active] !== "ok") rpc.switchTo(rpc.cluster.indexOf("ok"), new Error("no answer to getGenesisHash at start"));
  const silent = rpcUrls.flatMap((_, i) => (rpc.cluster[i] === "unknown" ? [`${endpointName(i)}: ${(causes[i] ?? `no answer within ${CLUSTER_GRACE_MS / 1000} s`).slice(0, 160)}`] : []));
  if (silent.length) log({ level: "error", msg: `RPC endpoint ${silent.join("; ")}: no answer to getGenesisHash, so not used until it answers on ${cfg.cluster} (asked again before each freshness check)` });
  clusterChecked = true;
}

/**
 * The guardian key pays every freeze, veto, cancel and heartbeat. Below
 * `minBalanceSol` (default 0.05) it says so, urgently, at most every 6 hours:
 * a key with no SOL learns it at the first freeze (docs/09, finding 83).
 */
let balanceWarnedAt = 0;
async function checkBalance() {
  const lamports = (await rpc.call("getBalance", [guardian.address, { commitment: "confirmed" }]))?.value;
  const min = (cfg.minBalanceSol ?? 0.05) * 1e9;
  if (lamports != null && lamports < min && Date.now() - balanceWarnedAt > 6 * 3_600_000) {
    balanceWarnedAt = Date.now();
    log({ level: "error", msg: `the guardian key holds ${lamports / 1e9} SOL, under ${min / 1e9}: fund it, or its freezes, vetoes and heartbeats will fail`, lamports });
  }
}

/**
 * An outbound liveness ping (a dead-man's switch: healthchecks.io, a pager's
 * heartbeat URL) every `liveness.everyS` (default 60) while the loop runs.
 * The bot's own alerts stop when the process or its host dies; the service
 * that stops hearing this ping is what tells someone (docs/09, finding 83).
 */
let livenessAt = 0;
function pingLiveness() {
  if (!cfg.liveness || Date.now() < livenessAt) return;
  livenessAt = Date.now() + (cfg.liveness.everyS ?? 60) * 1000;
  fetch(cfg.liveness.url, { method: "GET", signal: AbortSignal.timeout(10_000) }).catch((e) => log({ level: "warn", msg: `liveness ping failed: ${e.message}` }));
}

async function main() {
  log({ msg: "guardian started", guardian: guardian.address, protocol: b58encode(vc.protocol), policy });
  for (const w of configWarnings) log({ level: "warn", msg: w });
  if (stateProblem) log({ level: "error", msg: stateProblem });
  await must(checkCluster);
  // Fatal, like the cluster check: with no start slot, a restart would replay
  // all that lands until its first good poll.
  if (floorWatch.length) floorLiveAfterSlot = await must(() => startSlot(rpc));
  await checkBalance().catch((e) => log({ level: "warn", msg: `could not read the guardian key's balance: ${e.message}` }));
  if (state.incidentSince != null) log({ msg: "incident hold resumed from saved state", incidentSince: state.incidentSince, stateFile });
  const unpinned = unpinnedChangeApprovals(policy);
  if (unpinned.length) {
    log({ level: "warn", msg: "approvedChanges not pinned to a base version: each is spent once a matching change executes, as recorded in the state file. Pin them (\"kind:target:payloadHex#<baseVersion>\", printed by cloud/deploy/approvals.mjs) so no replay can match, whatever this guardian remembers (docs/07)", approvals: unpinned });
  }
  if (!state.changeBaseline) log({ msg: "no record of executed changes yet: the first change scan records them and spends no approval", stateFile });
  await refreshWorstCase();
  let heartbeatAt = await beat();
  let balanceAt = Date.now() + 600_000;
  // As far back as the longest freeze rule reads: 72 hours with the 72-hour
  // rule on (finding 76), else the day.
  const oldest = wallNow() - (policy.freezeFractionOfWorst72h > 0 ? OUTFLOW_KEEP_S : DAY_S);
  const maxReplay = cfg.startupMaxSignatures ?? 50_000;
  const history = await signatures(undefined, oldest, { maxRows: maxReplay });
  const until = history[0]?.signature;
  const inWindow = history.filter((s) => s.blockTime == null || s.blockTime >= oldest);
  if (history.truncated) {
    const from = history.at(-1)?.blockTime;
    log({ level: "error", msg: `startup replay capped at its newest ${history.length} signatures (startupMaxSignatures): outflows before ${from ? new Date(from * 1000).toISOString() : "then"} are not counted, so the 24-hour and 72-hour rules undercount until that time leaves their window. Spam on the protocol account? (docs/09, finding 83)`, signatures: history.length });
  }
  await ingest(inWindow, false, () => {}, null, Infinity, { skipUnreadable: true });
  // The chain scan recovers every active ticket, including older tickets whose
  // release is outside the rolling outflow window. Current chain state is live,
  // so an already-active freeze must sweep tickets at startup too.
  await syncFromChain(true, { startup: true });
  rebuildIncident();
  unjudged =new Set([...cfg.mints, ...state.outflows.map((o) => o.mint)]);
  await judgeStartupWindow(decisionTime(wallNow(), state.outflows));
  // Floor cursors before the scan, so nothing lands between the two unseen.
  if (floorWatch.length) await step("floor events", followFloor);
  // A step: a refused scan here is retried by the loop and counted toward a
  // stall, not fatal.
  await step("pending proposals", () => vetoStillPending(wallNow()));
  log({ msg: "caught up", signatures: inWindow.length });
  await checkFloor().catch((e) => log({ level: "warn", msg: `floor check failed: ${e.message}` }));
  let cursor = until;
  // The cursor's slot, and what was ingested in it: enough to read on if the
  // node forgets the cursor signature (cursorGone).
  let cursorSlot = history[0]?.slot ?? 0;
  let cursorSeen = new Set(history.filter((s) => s.slot === cursorSlot).map((s) => s.signature));
  let goneLogged = null;
  let lastAttest = Date.now();
  lastFloorCheck = Date.now();
  // Signatures listed but not yet ingested (newest-first): a pass ingests for
  // at most `ingestBudgetMs` and the rest waits here for the next one.
  let backlog = [];
  let lagCheckedAt = 0;
  let lagAlertedAt = 0;
  let freshnessAt = Date.now() + freshnessEveryMs;
  for (;;) {
    // Chain state first, then the freeze retry, which has to see it: a freeze
    // that already landed (a backup endpoint may have carried it) must not be
    // sent again, since a second freeze extends the lockout. Each step has its
    // own try, so a transaction the RPC cannot return yet never holds up a
    // freeze, a veto or a heartbeat.
    await step("chain sync", async () => {
      await syncFromChain(true);
      if (!pendingFreeze || wallNow() < state.frozenUntil) return;
      const { action, event, eventTime } = pendingFreeze;
      if (await execute(action, event, eventTime)) {
        state.freezing = true;
        pendingFreeze = null;
        await sweepCancels(event, eventTime);
      }
    });
    await step("ingest", async () => {
      if (!backlog.length) {
        try {
          backlog = await signatures(cursor, null, { minSlot: cursorSlot || null, seen: cursorSeen });
        } catch (e) {
          if (!cursorGone(e, cursor)) throw e;
          if (goneLogged !== cursor) {
            goneLogged = cursor;
            log({ level: "warn", msg: "the node no longer has the cursor signature; reading on from its slot", cursor, slot: cursorSlot });
          }
          backlog = await signatureWalkSinceSlot((q) => rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), q]), { slot: cursorSlot, seen: cursorSeen });
        }
      }
      // A failure keeps what is not done yet; the rest is retried from there.
      const done = new Set();
      try {
        backlog = await ingest(backlog, true, (signature, s) => {
          done.add(signature);
          cursor = signature;
          if (s.slot !== cursorSlot) {
            cursorSlot = s.slot;
            cursorSeen = new Set();
          }
          cursorSeen.add(signature);
        }, null, ingestBudgetMs);
      } catch (e) {
        backlog = backlog.filter((s) => !done.has(s.signature));
        throw e;
      }
      // More than `lagAlertS` behind the chain: say so, urgently, at most every
      // 10 minutes. The chain's time is read only while a backlog is left, at
      // most every 10 s (docs/09, finding 76).
      if (!backlog.length || Date.now() - lagCheckedAt < 10_000) return;
      lagCheckedAt = Date.now();
      const chainTimeS = await rpc.call("getSlot", [{ commitment: "confirmed" }]).then((slot) => rpc.call("getBlockTime", [slot])).catch(() => null);
      const lagS = ingestLagS(backlog, chainTimeS);
      if (lagS > lagAlertS && Date.now() - lagAlertedAt > 600_000) {
        lagAlertedAt = Date.now();
        log({ level: "warn", msg: `ingest lagging: the oldest unread transaction on the protocol account is ${lagS}s behind the chain, ${backlog.length} waiting; a freeze comes that much later. Spam on the protocol account, or a slow RPC (docs/07 §6)`, lagS, backlog: backlog.length });
      }
    });
    // On its own cadence, or at once after a truncated transaction, whatever
    // the ingest backlog (finding 76).
    if (ticketScanDue(Date.now(), nextTicketScanAt, truncatedSeen)) await scanTickets();
    if (freshnessEveryMs > 0 && rpc instanceof FailoverRpc && Date.now() >= freshnessAt) {
      freshnessAt = Date.now() + freshnessEveryMs;
      await step("rpc freshness", async () => {
        const r = await rpc.crossCheck(b58encode(vc.protocol));
        if (r.switched) log({ level: "warn", msg: `${r.reason}; switched endpoints (docs/07 §6)`, slots: r.slots });
      });
    }
    if (floorWatch.length) await step("floor events", followFloor);
    // A step with nothing to do this pass is idle: an earlier failure of it is
    // over, not a stall that went on while it did not run (docs/09, finding 71).
    if (changeChecks.size) await step("approval checks", runChangeChecks);
    else stalls.idle("approval checks");
    if (!pendingVetoes.length) stalls.idle("veto retry");
    if (pendingVetoes.length && Date.now() >= vetoNotBefore) {
      await step("veto retry", async () => {
        const still = [];
        for (const action of pendingVetoes) {
          if (!(await execute(action, { reason: action.reason }, wallNow(), { retrying: true }))) still.push(action);
        }
        pendingVetoes = still;
        if (still.length) vetoNotBefore = Date.now() + VETO_RETRY_MS;
      });
    }
    if (Date.now() - lastAttest > 10_000) {
      await step("attest", async () => {
        await refreshWorstCase();
        lastAttest = Date.now();
        // A mint whose attest failed at startup has its replayed window
        // judged once the figure exists.
        if (unjudged.size) await judgeStartupWindow(decisionTime(wallNow(), state.outflows));
      });
    }
    if (Date.now() >= nextChangeScanAt) {
      await step("pending proposals", () => vetoStillPending(wallNow()));
      await step("keeper", () => keepApproved(wallNow()));
    }
    if (floorWatch.length && Date.now() - lastFloorCheck > 60_000) {
      lastFloorCheck = Date.now();
      await step("floor check", checkFloor);
    }
    if (Date.now() >= heartbeatAt) await step("heartbeat", async () => { heartbeatAt = await beat(); });
    if (Date.now() >= balanceAt) {
      balanceAt = Date.now() + 600_000;
      await step("balance", checkBalance);
    }
    pingLiveness();
    await new Promise((r) => setTimeout(r, cfg.pollMs ?? 400));
  }
}

main().catch(fatal);
