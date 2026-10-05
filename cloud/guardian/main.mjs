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
//     "floorProgram": "...", "floorProtected": ["program id", ...] }
//
// With `floorProtected`, the bot also checks each program's Floor config every
// minute and logs a warning whenever what is missing changes: no abort buffer
// staged (nobody can stop it) or no snapshot pinned (docs/15, A5).
//
// Every decision is one JSON line on stdout: the triggering event, the action,
// the reason, the transaction, and the latency from the triggering
// transaction's block time to the guardian's own confirmation.
//
// The 24-hour rule needs the last day of releases. On startup the bot replays
// that window from chain history (block times, not the wall clock) and, if it
// is already over a threshold and the protocol is not frozen, freezes once.
// A failed freeze is retried; it does not stick in `state.freezing`.
//
// What it believes: an event counts only if the Vault (or Floor) program wrote
// it (any program can write a "Program data:" line); freeze state is read from
// chain every cycle; active tickets are scanned at startup, on a freeze, and
// periodically; truncated logs use the vault's own transfers and balances.
//
// Heartbeats keep this key live on the Vault and on every watched Floor it
// guards, each inside its chain interval. A failed one is retried on a
// backoff; a key that is already stale or absent is reported, not resent.

import { readFileSync } from "node:fs";
import { Rpc, b58encode, parseLogs, decodeProtocol, decodeFloor } from "../lib/solana.mjs";
import { Keypair, send, priorityPrice } from "../lib/signer.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { assess, decode, floorAlerts, newState, observeProtocolFreeze, pendingCancels, rememberTicket, retirePendingFreeze, decisionTime, judgeReplayedWindow, queueFailedVeto, guardianStanding, afterHeartbeat, heartbeatEveryAfterAccount, pendingChangeVeto, pendingUpgradeVeto, vetoRetryDisposition, readChangeVeto, DEFAULT_POLICY, DAY_S } from "./policy.mjs";
import { ingestSignatures, signatureWalk, PAGE_LOG_INTERVAL, requireTransaction } from "./follow.mjs";
import { activeTickets, activeChanges, ticketRelease, settlementRows, truncatedOutflows, unexplainedOutflow } from "./chain.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const policy = { ...DEFAULT_POLICY, ...(cfg.policy ?? {}) };
const rpc = new Rpc(cfg.rpc);
// Extra endpoints every guardian transaction is also sent to (optional).
const extraRpcs = (cfg.rpcs ?? []).map((url) => new Rpc(url));
const guardian = Keypair.load(cfg.guardianKey);
const vc = await new VaultClient(cfg.vaultProgram, cfg.protocolProgram).init();
// The watched vaults, by vault address and by token account address.
const watched = await Promise.all(cfg.mints.map(async (mint) => ({ mint, ...(await vc.vault(mint)) })));
const vaultMints = new Map(watched.map((v) => [b58encode(v.vault), v.mint]));
const tokenMints = new Map(watched.map((v) => [b58encode(v.vaultTokens), v.mint]));
// Each mint's vault PDA. A transfer into a token account it owns is a lifeboat move.
const vaultOf = new Map(watched.map((v) => [v.mint, b58encode(v.vault)]));
// Only these programs' events count: any program can write "Program data:".
const trusted = [cfg.vaultProgram, cfg.floorProgram].filter(Boolean);
const state = newState();
const log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o }, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

// Programs under Floor whose readiness the bot reports (A5).
const floorWatch = cfg.floorProgram
  ? await Promise.all((cfg.floorProtected ?? []).map((p) => new FloorClient(cfg.floorProgram, p).init()))
  : [];
const floorReported = new Map();

const worst1h = new Map();
const worst24h = new Map();
const warned = new Set();
let pendingFreeze = null;
let pendingVetoes = [];
let vetoNotBefore = 0;
const cancelRetryAt = new Map();
const CANCEL_RETRY_MS = 15_000;
const VETO_RETRY_MS = 15_000;
let nextTicketScanAt = 0;
let nextChangeScanAt = 0;
let sweptFreezeUntil = 0;

function wallNow() {
  return Math.floor(Date.now() / 1000);
}

/** This mint's own worst case. Missing attest is 0: any unbacked outflow freezes. */
function worstFor(mint) {
  if (worst1h.has(mint)) {
    return { worst1h: worst1h.get(mint), worst24h: worst24h.get(mint) ?? 0n };
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
    } catch (e) {
      log({ level: "warn", msg: `attest failed for ${mint}: ${e.message}` });
    }
  }
}

/** Compute budget, priority price and extra endpoints for one guardian transaction. */
async function sendOptions() {
  let microLamports = policy.priorityMicroLamports;
  if (microLamports === "auto") {
    try {
      const fees = await rpc.call("getRecentPrioritizationFees", [[b58encode(vc.protocol)]]);
      microLamports = priorityPrice(fees, { cap: policy.maxPriorityMicroLamports });
    } catch {
      microLamports = 0; // no fee data: send anyway, without a price
    }
  }
  return { computeUnits: policy.computeUnits, microLamports: Number(microLamports) || 0, rpcs: extraRpcs };
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
      const signature = await send(rpc, guardian, [ix()], [], await sendOptions());
      log({ ...logged, signature });
      outcome = "sent";
    } catch (e) {
      log({ level: "warn", msg: `${logged.action} failed: ${e.message}` });
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
    switch (action.type) {
      case "freeze":
        ixs = [vc.freeze(guardian.publicKey, action.secs)];
        break;
      case "cancel": {
        // The caller returns a failed cancel to the sweep; this one waits.
        if ((cancelRetryAt.get(action.ticketId) ?? 0) > Date.now()) return false;
        const vault = action.vault ?? (await vc.vault(action.mint ?? event.mint)).vault;
        const ticket = await vc.ticketAddress(action.ticketId);
        const acc = await rpc.account(ticket);
        if (!acc) {
          // A lagging read is not proof the ticket settled. Retry; leaving it
          // marked cancelled would let it pay out when the freeze ends.
          log({ action: "cancel", skipped: "ticket account missing; will retry", ticketId: action.ticketId });
          cancelRetryAt.set(action.ticketId, Date.now() + CANCEL_RETRY_MS);
          return false;
        }
        cancelRetryAt.delete(action.ticketId);
        const payer = acc.bytes.slice(136, 168); // Ticket: disc, protocol, vault, recipient, recipient_owner, payer
        ixs = [vc.cancelTicket(vault, ticket, guardian.publicKey, payer)];
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
      case "floor_veto": {
        const fc = await new FloorClient(cfg.floorProgram, action.program).init();
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
    const sig = await send(rpc, guardian, ixs, [], await sendOptions());
    const confirmed = Date.now();
    log({
      action: action.type,
      reason: action.reason,
      ticketId: action.ticketId,
      signature: sig,
      reaction_ms: confirmed - started,
      since_trigger_s: eventTime ? Math.round(confirmed / 1000 - eventTime) : undefined,
    });
    return true;
  } catch (e) {
    log({ level: "error", action: action.type, error: e.message });
    return false;
  }
}

/** After a freeze lands: cancel every queued ticket still outstanding. */
async function sweepCancels(event, eventTime, { refresh = true } = {}) {
  for (const id of cancelRetryAt.keys()) if (!state.pendingTickets.has(id)) cancelRetryAt.delete(id);
  if (refresh) {
    await tryRefreshPendingTickets();
  }
  for (const action of pendingCancels(state, policy)) {
    const ok = await execute(action, event, eventTime);
    if (ok) state.pendingTickets.delete(action.ticketId);
    else state.cancelled.delete(action.ticketId);
  }
}

async function applyActions(actions, event, eventTime) {
  let freezeOk = true;
  let froze = false;
  for (const action of actions) {
    // Cancels in this batch are "while frozen". If the freeze transaction
    // failed and the protocol is not already frozen, don't cancel yet.
    if (action.type === "cancel" && !freezeOk) {
      state.cancelled.delete(action.ticketId);
      continue;
    }
    const ok = await execute(action, event, eventTime);
    if (action.type === "cancel") {
      if (ok) state.pendingTickets.delete(action.ticketId);
      else state.cancelled.delete(action.ticketId);
    }
    if (action.type === "veto_change" || action.type === "floor_veto") {
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
}

/** Newest-first. `oldestWanted` null walks until `until` (live); a number walks the startup window. */
async function signatures(until, oldestWanted) {
  let lastLoggedPage = 0;
  return signatureWalk(
    (query) => rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), query]),
    {
      until,
      oldestWanted,
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
  if (!act) return;
  log({ event: e.kind, signature, ...e });
  await applyActions(actions, e, now);
}

/** Queued tickets already counted, with their addresses, for matching a truncated settlement. */
async function knownTickets() {
  const known = [];
  for (const mint of cfg.mints) {
    for (const row of settlementRows(state.outflows, state.pendingTickets, mint)) {
      known.push({ mint, ticketId: row.ticketId, ticket: b58encode(await vc.ticketAddress(row.ticketId)), amount: row.amount });
    }
  }
  return known;
}

async function ingest(sigs, act, checkpoint = () => {}) {
  await ingestSignatures(sigs, async (s) => {
    if (s.err) return;
    const tx = await requireTransaction(rpc, s.signature);
    const now = s.blockTime ?? tx?.blockTime ?? wallNow();
    const { events, truncated } = parseLogs(tx?.meta?.logMessages);
    const decoded = [];
    for (const raw of events) {
      if (!trusted.includes(raw.program)) continue; // written by another program: not an event
      const e = decode(raw);
      if (e.kind !== "other") decoded.push(e);
    }
    // Tickets as they were before this transaction: a surviving `settled`
    // event would otherwise drop the ticket its payout is matched against.
    const known = truncated ? await knownTickets() : [];
    for (const e of decoded) await consider(e, s.signature, now, act);
    if (!truncated) return;
    // Events past the log cap are gone; the instructions and balances are not.
    // What left the vaults beyond the events that survived is an unbacked
    // outflow of unknown owner.
    if (act) log({ level: "warn", msg: "log truncated: outflow taken from the vault's transfers and balances", signature: s.signature });
    const seen = truncatedOutflows(tx, { vaultProgram: cfg.vaultProgram, tokenMints, vaultOf, known, allowlist: policy.allowlistedOwners });
    const released = decoded.filter((e) => e.kind === "released");
    for (const [mint, amount] of unexplainedOutflow(seen.outflows, released, policy.allowlistedOwners)) {
      if (amount === 0n) continue;
      const e = { kind: "released", mint, owner: "(truncated log)", backed: 0n, instant: amount, queued: 0n, ticketId: 0n, etaS: 0 };
      await consider(e, s.signature, now, act);
    }
    // Their `vault:settled` events may be among the lost lines.
    for (const ticketId of seen.closed) assess(state, { kind: "ticket_closed", ticketId }, { now }, policy, act);
  }, checkpoint);
}

/** Rebuild active cancellation state from the Vault program's ticket accounts. */
async function refreshPendingTickets({ recoverOutflows = false, act = false } = {}) {
  const tickets = await activeTickets(rpc, cfg.vaultProgram, vc.protocol);
  if (recoverOutflows) {
    const cutoff = wallNow() - DAY_S;
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
    });
  }
  return tickets.length;
}

/** A stale or unavailable ticket scan must not block known-ticket cancellation. */
async function tryRefreshPendingTickets(options = {}) {
  try {
    const count = await refreshPendingTickets(options);
    nextTicketScanAt = Date.now() + 60_000;
    return count;
  } catch (e) {
    log({ level: "warn", msg: `active ticket scan failed; retrying: ${e.message}` });
    nextTicketScanAt = Date.now() + 5_000;
    return null;
  }
}

async function syncFromChain(act, { startup = false } = {}) {
  const acc = await rpc.account(vc.protocol);
  if (!acc) return;
  const p = decodeProtocol(acc.bytes);
  const now = wallNow();
  state.frozenUntil = p.frozenUntil;
  pendingFreeze = retirePendingFreeze(pendingFreeze, p.frozenUntil, now);
  if (p.frozenUntil > now) state.freezing = false;
  const frozen = p.frozenUntil > now;
  const newFreeze = frozen && p.frozenUntil !== sweptFreezeUntil;
  if (frozen) {
    const actions = observeProtocolFreeze(state, p.frozenUntil, now, policy, act);
    if (act) await applyActions(actions, { reason: "protocol already frozen" }, now);
  }
  const periodicScan = Date.now() >= nextTicketScanAt;
  if (startup || newFreeze || periodicScan) {
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
}

/** Log each Floor program's missing pieces, once per change (A5). */
async function checkFloor() {
  for (const fc of floorWatch) {
    const program = b58encode(fc.protected);
    const acc = await rpc.account(fc.config);
    const alerts = acc ? floorAlerts(decodeFloor(acc.bytes)) : [{ code: "missing", msg: "no Floor config for this program" }];
    const codes = alerts.map((a) => a.code).join(",");
    if (floorReported.get(program) === codes) continue;
    floorReported.set(program, codes);
    if (alerts.length) log({ level: "warn", msg: "floor not ready", program, alerts });
    else log({ msg: "floor ready", program });
  }
}

/** Veto loosenings and Floor upgrades that are still pending. Replay does not
 * send actions, so a proposal that landed while this process was down is read
 * from the account.
 */
async function vetoStillPending(now) {
  const actions = [];
  if (policy.vetoLoosenings) {
    try {
      for (const change of await activeChanges(rpc, cfg.vaultProgram, vc.protocol)) {
        const action = pendingChangeVeto(change, policy, now, state.vetoed);
        if (!action) continue;
        state.vetoed.add(`c${action.changeId}`);
        actions.push(action);
      }
    } catch (e) {
      log({ level: "warn", msg: `change scan failed; retrying: ${e.message}` });
    }
  }
  for (const fc of floorWatch) {
    try {
      const acc = await rpc.account(fc.config);
      if (!acc) continue;
      const fl = decodeFloor(acc.bytes);
      const action = pendingUpgradeVeto(fl, policy, state.vetoed);
      if (!action) continue;
      state.vetoed.add(`f${action.program}:${action.proposalId}`);
      actions.push(action);
    } catch (e) {
      log({ level: "warn", msg: `floor proposal scan failed; retrying: ${e.message}` });
    }
  }
  if (actions.length) await applyActions(actions, { reason: "still pending" }, now);
  nextChangeScanAt = Date.now() + 60_000;
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

/** One step of the loop. A failing step must not hold up the others. */
async function step(name, run) {
  try {
    await run();
  } catch (e) {
    log({ level: "warn", msg: `${name}: ${e.message}` });
  }
}

async function main() {
  log({ msg: "guardian started", guardian: guardian.address, protocol: b58encode(vc.protocol), policy });
  await refreshWorstCase();
  let heartbeatAt = await beat();
  const oldest = wallNow() - DAY_S;
  const history = await signatures(undefined, oldest);
  const until = history[0]?.signature;
  const inWindow = history.filter((s) => s.blockTime == null || s.blockTime >= oldest);
  await ingest(inWindow, false);
  // The chain scan recovers every active ticket, including older tickets whose
  // release is outside the rolling outflow window. Current chain state is live,
  // so an already-active freeze must sweep tickets at startup too.
  await syncFromChain(true, { startup: true });
  unjudged = new Set([...cfg.mints, ...state.outflows.map((o) => o.mint)]);
  await judgeStartupWindow(decisionTime(wallNow(), state.outflows));
  await vetoStillPending(wallNow());
  log({ msg: "caught up", signatures: inWindow.length });
  await checkFloor().catch((e) => log({ level: "warn", msg: `floor check failed: ${e.message}` }));
  let cursor = until;
  let lastAttest = Date.now();
  let lastFloorCheck = Date.now();
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
      const sigs = await signatures(cursor, null);
      await ingest(sigs, true, (signature) => { cursor = signature; });
    });
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
    if (Date.now() >= nextChangeScanAt) await step("pending proposals", () => vetoStillPending(wallNow()));
    if (floorWatch.length && Date.now() - lastFloorCheck > 60_000) {
      lastFloorCheck = Date.now();
      await step("floor check", checkFloor);
    }
    if (Date.now() >= heartbeatAt) await step("heartbeat", async () => { heartbeatAt = await beat(); });
    await new Promise((r) => setTimeout(r, cfg.pollMs ?? 400));
  }
}

main();
