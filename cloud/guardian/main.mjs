#!/usr/bin/env node
// Bulkhead Cloud guardian: watches a protocol's Bulkhead events and acts.
//
//   node cloud/guardian/main.mjs <config.json>
//
// config.json:
//   { "rpc": "http://127.0.0.1:8899",
//     "vaultProgram": "...", "protocolProgram": "...",
//     "mints": ["..."], "guardianKey": "path/to/keypair.json",
//     "pollMs": 400, "policy": { ...overrides of DEFAULT_POLICY } }
//
// Every decision is one JSON line on stdout: the triggering event, the action,
// the reason, the transaction, and the latency from the triggering
// transaction's block time to the guardian's own confirmation.
//
// The 24-hour rule needs the last day of releases. On startup the bot replays
// that window from chain history (block times, not the wall clock) and, if it
// is already over a threshold and the protocol is not frozen, freezes once.
// A failed freeze is retried; it does not stick in `state.freezing`.

import { readFileSync } from "node:fs";
import { Rpc, b58encode, parseEvents } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { assess, breach, decode, newState, DEFAULT_POLICY, DAY_S } from "./policy.mjs";
import { pageQuery, morePages, MAX_PAGES } from "./follow.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const policy = { ...DEFAULT_POLICY, ...(cfg.policy ?? {}) };
const rpc = new Rpc(cfg.rpc);
const guardian = Keypair.load(cfg.guardianKey);
const vc = await new VaultClient(cfg.vaultProgram, cfg.protocolProgram).init();
const state = newState();
const log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o }, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

const worst1h = new Map();
const worst24h = new Map();
const warned = new Set();
let pendingFreeze = null;

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

async function heartbeat() {
  const sig = await send(rpc, guardian, [vc.heartbeat(guardian.publicKey)]);
  log({ action: "heartbeat", signature: sig });
}

async function execute(action, event, eventTime) {
  const started = Date.now();
  try {
    let ixs;
    switch (action.type) {
      case "freeze":
        ixs = [vc.freeze(guardian.publicKey, action.secs)];
        break;
      case "cancel": {
        const { vault } = await vc.vault(event.mint);
        const ticket = await vc.ticketAddress(action.ticketId);
        const acc = await rpc.account(ticket);
        if (!acc) {
          log({ action: "cancel", skipped: "ticket already settled or cancelled", ticketId: action.ticketId });
          return true;
        }
        const payer = acc.bytes.slice(136, 168); // Ticket: disc, protocol, vault, recipient, recipient_owner, payer
        ixs = [vc.cancelTicket(vault, ticket, guardian.publicKey, payer)];
        break;
      }
      case "veto_change":
        ixs = [vc.vetoChange(await vc.changeAddress(action.changeId), guardian.publicKey)];
        break;
      case "floor_veto": {
        const fc = await new FloorClient(cfg.floorProgram, action.program).init();
        ixs = [fc.veto(guardian.publicKey)];
        break;
      }
      default:
        return false;
    }
    const sig = await send(rpc, guardian, ixs);
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

async function applyActions(actions, event, eventTime) {
  let freezeOk = true;
  for (const action of actions) {
    // Cancels in this batch are "while frozen". If the freeze transaction
    // failed and the protocol is not already frozen, don't cancel yet.
    if (action.type === "cancel" && !freezeOk) {
      state.cancelled.delete(action.ticketId);
      continue;
    }
    const ok = await execute(action, event, eventTime);
    if (action.type === "cancel" && !ok) state.cancelled.delete(action.ticketId);
    if (action.type !== "freeze") continue;
    freezeOk = ok;
    if (ok) pendingFreeze = null;
    else {
      state.freezing = false;
      pendingFreeze = { action, event, eventTime };
    }
  }
}

/** Newest-first. `oldestWanted` null walks until `until` (live); a number walks the startup window. */
async function signatures(until, oldestWanted) {
  const out = [];
  let before;
  for (let page = 0; page < MAX_PAGES; page++) {
    const q = pageQuery({ before, until });
    const got = await rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), q]);
    if (!got?.length) break;
    out.push(...got);
    if (!morePages(got, q.limit, oldestWanted)) break;
    before = got[got.length - 1].signature;
    if (page === MAX_PAGES - 1) log({ level: "error", msg: `signature walk stopped after ${MAX_PAGES} pages; the window may be incomplete` });
  }
  return out;
}

async function ingest(sigs, act) {
  for (const s of sigs) {
    if (s.err) continue;
    const tx = await rpc.call("getTransaction", [s.signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }]);
    const now = s.blockTime ?? tx?.blockTime ?? wallNow();
    for (const raw of parseEvents(tx?.meta?.logMessages)) {
      const e = decode(raw);
      if (e.kind === "other") continue;
      const ctx = { ...worstFor(e.mint), now };
      const actions = assess(state, e, ctx, policy, act);
      if (!act) continue;
      log({ event: e.kind, signature: s.signature, ...e });
      await applyActions(actions, e, s.blockTime ?? now);
    }
  }
}

async function freezeIfWindowStillOpen(now) {
  if (now < state.frozenUntil || state.freezing) return;
  const mints = new Set([...cfg.mints, ...state.outflows.map((o) => o.mint)]);
  for (const mint of mints) {
    if (!worst1h.has(mint)) continue; // no figure yet: don't freeze from history alone
    const action = breach(state, mint, { ...worstFor(mint), now }, policy);
    if (!action) continue;
    state.freezing = true;
    log({ msg: "window already over threshold after catch-up", mint, reason: action.reason });
    await applyActions([action], { mint }, now);
    return;
  }
}

async function main() {
  log({ msg: "guardian started", guardian: guardian.address, protocol: b58encode(vc.protocol), policy });
  await refreshWorstCase();
  await heartbeat().catch((e) => log({ level: "warn", msg: `heartbeat failed: ${e.message}` }));
  const oldest = wallNow() - DAY_S;
  const history = await signatures(undefined, oldest);
  const until = history[0]?.signature;
  const inWindow = history.filter((s) => s.blockTime == null || s.blockTime >= oldest);
  await ingest([...inWindow].reverse(), false);
  await freezeIfWindowStillOpen(wallNow());
  log({ msg: "caught up", signatures: inWindow.length });
  let cursor = until;
  let lastHeartbeat = Date.now();
  let lastAttest = Date.now();
  for (;;) {
    try {
      if (pendingFreeze && wallNow() >= state.frozenUntil) {
        const ok = await execute(pendingFreeze.action, pendingFreeze.event, pendingFreeze.eventTime);
        if (ok) {
          state.freezing = true;
          pendingFreeze = null;
        }
      }
      const sigs = await signatures(cursor, null);
      if (sigs.length) cursor = sigs[0].signature;
      await ingest([...sigs].reverse(), true);
      if (Date.now() - lastAttest > 10_000) {
        await refreshWorstCase();
        lastAttest = Date.now();
      }
      if (Date.now() - lastHeartbeat > policy.heartbeatEveryS * 1000) {
        await heartbeat();
        lastHeartbeat = Date.now();
      }
    } catch (e) {
      log({ level: "warn", msg: e.message });
    }
    await new Promise((r) => setTimeout(r, cfg.pollMs ?? 400));
  }
}

main();
