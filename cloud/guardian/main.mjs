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

import { readFileSync } from "node:fs";
import { Rpc, b58encode, parseEvents } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { assess, decode, newState, DEFAULT_POLICY } from "./policy.mjs";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const policy = { ...DEFAULT_POLICY, ...(cfg.policy ?? {}) };
const rpc = new Rpc(cfg.rpc);
const guardian = Keypair.load(cfg.guardianKey);
const vc = await new VaultClient(cfg.vaultProgram, cfg.protocolProgram).init();
const state = newState();
const log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o }, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

const worst1h = new Map();
async function refreshWorstCase() {
  for (const mint of cfg.mints) {
    try {
      const a = await vc.attest(rpc, guardian.publicKey, mint);
      worst1h.set(mint, a.worst1h);
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
  let ixs;
  switch (action.type) {
    case "freeze":
      ixs = [vc.freeze(guardian.publicKey, action.secs)];
      break;
    case "cancel": {
      const { vault } = await vc.vault(event.mint);
      const ticket = await vc.ticketAddress(action.ticketId);
      const acc = await rpc.account(ticket);
      if (!acc) return log({ action: "cancel", skipped: "ticket already settled or cancelled", ticketId: action.ticketId });
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
      return;
  }
  try {
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
  } catch (e) {
    log({ level: "error", action: action.type, error: e.message });
  }
}

async function main() {
  // Anchor first: everything after this point is watched, even what happens
  // during the startup heartbeat.
  const head = await rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), { limit: 1, commitment: "confirmed" }]);
  let until = head[0]?.signature;
  log({ msg: "guardian started", guardian: guardian.address, protocol: b58encode(vc.protocol), policy });
  await refreshWorstCase();
  await heartbeat().catch((e) => log({ level: "warn", msg: `heartbeat failed: ${e.message}` }));
  let lastHeartbeat = Date.now();
  let lastAttest = Date.now();
  for (;;) {
    try {
      const opts = { limit: 100, commitment: "confirmed" };
      if (until) opts.until = until;
      const sigs = await rpc.call("getSignaturesForAddress", [b58encode(vc.protocol), opts]);
      if (sigs.length) until = sigs[0].signature;
      for (const s of sigs.reverse()) {
        if (s.err) continue;
        const tx = await rpc.call("getTransaction", [s.signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }]);
        const now = Math.floor(Date.now() / 1000);
        for (const raw of parseEvents(tx?.meta?.logMessages)) {
          const e = decode(raw);
          if (e.kind === "other") continue;
          const ctx = { worst1h: worst1h.get(e.mint) ?? worst1h.values().next().value ?? 0n, now };
          log({ event: e.kind, signature: s.signature, ...e });
          for (const action of assess(state, e, ctx, policy)) await execute(action, e, s.blockTime);
        }
      }
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
