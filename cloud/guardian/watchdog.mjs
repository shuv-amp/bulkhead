#!/usr/bin/env node
// Is anyone guarding? One look at the chain, from outside the guardians.
//
//   node cloud/guardian/watchdog.mjs --rpc <url> [--rpc <url> ...] [--cluster mainnet-beta]
//        --vault-program <id> (--protocol <account> | --protocol-program <id>)
//        [--floor-program <id> --floor-protected <program> ...] [--mint <mint> ...]
//        [--warn-hours 1] [--timeout-s 60] [--alert-url <url> [--alert-format slack]]
//   node cloud/guardian/watchdog.mjs --config <guardian-config.json> [flags]
//
// Run it on another host than every guardian, from cron or CI. With no live
// guardian every guarantee is delay-only, and a guardian's own liveness
// alerts stop with its process (external audit, F-10(a)). It holds no key
// and sends nothing; `--config` takes a guardian's config for the endpoints,
// cluster, programs, mints and alert webhook (flags add to it). With
// `--cluster`, only endpoints whose genesis hash matches are read (findings
// 114, 117), and every account only as its program owns it (F-01).
//
// It prints one JSON line: per guardian set (the Vault protocol's, each Floor
// config's) each key's heartbeat age and deadline, the live count against the
// threshold and threshold + GUARDIAN_MARGIN, when the quorum is lost if
// nobody heartbeats, the freeze or stop state, and every pending loosening
// with its ETA. Exit codes:
//   0  ok
//   1  warning: a live key stops counting within --warn-hours, the quorum is
//      lost within them, a key is dead, or fewer than threshold + 2 are live
//   2  critical: fewer live keys than the threshold (no quorum can unfreeze,
//      restore or eject), or a loosening pending with no live key to veto it
//      (docs/17 §3, item 3)
//   3  could not read what it needs (or the arguments are wrong)
// With an alert webhook, anything but 0 is posted there too (alert.mjs's
// formats). Each run alerts while the condition lasts: the schedule is the
// alert's cadence. A healthy guardian heartbeats with at least
// max(1 h, interval / 10) left, so the default --warn-hours of 1 is quiet.

import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { FailoverRpc, hostOf, b58encode, key, decodeProtocol, decodeVault, decodeFloor, IDS, SYSVAR_OWNER, GUARDIAN_MARGIN } from "../lib/solana.mjs";
import { VaultClient, FloorClient } from "../lib/bulkhead.mjs";
import { openChanges, openExit, protocolVersion, FLOOR_PROPOSAL_KINDS } from "../lib/changes.mjs";
import { activeChanges } from "./chain.mjs";
import { GENESIS } from "./policy.mjs";
import { formatFor, webhookBody, jsonText } from "./alert.mjs";

/** bulkhead-core MIN_HEARTBEAT_INTERVAL_S and MAX_HEARTBEAT_INTERVAL_S. */
const MIN_INTERVAL_S = 86_400;
const MAX_INTERVAL_S = 30 * 86_400;

/** bulkhead-core `guardian_alive`, exactly: on the chain's clock, no grace. */
export function aliveOnChain(lastS, intervalS, nowS) {
  const gap = nowS - lastS;
  return intervalS >= MIN_INTERVAL_S && intervalS <= MAX_INTERVAL_S && gap >= 0 && gap <= intervalS;
}

/**
 * One guardian set (a decoded Vault protocol or Floor config) at `nowS`:
 * each key's heartbeat age and deadline, the live count, and, if nobody
 * heartbeats again, when the quorum is lost (`quorumLostAtS`: now when it
 * already is) and when the last live key stops counting (`lastLiveUntilS`).
 */
export function setHealth({ guardians, lastHeartbeat, threshold, heartbeatIntervalS }, nowS) {
  const intervalS = Number(heartbeatIntervalS);
  const keys = guardians.map((k, i) => {
    const lastS = Number(lastHeartbeat[i]);
    const live = aliveOnChain(lastS, intervalS, nowS);
    return { key: k, lastHeartbeatS: lastS, ageS: nowS - lastS, live, deadlineS: lastS + intervalS, ...(live && { stopsCountingInS: lastS + intervalS - nowS }) };
  });
  const deadlines = keys.filter((k) => k.live).map((k) => k.deadlineS).sort((a, b) => b - a);
  const live = deadlines.length;
  const quorumLostAtS = threshold > 0 && live >= threshold ? deadlines[threshold - 1] + 1 : nowS;
  return {
    count: guardians.length, threshold, intervalS, live, margin: threshold + GUARDIAN_MARGIN,
    quorumLostAtS, quorumLostInS: quorumLostAtS - nowS, lastLiveUntilS: live ? deadlines[0] : null, guardians: keys,
  };
}

/**
 * What one set's health calls for: `critical`, `warnings` (reasons, as
 * text). `pending` are its loosenings (`{ what, etaS }`), `warnS` how soon a
 * key stopping or the quorum ending is worth a warning.
 */
export function judgeSet(name, health, pending, nowS, warnS) {
  const critical = [];
  const warnings = [];
  const { count, threshold, live, margin } = health;
  const h = (s) => `${(s / 3_600).toFixed(1)}h`;
  if (count === 0 || threshold === 0) critical.push(`${name}: no guardian set (${threshold}-of-${count}): nobody can freeze, veto or stop`);
  else if (live < threshold) critical.push(`${name}: ${live} of ${count} guardians live, under the threshold ${threshold}: no quorum can unfreeze, restore or eject, and every guarantee is delay-only once none is live`);
  if (live === 0 && pending.length) {
    for (const p of pending) critical.push(`${name}: ${p.what} executes ${p.etaS <= nowS ? "now" : `in ${h(p.etaS - nowS)}`} with no live guardian to veto it (docs/17 §3, item 3)`);
  }
  if (live >= threshold && threshold > 0) {
    if (live < margin) warnings.push(`${name}: ${live} of ${count} guardians live, under threshold + ${GUARDIAN_MARGIN} (${margin}): one lost key and one rogue guardian lock governance`);
    if (health.quorumLostInS <= warnS) warnings.push(`${name}: the quorum is lost in ${h(health.quorumLostInS)} unless guardians heartbeat`);
  }
  for (const g of health.guardians) {
    if (g.live && g.stopsCountingInS <= warnS) warnings.push(`${name}: guardian ${g.key} stops counting in ${h(g.stopsCountingInS)} (last heartbeat ${h(g.ageS)} ago)`);
    else if (!g.live) warnings.push(`${name}: guardian ${g.key} is not live (last heartbeat ${h(g.ageS)} ago, interval ${h(health.intervalS)}): it cannot freeze or veto; replace it`);
  }
  return { critical, warnings };
}

/**
 * The verdict on a snapshot read from the chain at `nowS`: `{ vault, floors,
 * unreadable, notes }`, where `vault` and each Floor are `{ set, pending,
 * ... }` (null when unread) and `unreadable` and `notes` are reasons already
 * found (an unread account, an endpoint on another cluster). Exit 2 for any
 * critical reason, else 3 for anything unread, else 1 for any warning, else 0.
 */
export function evaluate(snapshot, nowS, { warnS = 3_600 } = {}) {
  const critical = [];
  const warnings = [...(snapshot.notes ?? [])];
  const unreadable = [...(snapshot.unreadable ?? [])];
  const sets = [];
  const add = (name, entry, extra) => {
    if (!entry?.set) return;
    const health = setHealth(entry.set, nowS);
    const verdict = judgeSet(name, health, entry.pending ?? [], nowS, warnS);
    critical.push(...verdict.critical);
    warnings.push(...verdict.warnings);
    const { guardians, ...summary } = health;
    sets.push({ name, ...extra, ...summary, guardians, pending: (entry.pending ?? []).map((p) => ({ ...p, inS: p.etaS - nowS })) });
  };
  if (snapshot.vault) {
    const frozenUntil = snapshot.vault.set?.frozenUntil ?? 0;
    add("vault", snapshot.vault, { protocol: snapshot.vault.protocol, frozen: frozenUntil > nowS, frozenUntil });
  }
  for (const f of snapshot.floors ?? []) add(`floor ${f.program}`, f, { program: f.program, stopped: f.set?.status === "aborted" });
  const exit = critical.length ? 2 : unreadable.length ? 3 : warnings.length ? 1 : 0;
  return { status: ["ok", "warning", "critical", "unreadable"][exit], exit, critical, unreadable, warnings, sets };
}

/** The Vault protocol's pending loosenings: open changes (not stale), a seal, lifeboat exits. */
export function vaultPending(protocol, changes, vaults, nowS) {
  const out = openChanges(changes, nowS, { abdications: protocol.abdications, versionOf: (c) => protocolVersion(protocol, c.kind) })
    .filter((c) => c.state !== "stale")
    .map((c) => ({ what: `loosening #${c.id} (${c.kindName})`, kind: "change", id: String(c.id), etaS: c.executableS, expiresS: c.expiresS }));
  if (!protocol.sealed && protocol.sealExecutableS && !protocol.sealVetoed && nowS < protocol.sealExpiresS) {
    out.push({ what: "the seal", kind: "seal", etaS: protocol.sealExecutableS, expiresS: protocol.sealExpiresS });
  }
  for (const { mint, vault } of vaults) {
    if (openExit(vault, nowS)) out.push({ what: `a lifeboat exit of ${vault.exitAmount} (${mint})`, kind: "exit", mint, etaS: vault.exitExecutableS, expiresS: vault.exitExpiresS });
  }
  return out.sort((a, b) => a.etaS - b.etaS);
}

/** A Floor config's pending proposal, as a loosening, or none. */
export function floorPending(fl, nowS) {
  if (!fl.pendingKind || fl.pendingVetoed || nowS >= fl.pendingExpires) return [];
  const kind = FLOOR_PROPOSAL_KINDS[fl.pendingKind] ?? `kind ${fl.pendingKind}`;
  return [{ what: `proposal #${fl.pendingId} (${kind})`, kind: "proposal", id: String(fl.pendingId), etaS: fl.pendingEta, expiresS: fl.pendingExpires }];
}

/** Settings from `--config` (a guardian's) and the flags, the flags winning. */
export function settings(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: "string" }, rpc: { type: "string", multiple: true }, cluster: { type: "string" },
      "vault-program": { type: "string" }, protocol: { type: "string" }, "protocol-program": { type: "string" },
      "floor-program": { type: "string" }, "floor-protected": { type: "string", multiple: true }, mint: { type: "string", multiple: true },
      "warn-hours": { type: "string" }, "timeout-s": { type: "string" }, "alert-url": { type: "string" }, "alert-format": { type: "string" },
    },
  });
  const cfg = values.config ? JSON.parse(readFileSync(values.config, "utf8")) : {};
  const num = (v, dflt, name) => {
    if (v === undefined) return dflt;
    const n = Number(v);
    if (!(n > 0)) throw new Error(`--${name} needs a positive number`);
    return n;
  };
  const s = {
    rpcs: values.rpc ?? [cfg.rpc, ...(cfg.rpcs ?? [])].filter(Boolean),
    cluster: values.cluster ?? cfg.cluster ?? null,
    vaultProgram: values["vault-program"] ?? cfg.vaultProgram,
    protocol: values.protocol ?? null,
    protocolProgram: values["protocol-program"] ?? cfg.protocolProgram ?? null,
    floorProgram: values["floor-program"] ?? cfg.floorProgram ?? null,
    floorProtected: values["floor-protected"] ?? cfg.floorProtected ?? [],
    mints: values.mint ?? cfg.mints ?? [],
    warnS: num(values["warn-hours"], 1, "warn-hours") * 3_600,
    timeoutMs: num(values["timeout-s"], 60, "timeout-s") * 1_000,
    alert: values["alert-url"] ? { url: values["alert-url"], format: values["alert-format"] } : cfg.alert ?? null,
  };
  if (!s.rpcs.length) throw new Error("no endpoint: give --rpc (or --config)");
  if (!s.vaultProgram || !(s.protocol || s.protocolProgram)) throw new Error("give --vault-program and --protocol (or --protocol-program)");
  if (s.floorProtected.length && !s.floorProgram) throw new Error("--floor-protected needs --floor-program");
  if (s.cluster !== null && s.cluster !== "localnet" && !Object.hasOwn(GENESIS, s.cluster)) throw new Error(`--cluster must be one of ${[...Object.keys(GENESIS), "localnet"].join(", ")}`);
  return s;
}

/**
 * Reads what `evaluate` needs. Every endpoint is asked its genesis hash with
 * a cluster, and only those on it are read; each account is read only as its
 * program owns it. An unread part becomes an `unreadable` reason, never a
 * guess: the verdict does not call a set healthy that it could not see.
 */
export async function readSnapshot(s) {
  const unreadable = [];
  const notes = [];
  const name = (i) => `${hostOf(s.rpcs[i])} (${i > 0 ? `rpc ${i + 1}` : "rpc"})`;
  const rpc = new FailoverRpc(s.rpcs, {
    genesis: s.cluster && s.cluster !== "localnet" ? GENESIS[s.cluster] : null,
    onCluster: (url, got, at) => { if (got !== GENESIS[s.cluster]) notes.push(`endpoint ${name(at)} serves another cluster than ${s.cluster} (genesis ${got}): not read`); },
    onBadAnswer: (url, why, at) => notes.push(`endpoint ${name(at)} served an account with the wrong owner (${why}): not read; replace it (F-01)`),
  });
  const program = b58encode(key(s.vaultProgram));
  const vc = await new VaultClient(s.vaultProgram, s.protocolProgram ?? s.vaultProgram).init();
  if (s.protocol) vc.protocol = key(s.protocol); // vaults are derived from it
  const protocolKey = vc.protocol;
  const part = async (what, run) => {
    try {
      return await run();
    } catch (e) {
      unreadable.push(`${what}: ${String(e?.message ?? e).slice(0, 200)}`);
      return undefined;
    }
  };
  // The chain's clock, which judges every heartbeat; the host's only if unread.
  let nowS = Math.floor(Date.now() / 1000);
  let clock = "host";
  const c = await part("the Clock sysvar", () => rpc.account(IDS.clock, "confirmed", { owner: SYSVAR_OWNER }));
  if (c?.bytes?.length >= 40) {
    nowS = Number(new DataView(c.bytes.buffer, c.bytes.byteOffset).getBigInt64(32, true));
    clock = "chain";
  }
  const vault = { protocol: b58encode(protocolKey), set: null, pending: [] };
  const acc = await part("the protocol account", () => rpc.account(protocolKey, "confirmed", { owner: program }));
  if (acc === null) unreadable.push(`the protocol account: none at ${b58encode(protocolKey)} (wrong id or cluster?)`);
  if (acc) {
    vault.set = decodeProtocol(acc.bytes);
    const changes = await part("the change scan (getProgramAccounts)", () => activeChanges(rpc, s.vaultProgram, protocolKey)) ?? [];
    const vaults = [];
    for (const mint of s.mints) {
      const v = await vc.vault(mint);
      const va = await part(`the vault for ${mint}`, () => rpc.account(v.vault, "confirmed", { owner: program }));
      if (va) vaults.push({ mint, vault: decodeVault(va.bytes) });
    }
    vault.pending = vaultPending(vault.set, changes, vaults, nowS);
  }
  const floors = [];
  for (const p of s.floorProtected) {
    const fc = await new FloorClient(s.floorProgram, p).init();
    const fa = await part(`the Floor config for ${p}`, () => rpc.account(fc.config, "confirmed", { owner: b58encode(fc.program) }));
    if (fa === null) unreadable.push(`the Floor config for ${p}: none (not under Floor?)`);
    if (!fa) continue;
    const set = decodeFloor(fa.bytes);
    floors.push({ program: p, set, pending: floorPending(set, nowS) });
  }
  return { nowS, clock, snapshot: { vault: vault.set ? vault : null, floors, unreadable, notes } };
}

/** Posts the verdict to the webhook in its format (alert.mjs), twice at most. */
async function postAlert(alert, verdict, protocol, fetchFn = fetch) {
  const severity = verdict.exit === 1 ? "warning" : "critical";
  const said = [...verdict.critical, ...verdict.unreadable, ...verdict.warnings];
  const body = jsonText(webhookBody({ severity, title: `Bulkhead watchdog: ${verdict.status}`, detail: said.join(" | ").slice(0, 1_500), at: new Date().toISOString() }, formatFor(alert.url, alert.format), protocol));
  for (let i = 0; i < 2; i++) {
    try {
      const r = await fetchFn(alert.url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(5_000) });
      if (r.ok) return null;
      if (i) return `webhook answered ${r.status}`;
    } catch (e) {
      if (i) return e.message;
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  return null;
}

async function main() {
  let s;
  try {
    s = settings(process.argv.slice(2));
  } catch (e) {
    console.error(`${e.message}\nusage: see the top of cloud/guardian/watchdog.mjs`);
    process.exit(3);
  }
  const deadline = new Promise((r) => setTimeout(() => r(null), s.timeoutMs).unref());
  const read = await Promise.race([readSnapshot(s).catch((e) => ({ error: e })), deadline]);
  const out = { t: new Date().toISOString() };
  let verdict;
  if (!read || read.error) {
    verdict = { status: "unreadable", exit: 3, critical: [], warnings: [], unreadable: [read ? String(read.error?.message ?? read.error).slice(0, 200) : `no answer within ${s.timeoutMs / 1000} s`], sets: [] };
  } else {
    verdict = evaluate(read.snapshot, read.nowS, { warnS: s.warnS });
    Object.assign(out, { clockS: read.nowS, clock: read.clock });
  }
  if (verdict.exit !== 0 && s.alert?.url) {
    const failed = await postAlert(s.alert, verdict, read?.snapshot?.vault?.protocol ?? s.protocol ?? "");
    if (failed) verdict.alertError = failed;
  }
  // Written out before the exit: a pipe on macOS is not written synchronously.
  process.stdout.write(`${jsonText({ ...out, ...verdict })}\n`, () => process.exit(verdict.exit));
}

let entry = null;
try {
  entry = realpathSync(process.argv[1] ?? "");
} catch {
  // imported by a test, or run from stdin
}
if (entry === realpathSync(fileURLToPath(import.meta.url))) main();
