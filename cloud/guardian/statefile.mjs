// The guardian's state file: what must survive a restart (a deploy, a crash),
// per protocol. The incident hold and the protocol's freeze end as last seen
// (without it, a restart after a quorum's unfreeze could not tell it from a
// freeze that ran out, and would freeze again); spent approvals and the
// executions already seen (an approval a restart forgot would approve its
// content once more, and an execution it forgot would spend one again); each
// watched Floor config's cursor and the proposal last seen pending there (a
// restart reads on from the cursor, so an execution while it was down still
// spends its approval); the live proposals waiting to be read by id; and,
// per mint, each recent day's highest unbacked outflow as a fraction of the
// 24h freeze threshold, with when it was last alerted (`outflowAlerts`): a
// sustained drip spans days, longer than a restart's replay (docs/09,
// finding 76).

import { writeFileSync, renameSync, chmodSync, openSync, fsyncSync, closeSync, readFileSync, writeSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

/** The state to save, as JSON text. Equal text: nothing to write. */
export function stateJson({ protocol, incidentSince, frozenUntil, protocolSlot = 0, state, floorCursors = new Map(), floorPendingSeen = new Map(), changeChecks = new Map() }) {
  return JSON.stringify({
    protocol,
    incidentSince,
    frozenUntil,
    // The slot `frozenUntil` was read at. The first read after a restart
    // asks for at least this slot: a node behind it would show an older
    // freeze end, which looks like a quorum's unfreeze and closed the
    // incident hold for good (docs/09, finding 137).
    protocolSlot,
    consumed: Object.fromEntries(state.consumed),
    // Vault changes seen executed. Without a baseline there is none to save:
    // the next start takes its own (`observeExecutions`).
    executedSeen: state.changeBaseline ? [...state.executedSeen].filter((k) => k.startsWith("c")) : undefined,
    floorExecutedSeen: [...state.executedSeen].filter((k) => k.startsWith("e")),
    floorCursors: Object.fromEntries(floorCursors),
    floorPendingSeen: Object.fromEntries([...floorPendingSeen].map(([p, s]) => [p, { id: String(s.id), approval: s.approval }])),
    changeChecks: Object.fromEntries([...changeChecks].map(([id, c]) => [String(id), c.sinceS])),
    drip: Object.fromEntries([...(state.drip ?? new Map())].map(([mint, r]) => [mint, { days: Object.fromEntries(r.days), alertedS: r.alertedS, sustainedS: r.sustainedS }])),
  });
}

/**
 * Reads saved state into `state` and returns the rest. State saved for
 * another protocol, or none, restores nothing. A file from before
 * `executedSeen` was kept restores no baseline: the first change scan takes
 * one and spends nothing (docs/09, finding 71).
 */
export function restoreState(text, protocol, state) {
  // `problem`: why a file that exists restored nothing. The guardian says so,
  // urgently: it forgets an open incident, Floor cursors and spent approvals
  // (docs/09, finding 83). It used to be silent.
  const out = { incidentSince: null, frozenUntil: null, protocolSlot: 0, floorCursors: new Map(), floorPendingSeen: new Map(), changeChecks: new Map(), problem: null };
  let s;
  try {
    s = JSON.parse(text);
  } catch {
    out.problem = "the state file is not valid JSON (damaged, or cut short by a crash)";
    return out;
  }
  if (s?.protocol !== protocol) {
    out.problem = `the state file is for another protocol (${s?.protocol ?? "none named"})`;
    return out;
  }
  if (Number.isFinite(s.incidentSince)) out.incidentSince = s.incidentSince;
  if (Number.isFinite(s.frozenUntil)) out.frozenUntil = s.frozenUntil;
  if (Number.isInteger(s.protocolSlot) && s.protocolSlot > 0) out.protocolSlot = s.protocolSlot;
  for (const [a, by] of Object.entries(s.consumed ?? {})) if (typeof by === "string") state.consumed.set(a, by);
  if (Array.isArray(s.executedSeen)) {
    for (const k of s.executedSeen) if (typeof k === "string") state.executedSeen.add(k);
    state.changeBaseline = true;
  }
  for (const k of s.floorExecutedSeen ?? []) if (typeof k === "string" && k.startsWith("e")) state.executedSeen.add(k);
  for (const [config, c] of Object.entries(s.floorCursors ?? {})) {
    if (typeof c?.signature === "string") out.floorCursors.set(config, { signature: c.signature, slot: Number(c.slot) || 0 });
  }
  for (const [program, p] of Object.entries(s.floorPendingSeen ?? {})) {
    if (typeof p?.approval === "string" && /^\d+$/.test(p.id ?? "")) out.floorPendingSeen.set(program, { id: BigInt(p.id), approval: p.approval });
  }
  for (const [id, sinceS] of Object.entries(s.changeChecks ?? {})) {
    if (/^\d+$/.test(id) && Number.isFinite(sinceS)) out.changeChecks.set(BigInt(id), { sinceS, warned: false });
  }
  for (const [mint, r] of Object.entries(s.drip ?? {})) {
    const days = new Map();
    for (const [d, m] of Object.entries(r?.days ?? {})) if (/^\d+$/.test(d) && Number.isFinite(m)) days.set(Number(d), m);
    const at = (x) => (Number.isFinite(x) ? x : null);
    state.drip.set(mint, { days, alertedS: at(r?.alertedS), sustainedS: at(r?.sustainedS) });
  }
  return out;
}

/**
 * Writes the state file owner-only, through a temporary file renamed over it.
 * The mode given to writeFileSync applies only to a new file, so a leftover
 * .tmp is tightened too. Only these two files: the directory used to be
 * chmod 0700 as well, and with the default `<config>.state.json` that is the
 * config's own directory (/tmp, /etc/bulkhead, a repository), which is not
 * the guardian's to change (docs/09, finding 71).
 */
export function writeStateFile(path, text) {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  // On disk before the rename, so a power loss leaves the old file or the
  // new one, never an empty one (docs/09, finding 83).
  const fd = openSync(tmp, "r+");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  try {
    const dir = openSync(dirname(path), "r");
    try {
      fsyncSync(dir);
    } finally {
      closeSync(dir);
    }
  } catch {
    // a directory that cannot be opened for sync (some platforms): the rename stands
  }
}

/**
 * One guardian per state file. Two guardians on one config (an operator's
 * hand-started one beside the service's) interleaved writes to the same
 * temporary file and each sent every freeze, cancel, veto and heartbeat
 * (docs/09, finding 139). The lock is `<stateFile>.lock` holding the pid,
 * created exclusively; a lock whose pid is gone is taken over. Returns the
 * release function, also run at exit.
 */
export function lockInstance(stateFile) {
  const path = `${stateFile}.lock`;
  const alive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return e?.code === "EPERM";
    }
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx", 0o600);
      try {
        writeSync(fd, String(process.pid));
      } finally {
        closeSync(fd);
      }
      const release = () => {
        try {
          if (readFileSync(path, "utf8").trim() === String(process.pid)) unlinkSync(path);
        } catch {
          // already gone
        }
      };
      process.on("exit", release);
      return release;
    } catch (e) {
      if (e?.code !== "EEXIST") throw e;
      let pid = NaN;
      try {
        pid = Number(readFileSync(path, "utf8").trim());
      } catch {
        // unreadable: treated as stale below
      }
      if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && alive(pid)) {
        throw new Error(`another guardian (pid ${pid}) holds ${path}: two guardians on one state file race it and send every action twice; stop one of them`);
      }
      try {
        unlinkSync(path);
      } catch {
        // raced away: the next attempt says so
      }
    }
  }
  throw new Error(`could not take ${path}`);
}
