// What a status page says about pending loosenings (docs/02 §4, principle 4:
// "every loosening has a countdown; pending changes show time left and who
// can veto"). `openChanges`, `openExit` and `duration` are pure;
// `readOpenChanges` reads the accounts they need.
//
// The rules restate programs/vault/src/governance.rs: a change executes once
// `now >= executableS`, until `expiresS`, unless vetoed, executed, its kind
// abdicated, or its target's version moved since it was proposed (`ChangeStale`).

import { b58encode, decodeChange, decodeVault, assetVersion } from "./solana.mjs";

export const VAULT_CHANGE_KINDS = ["limits", "asset", "guardians", "admin", "lifeboat destination", "loosen delay", "recovery key"];
export const FLOOR_PROPOSAL_KINDS = ["none", "upgrade", "restore", "release upgrade authority", "guardians", "owner", "delay", "recovery key"];

/** Kinds whose version lives on the protocol (governance.rs `version_slot`). */
const PROTOCOL_SLOT = { 2: 0, 3: 1, 4: 2, 5: 3, 6: 4 };

/**
 * The open changes, soonest first, each with a state:
 * "waiting" (`secondsLeft` until anyone may execute it), "executable"
 * (`secondsLeft` until it expires), or "stale" (its target moved: it can
 * never execute). Vetoed, executed, expired and abdicated changes are left out.
 *
 * `versionOf(change)` returns the target's current version, or undefined when
 * it is unknown (the change is then shown without a stale check).
 */
export function openChanges(changes, now, { abdications = 0, versionOf = () => undefined } = {}) {
  const out = [];
  for (const c of changes) {
    if (c.vetoed || c.executed || now >= c.expiresS) continue;
    if ((abdications >> c.kind) & 1) continue;
    const current = versionOf(c);
    let state;
    if (current !== undefined && current !== c.baseVersion) state = "stale";
    else if (now < c.executableS) state = "waiting";
    else state = "executable";
    out.push({
      ...c,
      kindName: VAULT_CHANGE_KINDS[c.kind] ?? `kind ${c.kind}`,
      state,
      secondsLeft: state === "waiting" ? c.executableS - now : state === "executable" ? c.expiresS - now : 0,
    });
  }
  return out.sort((a, b) => a.executableS - b.executableS || (a.id < b.id ? -1 : 1));
}

/** The version a protocol-level change is bound to, or undefined for vault and asset kinds. */
export function protocolVersion(protocol, kind) {
  const slot = PROTOCOL_SLOT[kind];
  return slot === undefined || !protocol.versions ? undefined : protocol.versions[slot];
}

/** A pending lifeboat exit (a decoded vault), or null. */
export function openExit(v, now) {
  if (!v.exitAmount || v.exitVetoed || now >= v.exitExpiresS) return null;
  const waiting = now < v.exitExecutableS;
  return {
    amount: v.exitAmount,
    state: waiting ? "waiting" : "executable",
    secondsLeft: waiting ? v.exitExecutableS - now : v.exitExpiresS - now,
  };
}

/** "3d 4h", "5h 20m", "12m": a countdown at the precision a reader needs. */
export function duration(s) {
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${Math.max(m, s > 0 ? 1 : 0)}m`;
}

/**
 * Reads every Change account of a protocol and the version each is bound to,
 * then `openChanges`. `vc` is an initialised VaultClient, `protocol` the
 * decoded protocol. Needs an RPC that serves `getProgramAccounts`.
 */
export async function readOpenChanges(rpc, vc, protocol, now) {
  const accounts = await rpc.call("getProgramAccounts", [b58encode(vc.program), {
    encoding: "base64",
    commitment: "confirmed",
    filters: [
      { memcmp: { offset: 0, bytes: b58encode(new TextEncoder().encode("BHCHNG01")) } },
      { memcmp: { offset: 8, bytes: b58encode(vc.protocol) } },
    ],
  }]);
  if (!Array.isArray(accounts)) throw new Error("this RPC did not list the change accounts");
  const changes = accounts.map(({ account }) => decodeChange(Uint8Array.from(atob(account.data[0]), (c) => c.charCodeAt(0))));
  const versions = new Map();
  for (const c of changes) {
    if (c.vetoed || c.executed || now >= c.expiresS) continue;
    if (c.kind === 0) {
      const acc = await rpc.account(c.target);
      versions.set(c.id, acc ? decodeVault(acc.bytes).limitsVersion : undefined);
    } else if (c.kind === 1) {
      const acc = await rpc.account(await vc.asset(c.target));
      versions.set(c.id, acc ? assetVersion(acc.bytes) : 0);
    } else {
      versions.set(c.id, protocolVersion(protocol, c.kind));
    }
  }
  return openChanges(changes, now, { abdications: protocol.abdications, versionOf: (c) => versions.get(c.id) });
}
