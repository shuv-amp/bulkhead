import { test } from "node:test";
import assert from "node:assert/strict";
import { afterHeartbeat, assess, breach, decode, decisionTime, floorAlerts, guardianStanding, heartbeatEveryAfterAccount, heartbeatEverySeconds, judgeReplayedWindow, newState, observeProtocolFreeze, openIncident, observeFreezeEnd, incidentHold, pendingCancels, pendingChangeVeto, pendingExitVeto, pendingUpgradeVeto, dueApprovedChange, dueApprovedFloor, queueFailedVeto, readChangeVeto, readPendingChange, rememberTicket, retirePendingFreeze, scaleBy, vetoRetryDisposition, DEFAULT_POLICY, HEARTBEAT_RECHECK_MS } from "../guardian/policy.mjs";
import { u64le, i64le, concat, key } from "../lib/solana.mjs";

const USDC = 1_000_000n;
const worst1h = 400_000n * USDC; // 10M vault, default limits (golden G-6)
const owner = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const mint = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";

function released({ backed = 0n, instant = 0n, queued = 0n, ticketId = 0n, who = owner, mint: which = mint }) {
  const outcome = concat(u64le(backed), u64le(instant), u64le(queued), u64le(ticketId), i64le(0));
  return decode({ name: "vault:released", fields: [key(which), key(who), outcome] });
}

test("the burst alone does not freeze; crossing half of worst_1h does", () => {
  const s = newState();
  let now = 1_000;
  assert.deepEqual(assess(s, released({ instant: 150_000n * USDC }), { worst1h, now }), []);
  now += 60;
  const a = assess(s, released({ instant: 50_000n * USDC }), { worst1h, now });
  assert.equal(a.length, 1);
  assert.equal(a[0].type, "freeze");
});

test("backed payouts and allowlisted owners never count", () => {
  const s = newState();
  assert.deepEqual(assess(s, released({ backed: 9_000_000n * USDC }), { worst1h, now: 1 }), []);
  const policy = { ...DEFAULT_POLICY, allowlistedOwners: [owner] };
  assert.deepEqual(assess(s, released({ instant: 300_000n * USDC }), { worst1h, now: 2 }, policy), []);
});

test("outflow older than an hour drops out of the window", () => {
  const s = newState();
  assess(s, released({ instant: 150_000n * USDC }), { worst1h, now: 0 });
  assert.deepEqual(assess(s, released({ instant: 100_000n * USDC }), { worst1h, now: 3_601 }), []);
});

test("once freezing, tickets to non-allowlisted owners are cancelled, each once", () => {
  const s = newState();
  assess(s, released({ queued: 10_000n * USDC, ticketId: 7n }), { worst1h, now: 0 });
  const a = assess(s, released({ instant: 200_000n * USDC }), { worst1h, now: 10 });
  assert.deepEqual(a.map((x) => x.type), ["freeze", "cancel"]);
  assert.equal(a[1].ticketId, 7n);
  const b = assess(s, released({ queued: 5n, ticketId: 8n }), { worst1h, now: 20 });
  assert.deepEqual(b.map((x) => [x.type, x.ticketId]), [["cancel", 8n]]);
});

test("a cancel names its ticket's own mint, not the mint that triggered the freeze", () => {
  const other = "11111111111111111111111111111111";
  const s = newState();
  assess(s, released({ queued: 10_000n * USDC, ticketId: 7n, mint: other }), { worst1h, now: 0 });
  const a = assess(s, released({ instant: 200_000n * USDC }), { worst1h, now: 10 });
  assert.deepEqual(a.map((x) => [x.type, x.ticketId, x.mint]), [["freeze", undefined, undefined], ["cancel", 7n, other]]);
});

test("thresholds scale in integers past 2^53", () => {
  assert.equal(scaleBy(1n << 60n, 0.5), 1n << 59n);
  assert.equal(scaleBy(1n, 0.5), 1n);
  assert.equal(scaleBy(100n, 1.5), 150n);
});

test("one mint's outflow does not fill another mint's window", () => {
  const other = "11111111111111111111111111111111";
  const s = newState();
  assert.deepEqual(assess(s, released({ instant: 250_000n * USDC, mint: other }), { worst1h, now: 1 }, DEFAULT_POLICY, false), []);
  assert.equal(s.freezing, false);
  assert.equal(breach(s, mint, { worst1h, now: 2 }), null);
  assert.equal(breach(s, other, { worst1h, now: 2 }).type, "freeze");
});

test("replaying history records the window and does not veto or freeze by itself", () => {
  const s = newState();
  const ev = decode({ name: "vault:change_proposed", fields: [u64le(3), Uint8Array.of(0), key(mint), i64le(0)] });
  assert.deepEqual(assess(s, ev, { worst1h, now: 0 }, DEFAULT_POLICY, false), []);
  assert.equal(s.vetoed.size, 0);
  assess(s, released({ instant: 250_000n * USDC }), { worst1h, worst24h: 2_000_000n * USDC, now: 10 }, DEFAULT_POLICY, false);
  assert.equal(s.freezing, false);
  assert.match(breach(s, mint, { worst1h, worst24h: 2_000_000n * USDC, now: 10 }).reason, /last hour/);
});

test("unapproved loosenings are vetoed once; approved ones are not", () => {
  const s = newState();
  const ev = decode({ name: "vault:change_proposed", fields: [u64le(3), Uint8Array.of(0), key(mint), i64le(0)] });
  assert.equal(assess(s, ev, { worst1h, now: 0 })[0].type, "veto_change");
  assert.deepEqual(assess(s, ev, { worst1h, now: 1 }), []);
  const s2 = newState();
  assert.deepEqual(assess(s2, ev, { worst1h, now: 0 }, { ...DEFAULT_POLICY, approvedChangeIds: [3] }), []);
});

const frozenEvent = (scope, until) =>
  decode({ name: "vault:frozen", fields: [Uint8Array.of(scope), key(owner), i64le(until)] });
const unfrozenEvent = (scope) => decode({ name: "vault:unfrozen", fields: [Uint8Array.of(scope), Uint8Array.of(3)] });

test("a vault-scoped freeze is not read as a protocol-wide freeze", () => {
  const s = newState();
  assess(s, frozenEvent(1, 90_000), { now: 1_000 });
  assert.equal(s.frozenUntil, 0, "one vault frozen: the protocol is not");
  // So a breach elsewhere still freezes the protocol.
  assess(s, released({ instant: 150_000n * USDC }), { worst1h, now: 1_010 });
  const a = assess(s, released({ instant: 50_000n * USDC }), { worst1h, now: 1_020 });
  assert.deepEqual(a.map((x) => x.type), ["freeze"]);
  // A protocol-wide freeze and unfreeze still count; a vault-scoped unfreeze doesn't undo it.
  const t = newState();
  assess(t, frozenEvent(0, 90_000), { now: 1_000 });
  assert.equal(t.frozenUntil, 90_000);
  assess(t, unfrozenEvent(1), { now: 1_001 });
  assert.equal(t.frozenUntil, 90_000);
  assess(t, unfrozenEvent(0), { now: 1_002 });
  assert.equal(t.frozenUntil, 0);
});

test("after a late freeze, every recorded ticket is swept up once, with its own mint", () => {
  const s = newState();
  const other = "11111111111111111111111111111112";
  // Replayed history (act = false): tickets recorded, nothing sent.
  assess(s, released({ queued: 10n, ticketId: 3n }), { worst1h, now: 0 }, DEFAULT_POLICY, false);
  assess(s, released({ queued: 20n, ticketId: 4n, mint: other }), { worst1h, now: 5 }, DEFAULT_POLICY, false);
  assess(s, released({ instant: 30n }), { worst1h, now: 6 }, DEFAULT_POLICY, false);
  const sweep = pendingCancels(s);
  assert.deepEqual(sweep.map((x) => [x.ticketId, x.mint]), [[3n, mint], [4n, other]]);
  assert.deepEqual(pendingCancels(s), [], "each ticket once");
  assert.deepEqual(pendingCancels(newState(), { ...DEFAULT_POLICY, cancelTicketsWhenFrozen: false }), []);
});

test("an externally observed chain freeze cancels tracked tickets", () => {
  const s = newState();
  rememberTicket(s, { ticketId: 301n, mint, vault: "vault-address", owner });
  const actions = observeProtocolFreeze(s, 100_000, 90_000);
  assert.deepEqual(actions.map((a) => [a.type, a.ticketId, a.vault]), [["cancel", 301n, "vault-address"]]);
});

test("settlement and cancellation events remove tickets from the cancellation set", () => {
  const s = newState();
  rememberTicket(s, { ticketId: 9n, mint, owner });
  const ev = decode({ name: "vault:settled", fields: [u64le(9), u64le(50)] });
  assess(s, ev, { now: 1 });
  assert.deepEqual(pendingCancels(s), []);
});

test("floor readiness: an unarmed stop button and an unpinned snapshot are reported (A5)", () => {
  const ready = { status: "live", abortStaged: true, snapshotPinned: true };
  assert.deepEqual(floorAlerts(ready), []);
  assert.deepEqual(floorAlerts({ ...ready, abortStaged: false }).map((a) => a.code), ["unarmed"]);
  assert.deepEqual(floorAlerts({ ...ready, snapshotPinned: false }).map((a) => a.code), ["no_snapshot"]);
  assert.deepEqual(floorAlerts({ ...ready, abortStaged: false, snapshotPinned: false }).map((a) => a.code), ["unarmed", "no_snapshot"]);
  // Stopped: arming is moot until it is restored; that is the one thing to say.
  assert.deepEqual(floorAlerts({ status: "aborted", abortStaged: false, snapshotPinned: false }).map((a) => a.code), ["stopped"]);
});

test("floor readiness reads the real account layout", async () => {
  const { decodeFloor } = await import("../lib/solana.mjs");
  const d = new Uint8Array(916);
  d.set(new TextEncoder().encode("FLOORv01"), 0);
  new DataView(d.buffer).setBigUint64(528, 4n, true);
  assert.equal(decodeFloor(d).pendingId, 4n);
  assert.deepEqual(floorAlerts(decodeFloor(d)).map((a) => a.code), ["unarmed", "no_snapshot"]);
  d[448] = 6; // abort buffer (programs/floor/src/state.rs O_ABORT_BUF)
  d[480] = 7; // snapshot buffer (O_SNAP_BUF)
  assert.deepEqual(floorAlerts(decodeFloor(d)), []);
  d[426] = 1; // STATUS_ABORTED
  assert.deepEqual(floorAlerts(decodeFloor(d)).map((a) => a.code), ["stopped"]);
});

test("a later outflow is not treated as already inside an earlier window", () => {
  const s = newState();
  assess(s, released({ instant: 250_000n * USDC }), { worst1h, now: 20_000 }, DEFAULT_POLICY, false);
  const actions = assess(s, released({ instant: 1n }), { worst1h, now: 10_000 });
  assert.deepEqual(actions, []);
  assert.equal(s.outflows.length, 2);
});

test("an empty window does not freeze when the worst case is zero", () => {
  const s = newState();
  const future = released({ queued: 400n, ticketId: 1n });
  future.at = 5_000;
  assert.deepEqual(assess(s, future, { worst1h: 0n, worst24h: 0n, now: 1_000 }), []);
  assert.equal(breach(s, mint, { worst1h: 0n, worst24h: 0n, now: 1_000 }), null);
  assert.equal(breach(s, mint, { worst1h: 0n, worst24h: 0n, now: 5_000 }).type, "freeze");
  const live = newState();
  assert.equal(assess(live, released({ instant: 1n }), { worst1h: 0n, worst24h: 0n, now: 1 })[0].type, "freeze");
});

test("a recovered ticket is stamped when it was created and judged now", () => {
  const s = newState();
  const e = released({ queued: 250_000n * USDC, ticketId: 4n });
  e.at = 1_000;
  const actions = assess(s, e, { worst1h, now: 20_000 });
  assert.deepEqual(actions, []);
  assert.equal(s.outflows[0].t, 1_000);
});

test("a freeze already on chain retires a failed local freeze", () => {
  const pending = { action: { type: "freeze" } };
  assert.equal(retirePendingFreeze(pending, 90_000, 1_000), null);
  assert.equal(retirePendingFreeze(pending, 0, 1_000), pending);
  assert.equal(retirePendingFreeze(null, 90_000, 1_000), null);
});

test("startup judges a breach at the chain time when the wall clock is behind", () => {
  const s = newState();
  assess(s, released({ instant: 250_000n * USDC }), { worst1h, now: 9_800 }, DEFAULT_POLICY, false);
  assert.equal(breach(s, mint, { worst1h, now: 9_000 }), null);
  const now = decisionTime(9_000, s.outflows);
  assert.equal(now, 9_800);
  assert.match(breach(s, mint, { worst1h, now }).reason, /last hour/);
});

test("a missing ticket account stays cancellable", () => {
  const s = newState();
  rememberTicket(s, { ticketId: 7n, mint, vault: "vault-address", owner });
  assert.equal(pendingCancels(s).length, 1);
  // A failed cancel (here: the account read came back empty) is returned to the sweep.
  s.cancelled.delete(7n);
  assert.equal(pendingCancels(s).length, 1);
  assert.equal(pendingCancels(s).length, 0);
});

test("a failed veto is queued once and can be sent again", () => {
  const action = { type: "veto_change", changeId: 3n, reason: "loosening 3" };
  const queued = queueFailedVeto([], action);
  assert.deepEqual(queueFailedVeto(queued, action), queued);
  assert.equal(queued[0].changeId, 3n);
  const floor = { type: "floor_veto", program: "prog", proposalId: 4n };
  assert.equal(queueFailedVeto(queued, floor).length, 2);
});

test("a failed heartbeat backs off, stays inside the time left, and a success waits out the interval", () => {
  const day = 86_400_000;
  assert.deepEqual(afterHeartbeat({ outcome: "sent", failures: 3, nowMs: 1_000, everyMs: day }), { nextAt: 1_000 + day, failures: 0 });
  assert.deepEqual(afterHeartbeat({ outcome: "failed", nowMs: 0, everyMs: day }), { nextAt: 15_000, failures: 1 });
  assert.equal(afterHeartbeat({ outcome: "failed", failures: 1, nowMs: 0, everyMs: day }).nextAt, 30_000);
  assert.equal(afterHeartbeat({ outcome: "failed", failures: 20, nowMs: 0, everyMs: day }).nextAt, 600_000);
  // Twenty minutes left: never wait more than a quarter of it.
  assert.equal(afterHeartbeat({ outcome: "failed", failures: 20, nowMs: 0, everyMs: day, deadlineMs: 1_200_000 }).nextAt, 300_000);
  assert.equal(afterHeartbeat({ outcome: "failed", failures: 20, nowMs: 0, everyMs: day, deadlineMs: 10_000 }).nextAt, 15_000);
  // A stale or absent key is looked at again later, with nothing sent.
  assert.deepEqual(afterHeartbeat({ outcome: "dead", failures: 4, nowMs: 0, everyMs: day }), { nextAt: HEARTBEAT_RECHECK_MS, failures: 0 });
  assert.equal(afterHeartbeat({ outcome: "absent", nowMs: 0, everyMs: day }).nextAt, HEARTBEAT_RECHECK_MS);
});

test("only a live guardian heartbeats: a stale key cannot revive itself on chain", () => {
  const account = { guardians: ["g0", "g1"], lastHeartbeat: [1_000, 0], heartbeatIntervalS: 86_400 };
  assert.deepEqual(guardianStanding(account, "g0", 1_000 + 86_400), { standing: "live", deadlineS: 1_000 + 86_400 });
  // A clock behind the chain still sees a fresh heartbeat as live, and a key
  // is written off only ten minutes past its deadline.
  assert.equal(guardianStanding(account, "g0", 900).standing, "live");
  assert.equal(guardianStanding(account, "g0", 1_000 + 86_400 + 600).standing, "live");
  assert.equal(guardianStanding(account, "g0", 1_000 + 86_400 + 601).standing, "dead");
  assert.equal(guardianStanding(account, "g1", 100_000).standing, "dead");
  assert.equal(guardianStanding(account, "nobody", 1_000).standing, "absent");
  assert.equal(guardianStanding(null, "g0", 1_000).standing, "absent");
  assert.equal(guardianStanding(undefined, "g0", 1_000).standing, "unknown");
  // An interval outside bulkhead-core's 1..30 day range keeps nobody live.
  assert.equal(guardianStanding({ ...account, heartbeatIntervalS: 3_600 }, "g0", 1_000).standing, "dead");
});

test("a heartbeat period equal to the chain interval is pulled inside the window", () => {
  assert.equal(heartbeatEverySeconds(86_400, 86_400), 77_760);
  assert.equal(heartbeatEverySeconds(86_400, 604_800), 86_400);
  assert.equal(heartbeatEverySeconds(1_000, 86_400), 1_000);
  assert.equal(heartbeatEveryAfterAccount(86_400, null), 77_760);
  assert.equal(heartbeatEveryAfterAccount(86_400, 604_800), 86_400);
});

test("the replayed window is judged once per mint, so a quorum's unfreeze sticks", () => {
  const s = newState();
  const policy = { ...DEFAULT_POLICY, allowlistedOwners: [] };
  assess(s, released({ instant: 250_000n * USDC }), { worst1h, now: 1_000 }, policy, false);
  const figure = () => ({ worst1h, worst24h: 1_000_000n * USDC });
  // No attest yet: the mint waits, nothing is sent.
  let judged = judgeReplayedWindow(s, new Set([mint]), () => null, 1_100, policy);
  assert.equal(judged.action, null);
  assert.deepEqual([...judged.unjudged], [mint]);
  judged = judgeReplayedWindow(s, judged.unjudged, figure, 1_100, policy);
  assert.equal(judged.action.type, "freeze");
  assert.equal(judged.unjudged.size, 0);
  // The freeze lands; ten minutes later a guardian quorum unfreezes.
  s.frozenUntil = 1_100 + 86_400;
  assess(s, { kind: "unfrozen", scope: 0 }, { now: 1_700 }, policy);
  assert.equal(s.frozenUntil, 0);
  // The quorum weighed the window: it no longer counts, so nothing freezes
  // again, neither here nor in a restart that replays it.
  assert.equal(breach(s, mint, { ...figure(), now: 1_710 }, policy), null);
  assert.equal(judgeReplayedWindow(s, judged.unjudged, figure, 1_710, policy).action, null);
  // A protocol already frozen at startup settles every mint.
  const frozen = newState();
  frozen.frozenUntil = 5_000;
  assert.equal(judgeReplayedWindow(frozen, new Set([mint]), figure, 1_000, policy).unjudged.size, 0);
});

test("a restart vetoes a loosening that is still pending and leaves a closed one", () => {
  const bytes = new Uint8Array(448) /* Change::LEN */;
  bytes.set(new TextEncoder().encode("BHCHNG01"));
  new DataView(bytes.buffer).setBigUint64(40, 9n, true);
  bytes[48] = 4;
  new DataView(bytes.buffer).setBigInt64(132, 5_000n, true);
  const open = readPendingChange(bytes);
  assert.equal(open.id, 9n);
  assert.equal(open.kind, 4);
  const policy = { ...DEFAULT_POLICY, approvedChangeIds: [] };
  const veto = pendingChangeVeto(open, policy, 1_000, new Set());
  assert.equal(veto.type, "veto_change");
  assert.equal(veto.changeId, 9n);
  assert.equal(pendingChangeVeto(open, policy, 1_000, new Set(["c9"])), null);
  assert.equal(pendingChangeVeto({ ...open, vetoed: true }, policy, 1_000, new Set()), null);
  assert.equal(pendingChangeVeto(open, policy, 5_000, new Set()), null);
  assert.equal(pendingChangeVeto(open, { ...policy, approvedChangeIds: [9] }, 1_000, new Set()), null);
  const floor = { program: "prog", pendingKind: 1, pendingId: 4n, pendingVetoed: false, pendingTarget: "buf" };
  assert.equal(pendingUpgradeVeto(floor, DEFAULT_POLICY, new Set()).proposalId, 4n);
  assert.equal(pendingUpgradeVeto(floor, { ...DEFAULT_POLICY, approvedUpgradeBuffers: ["buf"] }, new Set()), null);
  assert.equal(pendingUpgradeVeto({ ...floor, pendingKind: 0 }, DEFAULT_POLICY, new Set()), null);
});

test("a retried floor veto is dropped when a different proposal is pending", () => {
  const action = { type: "floor_veto", program: "p", proposalId: 4n };
  const open = { pendingKind: 1, pendingId: 4n, pendingVetoed: false };
  assert.equal(vetoRetryDisposition(action, open), "send");
  assert.equal(vetoRetryDisposition(action, { ...open, pendingId: 5n }), "drop");
  assert.equal(vetoRetryDisposition(action, { ...open, pendingKind: 0 }), "drop");
  // Any kind is worth a retried veto while the same proposal waits.
  assert.equal(vetoRetryDisposition(action, { ...open, pendingKind: 3 }), "send");
  assert.equal(vetoRetryDisposition(action, { ...open, pendingVetoed: true }), "drop");
  assert.equal(vetoRetryDisposition(action, null), "keep");
});

test("a retried vault veto stops once the change is closed", () => {
  const action = { type: "veto_change", changeId: 3n };
  assert.equal(vetoRetryDisposition(action, { vetoed: false, executed: false }), "send");
  assert.equal(vetoRetryDisposition(action, { vetoed: true, executed: false }), "drop");
  assert.equal(vetoRetryDisposition(action, { vetoed: false, executed: true }), "drop");
  assert.equal(vetoRetryDisposition(action, null), "keep");
  const bytes = new Uint8Array(448); // Change::LEN
  bytes.set(new TextEncoder().encode("BHCHNG01"));
  bytes[50] = 1;
  assert.deepEqual(readChangeVeto(bytes), { vetoed: false, executed: true });
  assert.equal(readChangeVeto(new Uint8Array(448)), null, "not a change account");
  assert.equal(readChangeVeto(bytes.subarray(0, 447)), null, "too short");
});

test("a lifeboat exit is vetoed unless pre-approved, once per proposal", () => {
  const mintKey = new Uint8Array(32).fill(7);
  const exit = (amount, executableS) => decode({ name: "vault:exit_proposed", fields: [mintKey, u64le(amount), i64le(executableS)] });
  const e = exit(4_000_000n, 900_000);
  assert.equal(e.kind, "exit_proposed");
  assert.equal(e.amount, 4_000_000n);
  assert.equal(e.executableS, 900_000);
  const s = newState();
  const policy = { ...DEFAULT_POLICY };
  const actions = assess(s, e, { now: 1 }, policy);
  assert.deepEqual(actions.map((a) => [a.type, a.mint, a.executableS]), [["veto_exit", e.mint, 900_000]]);
  assert.deepEqual(assess(s, e, { now: 2 }, policy), [], "the same proposal is vetoed once");
  // A new proposal (the admin proposed again) is a new veto.
  assert.equal(assess(s, exit(4_000_000n, 950_000), { now: 3 }, policy).length, 1);
  // Pre-approved by mint and exact amount; anything else is still vetoed.
  const approved = { ...policy, approvedExits: [`${e.mint}:4000000`] };
  assert.deepEqual(assess(newState(), e, { now: 1 }, approved), []);
  assert.equal(assess(newState(), exit(4_000_001n, 900_000), { now: 1 }, approved).length, 1);
  assert.deepEqual(assess(newState(), e, { now: 1 }, { ...policy, vetoLifeboatExits: false }), []);
  // Replayed history decides nothing; the restart scan does.
  assert.deepEqual(assess(newState(), e, { now: 1 }, policy, false), []);
  const lifeboatIn = decode({ name: "vault:lifeboat_in", fields: [mintKey, u64le(5n)] });
  assert.deepEqual([lifeboatIn.kind, lifeboatIn.amount], ["lifeboat_in", 5n]);
});

test("a retried exit veto stops once that exit is gone, vetoed or replaced", () => {
  const action = { type: "veto_exit", mint: "m", executableS: 900_000 };
  const open = { exitAmount: 10n, exitVetoed: false, exitExecutableS: 900_000 };
  assert.equal(vetoRetryDisposition(action, open), "send");
  assert.equal(vetoRetryDisposition(action, { ...open, exitAmount: 0n }), "drop");
  assert.equal(vetoRetryDisposition(action, { ...open, exitVetoed: true }), "drop");
  assert.equal(vetoRetryDisposition(action, { ...open, exitExecutableS: 950_000 }), "drop");
  assert.equal(vetoRetryDisposition(action, null), "keep");
  assert.deepEqual(queueFailedVeto(queueFailedVeto([], action), action), [action]);
});

test("a restart vetoes a lifeboat exit that is still pending", () => {
  const vault = { mint: "m", exitAmount: 10n, exitVetoed: false, exitExecutableS: 900_000, exitExpiresS: 1_500_000 };
  const policy = { ...DEFAULT_POLICY };
  assert.equal(pendingExitVeto(vault, policy, 1_000, new Set()).type, "veto_exit");
  assert.equal(pendingExitVeto(vault, policy, 1_000, new Set(["xm:900000"])), null);
  assert.equal(pendingExitVeto({ ...vault, exitAmount: 0n }, policy, 1_000, new Set()), null);
  assert.equal(pendingExitVeto({ ...vault, exitVetoed: true }, policy, 1_000, new Set()), null);
  assert.equal(pendingExitVeto(vault, policy, 1_500_000, new Set()), null, "expired");
  assert.equal(pendingExitVeto(vault, { ...policy, approvedExits: ["m:10"] }, 1_000, new Set()), null);
});

test("every Floor proposal a stolen owner key could make is vetoed unless pre-approved", () => {
  const program = "prog";
  // A Floor proposed event: program, kind, id, target.
  const proposed = (kind, id, target = new Uint8Array(32).fill(9)) =>
    decode({ name: "floor:proposed", fields: [new Uint8Array(32).fill(1), Uint8Array.of(kind), u64le(id), target] });
  for (const kind of [1, 2, 3, 4, 5, 6]) {
    const e = proposed(kind, 10n + BigInt(kind));
    const actions = assess(newState(), e, { now: 1 }, DEFAULT_POLICY);
    assert.equal(actions.length, 1, `kind ${kind} is vetoed`);
    assert.equal(actions[0].proposalId, e.id);
  }
  // Code is approved by buffer, everything else by program:id.
  const code = proposed(2, 12n);
  assert.deepEqual(assess(newState(), code, { now: 1 }, { ...DEFAULT_POLICY, approvedUpgradeBuffers: [code.target] }), []);
  const release = proposed(3, 13n);
  assert.deepEqual(assess(newState(), release, { now: 1 }, { ...DEFAULT_POLICY, approvedFloorProposals: [`${release.program}:13`] }), []);
  assert.equal(assess(newState(), release, { now: 1 }, { ...DEFAULT_POLICY, approvedFloorProposals: [`${release.program}:14`] }).length, 1);
  // After a restart, the same rule from the config.
  const pending = { program, pendingKind: 3, pendingId: 7n, pendingVetoed: false, pendingTarget: "attacker" };
  assert.match(pendingUpgradeVeto(pending, DEFAULT_POLICY, new Set()).reason, /release of the upgrade authority/);
  assert.equal(pendingUpgradeVeto(pending, { ...DEFAULT_POLICY, approvedFloorProposals: ["prog:7"] }, new Set()), null);
});

test("a queued release's ticket address travels from the event to the cancel", () => {
  const addr = new Uint8Array(32).fill(5);
  const outcome = concat(u64le(0n), u64le(0n), u64le(400n), u64le(7n), i64le(99));
  const e = decode({ name: "vault:released", fields: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), outcome, addr] });
  assert.equal(e.ticketId, 7n);
  assert.equal(e.ticket, decode({ name: "vault:released", fields: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), outcome, addr] }).ticket);
  assert.notEqual(e.ticket, null);
  // An all-zero address (nothing queued), or an event from an older build without it, is no address.
  assert.equal(decode({ name: "vault:released", fields: [new Uint8Array(32), new Uint8Array(32), outcome, new Uint8Array(32)] }).ticket, null);
  assert.equal(decode({ name: "vault:released", fields: [new Uint8Array(32), new Uint8Array(32), outcome] }).ticket, null);
  const s = newState();
  assess(s, e, { worst1h: 1_000_000n, worst24h: 2_000_000n, now: 1 }, DEFAULT_POLICY, false);
  assert.equal(s.pendingTickets.get(7n).address, e.ticket);
  // A later chain scan without an address does not erase it.
  rememberTicket(s, { ticketId: 7n });
  assert.equal(s.pendingTickets.get(7n).address, e.ticket);
  const [cancel] = pendingCancels(s);
  assert.deepEqual([cancel.ticketId, cancel.address], [7n, e.ticket]);
});

test("the keeper executes exactly the approved changes, only while they are due", () => {
  const change = { id: 3n, kind: 2, target: "t", vetoed: false, executed: false, executableS: 1_000, expiresS: 2_000 };
  const policy = { ...DEFAULT_POLICY, approvedChangeIds: [3] };
  assert.equal(dueApprovedChange(change, policy, 1_000, new Set()).changeId, 3n);
  assert.equal(dueApprovedChange(change, policy, 999, new Set()), null, "not yet due");
  assert.equal(dueApprovedChange(change, policy, 2_000, new Set()), null, "expired");
  assert.equal(dueApprovedChange(change, DEFAULT_POLICY, 1_500, new Set()), null, "not approved: vetoed instead, never executed");
  assert.equal(dueApprovedChange({ ...change, vetoed: true }, policy, 1_500, new Set()), null);
  assert.equal(dueApprovedChange({ ...change, executed: true }, policy, 1_500, new Set()), null);
  assert.equal(dueApprovedChange(change, policy, 1_500, new Set(["c3"])), null, "sent once");
  assert.equal(dueApprovedChange(change, { ...policy, executeApproved: false }, 1_500, new Set()), null);
  // Readable straight from a change account.
  const bytes = new Uint8Array(448) /* Change::LEN */;
  bytes.set(new TextEncoder().encode("BHCHNG01"));
  const v = new DataView(bytes.buffer);
  v.setBigUint64(40, 3n, true);
  bytes[48] = 2;
  v.setBigInt64(124, 1_000n, true);
  v.setBigInt64(132, 2_000n, true);
  const read = readPendingChange(bytes);
  assert.deepEqual([read.executableS, read.expiresS], [1_000, 2_000]);
  assert.equal(dueApprovedChange(read, policy, 1_500, new Set()).kind, 2);
});

test("the keeper executes approved Floor proposals when due, but never releases the authority", () => {
  const floor = { program: "prog", pendingKind: 4, pendingId: 7n, pendingVetoed: false, pendingTarget: "x", pendingEta: 1_000, pendingExpires: 2_000 };
  const policy = { ...DEFAULT_POLICY, approvedFloorProposals: ["prog:7"], approvedUpgradeBuffers: ["buf"] };
  assert.equal(dueApprovedFloor(floor, policy, 1_000, new Set()).kind, 4);
  assert.equal(dueApprovedFloor(floor, policy, 999, new Set()), null);
  assert.equal(dueApprovedFloor(floor, policy, 2_000, new Set()), null);
  assert.equal(dueApprovedFloor(floor, DEFAULT_POLICY, 1_500, new Set()), null, "not approved");
  assert.equal(dueApprovedFloor({ ...floor, pendingVetoed: true }, policy, 1_500, new Set()), null);
  assert.equal(dueApprovedFloor(floor, policy, 1_500, new Set(["eprog:7"])), null);
  // Code by buffer.
  assert.equal(dueApprovedFloor({ ...floor, pendingKind: 1, pendingTarget: "buf" }, policy, 1_500, new Set()).kind, 1);
  assert.equal(dueApprovedFloor({ ...floor, pendingKind: 1, pendingTarget: "other" }, policy, 1_500, new Set()), null);
  // Releasing the upgrade authority closes Floor's config: always a person's call.
  assert.equal(dueApprovedFloor({ ...floor, pendingKind: 3 }, { ...policy, approvedFloorProposals: ["prog:7"] }, 1_500, new Set()), null);
});

test("the keeper's execute instruction names the right target for each kind of change", async () => {
  const { executeChangeIx } = await import("../guardian/keeper.mjs");
  const { b58encode: enc, findPda, key: k, u64le: le, IDS } = await import("../lib/solana.mjs");
  const vaultProgram = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
  const protocol = "26dY2HWrczKyPYh8jB4cBgzFsf5gkYo789BfCBQXRvSq";
  const payer = "E3VZyofZZJLJWt6kjzEPUWedMTFUdkpoogGDbR6RF7xC";
  const mint = "CBK36QrH6fzjrDYwkKHF6jeEAEfHcm8iSVN9BZrCxHSB";
  const vault = "7qrrXwX5uYeCDTfdQbbRNJC7tdLYRFCLfq6sswKuZqZw";
  const build = (kind, target, mintOwner) => executeChangeIx({ vaultProgram, protocol, payer, defaultMint: mint, changeId: 5n, kind, target, mintOwner });
  const names = (ix) => ix.accounts.map((a) => enc(a.pubkey));
  const [change] = await findPda(["change", k(protocol), le(5n)], k(vaultProgram));
  // A protocol-level change (guardians): the protocol stands in as the target.
  const guardians = await build(2, "11111111111111111111111111111111");
  assert.deepEqual(names(guardians).slice(0, 4), [protocol, enc(change), protocol, payer]);
  assert.equal(guardians.data[0], 20);
  assert.deepEqual(guardians.accounts.map((a) => [!!a.writable, !!a.signer]), [[true, false], [true, false], [true, false], [true, true], [false, false], [false, false], [false, false]]);
  // SetLimits: the vault.
  assert.equal(names(await build(0, vault))[2], vault);
  // UpsertAsset: the asset record, the mint, and the mint's token program.
  const token2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
  const asset = await build(1, mint, token2022);
  const [assetPda] = await findPda(["asset", k(protocol), k(mint)], k(vaultProgram));
  assert.deepEqual(names(asset).slice(2), [enc(assetPda), payer, mint, token2022, enc(IDS.system)]);
});

// --- incident hold ------------------------------------------------------------
// A stolen admin key stays stolen when a 24h freeze ends. Without the hold a
// patient attacker waits each freeze out and takes one more burst a day.

test("incident hold: renews a guardian freeze near its end, never past the hold", () => {
  const H = DEFAULT_POLICY.holdIncidentS, F = DEFAULT_POLICY.freezeSecs;
  const s = newState();
  assert.equal(incidentHold(s, 0, 1_000), null, "no incident, no hold");
  openIncident(s, 1_000);
  openIncident(s, 5_000); // a renewal landing keeps the incident's start
  assert.equal(s.incidentSince, 1_000);
  assert.equal(incidentHold(s, 1_000 + F, 2_000), null, "plenty of freeze left");
  const r = incidentHold(s, 1_000 + F, 1_000 + F - 3_600);
  assert.equal(r.type, "freeze");
  assert.equal(r.secs, F);
  // Already thawed (the guardian was down): freeze again at once.
  assert.equal(incidentHold(s, 1_000 + F, 1_000 + F + 10).secs, F);
  // The last renewal is cut to the hold's end.
  assert.equal(incidentHold(s, 0, 1_000 + H - 600).secs, 600);
  // At the end the incident closes.
  assert.equal(incidentHold(s, 0, 1_000 + H), null);
  assert.equal(s.incidentSince, null);
});

test("incident hold: a freeze in flight is not doubled; 0 turns the hold off", () => {
  const s = newState();
  openIncident(s, 0);
  s.freezing = true;
  assert.equal(incidentHold(s, 0, 100), null);
  s.freezing = false;
  assert.equal(incidentHold(s, 0, 100, { ...DEFAULT_POLICY, holdIncidentS: 0 }), null);
  assert.ok(incidentHold(s, 0, 100));
});

test("incident hold: a quorum unfreeze ends it; a freeze that runs out does not", () => {
  const s = newState();
  openIncident(s, 0);
  // Ran out: the end stays where it was. Renewed: the end moves later.
  observeFreezeEnd(s, 86_400, 86_400);
  observeFreezeEnd(s, 86_400, 172_800);
  assert.equal(s.incidentSince, 0);
  // Lifted early by a quorum: the end moved earlier (to the moment it ran).
  observeFreezeEnd(s, 86_400, 50_000);
  assert.equal(s.incidentSince, null);
  // A guardian restarted long after, having missed that unfreeze, still sees
  // it from the saved end: comparing ends, not clocks (a restart at 200,000
  // with the old rule froze again against the quorum's decision).
  const restarted = newState();
  openIncident(restarted, 0);
  observeFreezeEnd(restarted, 86_400, 50_000);
  assert.equal(restarted.incidentSince, null);
  assert.equal(incidentHold(restarted, 50_000, 200_000), null);
  assert.equal(incidentHold(s, 50_000, 50_010), null);
  // The unfrozen event closes it the same way.
  openIncident(s, 60_000);
  assess(s, { kind: "unfrozen", scope: 0 }, { now: 60_100 });
  assert.equal(s.incidentSince, null);
  // One vault unfrozen is not the protocol.
  openIncident(s, 70_000);
  assess(s, { kind: "unfrozen", scope: 1 }, { now: 70_100 });
  assert.equal(s.incidentSince, 70_000);
});
