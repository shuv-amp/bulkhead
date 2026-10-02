import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, breach, decode, floorAlerts, newState, observeProtocolFreeze, pendingCancels, rememberTicket, retirePendingFreeze, scaleBy, DEFAULT_POLICY } from "../guardian/policy.mjs";
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
