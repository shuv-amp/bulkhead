import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, newState, decode, DEFAULT_POLICY } from "../guardian/policy.mjs";
import { u64le, i64le, concat, key } from "../lib/solana.mjs";

const USDC = 1_000_000n;
const worst1h = 400_000n * USDC; // 10M vault, default limits (golden G-6)
const owner = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const mint = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";

function released({ backed = 0n, instant = 0n, queued = 0n, ticketId = 0n, who = owner }) {
  const outcome = concat(u64le(backed), u64le(instant), u64le(queued), u64le(ticketId), i64le(0));
  return decode({ name: "vault:released", fields: [key(mint), key(who), outcome] });
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

test("unapproved loosenings are vetoed once; approved ones are not", () => {
  const s = newState();
  const ev = decode({ name: "vault:change_proposed", fields: [u64le(3), Uint8Array.of(0), key(mint), i64le(0)] });
  assert.equal(assess(s, ev, { worst1h, now: 0 })[0].type, "veto_change");
  assert.deepEqual(assess(s, ev, { worst1h, now: 1 }), []);
  const s2 = newState();
  assert.deepEqual(assess(s2, ev, { worst1h, now: 0 }, { ...DEFAULT_POLICY, approvedChangeIds: [3] }), []);
});
