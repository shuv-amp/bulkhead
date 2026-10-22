// The external review of 22 Oct 2026 (docs/09, findings 137–139): each
// behaviour it changed in the guardian, with the test that fails without it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { key, FailoverRpc, decodeProtocol } from "../lib/solana.mjs";
import { decode, decodeOrOther, incidentHold, newState, DEFAULT_POLICY } from "../guardian/policy.mjs";
import { stateJson, restoreState, lockInstance } from "../guardian/statefile.mjs";
import { vaultOutflows } from "../guardian/chain.mjs";

const PROTOCOL = "8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb";

function stubFetch(routes) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...routes[new URL(url).host](method, params) }), { status: 200 });
  };
  return { restore: () => { globalThis.fetch = real; } };
}

test("a configured address must decode to exactly 32 bytes (finding 139)", () => {
  assert.equal(key(PROTOCOL).length, 32);
  // A typo that shortens the id used to be zero-padded into another valid key.
  assert.throws(() => key(PROTOCOL.slice(0, -2)), /not a 32-byte key/);
  assert.throws(() => key("1"), /not a 32-byte key/);
  assert.throws(() => key(`${PROTOCOL}zz`), /not a 32-byte key/);
});

test("an event layout the decoder cannot read is dropped, not thrown (finding 139)", () => {
  // `vault:change_proposed` reads a u64 from f[0]: a two-byte field used to
  // throw a RangeError out of the ingest, which then stalled at that
  // signature for good (the field count is right, so it passed the gate).
  const bad = { name: "vault:change_proposed", fields: [new Uint8Array(2), Uint8Array.of(3), new Uint8Array(32), key(PROTOCOL)] };
  assert.throws(() => decode(bad));
  const e = decodeOrOther(bad);
  assert.equal(e.kind, "other");
  assert.equal(e.unreadable, true);
  const good = { name: "vault:change_proposed", fields: [new Uint8Array(8), Uint8Array.of(3), new Uint8Array(32), key(PROTOCOL)] };
  assert.equal(decodeOrOther(good).kind, "change_proposed");
});

test("the hold's last renewal is not returned once the chain already covers the hold's end (finding 139)", () => {
  const policy = { ...DEFAULT_POLICY, holdIncidentS: 7 * 86_400, holdRenewBeforeS: 3_600, freezeSecs: 86_400 };
  const s = newState();
  s.incidentSince = 1_000;
  const end = s.incidentSince + policy.holdIncidentS;
  // Half an hour of freeze left, the hold ending in three days: renew.
  assert.equal(incidentHold(s, end - 3 * 86_400 + 1_800, end - 3 * 86_400, policy)?.type, "freeze");
  // The freeze already runs to the hold's end: nothing to send, every poll.
  for (const now of [end - 3_000, end - 600, end - 1]) assert.equal(incidentHold(s, end, now, policy), null, `${now}`);
  assert.equal(incidentHold(s, end + 10, end - 100, policy), null);
});

test("the state file keeps the slot the protocol account was read at (finding 137)", () => {
  const s = newState();
  const text = stateJson({ protocol: PROTOCOL, incidentSince: 5, frozenUntil: 99, protocolSlot: 123_456, state: s });
  assert.equal(JSON.parse(text).protocolSlot, 123_456);
  const r = restoreState(text, PROTOCOL, newState());
  assert.equal(r.protocolSlot, 123_456);
  assert.equal(r.frozenUntil, 99);
  // Older files, or a damaged value, restore no slot.
  assert.equal(restoreState(JSON.stringify({ protocol: PROTOCOL, frozenUntil: 1 }), PROTOCOL, newState()).protocolSlot, 0);
  assert.equal(restoreState(JSON.stringify({ protocol: PROTOCOL, protocolSlot: -4 }), PROTOCOL, newState()).protocolSlot, 0);
  assert.equal(restoreState(JSON.stringify({ protocol: PROTOCOL, protocolSlot: "7" }), PROTOCOL, newState()).protocolSlot, 0);
});

test("one guardian per state file: a live holder refuses a second, a dead one is taken over (finding 139)", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-lock-"));
  const stateFile = join(dir, "x.state.json");
  const release = lockInstance(stateFile);
  assert.equal(readFileSync(`${stateFile}.lock`, "utf8"), String(process.pid));
  release();
  assert.equal(existsSync(`${stateFile}.lock`), false);
  // Another live process holds it (the test runner's parent stands in): refused.
  writeFileSync(`${stateFile}.lock`, String(process.ppid));
  assert.throws(() => lockInstance(stateFile), /another guardian \(pid \d+\) holds/);
  assert.equal(readFileSync(`${stateFile}.lock`, "utf8"), String(process.ppid), "left alone");
  // A lock left by a process that is gone (or unreadable) is taken over.
  writeFileSync(`${stateFile}.lock`, "999999999");
  const again = lockInstance(stateFile);
  assert.equal(readFileSync(`${stateFile}.lock`, "utf8"), String(process.pid));
  again();
  writeFileSync(`${stateFile}.lock`, "not a pid");
  lockInstance(stateFile)();
});

test("a balance row without an amount is skipped, not thrown on (finding 139)", () => {
  const vaultTokens = "6fTfk8ZHDSoDqfk6BkQwBuxMuhHnnj5ntBg6o4UhzjUS";
  const tx = {
    transaction: { message: { accountKeys: [{ pubkey: vaultTokens }] } },
    meta: {
      preTokenBalances: [{ accountIndex: 0, uiTokenAmount: { amount: "500" } }, { accountIndex: 0, uiTokenAmount: null }],
      postTokenBalances: [{ accountIndex: 0, uiTokenAmount: { amount: "200" } }, { accountIndex: 0 }],
    },
  };
  assert.deepEqual([...vaultOutflows(tx, new Map([[vaultTokens, "USDC"]]))], [["USDC", 300n]]);
});

test("a backup reporting a larger counter than the primary, for long enough, proves the primary hides writes (finding 138)", async () => {
  // A protocol account whose next ticket id is 7 on the primary and 9 on a backup.
  const account = (nextTicketId) => {
    const d = new Uint8Array(597);
    d.set(new TextEncoder().encode("BHPROTv1"), 0);
    const view = new DataView(d.buffer);
    // next_ticket_id sits after: 3 keys, 8 guardians, 8 heartbeats, 4 bytes, 3 i64, 2 u32.
    const at = 8 + 96 + 256 + 64 + 4 + 24 + 8;
    view.setBigUint64(at, BigInt(nextTicketId), true);
    return { result: { context: { slot: 1 }, value: { data: [Buffer.from(d).toString("base64"), "base64"] } } };
  };
  assert.equal(decodeProtocol(Uint8Array.from(Buffer.from(account(9).result.value.data[0], "base64"))).nextTicketId, 9n);
  const counter = (_address, bytes) => decodeProtocol(bytes).nextTicketId;
  const f = stubFetch({ "a.invalid": () => account(7), "b.invalid": () => account(9), "c.invalid": () => ({ error: { code: -32000, message: "down" } }) });
  try {
    const switches = [];
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid", "http://c.invalid"], { onSwitch: (from, to) => switches.push([from, to]) });
    // Seen once: it may be a backup a slot ahead. Not yet a switch.
    assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 0 })).switched, false);
    assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 20_000 })).switched, false);
    const r = await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 31_000 });
    assert.equal(r.switched, true);
    assert.match(r.reason, /behind on .*: a backup has read a counter of 9 .* while the primary returns 7/);
    assert.deepEqual(switches, [["http://a.invalid", "http://b.invalid"]]);
    assert.equal(rpc.url, "http://b.invalid");
  } finally {
    f.restore();
  }
  // Equal counters, or a primary ahead: nothing, however long.
  const g = stubFetch({ "a.invalid": () => account(9), "b.invalid": () => account(7) });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    for (const t of [0, 31_000, 120_000]) assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: t })).switched, false, `${t}`);
  } finally {
    g.restore();
  }
  // A backup that catches down (the primary caught up) forgets the mark.
  let ahead = true;
  const h = stubFetch({ "a.invalid": () => account(7), "b.invalid": () => account(ahead ? 9 : 7) });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 0 })).switched, false);
    ahead = false;
    assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 10_000 })).switched, false);
    ahead = true;
    assert.equal((await rpc.crossCheckCounters([PROTOCOL], counter, { nowMs: 40_000 })).switched, false, "a fresh mark: the clock restarts");
  } finally {
    h.restore();
  }
});
