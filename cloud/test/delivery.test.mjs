import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, send, sendWithFallback, sendEscalating, refusalCause, computeBudget, priorityPrice, COMPUTE_BUDGET, PREFLIGHT_REFUSED } from "../lib/signer.mjs";
import { b58encode, Rpc } from "../lib/solana.mjs";

test("compute budget: a unit limit, and a price only when one is set", () => {
  const [limit, price] = computeBudget(50_000, 1_234);
  assert.equal(b58encode(limit.programId), "ComputeBudget111111111111111111111111111111");
  assert.deepEqual([...limit.data], [2, 0x50, 0xc3, 0, 0]); // SetComputeUnitLimit(50,000)
  assert.deepEqual([...price.data], [3, 0xd2, 0x04, 0, 0, 0, 0, 0, 0]); // SetComputeUnitPrice(1,234)
  assert.equal(computeBudget(50_000, 0).length, 1);
});

test("priority price: a high percentile of what others paid, capped, zero when nobody paid", () => {
  const fees = [0, 0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1_000].map((f, i) => ({ slot: i, prioritizationFee: f }));
  assert.equal(priorityPrice(fees), 900); // 90th percentile of the ten non-zero fees
  assert.equal(priorityPrice(fees, { cap: 250 }), 250);
  assert.equal(priorityPrice([{ slot: 1, prioritizationFee: 0 }]), 0);
  assert.equal(priorityPrice(undefined), 0);
});

test("one signed transaction goes to every endpoint, with the budget first", async () => {
  const sent = [];
  const endpoint = (name, { fails = false } = {}) => ({
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method, params) => {
      if (method === "sendTransaction") {
        sent.push([name, params[0]]);
        if (fails) throw new Error("endpoint down");
        return "sig";
      }
      if (method === "getSignatureStatuses") return { value: [{ confirmationStatus: "confirmed" }] };
      throw new Error(`unexpected ${method}`);
    },
  });
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const sig = await send(endpoint("primary"), payer, [ix], [], {
    computeUnits: 50_000,
    microLamports: 10,
    rpcs: [endpoint("backup-1"), endpoint("backup-2", { fails: true })],
  });
  assert.equal(sig, "sig");
  assert.deepEqual(sent.map(([n]) => n).sort(), ["backup-1", "backup-2", "primary"]);
  assert.equal(new Set(sent.map(([, tx]) => tx)).size, 1, "the same bytes everywhere");
  const bytes = Buffer.from(sent[0][1], "base64");
  assert.ok(bytes.includes(Buffer.from(COMPUTE_BUDGET)), "the compute-budget program is in the message");
});

test("a hanging backup send cannot delay primary confirmation", async () => {
  const primary = {
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method) => {
      if (method === "sendTransaction") return "sig";
      if (method === "getSignatureStatuses") return { value: [{ confirmationStatus: "confirmed" }] };
      throw new Error(`unexpected ${method}`);
    },
  };
  const backup = { call: async () => new Promise(() => {}) };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("primary confirmation was delayed")), 1_000); });
  try {
    assert.equal(await Promise.race([send(primary, payer, [ix], [], { rpcs: [backup] }), timeout]), "sig");
  } finally {
    clearTimeout(timer);
  }
});

test("backups still get the transaction when the primary's send fails", async () => {
  const sent = [];
  const primary = {
    blockhash: async () => "11111111111111111111111111111111",
    call: async () => { throw new Error("primary down"); },
  };
  const backup = { call: async (method, params) => { sent.push([method, params[0]]); return "sig"; } };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  await assert.rejects(send(primary, payer, [ix], [], { rpcs: [backup] }), /primary down/);
  assert.deepEqual(sent.map(([m]) => m), ["sendTransaction"]);
});

// Finding 47: on 1 Oct on devnet a mistyped Compute Budget id made every
// guardian freeze fail simulation for 5½ minutes. The budget may never be
// what stops a guardian transaction.
function refusingEndpoint({ refuse }) {
  const sent = [];
  return {
    sent,
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method, params) => {
      if (method === "sendTransaction") {
        const tx = Buffer.from(params[0], "base64");
        const withBudget = tx.includes(Buffer.from(COMPUTE_BUDGET));
        sent.push(withBudget);
        if (refuse(withBudget)) {
          const err = new Error(`sendTransaction: simulation failed (${withBudget ? "with" : "without"} budget)`);
          err.rpcError = { code: PREFLIGHT_REFUSED, message: "Transaction simulation failed" };
          throw err;
        }
        return withBudget ? "sig-budget" : "sig-bare";
      }
      if (method === "getSignatureStatuses") return { value: [{ confirmationStatus: "confirmed" }] };
      throw new Error(`unexpected ${method}`);
    },
  };
}

test("a budget the node refuses is dropped, and the same instructions land without it", async () => {
  const rpc = refusingEndpoint({ refuse: (withBudget) => withBudget });
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const told = [];
  const sig = await sendWithFallback(rpc, payer, [ix], [], { computeUnits: 200_000, microLamports: 50_000 }, (e) => told.push(e.message));
  assert.equal(sig, "sig-bare");
  assert.deepEqual(rpc.sent, [true, false], "first with the budget, then without");
  assert.equal(told.length, 1, "the fallback is reported");
});

test("no fallback when the budget is fine, absent, or the error is not a refused preflight", async () => {
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const ok = refusingEndpoint({ refuse: () => false });
  assert.equal(await sendWithFallback(ok, payer, [ix], [], { computeUnits: 200_000 }), "sig-budget");
  assert.deepEqual(ok.sent, [true]);
  // Without a budget there is nothing to drop: the refusal is the answer.
  const bare = refusingEndpoint({ refuse: () => true });
  await assert.rejects(sendWithFallback(bare, payer, [ix], [], {}), /without budget/);
  assert.deepEqual(bare.sent, [false]);
  // A network failure is not a refusal: no second transaction.
  const down = { blockhash: async () => "11111111111111111111111111111111", call: async () => { throw new Error("connection reset"); } };
  await assert.rejects(sendWithFallback(down, payer, [ix], [], { computeUnits: 200_000 }), /connection reset/);
});

test("instructions the node refuses either way: the second refusal is thrown, no fallback reported", async () => {
  const rpc = refusingEndpoint({ refuse: () => true });
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  let told = 0;
  await assert.rejects(sendWithFallback(rpc, payer, [ix], [], { computeUnits: 200_000 }, () => told++), /without budget/);
  assert.deepEqual(rpc.sent, [true, false]);
  assert.equal(told, 0);
});

test("an RPC error keeps its JSON-RPC code, so a refused preflight can be told apart", async () => {
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32002, message: "Transaction simulation failed: Attempt to load a program that does not exist" } }), { status: 200 });
  try {
    const err = await new Rpc("http://rpc.invalid").call("sendTransaction", ["x"]).then(() => null, (e) => e);
    assert.equal(err.rpcError.code, PREFLIGHT_REFUSED);
    assert.match(err.message, /^sendTransaction: /);
  } finally {
    globalThis.fetch = real;
  }
});

// A dead primary used to cost about a minute per call (6 retries with
// backoff), and the guardian read only from it: blind while backups were up.
import { FailoverRpc, endpointTrouble } from "../lib/solana.mjs";

function stubFetch(routes) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const { method } = JSON.parse(init.body);
    calls.push([new URL(url).host, method]);
    const r = routes[new URL(url).host];
    if (r === "down") throw new TypeError("fetch failed");
    if (typeof r === "number") return new Response("busy", { status: r });
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, ...r(method) }), { status: 200 });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test("failover: a dead primary hands over to the backup at once, and the backup sticks", async () => {
  const f = stubFetch({ "a.invalid": "down", "b.invalid": () => ({ result: 7 }) });
  const switches = [];
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"], { onSwitch: (from, to) => switches.push([from, to]) });
    const t0 = Date.now();
    assert.equal(await rpc.call("getSlot"), 7);
    assert.ok(Date.now() - t0 < 3_000, `took ${Date.now() - t0} ms`);
    assert.deepEqual(switches, [["http://a.invalid", "http://b.invalid"]]);
    f.calls.length = 0;
    assert.equal(await rpc.call("getSlot"), 7);
    assert.deepEqual(f.calls, [["b.invalid", "getSlot"]], "the working endpoint is used first");
  } finally {
    f.restore();
  }
});

test("failover: an answer is final; an unhealthy node or a 5xx is not", async () => {
  const refused = { error: { code: -32002, message: "Transaction simulation failed" } };
  let f = stubFetch({ "a.invalid": () => refused, "b.invalid": () => ({ result: "never" }) });
  try {
    const rpc = new FailoverRpc(["http://a.invalid", "http://b.invalid"]);
    const err = await rpc.call("sendTransaction", ["x"]).then(() => null, (e) => e);
    assert.equal(err.rpcError.code, -32002, "the refusal comes back as is");
    assert.deepEqual(f.calls.map(([h]) => h), ["a.invalid"], "and is not asked of another node");
  } finally {
    f.restore();
  }
  f = stubFetch({ "a.invalid": () => ({ error: { code: -32005, message: "Node is unhealthy" } }), "b.invalid": () => ({ result: 1 }) });
  try {
    assert.equal(await new FailoverRpc(["http://a.invalid", "http://b.invalid"]).call("getSlot"), 1);
  } finally {
    f.restore();
  }
  f = stubFetch({ "a.invalid": 503, "b.invalid": () => ({ result: 2 }) });
  try {
    assert.equal(await new FailoverRpc(["http://a.invalid", "http://b.invalid"]).call("getSlot"), 2);
  } finally {
    f.restore();
  }
});

test("failover: every endpoint down fails with the last error", async () => {
  const f = stubFetch({ "a.invalid": "down", "b.invalid": "down" });
  try {
    await assert.rejects(new FailoverRpc(["http://a.invalid", "http://b.invalid"]).call("getSlot"), /getSlot: fetch failed/);
  } finally {
    f.restore();
  }
  assert.equal(endpointTrouble(new Error("x")), true);
  assert.equal(endpointTrouble(Object.assign(new Error("x"), { rpcError: { code: -32602 } })), false, "a bad request is the caller's");
});

// Calls overlap (a cancel sweep sends several at once). Each endpoint answers
// or fails per caller; a caller's request may wait on a gate (another call
// finishing), so the order is set by the test, not by timers.
function overlapRpc(behaviour) {
  const switches = [];
  const asked = {};
  const causes = [];
  const rpc = new FailoverRpc(behaviour.map((_, i) => `http://e${i}.invalid`), {
    onSwitch: (from, to, err) => (switches.push([from, to]), causes.push(err?.message)),
  });
  rpc.endpoints = behaviour.map((b, i) => ({
    url: `http://e${i}.invalid`,
    call: async (_method, [who]) => {
      (asked[who] ??= []).push(i);
      const [ok, gate] = b[who];
      await (gate ? gate() : null);
      if (!ok) throw new TypeError(`e${i}: fetch failed`);
      return `e${i}`;
    },
  }));
  return { rpc, switches, causes, asked };
}
const settled = (p) => p.then(() => {}, () => {});
const e = (i) => `http://e${i}.invalid`;

test("failover: a call that overlaps a switch still asks the live endpoint", async () => {
  // A finds e0 dead and moves to e1 while B is still waiting on e0.
  let a;
  const { rpc, asked } = overlapRpc([{ A: [false], B: [false, () => settled(a)] }, { A: [true], B: [true] }]);
  a = rpc.call("m", ["A"]);
  const b = rpc.call("m", ["B"]).catch((err) => err.message);
  assert.equal(await a, "e1");
  assert.equal(await b, "e1");
  assert.deepEqual(asked.B, [0, 1], "B asks e1 after e0, not e0 twice");
  assert.equal(rpc.active, 1);
});

test("failover: a slow answer from the old endpoint does not move the call back", async () => {
  // e0 fails A but answers B, after A has moved to e1.
  let a;
  const { rpc, switches } = overlapRpc([{ A: [false], B: [true, () => settled(a)] }, { A: [true], B: [true] }]);
  a = rpc.call("m", ["A"]);
  assert.deepEqual(await Promise.all([a, rpc.call("m", ["B"])]), ["e1", "e0"]);
  assert.equal(rpc.active, 1);
  assert.deepEqual(switches, [[e(0), e(1)]], "one switch, logged once");
});

test("failover: a call that saw only the old endpoint fail leaves a newer move alone", async () => {
  // Both start on e0. A fails over to e2. B, failing on e0 after that, gets
  // an answer from e1: it has no evidence against e2.
  let a;
  const { rpc, switches } = overlapRpc([
    { A: [false], B: [false, () => settled(a)] },
    { A: [false], B: [true] },
    { A: [true], B: [true] },
  ]);
  a = rpc.call("m", ["A"]);
  assert.deepEqual(await Promise.all([a, rpc.call("m", ["B"])]), ["e2", "e1"]);
  assert.equal(rpc.active, 2);
  assert.deepEqual(switches, [[e(0), e(2)]]);
});

test("failover: a call that saw the new endpoint fail too moves off it", async () => {
  // A moves e0 -> e1. B, started on e0, then sends to e1, which fails it,
  // and e2 answers: e1 failed after the last move, so B moves to e2.
  let a;
  const { rpc, switches } = overlapRpc([
    { A: [false], B: [false, () => settled(a)] },
    { A: [true], B: [false] },
    { A: [true], B: [true] },
  ]);
  a = rpc.call("m", ["A"]);
  assert.deepEqual(await Promise.all([a, rpc.call("m", ["B"])]), ["e1", "e2"]);
  assert.equal(rpc.active, 2);
  assert.deepEqual(switches, [[e(0), e(1)], [e(1), e(2)]]);
});

test("failover: a fresh failure on an endpoint that is not active is no evidence against the active one", async () => {
  // A moves e0 -> e3. B's request to e0 was sent before that; B then sends to
  // e1, which fails it after the move, and e2 answers. Only e3's own failures
  // count against e3, and B saw none, so B leaves e3 active.
  let a;
  const { rpc, switches } = overlapRpc([
    { A: [false], B: [false, () => settled(a)] },
    { A: [false], B: [false] },
    { A: [false], B: [true] },
    { A: [true], B: [true] },
  ]);
  a = rpc.call("m", ["A"]);
  assert.deepEqual(await Promise.all([a, rpc.call("m", ["B"])]), ["e3", "e2"]);
  assert.equal(rpc.active, 3);
  assert.deepEqual(switches, [[e(0), e(3)]]);
});

test("failover: a failure sent before two moves does not undo them (e0 -> e1 -> e0)", async () => {
  // B's request to e0 is sent first and fails last. Meanwhile X moves e0 ->
  // e1, and Y, started on e1, finds e1 and e2 down and moves back to e0.
  // B's failure predates Y's answer from e0, so B leaves e0 active.
  let yDone;
  const yGate = new Promise((r) => (yDone = r));
  const { rpc, switches } = overlapRpc([
    { B: [false, () => yGate], X: [false], Y: [true] },
    { B: [true], X: [true], Y: [false] },
    { B: [true], X: [true], Y: [false] },
  ]);
  const b = rpc.call("m", ["B"]);
  assert.equal(await rpc.call("m", ["X"]), "e1");
  assert.equal(await rpc.call("m", ["Y"]), "e0");
  yDone();
  assert.equal(await b, "e1");
  assert.equal(rpc.active, 0);
  assert.deepEqual(switches, [[e(0), e(1)], [e(1), e(0)]]);
});

test("failover: a move made outside call() (crossCheck) also dates a call's evidence", async () => {
  // crossCheck moves through switchTo. Two such moves (e0 -> e1 -> e0) while
  // B waits on e0 make B's failure older than both.
  let release;
  const gate = new Promise((r) => (release = r));
  const { rpc, switches } = overlapRpc([{ B: [false, () => gate] }, { B: [true] }]);
  const b = rpc.call("m", ["B"]);
  rpc.switchTo(1, new Error("behind"));
  rpc.switchTo(0, new Error("behind"));
  release();
  assert.equal(await b, "e1");
  assert.equal(rpc.active, 0);
  assert.equal(switches.length, 2);
});

test("a refused preflight is not resent when a backup already landed the transaction", async () => {
  const sent = [];
  let landedSig = null;
  const primary = {
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method, params) => {
      if (method === "sendTransaction") {
        sent.push(Buffer.from(params[0], "base64").includes(Buffer.from(COMPUTE_BUDGET)) ? "budget" : "bare");
        const err = new Error("sendTransaction: simulation failed");
        err.rpcError = { code: PREFLIGHT_REFUSED, message: "Transaction simulation failed: Blockhash not found" };
        throw err;
      }
      if (method === "getSignatureStatuses") {
        // The backup landed exactly the transaction the primary refused.
        return { value: [params[0][0] === landedSig ? { confirmationStatus: "confirmed", err: null } : null] };
      }
      throw new Error(`unexpected ${method}`);
    },
  };
  const backup = { call: async (method, params) => { if (method === "sendTransaction") sent.push("backup"); return "x"; } };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  // The signature of the budgeted transaction is what the error carries.
  const err = await send(primary, payer, [ix], [], { computeUnits: 200_000, rpcs: [backup] }).then(() => null, (e) => e);
  landedSig = err.signature;
  sent.length = 0;
  const sig = await sendWithFallback(primary, payer, [ix], [], { computeUnits: 200_000, rpcs: [backup], landedWaitMs: 50 });
  assert.equal(sig, landedSig);
  assert.deepEqual(sent.sort(), ["backup", "budget"], "no second, unbudgeted transaction");
});

test("a budgeted transaction a backup landed with an error (out of compute) falls back instead of failing", async () => {
  const sent = [];
  let failedSig = null;
  const primary = {
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method, params) => {
      if (method === "sendTransaction") {
        const withBudget = Buffer.from(params[0], "base64").includes(Buffer.from(COMPUTE_BUDGET));
        sent.push(withBudget ? "budget" : "bare");
        if (withBudget) {
          const err = new Error("sendTransaction: simulation failed");
          err.rpcError = { code: PREFLIGHT_REFUSED, message: "Transaction simulation failed: exceeded CUs meter" };
          throw err;
        }
        return "sig-bare";
      }
      if (method === "getSignatureStatuses") {
        if (params[0][0] === failedSig) return { value: [{ confirmationStatus: "confirmed", err: { InstructionError: [1, "ComputationalBudgetExceeded"] } }] };
        return { value: [{ confirmationStatus: "confirmed", err: null }] };
      }
      throw new Error(`unexpected ${method}`);
    },
  };
  const backup = { call: async () => "x" };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const err = await send(primary, payer, [ix], [], { computeUnits: 200_000, rpcs: [backup] }).then(() => null, (e) => e);
  failedSig = err.signature;
  sent.length = 0;
  let told = 0;
  const sig = await sendWithFallback(primary, payer, [ix], [], { computeUnits: 200_000, rpcs: [backup], landedWaitMs: 50 }, () => told++);
  assert.equal(sig, "sig-bare");
  assert.deepEqual(sent, ["budget", "bare"], "the unbudgeted fallback ran");
  assert.equal(told, 1);
});

test("an unconfirmed transaction is sent again, the same bytes, until it lands", async () => {
  const sent = [];
  let polls = 0;
  const endpoint = (name) => ({
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method, params) => {
      if (method === "sendTransaction") {
        sent.push([name, params[0]]);
        return "sig";
      }
      if (method === "getSignatureStatuses") return { value: [++polls > 8 ? { confirmationStatus: "confirmed" } : null] };
      throw new Error(`unexpected ${method}`);
    },
  });
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  assert.equal(await send(endpoint("primary"), payer, [ix], [], { rpcs: [endpoint("backup")], pollMs: 5, rebroadcastMs: 10 }), "sig");
  await new Promise((r) => setTimeout(r, 5));
  assert.ok(sent.filter(([n]) => n === "primary").length >= 2, "rebroadcast to the primary");
  assert.ok(sent.filter(([n]) => n === "backup").length >= 2, "and to the backups");
  assert.equal(new Set(sent.map(([, tx]) => tx)).size, 1, "the same signed bytes");
});

test("a transaction whose blockhash expired unconfirmed is reported at once", async () => {
  const primary = {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 100 }),
    call: async (method) => {
      if (method === "sendTransaction") return "sig";
      if (method === "getSignatureStatuses") return { value: [null] };
      if (method === "getBlockHeight") return 151;
      throw new Error(`unexpected ${method}`);
    },
  };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  await assert.rejects(send(primary, payer, [ix], [], { pollMs: 5, rebroadcastMs: 10 }), /expired unconfirmed/);
});

test("a key file the group or others can read is refused; an owner-only one loads", async () => {
  const { mkdtempSync, chmodSync, statSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const path = `${mkdtempSync(`${tmpdir()}/bh-key-`)}/k.json`;
  const kp = Keypair.generate();
  kp.save(path);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(Keypair.load(path).address, kp.address);
  chmodSync(path, 0o644);
  assert.throws(() => Keypair.load(path), /open to group or others.*chmod 600/);
  // Saving again tightens an existing file, not only a new one.
  kp.save(path);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

// --- finding 82: the freeze's own sending loop ------------------------------

/** A node on which only the `landsAt`-th distinct signed transaction lands (rebroadcasts are not new). */
function congested({ landsAt = Infinity, failPollsFirst = 0 } = {}) {
  const log = { sends: 0, distinct: [] };
  const landed = new Set();
  let polls = 0;
  return {
    log,
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: null }),
    call: async (method, params) => {
      if (method === "sendTransaction") {
        log.sends++;
        if (!log.distinct.includes(params[0])) log.distinct.push(params[0]);
        const sig = `sig${log.distinct.indexOf(params[0])}`;
        if (log.distinct.indexOf(params[0]) + 1 >= landsAt) landed.add(sig);
        return sig;
      }
      if (method === "getSignatureStatuses") {
        if (polls++ < failPollsFirst) throw new Error("timeout");
        return { value: params[0].map((s) => (landed.has(s) ? { confirmationStatus: "confirmed" } : null)) };
      }
      throw new Error(`unexpected ${method}`);
    },
  };
}

test("a freeze is signed again at twice the price until it lands (finding 82)", async () => {
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const prices = [];
  const node = congested({ landsAt: 3 });
  const r = await sendEscalating(node, payer, [ix], { price: 0, floor: 100_000, cap: 1_000_000, attemptMs: 40, rebroadcastMs: 10, pollMs: 5, onAttempt: ({ nextPrice }) => prices.push(nextPrice) });
  assert.deepEqual([r.attempts, r.price, prices], [3, 400_000, [200_000, 400_000]], "from the floor (a quiet account shows 0), doubling");
  assert.equal(node.log.distinct.length, 3, "a fresh signature each attempt");
  assert.ok(node.log.sends > 3, "and rebroadcast within each");
  // Never above the cap; the deadline ends it.
  const capped = [];
  await assert.rejects(sendEscalating(congested(), payer, [ix], { floor: 100_000, cap: 300_000, attemptMs: 20, rebroadcastMs: 10, pollMs: 5, deadlineMs: 150, onAttempt: ({ nextPrice }) => capped.push(nextPrice) }), /not confirmed/);
  assert.equal(Math.max(...capped), 300_000);
  // An outcome reached meanwhile (another guardian froze) ends it too.
  const r2 = await sendEscalating(congested(), payer, [ix], { floor: 100_000, attemptMs: 20, rebroadcastMs: 10, pollMs: 5, settled: async () => true });
  assert.deepEqual([r2.signature, r2.attempts], [null, 1]);
});

test("one failed status poll does not abandon a transaction in flight (finding 82)", async () => {
  const node = congested({ landsAt: 1, failPollsFirst: 2 });
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  assert.ok(await send(node, payer, [ix], [], { pollMs: 5 }));
  assert.equal(node.log.distinct.length, 1, "no second transaction");
});

test("a blockhash a node lacks is not a refused budget; an instruction's own failure is not either (finding 82)", () => {
  const refused = (err) => Object.assign(new Error("x"), { rpcError: { code: PREFLIGHT_REFUSED, data: { err } } });
  assert.equal(refusalCause(refused("BlockhashNotFound")), "blockhash");
  assert.equal(refusalCause(refused({ InstructionError: [2, { Custom: 8006 }] })), "instructions");
  assert.equal(refusalCause(refused({ InstructionError: [2, "ComputationalBudgetExceeded"] })), "budget");
  assert.equal(refusalCause(refused({ InstructionError: [0, "InvalidInstructionData"] })), "budget");
  assert.equal(refusalCause(refused("ProgramAccountNotFound")), "budget", "finding 47's mistyped id");
});

test("a malformed key file's error never quotes its bytes (finding 82)", async () => {
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const p = `${mkdtempSync(`${tmpdir()}/k`)}/bad.json`;
  writeFileSync(p, "[4,176,210,99,", { mode: 0o600 });
  assert.throws(() => Keypair.load(p), (e) => !/176|210/.test(e.message) && /not a keypair file/.test(e.message));
});

test("a primary's preflight that finds the transaction already processed is a success, not a refusal (finding 82)", async () => {
  // The backup lands it first; the slower primary simulates it afterwards.
  let sends = 0;
  const primary = {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: null }),
    call: async (method, params) => {
      if (method === "sendTransaction") {
        sends++;
        throw Object.assign(new Error("sendTransaction: already processed"), { rpcError: { code: PREFLIGHT_REFUSED, data: { err: "AlreadyProcessed" } } });
      }
      if (method === "getSignatureStatuses") return { value: params[0].map(() => ({ confirmationStatus: "confirmed" })) };
      throw new Error(`unexpected ${method}`);
    },
  };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const sig = await sendWithFallback(primary, payer, [ix], [], { computeUnits: 50_000, microLamports: 10_000, pollMs: 5 });
  assert.ok(sig);
  assert.equal(sends, 1, "not sent again without its budget");
});

test("a send that fails at once is paced and not priced up; a refusal ends the loop; an earlier copy that lands is the answer (finding 84)", async () => {
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  // Every endpoint refuses at once (unhealthy): no doubling, no spin.
  let sends = 0;
  const down = {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: null }),
    call: async (method) => {
      if (method === "sendTransaction") { sends++; throw new Error("node unhealthy"); }
      return { value: [] };
    },
  };
  const prices = [];
  await assert.rejects(sendEscalating(down, payer, [ix], { floor: 100_000, retryPauseMs: 20, deadlineMs: 200, onAttempt: ({ nextPrice }) => prices.push(nextPrice) }), /unhealthy/);
  assert.ok(sends <= 15, `paced (${sends} sends in 200 ms)`);
  assert.ok(prices.every((p) => p === 100_000), "the price stays: no copy went out");
  // A simulation that says no price helps (no SOL) ends it at the next check.
  const t0 = Date.now();
  await assert.rejects(sendEscalating(congested(), payer, [ix], { floor: 100_000, attemptMs: 30, rebroadcastMs: 10, pollMs: 5, deadlineMs: 5_000, precheck: async () => new Error("cannot be paid for") }), /cannot be paid for/);
  assert.ok(Date.now() - t0 < 1_000);
  // The first copy lands late, during the second attempt's window: that
  // attempt returns it (it used to be noticed only after its own 6 s).
  const distinct = [];
  const late = {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: null }),
    call: async (method, params) => {
      if (method === "sendTransaction") {
        if (!distinct.includes(params[0])) distinct.push(params[0]);
        return `sig${distinct.indexOf(params[0])}`;
      }
      if (method === "getSignatureStatuses") return { value: params[0].map((x) => (x === "sig0" && distinct.length >= 2 ? { confirmationStatus: "confirmed" } : null)) };
      throw new Error(`unexpected ${method}`);
    },
  };
  const t1 = Date.now();
  const r = await sendEscalating(late, payer, [ix], { floor: 100_000, attemptMs: 200, rebroadcastMs: 10, pollMs: 5 });
  assert.deepEqual([r.signature, r.attempts], ["sig0", 2], "the earlier copy, from within the second attempt");
  assert.ok(Date.now() - t1 < 380, "before the second attempt's window ran out");
});

test("a blockhash refusal after a backup landed the first copy is that copy, not a second (finding 84)", async () => {
  let distinct = new Set();
  const primary = {
    latestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: null }),
    call: async (method, params) => {
      if (method === "sendTransaction") {
        distinct.add(params[0]);
        throw Object.assign(new Error("sendTransaction: blockhash"), { rpcError: { code: PREFLIGHT_REFUSED, data: { err: "BlockhashNotFound" } } });
      }
      if (method === "getSignatureStatuses") return { value: params[0].map(() => ({ confirmationStatus: "confirmed" })) };
      throw new Error(`unexpected ${method}`);
    },
  };
  const backup = { call: async () => "ok" };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  const sig = await sendWithFallback(primary, payer, [ix], [], { computeUnits: 50_000, microLamports: 10_000, rpcs: [backup], landedWaitMs: 50 });
  assert.ok(sig);
  assert.equal(distinct.size, 1, "not signed again");
});
