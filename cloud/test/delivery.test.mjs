import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, send, sendWithFallback, computeBudget, priorityPrice, COMPUTE_BUDGET, PREFLIGHT_REFUSED } from "../lib/signer.mjs";
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
