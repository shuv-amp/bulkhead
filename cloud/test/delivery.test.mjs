import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, send, computeBudget, priorityPrice, COMPUTE_BUDGET } from "../lib/signer.mjs";
import { b58encode } from "../lib/solana.mjs";

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
