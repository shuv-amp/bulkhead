import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLogs, parseEvents, decodeTicket, concat, key, u64le, i64le, b58encode } from "../lib/solana.mjs";
import { vaultOutflows, ticketRelease } from "../guardian/chain.mjs";
import { assess, decode, newState } from "../guardian/policy.mjs";

const VAULT = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
const HARBOR = "6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh";
const OTHER = "Stranger11111111111111111111111111111111111";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const data = (name, ...fields) => `Program data: ${[b64(Buffer.from(name)), ...fields.map(b64)].join(" ")}`;
const frozen = data("vault:frozen", Uint8Array.of(0), key(OTHER), i64le(9_999_999_999));

test("an event belongs to the innermost program running when it was written", () => {
  const logs = [
    `Program ${HARBOR} invoke [1]`,
    `Program ${VAULT} invoke [2]`,
    `Program ${TOKEN} invoke [3]`,
    `Program ${TOKEN} success`,
    data("vault:released"),
    `Program ${VAULT} consumed 9893 of 1396136 compute units`,
    `Program ${VAULT} success`,
    data("harbor:after"),
    `Program ${HARBOR} success`,
  ];
  const { events, truncated } = parseLogs(logs);
  assert.deepEqual(events.map((e) => [e.program, e.name]), [[VAULT, "vault:released"], [HARBOR, "harbor:after"]]);
  assert.equal(truncated, false);
});

test("a vault-named line written by another program is not a Vault event", () => {
  const logs = [`Program ${OTHER} invoke [1]`, frozen, `Program ${OTHER} success`];
  assert.equal(parseEvents(logs).length, 1);
  assert.deepEqual(parseEvents(logs, [VAULT]), []);
  // Nor is one written between invocations, or after the Vault returned.
  const after = [`Program ${VAULT} invoke [1]`, `Program ${VAULT} success`, frozen];
  assert.deepEqual(parseEvents(after, [VAULT]), []);
});

test("a failed inner call closes its frame, and a truncated log is flagged", () => {
  const logs = [
    `Program ${VAULT} invoke [1]`,
    `Program ${OTHER} invoke [2]`,
    `Program ${OTHER} failed: custom program error: 0x1`,
    data("vault:released"),
    "Log truncated",
  ];
  const { events, truncated } = parseLogs(logs);
  assert.deepEqual(events.map((e) => e.program), [VAULT]);
  assert.equal(truncated, true);
});

test("lines that aren't base64 are nobody's event", () => {
  const { events } = parseLogs([`Program ${VAULT} invoke [1]`, "Program data: !!not-base64!!", `Program ${VAULT} success`]);
  assert.deepEqual(events, []);
});

test("a ticket account decodes to its vault, owner, amount and times", () => {
  const d = concat(
    Buffer.from("BHTICKT1"),
    key(VAULT), key(HARBOR), key(OTHER), key(TOKEN), key(VAULT),
    u64le(7), u64le(123_456), i64le(1_000), i64le(22_600), i64le(0), Uint8Array.of(254), new Uint8Array(7),
  );
  const t = decodeTicket(d);
  assert.equal(t.vault, b58encode(key(HARBOR)));
  assert.equal(t.recipientOwner, b58encode(key(TOKEN)));
  assert.deepEqual([t.id, t.amount, t.createdS, t.etaS], [7n, 123_456n, 1_000, 22_600]);
  assert.throws(() => decodeTicket(concat(Buffer.from("BHCHNG01"), d.slice(8))));
});

test("a truncated transaction's outflow comes from the vault's own token balances", () => {
  const vaultTokens = "VauLtTokens11111111111111111111111111111111";
  const tx = {
    transaction: { message: { accountKeys: [OTHER, vaultTokens, HARBOR] } },
    meta: {
      preTokenBalances: [{ accountIndex: 1, uiTokenAmount: { amount: "10000000000000" } }, { accountIndex: 2, uiTokenAmount: { amount: "5" } }],
      postTokenBalances: [{ accountIndex: 1, uiTokenAmount: { amount: "9800000000000" } }, { accountIndex: 2, uiTokenAmount: { amount: "200000000005" } }],
    },
  };
  assert.deepEqual([...vaultOutflows(tx, new Map([[vaultTokens, "USDC"]]))], [["USDC", 200_000_000_000n]]);
  // A deposit (the balance went up) is not an outflow.
  const inflow = { ...tx, meta: { preTokenBalances: tx.meta.postTokenBalances, postTokenBalances: tx.meta.preTokenBalances } };
  assert.equal(vaultOutflows(inflow, new Map([[vaultTokens, "USDC"]])).size, 0);
});

test("a ticket read from the chain counts once, even when its event arrives too", () => {
  const vault = "VauLt111111111111111111111111111111111111111";
  const ticket = { vault, recipientOwner: OTHER, id: 3n, amount: 50n, etaS: 99 };
  assert.equal(ticketRelease(ticket, new Map()), null, "an unwatched vault");
  const fromChain = ticketRelease(ticket, new Map([[vault, "USDC"]]));
  const s = newState();
  const ctx = { worst1h: 1_000_000n, worst24h: 2_500_000n, now: 10 };
  assess(s, fromChain, ctx);
  const outcome = concat(u64le(0), u64le(7), u64le(50), u64le(3), i64le(99));
  const event = decode({ name: "vault:released", fields: [key(TOKEN), key(OTHER), outcome] });
  assess(s, { ...event, mint: "USDC" }, { ...ctx, now: 11 });
  const amounts = s.outflows.map((o) => [o.amount, o.ticketId]);
  assert.deepEqual(amounts, [[50n, 3n], [7n, null]], "the event adds only its instant part");
});
