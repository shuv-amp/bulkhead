import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLogs, parseEvents, decodeTicket, concat, key, u64le, i64le, b58encode } from "../lib/solana.mjs";
import { activeTickets, freshVaultOutflow, settledTicketAccounts, vaultOutflows, ticketRelease } from "../guardian/chain.mjs";
import { assess, decode, newState, observeProtocolFreeze, pendingCancels, rememberTicket } from "../guardian/policy.mjs";

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

test("a truncated settlement is not a second outflow for a ticket already in the window", () => {
  const vaultProgram = "Va1t111111111111111111111111111111111111111";
  const ticket = "Tick111111111111111111111111111111111111111";
  const vaultTokens = "VauLtTokens11111111111111111111111111111111";
  const settle = {
    transaction: {
      message: {
        accountKeys: [vaultProgram, ticket, vaultTokens],
        instructions: [{ programIdIndex: 0, accounts: [0, 0, 2, 0, 1], data: b58encode(Uint8Array.of(9)) }],
      },
    },
    meta: {
      preTokenBalances: [{ accountIndex: 2, uiTokenAmount: { amount: "1000" } }],
      postTokenBalances: [{ accountIndex: 2, uiTokenAmount: { amount: "600" } }],
      innerInstructions: [{
        index: 0,
        instructions: [{ programIdIndex: 0, accounts: [0, 0, 2, 0, 1], data: b58encode(Uint8Array.of(8)) }],
      }],
    },
  };
  const settling = settledTicketAccounts(settle, vaultProgram);
  assert.deepEqual([...settling], [ticket]);
  const drop = vaultOutflows(settle, new Map([[vaultTokens, "USDC"]])).get("USDC");
  assert.equal(freshVaultOutflow(drop, settling, [{ ticket, amount: 400n }]), 0n);
  assert.equal(freshVaultOutflow(drop, settling, [{ ticket, amount: 400n }, { ticket: "other", amount: 50n }]), 0n);
  // The same drop with an extra 100 that is not a known settlement still counts.
  const mixed = structuredClone(settle);
  mixed.meta.postTokenBalances[0].uiTokenAmount.amount = "500";
  const mixedDrop = vaultOutflows(mixed, new Map([[vaultTokens, "USDC"]])).get("USDC");
  assert.equal(freshVaultOutflow(mixedDrop, settling, [{ ticket, amount: 400n }]), 100n);
  // A release (tag 8), even as an inner instruction, is not a settlement.
  const releaseOnly = structuredClone(settle);
  releaseOnly.transaction.message.instructions[0].data = b58encode(Uint8Array.of(8));
  assert.equal(settledTicketAccounts(releaseOnly, vaultProgram).size, 0);
  assert.equal(freshVaultOutflow(drop, settledTicketAccounts(releaseOnly, vaultProgram), [{ ticket, amount: 400n }]), drop);
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

test("a recent chain-only ticket contributes its queued amount before cancellation tracking", () => {
  const vault = "VauLt111111111111111111111111111111111111111";
  const ticket = { vault, recipientOwner: OTHER, id: 12n, amount: 50n, createdS: 100, etaS: 700 };
  const fromChain = ticketRelease(ticket, new Map([[vault, "USDC"]]));
  const state = newState();
  const ctx = { worst1h: 1_000_000n, worst24h: 2_500_000n, now: 100 };
  assess(state, fromChain, ctx, undefined, false);
  rememberTicket(state, ticket);
  assess(state, fromChain, { ...ctx, now: 101 }, undefined, false);
  assert.deepEqual(state.outflows.map((o) => [o.amount, o.ticketId]), [[50n, 12n]]);
});

test("active ticket scan returns every protocol ticket, including old ids beyond 256", async () => {
  const protocol = key(VAULT);
  const accounts = Array.from({ length: 300 }, (_, i) => {
    const bytes = concat(
      Buffer.from("BHTICKT1"), protocol, key(HARBOR), key(OTHER), key(TOKEN), key(VAULT),
      u64le(BigInt(i + 1)), u64le(50n), i64le(1_000), i64le(700_000), i64le(0), Uint8Array.of(254), new Uint8Array(7),
    );
    return { pubkey: `ticket-${i + 1}`, account: { data: [Buffer.from(bytes).toString("base64"), "base64"] } };
  });
  let request;
  const rpc = { call: async (...args) => { request = args; return accounts; } };
  const tickets = await activeTickets(rpc, VAULT, protocol);
  assert.equal(request[0], "getProgramAccounts");
  assert.equal(request[1][1].filters[0].memcmp.offset, 0);
  assert.equal(request[1][1].filters[1].memcmp.offset, 8);
  assert.equal(tickets.length, 300);
  assert.deepEqual([tickets[0].id, tickets.at(-1).id], [1n, 300n]);
  assert.equal(tickets[0].createdS, 1_000, "old outstanding accounts are not filtered by age");
  const state = newState();
  for (const ticket of tickets) rememberTicket(state, ticket);
  const cancels = observeProtocolFreeze(state, 100_000, 90_000);
  assert.equal(cancels.length, 300, "an observed freeze sweeps ids beyond the former 256-ticket window");
  assert.equal(cancels.at(-1).ticketId, 300n);
});

test("tickets stay cancellable after their outflow ages out of the 24-hour window", () => {
  const state = newState();
  rememberTicket(state, { ticketId: 7n, mint: "USDC", vault: HARBOR, owner: OTHER });
  const ctx = { worst1h: 1_000_000n, worst24h: 2_500_000n, now: 90_000 };
  assess(state, { kind: "released", mint: "USDC", owner: OTHER, backed: 0n, instant: 1n, queued: 0n, ticketId: 0n, etaS: 0 }, ctx);
  assert.equal(state.outflows.length, 1, "the rolling window discarded the old outflow");
  assert.deepEqual(pendingCancels(state).map((a) => [a.ticketId, a.vault]), [[7n, HARBOR]]);
});
