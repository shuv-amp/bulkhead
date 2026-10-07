import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLogs, parseEvents, decodeTicket, concat, key, u64le, i64le, b58encode } from "../lib/solana.mjs";
import { activeTickets, freshVaultOutflow, settledTicketAccounts, vaultOutflows, ticketRelease, settlementRows, tokenIncreases, countedAfterAllowlist, truncatedOutflows, unexplainedOutflow, vaultTransfersOut } from "../guardian/chain.mjs";
import { assess, decode, newState, observeProtocolFreeze, pendingCancels, rememberTicket, watchedEvents } from "../guardian/policy.mjs";

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
  assert.deepEqual([...settling.keys()], [ticket]);
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

test("a truncated settlement of a ticket that aged out of the window is not a new outflow", () => {
  const pending = new Map([[7n, { ticketId: 7n, mint: "USDC", amount: 400n }]]);
  const rows = settlementRows([], pending, "USDC");
  assert.deepEqual(rows, [{ ticketId: 7n, amount: 400n }]);
  assert.equal(freshVaultOutflow(400n, new Set(["ticket"]), [{ ticket: "ticket", amount: rows[0].amount }]), 0n);
  // A ticket still in the window and the same pending ticket are one credit, not two.
  const once = settlementRows([{ mint: "USDC", ticketId: 7n, amount: 400n }], pending, "USDC");
  assert.deepEqual(once, [{ ticketId: 7n, amount: 400n }]);
});

test("a truncated payout to an allowlisted owner is not an outflow", () => {
  const vaultTokens = "VauLtTokens11111111111111111111111111111111";
  const recipient = "Recip111111111111111111111111111111111111111";
  const tx = {
    transaction: { message: { accountKeys: [vaultTokens, recipient] } },
    meta: {
      preTokenBalances: [
        { accountIndex: 0, mint: "USDC", owner: "vault", uiTokenAmount: { amount: "1000" } },
        { accountIndex: 1, mint: "USDC", owner: "mm", uiTokenAmount: { amount: "0" } },
      ],
      postTokenBalances: [
        { accountIndex: 0, mint: "USDC", owner: "vault", uiTokenAmount: { amount: "600" } },
        { accountIndex: 1, mint: "USDC", owner: "mm", uiTokenAmount: { amount: "400" } },
      ],
    },
  };
  const increases = tokenIncreases(tx, new Set([vaultTokens])).filter((r) => r.mint === "USDC");
  assert.equal(countedAfterAllowlist(400n, increases, ["mm"]), 0n);
  assert.equal(countedAfterAllowlist(400n, increases, []), 400n);
  // The recipient account was created in this transaction, so it has no pre balance.
  const created = {
    transaction: { message: { accountKeys: [vaultTokens, recipient] } },
    meta: {
      preTokenBalances: [
        { accountIndex: 0, mint: "USDC", owner: "vault", uiTokenAmount: { amount: "1000" } },
      ],
      postTokenBalances: [
        { accountIndex: 0, mint: "USDC", owner: "vault", uiTokenAmount: { amount: "600" } },
        { accountIndex: 1, mint: "USDC", owner: "mm", uiTokenAmount: { amount: "400" } },
      ],
    },
  };
  const fresh = tokenIncreases(created, new Set([vaultTokens])).filter((r) => r.mint === "USDC");
  assert.equal(countedAfterAllowlist(400n, fresh, ["mm"]), 0n);
});

// A truncated transaction as getTransaction returns it: `keys` in index order,
// the vault's CPIs as inner instructions, token balances with their owners.
const VAULT_PROGRAM = "Va1t111111111111111111111111111111111111111";
const VAULT_TOKENS = "VauLtTokens11111111111111111111111111111111";
const VAULT_PDA = "VauLtPda1111111111111111111111111111111111";
function truncatedTx({ keys, outer = [], inner = [], balances }) {
  const at = (k) => keys.indexOf(k);
  const ix = (program, accounts, bytes) => ({ programIdIndex: at(program), accounts: accounts.map(at), data: b58encode(bytes) });
  const transfer = (to, amount) => ix(TOKEN, [VAULT_TOKENS, "Mint11111111111111111111111111111111111111", to, VAULT_PDA], concat(Uint8Array.of(12), u64le(amount), Uint8Array.of(6)));
  const entry = (k, [owner, amount]) => ({ accountIndex: at(k), mint: "USDC", owner, uiTokenAmount: { amount: String(amount) } });
  return {
    transaction: { message: { accountKeys: keys, instructions: outer.map((o) => ix(...o)) } },
    meta: {
      preTokenBalances: Object.entries(balances).filter(([, v]) => v[1] !== null).map(([k, v]) => entry(k, [v[0], v[1]])),
      postTokenBalances: Object.entries(balances).map(([k, v]) => entry(k, [v[0], v[2]])),
      innerInstructions: inner === null ? null : [{ index: 0, instructions: inner.map(([to, amount]) => transfer(to, amount)) }],
    },
  };
}
const MINTS = new Map([[VAULT_TOKENS, "USDC"]]);
const VAULT_OF = new Map([["USDC", VAULT_PDA]]);
const KEYS = [VAULT_PROGRAM, TOKEN, VAULT_TOKENS, "Mint11111111111111111111111111111111111111", VAULT_PDA, "Tick111111111111111111111111111111111111111", "Treasury1111111111111111111111111111111111", "Attacker1111111111111111111111111111111111", "Lifeboat1111111111111111111111111111111111"];
const [, , , , , TICKET, TREASURY_TOKENS, ATTACKER_TOKENS, LIFEBOAT] = KEYS;
const settleIx = [VAULT_PROGRAM, [VAULT_PROGRAM, VAULT_PDA, VAULT_TOKENS, KEYS[3], TICKET, TREASURY_TOKENS, VAULT_PROGRAM, TOKEN], Uint8Array.of(9)];

test("a settled allowlisted ticket is not also an allowlist credit, so a hidden release still counts", () => {
  // One truncated transaction settles the treasury's queued ticket (100) and
  // pays 100 instantly to an attacker.
  const tx = truncatedTx({
    keys: KEYS,
    outer: [settleIx],
    inner: [[TREASURY_TOKENS, 100n], [ATTACKER_TOKENS, 100n]],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 800], [TREASURY_TOKENS]: ["treasury", 0, 100], [ATTACKER_TOKENS]: ["attacker", 0, 100] },
  });
  const known = [{ mint: "USDC", ticketId: 7n, ticket: TICKET, amount: 100n }];
  const seen = truncatedOutflows(tx, { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known, allowlist: ["treasury"] });
  assert.equal(seen.outflows.get("USDC"), 100n);
  assert.deepEqual(seen.closed, [7n]);
  // Without the settlement, an allowlisted payout is still not an outflow.
  const payout = truncatedTx({
    keys: KEYS,
    inner: [[TREASURY_TOKENS, 100n]],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 900], [TREASURY_TOKENS]: ["treasury", 0, 100] },
  });
  assert.equal(truncatedOutflows(payout, { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known: [], allowlist: ["treasury"] }).outflows.size, 0);
});

test("tokens sent to an allowlisted owner from elsewhere earn no credit", () => {
  // The attacker drains 100 and, in the same transaction, sends 100 of its own
  // tokens to the treasury. Only the vault's own transfers are credited.
  const tx = truncatedTx({
    keys: KEYS,
    inner: [[ATTACKER_TOKENS, 100n]],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 900], [TREASURY_TOKENS]: ["treasury", 0, 100], [ATTACKER_TOKENS]: ["attacker", 50, 50] },
  });
  assert.equal(truncatedOutflows(tx, { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known: [], allowlist: ["treasury"] }).outflows.get("USDC"), 100n);
});

test("a deposit in the same transaction does not hide a truncated release", () => {
  // 500 deposited, 500 released: the balance is unchanged, the transfer is not.
  const tx = truncatedTx({
    keys: KEYS,
    inner: [[ATTACKER_TOKENS, 500n]],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 1_000], [ATTACKER_TOKENS]: ["attacker", 0, 500] },
  });
  assert.equal(vaultOutflows(tx, MINTS).size, 0);
  assert.equal(truncatedOutflows(tx, { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known: [], allowlist: [] }).outflows.get("USDC"), 500n);
});

test("a lifeboat move is not an outflow; a payout the parser cannot see still is", () => {
  const move = truncatedTx({
    keys: KEYS,
    inner: [[LIFEBOAT, 300n]],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 700], [LIFEBOAT]: [VAULT_PDA, 0, 300] },
  });
  const args = { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known: [], allowlist: [] };
  assert.equal(truncatedOutflows(move, args).outflows.size, 0);
  // An account another vault owns is not this vault's lifeboat.
  assert.equal(truncatedOutflows(move, { ...args, vaultOf: new Map([["USDC", "SomeOtherVault"]]) }).outflows.get("USDC"), 300n);
  // A balance drop larger than the transfers read still counts in full.
  const unseen = truncatedTx({
    keys: KEYS,
    inner: [],
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 600] },
  });
  assert.deepEqual(vaultTransfersOut(unseen, MINTS), []);
  assert.equal(truncatedOutflows(unseen, args).outflows.get("USDC"), 400n);
});

test("without inner instructions the balances decide, and a settlement payee is never an allowlist credit", () => {
  const tx = truncatedTx({
    keys: KEYS,
    outer: [settleIx],
    inner: null,
    balances: { [VAULT_TOKENS]: [VAULT_PDA, 1_000, 800], [TREASURY_TOKENS]: ["treasury", 0, 100], [ATTACKER_TOKENS]: ["attacker", 0, 100] },
  });
  assert.equal(vaultTransfersOut(tx, MINTS), null);
  const known = [{ mint: "USDC", ticketId: 7n, ticket: TICKET, amount: 100n }];
  const seen = truncatedOutflows(tx, { vaultProgram: VAULT_PROGRAM, tokenMints: MINTS, vaultOf: VAULT_OF, known, allowlist: ["treasury"] });
  assert.equal(seen.outflows.get("USDC"), 100n);
  assert.deepEqual(seen.closed, [7n]);
});

test("a surviving release event explains its part of a truncated figure", () => {
  const outflows = new Map([["USDC", 500n]]);
  // Counted on its own, under its owner: backed and instant both left the vault.
  const left = unexplainedOutflow(outflows, [{ mint: "USDC", owner: "attacker", backed: 100n, instant: 200n }], []);
  assert.equal(left.get("USDC"), 200n);
  // An allowlisted payout was never in the figure.
  assert.equal(unexplainedOutflow(outflows, [{ mint: "USDC", owner: "mm", backed: 0n, instant: 200n }], ["mm"]).get("USDC"), 500n);
  // More surviving than the figure (a same-transaction deposit, balances only): nothing left over.
  assert.equal(unexplainedOutflow(outflows, [{ mint: "USDC", owner: "attacker", backed: 0n, instant: 900n }], []).get("USDC"), 0n);
  assert.equal(unexplainedOutflow(outflows, [{ mint: "SOL", owner: "attacker", backed: 0n, instant: 900n }], []).get("USDC"), 500n);
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
  const event = decode({ name: "vault:released", fields: [key(TOKEN), key(OTHER), outcome, new Uint8Array(32), key(VAULT)] });
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

// Finding 64: one Vault program serves every protocol. Anyone can register a
// protocol B and send a transaction that lists protocol A's account: it is in
// A's signature history, and B's events are in its log.
const PROTO_A = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const PROTO_B = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";
const at = (protocol) => key(protocol);
const outcomeOf = (instant) => concat(u64le(0), u64le(instant), u64le(0), u64le(0), i64le(0));
const inVault = (...lines) => [`Program ${VAULT} invoke [1]`, ...lines, `Program ${VAULT} success`];

test("another protocol's unfreeze, release, proposal and ticket events are not this protocol's", () => {
  const logs = inVault(
    data("vault:unfrozen", Uint8Array.of(0), Uint8Array.of(3), at(PROTO_B)),
    data("vault:released", key(TOKEN), key(OTHER), outcomeOf(500), new Uint8Array(32), at(PROTO_B)),
    data("vault:change_proposed", u64le(9), Uint8Array.of(3), key(OTHER), i64le(0), at(PROTO_B)),
    data("vault:exit_proposed", key(TOKEN), u64le(5), i64le(0), at(PROTO_B)),
    data("vault:settled", u64le(7), u64le(50), at(PROTO_B)),
    data("vault:ticket_cancelled", u64le(7), key(OTHER), at(PROTO_B)),
    data("vault:released", key(TOKEN), key(OTHER), outcomeOf(100), new Uint8Array(32), at(PROTO_A)),
  );
  const seen = watchedEvents(logs, { vaultProgram: VAULT, protocol: PROTO_A });
  assert.deepEqual(seen.events.map((e) => [e.kind, e.protocol]), [["released", PROTO_A]]);
  assert.equal(seen.foreign, 6);
  // Read the old way, B's events acted on A: the incident hold ends, A's
  // approved change id is vetoed, its ticket leaves the cancel list.
  const s = newState();
  s.incidentSince = 100;
  s.frozenUntil = 9_999;
  rememberTicket(s, { ticketId: 7n, mint: "USDC", owner: OTHER });
  for (const e of seen.events) assess(s, { ...e, mint: "USDC" }, { worst1h: 1_000_000n, worst24h: 2_000_000n, now: 200 });
  assert.equal(s.incidentSince, 100, "the hold stands");
  assert.equal(s.frozenUntil, 9_999);
  assert.equal(s.vetoed.size, 0, "no veto for B's proposal");
  assert.ok(s.pendingTickets.has(7n), "A's ticket 7 is still cancellable");
});

test("an event that names no protocol (an older Vault) is dropped and counted, never guessed", () => {
  const logs = inVault(data("vault:unfrozen", Uint8Array.of(0), Uint8Array.of(3)), data("vault:released", key(TOKEN), key(OTHER), outcomeOf(1), at(PROTO_A)));
  const seen = watchedEvents(logs, { vaultProgram: VAULT, protocol: PROTO_A });
  assert.deepEqual(seen.events, []);
  assert.equal(seen.unnamed, 2);
});

test("a truncated outflow is explained only by this protocol's surviving releases", () => {
  // A's vault lost 500 in a truncated transaction. B's release of 500, in
  // the same log, used to explain it away.
  const logs = inVault(data("vault:released", key(TOKEN), key(OTHER), outcomeOf(500), new Uint8Array(32), at(PROTO_B)), "Log truncated");
  const seen = watchedEvents(logs, { vaultProgram: VAULT, protocol: PROTO_A });
  assert.equal(seen.truncated, true);
  const released = seen.events.filter((e) => e.kind === "released").map((e) => ({ ...e, mint: "USDC" }));
  assert.equal(unexplainedOutflow(new Map([["USDC", 500n]]), released, []).get("USDC"), 500n);
  // This protocol's own surviving release still explains its part.
  const own = watchedEvents(inVault(data("vault:released", key(TOKEN), key(OTHER), outcomeOf(200), new Uint8Array(32), at(PROTO_A)), "Log truncated"), { vaultProgram: VAULT, protocol: PROTO_A });
  assert.equal(unexplainedOutflow(new Map([["USDC", 500n]]), own.events.map((e) => ({ ...e, mint: "USDC" })), []).get("USDC"), 300n);
});

test("Floor events count only from Floor, for a watched program", () => {
  const FLOOR = "F1oor11111111111111111111111111111111111111";
  const replaced = (prog) => data("floor:recovery_replaced", key(prog), new Uint8Array(32), Uint8Array.of(3));
  const logs = [`Program ${FLOOR} invoke [1]`, replaced(HARBOR), replaced(OTHER), `Program ${FLOOR} success`, `Program ${VAULT} invoke [1]`, replaced(HARBOR), `Program ${VAULT} success`];
  const seen = watchedEvents(logs, { floorProgram: FLOOR, floorPrograms: [HARBOR] });
  assert.deepEqual(seen.events.map((e) => [e.program, e.recovery]), [[HARBOR, null]]);
  // The protocol path reads no Floor events at all.
  assert.deepEqual(watchedEvents(logs, { vaultProgram: VAULT, protocol: PROTO_A }).events, []);
});

test("a transaction with no log at all is read as truncated, so its balances are checked", () => {
  assert.deepEqual(parseLogs(null), { events: [], truncated: true });
  assert.deepEqual(parseLogs(undefined), { events: [], truncated: true });
  assert.equal(parseLogs([]).truncated, false);
});

test("tickets stay cancellable after their outflow ages out of the 24-hour window", () => {
  const state = newState();
  rememberTicket(state, { ticketId: 7n, mint: "USDC", vault: HARBOR, owner: OTHER });
  const ctx = { worst1h: 1_000_000n, worst24h: 2_500_000n, now: 90_000 };
  assess(state, { kind: "released", mint: "USDC", owner: OTHER, backed: 0n, instant: 1n, queued: 0n, ticketId: 0n, etaS: 0 }, ctx);
  assert.equal(state.outflows.length, 1, "the rolling window discarded the old outflow");
  assert.deepEqual(pendingCancels(state).map((a) => [a.ticketId, a.vault]), [[7n, HARBOR]]);
});
