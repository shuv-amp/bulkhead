// Facts the guardian takes from the chain instead of from log text. Pure
// functions over RPC results, so every rule is unit-tested (cloud/test).

import { b58decode, b58encode, decodeTicket, key } from "../lib/solana.mjs";

/** Vault `settle_ticket`. A settlement moves tokens already counted when queued. */
const SETTLE_TICKET = 9;

/** All account keys of a `getTransaction` result, in index order (v0 lookups included). */
export function accountKeys(tx) {
  const keys = (tx?.transaction?.message?.accountKeys ?? []).map((k) => (typeof k === "string" ? k : k.pubkey));
  const loaded = tx?.meta?.loadedAddresses;
  return [...keys, ...(loaded?.writable ?? []), ...(loaded?.readonly ?? [])];
}

/**
 * How much each watched vault token account lost in one transaction, from the
 * runtime's own pre/post token balances, keyed by mint. Used when a log was
 * truncated: the events may be gone, the balances are not. Counts every
 * decrease as unbacked (a backed withdrawal in a truncated log is counted too,
 * which errs toward freezing).
 */
export function vaultOutflows(tx, tokenMints) {
  const keys = accountKeys(tx);
  const read = (list) => new Map((list ?? []).map((b) => [keys[b.accountIndex], BigInt(b.uiTokenAmount.amount)]));
  const pre = read(tx?.meta?.preTokenBalances);
  const post = read(tx?.meta?.postTokenBalances);
  const out = new Map();
  for (const [address, mint] of tokenMints) {
    const before = pre.get(address);
    const after = post.get(address);
    if (before === undefined || after === undefined || after >= before) continue;
    out.set(mint, (out.get(mint) ?? 0n) + (before - after));
  }
  return out;
}

function instructionData(data) {
  if (typeof data === "string") return b58decode(data);
  return data ?? new Uint8Array();
}

function compiledAccounts(ix, keys) {
  if (!Array.isArray(ix.accounts)) return [];
  if (typeof ix.accounts[0] === "number") return ix.accounts.map((i) => keys[i]);
  return ix.accounts;
}

/**
 * Ticket accounts this transaction settles. The instruction list is still
 * complete when the log is truncated, so a settlement can be told apart from
 * a new release. Account 4 of `settle_ticket` is the ticket.
 */
export function settledTicketAccounts(tx, vaultProgram) {
  const keys = accountKeys(tx);
  const outer = tx?.transaction?.message?.instructions ?? [];
  const inner = (tx?.meta?.innerInstructions ?? []).flatMap((g) => g.instructions ?? []);
  const out = new Set();
  for (const ix of [...outer, ...inner]) {
    const program = typeof ix.programIdIndex === "number" ? keys[ix.programIdIndex] : ix.programId;
    if (program !== vaultProgram) continue;
    if (instructionData(ix.data)[0] !== SETTLE_TICKET) continue;
    const ticket = compiledAccounts(ix, keys)[4];
    if (ticket) out.add(ticket);
  }
  return out;
}

/**
 * Queued amounts to credit when a truncated transaction settles those tickets.
 * The rolling window forgets a ticket after a day; the ticket is still the
 * same money leaving, so a pending ticket's amount counts too.
 */
export function settlementRows(outflows, pending, mint) {
  const byTicket = new Map();
  for (const o of outflows) {
    if (o.mint !== mint || o.ticketId == null) continue;
    byTicket.set(o.ticketId, o.amount);
  }
  for (const t of pending.values()) {
    if (t.mint !== mint || t.amount == null) continue;
    byTicket.set(t.ticketId, t.amount);
  }
  return [...byTicket].map(([ticketId, amount]) => ({ ticketId, amount }));
}

/** Mints whose watched vault token account has both a pre and a post balance. */
export function vaultBalancesSeen(tx, tokenMints) {
  const keys = accountKeys(tx);
  const present = (list) => new Set((list ?? []).map((b) => keys[b.accountIndex]));
  const pre = present(tx?.meta?.preTokenBalances);
  const post = present(tx?.meta?.postTokenBalances);
  const seen = new Set();
  for (const [address, mint] of tokenMints) {
    if (pre.has(address) && post.has(address)) seen.add(mint);
  }
  return seen;
}

/**
 * Token accounts, other than the watched vault accounts, that gained `mint`.
 * `owner` is the wallet on the balance entry. A truncated log still has this.
 */
export function tokenIncreases(tx, skip) {
  const keys = accountKeys(tx);
  const read = (list) => new Map((list ?? []).map((b) => [keys[b.accountIndex], b]));
  const pre = read(tx?.meta?.preTokenBalances);
  const post = read(tx?.meta?.postTokenBalances);
  const out = [];
  for (const [address, after] of post) {
    if (skip.has(address) || !after?.uiTokenAmount) continue;
    const before = pre.get(address);
    if (!before?.uiTokenAmount || before.mint !== after.mint) continue;
    const gained = BigInt(after.uiTokenAmount.amount) - BigInt(before.uiTokenAmount.amount);
    if (gained <= 0n) continue;
    out.push({ mint: after.mint, owner: after.owner, amount: gained });
  }
  return out;
}

/** Drop the part of a truncated outflow that landed with an allowlisted owner. */
export function countedAfterAllowlist(drop, increases, allowlist) {
  let credit = 0n;
  for (const row of increases) {
    if (row.owner && allowlist.includes(row.owner)) credit += row.amount;
  }
  if (credit > drop) credit = drop;
  return drop - credit;
}

/**
 * How much of a truncated balance drop was not already counted. `windowed`
 * is `{ ticket, amount }` for queued outflows of this mint, including tickets
 * that have aged out of the freeze window; settling one of them is the same
 * money leaving, not a new release.
 */
export function freshVaultOutflow(drop, settling, windowed) {
  let already = 0n;
  for (const row of windowed) {
    if (row.ticket && settling.has(row.ticket)) already += row.amount;
  }
  return already >= drop ? 0n : drop - already;
}

/**
 * A release record for a ticket read from its account, for tickets whose
 * event the guardian never saw. `null` for a vault this guardian doesn't watch.
 */
export function ticketRelease(ticket, vaultMints) {
  const mint = vaultMints.get(ticket.vault);
  if (!mint) return null;
  return {
    kind: "released",
    mint,
    vault: ticket.vault,
    owner: ticket.recipientOwner,
    backed: 0n,
    instant: 0n,
    queued: ticket.amount,
    ticketId: ticket.id,
    etaS: ticket.etaS,
  };
}

/** All live tickets for one protocol, filtered by their account discriminator and protocol key. */
export async function activeTickets(rpc, vaultProgram, protocol) {
  const protocolKey = b58encode(key(protocol));
  const discriminator = b58encode(new TextEncoder().encode("BHTICKT1"));
  const accounts = await rpc.call("getProgramAccounts", [b58encode(key(vaultProgram)), {
    encoding: "base64",
    commitment: "confirmed",
    filters: [
      { memcmp: { offset: 0, bytes: discriminator } },
      { memcmp: { offset: 8, bytes: protocolKey } },
    ],
  }]);
  if (!Array.isArray(accounts)) throw new Error("getProgramAccounts returned no ticket account list");
  return accounts.map(({ pubkey, account }) => {
    const encoded = account?.data?.[0];
    if (typeof encoded !== "string") throw new Error(`ticket account ${pubkey} has no base64 data`);
    const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    const ticket = decodeTicket(bytes);
    if (ticket.protocol !== protocolKey) throw new Error(`ticket account ${pubkey} belongs to another protocol`);
    return { ...ticket, address: pubkey };
  });
}
