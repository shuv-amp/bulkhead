// Facts the guardian takes from the chain instead of from log text. Pure
// functions over RPC results, so every rule is unit-tested (cloud/test).

import { b58decode, b58encode, decodeTicket, key } from "../lib/solana.mjs";
import { readPendingChange } from "./policy.mjs";

/** Vault `settle_ticket`. A settlement moves tokens already counted when queued. */
const SETTLE_TICKET = 9;
/** SPL Token and Token-2022 `Transfer` and `TransferChecked`. */
const TOKEN_PROGRAMS = new Set(["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"]);
const TRANSFER = 3;
const TRANSFER_CHECKED = 12;

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
 * Ticket accounts this transaction settles, each with its recipient token
 * account. The instruction list is still complete when the log is truncated,
 * so a settlement can be told apart from a new release. Accounts 4 and 5 of
 * `settle_ticket` are the ticket and the recipient.
 */
export function settledTicketAccounts(tx, vaultProgram) {
  const keys = accountKeys(tx);
  const outer = tx?.transaction?.message?.instructions ?? [];
  const inner = (tx?.meta?.innerInstructions ?? []).flatMap((g) => g.instructions ?? []);
  const out = new Map();
  for (const ix of [...outer, ...inner]) {
    const program = typeof ix.programIdIndex === "number" ? keys[ix.programIdIndex] : ix.programId;
    if (program !== vaultProgram) continue;
    if (instructionData(ix.data)[0] !== SETTLE_TICKET) continue;
    const accounts = compiledAccounts(ix, keys);
    if (accounts[4]) out.set(accounts[4], accounts[5] ?? null);
  }
  return out;
}

/**
 * Token transfers out of the watched vault token accounts, read from the
 * instructions, which are complete when the log is truncated. A vault pays
 * only through a CPI, so null when the RPC returned no inner instructions:
 * an empty list would then be wrong, not empty. `owner` is the destination's
 * token owner from the balance entries, null when the RPC gave none.
 */
export function vaultTransfersOut(tx, tokenMints) {
  const inner = tx?.meta?.innerInstructions;
  if (!Array.isArray(inner)) return null;
  const keys = accountKeys(tx);
  const owners = new Map();
  for (const b of [...(tx?.meta?.preTokenBalances ?? []), ...(tx?.meta?.postTokenBalances ?? [])]) {
    if (b?.owner) owners.set(keys[b.accountIndex], b.owner);
  }
  const outer = tx?.transaction?.message?.instructions ?? [];
  const out = [];
  for (const ix of [...outer, ...inner.flatMap((g) => g.instructions ?? [])]) {
    const program = typeof ix.programIdIndex === "number" ? keys[ix.programIdIndex] : ix.programId;
    if (!TOKEN_PROGRAMS.has(program)) continue;
    const d = instructionData(ix.data);
    const accounts = compiledAccounts(ix, keys);
    let destination;
    if (d[0] === TRANSFER && d.length >= 9) destination = accounts[1];
    else if (d[0] === TRANSFER_CHECKED && d.length >= 10) destination = accounts[2];
    else continue;
    const mint = tokenMints.get(accounts[0]);
    if (!mint || !destination) continue;
    const amount = new DataView(d.buffer, d.byteOffset + 1, 8).getBigUint64(0, true);
    out.push({ mint, address: destination, owner: owners.get(destination) ?? null, amount });
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
    // Created in this transaction: there is no pre balance. The whole post
    // balance arrived here, which is how a first payout to an allowlisted
    // owner looks.
    if (!before?.uiTokenAmount) {
      const gained = BigInt(after.uiTokenAmount.amount);
      if (gained > 0n && after.mint) out.push({ mint: after.mint, address, owner: after.owner, amount: gained });
      continue;
    }
    if (before.mint !== after.mint) continue;
    const gained = BigInt(after.uiTokenAmount.amount) - BigInt(before.uiTokenAmount.amount);
    if (gained <= 0n) continue;
    out.push({ mint: after.mint, address, owner: after.owner, amount: gained });
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
 * What a transaction with a truncated log took out of each watched vault that
 * no surviving event or earlier record already counts.
 *
 * The gross is the vault's own transfers out when the inner instructions are
 * there, so a deposit in the same transaction cannot hide a release, and the
 * net balance drop otherwise (or when it is larger: a transfer this parser
 * does not know still left the vault). A transfer into an account that the
 * same vault PDA owns (`vaultOf`: mint -> vault address) is a lifeboat move,
 * not an outflow: release and settle_ticket refuse such a recipient.
 *
 * From that gross: a settled ticket was counted when it was queued (`known`:
 * `{ mint, ticketId, ticket, amount }`), and a payout to an allowlisted owner
 * is not counted. A settlement's own payout is never also an allowlist
 * credit, so one transfer cannot be subtracted twice; and only tokens that
 * came out of the vault earn that credit, not tokens sent there from elsewhere.
 *
 * Returns `{ outflows: Map(mint -> amount), closed: ticket ids settled here }`.
 */
export function truncatedOutflows(tx, { vaultProgram, tokenMints, vaultOf, known, allowlist }) {
  const settling = settledTicketAccounts(tx, vaultProgram);
  const payees = new Set([...settling.values()].filter(Boolean));
  const transfers = vaultTransfersOut(tx, tokenMints);
  const drops = vaultOutflows(tx, tokenMints);
  const increases = transfers ? null : tokenIncreases(tx, new Set(tokenMints.keys()));
  const sum = (rows) => rows.reduce((total, row) => total + row.amount, 0n);
  const mints = new Set([...drops.keys(), ...(transfers ?? []).map((t) => t.mint)]);
  const outflows = new Map();
  for (const mint of mints) {
    const out = (transfers ?? []).filter((t) => t.mint === mint);
    const toVault = sum(out.filter((t) => t.owner && t.owner === vaultOf.get(mint)));
    const sent = sum(out);
    const drop = drops.get(mint) ?? 0n;
    const gross = sent > drop ? sent : drop;
    const base = gross > toVault ? gross - toVault : 0n;
    const rows = known.filter((k) => k.mint === mint);
    const fresh = freshVaultOutflow(base, settling, rows);
    const credits = (transfers ? out : increases.filter((r) => r.mint === mint)).filter((r) => !payees.has(r.address));
    const countable = countedAfterAllowlist(fresh, credits, allowlist);
    if (countable > 0n) outflows.set(mint, countable);
  }
  const closed = known.filter((k) => settling.has(k.ticket)).map((k) => k.ticketId);
  return { outflows, closed: [...new Set(closed)] };
}

/**
 * The part of `truncatedOutflows` that no surviving release event explains.
 * A surviving event is counted on its own, under its real owner, and all it
 * moved (backed and instant) is part of the figure. An allowlisted owner's
 * payout was never in the figure, so it explains none of it.
 */
export function unexplainedOutflow(outflows, released, allowlist) {
  const left = new Map(outflows);
  for (const e of released) {
    if (!left.has(e.mint) || allowlist.includes(e.owner)) continue;
    const moved = (e.backed ?? 0n) + (e.instant ?? 0n);
    const amount = left.get(e.mint);
    left.set(e.mint, amount > moved ? amount - moved : 0n);
  }
  return left;
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

/** Change accounts for one protocol. The caller decides which are still open. */
export async function activeChanges(rpc, vaultProgram, protocol) {
  const protocolKey = b58encode(key(protocol));
  const discriminator = b58encode(new TextEncoder().encode("BHCHNG01"));
  const accounts = await rpc.call("getProgramAccounts", [b58encode(key(vaultProgram)), {
    encoding: "base64",
    commitment: "confirmed",
    filters: [
      { memcmp: { offset: 0, bytes: discriminator } },
      { memcmp: { offset: 8, bytes: protocolKey } },
    ],
  }]);
  if (!Array.isArray(accounts)) throw new Error("getProgramAccounts returned no change account list");
  return accounts.flatMap(({ pubkey, account }) => {
    const encoded = account?.data?.[0];
    if (typeof encoded !== "string") throw new Error(`change account ${pubkey} has no base64 data`);
    const change = readPendingChange(Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)));
    if (!change || change.protocol !== protocolKey) return [];
    return [change];
  });
}
