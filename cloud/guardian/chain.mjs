// Facts the guardian takes from the chain instead of from log text. Pure
// functions over RPC results, so every rule is unit-tested (cloud/test).

import { b58encode, decodeTicket, key } from "../lib/solana.mjs";

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
