// The keeper's instructions: what the Cloud guardian sends to execute an
// approved change once due. Separate from main.mjs so it can be built and
// simulated on its own.

import { key, findPda, u64le, IDS } from "../lib/solana.mjs";

/**
 * Vault `execute_change` (20). Accounts: protocol [w], change [w], target [w]
 * (the vault for SetLimits, the asset record for UpsertAsset, the protocol for
 * a protocol-level change), payer [s,w], mint, token program, system.
 * `mintOwner` is the token program owning the asset's mint (UpsertAsset only).
 */
export async function executeChangeIx({ vaultProgram, protocol, payer, defaultMint, changeId, kind, target, mintOwner = null }) {
  const program = key(vaultProgram);
  const [change] = await findPda(["change", key(protocol), u64le(BigInt(changeId))], program);
  let account = key(protocol);
  let mint = key(defaultMint);
  let tokenProgram = IDS.token;
  if (kind === 0) account = key(target);
  if (kind === 1) {
    mint = key(target);
    [account] = await findPda(["asset", key(protocol), mint], program);
    if (mintOwner) tokenProgram = key(mintOwner);
  }
  return {
    programId: program,
    accounts: [
      { pubkey: key(protocol), writable: true }, { pubkey: change, writable: true }, { pubkey: account, writable: true },
      { pubkey: key(payer), writable: true, signer: true }, { pubkey: mint }, { pubkey: tokenProgram }, { pubkey: IDS.system },
    ],
    data: Uint8Array.of(20),
  };
}
