// Instruction builders for Bulkhead Vault and Floor, and the views a guardian
// reads. Account orders follow programs/vault/src and programs/floor/src.

import { key, findPda, concat, i64le, u64le, IDS, decodeAttestation } from "./solana.mjs";

const w = (pubkey) => ({ pubkey: key(pubkey), writable: true });
const r = (pubkey) => ({ pubkey: key(pubkey) });
const s = (pubkey, writable = false) => ({ pubkey: key(pubkey), signer: true, writable });

export class VaultClient {
  constructor(vaultProgram, protocolProgram) {
    this.program = key(vaultProgram);
    this.protocolProgram = key(protocolProgram);
  }
  async init() {
    [this.protocol] = await findPda(["protocol", this.protocolProgram], this.program);
    return this;
  }
  async vault(mint) {
    const [v] = await findPda(["vault", this.protocol, key(mint)], this.program);
    const [t] = await findPda(["vault-tokens", this.protocol, key(mint)], this.program);
    return { vault: v, vaultTokens: t };
  }
  ix(tag, args, accounts) {
    return { programId: this.program, accounts, data: concat(Uint8Array.of(tag), args) };
  }
  /** Scope: null = whole protocol, else a vault address. */
  freeze(guardian, secs, vault = null) {
    const a = [w(this.protocol), s(guardian)];
    if (vault) a.push(w(vault));
    return this.ix(12, concat(Uint8Array.of(vault ? 1 : 0), i64le(secs)), a);
  }
  unfreeze(guardians, vault = null) {
    return this.ix(13, Uint8Array.of(vault ? 1 : 0), [w(this.protocol), vault ? w(vault) : r(this.protocol), ...guardians.map((g) => s(g))]);
  }
  heartbeat(guardian) {
    return this.ix(14, new Uint8Array(0), [w(this.protocol), s(guardian)]);
  }
  cancelTicket(vault, ticket, signer, rentReceiver) {
    return this.ix(10, new Uint8Array(0), [r(this.protocol), w(vault), w(ticket), s(signer), w(rentReceiver)]);
  }
  vetoChange(change, guardian) {
    return this.ix(19, new Uint8Array(0), [r(this.protocol), w(change), s(guardian)]);
  }
  attestIx(vault, vaultTokens) {
    return this.ix(22, new Uint8Array(0), [r(this.protocol), r(vault), r(vaultTokens)]);
  }
  async ticketAddress(id) {
    const [t] = await findPda(["ticket", this.protocol, u64le(id)], this.program);
    return t;
  }
  async changeAddress(id) {
    const [c] = await findPda(["change", this.protocol, u64le(id)], this.program);
    return c;
  }
  /** The live worst case, straight from the program (`attest`, simulated). */
  async attest(rpc, feePayer, mint) {
    const { vault, vaultTokens } = await this.vault(mint);
    const sim = await rpc.simulate(feePayer, [this.attestIx(vault, vaultTokens)]);
    if (sim.err) throw new Error(`attest failed: ${JSON.stringify(sim.err)} ${sim.logs?.join(" | ")}`);
    const b = Uint8Array.from(atob(sim.returnData.data[0]), (c) => c.charCodeAt(0));
    return decodeAttestation(b);
  }
}

export class FloorClient {
  constructor(floorProgram, protectedProgram) {
    this.program = key(floorProgram);
    this.protected = key(protectedProgram);
  }
  async init() {
    [this.config] = await findPda(["floor", this.protected], this.program);
    [this.authority] = await findPda(["authority", this.protected], this.program);
    [this.programdata] = await findPda([this.protected], IDS.loaderV3);
    return this;
  }
  ix(tag, args, accounts) {
    return { programId: this.program, accounts, data: concat(Uint8Array.of(tag), args) };
  }
  abort(signer, abortBuffer, snapshot = null) {
    const a = [
      w(this.config), s(signer), w(this.programdata), w(this.protected), w(abortBuffer), w(signer),
      r(IDS.rent), r(IDS.clock), r(this.authority), r(IDS.loaderV3),
    ];
    if (snapshot) a.push(r(snapshot));
    return this.ix(3, new Uint8Array(0), a);
  }
  /** Takes the upgrade authority in the same instruction; signed by the current authority. */
  register(payer, currentAuthority, owner, guardians, threshold, intervalS, delayS) {
    const args = concat(
      key(owner),
      Uint8Array.of(guardians.length),
      ...guardians.map((g) => key(g)),
      Uint8Array.of(threshold),
      i64le(intervalS),
      i64le(delayS),
    );
    return this.ix(0, args, [
      s(payer, true), w(this.config), r(this.authority), r(this.protected), w(this.programdata),
      s(currentAuthority), r(IDS.system), r(IDS.loaderV3),
    ]);
  }
  /** A frozen buffer (authority = Floor's PDA) holding a canonical abort binary. */
  stageAbort(buffer) {
    return this.ix(1, new Uint8Array(0), [w(this.config), r(buffer), r(this.programdata)]);
  }
  /** A frozen buffer holding a copy of the live code, verified byte for byte. */
  pinSnapshot(buffer) {
    return this.ix(2, new Uint8Array(0), [w(this.config), r(this.programdata), r(buffer)]);
  }
  /** A live guardian quorum reinstalls the verified snapshot. */
  restoreSnapshot(snapshot, spill, guardians) {
    return this.ix(8, new Uint8Array(0), [
      w(this.config), w(this.programdata), w(this.protected), w(snapshot), w(spill),
      r(IDS.rent), r(IDS.clock), r(this.authority), r(IDS.loaderV3),
      ...guardians.map((g) => s(g)),
    ]);
  }
  veto(guardian) {
    return this.ix(5, new Uint8Array(0), [w(this.config), s(guardian)]);
  }
  heartbeat(guardian) {
    return this.ix(9, new Uint8Array(0), [w(this.config), s(guardian)]);
  }
}
