// Instruction builders for Bulkhead Vault and Floor, and the views a guardian
// reads. Account orders follow programs/vault/src and programs/floor/src.

import { key, findPda, concat, i64le, u64le, IDS, decodeAttestation, b58encode as b58 } from "./solana.mjs";

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
  /** The asset record of `mint` (`["asset", protocol, mint]`). */
  async asset(mint) {
    const [a] = await findPda(["asset", this.protocol, key(mint)], this.program);
    return a;
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
  /**
   * Names the ticket id the guardian decided on: ticket addresses are reused
   * once a ticket closes, and the program refuses (WrongTicket) when the
   * address now holds another one.
   */
  cancelTicket(vault, ticket, signer, rentReceiver, ticketId) {
    if (ticketId == null) throw new Error("cancelTicket needs the ticket id");
    return this.ix(10, u64le(BigInt(ticketId)), [r(this.protocol), w(vault), w(ticket), s(signer), w(rentReceiver)]);
  }
  /** Delays a ticket by `secs` (≤ 24h a call, ≤ 7 days in all); names its id, as a cancel does. */
  extendTicket(ticket, guardian, secs, ticketId) {
    if (ticketId == null) throw new Error("extendTicket needs the ticket id");
    return this.ix(11, concat(i64le(secs), u64le(BigInt(ticketId))), [r(this.protocol), w(ticket), s(guardian)]);
  }
  vetoChange(change, guardian) {
    return this.ix(19, new Uint8Array(0), [r(this.protocol), w(change), s(guardian)]);
  }
  /** The admin with a live guardian quorum replaces the recovery key at once (all-zero: none). */
  replaceRecovery(admin, recovery, guardians) {
    return this.ix(29, key(recovery), [w(this.protocol), s(admin), ...guardians.map((g) => s(g))]);
  }
  vetoExit(vault, guardian) {
    return this.ix(28, new Uint8Array(0), [r(this.protocol), w(vault), s(guardian)]);
  }
  attestIx(vault, vaultTokens) {
    return this.ix(22, new Uint8Array(0), [r(this.protocol), r(vault), r(vaultTokens)]);
  }
  /** A ticket's address: named by its payer and the payer's nonce, not by its id. */
  async ticketAddress(payer, nonce) {
    const [t] = await findPda(["ticket", this.protocol, key(payer), u64le(nonce)], this.program);
    return t;
  }
  async changeAddress(id) {
    const [c] = await findPda(["change", this.protocol, u64le(id)], this.program);
    return c;
  }
  /**
   * The live worst case, straight from the program (`attest`, simulated), and
   * `clockS`: the unix time the simulation ran at (its Clock sysvar), which a
   * local computation must use to agree exactly.
   */
  async attest(rpc, feePayer, mint) {
    const { vault, vaultTokens } = await this.vault(mint);
    const sim = await rpc.simulate(feePayer, [this.attestIx(vault, vaultTokens)], [IDS.clock]);
    if (sim.err) throw new Error(`attest failed: ${JSON.stringify(sim.err)} ${sim.logs?.join(" | ")}`);
    const b = Uint8Array.from(atob(sim.returnData.data[0]), (c) => c.charCodeAt(0));
    const clock = Uint8Array.from(atob(sim.accounts[0].data[0]), (c) => c.charCodeAt(0));
    const clockS = Number(new DataView(clock.buffer).getBigInt64(32, true)); // Clock.unix_timestamp
    return { ...decodeAttestation(b), clockS };
  }
}

/**
 * What each buffer Floor holds is for, as `close_buffer` judges it
 * (`buffer_closable`, docs/09 finding 78): the staged abort buffer, the pin,
 * the pending upgrade's or restore's buffer, or an orphan the owner may close.
 * `config` is `decodeFloor`'s result.
 */
export function floorBufferRole(config, address) {
  if (address === config.abortBuffer) return "abort";
  if (address === config.snapshotBuffer) return "pin";
  if ((config.pendingKind === 1 || config.pendingKind === 2) && address === config.pendingTarget) return "pending";
  return "orphan";
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
  /**
   * Stops the program. `snapshot`: the pinned snapshot buffer, required while
   * one is pinned (docs/09, finding 53). The spill is the config itself
   * (finding 88).
   */
  abort(signer, abortBuffer, snapshot = null) {
    const a = [
      w(this.config), s(signer), w(this.programdata), w(this.protected), w(abortBuffer), w(this.config),
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
  /** Anyone stages the first; replacing a staged one takes a live guardian quorum (`guardians`, finding 88). */
  stageAbort(buffer, guardians = []) {
    return this.ix(1, new Uint8Array(0), [w(this.config), r(buffer), r(this.programdata), ...guardians.map((g) => s(g))]);
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
  /** The owner proposes a change (kind: 1 upgrade, 2 restore, ...); an upgrade or restore targets a frozen buffer. */
  propose(owner, kind, target, payload = new Uint8Array(0)) {
    const a = [w(this.config), s(owner)];
    if (kind === 1 || kind === 2) a.push(r(target));
    return this.ix(4, concat(Uint8Array.of(kind), key(target), payload), a);
  }
  /** Execute a pending SetGuardians / SetOwner / SetDelay / SetRecovery (anyone). */
  executeConfig() {
    return this.ix(7, new Uint8Array(0), [w(this.config)]);
  }
  /** Anyone executes a pending upgrade or restore once it is allowed; the spill is the owner. */
  executeUpgrade(buffer, spill) {
    return this.ix(7, new Uint8Array(0), [
      w(this.config), w(this.programdata), w(this.protected), w(buffer), w(spill),
      r(IDS.rent), r(IDS.clock), r(this.authority), r(IDS.loaderV3),
    ]);
  }
  /**
   * Execute a pending ReleaseAuthority (anyone, once due). A release to a key
   * needs that key's signature (SetAuthorityChecked); `held` are the staged
   * abort buffer and the pinned snapshot, which it closes (docs/09, 78 and 80).
   */
  executeRelease(owner, newAuthority, held = []) {
    const a = [w(this.config), w(this.programdata), r(this.authority), r(IDS.loaderV3), w(owner)];
    if (newAuthority) a.push(s(newAuthority));
    return this.ix(7, new Uint8Array(0), [...a, ...held.map((b) => w(b))]);
  }
  /**
   * Every loader-v3 buffer whose authority is this program's Floor PDA:
   * `[{ address, lamports }]`. Buffer accounts begin with the tag 1 (u32) and
   * an authority option, so the PDA sits at byte 5. Read at "confirmed", like
   * every other read here: the RPC's default, "finalized", still lists for
   * ~13 s a buffer that a restore or close has just consumed.
   */
  async heldBuffers(rpc) {
    const rows = await rpc.call("getProgramAccounts", [b58(IDS.loaderV3), {
      encoding: "base64",
      commitment: "confirmed",
      dataSlice: { offset: 0, length: 0 },
      filters: [{ memcmp: { offset: 0, bytes: "2UzHM" } }, { memcmp: { offset: 4, bytes: "2" } }, { memcmp: { offset: 5, bytes: b58(this.authority) } }],
    }]);
    return rows.map((r) => ({ address: r.pubkey, lamports: r.account.lamports }));
  }
  /** The owner closes a buffer Floor holds that nothing refers to; its rent goes to the owner (docs/09, 78). */
  closeBuffer(owner, buffer) {
    return this.ix(13, new Uint8Array(0), [r(this.config), s(owner, true), w(buffer), r(this.authority), r(IDS.loaderV3), r(this.programdata)]);
  }
  cancel(owner) {
    return this.ix(11, new Uint8Array(0), [w(this.config), s(owner)]);
  }
  veto(guardian, proposalId = null) {
    const data = proposalId == null ? new Uint8Array(0) : u64le(proposalId);
    return this.ix(5, data, [w(this.config), s(guardian)]);
  }
  heartbeat(guardian) {
    return this.ix(9, new Uint8Array(0), [w(this.config), s(guardian)]);
  }
  /** The owner with a live guardian quorum replaces the recovery key at once (all-zero: none). */
  replaceRecovery(owner, recovery, guardians) {
    return this.ix(12, key(recovery), [w(this.config), s(owner), ...guardians.map((g) => s(g))]);
  }
}
