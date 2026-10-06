#!/usr/bin/env node
// Sets up a Bulkhead market on a real cluster (devnet, or a local validator for
// a dry run): a test USDC mint, Harbor registered with Bulkhead, one vault with
// the default limits, 10,000,000 test USDC deposited, and the seal proposed.
// The seal can execute only after the 72h loosen delay.
//
//   node cloud/deploy/market.mjs setup <rpc> <dir> <payer.json> <vaultProgram> <harborProgram>
//   node cloud/deploy/market.mjs seal  <rpc> <dir> <payer.json>
//
// <dir> receives world.json (the same fields cloud/e2e uses) and keys/*.json:
// admin, guardian0..2, lifeboat destination, mint authority, whale, attacker,
// and the mint and token accounts. Setup resumes after a failure: run it again
// with the same <dir>. Keys are saved before they are used, each step records
// its signature in progress.json, and a step whose effect is already on chain
// is skipped. A recorded step is redone when this cluster does not have it,
// so a copied progress.json cannot write world.json for a market that was
// never created. The seal is proposed at most once (proposing again would
// restart its 72h clock). world.json is written last, when every step has landed.
// Zero dependencies: only this repository's cloud/lib and Node's standard library.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Rpc, key, findPda, concat, u64le, i64le, IDS, b58encode, decodeProtocol, decodeVault } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";

const DAY = 86_400;
const USDC = 1_000_000n; // 6 decimals
const TVL = 10_000_000n * USDC;

const w = (pubkey) => ({ pubkey: key(pubkey), writable: true });
const r = (pubkey) => ({ pubkey: key(pubkey) });
const s = (pubkey, writable = false) => ({ pubkey: key(pubkey), signer: true, writable });
const u32le = (v) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
};
const u16le = (v) => Uint8Array.of(v & 0xff, v >> 8);

// --- System and SPL Token instructions -----------------------------------------
function createAccount(from, account, lamports, space, owner) {
  return {
    programId: IDS.system,
    accounts: [s(from, true), s(account, true)],
    data: concat(u32le(0), u64le(lamports), u64le(space), key(owner)),
  };
}
const initializeMint2 = (mint, decimals, authority) => ({
  programId: IDS.token,
  accounts: [w(mint)],
  data: concat(Uint8Array.of(20, decimals), key(authority), Uint8Array.of(0)), // no freeze authority
});
const initializeAccount3 = (account, mint, owner) => ({
  programId: IDS.token,
  accounts: [w(account), r(mint)],
  data: concat(Uint8Array.of(18), key(owner)),
});
const mintTo = (mint, to, authority, amount) => ({
  programId: IDS.token,
  accounts: [w(mint), w(to), s(authority)],
  data: concat(Uint8Array.of(7), u64le(amount)),
});

// SKIP_PREFLIGHT=1 skips the RPC's simulation (for endpoints whose account reads
// are unavailable); a failed transaction still raises from its confirmed status.
const sendTx = (rpc, payer, ixs, extra = []) => send(rpc, payer, ixs, extra, { skipPreflight: process.env.SKIP_PREFLIGHT === "1" });

async function rentFor(rpc, space) {
  return rpc.call("getMinimumBalanceForRentExemption", [space]);
}

async function newTokenAccount(rpc, payer, acc, mint, owner) {
  return sendTx(rpc, payer, [
    createAccount(payer.publicKey, acc.publicKey, await rentFor(rpc, 165), 165, IDS.token),
    initializeAccount3(acc.publicKey, mint, owner),
  ], [acc]);
}

// --- Bulkhead (Vault) and Harbor instructions ---------------------------------
// Account orders follow programs/vault/src and programs/harbor/src, and the
// builders in programs/tests/tests/common/vault.rs.
export function harborIx(m, tag, args, harborAccounts, vaultAccounts) {
  return {
    programId: key(m.harbor),
    accounts: [r(m.vaultProgram), r(m.caller), ...harborAccounts, ...vaultAccounts],
    data: concat(Uint8Array.of(tag), args),
  };
}
export const vaultIx = (m, tag, args, accounts) => ({ programId: key(m.vaultProgram), accounts, data: concat(Uint8Array.of(tag), args) });

export function defaultLimits() {
  // docs/03 §1: 2%/hour, 5%/day, 6h minimum queue delay, no floors or caps.
  return limitsWithCaps(0n, 0n);
}

/** The default limits plus absolute caps in base units (0 = none). */
export function limitsWithCaps(shortCap, longCap) {
  return concat(u16le(200), u32le(3_600), u16le(500), u32le(86_400), u32le(21_600), u64le(0), u64le(0), u64le(shortCap), u64le(longCap));
}

/** The calibration rule (docs/07 §4): caps at the same percentages of the
 * vault's honest size, here the whale's 10M. They bound capital an attacker
 * parks in the vault first (docs/15, A1b); at 10M they equal 2% and 5%. */
export const CAPS = { short: (TVL * 200n) / 10_000n, long: (TVL * 500n) / 10_000n };

export function registerArgs(admin, guardians, destination) {
  return concat(
    key(admin),
    Uint8Array.of(guardians.length),
    ...guardians.map((g) => key(g)),
    Uint8Array.of(2), // threshold
    i64le(7 * DAY), // heartbeat interval
    i64le(3 * DAY), // loosen delay: the 72h constant minimum
    key(destination),
  );
}

// --- commands ------------------------------------------------------------------
function keysIn(dir) {
  mkdirSync(`${dir}/keys`, { recursive: true, mode: 0o700 });
  const k = (name) => {
    const p = `${dir}/keys/${name}.json`;
    if (existsSync(p)) return Keypair.load(p);
    const kp = Keypair.generate();
    kp.save(p);
    return kp;
  };
  return {
    admin: k("admin"),
    guardians: [k("guardian0"), k("guardian1"), k("guardian2")],
    destination: k("lifeboat-destination"),
    mintAuthority: k("mint-authority"),
    whale: k("whale"),
    attacker: k("attacker"),
    mint: k("mint"),
    whaleTokens: k("whale-tokens"),
    attackerTokens: k("attacker-tokens"),
    recovery: () => k("recovery"), // only created when a recovery key is proposed
  };
}

async function fund(rpc, payer, to, lamports) {
  return sendTx(rpc, payer, [{ programId: IDS.system, accounts: [s(payer.publicKey, true), w(to)], data: concat(u32le(2), u64le(lamports)) }]);
}

const FEES = 50_000_000n; // lamports each for the admin, guardians and whale
const tokenAmount = (acc) => new DataView(acc.bytes.buffer, acc.bytes.byteOffset).getBigUint64(64, true);
const utc = (s) => new Date(s * 1000).toISOString().replace(".000Z", "Z");

async function setup(url, dir, payerPath, vaultProgram, harbor) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const step = (msg) => console.log(`== ${msg}`);
  const progressPath = `${dir}/progress.json`;
  const progress = existsSync(progressPath) ? JSON.parse(readFileSync(progressPath, "utf8")) : {};
  // An account; null if it doesn't exist, undefined if the endpoint can't read accounts.
  const read = (addr) => rpc.account(addr).catch(() => undefined);
  const exists = (addr) => async () => {
    const a = await read(addr);
    if (a === undefined) return undefined;
    return !!a;
  };
  // `landed` is true, false, or undefined when the account could not be read.
  // A progress.json entry is not proof: the file may be from another cluster.
  async function once(name, landed, run) {
    const found = await landed();
    const what = stepDisposition(progress[name], found);
    if (what === "unreadable") throw new Error(`${name}: can't read the cluster to see whether this step already landed`);
    if (what === "skip") {
      console.log(progress[name] ? `   ${name}: done earlier (${progress[name]})` : `   ${name}: already on chain`);
      if (!progress[name]) {
        progress[name] = "found on chain";
        writeFileSync(progressPath, JSON.stringify(progress, null, 2) + "\n");
      }
      return;
    }
    if (what === "redo") console.log(`   ${name}: recorded as done, but it is not on this cluster; doing it`);
    progress[name] = await run();
    writeFileSync(progressPath, JSON.stringify(progress, null, 2) + "\n");
  }

  const mint = k.mint;
  const whaleTokens = k.whaleTokens.address;
  const attackerTokens = k.attackerTokens.address;
  const [caller] = await findPda(["bulkhead-caller"], harbor);
  const [protocol] = await findPda(["protocol", key(harbor)], vaultProgram);
  const [vault] = await findPda(["vault", protocol, mint.publicKey], vaultProgram);
  const [vaultTokens] = await findPda(["vault-tokens", protocol, mint.publicKey], vaultProgram);
  const [backing] = await findPda(["backing", protocol, k.whale.publicKey], vaultProgram);
  const m = { vaultProgram: key(vaultProgram), harbor: key(harbor), caller, protocol };

  step("funding the admin, guardians and whale (fees and rent)");
  for (const [name, kp] of [["admin", k.admin], ...k.guardians.map((g, i) => [`guardian${i}`, g]), ["whale", k.whale]]) {
    await once(`fund ${name}`, async () => {
      const a = await read(kp.publicKey);
      if (a === undefined) return undefined;
      return BigInt(a?.lamports ?? 0) >= FEES;
    }, () => fund(rpc, payer, kp.publicKey, FEES));
  }

  step("creating a test USDC mint (6 decimals, no freeze authority)");
  await once("mint", exists(mint.publicKey), async () => sendTx(rpc, payer, [
    createAccount(payer.publicKey, mint.publicKey, await rentFor(rpc, 82), 82, IDS.token),
    initializeMint2(mint.publicKey, 6, k.mintAuthority.publicKey),
  ], [mint]));

  step("registering Harbor with Bulkhead (the caller PDA is the registrar)");
  let registeredNow = false;
  await once("register", async () => {
    const a = await read(protocol);
    if (a === undefined) return undefined;
    if (!a) return false;
    // Harbor lets anyone register it: the protocol must be ours.
    const { admin } = decodeProtocol(a.bytes);
    if (admin !== k.admin.address) throw new Error(`protocol ${b58encode(protocol)} was registered with another admin (${admin}): deploy Harbor under a new program id`);
    return true;
  }, async () => {
    const sig = await sendTx(rpc, payer, [harborIx(m, 0, registerArgs(k.admin.publicKey, k.guardians.map((g) => g.publicKey), k.destination.publicKey), [], [
      s(payer.publicKey, true), w(protocol), r(harbor), r(harbor), r(caller), r(IDS.system),
    ])]);
    registeredNow = true;
    return sig;
  });

  step("creating the USDC vault with the demo limits and calibrated caps (2%/h, 5%/day)");
  await once("vault", exists(vault), () => sendTx(rpc, payer, [vaultIx(m, 1, limitsWithCaps(CAPS.short, CAPS.long), [
    s(payer.publicKey, true), s(k.admin.publicKey), w(protocol), w(vault), w(vaultTokens), r(mint.publicKey), r(IDS.token), r(IDS.system),
  ])], [k.admin]));

  step("minting 10,000,000 test USDC to the whale and depositing it through Harbor");
  await once("whale token account", exists(whaleTokens), () => newTokenAccount(rpc, payer, k.whaleTokens, mint.publicKey, k.whale.publicKey));
  await once("mint to whale", async () => {
    const deposited = await read(backing);
    if (deposited === undefined) return undefined;
    if (deposited) return true; // already deposited
    const a = await read(whaleTokens);
    if (a === undefined) return undefined;
    return !!a && tokenAmount(a) >= TVL;
  }, () => sendTx(rpc, payer, [mintTo(mint.publicKey, whaleTokens, k.mintAuthority.publicKey, TVL)], [k.mintAuthority]));
  await once("deposit", exists(backing), () => sendTx(rpc, payer, [harborIx(m, 1, u64le(TVL), [s(k.whale.publicKey)], [
    r(protocol), w(vault), w(vaultTokens), r(mint.publicKey), w(whaleTokens), s(k.whale.publicKey), w(backing),
    s(payer.publicKey, true), r(IDS.token), r(IDS.system),
  ])], [k.whale]));

  step("an attacker token account (for the S1 run after the seal)");
  await once("attacker token account", exists(attackerTokens), () => newTokenAccount(rpc, payer, k.attackerTokens, mint.publicKey, k.attacker.publicKey));

  step("proposing the seal: it can execute after the 72h loosen delay");
  await once("seal proposal", async () => {
    const a = await read(protocol);
    if (a === undefined && !registeredNow) throw new Error("can't read the protocol to rule out an earlier seal proposal (proposing again restarts its 72h clock); run setup again once getAccountInfo works");
    if (a === undefined) return false;
    if (a) return decodeProtocol(a.bytes).sealExecutableS !== 0;
    if (registeredNow) return false; // registered in this run: no earlier proposal exists
    throw new Error("can't read the protocol to rule out an earlier seal proposal (proposing again restarts its 72h clock); run setup again once getAccountInfo works");
  }, () => sendTx(rpc, payer, [vaultIx(m, 4, new Uint8Array(0), [w(protocol), s(k.admin.publicKey)])], [k.admin]));

  const world = {
    cluster: url,
    vaultProgram: b58encode(key(vaultProgram)),
    harbor: b58encode(key(harbor)),
    protocol: b58encode(protocol),
    caller: b58encode(caller),
    mint: mint.address,
    vault: b58encode(vault),
    vaultTokens: b58encode(vaultTokens),
    whaleTokens,
    attackerTokens,
    attacker: k.attacker.address,
    tokenProgram: b58encode(IDS.token),
    sealProposal: progress["seal proposal"],
  };
  writeFileSync(`${dir}/world.json`, JSON.stringify(world, null, 2) + "\n");
  const a = await read(protocol);
  if (a) {
    const p = decodeProtocol(a.bytes);
    console.log(`protocol ${world.protocol}: sealed ${p.sealed}, vaults ${p.vaultCount}, guardians ${p.guardians.length} (quorum ${p.threshold})`);
    console.log(`seal executable from ${utc(p.sealExecutableS)} until ${utc(p.sealExpiresS)}${p.sealVetoed ? " (VETOED)" : ""}`);
  } else {
    console.log(`protocol ${world.protocol}: created (state read unavailable)`);
  }
  console.log(`seal proposed: ${world.sealProposal}`);
  console.log(`world: ${dir}/world.json`);
}

async function seal(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const m = { vaultProgram: key(world.vaultProgram) };
  const [lifeboat] = await findPda(["lifeboat-tokens", key(world.protocol), key(world.mint)], m.vaultProgram);
  const sig = await sendTx(rpc, payer, [vaultIx(m, 5, new Uint8Array(0), [w(world.protocol), r(world.vault), r(world.vaultTokens), r(lifeboat)])]);
  console.log(`sealed: ${sig}`);
}

// Sets the calibrated absolute caps (CAPS) on the market's vault. Tightening, so
// it applies at once, before or after the seal; a re-run with the caps already
// set sends nothing.
async function caps(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const fmt = (x) => (Number(x) / 1e6).toLocaleString("en-US");
  const limits = async () => decodeVault((await rpc.account(world.vault)).bytes).limits;
  const before = await limits();
  if (before.shortCap === CAPS.short && before.longCap === CAPS.long) {
    return console.log(`caps already set: ${fmt(CAPS.short)} per 1h, ${fmt(CAPS.long)} per 24h`);
  }
  const p = decodeProtocol((await rpc.account(world.protocol)).bytes);
  const vaultProgram = key(world.vaultProgram);
  const [change] = await findPda(["change", key(world.protocol), u64le(p.nextChangeId)], vaultProgram);
  const args = concat(Uint8Array.of(0), key(world.vault), limitsWithCaps(CAPS.short, CAPS.long)); // kind 0: limits
  const sig = await sendTx(rpc, payer, [vaultIx({ vaultProgram }, 18, args, [
    s(payer.publicKey, true), s(k.admin.publicKey), w(world.protocol), w(change), r(IDS.system), w(world.vault),
  ])], [k.admin]);
  const after = await limits();
  if (after.shortCap !== CAPS.short || after.longCap !== CAPS.long) throw new Error(`caps not applied: ${after.shortCap} / ${after.longCap}`);
  console.log(`caps set: ${fmt(CAPS.short)} per 1h, ${fmt(CAPS.long)} per 24h (a tightening, applied at once): ${sig}`);
}

/** Proposes a protocol-level change (kind, target, payload) as the admin. */
async function proposeAsAdmin(rpc, payer, k, world, kind, target, payload) {
  const p = decodeProtocol((await rpc.account(world.protocol)).bytes);
  const vaultProgram = key(world.vaultProgram);
  const [change] = await findPda(["change", key(world.protocol), u64le(p.nextChangeId)], vaultProgram);
  const sig = await sendTx(rpc, payer, [vaultIx({ vaultProgram }, 18, concat(Uint8Array.of(kind), key(target), payload), [
    s(payer.publicKey, true), s(k.admin.publicKey), w(world.protocol), w(change), r(IDS.system),
  ])], [k.admin]);
  const executable = new Date((Math.floor(Date.now() / 1000) + 3 * DAY) * 1000).toISOString();
  return { id: p.nextChangeId, sig, executable };
}

/** Every guardian that is still live sends a heartbeat (a dead one cannot). */
async function heartbeat(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const p = decodeProtocol((await rpc.account(world.protocol)).bytes);
  const now = Math.floor(Date.now() / 1000);
  for (const [i, g] of k.guardians.entries()) {
    const at = p.guardians.indexOf(g.address);
    const last = at < 0 ? null : Number(p.lastHeartbeat[at]);
    if (last === null || now - last > p.heartbeatIntervalS) {
      console.log(`guardian${i}: not live (last heartbeat ${last ? new Date(last * 1000).toISOString() : "none"}); only a new guardian set revives it`);
      continue;
    }
    const sig = await sendTx(rpc, payer, [vaultIx({ vaultProgram: key(world.vaultProgram) }, 14, new Uint8Array(0), [w(world.protocol), s(g.publicKey)])], [g]);
    console.log(`guardian${i}: heartbeat ${sig}`);
  }
}

/** The admin proposes the same guardian set again: after the delay, every
 * guardian counts as live from that moment (the way a stale one comes back). */
async function renewGuardians(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const set = concat(Uint8Array.of(k.guardians.length), ...k.guardians.map((g) => key(g.publicKey)), Uint8Array.of(2), i64le(7 * DAY));
  const c = await proposeAsAdmin(rpc, payer, k, world, 2, new Uint8Array(32), set);
  console.log(`guardian set proposed as change ${c.id} (${c.sig}); anyone may execute it from about ${c.executable}: market.mjs execute-change <rpc> <dir> <payer> ${c.id}`);
}

/** The admin names a recovery key (allowed only while none exists; docs/15, A4). */
async function setRecovery(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const recovery = k.recovery();
  const c = await proposeAsAdmin(rpc, payer, k, world, 6, recovery.publicKey, new Uint8Array(0));
  console.log(`recovery key ${recovery.address} (keys/recovery.json) proposed as change ${c.id} (${c.sig}); executable from about ${c.executable}`);
}

/** Anyone executes a protocol-level change once it is due. */
async function executeChange(url, dir, payerPath, id) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const vaultProgram = key(world.vaultProgram);
  const [change] = await findPda(["change", key(world.protocol), u64le(BigInt(id))], vaultProgram);
  const sig = await sendTx(rpc, payer, [vaultIx({ vaultProgram }, 20, new Uint8Array(0), [
    w(world.protocol), w(change), w(world.protocol), s(payer.publicKey, true), r(world.mint), r(IDS.token), r(IDS.system),
  ])]);
  console.log(`change ${id} executed: ${sig}`);
}

/**
 * What to do with one setup step. `found` is true or false from a successful
 * read, and anything else means the read failed. A recorded step still has to
 * be on this cluster.
 */
export function stepDisposition(recorded, found) {
  if (found !== true && found !== false) return "unreadable";
  if (found) return "skip";
  return recorded ? "redo" : "run";
}

/**
 * Why world.json must not be treated as a finished market, or null when the
 * directory matches this vault program, this Harbor, a protocol that has a
 * vault and a seal, and the vault account named in the file.
 * An account argument is null when the account is absent and undefined when
 * it could not be read.
 */
export function marketDirProblem(world, vaultProgram, harbor, protocolAccount, vaultAccount) {
  if (!world || world.vaultProgram !== vaultProgram || world.harbor !== harbor) {
    return `world.json is for vault ${world?.vaultProgram} and harbor ${world?.harbor}, not ${vaultProgram} and ${harbor}`;
  }
  if (protocolAccount === undefined) return "can't read the protocol account named in world.json";
  if (protocolAccount === null) return `protocol ${world.protocol} from world.json is not on this cluster`;
  let decoded;
  try {
    decoded = decodeProtocol(protocolAccount.bytes ?? protocolAccount);
  } catch {
    return "the protocol account named in world.json is not a Bulkhead protocol";
  }
  if (decoded.protocolProgram !== harbor) return "the protocol on chain was not registered by this Harbor";
  // world.json is written only after the vault exists and the seal is proposed.
  // A bare register at the same address is not that market.
  if (decoded.vaultCount < 1 || (!decoded.sealed && decoded.sealExecutableS === 0)) {
    return "the protocol on chain has no vault and seal";
  }
  if (vaultAccount === undefined) return "can't read the vault account named in world.json";
  if (vaultAccount === null) return `vault ${world.vault} from world.json is not on this cluster`;
  let vaultDecoded;
  try {
    vaultDecoded = decodeVault(vaultAccount.bytes ?? vaultAccount);
  } catch {
    return "the vault account named in world.json is not a Bulkhead vault";
  }
  if (vaultDecoded.protocol !== world.protocol) return "the vault on chain belongs to another protocol";
  if (world.mint && vaultDecoded.mint !== world.mint) return "the vault on chain is for another mint";
  return null;
}

async function confirm(url, dir, vaultProgram, harbor) {
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const rpc = new Rpc(url);
  const read = async (addr) => {
    try {
      return await rpc.account(addr);
    } catch {
      return undefined;
    }
  };
  const problem = marketDirProblem(world, vaultProgram, harbor, await read(world.protocol), await read(world.vault));
  if (problem) throw new Error(problem);
}

// The builders above are shared with cloud/deploy/vault-check.mjs; the commands
// run only when this file is invoked directly.
if (import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === "setup" && args.length === 5) await setup(...args);
  else if (cmd === "seal" && args.length === 3) await seal(...args);
  else if (cmd === "caps" && args.length === 3) await caps(...args);
  else if (cmd === "confirm" && args.length === 4) await confirm(...args);
  else if (cmd === "heartbeat" && args.length === 3) await heartbeat(...args);
  else if (cmd === "renew-guardians" && args.length === 3) await renewGuardians(...args);
  else if (cmd === "set-recovery" && args.length === 3) await setRecovery(...args);
  else if (cmd === "execute-change" && args.length === 4) await executeChange(...args);
  else {
    console.error("usage: market.mjs setup <rpc> <dir> <payer.json> <vaultProgram> <harborProgram> | confirm <rpc> <dir> <vaultProgram> <harborProgram> | heartbeat|renew-guardians|set-recovery <rpc> <dir> <payer.json> | execute-change <rpc> <dir> <payer.json> <id> | seal <rpc> <dir> <payer.json> | caps <rpc> <dir> <payer.json>");
    process.exit(2);
  }
}
