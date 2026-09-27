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
// admin, guardian0..2, lifeboat destination, mint authority, whale, attacker.
// Zero dependencies: only this repository's cloud/lib and Node's standard library.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { Rpc, key, findPda, concat, u64le, i64le, IDS, b58encode, decodeProtocol } from "../lib/solana.mjs";
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

async function rentFor(rpc, space) {
  return rpc.call("getMinimumBalanceForRentExemption", [space]);
}

async function newTokenAccount(rpc, payer, mint, owner) {
  const acc = Keypair.generate();
  await send(rpc, payer, [
    createAccount(payer.publicKey, acc.publicKey, await rentFor(rpc, 165), 165, IDS.token),
    initializeAccount3(acc.publicKey, mint, owner),
  ], [acc]);
  return acc.address;
}

// --- Bulkhead (Vault) and Harbor instructions ---------------------------------
// Account orders follow programs/vault/src and programs/harbor/src, and the
// builders in programs/tests/tests/common/vault.rs.
function harborIx(m, tag, args, harborAccounts, vaultAccounts) {
  return {
    programId: key(m.harbor),
    accounts: [r(m.vaultProgram), r(m.caller), ...harborAccounts, ...vaultAccounts],
    data: concat(Uint8Array.of(tag), args),
  };
}
const vaultIx = (m, tag, args, accounts) => ({ programId: key(m.vaultProgram), accounts, data: concat(Uint8Array.of(tag), args) });

function defaultLimits() {
  // docs/03 §1: 2%/hour, 5%/day, 6h minimum queue delay, no floors or caps.
  return concat(u16le(200), u32le(3_600), u16le(500), u32le(86_400), u32le(21_600), u64le(0), u64le(0), u64le(0), u64le(0));
}

function registerArgs(admin, guardians, destination) {
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
  mkdirSync(`${dir}/keys`, { recursive: true });
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
  };
}

async function fund(rpc, payer, to, lamports) {
  await send(rpc, payer, [{ programId: IDS.system, accounts: [s(payer.publicKey, true), w(to)], data: concat(u32le(2), u64le(lamports)) }]);
}

async function setup(url, dir, payerPath, vaultProgram, harbor) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const k = keysIn(dir);
  const step = (msg) => console.log(`== ${msg}`);

  step("funding the admin, guardians and whale (fees and rent)");
  for (const kp of [k.admin, ...k.guardians, k.whale]) await fund(rpc, payer, kp.publicKey, 50_000_000n);

  step("creating a test USDC mint (6 decimals, no freeze authority)");
  const mint = Keypair.generate();
  await send(rpc, payer, [
    createAccount(payer.publicKey, mint.publicKey, await rentFor(rpc, 82), 82, IDS.token),
    initializeMint2(mint.publicKey, 6, k.mintAuthority.publicKey),
  ], [mint]);

  const [caller] = await findPda(["bulkhead-caller"], harbor);
  const [protocol] = await findPda(["protocol", key(harbor)], vaultProgram);
  const [vault] = await findPda(["vault", protocol, mint.publicKey], vaultProgram);
  const [vaultTokens] = await findPda(["vault-tokens", protocol, mint.publicKey], vaultProgram);
  const m = { vaultProgram: key(vaultProgram), harbor: key(harbor), caller, protocol };

  step("registering Harbor with Bulkhead (the caller PDA is the registrar)");
  await send(rpc, payer, [harborIx(m, 0, registerArgs(k.admin.publicKey, k.guardians.map((g) => g.publicKey), k.destination.publicKey), [], [
    s(payer.publicKey, true), w(protocol), r(harbor), r(harbor), r(caller), r(IDS.system),
  ])]);

  step("creating the USDC vault with the default limits (2%/h, 5%/day)");
  await send(rpc, payer, [vaultIx(m, 1, defaultLimits(), [
    s(payer.publicKey, true), s(k.admin.publicKey), w(protocol), w(vault), w(vaultTokens), r(mint.publicKey), r(IDS.token), r(IDS.system),
  ])], [k.admin]);

  step("minting 10,000,000 test USDC to the whale and depositing it through Harbor");
  const whaleTokens = await newTokenAccount(rpc, payer, mint.publicKey, k.whale.publicKey);
  await send(rpc, payer, [mintTo(mint.publicKey, whaleTokens, k.mintAuthority.publicKey, TVL)], [k.mintAuthority]);
  const [backing] = await findPda(["backing", protocol, k.whale.publicKey], vaultProgram);
  await send(rpc, payer, [harborIx(m, 1, u64le(TVL), [s(k.whale.publicKey)], [
    r(protocol), w(vault), w(vaultTokens), r(mint.publicKey), w(whaleTokens), s(k.whale.publicKey), w(backing),
    s(payer.publicKey, true), r(IDS.token), r(IDS.system),
  ])], [k.whale]);

  step("an attacker token account (for the S1 run after the seal)");
  const attackerTokens = await newTokenAccount(rpc, payer, mint.publicKey, k.attacker.publicKey);

  step("proposing the seal: it can execute after the 72h loosen delay");
  const sealSig = await send(rpc, payer, [vaultIx(m, 4, new Uint8Array(0), [w(protocol), s(k.admin.publicKey)])], [k.admin]);

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
    sealProposal: sealSig,
  };
  writeFileSync(`${dir}/world.json`, JSON.stringify(world, null, 2) + "\n");
  const p = decodeProtocol((await rpc.account(protocol)).bytes);
  console.log(`protocol ${world.protocol}: sealed ${p.sealed}, vaults ${p.vaultCount}, guardians ${p.guardians.length} (quorum ${p.threshold})`);
  console.log(`seal proposed: ${sealSig}`);
  console.log(`world: ${dir}/world.json`);
}

async function seal(url, dir, payerPath) {
  const rpc = new Rpc(url);
  const payer = Keypair.load(payerPath);
  const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
  const m = { vaultProgram: key(world.vaultProgram) };
  const sig = await send(rpc, payer, [vaultIx(m, 5, new Uint8Array(0), [w(world.protocol), r(world.vault), r(world.vaultTokens)])]);
  console.log(`sealed: ${sig}`);
}

const [cmd, ...args] = process.argv.slice(2);
if (cmd === "setup" && args.length === 5) await setup(...args);
else if (cmd === "seal" && args.length === 3) await seal(...args);
else {
  console.error("usage: market.mjs setup <rpc> <dir> <payer.json> <vaultProgram> <harborProgram> | seal <rpc> <dir> <payer.json>");
  process.exit(2);
}
