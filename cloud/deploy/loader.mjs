#!/usr/bin/env node
// A zero-dependency loader-v3 deployer and verifier. It uses only
// sendTransaction, getSignatureStatuses, getLatestBlockhash,
// getMinimumBalanceForRentExemption and getProgramAccounts, so it keeps working
// when an RPC endpoint's account reads (getAccountInfo) are unavailable, which
// is what stopped the Solana CLI on public devnet on 27 Sep 2026.
//
//   node cloud/deploy/loader.mjs deploy   <rpc> <payer.json> <program-keypair.json> <program.so>
//   node cloud/deploy/loader.mjs deployed <rpc> <authority> <program-id>      # exit 0 if deployed
//   node cloud/deploy/loader.mjs verify   <rpc> <authority> <program-id>=<program.so> ...
//
// The payer becomes the upgrade authority. Verification requires each program's
// on-chain code to equal the local file, followed only by zero padding.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Rpc, key, findPda, concat, u64le, IDS, b58encode, compileMessage, serializeTransaction } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";

const CHUNK = 950; // bytes per Write: fits a 1,232-byte legacy transaction with room to spare
const BUFFER_HEADER = 37; // tag u32 + Option<authority>
const PROGRAM_SIZE = 36; // tag u32 + programdata address
const PROGRAMDATA_HEADER = 45; // tag u32 + slot u64 + Option<authority>

const u32le = (v) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
};
const w = (pubkey) => ({ pubkey: key(pubkey), writable: true });
const r = (pubkey) => ({ pubkey: key(pubkey) });
const s = (pubkey, writable = false) => ({ pubkey: key(pubkey), signer: true, writable });
const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

const createAccount = (from, account, lamports, space, owner) => ({
  programId: IDS.system,
  accounts: [s(from, true), s(account, true)],
  data: concat(u32le(0), u64le(lamports), u64le(space), key(owner)),
});
const initializeBuffer = (buffer, authority) => ({
  programId: IDS.loaderV3,
  accounts: [w(buffer), r(authority)],
  data: u32le(0),
});
const write = (buffer, authority, offset, bytes) => ({
  programId: IDS.loaderV3,
  accounts: [w(buffer), s(authority)],
  data: concat(u32le(1), u32le(offset), u64le(bytes.length), bytes),
});
const deployWithMaxDataLen = (payer, programdata, program, buffer, authority, maxLen) => ({
  programId: IDS.loaderV3,
  accounts: [s(payer, true), w(programdata), w(program), w(buffer), r(IDS.rent), r(IDS.clock), r(IDS.system), s(authority)],
  data: concat(u32le(2), u64le(maxLen)),
});

async function rent(rpc, space) {
  return rpc.call("getMinimumBalanceForRentExemption", [space]);
}

/** Signs and submits without waiting; returns the signature. */
async function submit(rpc, payer, instructions, blockhash) {
  const { message, signers } = compileMessage(payer.publicKey, instructions, blockhash);
  const sigs = signers.map(() => payer.sign(message)); // every Write is signed by the payer alone
  const tx = Buffer.from(serializeTransaction(message, sigs)).toString("base64");
  await rpc.call("sendTransaction", [tx, { encoding: "base64", skipPreflight: true, maxRetries: 5 }]);
  return b58encode(sigs[0]);
}

/** Writes every chunk, resending any not confirmed within ~40 s with a fresh blockhash. */
async function writeAll(rpc, payer, buffer, bytes) {
  const pending = new Map(); // offset -> { signature, sentAt }
  const todo = [];
  for (let o = 0; o < bytes.length; o += CHUNK) todo.push(o);
  let done = 0;
  for (let round = 0; todo.length && round < 8; round++) {
    const blockhash = await rpc.blockhash();
    const unsent = [];
    for (let i = 0; i < todo.length; i += 4) {
      await Promise.all(todo.slice(i, i + 4).map(async (o) => {
        try {
          pending.set(o, await submit(rpc, payer, [write(buffer, payer.publicKey, o, bytes.subarray(o, o + CHUNK))], blockhash));
        } catch {
          unsent.push(o); // rate limit or transient error: retry next round
        }
      }));
      await sleep(250); // stay well under public rate limits (with the Rpc throttle)
    }
    todo.length = 0;
    todo.push(...unsent);
    const deadline = Date.now() + 40_000;
    while (pending.size && Date.now() < deadline) {
      const entries = [...pending.entries()];
      for (let i = 0; i < entries.length; i += 200) {
        const batch = entries.slice(i, i + 200);
        const st = (await rpc.call("getSignatureStatuses", [batch.map(([, sig]) => sig)])).value;
        batch.forEach(([o], j) => {
          const x = st[j];
          if (x?.err) throw new Error(`write at offset ${o} failed: ${JSON.stringify(x.err)}`);
          if (x && (x.confirmationStatus === "confirmed" || x.confirmationStatus === "finalized")) {
            pending.delete(o);
            done++;
          }
        });
      }
      if (pending.size) await sleep(2_000);
    }
    process.stdout.write(`   ${done}/${Math.ceil(bytes.length / CHUNK)} chunks confirmed\n`);
    todo.push(...pending.keys()); // not confirmed in time: rewrite them (writes are idempotent)
    pending.clear();
  }
  if (todo.length) throw new Error(`${todo.length} chunks never confirmed`);
}

export async function deployProgram(rpc, payer, program, bytes) {
  const [programdata] = await findPda([program.publicKey], IDS.loaderV3);
  const buffer = Keypair.generate();
  console.log(`   buffer ${buffer.address}: ${bytes.length.toLocaleString()} bytes in ${Math.ceil(bytes.length / CHUNK)} writes`);
  await send(rpc, payer, [
    createAccount(payer.publicKey, buffer.publicKey, await rent(rpc, BUFFER_HEADER + bytes.length), BUFFER_HEADER + bytes.length, IDS.loaderV3),
    initializeBuffer(buffer.publicKey, payer.publicKey),
  ], [buffer], { skipPreflight: true });
  await writeAll(rpc, payer, buffer.publicKey, bytes);
  const sig = await send(rpc, payer, [
    createAccount(payer.publicKey, program.publicKey, await rent(rpc, PROGRAM_SIZE), PROGRAM_SIZE, IDS.loaderV3),
    deployWithMaxDataLen(payer.publicKey, programdata, program.publicKey, buffer.publicKey, payer.publicKey, bytes.length),
  ], [program], { skipPreflight: true });
  console.log(`   deployed ${program.address}: ${sig}`);
  return sig;
}

/** Every programdata account whose upgrade authority is `authority`, keyed by address. */
async function programdataOf(rpc, authority) {
  const res = await rpc.call("getProgramAccounts", [b58encode(IDS.loaderV3), {
    encoding: "base64",
    commitment: "confirmed", // a deploy that just landed counts (finalized lags ~13 s)
    filters: [{ memcmp: { offset: 0, bytes: b58encode(Uint8Array.of(3, 0, 0, 0)) } }, { memcmp: { offset: 13, bytes: authority } }],
  }]);
  return new Map(res.map((a) => [a.pubkey, Buffer.from(a.account.data[0], "base64")]));
}

async function main() {
  const [cmd, url, ...args] = process.argv.slice(2);
  const rpc = new Rpc(url);
  if (cmd === "deploy" && args.length === 3) {
    const [payerPath, programPath, soPath] = args;
    await deployProgram(rpc, Keypair.load(payerPath), Keypair.load(programPath), readFileSync(soPath));
    return 0;
  }
  if (cmd === "deployed" && args.length === 2) {
    const [authority, programId] = args;
    const [pd] = await findPda([key(programId)], IDS.loaderV3);
    return (await programdataOf(rpc, authority)).has(b58encode(pd)) ? 0 : 1;
  }
  if (cmd === "verify" && args.length >= 2) {
    const [authority, ...pairs] = args;
    const onchain = await programdataOf(rpc, authority);
    let bad = 0;
    for (const pair of pairs) {
      const [id, so] = pair.split("=");
      const local = readFileSync(so);
      const [pd] = await findPda([key(id)], IDS.loaderV3);
      const data = onchain.get(b58encode(pd));
      const code = data ? data.subarray(PROGRAMDATA_HEADER) : null;
      const ok = !!code && code.length >= local.length && code.subarray(0, local.length).equals(local) && code.subarray(local.length).every((b) => b === 0);
      bad += ok ? 0 : 1;
      const digest = createHash("sha256").update(local).digest("hex");
      console.log(`${ok ? "MATCH" : "MISMATCH"}  ${id}  ${so}  sha256 ${digest}${code ? ` (${local.length.toLocaleString()} bytes; ${(code.length - local.length).toLocaleString()} of padding)` : " (not deployed under this authority)"}`);
    }
    console.log(bad ? "VERIFICATION FAILED" : "VERIFIED: every program runs the code built from this checkout");
    return bad ? 1 : 0;
  }
  console.error("usage: loader.mjs deploy <rpc> <payer.json> <program-keypair.json> <program.so> | deployed <rpc> <authority> <id> | verify <rpc> <authority> <id>=<so> ...");
  return 2;
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1])).href) process.exit(await main());
