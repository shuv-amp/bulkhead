#!/usr/bin/env node
// Stops a program under Floor, now, and keeps at it until it has stopped.
//
//   node cloud/guardian/stop.mjs <guardian-config.json> <protected-program> [--max-seconds 900]
//
// The guardian bot never stops a program on its own: a stop is a person's
// decision. This is the tool for that moment. It uses the guardian's config
// (rpc, rpcs, guardianKey, floorProgram) and:
//   - reads Floor's config fresh before every attempt, so it names the abort
//     buffer and the current snapshot pin (anyone may re-pin; finding 66);
//   - sizes the compute budget to the program (a stop of a 10 MiB program
//     costs ~132k CU, above the guardian's usual 50k; sized again before every
//     attempt, since anyone may extend the program) and takes its priority
//     price from recent fees on the program's accounts (never below 10,000
//     µL/CU), doubling it after each
//     attempt that lost its slot, up to --max-micro-lamports;
//   - sends to every endpoint without preflight and re-sends every slot.
//     Anyone may extend the program, and loader-v3 refuses an upgrade (a stop
//     is one) in a slot where it was extended: an attacker can hold a stop off,
//     slot by slot, until the program reaches 10 MiB (finding 77). Re-sending
//     each slot, at a rising price, is how the stop wins a slot;
//   - stops when Floor's config says the program is stopped, and then checks
//     that a call to the program fails with Floor's code ("FLOR").
// Exit 0: stopped (by us or someone else). 1: gave up (time limit). 2: this
// key cannot stop it (not a live guardian, no abort buffer, no config).
import { readFileSync } from "node:fs";
import { Rpc, FailoverRpc, key, b58encode, decodeFloor } from "../lib/solana.mjs";
import { Keypair, send, priorityPrice } from "../lib/signer.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";

const argv = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = argv.indexOf(name);
  if (i < 0) return dflt;
  const v = Number(argv[i + 1]);
  // A flag with no number used to give NaN, and a time limit that never ran out.
  if (!Number.isFinite(v) || v <= 0) {
    console.error(`${name} needs a positive number`);
    process.exit(2);
  }
  return v;
};
const [configPath, protectedProgram] = argv;
if (!configPath || !protectedProgram) {
  console.error("usage: stop.mjs <guardian-config.json> <protected-program> [--max-seconds 900] [--max-micro-lamports 2000000]");
  process.exit(2);
}
const maxSeconds = flag("--max-seconds", 900);
const maxMicroLamports = flag("--max-micro-lamports", 2_000_000);
const cfg = JSON.parse(readFileSync(configPath, "utf8"));
if (!cfg.floorProgram) {
  console.error("the config has no floorProgram");
  process.exit(2);
}
// Reads go to the next endpoint when one cannot answer, as the guardian's do:
// the primary alone used to decide, and one refused read ended the stop
// before anything was sent (docs/09, finding 85).
const rpc = cfg.rpcs?.length
  ? new FailoverRpc([cfg.rpc, ...cfg.rpcs], { onSwitch: (from, to, e) => console.log(JSON.stringify({ t: new Date().toISOString(), level: "warn", msg: `RPC ${new URL(from).host} failing; now using ${new URL(to).host}`, cause: e?.message?.slice(0, 120) })) })
  : new Rpc(cfg.rpc);
const backups = (cfg.rpcs ?? []).map((u) => new Rpc(u));
const guardian = Keypair.load(cfg.guardianKey);
const fc = await new FloorClient(cfg.floorProgram, protectedProgram).init();

const FLOR = 0x464c4f52; // the abort binary's error code
const NOT_LIVE_GUARDIAN = 7014;
const NOT_LIVE = 7016;
const NO_ABORT_BUFFER = 7019;
const SNAPSHOT_MISMATCH = 7023;

const log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o }));
const started = Date.now();
const slotAtStart = await rpc.call("getSlot", [{ commitment: "processed" }]).catch(() => null);

async function readConfig() {
  const acc = await rpc.account(fc.config);
  if (!acc) {
    log({ level: "error", msg: "no Floor config for this program" });
    process.exit(2);
  }
  return decodeFloor(acc.bytes);
}

/**
 * A call to the stopped program fails with Floor's code. While someone keeps
 * extending it, a call in a slot with an extension fails with
 * `UnsupportedProgramId` instead (the loader re-deploys it, visible from the
 * next slot): the old code does not run then either (measured: 26 of 30 calls
 * during a flood, FLOR on all 30 once it ended; finding 77).
 */
async function verifyStopped() {
  const sim = await rpc.simulate(guardian.publicKey, [{ programId: key(protectedProgram), accounts: [], data: new Uint8Array(0) }]);
  const err = JSON.stringify(sim.err ?? null);
  if (err.includes(String(FLOR))) return "FLOR";
  if (err.includes("UnsupportedProgramId")) return "extended";
  return null;
}

/**
 * Compute for the stop: grows with the program data it scans (measured:
 * ~10k CU at 200 KB, 132,080 at 10 MiB). Read again before every attempt:
 * anyone may extend the program meanwhile, and a budget sized once made
 * every later attempt run out of compute (docs/09, finding 85). 1.5x the
 * measured slope, never below 60,000; unknown size: the most a transaction
 * may ask.
 */
async function computeFor() {
  const pd = await rpc.call("getAccountInfo", [b58encode(fc.programdata), { encoding: "base64", commitment: "confirmed", dataSlice: { offset: 0, length: 0 } }]).catch(() => null);
  const size = pd?.value?.space;
  if (size == null) return 1_400_000;
  return Math.min(1_400_000, Math.max(60_000, 30_000 + Math.ceil((size * 3) / 200)));
}

async function basePrice() {
  const fees = await rpc.call("getRecentPrioritizationFees", [[protectedProgram]]).catch(() => []);
  return Math.max(10_000, priorityPrice(fees, { percentile: 0.9, cap: maxMicroLamports }));
}

const codeOf = (e) => {
  const m = /"Custom":(\d+)/.exec(e?.message ?? "") ?? /"Custom":(\d+)/.exec(JSON.stringify(e?.rpcError?.data?.err ?? ""));
  return m ? Number(m[1]) : null;
};

let price = await basePrice();
let units = await computeFor();
let attempts = 0;
let lostSlots = 0;
log({ msg: "stopping", program: protectedProgram, guardian: b58encode(guardian.publicKey), computeUnits: units, microLamports: price });
for (;;) {
  // A read that fails costs this round, not the stop: the time limit below
  // still bounds the whole (finding 85).
  let c;
  try {
    c = await readConfig();
  } catch (e) {
    if ((Date.now() - started) / 1000 > maxSeconds) {
      log({ level: "error", msg: "gave up: Floor's config could not be read within the time limit", error: String(e.message).slice(0, 160) });
      process.exit(1);
    }
    log({ level: "warn", msg: "could not read Floor's config; trying again", error: String(e.message).slice(0, 160) });
    await new Promise((r) => setTimeout(r, 400));
    continue;
  }
  if (c.status === "aborted") {
    // New code is visible from the slot after the upgrade: wait for a call to
    // the program to fail with Floor's code before calling it stopped.
    let seen = null;
    for (let i = 0; i < 25; i++) {
      seen = await verifyStopped().catch(() => null);
      if (seen === "FLOR") break;
      await new Promise((r) => setTimeout(r, 400));
    }
    const slot = await rpc.call("getSlot", [{ commitment: "confirmed" }]).catch(() => null);
    const msg = seen === "FLOR"
      ? "stopped: calls now fail with FLOR"
      : seen === "extended"
        ? "stopped: the abort code is installed; someone is still extending the program, so calls fail with UnsupportedProgramId (the old code cannot run)"
        : "Floor says stopped, but calls did not fail as expected within 10 s: check the program";
    log({ msg, attempts, lostSlots, seconds: (Date.now() - started) / 1000, slots: slot != null && slotAtStart != null ? slot - slotAtStart : null });
    process.exit(seen ? 0 : 1);
  }
  if (!c.abortBuffer) {
    log({ level: "error", msg: "no abort buffer staged: no one can stop this program until one is (stage_abort)" });
    process.exit(2);
  }
  if ((Date.now() - started) / 1000 > maxSeconds) {
    log({ level: "error", msg: "gave up: not stopped within the time limit", attempts, lostSlots });
    process.exit(1);
  }
  attempts++;
  if (attempts > 1) units = await computeFor();
  if (attempts === 1) {
    // Without a preflight, a key that cannot pay or is not a live guardian
    // looked like a lost slot for the whole time limit: ask once, by
    // simulation, and say so at once (docs/09, finding 85).
    const sim = await rpc.simulate(guardian.publicKey, [fc.abort(guardian.publicKey, key(c.abortBuffer), c.snapshotBuffer ? key(c.snapshotBuffer) : null)]).catch(() => null);
    const err = sim?.err;
    const custom = err?.InstructionError?.[1]?.Custom;
    if (err === "InsufficientFundsForFee" || err === "AccountNotFound") {
      log({ level: "error", msg: `this key cannot pay for the stop (${JSON.stringify(err)}): fund ${b58encode(guardian.publicKey)}` });
      process.exit(2);
    }
    if (custom === NOT_LIVE_GUARDIAN || custom === NO_ABORT_BUFFER) {
      log({ level: "error", msg: custom === NOT_LIVE_GUARDIAN ? "this key is not a live guardian here (or is the owner while a quorum is live)" : "no abort buffer staged", code: custom });
      process.exit(2);
    }
  }
  try {
    const sig = await send(rpc, guardian, [fc.abort(guardian.publicKey, key(c.abortBuffer), c.snapshotBuffer ? key(c.snapshotBuffer) : null)], [], {
      skipPreflight: true,
      computeUnits: units,
      microLamports: price,
      rpcs: backups,
      rebroadcastMs: 400,
      confirmMs: 4_000,
    });
    log({ msg: "stop landed", signature: sig, attempt: attempts });
  } catch (e) {
    const code = codeOf(e);
    if (code === NOT_LIVE) continue; // someone else stopped it: the next read says so
    if (code === NOT_LIVE_GUARDIAN || code === NO_ABORT_BUFFER) {
      log({ level: "error", msg: code === NOT_LIVE_GUARDIAN ? "this key is not a live guardian here (or is the owner while a quorum is live)" : "no abort buffer staged", code });
      process.exit(2);
    }
    if (code === SNAPSHOT_MISMATCH) {
      log({ level: "warn", msg: "the snapshot pin moved; re-reading and trying again", attempt: attempts });
      continue;
    }
    // Lost the slot (an extension in it, InvalidArgument), dropped, or expired:
    // try the next slot at a higher price.
    lostSlots++;
    price = Math.min(maxMicroLamports, price * 2);
    log({ level: "warn", msg: "stop did not land; again next slot at a higher price", attempt: attempts, microLamports: price, error: String(e.message ?? e).slice(0, 160) });
  }
}
