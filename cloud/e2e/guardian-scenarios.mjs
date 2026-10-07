#!/usr/bin/env node
// Guardian scenarios on a real validator, each one a bug this project found
// and fixed (docs/09). Run through cloud/e2e/guardian-scenarios.sh, which
// starts a fresh validator with the e2e world for each.
//
//   node cloud/e2e/guardian-scenarios.mjs <scenario> <world-dir> <rpc>
//
//   hold       a breach freeze is renewed before it ends, also by a guardian
//              restarted mid-incident, until a quorum unfreezes (finding 48)
//   restart    a guardian restarted after a quorum's unfreeze it missed does
//              not freeze again (finding 54)
//   failover   the primary RPC dies after startup; the guardian reads from the
//              backup and freezes the attack (finding 51)
//   approvals  a stolen admin key proposes first and takes the id the
//              operators expected; approvals name what a change does, so the
//              thief's change is vetoed and theirs is not (finding 61)
//   cursor     the node forgets the guardian's last signature on a quiet
//              protocol; the guardian reads on and freezes an attack (49).
//              Needs a validator with a small ledger (the .sh does that).
//
// Exits 0 on success; prints SCENARIO <name> PASSED or FAILED: <why>.
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { openSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { Rpc, decodeProtocol, decodeChange, findPda, key, u64le, concat, IDS } from "../lib/solana.mjs";
import { changeApproval } from "../guardian/policy.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { Keypair, send } from "../lib/signer.mjs";

const [scenario, dir, url] = process.argv.slice(2);
const world = JSON.parse(readFileSync(`${dir}/world.json`, "utf8"));
const rpc = new Rpc(url);
const vc = await new VaultClient(world.vaultProgram, world.harbor).init();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);
const frozenUntil = async () => decodeProtocol((await rpc.account(vc.protocol)).bytes).frozenUntil;
const logPath = `${dir}/guardian.log`;
const log = () => readFileSync(logPath, "utf8");
let guardian = null;

function fail(why) {
  console.log(`SCENARIO ${scenario} FAILED: ${why}`);
  guardian?.kill("SIGKILL");
  process.exit(1);
}

/** Writes the guardian config and starts it; resolves once it has caught up. */
async function startGuardian(extra = {}, { fresh = true } = {}) {
  if (fresh) {
    rmSync(logPath, { force: true });
    rmSync(`${dir}/guardian.json.state.json`, { force: true });
  }
  writeFileSync(`${dir}/guardian.json`, JSON.stringify({
    rpc: url, vaultProgram: world.vaultProgram, protocolProgram: world.harbor, mints: [world.mint],
    guardianKey: `${dir}/keys/guardian0.json`, pollMs: 300, ...extra,
  }));
  const before = fresh ? 0 : (log().match(/"msg":"caught up"/g) ?? []).length;
  const out = openSync(logPath, "a");
  guardian = spawn("node", ["cloud/guardian/main.mjs", `${dir}/guardian.json`], { stdio: ["ignore", out, out] });
  for (let i = 0; i < 240; i++) {
    if ((log().match(/"msg":"caught up"/g) ?? []).length > before) return;
    await sleep(500);
  }
  fail("the guardian did not catch up within 120 s");
}

function attack(count = 3) {
  const r = spawnSync("node", ["cloud/e2e/attack.mjs", `${dir}/world.json`, `${dir}/keys`, url, String(count), "100000000000", "800"], { encoding: "utf8" });
  if (r.status !== 0) fail(`the attack script failed: ${r.stderr.slice(0, 300)}`);
}

async function waitForFreeze(withinS) {
  const t0 = now();
  while (now() - t0 < withinS) {
    if ((await frozenUntil()) > now()) return now() - t0;
    await sleep(1000);
  }
  fail(`no freeze within ${withinS} s`);
}

/** The freeze ends seen until `count` distinct ones (each renewal moves it). */
async function freezeEnds(count, withinS) {
  const ends = [];
  const t0 = now();
  while (ends.length < count && now() - t0 < withinS) {
    const u = await frozenUntil();
    if (u > now() && u !== ends.at(-1)?.until) ends.push({ until: u, seenAt: now() });
    await sleep(1000);
  }
  if (ends.length < count) fail(`saw ${ends.length} freeze ends, wanted ${count}`);
  for (let i = 1; i < ends.length; i++) {
    if (ends[i].until <= ends[i - 1].until) fail(`freeze end ${i} did not move later`);
    if (ends[i].seenAt > ends[i - 1].until) fail(`renewal ${i} came after the freeze had ended`);
  }
  return ends;
}

async function quorumUnfreeze() {
  const g1 = Keypair.load(`${dir}/keys/guardian1.json`);
  const g2 = Keypair.load(`${dir}/keys/guardian2.json`);
  await send(rpc, g1, [vc.unfreeze([g1.publicKey, g2.publicKey])], [g2]);
}

async function staysUnfrozen(forS) {
  const t0 = now();
  while (now() - t0 < forS) {
    const u = await frozenUntil();
    if (u > now()) fail(`frozen again (until ${u}) after the quorum's unfreeze`);
    await sleep(2000);
  }
}

const HOLD = { policy: { freezeSecs: 60, holdRenewBeforeS: 30, holdIncidentS: 600 } };

const scenarios = {
  async hold() {
    await startGuardian(HOLD);
    attack();
    const first = await freezeEnds(2, 150);
    guardian.kill("SIGKILL");
    await startGuardian(HOLD, { fresh: false });
    if (!log().includes("incident hold resumed from saved state")) fail("the restarted guardian did not resume the incident");
    // The restarted guardian renews before the freeze it inherited ends.
    const old = first.at(-1).until;
    for (;;) {
      const u = await frozenUntil();
      if (u > old) break;
      if (now() > old) fail("the freeze ran out before the restarted guardian renewed it");
      await sleep(1000);
    }
    await quorumUnfreeze();
    await staysUnfrozen(90);
  },

  async restart() {
    await startGuardian(HOLD);
    attack();
    const ends = await freezeEnds(2, 150);
    guardian.kill("SIGKILL");
    await quorumUnfreeze();
    while (now() <= ends.at(-1).until + 5) await sleep(1000);
    await startGuardian(HOLD, { fresh: false });
    await staysUnfrozen(75);
  },

  async failover() {
    // The primary is a proxy to the validator, killed once the guardian runs.
    const proxy = createServer(async (req, res) => {
      let body = "";
      for await (const c of req) body += c;
      const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(await r.text());
    });
    await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
    const primary = `http://127.0.0.1:${proxy.address().port}`;
    await startGuardian({ rpc: primary, rpcs: [url] });
    proxy.closeAllConnections();
    proxy.close();
    await sleep(2000);
    attack();
    await waitForFreeze(120);
    if (!/is failing; now using/.test(log())) fail("the switch to the backup endpoint was not logged");
  },

  async approvals() {
    const admin = Keypair.load(`${dir}/keys/admin.json`);
    const fresh = Keypair.generate().address;
    const thief = Keypair.generate().address;
    // The operators approve rotating the admin to `fresh`, by what it does.
    await startGuardian({ policy: { approvedChanges: [changeApproval({ kind: 3, target: fresh, payload: new Uint8Array(0) })] } });
    const first = decodeProtocol((await rpc.account(vc.protocol)).bytes).nextChangeId;
    const change = async (id) => (await findPda(["change", vc.protocol, u64le(id)], vc.program))[0];
    const propose = async (id, target) => send(rpc, admin, [{
      programId: vc.program,
      data: concat(Uint8Array.of(18, 3), key(target)),
      accounts: [
        { pubkey: admin.publicKey, signer: true, writable: true }, { pubkey: admin.publicKey, signer: true },
        { pubkey: vc.protocol, writable: true }, { pubkey: await change(id), writable: true }, { pubkey: IDS.system },
      ],
    }]);
    // The thief proposes first and gets the id the operators expected.
    await propose(first, thief);
    await propose(first + 1n, fresh);
    const read = async (id) => decodeChange((await rpc.account(await change(id))).bytes);
    const t0 = now();
    while (!(await read(first)).vetoed) {
      if (now() - t0 > 90) fail(`the thief's change ${first} was not vetoed within 90 s`);
      await sleep(1000);
    }
    // Past the guardian's account scan (every 60 s), the approved one stands.
    while (now() - t0 < 75) await sleep(1000);
    const ours = await read(first + 1n);
    if (ours.vetoed) fail(`the approved change ${first + 1n} was vetoed`);
    if (ours.target !== fresh) fail("read the wrong change");
  },

  async cursor() {
    await startGuardian();
    const t0 = now();
    while (!/no longer has the cursor/.test(log())) {
      if (now() - t0 > 1800) fail("the node never forgot the cursor in 30 min (is the ledger limit set?)");
      await sleep(5000);
    }
    attack();
    await waitForFreeze(120);
  },
};

if (!scenarios[scenario]) fail(`unknown scenario (one of ${Object.keys(scenarios).join(", ")})`);
await scenarios[scenario]();
guardian?.kill("SIGKILL");
console.log(`SCENARIO ${scenario} PASSED`);
process.exit(0);
