// Fresh recipients: unbacked payouts to owners first seen on chain just
// before (stolen funds went to addresses minutes old in the Oct 2026 Binance
// theft) alert, and, with freshRecipientWeight above 1, count more toward the
// freeze rules. The signal only ever adds caution.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { b58encode, key, SYSVAR_OWNER } from "../lib/solana.mjs";
import { VaultClient } from "../lib/bulkhead.mjs";
import { Keypair } from "../lib/signer.mjs";
import {
  assess, newState, checkPolicy, DEFAULT_POLICY, HOUR_S, GENESIS,
  recipientFirstSeen, recipientFreshness, needsLookup, freshCandidate, freshLookups, readyPayouts, freshRecipientCheck,
  FRESH_LOOKUP_LIMIT, FRESH_RETRY_S,
} from "../guardian/policy.mjs";
import { alertFor } from "../guardian/alert.mjs";
import { accountInfo, clockBytes, protocolBytes, rpcServer } from "./chain-fixtures.mjs";

const MINT = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";
const NEW = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const OLD = "8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb";
const VAULT = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";
// worst_1h 1,000,000: the 1-hour freeze threshold is 500,000.
const FIG = { worst1h: 1_000_000n, worst24h: 2_500_000n };
const release = (owner, instant, at) => ({ kind: "released", mint: MINT, owner, backed: 0n, instant, queued: 0n, ticketId: 0n, etaS: 0, at });
const DAY = 86_400;

test("one page of signatures dates an owner when it holds the whole history, bounds it when full", () => {
  assert.deepEqual(recipientFirstSeen([{ blockTime: 900 }, { blockTime: 500 }], 100, 1_000), { status: "dated", firstS: 500, exact: true, checkedS: 1_000 });
  assert.deepEqual(recipientFirstSeen([], 100, 1_000), { status: "dated", firstS: 1_000, exact: true, checkedS: 1_000 }, "nothing before the check");
  const full = Array.from({ length: 3 }, (_, i) => ({ blockTime: 900 - i }));
  assert.equal(recipientFirstSeen(full, 3, 1_000).exact, false);
  assert.equal(recipientFirstSeen(null, 100, 1_000).status, "unknown");
  assert.equal(recipientFirstSeen([{ blockTime: null }], 100, 1_000).status, "unknown");
});

test("an owner is fresh only on a whole history inside the window; a full page proves old, never fresh", () => {
  const dated = (firstS, exact = true) => ({ status: "dated", firstS, exact, checkedS: 0 });
  assert.equal(recipientFreshness(dated(10_000), 10_060, DAY), "fresh");
  assert.equal(recipientFreshness(dated(10_000), 10_000 + DAY, DAY), "old");
  assert.equal(recipientFreshness(dated(10_000, false), 10_060, DAY), "unknown", "busy: its newest page is all inside the window");
  assert.equal(recipientFreshness(dated(10_000, false), 10_000 + 2 * DAY, DAY), "old");
  assert.equal(recipientFreshness({ status: "unknown", checkedS: 0 }, 5, DAY), "unknown");
  assert.equal(recipientFreshness(undefined, 5, DAY), null, "not looked up: not counted");
  assert.equal(recipientFreshness(dated(10_000), 10_060, 0), null, "the signal off");
  assert.equal(needsLookup(undefined, 0), true);
  assert.equal(needsLookup({ status: "unknown", checkedS: 0 }, FRESH_RETRY_S - 1), false);
  assert.equal(needsLookup({ status: "unknown", checkedS: 0 }, FRESH_RETRY_S), true);
  assert.equal(needsLookup(dated(1), 1e12), false, "an age is never asked again");
});

test("only an unbacked payout to a named, non-allowlisted owner is looked up", () => {
  assert.equal(freshCandidate(release(NEW, 5n, 0)), true);
  assert.equal(freshCandidate({ ...release(NEW, 0n, 0), backed: 9n }), false, "backed only");
  assert.equal(freshCandidate(release("(truncated log)", 5n, 0)), false);
  assert.equal(freshCandidate(release(NEW, 5n, 0), { ...DEFAULT_POLICY, allowlistedOwners: [NEW] }), false);
  assert.equal(freshCandidate(release(NEW, 5n, 0), { ...DEFAULT_POLICY, freshRecipientAgeS: 0 }), false);
});

test("the fresh-recipient keys are checked like every policy value", () => {
  assert.doesNotThrow(() => checkPolicy({ ...DEFAULT_POLICY }));
  assert.doesNotThrow(() => checkPolicy({ ...DEFAULT_POLICY, freshRecipientWeight: 2.5, freshRecipientUnknownIsFresh: true, freshRecipientAgeS: 0 }));
  for (const [k, v, why] of [["freshRecipientWeight", 0.5, /from 1 to 10/], ["freshRecipientWeight", 11, /from 1 to 10/], ["freshRecipientWeight", "2", /from 1 to 10/],
    ["freshRecipientAgeS", -1, /whole number from 0/], ["freshRecipientAgeS", 1.5, /whole number/], ["freshRecipientAlertFraction", 10, /fraction/],
    ["freshRecipientUnknownIsFresh", "yes", /true or false/], ["freshRecipientLookupsPerPass", 0, /from 1 to 64/]]) {
    assert.throws(() => checkPolicy({ ...DEFAULT_POLICY, [k]: v }), why, `${k} = ${JSON.stringify(v)}`);
  }
});

test("by default a payout to a fresh recipient alerts once per window and never freezes", () => {
  const s = newState();
  const ages = new Map([[NEW, { status: "dated", firstS: 990, exact: true }], [OLD, { status: "dated", firstS: -10 * DAY, exact: true }]]);
  const freshOf = (o, t) => recipientFreshness(ages.get(o), t, DEFAULT_POLICY.freshRecipientAgeS);
  const at = (owner, amount, t) => {
    assert.deepEqual(assess(s, release(owner, amount, t), { ...FIG, now: t }), []);
    return freshRecipientCheck(s, MINT, { ...FIG, now: t }, DEFAULT_POLICY, freshOf);
  };
  assert.deepEqual(at(OLD, 400_000n, 1_000), [], "an old owner: nothing, however much");
  // Bar: 0.1 × 500,000 = 50,000 in the hour.
  assert.deepEqual(at(NEW, 40_000n, 1_010), []);
  const [alert, ...rest] = at(NEW, 20_000n, 1_020);
  assert.deepEqual(rest, []);
  assert.equal(alert.code, "fresh_recipient");
  assert.match(alert.msg, /^unbacked outflow to fresh recipients: 60000 in the last hour and 60000 in 24 hours went to owners first seen on chain under 86400s before/);
  assert.match(alert.msg, /freezes only past the thresholds \(freshRecipientWeight 1\)/);
  assert.ok(alertFor({ level: "warn", msg: alert.msg, mint: MINT }, new Map(), 0), "an urgent warning");
  assert.deepEqual(at(NEW, 30_000n, 1_030), [], "once per outflowAlertEveryS");
  assert.equal(at(NEW, 60_000n, 1_030 + 6 * HOUR_S).length, 1, "and again once the window has passed");
});

test("with a weight, outflow to fresh recipients counts that many times toward the freeze rules", () => {
  const policy = { ...DEFAULT_POLICY, freshRecipientWeight: 2 };
  const ages = new Map([[NEW, { status: "dated", firstS: 990, exact: true }], [OLD, { status: "dated", firstS: -10 * DAY, exact: true }]]);
  const freshOf = (o, t) => recipientFreshness(ages.get(o), t, policy.freshRecipientAgeS);
  // 250,000 to an old owner: half the threshold, nothing.
  const s = newState();
  assess(s, release(OLD, 250_000n, 1_000), { ...FIG, now: 1_000 }, policy);
  assert.deepEqual(freshRecipientCheck(s, MINT, { ...FIG, now: 1_000 }, policy, freshOf).filter((a) => a.type), []);
  // 250,000 to a fresh one counts 500,000: the threshold.
  const t = newState();
  assess(t, release(NEW, 250_000n, 1_000), { ...FIG, now: 1_000 }, policy);
  const [freeze] = freshRecipientCheck(t, MINT, { ...FIG, now: 1_000 }, policy, freshOf).filter((a) => a.type);
  assert.equal(freeze.type, "freeze");
  assert.equal(freeze.secs, policy.freezeSecs);
  assert.match(freeze.reason, /in the last hour: 500000 ≥ 500000 .*counted 2× \(freshRecipientWeight\)/);
  assert.equal(t.freezing, true);
  assert.deepEqual(freshRecipientCheck(t, MINT, { ...FIG, now: 1_001 }, policy, freshOf).filter((a) => a.type), [], "a freeze already on its way");
  const frozen = newState();
  frozen.frozenUntil = 5_000;
  assess(frozen, release(NEW, 250_000n, 1_000), { ...FIG, now: 1_000 }, policy);
  assert.deepEqual(freshRecipientCheck(frozen, MINT, { ...FIG, now: 1_000 }, policy, freshOf).filter((a) => a.type), [], "already frozen");
});

test("an unknown age counts as fresh only when configured; one not looked up never counts", () => {
  const ages = new Map([[NEW, { status: "unknown", why: "no signature list", checkedS: 1_000 }]]);
  const check = (policy) => {
    const s = newState();
    assess(s, release(NEW, 250_000n, 1_000), { ...FIG, now: 1_000 }, policy);
    assess(s, release(OLD, 1n, 1_000), { ...FIG, now: 1_000 }, policy);
    return freshRecipientCheck(s, MINT, { ...FIG, now: 1_000 }, policy, (o, t) => recipientFreshness(ages.get(o), t, policy.freshRecipientAgeS)).map((a) => a.type ?? a.code);
  };
  assert.deepEqual(check({ ...DEFAULT_POLICY, freshRecipientWeight: 2 }), []);
  assert.deepEqual(check({ ...DEFAULT_POLICY, freshRecipientWeight: 2, freshRecipientUnknownIsFresh: true }), ["freeze", "fresh_recipient"]);
});

test("the fresh-recipient rule never raises a threshold, delays or holds back a freeze (random payouts)", () => {
  // Whatever each owner's age and whatever the settings, the first freeze
  // comes no later than the rules alone make it.
  let seed = 7;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed % n; };
  const owners = [NEW, OLD, MINT, VAULT];
  for (let run = 0; run < 300; run++) {
    const policy = { ...DEFAULT_POLICY, freshRecipientWeight: 1 + rand(10), freshRecipientUnknownIsFresh: rand(2) === 1, freshRecipientAlertFraction: rand(3) / 4 };
    const verdict = new Map(owners.map((o) => [o, ["fresh", "old", "unknown", null][rand(4)]]));
    const payouts = Array.from({ length: 12 }, (_, i) => release(owners[rand(4)], BigInt(1 + rand(120_000)), 1_000 + i * rand(900)));
    const firstFreeze = (withFresh) => {
      const s = newState();
      for (const [i, e] of payouts.entries()) {
        const ctx = { ...FIG, now: e.at };
        const actions = assess(s, e, ctx, policy);
        if (withFresh) actions.push(...freshRecipientCheck(s, MINT, ctx, policy, (o) => verdict.get(o)));
        if (actions.some((a) => a.type === "freeze")) return i;
      }
      return Infinity;
    };
    assert.ok(firstFreeze(true) <= firstFreeze(false), `run ${run}`);
  }
});

test("lookups are bounded, deduplicated and never repeated while in flight; the queue cannot grow without bound", () => {
  const pending = [NEW, NEW, OLD, MINT, VAULT].map((owner, i) => ({ mint: MINT, owner, t: i }));
  const ages = new Map([[VAULT, { status: "dated", firstS: 0, exact: true }]]);
  assert.deepEqual(freshLookups(pending, ages, new Set(), 100, 2), [NEW, OLD]);
  assert.deepEqual(freshLookups(pending, ages, new Set([NEW]), 100, 2), [OLD], "one in flight leaves room for one");
  assert.deepEqual(freshLookups(pending, ages, new Set(), 100, 8), [NEW, OLD, MINT], "a dated owner is never looked up again");
  const { ready, waiting } = readyPayouts(pending, ages, new Set(), 100);
  assert.deepEqual(ready.map((p) => p.owner), [VAULT]);
  assert.equal(waiting.length, 4);
  // Past the cap, the oldest waiting are judged now, as unknown, never old.
  const capped = readyPayouts(pending, new Map(), new Set(), 100, 2);
  assert.deepEqual(capped.ready.map((p) => p.owner), [NEW, NEW, OLD]);
  assert.deepEqual(capped.waiting.map((p) => p.owner), [MINT, VAULT]);
});

// The guardian end to end: a payout of 100,000 (a fifth of the 1-hour
// threshold) to an owner whose only signature is two minutes old.
async function runGuardian(policy, until, killMs = 40_000) {
  const vc = await new VaultClient(VAULT, OLD).init();
  const protocol = b58encode(vc.protocol);
  const now = Math.floor(Date.now() / 1000);
  const b64 = (b) => Buffer.from(b).toString("base64");
  const amounts = new Uint8Array(40);
  new DataView(amounts.buffer).setBigUint64(8, 100_000n, true); // instant
  const event = [new TextEncoder().encode("vault:released"), key(MINT), key(NEW), amounts, new Uint8Array(32), vc.protocol].map(b64).join(" ");
  const ret = new Uint8Array(64);
  new DataView(ret.buffer).setBigUint64(8, FIG.worst1h, true);
  new DataView(ret.buffer).setBigUint64(16, FIG.worst24h, true);
  const SIG = "4".repeat(87);
  let frozenUntil = 0;
  let listed = 0;
  const node = await rpcServer((method, params) => {
    switch (method) {
      case "getGenesisHash": return GENESIS.devnet;
      case "getBalance": return { value: 1e9 };
      case "getLatestBlockhash": return { value: { blockhash: OLD, lastValidBlockHeight: 1e9 } };
      case "getBlockHeight": return 1;
      case "getRecentPrioritizationFees": return [];
      case "getProgramAccounts": return [];
      case "simulateTransaction": return { value: { err: null, logs: [], returnData: { programId: VAULT, data: [b64(ret), "base64"] }, accounts: [{ owner: SYSVAR_OWNER, data: [b64(clockBytes(now)), "base64"] }] } };
      case "getAccountInfo": return params[0] === protocol ? accountInfo(protocolBytes({ frozenUntil }), VAULT, 5) : accountInfo(null);
      case "sendTransaction":
        frozenUntil = now + DAY; // the freeze lands
        return SIG;
      case "getSignatureStatuses": return { value: params[0].map(() => ({ confirmationStatus: "confirmed", err: null })) };
      case "getSignaturesForAddress":
        if (params[0] === NEW) return [{ signature: "2".repeat(87), slot: 9, blockTime: now - 120, err: null }];
        if (params[0] !== protocol || params[1]?.until === SIG || listed++ === 0) return [];
        return [{ signature: SIG, slot: 10, blockTime: now, err: null }];
      case "getTransaction":
        return { slot: 10, blockTime: now, meta: { err: null, logMessages: [`Program ${VAULT} invoke [1]`, `Program data: ${event}`, `Program ${VAULT} success`], preTokenBalances: [], postTokenBalances: [], innerInstructions: [] }, transaction: { message: { accountKeys: [], instructions: [] } } };
      default: return null;
    }
  });
  const dir = mkdtempSync(`${tmpdir()}/bh-fresh-`);
  const keyPath = `${dir}/guardian.json`;
  Keypair.generate().save(keyPath);
  const cfgPath = `${dir}/g.json`;
  writeFileSync(cfgPath, JSON.stringify({ rpc: node.url, cluster: "devnet", vaultProgram: VAULT, protocolProgram: OLD, mints: [MINT], guardianKey: keyPath, stateFile: `${dir}/state.json`, policy }));
  const main = fileURLToPath(new URL("../guardian/main.mjs", import.meta.url));
  const child = spawn(process.execPath, [main, cfgPath], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const timer = setTimeout(() => child.kill(), killMs);
  for (const s of [child.stdout, child.stderr]) s.on("data", (c) => { out += c; if (until.test(out)) child.kill(); });
  await new Promise((r) => child.on("exit", r));
  clearTimeout(timer);
  node.close();
  return { out, lines: out.split("\n").filter((l) => l.startsWith("{")).flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } }), lookups: node.calls.filter(([m, p]) => m === "getSignaturesForAddress" && p[0] === NEW) };
}

test("the guardian looks a payout's recipient up in the background, alerts on a fresh one, and does not freeze by default", async () => {
  const { out, lines, lookups } = await runGuardian({}, /unbacked outflow to fresh recipients.*\n/);
  const payout = lines.find((l) => l.event === "released");
  const fresh = lines.find((l) => l.msg === "payout to a fresh recipient");
  const alert = lines.find((l) => l.alert === "fresh_recipient");
  assert.ok(payout && fresh && alert, out);
  assert.equal(fresh.owner, NEW);
  assert.equal(alert.level, "warn");
  assert.match(alert.msg, /100000 in the last hour/);
  assert.deepEqual(lookups.map(([, p]) => p[1].limit), [FRESH_LOOKUP_LIMIT], "one page, once");
  assert.ok(!lines.some((l) => l.action === "freeze"), out);
});

test("with freshRecipientWeight 5, the same payout freezes, and says why", async () => {
  const { out, lines } = await runGuardian({ freshRecipientWeight: 5, freezeDeadlineS: 10 }, /"action":"freeze".*\n/);
  const freeze = lines.find((l) => l.action === "freeze");
  assert.ok(freeze?.signature, out);
  assert.match(freeze.reason, /in the last hour: 500000 ≥ 500000 \(0\.5 × worst_1h\), outflow to recipients first seen in the last 86400s counted 5× \(freshRecipientWeight\)/);
  // The rules alone did not freeze it: 100,000 is a fifth of the threshold.
  const event = lines.findIndex((l) => l.event === "released");
  assert.ok(lines.findIndex((l) => l.msg === "payout to a fresh recipient") > event, "decided once the lookup returned");
});
