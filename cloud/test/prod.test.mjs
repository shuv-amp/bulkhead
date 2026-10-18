// Production readiness (docs/09, finding 83): config checks, alert delivery,
// rate limits, the startup replay and the state file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPolicy, checkConfig, DEFAULT_POLICY } from "../guardian/policy.mjs";
import { alerter } from "../guardian/alert.mjs";
import { restoreState } from "../guardian/statefile.mjs";
import { signatureWalk, transactionOrSkip } from "../guardian/follow.mjs";
import { retryWaitMs } from "../lib/solana.mjs";
import { newState } from "../guardian/policy.mjs";

const KEY = "11111111111111111111111111111112";
const base = { rpc: "https://primary.example", vaultProgram: KEY, protocolProgram: KEY, mints: [KEY], guardianKey: "/etc/bulkhead/keys/g.json" };
const policy = (over) => checkPolicy({ ...DEFAULT_POLICY, ...over });

test("a policy typo, a percent for a fraction or a string for seconds stops the start (finding 83)", () => {
  assert.doesNotThrow(() => policy({}));
  assert.throws(() => policy({ freezeFractionOfWorst1H: 0.5 }), /not a policy setting/);
  // Parsed from JSON, as the config is: each name is the object's own key.
  for (const k of ["constructor", "__proto__", "toString"]) assert.throws(() => policy(JSON.parse(`{"${k}": 1}`)), /not a policy setting/, k);
  assert.throws(() => policy({ freezeFractionOfWorst1h: 50 }), /fraction/);
  assert.throws(() => policy({ freezeFractionOfWorst24h: 0 }), /fraction in \(0, 1\]/);
  assert.doesNotThrow(() => policy({ freezeFractionOfWorst72h: 0 }), "0 turns the 72h rule off");
  // "24h" made the next heartbeat NaN: none was ever sent again.
  assert.throws(() => policy({ heartbeatEveryS: "24h" }), /whole number/);
  assert.throws(() => policy({ heartbeatEveryS: 0 }), /whole number from 3600/, "a heartbeat every poll");
  assert.throws(() => policy({ freezeSecs: 90_000 }), /86400/, "the program refuses a freeze over 24h");
  assert.throws(() => policy({ allowlistedOwners: "treasury" }), /base58/, "a string was matched as a substring");
  assert.throws(() => policy({ priorityMicroLamports: "high" }), /auto/);
  assert.throws(() => policy({ minPriorityMicroLamports: 2_000_000 }), /must not exceed/);
  assert.throws(() => policy({ holdRenewBeforeS: 86_400 }), /shorter than freezeSecs/);
});

test("a mainnet config needs backups and alerts; unknown settings are refused (finding 83)", () => {
  assert.deepEqual(checkConfig({ ...base, cluster: "localnet", alert: { url: "https://hook.example" } }), []);
  assert.throws(() => checkConfig({ ...base, rpcs: "https://b.example" }), /list of http/);
  // Spread into DEFAULT_POLICY at start, these add no keys: the guardian
  // ran on the defaults alone, with no word that the policy was dropped.
  for (const p of [true, 5, [], null, ""]) assert.throws(() => checkConfig({ ...base, policy: p }), /config.policy must be/, JSON.stringify(p));
  assert.deepEqual(checkConfig({ ...base, cluster: "localnet", alert: { url: "https://hook.example" }, policy: {} }), []);
  assert.throws(() => checkConfig({ ...base, polMs: 400 }), /not a guardian setting/);
  assert.throws(() => checkConfig({ ...base, pollMs: 5 }), /pollMs/);
  assert.throws(() => checkConfig({ ...base, cluster: "mainnet" }), /must be one of/);
  // Only the names themselves: `in` also took ["mainnet-beta"], which then
  // skipped every mainnet rule below while matching mainnet's genesis hash,
  // and names Object.prototype gives every object, such as "constructor".
  for (const c of [["mainnet-beta"], "constructor", "__proto__", "toString"]) assert.throws(() => checkConfig({ ...base, cluster: c }), /must be one of/, JSON.stringify(c));
  assert.throws(() => checkConfig({ ...base, cluster: "mainnet-beta", alert: { url: "https://hook.example" } }), /backup endpoint/);
  assert.throws(() => checkConfig({ ...base, cluster: "mainnet-beta", rpcs: ["https://b.example"] }), /config.alert/);
  const w = checkConfig({ ...base, cluster: "mainnet-beta", rpcs: ["https://b.example"], alert: { url: "https://hook.example" } });
  assert.match(w.join(" "), /liveness/);
  assert.deepEqual(checkConfig({ ...base, cluster: "mainnet-beta", rpcs: ["https://b.example"], alert: { url: "https://hook.example" }, liveness: { url: "https://hc.example/x" } }), []);
  assert.match(checkConfig(base).join(" "), /cluster is not set.*|no config.alert/);
});

test("a webhook that fails is tried again, and an alert never delivered is not muted (finding 83)", async () => {
  let calls = 0;
  const flaky = async () => (++calls < 3 ? { ok: false, status: 503 } : { ok: true });
  const errors = [];
  const send = alerter({ url: "https://hook.example", retryDelaysMs: [1, 1, 1] }, { fetchFn: flaky, onError: (e) => errors.push(e), sleep: async () => {} });
  send({ level: "error", msg: "freeze failed" });
  await send.flush();
  assert.deepEqual([calls, errors.length], [3, 0], "delivered on the third try");
  // Never delivered: reported, and the same alert is tried again next time.
  calls = 0;
  const down = async () => { calls++; throw new Error("timeout"); };
  const send2 = alerter({ url: "https://hook.example", retryDelaysMs: [1] }, { fetchFn: down, onError: (e) => errors.push(e), sleep: async () => {} });
  send2({ level: "error", msg: "freeze failed" });
  await send2.flush();
  send2({ level: "error", msg: "freeze failed" });
  await send2.flush();
  assert.deepEqual([calls, errors.length], [4, 2], "not muted for the window");
});

test("a 429's Retry-After is honoured, capped, with jitter (finding 83)", () => {
  assert.equal(retryWaitMs("2", 0, () => 0.5), 2_000);
  assert.equal(retryWaitMs("120", 0, () => 0.5), 30_000);
  assert.equal(retryWaitMs(null, 2, () => 0.5), 4_000);
  assert.equal(retryWaitMs(null, 9, () => 0.5), 8_000);
  assert.equal(retryWaitMs(null, 0, () => 0), 800);
  assert.equal(retryWaitMs(null, 0, () => 1), 1_200);
});

test("the startup replay is bounded, and skips a transaction the node will not return (finding 83)", async () => {
  // 10 pages of 1,000 in the window; a bound of 2,500 stops after 3 pages.
  let pages = 0;
  const got = await signatureWalk(async (q) => {
    pages++;
    const start = q.before ? Number(q.before.slice(1)) - 1 : 9_999;
    return Array.from({ length: 1_000 }, (_, i) => ({ signature: `s${start - i}`, blockTime: 1e9 }));
  }, { oldestWanted: 0, maxRows: 2_500 });
  assert.deepEqual([pages, got.length, got.truncated], [3, 3_000, true]);
  // An old transaction the node does not have: skipped and reported.
  const skipped = [];
  const rpc = { call: async () => null };
  assert.deepEqual(await transactionOrSkip(rpc, "old", { tries: 2, waitMs: 1, onSkip: (s) => skipped.push(s) }), { skipped: true });
  assert.deepEqual(skipped, ["old"]);
});

test("a state file that exists but restores nothing says why (finding 83)", () => {
  assert.match(restoreState("{not json", "P", newState()).problem, /not valid JSON/);
  assert.match(restoreState(JSON.stringify({ protocol: "Q" }), "P", newState()).problem, /another protocol/);
  assert.equal(restoreState(JSON.stringify({ protocol: "P" }), "P", newState()).problem, null);
});
