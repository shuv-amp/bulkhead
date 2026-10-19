// Guardian alerts (cloud/guardian/alert.mjs): what reaches a person, and that
// sending never blocks or breaks the guardian.
import { test } from "node:test";
import assert from "node:assert/strict";
import { alertFor, alerter, webhookBody, stallWatch, actionLine, ALERT_FORMATS, formatFor, jsonText, MESSAGE_MAX, MESSAGE_TAIL, errorCause } from "../guardian/alert.mjs";
import { Rpc, b58encode } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { freezeRefusal } from "../guardian/policy.mjs";

test("actions, errors and urgent warnings alert; routine lines do not", () => {
  const seen = new Map();
  assert.equal(alertFor({ msg: "caught up" }, seen, 0), null);
  assert.equal(alertFor({ action: "heartbeat", signature: "s" }, seen, 0), null);
  assert.equal(alertFor({ level: "warn", msg: "active ticket scan failed; retrying" }, seen, 0), null);
  const f = alertFor({ action: "freeze", reason: "unbacked outflow ≥ limit", signature: "SIG" }, seen, 0);
  assert.equal(f.severity, "critical");
  assert.match(f.title, /freeze sent/);
  assert.match(f.detail, /unbacked outflow/);
  assert.match(f.detail, /tx SIG/);
  assert.equal(alertFor({ level: "error", action: "freeze", error: "simulation failed" }, seen, 0).title, "Bulkhead guardian: freeze failed");
  assert.equal(alertFor({ level: "warn", msg: "the admin moved tokens into the lifeboat: depositors may be short" }, seen, 0).severity, "warning");
  assert.equal(alertFor({ level: "warn", msg: "the recovery key was replaced by the admin with a guardian quorum" }, seen, 0).severity, "warning");
  assert.ok(alertFor({ level: "error", msg: "this key is no longer a live guardian" }, seen, 0));
  // A key that cannot heartbeat at all needs a person before it is dead.
  assert.ok(alertFor({ level: "warn", msg: "no heartbeat sent: the account does not exist or this key is not on its guardian list", target: "vault" }, seen, 0));
});

test("repeats are suppressed for the window, freezes never", () => {
  const seen = new Map();
  const cancel = (id) => ({ action: "cancel", ticketId: id, signature: `s${id}` });
  assert.ok(alertFor(cancel(0), seen, 0));
  assert.equal(alertFor(cancel(1), seen, 1_000), null, "the second cancel of a sweep");
  assert.ok(alertFor(cancel(2), seen, 600_000), "after the window");
  const freeze = { action: "freeze", reason: "incident hold", signature: "x" };
  assert.ok(alertFor(freeze, seen, 0));
  assert.ok(alertFor(freeze, seen, 1), "a freeze always alerts");
});

test("webhook bodies: Slack text, Discord content (≤ 2000), plain JSON", () => {
  const a = { severity: "critical", title: "Bulkhead guardian: freeze sent", detail: "d".repeat(3000), at: "t" };
  assert.match(webhookBody(a, "slack", "P").text, /^🚨 Bulkhead guardian: freeze sent \(protocol P\)\n/);
  assert.equal(webhookBody(a, "discord").content.length, 2000);
  assert.deepEqual(webhookBody(a, "json", "P"), { ...a, protocol: "P" });
  // checkConfig takes exactly these: a format listed without its own body
  // would post the JSON one, which Slack and Discord do not show.
  const shapes = ALERT_FORMATS.map((f) => Object.keys(webhookBody(a, f)).join());
  assert.equal(new Set(shapes).size, ALERT_FORMATS.length, shapes.join(" | "));
});

test("webhook bodies show an RPC's error text as typed, not as mentions, links or markup", () => {
  // An RPC's JSON error reaches the detail verbatim (solana.mjs puts it in
  // the Error's message): a provider could ping the operator channel, show
  // a link under a label of its choosing, or hide the rest in a spoiler.
  const detail = 'scan failed: {"message":"<!channel> fees & limits: <https://x.example|approve here> @everyone [ok](https://x.example) ||``` # hi"} | tx s';
  const a = { severity: "warning", title: "Bulkhead guardian: <t> & co", detail, at: "t" };
  const sl = webhookBody(a, "slack");
  assert.deepEqual([sl.unfurl_links, sl.unfurl_media], [false, false], "Slack shows no preview of a link in it");
  assert.equal(
    sl.text,
    '⚠️ Bulkhead guardian: &lt;t&gt; &amp; co\n```\nscan failed: {"message":"&lt;!channel&gt; fees &amp; limits: &lt;https://x.example|approve here&gt; @everyone [ok](https://x.example) ||ˋˋˋ # hi"} | tx s\n```',
  );
  const d = webhookBody(a, "discord");
  assert.equal(
    d.content,
    '⚠️ Bulkhead guardian: <t> & co\n```\nscan failed: {"message":"<!channel> fees & limits: <https://x.example|approve here> @everyone [ok](https://x.example) ||ˋˋˋ # hi"} | tx s\n```',
  );
  assert.deepEqual(d.allowed_mentions, { parse: [] }, "Discord pings no one the text names");
  assert.equal(d.flags, 4, "and shows no preview of a link in it");
  // Discord's cut at 2000 keeps the block closed and no half surrogate
  // pair: the title line is 30 UTF-16 units and the fences and their line
  // breaks 9, so unit 1961 of the detail is the second 😀's high half.
  // With the protocol's label the title line is 44 + 12 units longer.
  const label = "1".repeat(44);
  const labelled = webhookBody({ ...a, detail: "d".repeat(3000) }, "discord", label).content;
  assert.ok(labelled.length === 2000 && labelled.endsWith(`(protocol ${label})\n\`\`\`\n${"d".repeat(1961 - 56)}\n\`\`\``));
  const cut = webhookBody({ ...a, detail: `${"d".repeat(1958)}😀😀` }, "discord").content;
  assert.ok(cut.isWellFormed(), `ends ${JSON.stringify(cut.slice(-6))}`);
  assert.equal(cut.length, 1999, "only the split pair is dropped");
  assert.ok(cut.endsWith("d😀\n```"));
  // A pair that ends exactly at the cut is kept whole.
  const pair = webhookBody({ ...a, detail: `${"d".repeat(1959)}😀😀` }, "discord").content;
  assert.ok(pair.length === 2000 && pair.isWellFormed() && pair.endsWith("d😀\n```"), `ends ${JSON.stringify(pair.slice(-6))}`);
  const whole = webhookBody({ ...a, detail: "d".repeat(1961) }, "discord").content;
  assert.ok(whole.length === 2000 && whole.endsWith("d\n```"), "a detail that fits is not cut");
  // Half a pair cut upstream (main.mjs cuts RPC errors to 160 or 200
  // units) shows as U+FFFD; an empty detail gets no block.
  const half = { ...a, detail: "x\uD83D | ticket 7" };
  assert.equal(webhookBody(half, "slack").text, "⚠️ Bulkhead guardian: &lt;t&gt; &amp; co\n```\nx\uFFFD | ticket 7\n```");
  assert.equal(webhookBody(half, "discord").content, "⚠️ Bulkhead guardian: <t> & co\n```\nx\uFFFD | ticket 7\n```");
  assert.equal(webhookBody({ ...a, detail: "" }, "slack").text, "⚠️ Bulkhead guardian: &lt;t&gt; &amp; co");
  assert.equal(webhookBody({ ...a, detail: "" }, "discord").content, "⚠️ Bulkhead guardian: <t> & co");
});

test("a long RPC error is cut in the detail, so what follows it reaches Discord", () => {
  // A failed send quotes the RPC's JSON error, simulation logs included
  // (solana.mjs), and main.mjs logs it uncut. Discord's body is cut to 2000
  // units, so the ids after the error were lost. Every part at its longest:
  // keys of 44, ids of 2^64 - 1, a reason as long as the guardian's longest
  // (main.mjs, stalled). A failed action has no tx.
  const K = "K".repeat(44), max = 2n ** 64n - 1n;
  const line = { level: "error", action: "veto_change", reason: "r".repeat(240), error: `{"code":-32002,"logs":"${"l".repeat(12_000)}"}`,
    what: K, target: `${K}t`, changeId: max, proposalId: max, program: `${K}p`, mint: `${K}m`, ticketId: max };
  const a = alertFor(line, new Map(), 0);
  assert.equal(a.title, "Bulkhead guardian: veto_change failed");
  const [H, T] = [MESSAGE_MAX - MESSAGE_TAIL - 1, MESSAGE_TAIL];
  assert.ok(a.detail.includes(`${line.reason} | ${line.error.slice(0, H)}…${line.error.slice(-T)} | `), a.detail.slice(0, 300));
  const tail = ` | change ${max} | proposal ${max} | program ${K}p | mint ${K}m | ticket ${max}`;
  assert.ok(a.detail.endsWith(tail));
  const { content } = webhookBody(a, "discord", K);
  assert.ok(content.length <= 2000, String(content.length));
  assert.ok(content.endsWith(`${tail}\n\`\`\``));
  // At the cap, uncut. Past it, the start and the end, and a cut through a
  // surrogate pair drops the half. A part said only in the middle left out
  // is named; one said in the end is not named twice.
  const detail = (msg, extra = {}) => alertFor({ level: "error", msg, ...extra }, new Map(), 0).detail;
  const m = (n) => "m".repeat(n);
  assert.equal(detail(m(MESSAGE_MAX)), m(MESSAGE_MAX));
  assert.equal(detail(m(MESSAGE_MAX + 1)), `${m(H)}…${m(T)}`);
  assert.equal(detail(`${m(H - 1)}😀${m(400)}`), `${m(H - 1)}…${m(T)}`);
  assert.equal(detail(`${m(800)}😀${m(T - 1)}`), `${m(H)}…${m(T - 1)}`);
  assert.equal(detail(`${m(H)} change 4 ${m(400)}`, { changeId: 4 }), `${m(H)}…${m(T)} | change 4`);
  assert.equal(detail(`${m(MESSAGE_MAX)} change 4`, { changeId: 4 }), `${m(H)}…${m(T - 9)} change 4`);
  // A word at a cut reads as cut, whether it goes on ("change 45") or not,
  // so the part is named again; a part before or after it is not.
  assert.equal(detail(`${m(H - 9)} change 45 ${m(400)}`, { changeId: 4 }), `${m(H - 9)} change 4…${m(T)} | change 4`);
  assert.equal(detail(`${m(H - 9)} change 4 ${m(400)}`, { changeId: 4 }), `${m(H - 9)} change 4…${m(T)} | change 4`);
  assert.equal(detail(`${m(H - 12)} change 4 mm ${m(400)}`, { changeId: 4 }), `${m(H - 12)} change 4 mm…${m(T)}`);
  const P = "Prog1111111111111111111111111111111111111111", y = "y".repeat(800);
  assert.equal(detail(`${y}x${P} ${m(T - 45)}`, { program: P }), `${y.slice(0, H)}…${P} ${m(T - 45)} | program ${P}`);
  assert.equal(detail(`${y} ${P} ${m(T - 46)}`, { program: P }), `${y.slice(0, H)}… ${P} ${m(T - 46)}`);
});

test("a format that is not one of ALERT_FORMATS, or none, follows the webhook's host", async () => {
  const slack = "https://hooks.slack.com/services/T/B/x";
  const discord = "https://discord.com/api/webhooks/1/x";
  for (const f of ALERT_FORMATS) assert.equal(formatFor(slack, f), f, "a valid format is kept");
  assert.equal(formatFor("https://chat.example/hooks/x", "Slack"), "slack", "in any case");
  assert.equal(formatFor("https://chat.example/hooks/x", " DISCORD\n"), "discord");
  assert.equal(formatFor(discord, "Slack"), "discord", "the webhook's own before a refused format");
  assert.equal(formatFor(slack, "JSON"), "slack");
  assert.equal(formatFor(slack, "slak"), "slack");
  assert.equal(formatFor(slack, undefined), "slack");
  assert.equal(formatFor("https://hooks.slack.com/triggers/T/1/x", undefined), "json", "a workflow trigger takes the JSON keys");
  assert.equal(formatFor(discord, "discrod"), "discord");
  assert.equal(formatFor("https://discordapp.com/api/v10/webhooks/1/x/", undefined), "discord");
  assert.equal(formatFor("https://ptb.discord.com/api/webhooks/1/x", undefined), "discord");
  assert.equal(formatFor(`${discord}/slack`, undefined), "json", "Discord's Slack-compatible endpoint is not guessed");
  assert.equal(formatFor("https://discord.com/api/channels/1/messages", undefined), "json");
  assert.equal(formatFor("https://hooks.slack.com.evil.example/services/x", "slak"), "json");
  assert.equal(formatFor("https://notslack.com/services/T/B/x", undefined), "json");
  assert.equal(formatFor("https://notdiscord.com/api/webhooks/1/x", undefined), "json");
  assert.equal(formatFor("https://discord.com.evil.example/api/webhooks/1/x", undefined), "json");
  assert.equal(formatFor("https://hook.example/x", "slak"), "json");
  assert.equal(formatFor("not a url", "slak"), "json");
  // Whatever JSON gave: checkConfig refuses it after this runs.
  assert.equal(formatFor("https://hook.example/x", ["Slack"]), "json");
  assert.equal(formatFor("https://hook.example/x", { toString: null }), "json");
  // The alerter posts that format: the "config refused" alert of a config
  // with "format": "Slack" reached Slack as a JSON body it does not show.
  const posted = [];
  const send = alerter({ url: slack, format: "Slack" }, { fetchFn: async (url, init) => { posted.push(JSON.parse(init.body)); return { ok: true }; } });
  send({ level: "error", msg: "guardian stopped: config.alert.format: \"Slack\" is not one of json, slack, discord" });
  await send.flush();
  assert.equal(posted.length, 1);
  assert.deepEqual(Object.keys(posted[0]), ["text", "unfurl_links", "unfurl_media"]);
  assert.match(posted[0].text, /guardian stopped: config\.alert\.format/);
});

test("log lines and webhook bodies are well-formed JSON, even when a cut halves a surrogate pair", async () => {
  // "😀".slice(0, 1) is what `.slice(0, 160)` leaves when the cut falls
  // inside the pair: JSON.stringify writes it as "\ud83d", which serde_json
  // refuses.
  const half = `rpc said ${"😀".slice(0, 1)}`;
  assert.equal(jsonText({ error: half, at: [{ low: "\uDE00x" }], n: 5n, ok: "😀" }), '{"error":"rpc said \uFFFD","at":[{"low":"\uFFFDx"}],"n":"5","ok":"😀"}');
  for (const format of ALERT_FORMATS) {
    const posted = [];
    const send = alerter({ url: "https://hook.invalid/x", format }, { fetchFn: async (url, init) => { posted.push(init.body); return { ok: true }; } });
    send({ level: "error", msg: "guardian stalled", reason: half });
    await send.flush();
    assert.equal(posted.length, 1, format);
    assert.doesNotMatch(posted[0], /\\u[dD][89a-fA-F]/, format);
    assert.match(posted[0], /rpc said \uFFFD/, format);
  }
});

test("sending returns at once, survives a dead or hanging webhook, and needs a URL", async () => {
  const posted = [];
  const errors = [];
  const ok = alerter({ url: "https://hook.invalid/x", format: "slack" }, {
    fetchFn: async (url, init) => { posted.push([url, JSON.parse(init.body)]); return { ok: true }; },
  });
  ok({ action: "freeze", signature: "s", reason: "r" });
  await ok.flush();
  assert.equal(posted.length, 1);
  assert.match(posted[0][1].text, /freeze sent/);

  const down = alerter({ url: "https://hook.invalid/x" }, { fetchFn: async () => { throw new Error("connection refused"); }, onError: (e) => errors.push(e.message) });
  down({ action: "freeze", signature: "s" });
  await down.flush();
  assert.deepEqual(errors, ["connection refused"]);

  const status = alerter({ url: "https://hook.invalid/x" }, { fetchFn: async () => ({ ok: false, status: 500 }), onError: (e) => errors.push(e.message) });
  status({ action: "freeze", signature: "s" });
  await status.flush();
  assert.equal(errors.at(-1), "webhook answered 500");

  let resolveHang;
  const hang = alerter({ url: "https://hook.invalid/x" }, { fetchFn: () => new Promise((r) => { resolveHang = r; }) });
  const t0 = Date.now();
  hang({ action: "freeze", signature: "s" });
  assert.ok(Date.now() - t0 < 50, "send does not wait for the webhook");
  await new Promise((r) => setImmediate(r));
  resolveHang({ ok: true });
  await hang.flush();

  const none = alerter({}, { fetchFn: async () => { throw new Error("must not be called"); } });
  none({ action: "freeze", signature: "s" });
  await none.flush();
});

test("review fixes: distinct vetoes alert, skipped lines do not, failing freezes are rate-limited", () => {
  const seen = new Map();
  // Two different loosenings vetoed minutes apart: two alerts.
  assert.ok(alertFor({ action: "veto_change", changeId: 4, signature: "a" }, seen, 0));
  assert.ok(alertFor({ action: "veto_change", changeId: 5, signature: "b" }, seen, 60_000));
  assert.equal(alertFor({ action: "veto_change", changeId: 5, signature: "c" }, seen, 61_000), null, "the same change again");
  // A skipped action is not news, and does not use up the slot.
  assert.equal(alertFor({ action: "cancel", skipped: "ticket account missing; will retry", ticketId: 3 }, seen, 0), null);
  assert.ok(alertFor({ action: "cancel", ticketId: 3, signature: "d" }, seen, 1));
  // A freeze failing on every poll: once a minute per cause; a landed one always.
  const failed = { level: "error", action: "freeze", error: "transaction simulation failed" };
  assert.ok(alertFor(failed, seen, 0));
  assert.equal(alertFor(failed, seen, 500), null);
  assert.equal(alertFor(failed, seen, 59_000), null);
  assert.ok(alertFor(failed, seen, 60_000));
  assert.ok(alertFor({ action: "freeze", signature: "e" }, seen, 60_001));
  assert.ok(alertFor({ action: "freeze", signature: "f" }, seen, 60_002));
});

test("a failed action's alert repeats per cause: an RPC's refusal, a transaction's failure", async () => {
  // The errors as cloud/lib makes them, logged as main.mjs logs a failed action.
  const real = globalThis.fetch;
  let answer;
  globalThis.fetch = async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: answer }), { status: 200 });
  const refusal = (error, method = "sendTransaction") => {
    answer = error;
    return new Rpc("http://a.invalid", { retries: 0 }).call(method, ["x"]).then(() => assert.fail("refused"), (e) => e);
  };
  const payer = Keypair.generate();
  const ix = { programId: payer.publicKey, accounts: [], data: Uint8Array.of(9) };
  // Sent without a preflight, as a freeze is, it lands and fails: the Vault's
  // instruction after the two compute-budget ones.
  const landed = (signature, custom) => send({
    blockhash: async () => "11111111111111111111111111111111",
    call: async (method) => (method === "sendTransaction" ? signature : { value: [{ err: { InstructionError: [2, { Custom: custom }] } }] }),
  }, payer, [ix], [], { skipPreflight: true, pollMs: 1, computeUnits: 50_000, microLamports: 1 }).then(() => assert.fail("failed"), (e) => e);
  try {
    // A local Agave 4.3 validator's preflight refusal, its logs cut short.
    const preflight = (custom, lamports) => refusal({
      code: -32002,
      message: `Transaction simulation failed: Error processing Instruction 0: custom program error: 0x${custom.toString(16)}`,
      data: { err: { InstructionError: [0, { Custom: custom }] }, logs: [`Transfer: insufficient lamports ${lamports}, need 1000000000000000000`], unitsConsumed: 150 },
    });
    const freeze = (e) => actionLine({ type: "freeze", reason: "unbacked outflow ≥ limit" }, { level: "error", error: e.message, errorCause: errorCause(e) });
    const [one, other] = [await preflight(1, 5), await preflight(6002, 5)];
    assert.equal(one.message.slice(0, 60), other.message.slice(0, 60), "every refusal starts alike");
    const seen = new Map();
    assert.ok(alertFor(freeze(one), seen, 0));
    assert.ok(alertFor(freeze(other), seen, 1_000), "another cause within the minute");
    assert.equal(alertFor(freeze(await preflight(1, 4)), seen, 2_000), null, "the same cause, a figure in its logs moved");
    // A refusal with no transaction error is its code and text, figures aside.
    const behind = async (n) => freeze(await refusal({ code: -32005, message: `Node is behind by ${n} slots`, data: { numSlotsBehind: n } }));
    assert.ok(alertFor(await behind(42), seen, 3_000));
    assert.equal(alertFor(await behind(43), seen, 4_000), null);
    assert.ok(alertFor(freeze(await refusal({ code: -32004, message: "Node is behind by 42 slots" })), seen, 4_050), "the same text, another code");
    const busy = async (ms) => freeze(await refusal({ code: -32000, message: `rate limited, retry in ${ms}ms` }));
    assert.ok(alertFor(await busy(734), seen, 4_100));
    assert.equal(alertFor(await busy(912), seen, 4_200), null, "digits in a word are a figure too");
    assert.equal(errorCause(await refusal({ code: -32000, message: "x".repeat(500) })).length, 160, "a cause is cut");
    assert.ok(alertFor(freeze(await refusal({ code: -32004, message: "Block not available for slot 9" })), seen, 5_000));
    // A freeze that failed on chain: each retry is signed anew, and is one cause.
    const [a, b] = [await landed(b58encode(new Uint8Array(64).fill(1)), 8006), await landed(b58encode(new Uint8Array(64).fill(2)), 8006)];
    assert.ok(a.message.startsWith(`transaction ${a.signature} failed`));
    assert.ok(alertFor(freeze(a), seen, 6_000));
    assert.equal(alertFor(freeze(b), seen, 7_000), null, "the same failure, signed again");
    assert.ok(alertFor(freeze(await landed(b58encode(new Uint8Array(64).fill(3)), 2)), seen, 8_000), "another failure");
    // The same refusal by the freeze's own simulation (no budget instructions)
    // and by a node's preflight: one cause however it came.
    assert.equal(alertFor(freeze(freezeRefusal({ InstructionError: [0, { Custom: 8006 }] })), seen, 9_000), null, "simulated, the same cause");
    assert.equal(alertFor(freeze(await preflight(8006, 7)), seen, 10_000), null, "refused in preflight, the same cause");
    assert.ok(alertFor(freeze(freezeRefusal("InsufficientFundsForFee")), seen, 11_000), "no SOL for the fee");
    const unpaid = { code: -32002, message: "Transaction simulation failed: Attempt to debit an account but found no record of a prior credit.", data: { err: "InsufficientFundsForFee" } };
    assert.equal(alertFor(freeze(await refusal(unpaid)), seen, 11_100), null, "no SOL for the fee, said by a node");
    assert.ok(alertFor(freeze(await refusal({ ...unpaid, data: { err: "BlockhashNotFound" } })), seen, 11_200), "another transaction error");
    // One code from two methods: the read before a send, then the send.
    const lagging = { code: -32005, message: "Node is behind by 42 slots" };
    assert.ok(alertFor(freeze(await refusal(lagging, "getAccountInfo")), seen, 12_000), "the read and the send are two causes");
    // A program's code in the text is kept, not taken for a figure.
    // (0x1770 and 0x1771: decimal digits only, so masking them would make one.)
    const bare = async (hex) => freeze(await refusal({ code: -32002, message: `Transaction simulation failed: Error processing Instruction 0: custom program error: 0x${hex}` }));
    assert.ok(alertFor(await bare("1770"), seen, 13_000));
    assert.ok(alertFor(await bare("1771"), seen, 14_000), "another program error, with no data");
    // Not confirmed in its window: each retry is signed anew, and is one cause.
    const unconfirmed = (signature) => send({
      blockhash: async () => "11111111111111111111111111111111",
      call: async (method) => (method === "sendTransaction" ? signature : { value: [null] }),
    }, payer, [ix], [], { skipPreflight: true, pollMs: 1, confirmMs: 0 }).then(() => assert.fail("unconfirmed"), (e) => e);
    const [u, v] = [await unconfirmed(b58encode(new Uint8Array(64).fill(4))), await unconfirmed(b58encode(new Uint8Array(64).fill(5)))];
    assert.ok(u.message.endsWith("not confirmed"));
    assert.ok(alertFor(freeze(u), seen, 15_000));
    assert.equal(alertFor(freeze(v), seen, 16_000), null, "not confirmed, signed again");
    // A send that failed before it reached a node carries the signature, not in its text.
    assert.equal(errorCause(Object.assign(new Error("sendTransaction: fetch failed"), { signature: a.signature })), undefined);
    // Any other error has no cause, and keeps the first 60 units.
    assert.equal(errorCause(new Error("endpoint down")), undefined);
    assert.equal(jsonText({ errorCause: errorCause(new Error("x")) }), "{}");
  } finally {
    globalThis.fetch = real;
  }
});

test("a step that keeps failing raises an urgent alert after the threshold, rate-limited", () => {
  const w = stallWatch({ afterMs: 120_000, everyMs: 600_000 });
  assert.equal(w.failed("ingest", 0), null);
  assert.equal(w.failed("ingest", 119_999), null, "not yet");
  assert.equal(w.failed("ingest", 120_000), 120_000);
  assert.equal(w.failed("ingest", 130_000), null, "said once per window");
  assert.equal(w.failed("ingest", 720_000), 720_000, "and again after it");
  w.ok("ingest");
  assert.equal(w.failed("ingest", 800_000), null, "a success starts the count over");
  assert.equal(w.failed("ingest", 920_000), 120_000);
  // The line the guardian logs for it is urgent; the plain step warning is not.
  assert.equal(alertFor({ level: "warn", msg: "ingest: getTransaction returned no transaction metadata" }, new Map(), 0), null);
  assert.equal(alertFor({ level: "error", msg: 'guardian stalled: "ingest" keeps failing', reason: "failing for 120s" }, new Map(), 0).severity, "critical");
});

test("a removed recovery key alerts like a replaced one", () => {
  assert.ok(alertFor({ level: "warn", msg: "the recovery key was removed by the admin with a guardian quorum: there is no recovery key now" }, new Map(), 0));
});

test("the same warning about two heartbeat targets is two alerts", () => {
  // beatOne names where the key is dead only in `target`: the Vault's line and
  // a Floor program's line minutes later used to share one repeat slot, so the
  // second never reached anyone.
  const seen = new Map();
  const dead = (target) => ({ level: "error", msg: "this key is no longer a live guardian; a heartbeat cannot revive it", target });
  assert.ok(alertFor(dead("vault"), seen, 0));
  assert.ok(alertFor(dead("floor P1"), seen, 60_000), "another target");
  assert.equal(alertFor(dead("floor P1"), seen, 120_000), null, "the same target again");
});

test("the line for a sent or failed action says what it acts on", () => {
  // execute() used to log only the reason, the ticket and the signature, so
  // two vetoes of different loosenings, exits or proposals had one kind and
  // the second was muted for 10 minutes. Shapes as policy.mjs builds them.
  const seen = new Map();
  const sent = (a, at) => alertFor(actionLine(a, { ticketId: a.ticketId, signature: `s${at}` }), seen, at);
  const failed = (a, at) => alertFor(actionLine(a, { level: "error", error: "blockhash not found", ticketId: a.ticketId }), seen, at);
  const change = (id) => ({ type: "veto_change", changeId: id, reason: `loosening ${id} (kind 1) is not pre-approved` });
  const exit = (mint) => ({ type: "veto_exit", mint, executableS: 9, reason: "lifeboat exit of 5 is not pre-approved" });
  const proposal = (id) => ({ type: "floor_veto", program: "P1", proposalId: id, reason: `floor P1 proposal ${id} is still pending` });
  const cancel = (id, mint) => ({ type: "cancel", ticketId: id, address: "A", mint, vault: "V", reason: "incident: ticket to O" });
  for (const [one, two] of [[change(4), change(5)], [exit("M1"), exit("M2")], [proposal(1), proposal(2)]]) {
    assert.ok(sent(one, 0));
    assert.ok(sent(two, 1_000), `${two.type}: a second target alerts`);
    assert.equal(sent(two, 2_000), null, `${two.type}: the same target again`);
    assert.ok(failed(one, 0));
    assert.ok(failed(two, 1_000), `${two.type}: a second failure alerts`);
  }
  // Proposal 1 on a second Floor program is another target too.
  assert.ok(sent({ ...proposal(1), program: "P2" }, 3_000));
  // The cancels of one sweep stay one alert, across mints too.
  assert.ok(sent(cancel(1, "M1"), 0));
  assert.equal(sent(cancel(2, "M2"), 1_000), null);
  assert.deepEqual(actionLine(change(4), { signature: "S" }), { action: "veto_change", signature: "S", reason: change(4).reason, changeId: 4 });
  // An id of 0 is kept: change ids start at 0 (see the next test).
  assert.deepEqual(actionLine(change(0n), { signature: "S" }), { action: "veto_change", signature: "S", reason: change(0n).reason, changeId: 0n });
  assert.equal(actionLine(change(4), { reason: "retried" }).reason, "retried", "a reason passed in stands");
});

test("an alert names what it is about when its text does not", () => {
  // The webhook shows the title and the detail only. "floor not ready" for
  // one of two Floor programs, a lifeboat move or a veto used to arrive
  // without the program, mint or change it was about. Line shapes as
  // main.mjs logs them.
  const P = "Prog1111111111111111111111111111111111111111";
  const M = "Mint1111111111111111111111111111111111111111";
  const detail = (line) => alertFor(line, new Map(), 0).detail;
  assert.equal(detail({ level: "warn", msg: "floor not ready (unarmed): no abort buffer staged", program: P, alerts: [{ code: "unarmed" }] }), `floor not ready (unarmed): no abort buffer staged | program ${P}`);
  assert.equal(detail({ level: "warn", msg: "the admin moved tokens into the lifeboat: depositors may be short", mint: M, amount: 5 }), `the admin moved tokens into the lifeboat: depositors may be short | mint ${M}`);
  const change = { type: "veto_change", changeId: 4, reason: "loosening 4 (kind 1) is not pre-approved" };
  assert.equal(detail(actionLine(change, { signature: "S" })), "loosening 4 (kind 1) is not pre-approved | change 4 | tx S");
  // A failed action says why it was sent too: "freeze failed | blockhash
  // not found" used to arrive without the breach it was for.
  assert.equal(detail(actionLine(change, { level: "error", error: "blockhash not found" })), "loosening 4 (kind 1) is not pre-approved | blockhash not found | change 4");
  const freeze = { type: "freeze", secs: 3600, reason: "unbacked outflow to non-allowlisted owners in the last hour: 9 ≥ 5 (0.5 × worst_1h)" };
  assert.equal(detail(actionLine(freeze, { level: "error", error: "blockhash not found" })), `${freeze.reason} | blockhash not found`);
  const cancel = { type: "cancel", ticketId: 3, mint: M, reason: "incident: ticket to O" };
  assert.equal(detail(actionLine(cancel, { level: "error", error: "blockhash not found", ticketId: 3 })), "incident: ticket to O | blockhash not found | ticket 3");
  const floor = { type: "floor_veto", program: P, proposalId: 7, reason: "upgrade to unapproved buffer B is still pending" };
  assert.equal(detail(actionLine(floor, { signature: "S" })), `upgrade to unapproved buffer B is still pending | proposal 7 | program ${P} | tx S`);
  const exit = { type: "veto_exit", mint: M, reason: "lifeboat exit of 5 is not pre-approved" };
  assert.equal(detail(actionLine(exit, { signature: "S" })), `lifeboat exit of 5 is not pre-approved | mint ${M} | tx S`);
  assert.equal(detail({ action: "execute", what: "change 5", signature: "S" }), "change 5 | tx S");
  assert.equal(detail({ level: "error", msg: "this key is no longer a live guardian", target: "vault" }), "this key is no longer a live guardian | on vault");
  // Change and ticket ids start at 0 (next_change_id and next_ticket_id
  // in programs/vault/src/genesis.rs), and the guardian reads them as
  // BigInt: a protocol's first loosening is change 0n, its first queued
  // payout ticket 0n. Each is named.
  assert.equal(detail({ level: "error", msg: "could not be read", changeId: 0n }), "could not be read | change 0");
  const firstTicket = { type: "cancel", ticketId: 0n, address: "A", mint: M, vault: "V", reason: "incident: ticket to O" };
  assert.equal(detail(actionLine(firstTicket, { ticketId: firstTicket.ticketId, signature: "S" })), "incident: ticket to O | ticket 0 | tx S");
  // Named once: not again when the reason, the text or a part before it
  // already says it, as a whole word, in any case; a key only exactly.
  assert.equal(detail({ action: "floor_veto", reason: `floor ${P} proposal 7 is still pending`, program: P, proposalId: 7, signature: "S" }), `floor ${P} proposal 7 is still pending | tx S`);
  assert.equal(detail({ level: "error", msg: "change 4 may be approved, but its account could not be read", changeId: 4 }), "change 4 may be approved, but its account could not be read");
  assert.equal(detail({ level: "error", msg: "Change 4 failed", changeId: 4 }), "Change 4 failed");
  assert.equal(detail({ level: "error", msg: "change 45 may be approved", changeId: 4 }), "change 45 may be approved | change 4");
  assert.equal(detail({ level: "error", msg: "exchange 4 failed", changeId: 4 }), "exchange 4 failed | change 4");
  assert.equal(detail({ level: "error", msg: "change 45 replaced change 4", changeId: 4 }), "change 45 replaced change 4");
  assert.equal(detail({ level: "error", msg: `${P.toLowerCase()} failed`, program: P }), `${P.toLowerCase()} failed | program ${P}`);
  assert.equal(detail({ level: "error", msg: `program ${P.toLowerCase()} failed`, program: P }), `program ${P.toLowerCase()} failed | program ${P}`);
  assert.equal(detail({ action: "execute", reason: `floor ${P.toLowerCase()} proposal 7 is due`, what: `floor ${P} proposal 7`, signature: "S" }), `floor ${P.toLowerCase()} proposal 7 is due | floor ${P} proposal 7 | tx S`);
  assert.equal(detail({ level: "warn", notify: true, msg: `the Floor guardians are 2-of-3 for ${P}: fix it`, program: P }), `the Floor guardians are 2-of-3 for ${P}: fix it`);
  assert.equal(detail({ level: "error", msg: "this key is no longer a live guardian", program: P, target: `floor ${P}` }), `this key is no longer a live guardian | on floor ${P}`);
  // The repeat key holds the labels: change 4 and proposal 4 are two alerts.
  const seen = new Map();
  assert.ok(alertFor({ level: "error", msg: "could not be read", changeId: 4 }, seen, 0));
  assert.ok(alertFor({ level: "error", msg: "could not be read", proposalId: 4 }, seen, 1_000));
  // An empty field names nothing, and is not searched for: indexOf("")
  // matches at the end of the text forever.
  assert.equal(detail({ level: "error", msg: "floor not ready", what: "", program: "" }), "floor not ready");
  assert.equal(detail({ action: "execute", reason: "due", what: "", signature: "S" }), "due | tx S");
});
