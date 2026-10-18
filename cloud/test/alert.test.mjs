// Guardian alerts (cloud/guardian/alert.mjs): what reaches a person, and that
// sending never blocks or breaks the guardian.
import { test } from "node:test";
import assert from "node:assert/strict";
import { alertFor, alerter, webhookBody, stallWatch, actionLine, ALERT_FORMATS } from "../guardian/alert.mjs";

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
