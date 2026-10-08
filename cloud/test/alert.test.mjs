// Guardian alerts (cloud/guardian/alert.mjs): what reaches a person, and that
// sending never blocks or breaks the guardian.
import { test } from "node:test";
import assert from "node:assert/strict";
import { alertFor, alerter, webhookBody, stallWatch } from "../guardian/alert.mjs";

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
