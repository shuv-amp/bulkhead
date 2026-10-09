// Alerts: what the guardian's operators must hear about, pushed to a webhook.
// A freeze or a lifeboat move needs people: only a guardian quorum unfreezes
// or returns the lifeboat, and one bot holds one key. The log alone is read
// too late.
//
// Config: "alert": { "url": "https://hooks.slack.com/...", "format": "slack" }
// (format "slack" | "discord" | "json"). The URL is a secret: it is never
// logged. An alert never delays the guardian: it is sent in the background,
// with a timeout, and a failure is only logged.

/** Warnings that need a person; any `error` line and any action do too. */
const URGENT_WARNINGS = [
  /moved tokens into the lifeboat/,
  /recovery key was replaced/,
  /recovery key was removed/,
  /no longer a live guardian/,
  /no heartbeat sent/,
  /no longer has the cursor/,
  /floor not ready/,
  /log truncated/,
  /no attest for/,
  // docs/09, finding 76: a patient drip, a guardian reading late, a stale
  // node, and Floor's stop and ejection, none of which used to alert.
  /unbacked outflow at \d+% of the 24h freeze threshold/,
  /sustained drip/,
  /ingest lagging/,
  /RPC endpoint is (behind|missing recent transactions)/,
  /no 72-hour figure/,
  /was stopped on Floor/,
  /guardian was ejected on Floor/,
];

/** Actions sent on chain: each one is news. */
const ACTIONS = new Set(["freeze", "cancel", "veto_change", "veto_exit", "floor_veto", "execute"]);

/**
 * The alert for one log line, or null. `line` is the object the guardian
 * logs. A freeze that landed always alerts. Anything else repeats at most once
 * per `windowMs` for the same kind (`seen` remembers when each kind was last
 * sent); a kind is what an action acts on (a change, a proposal, a mint), so
 * two different vetoes are two alerts, while the cancels of one sweep are one.
 * A failed freeze, retried every poll, alerts at most once a `failedFreezeMs`
 * per cause. A line that skipped its action is not an alert.
 */
export function alertFor(line, seen, nowMs, { windowMs = 600_000, failedFreezeMs = 60_000 } = {}) {
  const action = line.action;
  if (line.skipped) return null;
  const level = line.level ?? "info";
  const message = line.msg ?? line.error ?? "";
  // `notify`: an info line people should still hear about (a Floor restore,
  // a restore approval; finding 76). It alerts as a warning.
  const urgent = level === "error" || ACTIONS.has(action) || line.notify === true || (level === "warn" && URGENT_WARNINGS.some((r) => r.test(message)));
  if (!urgent) return null;
  const subject = [line.changeId, line.proposalId, line.program, line.mint, line.what].filter((x) => x != null).join("/");
  const kind = `${level}:${action ?? ""}:${subject}:${message.slice(0, 60)}`;
  const landedFreeze = action === "freeze" && line.signature;
  const window = action === "freeze" ? failedFreezeMs : windowMs;
  if (!landedFreeze && nowMs - (seen.get(kind) ?? -Infinity) < window) return null;
  seen.set(kind, nowMs);
  const what = action ? `${action}${line.signature ? " sent" : " failed"}` : level === "info" ? "notice" : level;
  const detail = [line.reason, message, line.ticketId != null ? `ticket ${line.ticketId}` : null, line.signature ? `tx ${line.signature}` : null]
    .filter(Boolean).join(" | ");
  return { severity: level === "error" || action === "freeze" ? "critical" : "warning", title: `Bulkhead guardian: ${what}`, detail, at: line.t };
}

/**
 * A loop step that keeps failing is a guardian that has gone quiet: one
 * transaction the RPC never returns (`requireTransaction`) used to hold
 * ingestion at that signature forever, logged only as a warning, which does
 * not alert. `failed(name, nowMs)` returns how long `name` has failed without
 * a success once that passes `afterMs`, at most once per `everyMs` (null
 * otherwise); `ok(name)` clears it.
 *
 * A failure counts toward a stall only while the step keeps being tried:
 * `idle(name)` (a loop pass with nothing for that step to do) clears it, and
 * so does a gap of more than `everyMs` since its last failure. The first
 * failure's time used to be kept while the step did not run at all, so a
 * step run only when there was work (a veto retry) that failed once, sat
 * idle for an hour and failed once more was reported "failing for 3600 s"
 * (docs/09, finding 71).
 */
export function stallWatch({ afterMs = 120_000, everyMs = 600_000 } = {}) {
  const since = new Map();
  const said = new Map();
  const last = new Map();
  const clear = (name) => {
    since.delete(name);
    said.delete(name);
    last.delete(name);
  };
  return {
    ok: clear,
    idle: clear,
    failed(name, nowMs) {
      if (last.has(name) && nowMs - last.get(name) > everyMs) clear(name);
      last.set(name, nowMs);
      if (!since.has(name)) since.set(name, nowMs);
      const failingMs = nowMs - since.get(name);
      if (failingMs < afterMs || nowMs - (said.get(name) ?? -Infinity) < everyMs) return null;
      said.set(name, nowMs);
      return failingMs;
    },
  };
}

/**
 * Runs each of `scans` (`[what, fn]`) even when one before it failed, tells
 * `onError(what, e)` about each failure, and then throws if any failed, so the
 * loop step that ran them counts as failing (`stallWatch`). The program-account
 * scans (pending changes, the keeper's, tickets) used to log a failure as a
 * warning and carry on: the step succeeded, and a node refusing
 * getProgramAccounts for good never raised the stall alert (docs/09, finding 71).
 */
export async function scanAll(scans, onError = () => {}) {
  const failed = [];
  for (const [what, run] of scans) {
    try {
      await run();
    } catch (e) {
      failed.push(`${what}: ${e?.message ?? e}`);
      onError(what, e);
    }
  }
  if (failed.length) throw new Error(failed.join("; "));
}

/** The webhook body for `format`. */
export function webhookBody(alert, format = "json", protocol = "") {
  const text = `${alert.severity === "critical" ? "🚨" : "⚠️"} ${alert.title}${protocol ? ` (protocol ${protocol})` : ""}\n${alert.detail}`;
  if (format === "slack") return { text };
  if (format === "discord") return { content: text.slice(0, 2000) };
  return { ...alert, protocol };
}

/**
 * A sender: `send(line)` returns at once; the POST runs in the background with
 * a timeout. `fetchFn` and `onError` are injectable for tests. `protocol` may
 * be a function: the guardian creates its alerter before it knows the
 * protocol, so a failed startup alerts too.
 */
export function alerter({ url, format = "json", protocol = "", windowMs, timeoutMs = 5_000 } = {}, { fetchFn = globalThis.fetch, onError = () => {}, now = () => Date.now() } = {}) {
  const seen = new Map();
  const inflight = new Set();
  function send(line) {
    if (!url) return;
    const alert = alertFor(line, seen, now(), { windowMs });
    if (!alert) return;
    const p = Promise.resolve()
      .then(() => fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(webhookBody(alert, format, typeof protocol === "function" ? protocol() : protocol)),
        signal: AbortSignal.timeout(timeoutMs),
      }))
      .then((r) => { if (!r.ok) throw new Error(`webhook answered ${r.status}`); })
      .catch((e) => onError(e))
      .finally(() => inflight.delete(p));
    inflight.add(p);
  }
  /** Wait for alerts in flight (tests, and a clean exit). */
  send.flush = () => Promise.allSettled([...inflight]);
  return send;
}
