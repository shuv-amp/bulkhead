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
  /no longer a live guardian/,
  /no longer has the cursor/,
  /floor not ready/,
  /log truncated/,
  /no attest for/,
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
  const urgent = level === "error" || ACTIONS.has(action) || (level === "warn" && URGENT_WARNINGS.some((r) => r.test(message)));
  if (!urgent) return null;
  const subject = [line.changeId, line.proposalId, line.program, line.mint, line.what].filter((x) => x != null).join("/");
  const kind = `${level}:${action ?? ""}:${subject}:${message.slice(0, 60)}`;
  const landedFreeze = action === "freeze" && line.signature;
  const window = action === "freeze" ? failedFreezeMs : windowMs;
  if (!landedFreeze && nowMs - (seen.get(kind) ?? -Infinity) < window) return null;
  seen.set(kind, nowMs);
  const what = action ? `${action}${line.signature ? " sent" : " failed"}` : level;
  const detail = [line.reason, message, line.ticketId != null ? `ticket ${line.ticketId}` : null, line.signature ? `tx ${line.signature}` : null]
    .filter(Boolean).join(" | ");
  return { severity: level === "error" || action === "freeze" ? "critical" : "warning", title: `Bulkhead guardian: ${what}`, detail, at: line.t };
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
 * a timeout. `fetchFn` and `onError` are injectable for tests.
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
        body: JSON.stringify(webhookBody(alert, format, protocol)),
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
