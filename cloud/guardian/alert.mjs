// Alerts: what the guardian's operators must hear about, pushed to a webhook.
// A freeze or a lifeboat move needs people: only a guardian quorum unfreezes
// or returns the lifeboat, and one bot holds one key. The log alone is read
// too late.
//
// Config: "alert": { "url": "https://hooks.slack.com/...", "format": "slack" }
// (format "slack" | "discord" | "json"; without one, the URL's own, see
// formatFor). The URL is a secret: it is never
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
  // A followed Floor config replaying rows at or before the start slot. With
  // a late start slot (an endpoint ahead of its chain) they landed after the
  // start, and their events (a key replaced or removed, a restore) are never
  // reported; a lagging node logs it too, and the two cannot be told apart.
  // Only rows listed after the first good poll: that poll's replay is silent.
  /listed transactions at or before the start slot/,
];

/**
 * The most of a line's message (in UTF-16 units) an alert's detail shows: a
 * longer one shows its first MESSAGE_MAX - MESSAGE_TAIL - 1 units, "…" and
 * its last MESSAGE_TAIL, one fewer on a side whose cut would split a pair.
 */
export const MESSAGE_MAX = 1000;
export const MESSAGE_TAIL = 300;

/** The first `n` UTF-16 units of `s`, less a high surrogate left without its pair. */
function firstUnits(s, n) {
  return s.slice(0, n).replace(/[\uD800-\uDBFF]$/, "");
}

/** The last `n` UTF-16 units of `s`, less a low surrogate left without its pair. */
function lastUnits(s, n) {
  return s.slice(-n).replace(/^[\uDC00-\uDFFF]/, "");
}

/**
 * What made `e` fail, for a log line's `errorCause`, which alertFor keys its
 * repeats on in place of the message's first 60 units. Those held no cause:
 * every refusal an RPC sends starts `sendTransaction: {"code":-32002,
 * "message":"Transaction simul`, so a second cause was muted; and a signed
 * transaction's failure starts `transaction <signature>`, new on every
 * retry, so a freeze failing on chain alerted on every poll.
 * - A transaction's error, however it came (a node's refused preflight, the
 *   transaction failing on chain, the freeze's own simulation): the error,
 *   and for an instruction's, only what it failed with. Its index moves with
 *   the compute-budget instructions sent before it, which a simulation or a
 *   send without a budget leaves out.
 * - Any other RPC error: the method, the code and the text with each run of
 *   digits as "#", in a word too (a node "behind by 42 slots" is behind by
 *   43 a poll later; "retry in 734ms"), but a program's "0x1770" is kept.
 * - A signed transaction's failure: its message without the signature.
 * Cut at 160 units. Undefined for anything else.
 */
export function errorCause(e) {
  return rawCause(e)?.slice(0, 160);
}
function rawCause(e) {
  const err = e?.rpcError?.data?.err ?? e?.onChainErr ?? e?.simulatedErr;
  if (err != null) {
    const ie = err.InstructionError;
    return Array.isArray(ie) ? `instruction error ${JSON.stringify(ie[1])}` : `transaction error ${JSON.stringify(err)}`;
  }
  const r = e?.rpcError;
  if (r?.code != null) return `${e.rpcMethod ?? "?"} RPC ${r.code} ${String(r.message ?? "").replace(/(0x[0-9a-f]+)|\d+/gi, (m, hex) => hex ?? "#")}`;
  const sig = e?.signature;
  const message = String(e?.message ?? "");
  if (typeof sig === "string" && sig && message.includes(sig)) return message.replaceAll(sig, "<signature>");
  return undefined;
}

/** Actions sent on chain: each one is news. */
const ACTIONS = new Set(["freeze", "cancel", "veto_change", "veto_exit", "floor_veto", "execute"]);

/**
 * The alert for one log line, or null. `line` is the object the guardian
 * logs. A freeze that landed always alerts. Anything else repeats at most once
 * per `windowMs` for the same kind (`seen` remembers when each kind was last
 * sent); a kind is what an action acts on (a change, a proposal, a mint) and
 * why it failed (the line's `errorCause` when it has one, or else its
 * message's first 60 units), so two different vetoes are two alerts, while
 * the cancels of one sweep are one. A failed freeze, retried every poll,
 * alerts at most once a `failedFreezeMs` per cause. A line that skipped its
 * action is not an alert.
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
  const parts = about(line);
  const subject = parts.map((p) => p.shown).join("/");
  const kind = `${level}:${action ?? ""}:${subject}:${line.errorCause ?? message.slice(0, 60)}`;
  const landedFreeze = action === "freeze" && line.signature;
  const window = action === "freeze" ? failedFreezeMs : windowMs;
  if (!landedFreeze && nowMs - (seen.get(kind) ?? -Infinity) < window) return null;
  seen.set(kind, nowMs);
  const what = action ? `${action}${line.signature ? " sent" : " failed"}` : level === "info" ? "notice" : level;
  // An RPC's error text can run to kilobytes (a failed send quotes the
  // simulation's logs), and webhookBody cuts Discord's body to Discord's
  // 2000-unit limit, so the change, program, mint or ticket after it were
  // lost. The detail keeps its start (the RPC's message) and its end (the
  // last logs, or what a line says after the error it quotes).
  let shown = message, heard = [message];
  if (message.length > MESSAGE_MAX) {
    const [head, tail] = [firstUnits(message, MESSAGE_MAX - MESSAGE_TAIL - 1), lastUnits(message, MESSAGE_TAIL)];
    shown = `${head}…${tail}`;
    // A word at a cut does not name a part: it reads as cut ("change 4…"
    // may be change 45), so that part is named again in full.
    heard = [head.replace(/\w+$/, ""), tail.replace(/^\w+/, "")];
  }
  const detail = [line.reason, shown, ...named(parts, [line.reason ?? "", ...heard]), line.ticketId != null ? `ticket ${line.ticketId}` : null, line.signature ? `tx ${line.signature}` : null]
    .filter(Boolean).join(" | ");
  const alert = { severity: level === "error" || action === "freeze" ? "critical" : "warning", title: `Bulkhead guardian: ${what}`, detail, at: line.t };
  // Not part of the message: lets the sender un-mute an alert it could not deliver.
  Object.defineProperty(alert, "kind", { value: kind });
  return alert;
}

/**
 * What `line` is about: each part as the webhook shows it (`shown`), and the
 * word that says it is already in a text (`needle`). alertFor keys its
 * repeats on the shown parts ("change 4" and "proposal 4" differ) and names
 * them in the detail, so the webhook never keys on a part it doesn't show.
 * A program or mint is said by its bare key, and a change or proposal in any
 * case ("Change 4"). `what` and `target` may hold a key, so they and the keys
 * match exactly: base58 case matters.
 */
function about(line) {
  return [
    [line.what, ""], [line.target, "on "],
    [line.changeId, "change ", false, true], [line.proposalId, "proposal ", false, true],
    [line.program, "program ", true], [line.mint, "mint ", true],
  ].filter(([v]) => v != null && v !== "") // says() never ends on an empty word
    .map(([v, label, bare = false, fold = false]) => ({ shown: `${label}${v}`, needle: bare ? String(v) : `${label}${v}`, fold }));
}

/**
 * The `parts` (from `about`) the webhook should show: those that `texts` (the
 * reason and the message) or an earlier part don't already say. The webhook
 * gets only the title and the detail, so "floor not ready" for one of two
 * Floor programs used to arrive without saying which.
 */
function named(parts, texts) {
  const out = [];
  for (const { shown, needle, fold } of parts) {
    if (![...texts, ...out].some((s) => says(s, needle, fold))) out.push(shown);
  }
  return out;
}

/**
 * `s` contains `word` (ignoring case if `fold`), and not as part of a longer
 * word or number ("change 4" is not in "change 45").
 */
function says(s, word, fold = false) {
  const [hay, needle] = fold ? [s.toLowerCase(), word.toLowerCase()] : [s, word];
  for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + 1)) {
    if (!/\w/.test(hay[i - 1] ?? "") && !/\w/.test(hay[i + needle.length] ?? "")) return true;
  }
  return false;
}

/**
 * The line the guardian logs for an action it sent or failed to send: `fields`
 * plus why it was sent (its reason) and what it acts on (a change, a
 * proposal and its program, a mint), which alertFor keys its repeats on. The
 * line used to carry only the reason and the ticket, so two vetoes of
 * different loosenings, exits or proposals were one kind, and the second was
 * muted for the window. A failed action's line had no reason at all, so
 * "freeze failed | blockhash not found" didn't say which breach. A cancel's
 * mint is left out: the cancels of one sweep are one alert.
 */
export function actionLine(action, fields) {
  const line = { action: action.type, ...(action.reason != null && { reason: action.reason }), ...fields };
  for (const k of ["changeId", "proposalId", "program", "mint"]) {
    if (action[k] != null && !(k === "mint" && action.type === "cancel")) line[k] = action[k];
  }
  return line;
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

/** The bodies webhookBody writes, by `alert.format` (checkConfig refuses others). */
export const ALERT_FORMATS = ["json", "slack", "discord"];

/**
 * The body format the alerter posts: `format` when it is one of
 * ALERT_FORMATS; else the webhook's own: a Slack incoming webhook
 * (hooks.slack.com/services/...) Slack's, a Discord webhook (discord.com or
 * discordapp.com or a subdomain of either,
 * /api[/vN]/webhooks/<id>/<token>[/]) Discord's; else a format refused only
 * for its case or spacing ("Slack") as meant; else JSON. Slack workflow
 * triggers take the JSON body's keys, so they keep it. The fatal alert of a
 * config checkConfig refused (a misspelt format, or a misspelt key beside the
 * url) is sent with that config, and Slack and Discord drop a JSON body, so
 * the alert saying the guardian did not start was lost.
 */
export function formatFor(url, format) {
  if (ALERT_FORMATS.includes(format)) return format;
  let host = "";
  let path = "";
  try {
    ({ hostname: host, pathname: path } = new URL(url));
  } catch {}
  if (host === "hooks.slack.com" && path.startsWith("/services/")) return "slack";
  if (/(^|\.)discord(app)?\.com$/.test(host) && /^\/api(\/v\d+)?\/webhooks\/[^/]+\/[^/]+\/?$/.test(path)) return "discord";
  const meant = typeof format === "string" ? format.trim().toLowerCase() : "";
  return ALERT_FORMATS.includes(meant) ? meant : "json";
}

const SLACK_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };
const [OPEN, CLOSE] = ["\n```\n", "\n```"];

/**
 * The webhook body for `format`. The detail can hold an RPC's own error text
 * (solana.mjs puts its JSON error in the message), so the chat bodies show it
 * as typed: in a code block (none when it is empty), which keeps a masked
 * link "[label](url)", a spoiler or a heading from rendering. Its backticks
 * are swapped for ˋ so it cannot close the block, and half surrogate pairs
 * (cut upstream) for U+FFFD. Slack's body also escapes &, < and >, without which
 * "<!channel>" pings the channel and "<url|label>" is a link under any label,
 * and unfurls no link (unfurl_links, unfurl_media).
 * Discord's parses no mentions ("@everyone"), shows no link previews (flags 4,
 * SUPPRESS_EMBEDS), and its cut to 2000 keeps the block closed and no half
 * surrogate pair.
 */
export function webhookBody(alert, format = "json", protocol = "") {
  const head = `${alert.severity === "critical" ? "🚨" : "⚠️"} ${alert.title}${protocol ? ` (protocol ${protocol})` : ""}`;
  const detail = alert.detail.toWellFormed().replaceAll("`", "ˋ");
  const block = (d) => (d ? `${OPEN}${d}${CLOSE}` : "");
  if (format === "slack") return { text: `${head}${block(detail)}`.replace(/[&<>]/g, (c) => SLACK_ESCAPES[c]), unfurl_links: false, unfurl_media: false };
  if (format === "discord") {
    const cut = firstUnits(detail, 2000 - head.length - OPEN.length - CLOSE.length);
    return { content: `${head}${block(cut)}`, allowed_mentions: { parse: [] }, flags: 4 };
  }
  return { ...alert, protocol };
}

/**
 * The JSON text of a log line or a webhook body. An RPC's error text cut by
 * UTF-16 units (`.slice(0, 160)`) can end in half a surrogate pair, which
 * JSON.stringify writes as "\ud83d": strict parsers (Rust's serde_json)
 * refuse the whole line or body. Each string value is made well-formed
 * (U+FFFD for a half pair; keys are the guardian's own names) and a bigint
 * is written as its digits.
 */
export function jsonText(v) {
  return JSON.stringify(v, (_, x) => (typeof x === "string" ? x.toWellFormed() : typeof x === "bigint" ? x.toString() : x));
}

/**
 * A sender: `send(line)` returns at once; the POST runs in the background with
 * a timeout. `fetchFn` and `onError` are injectable for tests. `protocol` may
 * be a function: the guardian creates its alerter before it knows the
 * protocol, so a failed startup alerts too.
 */
/**
 * Posts alerts to the webhook. A delivery that fails (a timeout, a 5xx, a 429)
 * is tried again after each of `retryDelaysMs`; one never delivered is
 * un-muted, so its next occurrence is tried again rather than suppressed for
 * the window. One failed post used to drop even a freeze's alert and mute it
 * for 10 minutes (docs/09, finding 83). The body's format is formatFor's.
 */
export function alerter({ url, format, protocol = "", windowMs, timeoutMs = 5_000, retryDelaysMs = [1_000, 3_000, 9_000] } = {}, { fetchFn = globalThis.fetch, onError = () => {}, now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const seen = new Map();
  const inflight = new Set();
  const bodyFormat = formatFor(url, format);
  function send(line) {
    if (!url) return;
    const alert = alertFor(line, seen, now(), { windowMs });
    if (!alert) return;
    const body = jsonText(webhookBody(alert, bodyFormat, typeof protocol === "function" ? protocol() : protocol));
    const post = async () => {
      const r = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(timeoutMs) });
      if (!r.ok) throw new Error(`webhook answered ${r.status}`);
    };
    const p = (async () => {
      for (let i = 0; ; i++) {
        try {
          return await post();
        } catch (e) {
          if (i >= retryDelaysMs.length) {
            seen.delete(alert.kind);
            onError(e);
            return;
          }
          await sleep(retryDelaysMs[i]);
        }
      }
    })().finally(() => inflight.delete(p));
    inflight.add(p);
  }
  /** Wait for alerts in flight (tests, and a clean exit). */
  send.flush = () => Promise.allSettled([...inflight]);
  return send;
}
