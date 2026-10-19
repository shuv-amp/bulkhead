// Paging getSignaturesForAddress. Pages come back newest-first.
// One page is not the whole gap: the guardian used to request 100 signatures
// and then move its cursor to the newest, which dropped everything between
// that page and the previous cursor.

export const SIG_PAGE = 1000;
/** Emit a progress callback every this many pages during a long recovery. */
export const PAGE_LOG_INTERVAL = 40;

export function pageQuery({ before, until, limit = SIG_PAGE, minSlot = null } = {}) {
  const q = { limit, commitment: "confirmed" };
  if (before) q.before = before;
  if (until) q.until = until;
  // A node behind the cursor's slot answers -32016 (failed over), instead of
  // ignoring an `until` it does not have.
  if (minSlot) q.minContextSlot = minSlot;
  return q;
}

/**
 * Rows a walk after a cursor still needs: past the cursor's slot, or in it
 * and not read yet. Agave treats an `until` signature it does not have as no
 * bound and lists back to its oldest block (blockstore
 * `get_confirmed_signatures_for_address2`): a node behind the cursor, or one
 * missing it, returned history the guardian had already counted, and counted
 * it again (docs/09, finding 81).
 */
export function afterCursor(rows, minSlot, seen) {
  if (minSlot == null) return { rows, reachedBack: false };
  // Newest-first: from the first row already read, everything is older.
  const at = seen ? rows.findIndex((s) => seen.has(s.signature)) : -1;
  const upto = at >= 0 ? rows.slice(0, at) : rows;
  const keep = upto.filter((s) => s.slot > minSlot || (s.slot === minSlot && !seen?.has(s.signature)));
  return { rows: keep, reachedBack: at >= 0 || rows.some((s) => s.slot < minSlot) };
}

/**
 * An empty page after a full one ends a walk only if the node has the `before`
 * signature: then nothing is older (the last page was exactly full). A node
 * that lacks it (a failover mid-walk) also answers `[]`, and ending the walk
 * there skipped what lay between it and the cursor (docs/09, finding 81).
 * `knows(signature)` asks the node; without it the page is taken as the end.
 */
async function endOfWalk(before, knows) {
  if (!before || !knows) return;
  if (await knows(before)) return;
  throw new Error(`the node returned nothing before ${before}, the oldest signature of a full page, and does not have it: walking again`);
}

/**
 * True when this page may have older signatures the caller still needs.
 * `oldestWanted == null` is the live walk: only a short page ends it, so a
 * burst larger than one page is not dropped. A startup walk also stops once
 * the oldest signature on the page is already outside the window.
 */
export function morePages(page, limit, oldestWanted) {
  if (!page || page.length < limit) return false;
  if (oldestWanted == null) return true;
  const oldest = page[page.length - 1]?.blockTime;
  if (oldest == null) return true;
  return oldest >= oldestWanted;
}

/**
 * Walk every page, newest-first, until the live cursor or startup time bound.
 * A live walk passes the cursor's slot (`minSlot`) and the signatures already
 * read in it (`seen`): rows at or before the cursor are dropped, and a page
 * that reaches back past it ends the walk.
 */
export async function signatureWalk(fetchPage, { until, oldestWanted, limit = SIG_PAGE, onPage = () => {}, minSlot = null, seen = null, knows = null, maxRows = Infinity } = {}) {
  const out = [];
  let before;
  for (let page = 0; ; page++) {
    // A bound on a startup walk: spam can put millions of signatures in the
    // window, and nothing is watched until the walk is read (docs/09, finding 83).
    if (out.length >= maxRows) {
      out.truncated = true;
      break;
    }
    const query = pageQuery({ before, until, limit, minSlot });
    const signatures = await fetchPage(query);
    if (!signatures?.length) {
      await endOfWalk(before, knows);
      break;
    }
    const { rows, reachedBack } = afterCursor(signatures, minSlot, seen);
    out.push(...rows);
    onPage(page + 1, signatures.length);
    if (reachedBack || !morePages(signatures, limit, oldestWanted)) break;
    const nextBefore = signatures.at(-1).signature;
    if (nextBefore === before) throw new Error(`signature walk made no progress before ${nextBefore}`);
    before = nextBefore;
  }
  return out;
}

/**
 * Whether `e` says the node no longer has the cursor `signature`. A node keeps
 * a limited history; on a quiet protocol the last signature the guardian read
 * ages out, and every `until: <it>` query then fails. The guardian used to
 * retry that query forever, reading nothing new: an attack included.
 */
export function cursorGone(e, signature) {
  const message = e?.rpcError?.message ?? e?.message ?? "";
  return Boolean(signature) && message.includes(signature) && /not found/i.test(message);
}

/**
 * The signatures after a cursor the node no longer has: walk back from the
 * newest without `until`, and keep what is past the cursor's slot, or in its
 * slot and not ingested yet (`seen`). Stops at the first page that reaches
 * back before that slot.
 */
export async function signatureWalkSinceSlot(fetchPage, { slot, seen = new Set(), limit = SIG_PAGE } = {}) {
  const out = [];
  let before;
  for (;;) {
    const page = await fetchPage(pageQuery({ before, limit }));
    if (!page?.length) break;
    for (const s of page) if (s.slot > slot || (s.slot === slot && !seen.has(s.signature))) out.push(s);
    if (page.length < limit || page.at(-1).slot < slot) break;
    const next = page.at(-1).signature;
    if (next === before) throw new Error(`signature walk made no progress before ${next}`);
    before = next;
  }
  return out;
}

/**
 * One poll of an account followed on its own (a watched Floor config).
 * `cursor` is the last signature read ({ signature, slot }), or null for none
 * yet. Returns `{ sigs, cursor, status }`, `sigs` newest-first as pages come:
 *   "anchored": no cursor; it is now the newest signature, and nothing is read
 *   "empty":    no cursor, and the node returned no signature: still none, ask
 *               again next poll. A null cursor used to stay, and the next
 *               walk had no `until`: the config's whole history, read live
 *               (old proposals vetoed again, old recovery keys alerted)
 *   "ok":       every signature after the cursor
 *   "gap":      a restart resuming a saved cursor walks back only to
 *               `oldestWanted` (the Vault startup's bound), and stopped there
 *               before reaching the cursor: what lies between was not read
 *   "gone":     the node no longer has the cursor; re-anchored at the newest,
 *               and nothing in between was read
 * (docs/09, finding 71).
 */
export async function followAccount(fetchPage, { cursor = null, oldestWanted = null, limit = SIG_PAGE, knows = null } = {}) {
  const anchor = async (status) => {
    const newest = (await fetchPage({ limit: 1, commitment: "confirmed" }))?.[0];
    if (!newest) return { sigs: [], cursor: null, status: status === "gone" ? "gone" : "empty" };
    return { sigs: [], cursor: { signature: newest.signature, slot: newest.slot ?? 0 }, status };
  };
  if (!cursor?.signature) return anchor("anchored");
  const out = [];
  let before;
  try {
    for (;;) {
      const page = await fetchPage(pageQuery({ before, until: cursor.signature, limit, minSlot: cursor.slot || null }));
      if (!page?.length) {
        await endOfWalk(before, knows);
        break;
      }
      // The cursor's own signature is the one row of its slot already read.
      const { rows, reachedBack } = afterCursor(page, cursor.slot || null, new Set([cursor.signature]));
      out.push(...rows);
      if (reachedBack || page.length < limit) break;
      const oldest = page.at(-1).blockTime;
      if (oldestWanted != null && oldest != null && oldest < oldestWanted) return { sigs: out, cursor, status: "gap" };
      const next = page.at(-1).signature;
      if (next === before) throw new Error(`signature walk made no progress before ${next}`);
      before = next;
    }
  } catch (e) {
    if (!cursorGone(e, cursor.signature)) throw e;
    return anchor("gone");
  }
  return { sigs: out, cursor, status: "ok" };
}

/**
 * One poll of each watched Floor config (`configs`: `{ address, program }`):
 * followAccount from its cursor in `cursors`, then `ingest(sigs, live,
 * checkpoint, program)`. A config not yet in `followed` resumes, walking back
 * to `oldestWanted()` at most (a day back, as the gap message says), and what
 * landed before the start is a replay (not live; see below). One config whose
 * walk or ingest fails no longer stops the
 * configs after it: the others are followed, and then this throws, naming
 * each that failed, so a failure that lasts raises the stall alert. A plain
 * loop used to stop at the first failure, and the later programs' executions
 * and recovery keys went unread until it recovered. Each config's progress
 * is saved, a failed one's checkpoints included. They stay in turn, as
 * scanAll's scans do: ingesting acts and checkpoints, and walked together, a
 * config listed twice would be read twice from the same cursor. So an outage
 * of every endpoint costs one timeout per config.
 *
 * The line is the slot this process started at (`liveAfterSlot`, from
 * startSlot), on every poll: the first signature listed in a slot at or
 * before it, and all listed after it, are replayed; the newer ones are
 * live. It used to be the first good poll: a restart
 * whose replay failed stayed a replay until one succeeded, and one that
 * succeeded replayed what landed during the Vault startup, so a recovery
 * key replaced, a stop or an ejection after the start was read silently.
 * Without `liveAfterSlot`, a config resuming replays all it reads, and a
 * followed one acts on all. The node lists newest-first by slot (the walk
 * relies on it too), so the older part is replayed first and the newer one
 * then ingested live. A followed config that lists rows from before the
 * start (a lagging node, or a start slot from an endpoint ahead of its
 * chain) says so, with the slots, once they are read.
 */
export async function followConfigs(configs, { page, cursors, followed, oldestWanted, knows, ingest, log, saved = () => {}, liveAfterSlot = null }) {
  const failed = [];
  for (const { address, program } of configs) {
    try {
      const resuming = !followed.has(address);
      const r = await followAccount((q) => page(address, q), { cursor: cursors.get(address) ?? null, oldestWanted: resuming ? oldestWanted() : null, knows });
      if (r.status === "gone") {
        log({ level: "error", msg: "the node no longer has the Floor config's cursor signature; reading on from its newest. Floor history in the gap was not reviewed: check this program's proposals, executions and recovery key by hand", program });
      } else if (r.status === "gap") {
        log({ level: "error", msg: "Floor history older than a day, back to the saved cursor, was not reviewed: check this program's proposals, executions and recovery key by hand", program });
      }
      if (r.cursor) cursors.set(address, r.cursor);
      else cursors.delete(address);
      // No signature at all yet: ask again next poll, never from genesis.
      if (r.status === "empty") continue;
      const checkpoint = (signature, s) => cursors.set(address, { signature, slot: s.slot ?? 0 });
      const k = liveAfterSlot == null ? (resuming ? 0 : r.sigs.length) : newerThan(r.sigs, liveAfterSlot);
      const live = r.sigs.slice(0, k);
      const replay = r.sigs.slice(k);
      if (replay.length) await ingest(replay, false, checkpoint, program);
      // Once read, so a replay that keeps failing is not said again each poll.
      if (!resuming && replay.length) {
        // A row with no slot can sit in the replay part; the first row has one.
        const known = replay.map((s) => s.slot).filter((s) => s != null);
        const slots = [Math.min(...known), Math.max(...known)];
        log({ level: "warn", msg: `a followed Floor config listed transactions at or before the start slot: replayed, not acted on. A lagging RPC node (they landed before this process started), or a start slot from an endpoint ahead of its chain (they landed after it, and their events were not reported): ${replay.length} rows in slots ${slots[0]}-${slots[1]}, start slot ${liveAfterSlot}`, program, rows: replay.length, startSlot: liveAfterSlot, slots });
      }
      if (live.length) await ingest(live, true, checkpoint, program);
      followed.add(address);
    } catch (e) {
      failed.push(`${program}: ${e?.message ?? e}`);
    } finally {
      saved();
    }
  }
  if (failed.length) throw new Error(failed.join("; "));
}

/** How many of newest-first `sigs` come before the first in a slot at or
 * before `slot`. A row with no slot (null over JSON-RPC) never ends them, so
 * one among the newest is acted on (twice at worst, never unsaid); one below
 * the line is older than it, and replayed with it. */
function newerThan(sigs, slot) {
  const k = sigs.findIndex((s) => s.slot != null && s.slot <= slot);
  return k < 0 ? sigs.length : k;
}

/**
 * The slot a restart's Floor replay runs up to (followConfigs'
 * `liveAfterSlot`): the highest confirmed slot that any of a FailoverRpc's
 * endpoints gives. One endpoint behind would put the line early, and what
 * landed while the guardian was down would be acted on as new. Each endpoint
 * is admitted first, as crossCheck does (one not yet checked is asked its
 * genesis hash again): one unchecked or on another cluster is never read. Its
 * slot, higher, replayed every Floor event; lower, acted on what landed while
 * the guardian was down (docs/09, finding 131). If none answers, or `rpc` has
 * no endpoints (a plain Rpc), `rpc` itself is asked: an endpoint asked
 * directly leaves at once when busy (`hurry`), and FailoverRpc.call waits for
 * one once. Throws when that fails too.
 */
export async function startSlot(rpc) {
  const slot = (e) => e.call("getSlot", [{ commitment: "confirmed" }]);
  const ask = (p) => p.catch(() => null);
  let slots = (await Promise.all((rpc.endpoints ?? []).map((e, i) => ask(rpc.admit(i).then((ok) => (ok ? slot(e) : null)))))).filter(Number.isInteger);
  if (!slots.length) slots = [await ask(slot(rpc))].filter(Number.isInteger);
  if (!slots.length) throw new Error("no RPC endpoint gave its slot, so the Floor replay has no start");
  return Math.max(...slots);
}

/** Process one oldest-first signature batch, checkpointing only completed items. */
export async function ingestSignatures(signatures, ingestOne, checkpoint = () => {}) {
  for (const signature of [...signatures].reverse()) {
    await ingestOne(signature);
    checkpoint(signature.signature, signature);
  }
}

/**
 * Process a newest-first signature list oldest-first, with at most
 * `concurrency` transactions fetched ahead (`fetchOne(s)`), each processed
 * (`processOne(s, tx)`) strictly in order and checkpointed only once done.
 * Stops starting new ones once `budgetMs` has passed, and returns what is
 * left, still newest-first, for the next loop pass to continue.
 *
 * One "ingest" step used to fetch and process the whole backlog serially:
 * cheap `attest` spam at 40 tx/s with ~100 ms RPC latency put guardians
 * 178 s behind and growing, and the chain sync, freeze retry, ticket scan,
 * veto retry and heartbeats behind it waited the whole time, with no alert
 * (docs/09, finding 76). A failed fetch or process stops the batch at that
 * signature (the ones before it are done) and throws; fetches already in
 * flight are dropped quietly, never left as unhandled rejections.
 */
export async function ingestBudgeted(signatures, { fetchOne, processOne, checkpoint = () => {}, concurrency = 8, budgetMs = Infinity, nowMs = () => Date.now() }) {
  const queue = [...signatures].reverse();
  const started = nowMs();
  const inflight = [];
  let next = 0;
  const fill = () => {
    while (next < queue.length && inflight.length < concurrency) {
      const s = queue[next++];
      const p = Promise.resolve().then(() => fetchOne(s));
      p.catch(() => {}); // awaited below, in order; a dropped one must not crash the process
      inflight.push(p);
    }
  };
  let done = 0;
  while (done < queue.length) {
    if (done > 0 && nowMs() - started >= budgetMs) break;
    fill();
    const tx = await inflight.shift();
    await processOne(queue[done], tx);
    checkpoint(queue[done].signature, queue[done]);
    done++;
  }
  return queue.slice(done).reverse();
}

/**
 * How far ingestion is behind: the oldest unprocessed signature's block time
 * against the chain's latest block time, in seconds (0 with nothing left or
 * a time unknown). Lagging past `lagAlertS` is an urgent alert: a guardian
 * that reads a minute late freezes a minute late (docs/09, finding 76).
 */
export function ingestLagS(backlog, chainTimeS) {
  const oldest = backlog?.at(-1)?.blockTime;
  if (oldest == null || chainTimeS == null) return 0;
  return Math.max(0, chainTimeS - oldest);
}

/** A missing transaction is not an empty transaction: leave its cursor uncommitted and retry. */
/**
 * At startup only: a transaction the node will not return after `tries` is
 * skipped (`{ skipped: true }`) and reported through `onSkip`. One missing
 * old transaction used to end the process, and systemd restarted it into the
 * same replay: blind for good (docs/09, finding 83). Live, it still throws,
 * and the step retries it: nothing new is skipped.
 */
export async function transactionOrSkip(rpc, signature, { tries = 3, waitMs = 1_000, onSkip = () => {} } = {}) {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      return await requireTransaction(rpc, signature);
    } catch (e) {
      last = e;
      if (i + 1 < tries) await new Promise((r) => setTimeout(r, waitMs * (i + 1)));
    }
  }
  onSkip(signature, last);
  return { skipped: true };
}

export async function requireTransaction(rpc, signature) {
  const tx = await rpc.call("getTransaction", [signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }]);
  if (!tx?.meta) throw new Error(`getTransaction returned no transaction metadata for ${signature}; retrying`);
  return tx;
}
