// Paging getSignaturesForAddress. Pages come back newest-first.
// One page is not the whole gap: the guardian used to request 100 signatures
// and then move its cursor to the newest, which dropped everything between
// that page and the previous cursor.

export const SIG_PAGE = 1000;
/** Emit a progress callback every this many pages during a long recovery. */
export const PAGE_LOG_INTERVAL = 40;

export function pageQuery({ before, until, limit = SIG_PAGE } = {}) {
  const q = { limit, commitment: "confirmed" };
  if (before) q.before = before;
  if (until) q.until = until;
  return q;
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

/** Walk every page, newest-first, until the live cursor or startup time bound. */
export async function signatureWalk(fetchPage, { until, oldestWanted, limit = SIG_PAGE, onPage = () => {} } = {}) {
  const out = [];
  let before;
  for (let page = 0; ; page++) {
    const query = pageQuery({ before, until, limit });
    const signatures = await fetchPage(query);
    if (!signatures?.length) break;
    out.push(...signatures);
    onPage(page + 1, signatures.length);
    if (!morePages(signatures, limit, oldestWanted)) break;
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
export async function followAccount(fetchPage, { cursor = null, oldestWanted = null, limit = SIG_PAGE } = {}) {
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
      const page = await fetchPage(pageQuery({ before, until: cursor.signature, limit }));
      if (!page?.length) break;
      out.push(...page);
      if (page.length < limit) break;
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
export async function requireTransaction(rpc, signature) {
  const tx = await rpc.call("getTransaction", [signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }]);
  if (!tx?.meta) throw new Error(`getTransaction returned no transaction metadata for ${signature}; retrying`);
  return tx;
}
