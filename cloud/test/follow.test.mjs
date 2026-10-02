import { test } from "node:test";
import assert from "node:assert/strict";
import { ingestSignatures, morePages, pageQuery, requireTransaction, signatureWalk } from "../guardian/follow.mjs";

test("a full page is not the end of a live walk", () => {
  const page = Array.from({ length: 100 }, (_, i) => ({ signature: `s${i}`, blockTime: 1_000 - i }));
  assert.equal(morePages(page, 100, null), true);
});

test("a short page is the end", () => {
  assert.equal(morePages([{ signature: "a", blockTime: 100 }], 1000, null), false);
  assert.equal(morePages([], 1000, null), false);
});

test("a startup walk stops once the page crosses the cutoff", () => {
  const page = [
    { signature: "new", blockTime: 1_000_000 },
    { signature: "old", blockTime: 1 },
  ];
  assert.equal(morePages(page, 2, 500), false);
  assert.equal(morePages(page, 2, 0), true);
});

test("page query carries the cursor and does not invent one", () => {
  assert.deepEqual(pageQuery({ before: "b", until: "u", limit: 1000 }), {
    limit: 1000,
    commitment: "confirmed",
    before: "b",
    until: "u",
  });
  assert.deepEqual(pageQuery({}), { limit: 1000, commitment: "confirmed" });
});

test("a live signature walk does not truncate a backlog beyond 40 pages", async () => {
  let page = 0;
  const beforeValues = [];
  const signatures = await signatureWalk(async (query) => {
    beforeValues.push(query.before);
    page++;
    const count = page <= 41 ? 1000 : 1;
    return Array.from({ length: count }, (_, i) => ({ signature: `${page}:${i}`, blockTime: 50_000 - page * 1000 - i }));
  }, { until: "last-processed" });
  assert.equal(signatures.length, 41_001);
  assert.equal(page, 42);
  assert.equal(beforeValues[0], undefined);
  assert.equal(beforeValues[41], "41:999");
});

test("a failed item keeps the cursor at the last fully ingested signature", async () => {
  const batch = ["sig-c", "sig-b", "sig-a"].map((signature) => ({ signature }));
  let cursor = "sig-before";
  const ingested = [];
  let fail = true;
  await assert.rejects(ingestSignatures(batch, async ({ signature }) => {
    if (signature === "sig-c" && fail) {
      fail = false;
      throw new Error("temporary getTransaction failure");
    }
    ingested.push(signature);
  }, (signature) => { cursor = signature; }), /temporary getTransaction failure/);
  assert.equal(cursor, "sig-b");

  // `until: sig-b` returns the newer, unprocessed signature. The completed
  // prefix is not repeated and the failed item is retried.
  const retry = batch.filter(({ signature }) => signature === "sig-c");
  await ingestSignatures(retry, async ({ signature }) => { ingested.push(signature); }, (signature) => { cursor = signature; });
  assert.deepEqual(ingested, ["sig-a", "sig-b", "sig-c"]);
  assert.equal(cursor, "sig-c");
});

test("a null getTransaction result is retried instead of treated as empty logs", async () => {
  let calls = 0;
  const rpc = { call: async () => (++calls === 1 ? null : { meta: { logMessages: [] } }) };
  await assert.rejects(requireTransaction(rpc, "missing"), /returned no transaction/);
  assert.deepEqual(await requireTransaction(rpc, "missing"), { meta: { logMessages: [] } });
  assert.equal(calls, 2);
});
