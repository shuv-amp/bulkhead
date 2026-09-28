import { test } from "node:test";
import assert from "node:assert/strict";
import { morePages, pageQuery } from "../guardian/follow.mjs";

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
