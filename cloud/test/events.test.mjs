// Log attribution for the guardian. A `Program data:` line counts only when
// the innermost invoked program is one of ours, and a truncated log is visible.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseEvents } from "../lib/solana.mjs";
import { missedInstant } from "../guardian/policy.mjs";

const VAULT = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
const OTHER = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const FLOOR = "HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E";

const data = (name) => `Program data: ${Buffer.from(name).toString("base64")}`;

test("events are attributed to the innermost invoked program", () => {
  const logs = [
    `Program ${OTHER} invoke [1]`,
    data("foreign:nope"),
    `Program ${VAULT} invoke [2]`,
    data("vault:released"),
    `Program ${OTHER} invoke [3]`,
    data("token:inside"),
    `Program ${OTHER} success`,
    data("vault:after-cpi"),
    `Program ${VAULT} success`,
    data("foreign:after"),
    `Program ${OTHER} success`,
  ];
  const { events, truncated } = parseEvents(logs, { programs: [VAULT, FLOOR] });
  assert.equal(truncated, false);
  assert.deepEqual(events.map((e) => e.name), ["vault:released", "vault:after-cpi"]);
  assert.ok(events.every((e) => e.program === VAULT));
});

test("a foreign program's line is ignored even when it copies our event name", () => {
  const logs = [
    `Program ${OTHER} invoke [1]`,
    data("vault:released"),
    data("vault:frozen"),
    `Program ${OTHER} success`,
  ];
  const { events } = parseEvents(logs, { programs: [VAULT, FLOOR] });
  assert.equal(events.length, 0);
});

test("a truncated log is flagged", () => {
  const logs = [`Program ${VAULT} invoke [1]`, data("vault:frozen"), "Log truncated"];
  const parsed = parseEvents(logs, { programs: [VAULT] });
  assert.equal(parsed.truncated, true);
  assert.equal(parsed.events.length, 1);
  assert.equal(parseEvents([...logs, "Program log: Log truncated"], { programs: [VAULT] }).truncated, true);
});

test("floor lines count and vault lines still count in the same transaction", () => {
  const logs = [
    `Program ${FLOOR} invoke [1]`,
    data("floor:proposed"),
    `Program ${FLOOR} success`,
    `Program ${VAULT} invoke [1]`,
    data("vault:sealed"),
    `Program ${VAULT} success`,
  ];
  const { events } = parseEvents(logs, { programs: [VAULT, FLOOR] });
  assert.deepEqual(
    events.map((e) => [e.program, e.name]),
    [
      [FLOOR, "floor:proposed"],
      [VAULT, "vault:sealed"],
    ],
  );
});

test("missed instant is only the chain increase events did not already report", () => {
  assert.equal(missedInstant(12n, 5n), 7n);
  assert.equal(missedInstant(5n, 5n), 0n);
  assert.equal(missedInstant(4n, 9n), 0n);
});
