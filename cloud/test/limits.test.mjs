// Cross-language differential: the JavaScript limiter views against the Python
// reference and the Rust core (the worker `cargo build --release -p
// bulkhead-diff` builds; so does scripts/check.sh's `cargo test` step).
// Python generates the cases and both answer; JS must agree with both (the
// arbitrary states at the end are checked against Python only).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emaUpdate, windowLowTouch, attestLocal, capacityFromRef, maxUnbackedOver, availableNow } from "../lib/limits.mjs";

const reference = fileURLToPath(new URL("../../reference", import.meta.url));
const script = `
import random, sys, json
sys.path.insert(0, ${JSON.stringify(reference)})
import bulkhead_ref as ref, diff_runner as D, protocol as P
D.check_worker()
r = random.Random(20260927)
lines, source = [], []
def add(new, src):
    lines.extend(new)
    source.extend([src] * len(new))
while len(lines) < 30000:
    line = D.gen_pure(r)
    if (line[0] in "KEM" and line[1] == " ") or line.startswith("EL "):
        add([line], "realistic")
# Full-range inputs, which gen_pure samples only in realistic ranges.
for _ in range(10000):
    add([D.gen_full_range(r)], "full")
# Limiter sessions: the JS side follows each state through the R/Z/W answers
# and computes every A (available now) from it. A third at full range.
for i in range(1500):
    if i % 3 == 0:
        add(D.gen_full_range_session(r), "full")
    else:
        add(D.gen_limiter_session(r), "realistic")
py = P.run_lines(lines)
rs = D.run_worker(lines)
assert len(py) == len(rs) == len(lines), (len(lines), len(py), len(rs))
out = [list(c) for c in zip(lines, py, rs, source)]
# available_now on arbitrary bucket states, against Python only: the worker
# has no command that sets a state. Rust sees the states the sessions reach.
for _ in range(10000):
    c1, w1 = r.choice([0, 1, 200_000_000_000, r.randrange(0, 1 << 64)]), r.randrange(1, 10**9)
    c2, w2 = r.choice([0, 1, 500_000_000_000, r.randrange(0, 1 << 64)]), r.randrange(1, 10**10)
    now = r.randrange(0, 1 << 44)
    lim = ref.Limiter(c1, w1, c2, w2, 0, 1)
    lim.tat1 = now + r.choice([-w1, 0, 1, w1 // 2, w1, w1 + 1, r.randrange(-(1 << 40), 1 << 40)])
    lim.tat2 = now + r.choice([-w2, 0, 1, w2 // 2, w2, r.randrange(-(1 << 40), 1 << 40)])
    out.append([f"A* {c1} {w1} {c2} {w2} {lim.tat1} {lim.tat2} {now}", f"A {lim.available_now(now)}", None, "state"])
print(json.dumps(out))
`;

test("JS limiter views match Python and Rust on 40,000 edge cases and every available-now view in 1,500 limiter sessions, and Python on 10,000 states", () => {
  const cases = JSON.parse(execFileSync("python3", ["-c", script], { maxBuffer: 1 << 28 }).toString());
  const counts = {};
  const bucketPair = (t) => ({ short: { capacity: BigInt(t[1]), windowMs: BigInt(t[2]) }, long: { capacity: BigInt(t[3]), windowMs: BigInt(t[4]) } });
  let session = null;
  // A failure prints its line with the session before it: a replayable
  // fixture for diff_runner.py --replay.
  let replay = [];
  for (const [line, want, rust, source] of cases) {
    const t = line.split(" ");
    if (t[0] === "L") replay = [];
    if (["L", "R", "Z", "W", "A"].includes(t[0])) replay.push(line);
    else replay = [line];
    if (rust !== null && rust !== want) assert.fail(`Rust ${rust} vs Python ${want}:\n${replay.join("\n")}`);
    let got;
    switch (t[0]) {
      case "K":
        got = `K ${capacityFromRef(BigInt(t[1]), BigInt(t[2]), BigInt(t[3]), BigInt(t[4]))}`;
        break;
      case "E":
        got = `E ${emaUpdate(BigInt(t[1]), BigInt(t[2]), BigInt(t[3]), BigInt(t[4]), t[5] === "1")}`;
        break;
      case "EL": {
        const l = windowLowTouch({ prev: BigInt(t[1]), cur: BigInt(t[2]), window: BigInt(t[3]) }, BigInt(t[4]), BigInt(t[5]), t[6] === "1");
        got = `EL ${l.prev} ${l.cur} ${l.window}`;
        break;
      }
      case "M":
        got = `M ${maxUnbackedOver(bucketPair(t), BigInt(t[5]))}`;
        break;
      case "A*":
        got = `A ${availableNow(BigInt(t[5]), BigInt(t[6]), bucketPair(t), BigInt(t[7]))}`;
        break;
      // A session: the state comes from the answers, the view from the port.
      case "L":
        assert.equal(want, "L ok", line);
        session = { params: bucketPair(t), tatShort: 0n, tatLong: 0n };
        continue;
      case "R":
      case "Z":
      case "W":
        if (t[0] === "W") {
          session.params.short.windowMs = BigInt(t[2]);
          session.params.long.windowMs = BigInt(t[3]);
        }
        if (!want.startsWith("X ")) [session.tatShort, session.tatLong] = want.split(" ").slice(-2).map(BigInt);
        continue;
      case "A": {
        const now = BigInt(t[1]);
        got = `A ${availableNow(session.tatShort, session.tatLong, session.params, now)}`;
        // A view of a bucket with a backlog, not just a full one.
        if (session.tatShort > now || session.tatLong > now) counts[`${source} A backlog`] = (counts[`${source} A backlog`] ?? 0) + 1;
        break;
      }
    }
    if (got !== want) assert.fail(`JS ${got} vs Python ${want}:\n${replay.join("\n")}`);
    const k = `${source} ${t[0]}`;
    counts[k] = (counts[k] ?? 0) + 1;
  }
  for (const src of ["realistic", "full"]) {
    for (const k of ["K", "E", "EL", "M", "A"]) assert.ok(counts[`${src} ${k}`] > 2000, `coverage ${src} ${k}: ${counts[`${src} ${k}`]}`);
    assert.ok(counts[`${src} A backlog`] > 1000, `coverage ${src} A with a backlog: ${counts[`${src} A backlog`]}`);
  }
  assert.ok(counts["state A*"] > 2000, `coverage A*: ${counts["state A*"]}`);
});

test("the base is the least of the reference, the balance and the low-water balance (finding 65)", () => {
  const limits = { shortBps: 200, shortWindowS: 3_600, longBps: 500, longWindowS: 86_400, minQueueDelayS: 21_600, shortFloor: 0n, longFloor: 0n, shortCap: 0n, longCap: 0n };
  const at = (refBalance, low, balance, nowS) =>
    attestLocal({ refBalance, refUpdatedS: nowS, refInitialized: true, low, limits, tatShortMs: 0n, tatLongMs: 0n, frozenUntil: 0, queuedAmount: 0n, pendingTickets: 0 }, { frozenUntil: 0 }, balance, nowS);
  const T = 1_800 * 1_000;
  // A deposit taken back in the window: the 1M low counts, not the 10M balance.
  const flash = at(10_000_000n, { prev: 10_000_000n, cur: 1_000_000n, window: 1_000n }, 10_000_000n, T + 5);
  assert.equal(flash.availableNow, 20_000n);
  // Two windows later the low has rolled off: the 10M reference and balance.
  const later = at(10_000_000n, { prev: 10_000_000n, cur: 1_000_000n, window: 1_000n }, 10_000_000n, T + 2 * 1_800 + 5);
  assert.equal(later.availableNow, 200_000n);
  // The live balance still caps it at once (A1).
  assert.equal(at(10_000_000n, { prev: 10_000_000n, cur: 10_000_000n, window: 1_000n }, 1_000_000n, T + 5).availableNow, 20_000n);
});
