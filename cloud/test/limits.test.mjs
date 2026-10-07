// Cross-language differential: the JavaScript limiter views against the Python
// reference (which is itself checked against the Rust core on millions of
// cases). Python generates random edge cases and the expected outputs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { emaUpdate, touchReference, attestLocal, capacityFromRef, maxUnbackedOver, availableNow } from "../lib/limits.mjs";

const reference = fileURLToPath(new URL("../../reference", import.meta.url));
const script = `
import random, sys, json
sys.path.insert(0, ${JSON.stringify(reference)})
import bulkhead_ref as ref, diff_runner as D, protocol as P
r = random.Random(20260927)
s = P.Session()
out = []
while len(out) < 30000:
    line = D.gen_pure(r)
    if line[0] in "KEM" and line[1] == " ":
        out.append([line, s.run_line(line)])
# available_now: random bucket states
for _ in range(10000):
    c1, w1 = r.choice([0, 1, 200_000_000_000, r.randrange(0, 1 << 64)]), r.randrange(1, 10**9)
    c2, w2 = r.choice([0, 1, 500_000_000_000, r.randrange(0, 1 << 64)]), r.randrange(1, 10**10)
    now = r.randrange(0, 1 << 44)
    lim = ref.Limiter(c1, w1, c2, w2, 0, 1)
    lim.tat1 = now + r.choice([-w1, 0, 1, w1 // 2, w1, w1 + 1, r.randrange(-(1 << 40), 1 << 40)])
    lim.tat2 = now + r.choice([-w2, 0, 1, w2 // 2, w2, r.randrange(-(1 << 40), 1 << 40)])
    out.append([f"A* {c1} {w1} {c2} {w2} {lim.tat1} {lim.tat2} {now}", f"A {lim.available_now(now)}"])
print(json.dumps(out))
`;

test("JS limiter views match the Python reference on 40,000 edge cases", () => {
  const cases = JSON.parse(execFileSync("python3", ["-c", script], { maxBuffer: 1 << 28 }).toString());
  const counts = {};
  for (const [line, want] of cases) {
    const t = line.split(" ");
    let got;
    switch (t[0]) {
      case "K":
        got = `K ${capacityFromRef(BigInt(t[1]), BigInt(t[2]), BigInt(t[3]), BigInt(t[4]))}`;
        break;
      case "E":
        got = `E ${emaUpdate(BigInt(t[1]), BigInt(t[2]), BigInt(t[3]), BigInt(t[4]), t[5] === "1")}`;
        break;
      case "M": {
        const p = { short: { capacity: BigInt(t[1]), windowMs: BigInt(t[2]) }, long: { capacity: BigInt(t[3]), windowMs: BigInt(t[4]) } };
        got = `M ${maxUnbackedOver(p, BigInt(t[5]))}`;
        break;
      }
      case "A*": {
        const p = { short: { capacity: BigInt(t[1]), windowMs: BigInt(t[2]) }, long: { capacity: BigInt(t[3]), windowMs: BigInt(t[4]) } };
        got = `A ${availableNow(BigInt(t[5]), BigInt(t[6]), p, BigInt(t[7]))}`;
        break;
      }
    }
    assert.equal(got, want, line);
    counts[t[0]] = (counts[t[0]] ?? 0) + 1;
  }
  for (const k of ["K", "E", "M", "A*"]) assert.ok(counts[k] > 2000, `coverage ${k}: ${counts[k]}`);
});

test("the touched reference drops at once to the balance and rises slowly (finding 65)", () => {
  // Rising: the EMA step, as before.
  assert.equal(touchReference(1_000n, 0, 2_000n, 43_200, true), emaUpdate(1_000n, 0, 2_000n, 43_200, true));
  assert.equal(touchReference(1_000n, 0, 2_000n, 43_200, true), 1_500n);
  // Falling: straight to the balance, not halfway.
  assert.equal(emaUpdate(1_000n, 0, 200n, 43_200, true), 600n);
  assert.equal(touchReference(1_000n, 0, 200n, 43_200, true), 200n);
  assert.equal(touchReference(1_000n, 0, 200n, 0, true), 200n, "even with no time passed");
  assert.equal(touchReference(0n, 0, 5_000n, 0, false), 5_000n, "first touch: the balance");
  // attestLocal's figures use it: a vault whose stored reference sits above
  // the live balance is limited by the balance.
  const limits = { shortBps: 200, shortWindowS: 3_600, longBps: 500, longWindowS: 86_400, minQueueDelayS: 21_600, shortFloor: 0n, longFloor: 0n, shortCap: 0n, longCap: 0n };
  const vault = { refBalance: 10_000_000n, refUpdatedS: 0, refInitialized: true, limits, tatShortMs: 0n, tatLongMs: 0n, frozenUntil: 0, queuedAmount: 0n, pendingTickets: 0 };
  const a = attestLocal(vault, { frozenUntil: 0 }, 1_000_000n, 1);
  assert.equal(a.worst1h, attestLocal({ ...vault, refBalance: 1_000_000n }, { frozenUntil: 0 }, 1_000_000n, 1).worst1h);
});
