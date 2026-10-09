#!/usr/bin/env python3
"""Extreme-value differential: full-range i64/i32/u32 inputs for the pure
pricing, valuation, EMA and low-water functions, which `diff_runner.py`'s
generator only samples in realistic ranges. Python reference vs Rust worker."""
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import protocol  # noqa: E402

r = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
I64 = (1 << 63) - 1
U64 = (1 << 64) - 1


def i64():
    return r.choice([-I64 - 1, -1, 0, 1, I64, I64 - 1, r.randrange(-I64 - 1, I64 + 1), r.randrange(-10**6, 10**6)])


def u64():
    return r.choice([0, 1, U64, U64 - 1, r.randrange(0, U64 + 1), r.randrange(0, 10**12)])


def u32():
    return r.choice([0, 1, 10000, (1 << 32) - 1, r.randrange(0, 1 << 32)])


L = []
for _ in range(40000):
    k = r.randrange(5)
    if k == 0:
        L.append(f"U {i64()} {u64()} {i64()} {i64()} {r.choice([0, 1, 60, I64, r.randrange(0, 1 << 32)])} {u32()}")
    elif k == 1:
        L.append(f"P {i64()} {u64()} {i64()} {u32()}")
    elif k == 2:
        L.append(f"V {r.choice([1, U64, r.randrange(0, 1 << 128)])} {r.choice([1, r.randrange(0, 1 << 128)])} "
                 f"{r.choice([-(1 << 31), (1 << 31) - 1, r.randrange(-60, 60)])} {r.randrange(0, 256)} {u32()} {r.randrange(2)}")
    elif k == 3:
        last = r.randrange(-(1 << 40), 1 << 40)
        now = last + r.randrange(-(1 << 40), 1 << 40)
        L.append(f"E {u64()} {last} {u64()} {now} {r.randrange(2)}")
    else:
        now = r.randrange(-(1 << 50), 1 << 50)
        w = now // 1800 + r.choice([-2, -1, 0, 1, 2, 3, r.randrange(-(1 << 30), 1 << 30)])
        L.append(f"EL {u64()} {u64()} {w} {u64()} {now} {r.randrange(2)}")

exp = protocol.run_lines(L)
act = subprocess.run([os.path.join(ROOT, "target/release/bulkhead-diff-worker")],
                     input="\n".join(L) + "\n", capture_output=True, text=True).stdout.splitlines()
bad = [i for i, (a, b) in enumerate(zip(exp, act)) if a != b]
print(len(L), len(exp), len(act), "mismatches", len(bad))
for i in bad[:8]:
    print(L[i], "| py", exp[i], "| rs", act[i])
sys.exit(1 if bad or len(exp) != len(act) else 0)
