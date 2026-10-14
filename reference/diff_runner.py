#!/usr/bin/env python3
"""Differential runner: Python reference vs Rust bulkhead-core.

Same method as SP-Differ (github.com/shuv-amp/sp-differ): generate cases,
run two independent implementations, and turn any disagreement into a small
replayable fixture under reference/regressions/.

  python3 reference/diff_runner.py                 # 20k cases, seed 1
  python3 reference/diff_runner.py --cases 200000 --seed 7
  python3 reference/diff_runner.py --replay reference/regressions/<file>.txt

Exit code 0 = all outputs identical. 1 = mismatch (fixture written).
"""
from __future__ import annotations

import argparse
import os
import random
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import protocol  # noqa: E402
import bulkhead_ref  # noqa: E402

WORKER = os.path.join(ROOT, "target", "release", "bulkhead-diff-worker")
U64 = (1 << 64) - 1
I64 = (1 << 63) - 1


def edge_u64(r: random.Random) -> int:
    return r.choice([0, 1, 2, 7, 10**6, 10**9, 10**12, 10**15, 10**18, U64 // 2, U64 - 1, U64,
                     r.randrange(0, 1 << 16), r.randrange(0, 1 << 40), r.randrange(0, U64 + 1)])


def gen_limiter_session(r: random.Random) -> list:
    hour, day = 3_600_000, 86_400_000
    c1 = r.choice([0, 1, 1000, 200_000, 10**9, 10**15, r.randrange(1, U64 + 1)])
    c2 = r.choice([0, 1, 5000, 500_000, 10**10, 10**16, r.randrange(1, U64 + 1)])
    if r.random() < 0.9:
        c1, c2 = max(c1, 1), max(c2, 1)
    w1 = r.choice([1, 1000, 60_000, hour, r.randrange(1, 7 * day)])
    w2 = r.choice([hour, day, 7 * day, r.randrange(1, 30 * day)])
    d = r.choice([0, 1, 60_000, 6 * hour, r.randrange(0, 2 * day)])
    horizon = r.choice([1, hour, 7 * day, 30 * day, r.randrange(1, 60 * day)])
    lines = [f"L {c1} {w1} {c2} {w2} {d} {horizon}"]
    now = r.choice([0, 1_700_000_000_000, r.randrange(0, 1 << 42)])
    frozen = 0
    for _ in range(r.randrange(1, 120)):
        now += r.choice([0, 0, 1, 1000, 60_000, hour, day, r.randrange(0, 3 * day)])
        roll = r.random()
        if roll < 0.08:
            frozen = now + r.choice([0, 60_000, hour, day])
        if roll < 0.75:
            base = max(c1, 1)
            amt = r.choice([0, 1, base // 10, base // 2, base, base * 2, base * 50, edge_u64(r)])
            amt = min(max(amt, 0), U64)
            lines.append(f"R {now} {amt} {frozen}")
        elif roll < 0.84:
            lines.append(f"Z {now} {r.choice([0, 0, 0, 1, 5])}")
        elif roll < 0.88:
            # A new LimitConfig: windows longer (a tightening), shorter, or the same.
            lines.append(f"W {now} {r.choice([1, 1000, 60_000, hour, 4 * hour, 30 * day, r.randrange(1, 1 << 32) * 1000])} "
                         f"{r.choice([hour, day, 7 * day, 30 * day, r.randrange(1, 1 << 32) * 1000])}")
        else:
            lines.append(f"A {now}")
    return lines


def gen_pure(r: random.Random) -> str:
    k = r.randrange(11)
    if k == 0:
        return f"K {edge_u64(r)} {r.choice([0, 1, 200, 500, 10000, r.randrange(0, 65536)])} {edge_u64(r)} {edge_u64(r)}"
    if k == 1 and r.randrange(2):
        now = r.randrange(-10_000, 2_000_000_000)
        window = now // 1_800 + r.choice([-3, -1, 0, 0, 1, 2, r.randrange(-(1 << 40), 1 << 40)])
        return f"EL {edge_u64(r)} {edge_u64(r)} {window} {edge_u64(r)} {now} {r.randrange(2)}"
    if k == 1:
        last = r.randrange(0, 2_000_000_000)
        now = last + r.choice([-5, 0, 1, 3600, 86_400, 200_000, r.randrange(0, 10**7)])
        return f"E {edge_u64(r)} {last} {edge_u64(r)} {now} {r.randrange(2)}"
    if k == 2:
        amt = r.choice([edge_u64(r), r.randrange(0, 1 << 100)])
        man = r.choice([0, 1, 99_980_000, 15_000_000_000, r.randrange(0, 1 << 63), r.randrange(0, 1 << 120)])
        return f"V {amt} {man} {r.randrange(-40, 25)} {r.randrange(0, 20)} {r.choice([0, 1, 8000, 9900, 10000, 10100, 20000, r.randrange(0, 1 << 20)])} {r.randrange(2)}"
    if k == 3:
        pr = r.choice([-1, 0, 1, 99_980_000, 15_000_000_000, r.randrange(-(1 << 20), I64)])
        ema = r.choice([-1, 0, 1, 15_100_000_000, r.randrange(-(1 << 20), I64)])
        return f"P {pr} {edge_u64(r)} {ema} {r.choice([0, 10000, 20000, r.randrange(0, 1 << 20)])}"
    if k == 4:
        now = r.randrange(1, 2_000_000_000)
        publ = now - r.choice([-10, 0, 5, 30, 60, 120, r.randrange(0, 10**6)])
        return f"U {r.randrange(-100, I64)} {edge_u64(r)} {publ} {now} {r.choice([0, 30, 60, 600])} {r.choice([0, 50, 100, 200, 10000])}"
    if k == 5:
        return f"M {edge_u64(r)} {r.randrange(1, 10**9)} {edge_u64(r)} {r.randrange(1, 10**10)} {r.randrange(-10, 10**11)}"
    if k == 6:
        def cfg():
            return [r.randrange(0, 10001), r.randrange(1, 100_000), r.randrange(0, 10001), r.randrange(1, 1_000_000),
                    r.randrange(0, 100_000), r.randrange(0, 10**9), r.randrange(0, 10**9),
                    r.choice([0, r.randrange(1, 10**9)]), r.choice([0, r.randrange(1, 10**9)])]
        old = cfg()
        new = old[:] if r.random() < 0.5 else cfg()
        if r.random() < 0.5:
            i = r.randrange(9)
            new[i] = cfg()[i]
        return "CL " + " ".join(map(str, old + new))
    if k == 7:
        def acfg():
            return [r.randrange(2), r.randrange(0, 10001), r.randrange(10000, 20001), r.randrange(0, 40001),
                    r.randrange(0, 600), r.randrange(0, 1000), r.randrange(0, 3)]
        old = acfg()
        new = old[:] if r.random() < 0.5 else acfg()
        if r.random() < 0.5:
            i = r.randrange(7)
            new[i] = acfg()[i]
        return f"CA {r.randrange(2)} " + " ".join(map(str, old + new))
    if k == 8:
        return f"CD {r.choice([259_200, 300_000, r.randrange(0, 10**7)])} {r.choice([0, 259_199, 259_200, 300_000, r.randrange(0, 10**7)])}"
    if k == 9:
        h = bytearray(b"\x7fELF\x02\x01\x01" + bytes(57))
        if r.random() < 0.2:
            h[r.randrange(0, 6)] ^= 0xFF
        h[18:20] = r.choice([0xF7, 0x107, 0x3E, r.randrange(0, 65536)]).to_bytes(2, "little")
        h[48:52] = r.choice([0, 1, 2, 3, 4, r.randrange(0, 1 << 32)]).to_bytes(4, "little")
        if r.random() < 0.05:
            h = h[: r.randrange(0, 52)]
        return "F " + (bytes(h).hex() or "00")
    return gen_governance(r) if r.random() < 0.3 else gen_backed(r)


def gen_governance(r: random.Random) -> str:
    k = r.randrange(6)
    now = r.choice([0, 1_775_059_518, r.randrange(0, 1 << 40)])
    if k == 0:
        return f"GS {now} {r.choice(['T', 'L'])} {r.choice([0, 3600, 259_199, 259_200, 604_800, r.randrange(0, 10**7)])}"
    if k == 1:
        e = r.randrange(0, 1 << 40)
        x = e + r.choice([0, 1, 604_800, r.randrange(0, 10**7)])
        t = r.choice([e - 1, e, x - 1, x, x + 1, r.randrange(0, 1 << 41)])
        return f"GX {e} {x} {t} {r.randrange(2)} {r.randrange(2)} {r.randrange(2)}"
    if k == 2:
        return f"GF {r.choice([0, now, now + 86_400, r.randrange(0, 1 << 41)])} {now} {r.choice([-1, 0, 1, 3600, 86_400, 86_401, r.randrange(-10, 200_000)])}"
    if k == 3:
        if r.random() < 0.2:   # times far apart, across all of i64: the gap must not overflow
            ext = [-(1 << 63), -1, 0, 1, (1 << 63) - 1, r.randrange(-(1 << 63), 1 << 63)]
            return f"GH {r.choice(ext)} {r.choice([86_400, 604_800, 2_592_000])} {r.choice(ext)}"
        last = r.randrange(0, 1 << 40)
        return f"GH {last} {r.choice([0, 86_399, 86_400, 604_800, 2_592_000, 2_592_001, r.randrange(0, 10**7)])} {last + r.choice([-1, 0, 86_400, 604_800, 604_801, r.randrange(0, 10**7)])}"
    if k == 4:
        return f"GQ {r.randrange(256)} {r.randrange(256)} {r.randrange(10)}"
    return f"GA {r.randrange(0, 1 << 32)} {r.randrange(0, 40)}"


def _mutate(r: random.Random, b: bytes) -> bytes:
    """One small edit: flip a byte, truncate, extend, or leave as is."""
    k = r.randrange(5)
    if not b or k == 0:
        return b
    if k == 1:
        i = r.randrange(len(b))
        return b[:i] + bytes([b[i] ^ (1 << r.randrange(8))]) + b[i + 1:]
    if k == 2:
        return b[:r.randrange(len(b))]
    if k == 3:
        return b + bytes([r.choice([0, 1, 255])]) * r.randrange(1, 9)
    return bytes(r.randrange(256) for _ in range(len(b)))


def _h(b: bytes) -> str:
    return b.hex() if b else "-"


def gen_guardian_set(r: random.Random) -> str:
    """A guardian set, mostly well formed, then broken in one way or another:
    a count out of range, a zero, forbidden or repeated key, a threshold or an
    interval at or past its bounds, cut short, or with bytes after it."""
    forbidden = [bytes(r.randrange(256) for _ in range(32)) for _ in range(2)]
    if r.random() < 0.2:
        forbidden[1] = bytes(32)   # no recovery key
    count = r.choice([2, 3, 3, 4, 5, 8, 8, r.randrange(0, 12)])
    keys = [bytes(r.randrange(256) for _ in range(32)) for _ in range(min(count, 9))]
    roll = r.random()
    if keys and roll < 0.1:
        keys[r.randrange(len(keys))] = bytes(32)
    elif keys and roll < 0.2:
        keys[r.randrange(len(keys))] = r.choice(forbidden)
    elif len(keys) > 1 and roll < 0.3:
        keys[r.randrange(1, len(keys))] = keys[0]
    th = r.choice([2, 2, 3, count - 1, count, count + 1, 1, 0, r.randrange(256)]) % 256
    interval = r.choice([86_400, 86_399, 30 * 86_400, 30 * 86_400 + 1, 7 * 86_400, 0, -1,
                         -(1 << 63), (1 << 63) - 1, r.randrange(-(1 << 63), 1 << 63)])
    b = bytes([count % 256]) + b"".join(keys) + bytes([th]) + interval.to_bytes(8, "little", signed=True)
    cut = r.random()
    if cut < 0.15:
        b = b[:r.randrange(0, len(b) + 1)]
    elif cut < 0.3:
        b += bytes(r.randrange(256) for _ in range(r.randrange(1, 20)))
    elif cut < 0.35:
        b = _mutate(r, b)
    return f"GP {_h(b)} {forbidden[0].hex()} {forbidden[1].hex()}"


def gen_floor(r: random.Random) -> str:
    """Floor: loader-v3 parsing, snapshot identity, abort binary, restore, eject."""
    k = r.randrange(8)
    key = bytes(r.randrange(256) for _ in range(32))
    opt = r.choice([b"\x00", b"\x01" + key, b"\x02" + key, b"\x01" + key[:r.randrange(32)]])
    tail = bytes(r.randrange(256) for _ in range(r.choice([0, 0, 3, 40])))
    if k == 0:
        tag = r.choice([1, 1, 1, 0, 2, 3, 2**32 - 1])
        return f"FB {_h(_mutate(r, tag.to_bytes(4, 'little') + opt + bytes(32) + tail))}"
    if k == 1:
        tag = r.choice([3, 3, 3, 1, 2])
        slot = r.choice([0, 1, 450_763_557, U64, r.randrange(0, U64 + 1)])
        return f"FP {_h(_mutate(r, tag.to_bytes(4, 'little') + slot.to_bytes(8, 'little') + opt + bytes(32) + tail))}"
    if k == 2:
        tag = r.choice([2, 2, 2, 1, 3])
        return f"FG {_h(_mutate(r, tag.to_bytes(4, 'little') + key + tail))}"
    if k == 3:
        n = r.choice([0, 1, 8, 64, r.randrange(0, 300)])
        region = bytes(r.randrange(256) for _ in range(n)) + bytes(r.choice([0, 1, 16, 200]))
        cut = r.randrange(0, len(region) + 2)
        buf = region[:cut]
        roll = r.random()
        if roll < 0.3:
            buf = _mutate(r, buf)
        elif roll < 0.45 and len(region) > cut:
            i = r.randrange(cut, len(region))
            region = region[:i] + bytes([r.randrange(1, 256)]) + region[i + 1:]
        return f"FS {_h(buf)} {_h(region)}"
    if k == 4:
        base = r.choice([bulkhead_ref.abort_elf(), bulkhead_ref.abort_elf_minimal()])
        return f"FC {_h(base if r.random() < 0.3 else _mutate(r, base))}"
    if k == 5:
        now = r.randrange(0, 1 << 40)
        eta = now + r.choice([-1, 0, 1, 259_200, r.randrange(-10**6, 10**6)])
        exp = eta + r.choice([0, 1, 604_800, r.randrange(-10, 10**6)])
        return (f"FR {r.choice(['S', 'P'])} {r.randrange(3)} {r.randrange(3)} {r.randrange(2)} "
                f"{r.randrange(2)} {now} {eta} {exp}")
    if k == 6:
        if r.random() < 0.3:
            return gen_guardian_set(r)
        if r.random() < 0.2:
            return f"GV {r.randrange(12)} {r.randrange(12)}"
        if r.random() < 0.5:   # realistic guardian sets, so both outcomes are common
            count = r.randrange(2, 9)
            th = r.randrange(1, count + 1)
            full = (1 << count) - 1
            return (f"GJ {r.choice([full, 0xFF, r.randrange(256)])} {r.choice([full, 0xFF, r.randrange(256)])} "
                    f"{th} {r.randrange(count + 1)} {count}")
        return f"GJ {r.randrange(256)} {r.randrange(256)} {r.randrange(10)} {r.randrange(10)} {r.randrange(10)}"
    return f"FH {_h(bytes(r.randrange(256) for _ in range(r.randrange(0, 41))))}"


def gen_backed(r: random.Random) -> str:
    mints = r.sample(range(1, 12), r.randrange(0, 9))
    j = r.choice(mints + [r.randrange(1, 12)]) if mints else r.randrange(1, 12)
    universe = set(mints) | {j}
    assets = []
    for m in universe:
        roll = r.random()
        if roll < 0.2:
            assets.append(f"{m} N 0 0 0 0 0 0")
        elif roll < 0.3:
            assets.append(f"{m} U 0 0 0 0 0 0")
        elif roll < 0.95:
            mid = r.choice([1, 99_980_000, 100_000_000, 15_000_000_000, 6_000_000_000_000, r.randrange(1, 1 << 40)])
            spread = r.choice([0, mid // 1000, mid // 100, r.randrange(0, mid + 1)])
            lo, hi = max(0, mid - spread), mid + spread
            expo = r.choice([-8, -8, -6, -10, r.randrange(-18, 3)])
            dec = r.choice([6, 9, 8, 0, r.randrange(0, 13)])
            assets.append(f"{m} P {lo} {hi} {expo} {dec} {r.choice([0, 8000, 8500, 9900, 10000, r.randrange(0, 10001)])} "
                          f"{r.choice([10000, 10100, 10500, r.randrange(10000, 20001)])}")
        # else: missing -> treated as not allowlisted
    pos = []
    for m in mints:
        mag = r.choice([1, 10**6, 10**9, 10**12, 10**15, r.randrange(1, 1 << 64), r.randrange(1, 1 << 70)])
        pos.append(f"{m} {mag if r.random() < 0.7 else -mag}")
    amount = r.choice([0, 1, 10**6, 10**9, 10**12, r.randrange(0, 1 << 40), r.randrange(0, U64 + 1), U64])
    return f"B {amount} {j} {len(assets)} {' '.join(assets)} {len(pos)} {' '.join(pos)}".replace("  ", " ")


def generate(seed: int, cases: int) -> list:
    r = random.Random(seed)
    lines = []
    produced = 0
    while produced < cases:
        roll = r.random()
        if roll < 0.08:
            lines.extend(gen_limiter_session(r))   # one session counts as one case
        elif roll < 0.46:
            lines.append(gen_backed(r))            # the ledger gets the most cases
        elif roll < 0.58:
            lines.append(gen_governance(r))
        elif roll < 0.70:
            lines.append(gen_floor(r))
        else:
            lines.append(gen_pure(r))
        produced += 1
    return lines


def worker_inputs() -> list:
    """The source files the worker was built from, as cargo recorded them in
    its dep-info file (`<worker>.d`). Only these can make it stale: a test file
    or a crate the worker does not use is not an input, and cargo does not
    relink the worker for one (a guess from directories refused for good
    after any test edit). Without the file, every source of both crates."""
    dep_info = WORKER + ".d"
    if os.path.exists(dep_info):
        text = open(dep_info).read().replace("\\\n", " ")
        _, _, deps = text.partition(": ")
        # Paths with spaces are written with a backslash before each space.
        return [p.replace("\\ ", " ") for p in re.split(r"(?<!\\) ", deps.split("\n")[0]) if p]
    found = []
    for top in ("crates/bulkhead-core/src", "crates/bulkhead-diff/src"):
        for d, _, files in os.walk(os.path.join(ROOT, top)):
            found += [os.path.join(d, f) for f in files if f.endswith(".rs")]
    return found


def newest_source() -> tuple:
    """(mtime, path) of the newest input the worker is built from."""
    newest = (0.0, "")
    for p in worker_inputs():
        p = p if os.path.isabs(p) else os.path.join(ROOT, p)
        if os.path.exists(p):
            newest = max(newest, (os.path.getmtime(p), p))
    # Not the manifests or the toolchain pin: cargo rebuilds for what changes
    # in them, not for a newer timestamp (a branch switch), so `cargo build`
    # would not clear a refusal based on their times.
    return newest


def check_worker() -> None:
    """A worker older than the core it was built from compares the reference
    with yesterday's Rust: it reports mismatches that aren't there (and writes
    them as fixtures) or hides ones that are. Switching branches is enough to
    cause it, so refuse rather than run."""
    build = "cargo build --release -p bulkhead-diff"
    if not os.path.exists(WORKER):
        sys.exit(f"worker not built: run `{build}` first ({WORKER})")
    mtime, path = newest_source()
    if mtime > os.path.getmtime(WORKER):
        sys.exit(f"worker is older than {os.path.relpath(path, ROOT)}: run `{build}` first ({WORKER})")


def run_worker(lines: list) -> list:
    check_worker()
    p = subprocess.run([WORKER], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    return p.stdout.splitlines()


def fixture_for(lines: list, idx: int) -> list:
    """Smallest replayable prefix: the command, plus its limiter session if stateful."""
    cmd = lines[idx].split()[0]
    if cmd in ("R", "Z", "A", "W"):
        start = idx
        while start > 0 and lines[start].split()[0] != "L":
            start -= 1
        return lines[start: idx + 1]
    return [lines[idx]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=20_000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--replay", help="run one fixture file through both sides")
    args = ap.parse_args()

    if args.replay:
        with open(args.replay) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        lines = generate(args.seed, args.cases)

    t0 = time.time()
    expected = protocol.run_lines(lines)
    actual = run_worker(lines)
    dt = time.time() - t0
    if len(expected) != len(actual):
        print(f"length mismatch: python {len(expected)} rust {len(actual)}")
        return 1
    bad = [i for i, (e, a) in enumerate(zip(expected, actual)) if e != a]
    counts = {}
    for l in lines:
        c = l.split()[0]
        counts[c] = counts.get(c, 0) + 1
    summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    if not bad:
        print(f"OK seed={args.seed} lines={len(lines)} identical ({summary}) in {dt:.1f}s")
        return 0
    os.makedirs(os.path.join(HERE, "regressions"), exist_ok=True)
    for n, i in enumerate(bad[:5]):
        fx = fixture_for(lines, i)
        path = os.path.join(HERE, "regressions", f"seed{args.seed}-line{i}.txt")
        with open(path, "w") as f:
            f.write(f"# python: {expected[i]}\n# rust:   {actual[i]}\n")
            f.write("\n".join(fx) + "\n")
        print(f"MISMATCH line {i}: {lines[i][:160]}\n  python: {expected[i]}\n  rust:   {actual[i]}\n  fixture: {path}")
    print(f"{len(bad)} mismatches out of {len(lines)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
