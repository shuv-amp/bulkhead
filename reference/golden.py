#!/usr/bin/env python3
"""Generate or check the golden outputs from the Python reference.

  golden/expected.txt               outputs of golden/cases.txt
  golden/regressions-expected.txt   outputs of every fixture in regressions/

  python3 reference/golden.py           # rewrite both
  python3 reference/golden.py --check   # fail if either is stale
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import protocol  # noqa: E402

CASES = os.path.join(HERE, "golden", "cases.txt")
EXPECTED = os.path.join(HERE, "golden", "expected.txt")


REGRESSIONS = os.path.join(HERE, "regressions")
REGRESSIONS_EXPECTED = os.path.join(HERE, "golden", "regressions-expected.txt")


def regressions_text() -> str:
    """Each fixture's output under today's reference: `== file` then its lines."""
    blocks = []
    for name in sorted(os.listdir(REGRESSIONS)):
        if not name.endswith(".txt"):
            continue
        with open(os.path.join(REGRESSIONS, name)) as f:
            out = protocol.run_lines(f.read().splitlines())
        blocks.append("== " + name + "\n" + "\n".join(out))
    return "\n".join(blocks) + "\n"


def main() -> int:
    with open(CASES) as f:
        lines = f.read().splitlines()
    out = protocol.run_lines(lines)
    text = "\n".join(out) + "\n"
    reg = regressions_text()
    if "--check" in sys.argv:
        stale = []
        with open(EXPECTED) as f:
            if f.read() != text:
                stale.append("golden/expected.txt")
        with open(REGRESSIONS_EXPECTED) as f:
            if f.read() != reg:
                stale.append("golden/regressions-expected.txt")
        if stale:
            print(f"stale: {', '.join(stale)}: run python3 reference/golden.py")
            return 1
        print(f"golden OK ({len(out)} outputs; {reg.count('== ')} regression fixtures)")
        return 0
    with open(EXPECTED, "w") as f:
        f.write(text)
    with open(REGRESSIONS_EXPECTED, "w") as f:
        f.write(reg)
    print(f"wrote {EXPECTED} ({len(out)} outputs) and {REGRESSIONS_EXPECTED}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
