#!/usr/bin/env bash
# One command that proves the core, the reference, the tools and the Cloud
# code are healthy. Needs Rust (pinned), Python 3.9+ and Node 20+; nothing is
# installed. CI runs exactly this. The on-chain programs: scripts/check-programs.sh.
#   scripts/check.sh            # default depth
#   CASES=200000 scripts/check.sh   # deeper differential run
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
CASES="${CASES:-50000}"

echo "== fmt";      cargo fmt --all -- --check
echo "== claims (the counts README and docs/ state, against the tree)"
python3 tools/claims.py --self-test
python3 tools/claims.py
echo "== clippy";   cargo clippy --all-targets --release -- -D warnings
echo "== tests";    BULKHEAD_CASES="${BULKHEAD_CASES:-5000}" cargo test --release --quiet
echo "== golden";   python3 reference/golden.py --check
echo "== regressions"
for f in reference/regressions/*.txt; do python3 reference/diff_runner.py --replay "$f" >/dev/null; done
echo "== differential (python reference vs rust core, $CASES cases x 3 seeds)"
for seed in 11 12 13; do python3 reference/diff_runner.py --cases "$CASES" --seed "$seed"; done
echo "== extreme values (full-range i64/i32/u128 inputs, time going backwards; python vs rust)"
for seed in 5 9 11; do python3 reference/extreme_diff.py "$seed"; done
echo "== model";    python3 reference/drift_model.py > /dev/null
echo "== floor_check self-test (curve25519 vectors, PDA derivation)"
python3 tools/floor_check.py --self-test
echo "== cloud (zero-dependency JavaScript: codecs, limiter port vs Python, guardian policy)"
node --test cloud/test/*.test.mjs
echo "ALL CHECKS PASSED"
