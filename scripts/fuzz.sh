#!/usr/bin/env bash
# Coverage-guided fuzzing (libFuzzer via cargo-fuzz) of the byte parsers and
# the full-width arithmetic: every target in fuzz/fuzz_targets, in parallel.
# One-time setup: cargo install --locked cargo-fuzz@0.13.2
#   scripts/fuzz.sh                  # every target, 60 s each
#   SECONDS_PER=600 scripts/fuzz.sh  # longer
#   scripts/fuzz.sh limiter ledger   # some targets
# Fails if any target finds a crash; the input is left in fuzz/artifacts/<target>/.
# Seeds in fuzz/seeds/<target> (committed) reach paths a mutator rarely builds.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
export PATH="$HOME/.cargo/bin:$PATH"
TOOLCHAIN=nightly-2026-08-21
TIME="${SECONDS_PER:-60}"
if [ $# -gt 0 ]; then targets=("$@"); else
  targets=()
  for f in fuzz_targets/*.rs; do targets+=("$(basename "$f" .rs)"); done
fi
cargo +"$TOOLCHAIN" fuzz build -O
logs="$(mktemp -d)"
pids=()
for t in "${targets[@]}"; do
  mkdir -p "corpus/$t"
  dirs=("corpus/$t")
  [ -d "seeds/$t" ] && dirs+=("seeds/$t")
  cargo +"$TOOLCHAIN" fuzz run -O "$t" "${dirs[@]}" -- \
    -max_total_time="$TIME" -rss_limit_mb=2048 -print_final_stats=1 >"$logs/$t.log" 2>&1 &
  pids+=($!)
done
failed=0
for i in "${!targets[@]}"; do
  t="${targets[$i]}"
  if wait "${pids[$i]}"; then
    echo "$t: $(grep -m1 '^Done' "$logs/$t.log")"
  else
    failed=1
    echo "$t: FAILED"
    grep -A20 -m1 'panicked\|ERROR: libFuzzer' "$logs/$t.log" || tail -20 "$logs/$t.log"
  fi
done
exit "$failed"
