#!/usr/bin/env bash
# Mutation testing of bulkhead-core with cargo-mutants (mutants.rs).
# One-time setup: cargo install --locked cargo-mutants@27.1.0 (CI's version;
# the exclusion counts in .cargo/mutants.toml are that version's mutants)
# Every surviving ("missed") mutant must be killed by a test or listed as
# equivalent, with a reason, in docs/09-VERIFICATION.md §6, and excluded in
# .cargo/mutants.toml by a pattern that ends with its count (`# 1`).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
SCOPE=(--package bulkhead-core --exclude "crates/bulkhead-core/src/proofs.rs")
# The exclusions in .cargo/mutants.toml must still name exactly the
# equivalents (tools/mutant_exclusions.py says why). Skipped when the caller
# picks another config. No colours: CI sets CARGO_TERM_COLOR=always, which
# cargo-mutants obeys. Its report goes to stderr, so stdout is cargo-mutants'
# own (`--list --json`).
# --exclusions-only: that check and nothing else (scripts/check.sh runs it).
# The counts are the mutants of the version CI installs, so with another
# version, or none, it says so and passes; CI's `mutants` job checks them.
only=0
if [[ "${1:-}" == "--exclusions-only" ]]; then
  only=1; shift
  (( $# == 0 )) || { echo "mutants.sh: --exclusions-only takes no other argument" >&2; exit 2; }
  want=$(sed -n 's/.*cargo install --locked cargo-mutants@\([^ ]*\).*/\1/p' .github/workflows/ci.yml | sort -u)
  [[ "$want" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "mutants.sh: ci.yml must install one cargo-mutants version, X.Y.Z" >&2; exit 2; }
  have=$(cargo mutants --version 2>/dev/null | awk '{print $2}' || true)
  if [[ "$have" != "$want" ]]; then
    echo "mutant exclusions: not checked, they need cargo-mutants $want (CI's version)" >&2
    exit 0
  fi
fi
case " $* " in
  *" --no-config "* | *" --config "* | *" --config="*) ;;
  *)
    mkdir -p target
    cargo mutants --list --colors never --no-config "${SCOPE[@]}" > target/mutants-all.txt
    cargo mutants --list --colors never "${SCOPE[@]}" > target/mutants-kept.txt
    python3 tools/mutant_exclusions.py target/mutants-all.txt target/mutants-kept.txt >&2
    ;;
esac
if (( only )); then exit 0; fi
# Release profile (overflow checks stay on, Cargo.toml): the workspace's tests
# take ~5 s instead of ~36 s in debug, so a timeout means a mutant that loops,
# not a slow test. With debug builds on a loaded machine, 69 mutants once hit
# a 120 s limit and were counted as caught without being judged.
BULKHEAD_CASES="${BULKHEAD_CASES:-1500}" cargo mutants "${SCOPE[@]}" --test-workspace=true \
  --profile release -j "${JOBS:-4}" --timeout 60 "$@"
