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
case " $* " in
  *" --no-config "* | *" --config "* | *" --config="*) ;;
  *)
    mkdir -p target
    cargo mutants --list --colors never --no-config "${SCOPE[@]}" > target/mutants-all.txt
    cargo mutants --list --colors never "${SCOPE[@]}" > target/mutants-kept.txt
    python3 tools/mutant_exclusions.py target/mutants-all.txt target/mutants-kept.txt >&2
    ;;
esac
# Release profile (overflow checks stay on, Cargo.toml): the workspace's tests
# take ~5 s instead of ~36 s in debug, so a timeout means a mutant that loops,
# not a slow test. With debug builds on a loaded machine, 69 mutants once hit
# a 120 s limit and were counted as caught without being judged.
BULKHEAD_CASES="${BULKHEAD_CASES:-1500}" cargo mutants "${SCOPE[@]}" --test-workspace=true \
  --profile release -j "${JOBS:-4}" --timeout 60 "$@"
