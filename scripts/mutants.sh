#!/usr/bin/env bash
# Mutation testing of bulkhead-core with cargo-mutants (mutants.rs).
# One-time setup: cargo install --locked cargo-mutants
# Every surviving ("missed") mutant must be killed by a test or listed as
# equivalent, with a reason, in docs/09-VERIFICATION.md §6.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
# Release profile (overflow checks stay on, Cargo.toml): the workspace's tests
# take ~5 s instead of ~36 s in debug, so a timeout means a mutant that loops,
# not a slow test. With debug builds on a loaded machine, 69 mutants once hit
# a 120 s limit and were counted as caught without being judged.
BULKHEAD_CASES="${BULKHEAD_CASES:-1500}" cargo mutants --package bulkhead-core --test-workspace=true \
  --exclude "crates/bulkhead-core/src/proofs.rs" --profile release -j "${JOBS:-4}" --timeout 60 "$@"
