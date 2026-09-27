#!/usr/bin/env bash
# Mutation testing of bulkhead-core with cargo-mutants (mutants.rs).
# One-time setup: cargo install --locked cargo-mutants
# Every surviving ("missed") mutant must be killed by a test or listed as
# equivalent, with a reason, in docs/09-VERIFICATION.md §6.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
BULKHEAD_CASES="${BULKHEAD_CASES:-1500}" cargo mutants --package bulkhead-core --test-workspace=true \
  --exclude "crates/bulkhead-core/src/proofs.rs" -j "${JOBS:-4}" --timeout 120 "$@"
