#!/usr/bin/env bash
# Bounded proofs of bulkhead-core with Kani (github.com/model-checking/kani).
# One-time setup: cargo install --locked kani-verifier && cargo kani setup
#   scripts/prove.sh                 # every harness
#   scripts/prove.sh request_rules   # one harness (substring match)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
if [ $# -gt 0 ]; then
  cargo kani -p bulkhead-core --harness "$1"
else
  cargo kani -p bulkhead-core
fi
