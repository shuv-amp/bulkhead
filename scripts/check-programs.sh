#!/usr/bin/env bash
# The on-chain programs: build Floor, Vault and Harbor for sBPF v3 (and check
# each binary passes the SIMD-0500 gate), then run them in LiteSVM, i.e. the
# real agave runtime and loader-v3 with the mainnet feature set: every Floor
# and Vault scenario, the negative tests, compute measurements, and the
# program-vs-model differential.
#   scripts/check-programs.sh         # build + LiteSVM tests
#   E2E=1 scripts/check-programs.sh   # also, on local validators: the attacker-vs-guardian
#                                     # run, and a rehearsal of the devnet deploy
# Requires the Agave CLI v4.3.0 (cargo-build-sbf, solana-test-validator) and,
# for E2E, Node 20+. The tests use the toolchain in programs/tests/rust-toolchain.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
scripts/build-programs.sh
echo "== clippy (the LiteSVM harness and the fuzz targets: their own workspaces)"
(cd programs/tests && cargo clippy --release --tests -- -D warnings)
(cd fuzz && cargo clippy --all-targets -- -D warnings)
echo "== LiteSVM program tests"
(cd programs/tests && cargo test --release)
if [ "${E2E:-0}" = 1 ]; then
  echo "== end to end (solana-test-validator, Cloud guardian, attacker)"
  cloud/e2e/run.sh
  echo "== deploy rehearsal (fresh validator, real loader deploys, market setup, early seal refused)"
  scripts/deploy-dryrun.sh
fi
echo "PROGRAM CHECKS PASSED"
