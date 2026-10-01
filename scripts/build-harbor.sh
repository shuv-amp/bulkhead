#!/usr/bin/env bash
# Build Harbor bound to one Vault program id.
#
#   scripts/build-harbor.sh [vault-pubkey] [out-dir]
#
# The default pubkey is the devnet Vault and the default directory is
# `target/deploy`, so a clean `scripts/build-programs.sh` reproduces the
# binary `scripts/verify-deployed.sh` compares. A local deploy passes its
# own Vault pubkey and a separate directory, so it does not replace that
# binary with one that will not talk to the devnet Vault.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
VAULT_ID="${1:-${BULKHEAD_VAULT_ID:-HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b}}"
OUT="${2:-target/deploy}"
export BULKHEAD_VAULT_ID="$VAULT_ID"
TOOLS="${PLATFORM_TOOLS:-$HOME/.cache/solana/v1.57/platform-tools}"
if [ ! -x "$TOOLS/rust/bin/rustc" ]; then
  echo "platform-tools rustc not found at $TOOLS; run scripts/build-programs.sh once" >&2
  exit 1
fi
echo "== Harbor for Vault $VAULT_ID"
RUSTC="$TOOLS/rust/bin/rustc" cargo-build-sbf --no-rustup-override --arch v3 \
  --manifest-path programs/harbor/Cargo.toml --sbf-out-dir "$OUT"
