#!/usr/bin/env bash
# Deploy Floor, Vault and Harbor to a cluster through the real loader, then set
# up the demo market (cloud/deploy/market.mjs) and propose its seal.
#
#   scripts/deploy.sh <rpc-url> <deployer-keypair.json> [market-dir]
#   scripts/deploy.sh https://api.devnet.solana.com ~/keys/bulkhead-devnet.json
#
# The deployer pays for everything and becomes the programs' upgrade
# authority: a team key, to be disclosed in SECURITY.md with the program ids.
# Program ids come from target/deploy/*-keypair.json (created by the build).
# After the 72h seal delay: node cloud/deploy/market.mjs seal <rpc-url> <market-dir> <deployer.json>
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
if [ $# -lt 2 ]; then
  sed -n '2,11p' "$0"
  exit 2
fi
URL="$1"
PAYER="$2"
DIR="${3:-target/market-$(date +%Y%m%d-%H%M%S)}"

scripts/build-programs.sh
id() { solana-keygen pubkey "target/deploy/$1-keypair.json"; }
for p in bulkhead_floor bulkhead_vault bulkhead_harbor; do
  echo "== deploying $p as $(id "$p")"
  solana program deploy --url "$URL" --keypair "$PAYER" --upgrade-authority "$PAYER" \
    --program-id "target/deploy/$p-keypair.json" "target/deploy/$p.so"
done
mkdir -p "$DIR"
node cloud/deploy/market.mjs setup "$URL" "$DIR" "$PAYER" "$(id bulkhead_vault)" "$(id bulkhead_harbor)"
echo "programs: floor $(id bulkhead_floor), vault $(id bulkhead_vault), harbor $(id bulkhead_harbor)"
echo "DEPLOYED. Market state and keys: $DIR (keep the keys private)"
