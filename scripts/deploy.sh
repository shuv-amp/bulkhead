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
# Safe to re-run after a network failure: deployed programs are skipped (and
# checked by scripts/verify-deployed.sh), a failed deploy is retried, and the
# market is set up only once.
# LOADER=js deploys and checks through cloud/deploy/loader.mjs, which needs no
# account reads (for an endpoint whose getAccountInfo is down; see that file).
AUTH=$(solana-keygen pubkey "$PAYER")
deployed() {
  if [ "${LOADER:-cli}" = js ]; then node cloud/deploy/loader.mjs deployed "$URL" "$AUTH" "$(id "$1")"
  else solana program show --url "$URL" --keypair "$PAYER" "$(id "$1")" > /dev/null 2>&1; fi
}
deploy_one() {
  if [ "${LOADER:-cli}" = js ]; then node cloud/deploy/loader.mjs deploy "$URL" "$PAYER" "target/deploy/$1-keypair.json" "target/deploy/$1.so"
  else solana program deploy --url "$URL" --keypair "$PAYER" --upgrade-authority "$PAYER" \
    --program-id "target/deploy/$1-keypair.json" "target/deploy/$1.so"; fi
}
for p in bulkhead_floor bulkhead_vault bulkhead_harbor; do
  if deployed "$p"; then
    echo "== $p is already deployed as $(id "$p")"
    continue
  fi
  echo "== deploying $p as $(id "$p")"
  for attempt in 1 2 3; do
    if deploy_one "$p"; then
      break
    fi
    # A deploy that failed mid-write leaves a funded buffer: reclaim it.
    solana program close --buffers --url "$URL" --keypair "$PAYER" > /dev/null 2>&1 || true
    [ "$attempt" = 3 ] && { echo "deploy of $p failed 3 times"; exit 1; }
    echo "== retrying $p in 10 s (attempt $((attempt + 1)) of 3)"
    sleep 10
  done
done
mkdir -p "$DIR"
if [ -f "$DIR/world.json" ]; then
  echo "== market already set up: $DIR/world.json"
else
  node cloud/deploy/market.mjs setup "$URL" "$DIR" "$PAYER" "$(id bulkhead_vault)" "$(id bulkhead_harbor)"
fi
echo "programs: floor $(id bulkhead_floor), vault $(id bulkhead_vault), harbor $(id bulkhead_harbor)"
echo "DEPLOYED. Market state and keys: $DIR (keep the keys private)"
