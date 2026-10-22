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
# A public cluster gets only canonical binaries (Linux x86_64; finding 43),
# so anyone can rebuild them and get the deployed bytes.
case "$URL" in
  *localhost*|*127.0.0.1*) ;;
  *) if [ "$(uname -s)-$(uname -m)" != Linux-x86_64 ] && [ "${ALLOW_NONCANONICAL:-0}" != 1 ]; then
       echo "refusing: $(uname -s)-$(uname -m) is not the canonical build host; deploy from Linux x86_64 or CI's binaries" >&2
       exit 1
     fi
     # Only reviewed code: the bytes must be rebuildable from a commit. Every
     # tracked file counts (the build scripts, the toolchain pin and the
     # reference's SIMD-0500 gate shape the bytes too; finding 141).
     if [ -n "$(git status --porcelain --untracked-files=no)" ] && [ "${ALLOW_DIRTY:-0}" != 1 ]; then
       echo "refusing: uncommitted changes to tracked files; commit them (or ALLOW_DIRTY=1)" >&2
       git status --porcelain --untracked-files=no >&2
       exit 1
     fi
     echo "== deploying $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))" ;;
esac

scripts/build-programs.sh
id() { solana-keygen pubkey "target/deploy/$1-keypair.json"; }
# Harbor signs only for the Vault it was built for. A fresh keypair is not the
# devnet Vault, so build that Harbor beside the canonical binary. Replacing
# target/deploy/bulkhead_harbor.so would make the next devnet check deploy a
# program that refuses the devnet Vault.
DEVNET_VAULT=HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b
HARBOR_SO="target/deploy/bulkhead_harbor.so"
if [ "$(id bulkhead_vault)" != "$DEVNET_VAULT" ]; then
  mkdir -p "$DIR"
  scripts/build-harbor.sh "$(id bulkhead_vault)" "$DIR"
  HARBOR_SO="$DIR/bulkhead_harbor.so"
fi
# Safe to re-run after a network failure: deployed programs are skipped (and
# checked by scripts/verify-deployed.sh), a failed deploy is retried, and the
# market is set up only once.
# LOADER=js deploys and checks through cloud/deploy/loader.mjs, which needs no
# account reads (for an endpoint whose getAccountInfo is down; see that file).
AUTH=$(solana-keygen pubkey "$PAYER")
# Whether a program account exists: 0 yes, 1 no. Anything else (an RPC error,
# a rate limit) stops the script: read as "absent", it made a re-run deploy
# over the live program, which for a program this payer still owns is an
# upgrade to whatever is checked out.
deployed() {
  if [ "${LOADER:-cli}" = js ]; then node cloud/deploy/loader.mjs deployed "$URL" "$AUTH" "$(id "$1")"; return; fi
  local st
  st=$(python3 - "$URL" "$(id "$1")" <<'PY'
import json, sys, urllib.request
req = {"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [sys.argv[2], {"encoding": "base64", "commitment": "confirmed"}]}
r = urllib.request.Request(sys.argv[1], json.dumps(req).encode(), {"Content-Type": "application/json"})
print("absent" if json.load(urllib.request.urlopen(r, timeout=30))["result"]["value"] is None else "present")
PY
) || { echo "cannot tell whether $1 is deployed (RPC error): refusing to deploy over it; re-run" >&2; exit 1; }
  [ "$st" = present ]
}
so() { if [ "$1" = bulkhead_harbor ]; then echo "$HARBOR_SO"; else echo "target/deploy/$1.so"; fi; }
verify_one() {
  local pair="$(id "$1")=$(so "$1")"
  if [ "${LOADER:-cli}" = js ]; then
    node cloud/deploy/loader.mjs verify "$URL" "$AUTH" "$pair"
  else
    # The payer must hold the upgrade authority, as the JS path checks: a
    # program someone else controls is not ours to set a market up on (finding 85).
    EXPECT_AUTHORITY="$AUTH" SKIP_BUILD=1 scripts/verify-deployed.sh "$URL" "$pair"
  fi
}
deploy_one() {
  if [ "${LOADER:-cli}" = js ]; then node cloud/deploy/loader.mjs deploy "$URL" "$PAYER" "target/deploy/$1-keypair.json" "$(so "$1")"
  else solana program deploy --url "$URL" --keypair "$PAYER" --upgrade-authority "$PAYER" \
    --program-id "target/deploy/$1-keypair.json" "$(so "$1")"; fi
}
for p in bulkhead_floor bulkhead_vault bulkhead_harbor; do
  if deployed "$p"; then
    echo "== $p is already deployed as $(id "$p")"
    verify_one "$p"
    continue
  fi
  echo "== deploying $p as $(id "$p")"
  for attempt in 1 2 3; do
    if deploy_one "$p"; then
      break
    fi
    # Preserve every buffer: `close --buffers` closes all buffers under this
    # authority, including unrelated staged upgrades owned by the same key.
    echo "warning: preserving any buffer left by the failed deploy attempt" >&2
    [ "$attempt" = 3 ] && { echo "deploy of $p failed 3 times"; exit 1; }
    echo "== retrying $p in 10 s (attempt $((attempt + 1)) of 3)"
    sleep 10
  done
  verify_one "$p"
done
mkdir -p "$DIR"
if [ -f "$DIR/world.json" ]; then
  # A leftover world.json is not a market. Confirm this cluster still has it.
  node cloud/deploy/market.mjs confirm "$URL" "$DIR" "$(id bulkhead_vault)" "$(id bulkhead_harbor)"
  echo "== market already set up: $DIR/world.json"
else
  node cloud/deploy/market.mjs setup "$URL" "$DIR" "$PAYER" "$(id bulkhead_vault)" "$(id bulkhead_harbor)"
fi
echo "programs: floor $(id bulkhead_floor), vault $(id bulkhead_vault), harbor $(id bulkhead_harbor)"
echo "DEPLOYED. Market state and keys: $DIR (keep the keys private)"
