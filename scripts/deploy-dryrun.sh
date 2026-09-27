#!/usr/bin/env bash
# Rehearse scripts/deploy.sh on a fresh local validator: real loader-v3
# deploys of all three programs, the full market setup, and a check that the
# seal is refused before its 72h delay (SealNotExecutable, 8018 = 0x1f52).
# Nothing leaves this machine. Requires the Agave CLI v4.3.0 and Node 20+.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
D=target/dryrun
PORT="${PORT:-18999}"
RPC="http://127.0.0.1:$PORT"
rm -rf "$D"
mkdir -p "$D"

echo "== starting a fresh solana-test-validator on :$PORT"
solana-test-validator --reset --quiet --ledger "$D/ledger" --rpc-port "$PORT" --faucet-port $((PORT + 1001)) > "$D/validator.log" 2>&1 &
VPID=$!
trap 'kill $VPID 2>/dev/null || true' EXIT
for _ in $(seq 1 120); do
  if curl -s "$RPC" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"'; then break; fi
  sleep 0.5
done

solana-keygen new --no-bip39-passphrase --silent --force --outfile "$D/deployer.json"
solana airdrop 50 "$(solana-keygen pubkey "$D/deployer.json")" --url "$RPC" > /dev/null

scripts/deploy.sh "$RPC" "$D/deployer.json" "$D/market"

echo "== the deployed programs must run exactly the local build"
id() { solana-keygen pubkey "target/deploy/$1-keypair.json"; }
SKIP_BUILD=1 scripts/verify-deployed.sh "$RPC" "$(id bulkhead_floor)=bulkhead_floor" "$(id bulkhead_vault)=bulkhead_vault" "$(id bulkhead_harbor)=bulkhead_harbor"

echo "== the seal must be refused before 72h"
if out=$(node cloud/deploy/market.mjs seal "$RPC" "$D/market" "$D/deployer.json" 2>&1); then
  echo "$out"
  echo "DRY RUN FAILED: the seal executed early"
  exit 1
fi
if echo "$out" | grep -qE '0x1f52|"Custom":8018'; then
  echo "refused with SealNotExecutable (8018), as it must be"
else
  echo "$out"
  echo "DRY RUN FAILED: unexpected error"
  exit 1
fi
echo "DEPLOY DRY RUN PASSED"
