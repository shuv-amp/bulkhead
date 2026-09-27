#!/usr/bin/env bash
# Floor on a real program, with zero code changes:
#   1. dump any upgradeable mainnet program's bytes;
#   2. run them on a local validator with mainnet's feature set, under a local team key;
#   3. register with Floor, stop with one guardian, restore byte-identical with two.
#
#   scripts/floor-demo.sh <mainnet-program-id>
#
# Reads mainnet twice (the program's bytes, the feature set) from a public RPC,
# or SOURCE_RPC. Nothing is sent to mainnet. Requires the Agave CLI and Node 20+.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
if [ $# -ne 1 ]; then
  sed -n '2,10p' "$0"
  exit 2
fi
ID="$1"
SRC="${SOURCE_RPC:-https://api.mainnet-beta.solana.com}"
D=target/floor-demo
PORT="${PORT:-19099}"
RPC="http://127.0.0.1:$PORT"
rm -rf "$D"
mkdir -p "$D"
[ -f target/deploy/bulkhead_floor.so ] || scripts/build-programs.sh

echo "== reading $ID from mainnet (public data)"
solana program dump --url "$SRC" "$ID" "$D/program.so" > /dev/null
python3 -c "import sys; sys.path.insert(0, 'reference'); import bulkhead_ref as r; open('$D/abort.so', 'wb').write(r.abort_elf())"
solana-keygen new --no-bip39-passphrase --silent --force --outfile "$D/team.json"
FLOOR=$(solana-keygen pubkey target/deploy/bulkhead_floor-keypair.json)

echo "== local validator with mainnet's feature set; the program's upgrade key is a local team key"
solana-test-validator --reset --quiet --ledger "$D/ledger" --rpc-port "$PORT" --faucet-port $((PORT + 1001)) \
  --url "$SRC" --clone-feature-set \
  --upgradeable-program "$ID" "$D/program.so" "$(solana-keygen pubkey "$D/team.json")" \
  --bpf-program "$FLOOR" target/deploy/bulkhead_floor.so > "$D/validator.log" 2>&1 &
VPID=$!
trap 'kill $VPID 2>/dev/null || true' EXIT
for _ in $(seq 1 240); do
  if curl -s "$RPC" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"'; then break; fi
  sleep 0.5
done
solana airdrop 100 "$(solana-keygen pubkey "$D/team.json")" --url "$RPC" > /dev/null
echo
node cloud/deploy/floor-demo.mjs "$RPC" "$D" "$FLOOR" "$ID"
