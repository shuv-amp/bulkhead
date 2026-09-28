#!/usr/bin/env bash
# End-to-end: a real validator, the Bulkhead programs, a sealed 10M USDC vault,
# the Cloud guardian, and an attacker holding Harbor's admin key (scenario S1).
#
# The scenario itself is cloud/e2e/s1.sh, the same script that runs on devnet
# after the seal: it fails unless tokens are conserved, the attacker got at most
# the 2% burst, the guardian froze the protocol on its own, and no ticket is
# left pending.
# Requires: the Agave CLI (solana-test-validator), Node >= 20, scripts/build-programs.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
E=target/e2e
PORT="${PORT:-18899}"
RPC="http://127.0.0.1:$PORT"

echo "== building the world (LiteSVM, the same program ids)"
(cd programs/tests && cargo test --release --test e2e_world -- --ignored >/dev/null 2>&1)
field() { python3 -c "import json,sys; print(json.load(open('$E/world.json'))['$1'])"; }
VAULT=$(field vaultProgram); HARBOR=$(field harbor)

echo "== starting solana-test-validator on :$PORT"
rm -rf "$E/ledger"
args=(--reset --quiet --ledger "$E/ledger" --rpc-port "$PORT" --faucet-port $((PORT + 1001))
      --bpf-program "$VAULT" target/deploy/bulkhead_vault.so
      --bpf-program "$HARBOR" target/deploy/bulkhead_harbor.so)
for f in "$E"/accounts/*.json; do
  args+=(--account "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pubkey'])" "$f")" "$f")
done
solana-test-validator "${args[@]}" > "$E/validator.log" 2>&1 &
VPID=$!
trap 'kill $VPID 2>/dev/null || true' EXIT
for _ in $(seq 1 120); do
  if curl -s "$RPC" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"'; then break; fi
  sleep 0.5
done

for k in admin guardian0 guardian1 guardian2; do
  addr=$(solana-keygen pubkey "$E/keys/$k.json")
  curl -s "$RPC" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"$addr\",10000000000]}" >/dev/null
done
sleep 2

cloud/e2e/s1.sh "$RPC" "$E"
echo "E2E PASSED"
