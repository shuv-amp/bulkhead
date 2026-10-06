#!/usr/bin/env bash
# Guardian scenarios on a real validator (cloud/e2e/guardian-scenarios.mjs):
# each scenario gets a fresh validator with the e2e world.
#   cloud/e2e/guardian-scenarios.sh                    # hold restart failover
#   cloud/e2e/guardian-scenarios.sh cursor             # ~10 min of quiet first
# Requires: the Agave CLI (solana-test-validator), Node >= 20, built programs.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
scenarios=("$@")
[ ${#scenarios[@]} -gt 0 ] || scenarios=(hold restart failover)
E="$(pwd)/target/e2e-scenarios"
PORT="${PORT:-18699}"
RPC="http://127.0.0.1:$PORT"
mkdir -p "$E"
echo "== building the world (LiteSVM, the same program ids)"
(cd programs/tests && BULKHEAD_E2E_DIR="$E" cargo test --release --test e2e_world -- --ignored >/dev/null 2>&1)
field() { python3 -c "import json,sys; print(json.load(open('$E/world.json'))['$1'])"; }
VAULT=$(field vaultProgram); HARBOR=$(field harbor)
VPID=""
trap 'kill $VPID 2>/dev/null || true' EXIT
failed=0
for s in "${scenarios[@]}"; do
  [ -n "$VPID" ] && { kill "$VPID" 2>/dev/null || true; wait "$VPID" 2>/dev/null || true; }
  args=(--reset --quiet --ledger "$E/ledger" --rpc-port "$PORT" --faucet-port $((PORT + 1001))
        --bpf-program "$VAULT" target/deploy/bulkhead_vault.so --bpf-program "$HARBOR" target/deploy/bulkhead_harbor.so)
  # The cursor scenario needs a node that forgets old signatures soon.
  [ "$s" = cursor ] && args+=(--limit-ledger-size 200)
  for f in "$E"/accounts/*.json; do
    args+=(--account "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pubkey'])" "$f")" "$f")
  done
  rm -rf "$E/ledger"
  solana-test-validator "${args[@]}" > "$E/validator.log" 2>&1 &
  VPID=$!
  for _ in $(seq 1 120); do
    curl -s "$RPC" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' | grep -q '"ok"' && break
    sleep 0.5
  done
  for k in admin guardian0 guardian1 guardian2; do
    addr=$(solana-keygen pubkey "$E/keys/$k.json")
    curl -s "$RPC" -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"$addr\",10000000000]}" >/dev/null
  done
  sleep 2
  echo "== scenario $s"
  node cloud/e2e/guardian-scenarios.mjs "$s" "$E" "$RPC" || { failed=1; tail -5 "$E/guardian.log"; }
done
exit "$failed"
