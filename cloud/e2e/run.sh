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
E="${BULKHEAD_E2E_DIR:-target/e2e}"
case "$E" in
  /*) ;;
  *) E="$(pwd)/$E" ;;
esac
PORT="${PORT:-18899}"
RPC="http://127.0.0.1:$PORT"

echo "== building the world (LiteSVM, the same program ids)"
(cd programs/tests && BULKHEAD_E2E_DIR="$E" cargo test --release --test e2e_world -- --ignored >/dev/null 2>&1)
# Keypair.load refuses a key file others can read; the world writes them 0644.
chmod 700 "$E/keys" && chmod 600 "$E"/keys/*.json
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

for k in admin guardian0 guardian1 guardian2 guardian3; do
  addr=$(solana-keygen pubkey "$E/keys/$k.json")
  curl -s "$RPC" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"requestAirdrop\",\"params\":[\"$addr\",10000000000]}" >/dev/null
done
sleep 2

# A local webhook: the guardian's alerts land in alerts.jsonl.
rm -f "$E/alerts.jsonl"
HOOK_PORT=$((PORT + 2001))
node -e '
const fs = require("node:fs");
require("node:http").createServer((req, res) => {
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", () => { fs.appendFileSync(process.argv[1], b + "\n"); res.end("ok"); });
}).listen(Number(process.argv[2]), "127.0.0.1");
' "$E/alerts.jsonl" "$HOOK_PORT" &
HPID=$!
trap 'kill $VPID $HPID 2>/dev/null || true' EXIT

ALERT_URL="http://127.0.0.1:$HOOK_PORT/hook" cloud/e2e/s1.sh "$RPC" "$E"
echo "== alerts (cloud/guardian/alert.mjs)"
grep -q '"title":"Bulkhead guardian: freeze sent"' "$E/alerts.jsonl" 2>/dev/null \
  || { cat "$E/alerts.jsonl" 2>/dev/null; echo "E2E FAILED: no freeze alert reached the webhook"; exit 1; }
python3 -c "import json,sys; [print('   ', json.loads(l)['title']) for l in open(sys.argv[1]) if l.strip()]" "$E/alerts.jsonl"
echo "E2E PASSED"
