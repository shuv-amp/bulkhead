#!/usr/bin/env bash
# End-to-end: a real validator, the Bulkhead programs, a sealed 10M USDC vault,
# the Cloud guardian, and an attacker holding Harbor's admin key (scenario S1).
#
# Prints what the attacker got, when the guardian froze, and what it cancelled,
# then fails unless: tokens are conserved, the attacker got at most the 2% burst,
# the guardian froze the protocol on its own, and no ticket is left pending.
# Requires: the Agave CLI (solana-test-validator), Node >= 20, scripts/build-programs.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
E=target/e2e
PORT="${PORT:-18899}"
RPC="http://127.0.0.1:$PORT"
COUNT="${COUNT:-12}"            # payouts
AMOUNT="${AMOUNT:-100000000000}" # 100,000 USDC each
INTERVAL="${INTERVAL:-800}"     # ms between payouts

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
GPID=""
trap 'kill $VPID $GPID 2>/dev/null || true' EXIT
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

cat > "$E/guardian.json" <<CFG
{ "rpc": "$RPC", "vaultProgram": "$VAULT", "protocolProgram": "$HARBOR",
  "mints": ["$(field mint)"], "guardianKey": "$E/keys/guardian0.json", "pollMs": 300 }
CFG
echo "== guardian watching"
node cloud/guardian/main.mjs "$E/guardian.json" > "$E/guardian.log" 2>&1 &
GPID=$!
sleep 4

echo "== attack: $COUNT payouts of $((AMOUNT / 1000000)) USDC, every ${INTERVAL}ms"
node cloud/e2e/attack.mjs "$E/world.json" "$E/keys" "$RPC" "$COUNT" "$AMOUNT" "$INTERVAL" | tee "$E/attack.log"

echo "== result"
python3 - "$E" "$RPC" <<'PY'
import json, sys, urllib.request, base64
e, rpc = sys.argv[1], sys.argv[2]
world = json.load(open(f"{e}/world.json"))
def acct(a):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[a,{"encoding":"base64","commitment":"confirmed"}]}).encode()
    v = json.loads(urllib.request.urlopen(urllib.request.Request(rpc, body, {"content-type":"application/json"})).read())["result"]["value"]
    return base64.b64decode(v["data"][0])
import time
# Wait (up to 60 s) for the guardian to finish: no pending tickets left.
for _ in range(120):
    v = acct(world["vault"])
    if int.from_bytes(v[220:224], "little") == 0:
        break
    time.sleep(0.5)
v = acct(world["vault"])
pending, queued = int.from_bytes(v[220:224], "little"), int.from_bytes(v[224:232], "little") / 1e6
frozen_until = int.from_bytes(v[232:240], "little", signed=True)
p = acct(world["protocol"])
protocol_frozen = int.from_bytes(p[8 + 96 + 256 + 64 + 4 + 16: 8 + 96 + 256 + 64 + 4 + 24], "little", signed=True)
loot = int.from_bytes(acct(world["attackerTokens"])[64:72], "little") / 1e6
vault = int.from_bytes(acct(world["vaultTokens"])[64:72], "little") / 1e6
attack = [json.loads(l) for l in open(f"{e}/attack.log") if l.startswith("{")]
guard = [json.loads(l) for l in open(f"{e}/guardian.log") if l.startswith("{")]
acts = [g for g in guard if g.get("action") in ("freeze", "cancel")]
print(f"attacker ordered   {sum(a['amount'] for a in attack) / 1e6:,.0f} USDC in {len(attack)} payouts")
print(f"attacker received  {loot:,.0f} USDC (instant)")
print(f"vault holds        {vault:,.0f} USDC")
print(f"pending tickets    {pending} ({queued:,.0f} USDC queued)")
print(f"protocol frozen    {'yes, for ' + str(round((protocol_frozen - time.time()) / 3600, 1)) + 'h more' if protocol_frozen > time.time() else 'no'}")
for a in acts:
    extra = f" ticket {a['ticketId']}" if a.get("ticketId") is not None else ""
    when = f"{a['since_trigger_s']}s after the triggering block" if a.get("since_trigger_s") is not None else "skipped: " + a.get("skipped", "")
    print(f"guardian {a['action']:<7}{extra}  {when}")
    if a.get("reason"):
        print(f"         reason: {a['reason']}")

# The run is a test, not only a demo: every claim above is checked.
TVL = 10_000_000  # e2e_world.rs deposits 10M USDC; default short bucket 2%
failed = [msg for ok, msg in [
    (abs(loot + vault - TVL) < 1e-6, f"tokens not conserved: attacker {loot} + vault {vault} != {TVL}"),
    (loot <= TVL * 0.02, f"attacker received {loot} > the 2% burst"),
    (any(a["action"] == "freeze" and a.get("signature") for a in acts), "the guardian never froze"),
    (protocol_frozen > time.time(), "the protocol is not frozen"),
    (pending == 0, f"{pending} tickets still pending"),
] if not ok]
for msg in failed:
    print(f"E2E FAILED: {msg}")
sys.exit(1 if failed else 0)
PY
echo "== status (cloud/status/snapshot.mjs: the status page's data path)"
node cloud/status/snapshot.mjs "$RPC" "$VAULT" "$HARBOR" "$(field mint)" "$E/keys/guardian1.json"
echo "E2E PASSED"
