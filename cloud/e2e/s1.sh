#!/usr/bin/env bash
# Scenario S1 against a sealed market on any cluster: the Cloud guardian
# watches, and an attacker holding Harbor's admin key orders payouts to itself.
# cloud/e2e/run.sh runs it on a local validator; after the devnet seal, the
# same script runs on devnet with the market that scripts/deploy.sh wrote.
#
#   cloud/e2e/s1.sh <rpc-url> <market-dir>     # <market-dir>: world.json, keys/
#
# Prints what the attacker got, when the guardian froze, and what it cancelled,
# then fails unless: tokens are conserved, the attacker got at most the 2% burst,
# the guardian froze the protocol on its own, and no ticket is left pending.
# The admin pays each payout's fee and ticket rent; guardian 0 pays its own.
set -euo pipefail
cd "$(dirname "$0")/../.."
RPC="$1"
W="$2"
COUNT="${COUNT:-12}"            # payouts
AMOUNT="${AMOUNT:-100000000000}" # 100,000 USDC each
INTERVAL="${INTERVAL:-800}"     # ms between payouts
POLL_MS="${POLL_MS:-300}"       # the guardian's polling interval (public RPCs: 1000)
# Pending changes the market's owners want, which the guardian must not veto
# (comma-separated ids). Without them, its restart scan vetoes every pending
# loosening, a guardian renewal or a recovery key included.
APPROVED_CHANGE_IDS="${APPROVED_CHANGE_IDS:-}"
# A webhook the guardian posts its alerts to (cloud/guardian/alert.mjs), if any.
ALERT_URL="${ALERT_URL:-}"
ALERT_CFG=""
[ -n "$ALERT_URL" ] && ALERT_CFG=", \"alert\": { \"url\": \"$ALERT_URL\", \"format\": \"json\" }"
field() { python3 -c "import json,sys; print(json.load(open('$W/world.json'))['$1'])"; }
VAULT=$(field vaultProgram); HARBOR=$(field harbor)

cat > "$W/guardian.json" <<CFG
{ "rpc": "$RPC", "vaultProgram": "$VAULT", "protocolProgram": "$HARBOR",
  "mints": ["$(field mint)"], "guardianKey": "$W/keys/guardian0.json", "pollMs": $POLL_MS,
  "policy": { "approvedChangeIds": [$APPROVED_CHANGE_IDS] }$ALERT_CFG }
CFG
echo "== guardian watching"
node cloud/guardian/main.mjs "$W/guardian.json" > "$W/guardian.log" 2>&1 &
GPID=$!
trap 'kill $GPID 2>/dev/null || true' EXIT
# Ready once it has replayed the last 24 hours ("caught up"), at most 120 s.
# The heartbeat comes before that replay; an attack that starts during it would
# be read as history, and history alone never cancels a ticket.
ready=0
for _ in $(seq 1 240); do
  grep -q '"msg":"caught up"' "$W/guardian.log" 2>/dev/null && { ready=1; break; }
  kill -0 $GPID 2>/dev/null || { cat "$W/guardian.log"; echo "S1 FAILED: the guardian exited"; exit 1; }
  sleep 0.5
done
[ "$ready" = 1 ] || { tail -5 "$W/guardian.log"; echo "S1 FAILED: the guardian did not catch up within 120 s"; exit 1; }

echo "== attack: $COUNT payouts of $((AMOUNT / 1000000)) USDC, every ${INTERVAL}ms"
node cloud/e2e/attack.mjs "$W/world.json" "$W/keys" "$RPC" "$COUNT" "$AMOUNT" "$INTERVAL" | tee "$W/attack.log"

echo "== result"
python3 - "$W" "$RPC" <<'PY'
import json, sys, urllib.request, base64, time
w, rpc = sys.argv[1], sys.argv[2]
world = json.load(open(f"{w}/world.json"))
def acct(a):
    body = json.dumps({"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":[a,{"encoding":"base64","commitment":"confirmed"}]}).encode()
    v = json.loads(urllib.request.urlopen(urllib.request.Request(rpc, body, {"content-type":"application/json"})).read())["result"]["value"]
    return base64.b64decode(v["data"][0])
# Wait (up to 180 s) for the guardian to finish: no pending tickets left.
for _ in range(360):
    v = acct(world["vault"])
    if int.from_bytes(v[220:224], "little") == 0:
        break
    time.sleep(0.5)
v = acct(world["vault"])
pending, queued = int.from_bytes(v[220:224], "little"), int.from_bytes(v[224:232], "little") / 1e6
p = acct(world["protocol"])
protocol_frozen = int.from_bytes(p[8 + 96 + 256 + 64 + 4 + 16: 8 + 96 + 256 + 64 + 4 + 24], "little", signed=True)
loot = int.from_bytes(acct(world["attackerTokens"])[64:72], "little") / 1e6
vault = int.from_bytes(acct(world["vaultTokens"])[64:72], "little") / 1e6
attack = [json.loads(l) for l in open(f"{w}/attack.log") if l.startswith("{")]
guard = [json.loads(l) for l in open(f"{w}/guardian.log") if l.startswith("{")]
acts = [g for g in guard if g.get("action") in ("freeze", "cancel")]
print(f"attacker ordered   {sum(a['amount'] for a in attack) / 1e6:,.0f} USDC in {len(attack)} payouts")
print(f"attacker received  {loot:,.0f} USDC (instant)")
print(f"vault holds        {vault:,.0f} USDC")
print(f"pending tickets    {pending} ({queued:,.0f} USDC queued)")
print(f"protocol frozen    {'yes, for ' + str(round((protocol_frozen - time.time()) / 3600, 1)) + 'h more' if protocol_frozen > time.time() else 'no'}")
for a in acts:
    extra = f" ticket {a['ticketId']}" if a.get("ticketId") is not None else ""
    when = f"{a['since_trigger_s']}s after the triggering block" if a.get("since_trigger_s") is not None else "skipped: " + a.get("skipped", "")
    print(f"guardian {a['action']:<7}{extra}  {when}  {a.get('signature', '')}")
    if a.get("reason"):
        print(f"         reason: {a['reason']}")
for g in guard:
    if g.get("level") in ("warn", "error"):
        print(f"guardian {g['level']}: {g.get('msg') or g.get('error')}")

# The run is a test, not only a demo: every claim above is checked.
TVL = 10_000_000  # the market holds 10M test USDC; default short bucket 2%
failed = [msg for ok, msg in [
    (abs(loot + vault - TVL) < 1e-6, f"tokens not conserved: attacker {loot} + vault {vault} != {TVL}"),
    (loot <= TVL * 0.02, f"attacker received {loot} > the 2% burst"),
    (any(a["action"] == "freeze" and a.get("signature") for a in acts), "the guardian never froze"),
    (protocol_frozen > time.time(), "the protocol is not frozen"),
    (pending == 0, f"{pending} tickets still pending"),
] if not ok]
for msg in failed:
    print(f"S1 FAILED: {msg}")
sys.exit(1 if failed else 0)
PY
echo "== status (cloud/status/snapshot.mjs: the status page's data path)"
node cloud/status/snapshot.mjs "$RPC" "$VAULT" "$HARBOR" "$(field mint)" "$W/keys/guardian1.json"
echo "S1 PASSED"
