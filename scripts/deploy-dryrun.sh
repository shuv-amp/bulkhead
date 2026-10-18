#!/usr/bin/env bash
# Rehearse scripts/deploy.sh on a fresh local validator: real loader-v3
# deploys of all three programs, the full market setup, and a check that the
# seal is refused before its 72h delay (SealNotExecutable, 8018 = 0x1f52).
# Also rehearses scripts/floor-devnet.sh (the Floor lifecycle on a deployed
# target program). LOADER=js SKIP_PREFLIGHT=1 rehearses the path that needs no
# account reads.
# Nothing leaves this machine. Requires the Agave CLI v4.3.0 and Node 20+.
# BULKHEAD_DRYRUN_DIR selects where the disposable validator ledger and keys go.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
D="${BULKHEAD_DRYRUN_DIR:-target/dryrun}"
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

scripts/deploy.sh "$RPC" "$D/deployer.json" "$D/market" | tee "$D/deploy.log"

echo "== a second run must change nothing (safe re-run after a network failure)"
before=$(solana balance "$(solana-keygen pubkey "$D/deployer.json")" --url "$RPC" --lamports)
rerun=$(scripts/deploy.sh "$RPC" "$D/deployer.json" "$D/market" 2>&1)
after=$(solana balance "$(solana-keygen pubkey "$D/deployer.json")" --url "$RPC" --lamports)
skipped=$(echo "$rerun" | grep -c -e "already deployed" -e "market already set up" || true)
if [ "$skipped" != 4 ] || [ "$before" != "$after" ]; then
  echo "$rerun" | tail -5
  echo "DRY RUN FAILED: the re-run was not a no-op ($skipped of 4 steps skipped; balance $before -> $after)"
  exit 1
fi
echo "re-run skipped all 4 steps and spent nothing"

echo "== a market setup cut short resumes from the chain (world.json and progress.json lost)"
mv "$D/market/world.json" "$D/world.json.first"
rm "$D/market/progress.json"
before=$(solana balance "$(solana-keygen pubkey "$D/deployer.json")" --url "$RPC" --lamports)
scripts/deploy.sh "$RPC" "$D/deployer.json" "$D/market" > "$D/resume.log" 2>&1
after=$(solana balance "$(solana-keygen pubkey "$D/deployer.json")" --url "$RPC" --lamports)
found=$(grep -c "already on chain" "$D/resume.log" || true)
seal_first=$(grep -o 'seal executable from .*' "$D/deploy.log")
seal_resumed=$(grep -o 'seal executable from .*' "$D/resume.log" || true)
same_world=$(node -e 'const [a, b] = process.argv.slice(1).map((f) => ({ ...JSON.parse(require("fs").readFileSync(f)), sealProposal: 0 })); console.log(JSON.stringify(a) === JSON.stringify(b))' "$D/world.json.first" "$D/market/world.json")
if [ "$found" != 14 ] || [ "$before" != "$after" ] || [ "$seal_first" != "$seal_resumed" ] || [ "$same_world" != true ]; then
  tail -20 "$D/resume.log"
  echo "DRY RUN FAILED: the resumed setup was not a no-op ($found of 14 steps on chain; balance $before -> $after; $seal_first -> $seal_resumed; same world: $same_world)"
  exit 1
fi
echo "resumed setup found all 14 steps on chain, spent nothing, left the seal time alone ($seal_first) and rebuilt the same world.json"

echo "== resuming a market registered with three guardian keys (before finding 107) makes no fourth"
mv "$D/market/keys/guardian3.json" "$D/guardian3.json.aside"
if ! node cloud/deploy/market.mjs setup "$RPC" "$D/market" "$D/deployer.json" "$(solana-keygen pubkey target/deploy/bulkhead_vault-keypair.json)" "$(solana-keygen pubkey target/deploy/bulkhead_harbor-keypair.json)" > "$D/three-keys.log" 2>&1; then
  tail -5 "$D/three-keys.log"
  echo "DRY RUN FAILED: resuming a three-key market failed"
  exit 1
fi
if [ -e "$D/market/keys/guardian3.json" ]; then
  echo "DRY RUN FAILED: resuming a registered market made keys/guardian3.json, a key its set does not hold"
  exit 1
fi
mv "$D/guardian3.json.aside" "$D/market/keys/guardian3.json"
echo "resumed without making a guardian key the chain lacks"

echo "== a second market must not take over the same Harbor (Harbor lets anyone register it)"
if out=$(node cloud/deploy/market.mjs setup "$RPC" "$D/other" "$D/deployer.json" "$(solana-keygen pubkey target/deploy/bulkhead_vault-keypair.json)" "$(solana-keygen pubkey target/deploy/bulkhead_harbor-keypair.json)" 2>&1); then
  echo "DRY RUN FAILED: a second market was set up on the same Harbor"
  exit 1
fi
echo "$out" | grep -q "registered with another admin" || { echo "$out" | tail -5; echo "DRY RUN FAILED: unexpected error"; exit 1; }
echo "refused: the protocol is registered with another admin"

echo "== the market, checked without sending anything (cloud/deploy/vault-check.mjs, as on devnet)"
node cloud/deploy/vault-check.mjs "$RPC" "$D/market"

echo "== absolute caps (market.mjs caps: a tightening, applied at once; a re-run sends nothing)"
node cloud/deploy/market.mjs caps "$RPC" "$D/market" "$D/deployer.json"
node cloud/deploy/market.mjs caps "$RPC" "$D/market" "$D/deployer.json" | tee "$D/caps-again.log"
grep -q "caps already set" "$D/caps-again.log" || { echo "DRY RUN FAILED: setting the caps again sent a transaction"; exit 1; }
node cloud/deploy/vault-check.mjs "$RPC" "$D/market" | grep -E "absolute caps|attest|VAULT CHECK"

echo "== the deployed programs must run exactly the local build"
id() { solana-keygen pubkey "target/deploy/$1-keypair.json"; }
# A non-devnet Vault gets a side-built Harbor in the market directory. When the
# configured Vault id is the devnet id, deploy.sh uses the canonical binary.
HARBOR_SO="$D/market/bulkhead_harbor.so"
if [ ! -f "$HARBOR_SO" ]; then
  HARBOR_SO="target/deploy/bulkhead_harbor.so"
fi
SKIP_BUILD=1 scripts/verify-deployed.sh "$RPC" "$(id bulkhead_floor)=bulkhead_floor" "$(id bulkhead_vault)=bulkhead_vault" "$(id bulkhead_harbor)=$HARBOR_SO"
echo "== the same check without account reads (cloud/deploy/loader.mjs, getProgramAccounts only)"
node cloud/deploy/loader.mjs verify "$RPC" "$(solana-keygen pubkey "$D/deployer.json")" \
  "$(id bulkhead_floor)=target/deploy/bulkhead_floor.so" "$(id bulkhead_vault)=target/deploy/bulkhead_vault.so" "$(id bulkhead_harbor)=$HARBOR_SO"

echo "== Floor on a deployed target program (scripts/floor-devnet.sh, as on devnet)"
scripts/floor-devnet.sh "$RPC" "$D/deployer.json" "$D/floor"

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
