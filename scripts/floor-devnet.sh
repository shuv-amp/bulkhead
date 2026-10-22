#!/usr/bin/env bash
# Floor on a public cluster: deploy a target program under the team key, then
# run cloud/deploy/floor-demo.mjs against the deployed Floor: register, stage
# the stop, an upgrade that waits and is vetoed, stop, restore byte-identical,
# re-arm. Every forbidden action is simulated and must fail with its exact error.
#
#   scripts/floor-devnet.sh <rpc-url> <team-keypair.json> <dir> [program.so]
#
# The target is a copy of Harbor's binary under a new program id kept in
# <dir>/program-keypair.json (or the given .so). Floor's id: target/deploy.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
if [ $# -lt 3 ]; then
  sed -n '2,10p' "$0"
  exit 2
fi
URL="$1"
TEAM="$2"
D="$3"
SO="${4:-target/deploy/bulkhead_harbor.so}"
mkdir -p "$D"
chmod 700 "$D"
[ -f "$D/program.so" ] || cp "$SO" "$D/program.so"
# The path is an argument, never part of the Python source.
python3 -c "import sys; sys.path.insert(0, 'reference'); import bulkhead_ref as r; open(sys.argv[1], 'wb').write(r.abort_elf())" "$D/abort.so"
[ -f "$D/program-keypair.json" ] || solana-keygen new --no-bip39-passphrase --silent --outfile "$D/program-keypair.json"
chmod 600 "$D/program-keypair.json"
FLOOR=$(solana-keygen pubkey target/deploy/bulkhead_floor-keypair.json)
ID=$(solana-keygen pubkey "$D/program-keypair.json")
# Three states, as in deploy.sh: deployed, absent, or unknown (an RPC error, a
# rate limit). Unknown used to read as absent and deploy, an in-place upgrade
# of a program this key owns (finding 141).
if shown=$(solana program show --url "$URL" --keypair "$TEAM" "$ID" 2>&1); then
  echo "== the target program $ID is already deployed"
elif printf '%s' "$shown" | grep -qiE "unable to find|not found|AccountNotFound"; then
  echo "== deploying the target program as $ID (upgrade authority: the team key)"
  solana program deploy --url "$URL" --keypair "$TEAM" --upgrade-authority "$TEAM" \
    --program-id "$D/program-keypair.json" "$D/program.so" | grep -E "^(Program Id|Signature)"
else
  echo "cannot tell whether $ID is deployed (not an 'account not found' answer): refusing to deploy over it; re-run" >&2
  printf '%s\n' "$shown" >&2
  exit 1
fi
echo
node cloud/deploy/floor-demo.mjs "$URL" "$D" "$FLOOR" "$ID" "$TEAM"
