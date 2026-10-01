#!/usr/bin/env bash
# Check that deployed programs run exactly the code built from this checkout.
#
#   scripts/verify-deployed.sh <rpc-url> <program-id>=<name> [...]
#   scripts/verify-deployed.sh https://api.devnet.solana.com <floor-id>=bulkhead_floor <vault-id>=bulkhead_vault
#
# Builds with scripts/build-programs.sh (pinned Agave v4.3.0, platform-tools
# v1.57, sBPF v3; the build is deterministic, so a clean rebuild reproduces
# the same bytes), dumps each deployed program, and requires the on-chain
# code to be the local binary followed only by zero padding (the same rule as
# Floor's snapshot check, bulkhead_core::floor::snapshot_matches).
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
if [ $# -lt 2 ]; then
  sed -n '2,11p' "$0"
  exit 2
fi
URL="$1"
shift
[ "${SKIP_BUILD:-0}" = 1 ] || scripts/build-programs.sh > /dev/null
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
bad=0
for pair in "$@"; do
  id="${pair%%=*}"
  name="${pair#*=}"
  local_so="target/deploy/$name.so"
  case "$name" in *.so) local_so="$name" ;; esac
  solana program dump --url "$URL" "$id" "$T/$id.so" > /dev/null
  if python3 - "$local_so" "$T/$id.so" <<'PY'
import hashlib, sys
sys.path.insert(0, "reference")
import bulkhead_ref as ref
local, chain = (open(p, "rb").read() for p in sys.argv[1:3])
ok = ref.snapshot_matches(local, chain)
print(f"{'MATCH' if ok else 'MISMATCH'}  {sys.argv[1]}  sha256 {hashlib.sha256(local).hexdigest()}  ({len(local):,} bytes; {len(chain) - len(local):,} bytes of on-chain padding)")
sys.exit(0 if ok else 1)
PY
  then :; else bad=1; fi
done
[ "$bad" = 0 ] && echo "VERIFIED: every program runs the code built from this checkout" || { echo "VERIFICATION FAILED"; exit 1; }
