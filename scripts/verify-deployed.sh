#!/usr/bin/env bash
# Check that deployed programs run exactly the code built from this checkout.
#
#   scripts/verify-deployed.sh <rpc-url> <program-id>=<name> [...]
#   scripts/verify-deployed.sh https://api.devnet.solana.com <floor-id>=bulkhead_floor <vault-id>=bulkhead_vault
#
# Builds with scripts/build-programs.sh (pinned Agave v4.3.0, platform-tools
# v1.57, sBPF v3; the build is deterministic on a given host, so a clean
# rebuild reproduces the same bytes; released binaries are Linux x86_64
# builds, see scripts/verify-devnet.sh), dumps each deployed program, and requires the on-chain
# code to be the local binary followed only by zero padding (the same rule as
# Floor's snapshot check, bulkhead_core::floor::snapshot_matches). Each
# program's upgrade authority is printed; with EXPECT_AUTHORITY=<pubkey> (for
# a program Floor protects: Floor's authority PDA) it must be that key.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
if [ $# -lt 2 ]; then
  sed -n '2,14p' "$0"
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
  auth=$(python3 - "$URL" "$id" <<'PY'
# The programdata header (loader-v3): tag 3, slot, Option<authority> at 12.
import base64, json, sys, urllib.request
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
def data(addr):
    req = {"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [addr, {"encoding": "base64"}]}
    r = urllib.request.Request(sys.argv[1], json.dumps(req).encode(), {"Content-Type": "application/json"})
    return base64.b64decode(json.load(urllib.request.urlopen(r, timeout=30))["result"]["value"]["data"][0])
pd = data(b58(data(sys.argv[2])[4:36]))
print(b58(pd[13:45]) if pd[12] == 1 else "none")
PY
)
  echo "        upgrade authority $auth"
  if [ -n "${EXPECT_AUTHORITY:-}" ] && [ "$auth" != "$EXPECT_AUTHORITY" ]; then
    echo "MISMATCH  $id: upgrade authority $auth, expected $EXPECT_AUTHORITY"
    bad=1
  fi
done
[ "$bad" = 0 ] && echo "VERIFIED: every program runs the code built from this checkout" || { echo "VERIFICATION FAILED"; exit 1; }
