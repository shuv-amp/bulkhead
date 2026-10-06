#!/usr/bin/env bash
# The devnet deployment (SECURITY.md) runs exactly the programs built from
# this checkout: scripts/verify-deployed.sh with the three devnet ids. CI runs
# it weekly on main.
set -euo pipefail
cd "$(dirname "$0")/.."
exec scripts/verify-deployed.sh "${DEVNET_RPC:-https://api.devnet.solana.com}" \
  HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E=bulkhead_floor \
  HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b=bulkhead_vault \
  6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh=bulkhead_harbor
