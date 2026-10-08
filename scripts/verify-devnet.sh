#!/usr/bin/env bash
# The devnet deployment (SECURITY.md) runs exactly the programs built from
# this checkout: scripts/verify-deployed.sh with the three devnet ids. CI runs
# it weekly on main.
#
# The deployed binaries are Linux x86_64 builds (finding 43). On Linux x86_64
# this builds natively; anywhere else it builds the committed tree in Docker
# (scripts/build-programs-docker.sh) and compares those.
set -euo pipefail
cd "$(dirname "$0")/.."
RPC="${DEVNET_RPC:-https://api.devnet.solana.com}"
if [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ]; then
  scripts/build-programs.sh > /dev/null
  DIR=target/deploy
else
  scripts/build-programs-docker.sh > /dev/null
  DIR=target/docker
fi
# All three are upgraded by the team key disclosed in SECURITY.md.
SKIP_BUILD=1 EXPECT_AUTHORITY="${EXPECT_AUTHORITY:-71tqq65ovwE4akm8T5UhfkGE1fJ7qBx5wid11Z5GbHBP}" \
  exec scripts/verify-deployed.sh "$RPC" \
  "HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E=$DIR/bulkhead_floor.so" \
  "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b=$DIR/bulkhead_vault.so" \
  "6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh=$DIR/bulkhead_harbor.so"
