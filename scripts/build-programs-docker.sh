#!/usr/bin/env bash
# Build the committed programs (HEAD) on Linux x86_64 inside the Solana
# Foundation's verifiable-build image for Agave v4.3.0, pinned by digest, from
# any machine with Docker. The canonical binaries are Linux x86_64 builds:
# cargo-build-sbf on macOS (arm64) emits a Vault that differs in its bytes
# (docs/09, finding 43). CI builds natively on Linux; this script reproduces
# those bytes elsewhere. Output: target/docker/*.so and SHA256SUMS.
#   scripts/build-programs-docker.sh
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="solanafoundation/solana-verifiable-build:4.3.0@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd"
OUT=target/docker
rm -rf "$OUT" && mkdir -p "$OUT"
# Only committed files go in (what a verifier gets from the repository); the
# binaries come back out as a tar stream.
git archive --format=tar HEAD | docker run --rm -i --platform linux/amd64 "$IMAGE" bash -c '
  set -euo pipefail
  src=$(mktemp -d)
  tar -x -C "$src"
  cd "$src"
  if ! command -v python3 >/dev/null; then
    apt-get update -qq >&2
    apt-get install -y -qq python3 >&2
  fi
  scripts/build-programs.sh >&2
  tar -c -C target/deploy bulkhead_floor.so bulkhead_vault.so bulkhead_harbor.so
' | tar -x -C "$OUT"
(cd "$OUT" && sha256sum ./*.so 2>/dev/null || shasum -a 256 ./*.so) | tee "$OUT/SHA256SUMS"
