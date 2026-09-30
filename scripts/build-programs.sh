#!/usr/bin/env bash
# Build the on-chain programs for sBPF v3 and check each binary passes the
# SIMD-0500 gate (e_machine 0xF7, e_flags == 3) with our own checker.
#
# Requires the Agave CLI (cargo-build-sbf). Uses --no-rustup-override: the
# platform-tools rustc is passed through RUSTC, so rustup is never modified.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
TOOLS="${PLATFORM_TOOLS:-$HOME/.cache/solana/v1.57/platform-tools}"
if [ ! -x "$TOOLS/rust/bin/rustc" ]; then
  # First run: let cargo-build-sbf download platform-tools (the target check
  # after the download fails harmlessly because RUSTC is not set yet).
  cargo-build-sbf --no-rustup-override --arch v3 --manifest-path programs/floor/Cargo.toml \
    --sbf-out-dir target/deploy >/dev/null 2>&1 || true
fi
# `--harbor-for <vault-id> <out-dir>`: only Harbor, for a local Vault (Harbor
# forwards only to the Vault it was built for; programs/harbor/build.rs). The
# canonical build below always uses the default: the devnet Vault.
if [ "${1:-}" = --harbor-for ]; then
  BULKHEAD_VAULT_ID="$2" RUSTC="$TOOLS/rust/bin/rustc" cargo-build-sbf --no-rustup-override --arch v3 \
    --manifest-path programs/harbor/Cargo.toml --sbf-out-dir "$3"
  exit 0
fi
unset BULKHEAD_VAULT_ID
for p in programs/floor programs/vault programs/harbor; do
  RUSTC="$TOOLS/rust/bin/rustc" cargo-build-sbf --no-rustup-override --arch v3 \
    --manifest-path "$p/Cargo.toml" --sbf-out-dir target/deploy
done
python3 - <<'PY'
import glob, sys
sys.path.insert(0, "reference")
import bulkhead_ref as r
bad = 0
for so in sorted(glob.glob("target/deploy/*.so")):
    info = r.elf_info(open(so, "rb").read(64))
    ok = r.deployable_after_simd0500(info)
    digest = __import__("hashlib").sha256(open(so, "rb").read()).hexdigest()
    print(f"{so}: e_machine={info and info[0]} e_flags={info and info[1]} deployable after SIMD-0500: {ok}; sha256 {digest}")
    bad += not ok
sys.exit(1 if bad else 0)
PY
