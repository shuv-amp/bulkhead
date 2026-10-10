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
if ! command -v cargo-build-sbf >/dev/null; then
  echo "cargo-build-sbf not found: install the Agave CLI v4.3.0 with" >&2
  echo '  sh -c "$(curl -sSfL https://release.anza.xyz/v4.3.0/install)"' >&2
  exit 127
fi
if [ ! -x "$TOOLS/rust/bin/rustc" ]; then
  # First run: let cargo-build-sbf download platform-tools (the target check
  # after the download fails harmlessly because RUSTC is not set yet).
  cargo-build-sbf --no-rustup-override --arch v3 --manifest-path programs/floor/Cargo.toml \
    --sbf-out-dir target/deploy >/dev/null 2>&1 || true
fi
for p in programs/floor programs/vault; do
  RUSTC="$TOOLS/rust/bin/rustc" cargo-build-sbf --no-rustup-override --arch v3 \
    --manifest-path "$p/Cargo.toml" --sbf-out-dir target/deploy
done
# Harbor is bound to one Vault id at compile time. The canonical binary is
# always the devnet Vault. Passing it as an argument keeps a leftover
# BULKHEAD_VAULT_ID (a local deploy's own vault) from being baked in.
# A local deploy calls build-harbor.sh itself, with its vault and another directory.
scripts/build-harbor.sh HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b
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
# Release binaries are Linux x86_64 builds (CI; scripts/build-programs-docker.sh
# elsewhere). Another host emits the same instructions in another order, so
# its Vault hash differs (docs/09, finding 43).
if [ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]; then
  echo "note: built on $(uname -s)-$(uname -m), not the canonical Linux-x86_64; fine for tests, not for release"
fi
