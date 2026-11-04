#!/usr/bin/env bash
# Fetch the release toolchain from its GitHub release and refuse it unless its
# SHA-256 is the one pinned here. Two parts, each a tarball:
#   scripts/fetch-toolchain.sh platform-tools   # into ~/.cache/solana/v1.57/platform-tools
#   scripts/fetch-toolchain.sh agave            # the Agave CLI, as its installer lays it out
#
# Why: the toolchain is the only code the release binaries trust that is not
# in this tree. It came from `curl | sh` and from cargo-build-sbf's own
# download, neither of which checks what arrived against a known hash. The
# October 2026 Binance theft began with a tampered download on an engineer's
# machine; a build host is the same kind of target (docs/09, finding 149).
# The hashes are GitHub's own asset digests for the tagged releases, read on
# 5 Nov 2026 (anza-xyz/platform-tools v1.57, 21 Aug 2026; anza-xyz/agave
# v4.3.0, 18 Sep 2026). Changing a version means changing its hashes here.
set -euo pipefail
TOOLS_VERSION=v1.57
AGAVE_VERSION=4.3.0

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

host="$(uname -s)-$(uname -m)"
part="${1:-}"
case "$part" in
  platform-tools)
    case "$host" in
      Linux-x86_64)  asset=platform-tools-linux-x86_64.tar.bz2;  want=b0f7af104adf726fff2a6a09ea2eb2f2d2965c92295f4d7388c08d140e0c2b00 ;;
      Linux-aarch64) asset=platform-tools-linux-aarch64.tar.bz2; want=f2f31c9325cb2d00244df23b4a1a0904e51819cec49d39235a3ed3ee2320375d ;;
      Darwin-arm64)  asset=platform-tools-osx-aarch64.tar.bz2;   want=48c32c2ec3ac3729b5caf1fdd6c4145496125edf043b2662b0586bfbc932b34a ;;
      Darwin-x86_64) asset=platform-tools-osx-x86_64.tar.bz2;    want=e6f6231b149e64ad6cc12605d0f993405ce55862aa44406c023563159f8c3caf ;;
      *) echo "no pinned platform-tools $TOOLS_VERSION for $host" >&2; exit 1 ;;
    esac
    url="https://github.com/anza-xyz/platform-tools/releases/download/$TOOLS_VERSION/$asset"
    dest="${PLATFORM_TOOLS:-$HOME/.cache/solana/$TOOLS_VERSION/platform-tools}"
    ;;
  agave)
    case "$host" in
      Linux-x86_64)  asset=solana-release-x86_64-unknown-linux-gnu.tar.bz2; want=c97289a8abb1d0efb497d8b5cb285baabd9b7f8ea6647f5d145c5dc8ff3611e8 ;;
      Darwin-arm64)  asset=solana-release-aarch64-apple-darwin.tar.bz2;     want=0bfbd769a55e32f0a1fe1b92f76f360f01ee19475facf8c31cb90f99dcca7fe0 ;;
      Darwin-x86_64) asset=solana-release-x86_64-apple-darwin.tar.bz2;      want=4424d399404ec45d55533c60d0b524b7dd9addca7183c650b7b133828bcf558c ;;
      *) echo "no pinned Agave $AGAVE_VERSION for $host" >&2; exit 1 ;;
    esac
    url="https://github.com/anza-xyz/agave/releases/download/v$AGAVE_VERSION/$asset"
    dest="$HOME/.local/share/solana/install/releases/$AGAVE_VERSION"
    ;;
  *)
    echo "usage: $0 platform-tools|agave" >&2
    exit 2
    ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "== $part: $url"
curl -fsSL --retry 5 --retry-all-errors --connect-timeout 30 -o "$tmp/$asset" "$url"
got="$(sha256_of "$tmp/$asset")"
if [ "$got" != "$want" ]; then
  echo "refusing $asset: sha256 $got, pinned $want" >&2
  exit 1
fi
echo "== $part: sha256 matches the pin ($want)"
rm -rf "$dest.partial"
mkdir -p "$dest.partial"
tar -xjf "$tmp/$asset" -C "$dest.partial"
echo "$want  $asset" > "$dest.partial/.bulkhead-sha256"
rm -rf "$dest"
mv "$dest.partial" "$dest"
if [ "$part" = agave ]; then
  # The installer's layout: active_release -> releases/<version>/solana-release.
  ln -sfn "$dest/solana-release" "$HOME/.local/share/solana/install/active_release"
  echo "== agave: $("$dest/solana-release/bin/cargo-build-sbf" --version | head -1)"
fi
echo "== $part: installed in $dest"
