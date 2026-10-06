#!/usr/bin/env bash
# Supply chain: cargo-deny on every lockfile (the root workspace, the LiteSVM
# test harness, fuzz/). Fails on a known vulnerability (RustSec), a yanked or
# unmaintained crate, a licence outside the allow list, or a crate from
# anywhere but crates.io. Policies: deny.toml, programs/tests/deny.toml.
# One-time setup: cargo install --locked cargo-deny@0.20.2
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo deny --manifest-path Cargo.toml --config deny.toml check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check
cargo deny --manifest-path programs/tests/Cargo.toml --config programs/tests/deny.toml check
