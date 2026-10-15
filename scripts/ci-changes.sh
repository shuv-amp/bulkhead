#!/usr/bin/env bash
# Which CI jobs a change can affect. Reads changed paths (one per line) on
# stdin and prints `job=true|false` for each job, the format of $GITHUB_OUTPUT.
#   git diff --name-only main... | scripts/ci-changes.sh
# A job is skipped only when nothing it builds, runs or reads changed. The
# workflow, the toolchains and this script itself select everything. The
# weekly and manual runs do not use this; they run every job but `mutants`
# (ci.yml).
set -euo pipefail
programs=false fuzz=false kani=false mutants=false deny=false workflows=false devnet=false scenarios=false
all() { programs=true fuzz=true kani=true mutants=true deny=true workflows=true devnet=true scenarios=true; }
while IFS= read -r f; do
  case "$f" in
    .github/*|scripts/ci-changes.sh|rust-toolchain.toml|*/rust-toolchain.toml)
      all ;;
    # Cargo configuration changes every build (flags, profiles, sources).
    .cargo/config|.cargo/config.toml|*/.cargo/config.toml)
      all ;;
    cloud/guardian/*.service)
      workflows=true ;;
  esac
  case "$f" in
    crates/bulkhead-core/src/*|scripts/mutants.sh|.cargo/mutants.toml)
      mutants=true ;;
  esac
  case "$f" in
    crates/bulkhead-core/src/*|crates/bulkhead-core/Cargo.toml|scripts/prove.sh)
      kani=true ;;
  esac
  case "$f" in
    # The programs depend on the core; the build checks each binary with the
    # Python reference; the end-to-end run uses the Cloud guardian and pages;
    # the deploy rehearsal runs the deploy and Floor scripts; a LiteSVM test
    # checks tools/testdata.
    crates/*|programs/*|cloud/*|reference/*|tools/*|Cargo.toml|Cargo.lock|\
    scripts/build-programs.sh|scripts/build-harbor.sh|scripts/check-programs.sh|\
    scripts/deploy-dryrun.sh|scripts/verify-deployed.sh|scripts/deploy.sh|\
    scripts/floor-devnet.sh|scripts/floor-demo.sh)
      programs=true ;;
  esac
  case "$f" in
    # The fuzz targets call the core and the Vault and Floor parsers.
    fuzz/*|crates/bulkhead-core/*|programs/vault/*|programs/floor/*|scripts/fuzz.sh)
      fuzz=true ;;
  esac
  case "$f" in
    Cargo.toml|Cargo.lock|*/Cargo.toml|*/Cargo.lock|deny.toml|*/deny.toml|scripts/deny.sh)
      deny=true ;;
  esac
  case "$f" in
    # The guardian on a real validator, against the programs as built: what it
    # runs, the programs and core it acts on, the world and build it starts from.
    cloud/guardian/*|cloud/lib/*|cloud/e2e/*|programs/*|crates/*|scripts/build-programs.sh|scripts/build-harbor.sh|Cargo.toml|Cargo.lock|.cargo/*)
      scenarios=true ;;
  esac
  case "$f" in
    # Otherwise weekly only: the scripts that check devnet and the build image.
    scripts/verify-devnet.sh|scripts/verify-deployed.sh|scripts/build-programs-docker.sh|scripts/build-programs.sh)
      devnet=true ;;
  esac
done
for j in programs fuzz kani mutants deny workflows devnet scenarios; do echo "$j=${!j}"; done
