# Regression fixtures

Each `.txt` file is a replayable case from a real past mismatch between the Python reference and the Rust core. Replay one with:

    python3 reference/diff_runner.py --replay reference/regressions/<file>.txt

| Files | Found | What it was |
|---|---|---|
| `seed1-*`, `seed2-*`, `seed3-*` (15 files, all `K` commands) | 26 Sep 2026, first 100k-case differential runs | `capacity_from_ref` truncated `reference * bps / 10000` to u64 instead of saturating when `bps > 10000`. Fixed in both implementations; the program also rejects `bps > 10000`. See `docs/09-VERIFICATION.md §4`. |
| `seed12-*`, `seed21-*`, `seed22-*`, `seed23-*` (20 files, all `B` commands) | 27 Sep 2026, while optimizing the on-chain compute of `backed_amount` | A proposed early exit ("if paying one unit is invalid, nothing is payable") assumed the valid set is an interval. It is not when a collateral value overflows `u128`: that collateral counts 0 (fail closed), so paying *less* can be invalid while paying *more* is valid. The differential caught it in the first run. The optimization was never shipped; it was replaced by two exact early exits, stated identically in Rust and Python (no collateral at all → 0; a fully valid amount → the amount). See `docs/09-VERIFICATION.md §4`. |

Fixtures are never deleted, and this directory holds nothing else. Each fixture's output under the current Python reference is recorded in `reference/golden/regressions-expected.txt` (`python3 reference/golden.py` writes it; `--check` fails if it is stale). `cargo test -p bulkhead-diff` checks that the Rust core reproduces every one of those outputs, and `scripts/check.sh` also replays each fixture through both sides.
