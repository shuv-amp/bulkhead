# Evidence

| File | Supports | How to reproduce |
|---|---|---|
| `solgov_census.py` | "37 of 54 multisigs governing tracked Solana protocols have no timelock; longest 24h; 16/43 changed; 8/183 programs single-key" | `python3 evidence/solgov_census.py` (committed snapshot) or `--live` |
| `solgov_state_2026-09-26.json.gz` | The snapshot above (solgov public API, 26 Sep 2026 04:56 UTC) | — |
| `solgov_census_2026-09-26.json` | The census output from that snapshot | — |
| `drift_model_output.md` | The Drift loss tables (a model; assumptions stated) | `python3 reference/drift_model.py` |

Incident statistics (Zhou et al., IEEE S&P 2023) are cited from arXiv 2208.13035v3 (Table VI, §V-A); the PDF is not redistributed here.
