## Drift loss model (assumed $550M TVL, vault mix proportional to what was drained)

| Nobody freezes for | Bulkhead dual bucket (2%/h + 5%/day) | Hourly bucket only (2%/h) | Without Bulkhead |
|---|---|---|---|
| 2 min (guardian bot) | **$11.4M** (2.1% of TVL) | $11.4M | $285.0M in ~12 min |
| 1 h (human on call) | **$22.0M** (4.0% of TVL) | $22.0M | $285.0M in ~12 min |
| 2.5 h (nobody during the attack window) | **$30.4M** (5.5% of TVL) | $38.5M | $285.0M in ~12 min |
| 24 h (nobody for a day) | **$55.0M** (10.0% of TVL) | $275.0M | $285.0M in ~12 min |
| 72 h (nobody all weekend) | **$110.0M** (20.0% of TVL) | $285.0M | $285.0M in ~12 min |

## Hours of total silence before a share of a vault can leave

| Share of vault | Dual bucket | Hourly only | Drift, actual |
|---|---|---|---|
| 5% | 1.5 h (0.1 days) | 1.5 h | — |
| 10% | 24.0 h (1.0 days) | 4.0 h | — |
| 25% | 96.0 h (4.0 days) | 11.5 h | — |
| 50% | 216.0 h (9.0 days) | 24.0 h | ~12 minutes (52% of TVL) |
