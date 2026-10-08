#!/usr/bin/env python3
"""Drift (1 Apr 2026) loss model under Bulkhead's limiter. A MODEL, not a replay.

Inputs (sources in docs/13-SOURCES.md):
  - per-asset drained amounts, Chainalysis "Lessons from the Drift hack"
    (top 10 assets; the remaining ~$9.8M across 8 assets is grouped as "other")
  - total drained $285M; Chainalysis: "over 50% of its TVL"
  - ASSUMPTION: pre-hack TVL $550M, and each vault's balance is proportional to
    what was drained from it (scaled by 550/285). Labelled on every output.

Per asset: loss = min(drained, vault * f(T)), where f(T) is the fraction of a
vault the G1 bound lets out within T of the attack starting:
    f(T) = min(s_bps * (W_s + T) / W_s, l_bps * (W_l + T) / W_l) / 10_000
This uses the same bound as bulkhead_core::limiter::max_unbacked_over.

  python3 reference/drift_model.py            # print markdown tables
"""
from __future__ import annotations

from fractions import Fraction as F

DRAINED_MUSD = {  # Chainalysis, USD millions
    "JLP": F("159.3"), "USDC": F("71.4"), "cbBTC": F("11.3"), "USDT": F("5.6"), "USDS": F("5.3"),
    "WETH": F("4.7"), "dSOL": F("4.5"), "WBTC": F("4.4"), "FARTCOIN": F("4.1"), "JitoSOL": F("3.6"),
}
TOTAL = F(285)
DRAINED_MUSD["other (8 assets)"] = TOTAL - sum(DRAINED_MUSD.values())
TVL = F(550)
SCALE = TVL / TOTAL
HOUR, DAY = 3600, 86_400


def fraction(t_s: int, s_bps: int, w_s: int, l_bps: int | None, w_l: int | None) -> F:
    short = F(s_bps, 10_000) * F(w_s + t_s, w_s)
    if l_bps is None:
        return short
    return min(short, F(l_bps, 10_000) * F(w_l + t_s, w_l))


def loss(t_s: int, **kw) -> F:
    f = fraction(t_s, **kw)
    return sum(min(d, d * SCALE * f) for d in DRAINED_MUSD.values())


def musd(x: F) -> str:
    return f"${float(x):,.1f}M"


DUAL = dict(s_bps=200, w_s=HOUR, l_bps=500, w_l=DAY)
SINGLE = dict(s_bps=200, w_s=HOUR, l_bps=None, w_l=None)

RESPONSES = [
    ("2 min (guardian bot)", 120),
    ("1 h (human on call)", HOUR),
    ("2.5 h (nobody during the attack window)", 9000),
    ("24 h (nobody for a day)", DAY),
    ("72 h (nobody all weekend)", 3 * DAY),
]


def time_to_lose(pct: int, dual: bool) -> F:
    """Hours of total silence before pct% of a vault can leave."""
    x = F(pct, 100)
    t_short = (x / F(2, 100) - 1) * HOUR
    if not dual:
        return max(t_short, F(0)) / HOUR
    t_long = (x / F(5, 100) - 1) * DAY
    return max(t_short, t_long, F(0)) / HOUR


def check() -> None:
    """The figures the README states, so `scripts/check.sh` can fail on them."""
    claims = [
        ("at most 4% of a vault in any hour", fraction(HOUR, **DUAL), F(4, 100)),
        ("at most 10% of a vault in any day", fraction(DAY, **DUAL), F(10, 100)),
        ("5% needs an hour and a half of silence", time_to_lose(5, True), F(3, 2)),
        ("10% needs a day of silence", time_to_lose(10, True), F(24)),
    ]
    wrong = [f"{what}: got {got}, want {want}" for what, got, want in claims if got != want]
    if wrong:
        raise SystemExit("drift model disagrees with the stated bounds: " + "; ".join(wrong))


def main() -> None:
    check()
    print("## Drift loss model (assumed $550M TVL, vault mix proportional to what was drained)\n")
    print("| Nobody freezes for | Bulkhead dual bucket (2%/h + 5%/day) | Hourly bucket only (2%/h) | Without Bulkhead |")
    print("|---|---|---|---|")
    for label, t in RESPONSES:
        d, s = loss(t, **DUAL), loss(t, **SINGLE)
        print(f"| {label} | **{musd(d)}** ({float(d / TVL * 100):.1f}% of TVL) | {musd(s)} | $285.0M in ~12 min |")
    print("\n## Hours of total silence before a share of a vault can leave\n")
    print("| Share of vault | Dual bucket | Hourly only | Drift, actual |")
    print("|---|---|---|---|")
    for pct in (5, 10, 25, 50):
        d, s = time_to_lose(pct, True), time_to_lose(pct, False)
        actual = "~12 minutes (52% of TVL)" if pct == 50 else "—"
        print(f"| {pct}% | {float(d):,.1f} h ({float(d / 24):.1f} days) | {float(s):,.1f} h | {actual} |")


if __name__ == "__main__":
    main()
