#!/usr/bin/env python3
"""Binance (29 Oct 2026), the Solana leg, under Bulkhead's limiter. A MODEL, not a replay.

Inputs (sources in docs/13-SOURCES.md, facts in docs/01 §10):
  - TRM Labs: one Binance Solana wallet sent 970,500 SOL (~USD 96M) "shortly
    after 20:10 UTC", an ordinary signed transfer; the attacker controlled
    Binance's hot-wallet signing service (no key is reported leaked).
  - Response times from the same incident: Tether's first freeze landed 37
    minutes after the main Ethereum sweep (TRM); Binance removed the
    attackers' permissions at about 00:10 UTC (Wikipedia, citing Binance), so
    about 4 hours after the Solana transfer.
  - ASSUMPTION: the wallet's whole balance sat in one Bulkhead vault (as
    wrapped SOL) at the default limits, and every payout from it is unbacked
    (an exchange's customer ledger is off-chain, so nothing on-chain backs a
    withdrawal). An exchange would size absolute caps to its normal
    withdrawals instead; this shows only what the defaults bound.

Loss = vault * f(T), f being the G1 fraction of `drift_model.py`
(bulkhead_core::limiter::max_unbacked_over).

  python3 reference/binance_model.py            # print the markdown table
"""
from __future__ import annotations

import os
import sys
from fractions import Fraction as F

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # also under -I
from drift_model import DAY, DUAL, HOUR, fraction  # noqa: E402

SOL_DRAINED = 970_500
USD_DRAINED_M = F(96)  # TRM's valuation at transfer time
RESPONSES = [
    ("2 min (guardian bot, assumed)", 120),
    ("37 min (Tether's first freeze, reported)", 37 * 60),
    ("4 h (Binance revoked access, reported)", 4 * HOUR),
    ("24 h (nobody for a day)", DAY),
]


def loss_sol(t_s: int) -> F:
    return SOL_DRAINED * fraction(t_s, **DUAL)


def check() -> None:
    """The figures docs/01 §10 states, so `scripts/check.sh` can fail on them."""
    claims = [
        ("a 2-minute freeze holds the loss to 2.07% (31/1500) of the vault", fraction(120, **DUAL), F(31, 1500)),
        ("a 4-hour freeze, 35/600 of the vault (the daily bucket binds)", fraction(4 * HOUR, **DUAL), F(35, 600)),
        ("a day of silence, 10%", fraction(DAY, **DUAL), F(1, 10)),
    ]
    wrong = [f"{what}: got {got}, want {want}" for what, got, want in claims if got != want]
    if wrong:
        raise SystemExit("binance model disagrees with the stated bounds: " + "; ".join(wrong))


def main() -> None:
    check()
    print("## Binance, the Solana leg (970,500 SOL, one vault at the defaults, every payout unbacked)\n")
    print("| A freeze lands after | Share of the vault | SOL | USD (at TRM's transfer-time value) | Actual |")
    print("|---|---|---|---|---|")
    for label, t in RESPONSES:
        f = fraction(t, **DUAL)
        print(f"| {label} | {float(f * 100):.2f}% | {float(loss_sol(t)):,.0f} | ${float(USD_DRAINED_M * f):,.1f}M | 970,500 SOL (~$96M) in one transfer |")


if __name__ == "__main__":
    main()
