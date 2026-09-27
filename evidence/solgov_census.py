#!/usr/bin/env python3
"""Solana governance census: how protected are the keys that can change protocol code?

Source: solgov's public API (https://api.solgov.xyz/api/state, a Colosseum
Frontier project that reads Squads multisigs and upgrade authorities on-chain).
The 26 Sep 2026 snapshot is committed so the pitch numbers are reproducible:

  python3 evidence/solgov_census.py                      # use the committed snapshot
  python3 evidence/solgov_census.py --live               # fetch today's state

Spot-check any row on-chain with github.com/simonvellin/solana-upgrade-watch.
Coverage is solgov's tracked set (62 protocols), not all of Solana.
"""
import gzip
import json
import os
import statistics
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(HERE, "solgov_state_2026-09-26.json.gz")


def load():
    if "--live" in sys.argv:
        with urllib.request.urlopen("https://api.solgov.xyz/api/state", timeout=60) as r:
            return json.load(r)
    with gzip.open(SNAPSHOT, "rt") as f:
        return json.load(f)


def main():
    d = load()
    protocols = {k: v for k, v in d.items() if not k.startswith("_")}
    multisigs = {k: v for k, v in protocols.items() if (v.get("threshold") or 0) > 0}
    tl = [v.get("timeLock") or 0 for v in multisigs.values()]
    programs = d["_adminPath"]["results"]
    on_curve = [r for r in programs if r.get("authorityOnCurve") is True]
    activity = list(d["_govActivity"]["entries"].values())
    changed = [v for v in activity if v.get("timelockChanges", 0) > 0]
    fastest = [v["fastestExecuteH"] for v in activity if v.get("executionSamples", 0) >= 5]
    out = {
        "snapshot": d.get("_meta", {}).get("generatedAt"),
        "protocol_entries": len(protocols),
        "squads_multisigs": len(multisigs),
        "multisigs_zero_timelock": sum(1 for t in tl if t == 0),
        "longest_timelock_hours": max(tl) / 3600,
        "multisigs_timelock_ge_72h": sum(1 for t in tl if t >= 259_200),
        "programs_tracked": len(programs),
        "programs_single_key_upgrade_authority": len(on_curve),
        "multisigs_with_timelock_changes": f"{len(changed)}/{len(activity)}",
        "median_fastest_execution_minutes": round(statistics.median(fastest) * 60, 1),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
