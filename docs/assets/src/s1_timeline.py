"""Extract the S1 timeline Fig. 3 draws from one end-to-end run.

    BULKHEAD_E2E_DIR=<dir> cloud/e2e/run.sh 2>&1 | node docs/assets/src/stamp.mjs > run.tsv      # each line prefixed with its arrival time, ms
    python3 docs/assets/src/s1_timeline.py <dir> run.tsv > docs/assets/src/s1-run.json

The attacker's lines (cloud/e2e/attack.mjs) are timed by their arrival; each says how long its
payout took, so it was sent `ms` earlier. The guardian's lines carry their own wall-clock `t`.
Times are seconds from the moment the first payout was sent."""
import json, sys, datetime

e2e, tsv = sys.argv[1], sys.argv[2]
orders = []
for line in open(tsv):
    at, _, text = line.rstrip("\n").partition("\t")
    if text.startswith('{"payout"'):
        o = json.loads(text)
        orders.append(dict(i=o["payout"], amount=o["amount"] / 1e6, sent=int(at) - o["ms"], confirmed=int(at),
                           instant=o["instant"] / 1e6, queued=o["queued"] / 1e6, ticket=o.get("ticket"), sig=o["signature"]))
t0 = orders[0]["sent"]
ms = lambda iso: datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000
guard = [json.loads(l) for l in open(f"{e2e}/guardian.log") if l.startswith("{")]
freeze = next(g for g in guard if g.get("action") == "freeze" and g.get("signature"))
cancels = {str(g["ticketId"]): g for g in guard if g.get("action") == "cancel" and g.get("signature")}
rows = []
for o in orders:
    c = cancels.get(str(o["ticket"])) if o["queued"] else None
    rows.append(dict(i=o["i"], amount=o["amount"], instant=o["instant"], queued=o["queued"],
                     sent=round((o["sent"] - t0) / 1000, 3), confirmed=round((o["confirmed"] - t0) / 1000, 3),
                     cancelled=round((ms(c["t"]) - t0) / 1000, 3) if c else None, signature=o["sig"]))
json.dump(dict(
    recorded=datetime.datetime.fromtimestamp(t0 / 1000, datetime.timezone.utc).strftime("%Y-%m-%d"),
    tvl=10_000_000, orders=rows,
    freeze=dict(at=round((ms(freeze["t"]) - t0) / 1000, 3), signature=freeze["signature"], reason=freeze.get("reason")),
), sys.stdout, indent=1)
print()
