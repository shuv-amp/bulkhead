"""README figures: the header, Fig. 1 (Drift, modeled), Fig. 2 (architecture) and Fig. 3 (S1, measured), light and dark.

Fig. 1 draws reference/drift_model.py; Fig. 3 draws s1-run.json (s1_timeline.py). render.sh rebuilds docs/assets."""
import json, math, pathlib, sys

HERE = pathlib.Path(__file__).parent
OUT = HERE / "html"
OUT.mkdir(exist_ok=True)

THEMES = {
    "light": dict(bg="#FFFFFF", ink="#0F1115", body="#2B2F36", muted="#5E646C", faint="#8C9198",
                  rule="#E3E4E7", rule2="#CDD0D4", sig="#E5481B", sigfill="rgba(229,72,27,0.10)"),
    "dark":  dict(bg="#0D1117", ink="#ECEDEF", body="#C9CDD3", muted="#9097A0", faint="#6B727C",
                  rule="#262B33", rule2="#353B45", sig="#FF6B3D", sigfill="rgba(255,107,61,0.13)"),
}

FONTS = HERE / "fonts"
PAD = 32  # breathing room, so a figure shown in the other theme still reads as a card
def css(t):
    ff = lambda fam, f, w: f"@font-face{{font-family:'{fam}';src:url('{(FONTS/f).as_uri()}') format('woff2');font-weight:{w}}}"
    return "\n".join([
        ff("Inter Tight", "inter-tight-500.woff2", 500), ff("Inter Tight", "inter-tight-600.woff2", 600),
        ff("Inter", "inter-400.woff2", 400), ff("Inter", "inter-500.woff2", 500), ff("Inter", "inter-600.woff2", 600),
        ff("JBM", "jetbrains-mono-400.woff2", 400), ff("JBM", "jetbrains-mono-500.woff2", 500),
        f"""html,body{{margin:0;background:{t['bg']}}}
        body{{padding:{PAD}px}}
        svg{{display:block}}
        .disp{{font-family:'Inter Tight';font-weight:600;fill:{t['ink']}}}
        .sans{{font-family:'Inter';font-weight:400;fill:{t['body']}}}
        .sansm{{font-family:'Inter';font-weight:500;fill:{t['ink']}}}
        .mono{{font-family:'JBM';font-weight:400;fill:{t['muted']};letter-spacing:.06em}}
        .monom{{font-family:'JBM';font-weight:500;fill:{t['ink']};letter-spacing:.06em}}
        .tnum{{font-feature-settings:'tnum' 1}}"""])

def page(t, w, h, body):
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{css(t)}</style></head>
<body><svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">{body}</svg></body></html>"""

# ---------------------------------------------------------------- header
def mark(t, x, y, s):
    """The Bulkhead mark: a hull capsule, the bulkhead through it, the contained charge."""
    k = s / 100
    return f"""<g transform="translate({x},{y}) scale({k})" fill="none" stroke="{t['ink']}" stroke-width="9" stroke-linecap="round">
      <path d="M62 30 H30 a20 20 0 0 0 0 40 H62"/>
      <path d="M62 30 H70 a20 20 0 0 1 0 40 H62" />
      <circle cx="76" cy="50" r="8" fill="{t['sig']}" stroke="none"/>
      <line x1="62" y1="14" x2="62" y2="86"/>
    </g>"""

def header(t):
    W, H = 1000, 290
    # hull geometry
    deck, keel, wl = 112, 252, 176
    hull = f"M64,{deck} L64,{keel-34} Q64,{keel} 104,{keel} L790,{keel} C880,{keel} 930,{deck+60} 960,{deck} Z"
    bh = [196, 326, 456, 586, 716, 846]
    clip = f'<clipPath id="hc"><path d="{hull}"/></clipPath>'
    hatch = f"""<pattern id="hx" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
        <line x1="0" y1="0" x2="0" y2="7" stroke="{t['sig']}" stroke-width="1.4"/></pattern>"""
    flood = (bh[1], bh[2])
    stations = "".join(f'<line x1="{x}" y1="{keel}" x2="{x}" y2="{keel+5}" stroke="{t["rule2"]}" stroke-width="1"/>' for x in range(104, 790, 26))
    bulkheads = "".join(f'<line x1="{x}" y1="{deck}" x2="{x}" y2="{keel+10}" stroke="{t["ink"]}" stroke-width="{2.4 if x in flood else 1.2}"/>' for x in bh)
    nums = "".join(f'<text class="mono" x="{(a+b)/2}" y="{deck+20}" font-size="9.5" text-anchor="middle">{i:02d}</text>'
                   for i, (a, b) in enumerate(zip([64]+bh, bh+[930]), 1))
    fx = flood[0]+34
    return W, H, f"""<defs>{clip}{hatch}</defs>
    {mark(t, 0, 2, 64)}
    <text class="disp" x="78" y="54" font-size="46" letter-spacing="-1.6">Bulkhead</text>
    <text class="mono" x="1000" y="26" font-size="10.5" text-anchor="end">FIG. 0 — LONGITUDINAL SECTION</text>
    <text class="mono" x="1000" y="44" font-size="10.5" text-anchor="end">ONE COMPARTMENT BREACHED, THE REST DRY</text>

    <line x1="0" y1="{wl}" x2="1000" y2="{wl}" stroke="{t['rule2']}" stroke-width="1" stroke-dasharray="2 5"/>
    <text class="mono" x="0" y="{wl-7}" font-size="9.5">WL</text>
    <g clip-path="url(#hc)">
      <rect x="{flood[0]}" y="{wl}" width="{flood[1]-flood[0]}" height="{keel-wl+20}" fill="{t['sigfill']}"/>
      <rect x="{flood[0]}" y="{wl}" width="{flood[1]-flood[0]}" height="{keel-wl+20}" fill="url(#hx)"/>
      <line x1="{flood[0]}" y1="{wl}" x2="{flood[1]}" y2="{wl}" stroke="{t['sig']}" stroke-width="1.6"/>
      {bulkheads}
    </g>
    {stations}
    <path d="{hull}" fill="none" stroke="{t['ink']}" stroke-width="1.6" stroke-linejoin="round"/>
    <line x1="64" y1="{deck}" x2="960" y2="{deck}" stroke="{t['ink']}" stroke-width="1.6"/>
    {nums}

    <line x1="{fx}" y1="{wl+30}" x2="{fx}" y2="{deck-22}" stroke="{t['sig']}" stroke-width="1"/>
    <circle cx="{fx}" cy="{wl+30}" r="2.5" fill="{t['sig']}"/>
    <text class="monom" x="{fx+8}" y="{deck-24}" font-size="10.5" fill="{t['sig']}" style="fill:{t['sig']}">BREACH — ADMIN KEY STOLEN</text>
    <line x1="{bh[2]}" y1="{keel+10}" x2="{bh[2]}" y2="{keel+26}" stroke="{t['ink']}" stroke-width="1"/>
    <text class="monom" x="{bh[2]+8}" y="{keel+25}" font-size="10.5">BULKHEAD — HOLDS</text>
    <text class="mono" x="1000" y="{keel+25}" font-size="10.5" text-anchor="end">LIMITS REFILL 2% / H · 5% / DAY</text>
    """

# ---------------------------------------------------------------- fig 1
def drift(t):
    W, H = 1000, 500
    x0, x1, y0, y1 = 64, 980, 442, 172        # plot box: y0 = 0%, y1 = 60%
    lo, hi = math.log10(1), math.log10(15000)
    X = lambda m: x0 + (math.log10(m)-lo)/(hi-lo)*(x1-x0)
    Y = lambda p: y0 - p/60*(y0-y1)
    g = []
    for p in (10, 20, 30, 40, 50, 60):
        g.append(f'<line x1="{x0}" y1="{Y(p)}" x2="{x1}" y2="{Y(p)}" stroke="{t["rule"]}" stroke-width="1"/>')
        g.append(f'<text class="mono tnum" x="{x0-12}" y="{Y(p)+3.5}" font-size="10.5" text-anchor="end">{p}%</text>')
    g.append(f'<text class="mono tnum" x="{x0-12}" y="{Y(0)+3.5}" font-size="10.5" text-anchor="end">0</text>')
    g.append(f'<line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}" stroke="{t["ink"]}" stroke-width="1.2"/>')
    for m, lab in ((1, "1 min"), (10, "10 min"), (60, "1 h"), (360, "6 h"), (1440, "1 day"), (4320, "3 days"), (12960, "9 days")):
        g.append(f'<line x1="{X(m)}" y1="{y0}" x2="{X(m)}" y2="{y0+5}" stroke="{t["ink"]}" stroke-width="1.2"/>')
        g.append(f'<text class="mono tnum" x="{X(m)}" y="{y0+21}" font-size="10.5" text-anchor="middle">{lab}</text>')
    g.append(f'<text class="mono" x="{x1}" y="{y0+44}" font-size="10" text-anchor="end">TIME BEFORE ANYONE ACTS  (LOG SCALE) →</text>')
    g.append(f'<text class="mono" x="{x0-12}" y="{y1-16}" font-size="10">SHARE OF TVL DRAINED</text>')

    # Bulkhead, modeled (reference/drift_model.py)
    pts = [(2, 2.1), (60, 4.0), (150, 5.5), (1440, 10.0), (4320, 20.0), (12960, 50.0)]
    area = " ".join(f"{X(m):.1f},{Y(p):.1f}" for m, p in pts)
    g.append(f'<polygon points="{X(2):.1f},{Y(0)} {area} {X(12960):.1f},{Y(0)}" fill="{t["ink"]}" fill-opacity="0.045"/>')
    g.append(f'<polyline points="{area}" fill="none" stroke="{t["ink"]}" stroke-width="2" stroke-linejoin="round"/>')
    for m, p in pts:
        g.append(f'<circle cx="{X(m):.1f}" cy="{Y(p):.1f}" r="3.6" fill="{t["ink"]}"/>')
    labels = [  # (minutes, %, value, caption, dx, dy, anchor)
        (2, 2.1, "$11.4M", "a guardian freezes at 2 min", -2, -42, "start"),
        (60, 4.0, "$22.0M", "nobody acts for an hour", -2, -42, "start"),
        (1440, 10.0, "$55.0M", "nobody acts for a day", -14, -42, "end"),
        (12960, 50.0, "50% after 9 days", "nobody acts at all", 0, -44, "end"),
    ]
    for m, p, a, b, dx, dy, anchor in labels:
        x, y = X(m), Y(p)
        tx = x + dx
        g.append(f'<text class="sansm tnum" x="{tx:.1f}" y="{y+dy:.1f}" font-size="14" text-anchor="{anchor}">{a}</text>')
        g.append(f'<text class="sans" x="{tx:.1f}" y="{y+dy+17:.1f}" font-size="12.5" text-anchor="{anchor}" style="fill:{t["muted"]}">{b}</text>')

    # Drift, actual
    dx = X(12)
    g.append(f'<rect x="{dx-5}" y="{Y(52)}" width="10" height="{Y(0)-Y(52)}" fill="{t["sig"]}"/>')
    g.append(f'<text class="sansm tnum" x="{dx+16}" y="{Y(52)+10}" font-size="14" style="fill:{t["sig"]}">$285M · 52% of TVL</text>')
    g.append(f'<text class="sans" x="{dx+16}" y="{Y(52)+27}" font-size="12.5" style="fill:{t["muted"]}">Drift, actual: about twelve minutes</text>')

    head = f"""
    <text class="mono" x="0" y="16" font-size="10.5">FIG. 1 — DRIFT, 1 APRIL 2026, MODELED BEHIND BULKHEAD</text>
    <text class="disp" x="0" y="62" font-size="31" letter-spacing="-0.7">Half the vault left in twelve minutes.</text>
    <text class="disp" x="0" y="98" font-size="31" letter-spacing="-0.7" style="fill:{t['muted']}">Behind Bulkhead it takes nine days.</text>"""
    return W, H, head + "".join(g)

# ---------------------------------------------------------------- fig 2
def box(t, x, y, w, h, eyebrow, title, sub=None, accent=False, dashed=False):
    stroke = t["sig"] if accent else t["ink"]
    da = ' stroke-dasharray="4 4"' if dashed else ""
    s = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="3" fill="none" stroke="{stroke}" stroke-width="{1.6 if accent else 1.2}"{da}/>']
    yy = y + 22
    if eyebrow:
        s.append(f'<text class="mono" x="{x+14}" y="{yy}" font-size="9.5" style="fill:{t["sig"] if accent else t["muted"]}">{eyebrow}</text>'); yy += 22
    s.append(f'<text class="sansm" x="{x+14}" y="{yy}" font-size="15">{title}</text>')
    if sub:
        for i, line in enumerate(sub if isinstance(sub, list) else [sub]):
            s.append(f'<text class="sans" x="{x+14}" y="{yy+19+i*17}" font-size="12.5" style="fill:{t["muted"]}">{line}</text>')
    return "".join(s)

def arrow(t, pts, dashed=False, color=None, w=1.2):
    c = color or t["ink"]
    d = " ".join(("M" if i == 0 else "L") + f"{x},{y}" for i, (x, y) in enumerate(pts))
    da = ' stroke-dasharray="3 4"' if dashed else ""
    (ax, ay), (bx, by) = pts[-2], pts[-1]
    a = math.atan2(by-ay, bx-ax)
    h1 = (bx-8*math.cos(a-0.42), by-8*math.sin(a-0.42)); h2 = (bx-8*math.cos(a+0.42), by-8*math.sin(a+0.42))
    return (f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{w}"{da}/>'
            f'<path d="M{h1[0]:.1f},{h1[1]:.1f} L{bx},{by} L{h2[0]:.1f},{h2[1]:.1f}" fill="none" stroke="{c}" stroke-width="{w}" stroke-linejoin="round"/>')

def lab(t, x, y, s, anchor="start", accent=False, cls="mono", size=9.5):
    st = f' style="fill:{t["sig"]}"' if accent else ""
    return f'<text class="{cls}" x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}"{st}>{s}</text>'

def arch(t):
    W, H = 1000, 560
    s = [lab(t, 0, 16, "FIG. 2 — WHERE BULKHEAD SITS", size=10.5)]
    # actors
    # rows share centre lines so every arrow is straight
    r1, r2, r3 = 98, 163, 228            # vault lanes
    s.append(box(t, 0, r1-30, 200, 60, None, "Depositor", "their own deposit"))
    s.append(box(t, 0, r3-30, 200, 60, None, "Protocol", "admin key · orders payouts"))
    s.append(box(t, 300, 60, 250, 206, "VAULT · TIER 1", "Owns the token accounts",
                 ["The protocol decides who is paid.", "Bulkhead decides how fast."]))
    s.append(arrow(t, [(200, r1), (298, r1)]))
    s.append(arrow(t, [(200, r3), (298, r3)]))
    s.append(box(t, 690, r1-28, 310, 56, None, "Paid at once", "never throttled, frozen or priced"))
    s.append(box(t, 690, r2-28, 310, 56, None, "Paid", "within the limits"))
    s.append(box(t, 690, r3-28, 310, 56, None, "Public queue, at least 6 h", "over the limit · cancellable", accent=True))
    s.append(arrow(t, [(550, r1), (688, r1)])); s.append(lab(t, 562, r1-8, "OWN DEPOSIT"))
    s.append(arrow(t, [(550, r2), (688, r2)])); s.append(lab(t, 562, r2-8, "≤ 2% / H · 5% / DAY"))
    s.append(arrow(t, [(550, r3), (688, r3)], color=t["sig"])); s.append(lab(t, 562, r3-8, "ABOVE THAT", accent=True))

    # floor row
    fy, fh = 380, 86
    fc = fy + fh/2
    s.append(box(t, 300, fy, 250, fh, "FLOOR · TIER 0", "Holds the upgrade key", ["New code waits 72 h in public."]))
    s.append(box(t, 690, fy, 310, fh, None, "Protocol program", ["Stopped by one guardian, at once.", "Restored byte for byte by a quorum."]))
    s.append(arrow(t, [(550, fc), (688, fc)])); s.append(lab(t, 562, fc-8, "DEPLOYS"))

    # guardians: authority, not value
    s.append(box(t, 0, fy, 200, fh, None, "Guardians", ["3–8 keys. Stop, never steal:", "none can move a token."], dashed=True))
    bus = 322
    s.append(f'<path d="M100,{fy} L100,{bus} L845,{bus}" fill="none" stroke="{t["ink"]}" stroke-width="1.2" stroke-dasharray="3 4"/>')
    s.append(arrow(t, [(845, bus), (845, r3+30)], dashed=True)); s.append(lab(t, 853, bus-10, "FREEZE · CANCEL"))
    s.append(arrow(t, [(425, bus), (425, 268)], dashed=True)); s.append(lab(t, 433, bus-10, "VETO ANY LOOSENING"))
    s.append(arrow(t, [(200, fc), (298, fc)], dashed=True)); s.append(lab(t, 210, fc-8, "STOP · VETO"))

    # footer rule
    s.append(f'<line x1="0" y1="520" x2="1000" y2="520" stroke="{t["rule"]}" stroke-width="1"/>')
    s.append(lab(t, 0, 544, "LOOSENING ANY LIMIT WAITS 72 H, A CONSTANT. TIGHTENING IS INSTANT.", size=10))
    s.append(lab(t, 1000, 544, "SOLID: VALUE · DASHED: AUTHORITY", anchor="end", size=10))
    return W, H, "".join(s)

# ---------------------------------------------------------------- fig 3
S1 = json.loads((HERE / "s1-run.json").read_text())

def attack(t, clock=None, speed=None):
    """S1 as a trace: one row per payout the admin key ordered, drawn up to `clock` seconds (None: the end)."""
    W, H = 1000, 628
    rows, fz = S1["orders"], S1["freeze"]["at"]
    end = max(max(r["cancelled"] or r["confirmed"] for r in rows), fz)
    c = end + 1 if clock is None else clock
    span = math.ceil(end + 0.5)
    x0, x1 = 132, 860
    X = lambda s: x0 + s / span * (x1 - x0)
    top, rh = 168, 26
    Y = lambda i: top + i * rh
    bot = Y(len(rows)) + 4
    g = []

    head = f"""
    <text class="mono" x="0" y="16" font-size="10.5">FIG. 3 — SCENARIO S1, MEASURED ON A LOCAL VALIDATOR, {S1['recorded']}{f" · PLAYED AT {speed}×" if speed else ""}</text>
    <text class="disp" x="0" y="62" font-size="31" letter-spacing="-0.7">The admin key ordered 1,200,000 USDC.</text>
    <text class="disp" x="0" y="98" font-size="31" letter-spacing="-0.7" style="fill:{t['muted']}">It got 100,000. The guardian stopped the rest.</text>"""

    # time axis
    step = 5 if span > 20 else 2 if span > 10 else 1
    for s in range(0, span + 1, step):
        g.append(f'<line x1="{X(s):.1f}" y1="{top-14}" x2="{X(s):.1f}" y2="{bot}" stroke="{t["rule"]}" stroke-width="1"/>')
        g.append(f'<text class="mono tnum" x="{X(s):.1f}" y="{bot+18}" font-size="10.5" text-anchor="middle">{s} s</text>')
    g.append(f'<line x1="{x0}" y1="{bot}" x2="{x1}" y2="{bot}" stroke="{t["ink"]}" stroke-width="1.2"/>')
    g.append(lab(t, 0, top - 24, "PAYOUT ORDERED", size=10))
    g.append(lab(t, 1000, top - 24, "STATUS", anchor="end", size=10))
    ky = bot + 44  # key
    g.append(lab(t, 1000, ky + 3.5, "SECONDS SINCE THE FIRST ORDER →", anchor="end", size=10))
    key = [
        (f'<circle cx="4" cy="0" r="2.6" fill="{t["muted"]}"/><line x1="4" y1="0" x2="26" y2="0" stroke="{t["rule2"]}" stroke-width="2"/>', "ORDERED, IN FLIGHT", 34),
        (f'<rect x="0" y="-7" width="8" height="14" fill="{t["ink"]}"/>', "PAID", 16),
        (f'<rect x="0" y="-6" width="22" height="12" fill="{t["sigfill"]}" stroke="{t["sig"]}" stroke-width="1.2"/>', "QUEUED: CANNOT PAY FOR 6 H", 30),
        (f'<line x1="2" y1="-9" x2="2" y2="9" stroke="{t["ink"]}" stroke-width="2"/>', "CANCELLED BY THE GUARDIAN", 12),
    ]
    kx = 0
    for glyph, name, gw in key:
        g.append(f'<g transform="translate({kx},{ky})">{glyph}</g>')
        g.append(lab(t, kx + gw, ky + 3.5, name, size=10))
        kx += gw + len(name) * 6.6 + 28

    # the freeze
    if c >= fz:
        g.append(f'<line x1="{X(fz):.1f}" y1="{top-40}" x2="{X(fz):.1f}" y2="{bot}" stroke="{t["ink"]}" stroke-width="1.6"/>')
        g.append(f'<text class="monom" x="{X(fz)+8:.1f}" y="{top-30}" font-size="10.5">GUARDIAN FREEZES THE PROTOCOL · {fz:.1f} S</text>')

    paid = cancelled = ordered = 0
    for k, r in enumerate(rows):
        if c < r["sent"]:
            continue
        y = Y(k) + rh / 2
        ordered += r["amount"]
        g.append(f'<text class="mono tnum" x="0" y="{y+3.5}" font-size="10.5">#{r["i"]+1:02d}</text>')
        g.append(f'<text class="sans tnum" x="38" y="{y+4}" font-size="12.5">{r["amount"]:,.0f}</text>')
        # the attacker's client reports a payout after one more RPC call; the guardian can cancel first
        land = min(r["confirmed"], r["cancelled"] if r["cancelled"] is not None else r["confirmed"])
        conf = min(c, land)
        g.append(f'<line x1="{X(r["sent"]):.1f}" y1="{y}" x2="{X(conf):.1f}" y2="{y}" stroke="{t["rule2"]}" stroke-width="2"/>')
        g.append(f'<circle cx="{X(r["sent"]):.1f}" cy="{y}" r="2.6" fill="{t["muted"]}"/>')
        if c < land:
            status, col = "SENDING", t["faint"]
        elif r["instant"]:
            paid += r["instant"]
            g.append(f'<rect x="{X(r["confirmed"])-1:.1f}" y="{y-7}" width="8" height="14" fill="{t["ink"]}"/>')
            status, col = f"PAID {r['instant']:,.0f}", t["ink"]
        else:
            stop = r["cancelled"] if r["cancelled"] is not None else end
            qx, qe = X(land), X(min(c, stop))
            g.append(f'<rect x="{qx:.1f}" y="{y-6}" width="{max(qe-qx, 0):.1f}" height="12" fill="{t["sigfill"]}" stroke="{t["sig"]}" stroke-width="1.2"/>')
            if r["cancelled"] is not None and c >= r["cancelled"]:
                cancelled += r["queued"]
                g.append(f'<line x1="{qe:.1f}" y1="{y-9}" x2="{qe:.1f}" y2="{y+9}" stroke="{t["ink"]}" stroke-width="2"/>')
                status, col = "CANCELLED", t["muted"]
            else:
                status, col = "QUEUED", t["sig"]
        g.append(f'<text class="monom" x="1000" y="{y+3.5}" font-size="10.5" text-anchor="end" style="fill:{col}">{status}</text>')

    if clock is not None and clock <= end:
        g.append(f'<line x1="{X(c):.1f}" y1="{top-14}" x2="{X(c):.1f}" y2="{bot}" stroke="{t["sig"]}" stroke-width="1" stroke-dasharray="2 3"/>')

    # the ledger
    ly = bot + 104
    g.append(f'<line x1="0" y1="{ly-28}" x2="1000" y2="{ly-28}" stroke="{t["rule"]}" stroke-width="1"/>')
    cells = [("ORDERED", ordered, t["ink"]), ("PAID OUT", paid, t["ink"]),
             ("CANCELLED", cancelled, t["ink"]), ("STILL IN THE VAULT", S1["tvl"] - paid, t["ink"])]
    for k, (name, v, col) in enumerate(cells):
        x = k * 256
        g.append(lab(t, x, ly - 4, name, size=10))
        g.append(f'<text class="disp tnum" x="{x}" y="{ly+26}" font-size="24" letter-spacing="-0.4" style="fill:{col}">{v:,.0f}</text>')
    return W, H, head + "".join(g)

FIGS = {"header": header, "drift": drift, "arch": arch, "attack": attack}
FPS, SPEED = 12, 4  # the animation: frames per second and playback speed; render.sh holds the end 3 s

if __name__ == "__main__":
    if sys.argv[1:2] == ["frames"]:
        # The animated Fig. 3: the measured times played back at SPEED.
        end = max(max(r["cancelled"] or r["confirmed"] for r in S1["orders"]), S1["freeze"]["at"])
        n = int((end + 0.4) / SPEED * FPS) + 1
        for theme, t in THEMES.items():
            d = OUT / f"attack-{theme}"; d.mkdir(exist_ok=True)
            for f in range(n):
                W, H, body = attack(t, clock=f * SPEED / FPS - 0.2, speed=SPEED)
                (d / f"{f:04d}.html").write_text(page(t, W, H, body))
            W, H, body = attack(t, clock=end + 1, speed=SPEED)
            (d / f"{n:04d}.html").write_text(page(t, W, H, body))
            print("attack", theme, W + 2*PAD, H + 2*PAD, n + 1)
        sys.exit()
    for name, fn in FIGS.items():
        for theme, t in THEMES.items():
            W, H, body = fn(t)
            (OUT / f"{name}-{theme}.html").write_text(page(t, W, H, body))
            print(name, theme, W + 2*PAD, H + 2*PAD)
