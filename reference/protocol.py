"""Line protocol, Python side. Mirrors crates/bulkhead-diff/src/lib.rs exactly.

Command table (all integers are decimal):

  L c1 w1_ms c2 w2_ms d_ms horizon_ms        new limiter session           -> "L ok"
  R now_ms amount frozen_until_ms            unbacked request              -> "I tat1 tat2" | "Q eta tat1 tat2" | "X code"
  Z now_ms pending_tickets                   reset backlog                 -> "Z tat1 tat2" | "X code"
  A now_ms                                   instant headroom now          -> "A amount"
  M c1 w1_ms c2 w2_ms t_ms                   G1 bound over t               -> "M amount"
  K reference bps floor cap                  capacity from reference       -> "K capacity"
  E ref last_s balance now_s init            EMA step                      -> "E ref"
  V amount mantissa expo decimals w_bps up   exact value                   -> "V value" | "V NONE"
  P price conf ema conf_mult_bps             conservative bounds           -> "P lo hi" | "P NONE"
  U price conf publish now max_age max_conf  price usable?                 -> "U 0|1"
  B amount j nassets [id kind lo hi expo dec haircut liab]* npos [id net]*
                                             backed amount + health        -> "B backed health|NONE"
  CL <9 old> <9 new>                         limits change class           -> "CL T|L"
  CA exists <7 old> <7 new>                  asset change class            -> "CA T|L"
  CD old_s new_s                             loosen-delay change class     -> "CD T|L|X"
  F hex_header                               ELF check (SIMD-0500)         -> "F machine flags deployable" | "F NONE"
  GS now class(T|L) delay                    schedule a change             -> "GS executable expires"
  GX executable expires now vetoed executed abdicated   may it execute?   -> "GX OK|<error>"
  GF current now secs                        freeze                        -> "GF until" | "GF InvalidDuration"
  GH last interval now                       guardian alive?               -> "GH 0|1"
  GQ approvals alive threshold               quorum over live guardians    -> "GQ 0|1"
  GA mask kind                               abdicate, then check          -> "GA newmask abdicated(0|1)"
  GJ approvals alive threshold target count  eject a guardian?             -> "GJ 0|1"
  FH hex                                     murmur3_32 (syscall ids)      -> "FH u32"
  FB hex                                     loader-v3 buffer authority    -> "FB NONE" | "FB -" | "FB key"
  FP hex                                     loader-v3 programdata header  -> "FP NONE" | "FP slot key|-"
  FG hex                                     loader-v3 program account     -> "FG NONE" | "FG programdata"
  FS hex_buffer hex_region                   snapshot byte-identical?      -> "FS 0|1"
  FC hex                                     canonical abort binary?       -> "FC 0|1"
  FA                                         the two abort binaries        -> "FA hex hex_minimal"
  FR S|P buf approved quorum vetoed now eta expires   may restore?         -> "FR 0|1"
  ("-" is an empty byte string in any hex field.)
"""
from __future__ import annotations

import bulkhead_ref as ref


class Session:
    def __init__(self):
        self.limiter = None

    def run_line(self, line: str) -> str:
        t = line.split()
        cmd, a = t[0], t[1:]
        if cmd == "L":
            c1, w1, c2, w2, d, h = map(int, a)
            self.limiter = ref.Limiter(c1, w1, c2, w2, d, h)
            return "L ok"
        if cmd == "R":
            now, amount, frozen = map(int, a)
            r = self.limiter.request(now, amount, frozen)
            return " ".join(str(x) for x in r)
        if cmd == "Z":
            now, pending = map(int, a)
            r = self.limiter.reset_backlog(now, pending)
            return " ".join(str(x) for x in r)
        if cmd == "A":
            return f"A {self.limiter.available_now(int(a[0]))}"
        if cmd == "W":
            now, w1, w2 = map(int, a)
            r = self.limiter.set_windows(now, w1, w2)
            return " ".join(str(x) for x in r)
        if cmd == "M":
            c1, w1, c2, w2, tm = map(int, a)
            return f"M {ref.max_unbacked_over(c1, w1, c2, w2, max(tm, 0))}"
        if cmd == "K":
            r, bps, fl, cap = map(int, a)
            return f"K {ref.capacity_from_ref(r, bps, fl, cap)}"
        if cmd == "E":
            r, last, bal, now, init = map(int, a)
            return f"E {ref.ema_update(r, last, bal, now, bool(init))}"
        if cmd == "V":
            amt, man, expo, dec, w, up = map(int, a)
            v = ref.value_v(amt, man, expo, dec, w, bool(up))
            return "V NONE" if v is None else f"V {v}"
        if cmd == "P":
            pr, conf, ema, mult = map(int, a)
            b = ref.conservative_price(pr, conf, ema, mult)
            return "P NONE" if b is None else f"P {b[0]} {b[1]}"
        if cmd == "U":
            pr, conf, publ, now, age, mc = map(int, a)
            return f"U {int(ref.price_is_usable(pr, conf, publ, now, age, mc))}"
        if cmd == "B":
            i = 0
            amount = int(a[i]); j = int(a[i + 1]); nassets = int(a[i + 2]); i += 3
            assets = {}
            for _ in range(nassets):
                mid, kind = int(a[i]), a[i + 1]
                lo, hi, expo, dec, hc, lb = map(int, a[i + 2:i + 8])
                i += 8
                if kind == "N":
                    assets[mid] = ("N",)
                elif kind == "U":
                    assets[mid] = ("U",)
                else:
                    assets[mid] = ("P", lo, hi, expo, dec, hc, lb)
            npos = int(a[i]); i += 1
            positions = {}
            for _ in range(npos):
                positions[int(a[i])] = int(a[i + 1]); i += 2
            lookup = lambda m: assets.get(m, ("N",))
            b = ref.backed_amount(positions, j, amount, lookup)
            h = ref.health(positions, lookup)
            return f"B {b} {'NONE' if h is None else h}"
        if cmd == "CL":
            v = list(map(int, a))
            return f"CL {ref.classify_limits(v[:9], v[9:18])}"
        if cmd == "CA":
            v = list(map(int, a))
            exists, old, new = v[0], v[1:8], v[8:15]
            old[0] = bool(old[0]); new[0] = bool(new[0])
            return f"CA {ref.classify_asset(old if exists else None, new)}"
        if cmd == "CD":
            o, n = map(int, a)
            return f"CD {ref.classify_delay(o, n)}"
        if cmd == "F":
            info = ref.elf_info(bytes.fromhex(a[0]))
            if info is None:
                return "F NONE"
            return f"F {info[0]} {info[1]} {int(ref.deployable_after_simd0500(info))}"
        if cmd == "GS":
            e, x = ref.schedule(int(a[0]), a[1], int(a[2]))
            return f"GS {e} {x}"
        if cmd == "GX":
            e, x, now, v, ex, ab = map(int, a)
            return f"GX {ref.can_execute(e, x, now, bool(v), bool(ex), bool(ab))}"
        if cmd == "GF":
            cur, now, secs = map(int, a)
            r = ref.freeze_until(cur, now, secs)
            return "GF InvalidDuration" if r is None else f"GF {r}"
        if cmd == "GH":
            last, interval, now = map(int, a)
            return f"GH {int(ref.guardian_alive(last, interval, now))}"
        if cmd == "GQ":
            ap, al, th = map(int, a)
            return f"GQ {int(ref.quorum(ap, al, th))}"
        if cmd == "GA":
            mask, kind = map(int, a)
            m2 = ref.abdicate(mask, kind)
            return f"GA {m2} {int(ref.is_abdicated(m2, kind))}"
        if cmd == "GJ":
            ap, al, th, target, count = map(int, a)
            return f"GJ {int(ref.can_eject(ap, al, th, target, count))}"
        if cmd == "FH":
            return f"FH {ref.murmur3_32(_hex(a[0]))}"
        if cmd == "FB":
            r = ref.buffer_authority(_hex(a[0]))
            return "FB NONE" if r is None else f"FB {_key(r)}"
        if cmd == "FP":
            r = ref.programdata_header(_hex(a[0]))
            return "FP NONE" if r is None else f"FP {r[0]} {_key(r[1])}"
        if cmd == "FG":
            r = ref.program_programdata(_hex(a[0]))
            return "FG NONE" if r is None else f"FG {r.hex()}"
        if cmd == "FS":
            return f"FS {int(ref.snapshot_matches(_hex(a[0]), _hex(a[1])))}"
        if cmd == "FC":
            return f"FC {int(ref.is_canonical_abort(_hex(a[0])))}"
        if cmd == "FA":
            return f"FA {ref.abort_elf().hex()} {ref.abort_elf_minimal().hex()}"
        if cmd == "FR":
            source = a[0]
            buf, approved, quorum_ok, vetoed, now, eta, expires = map(int, a[1:])
            return f"FR {int(ref.can_restore(source, buf, approved, bool(quorum_ok), bool(vetoed), now, eta, expires))}"
        raise ValueError(f"unknown command {cmd}")


def _hex(tok: str) -> bytes:
    """'-' stands for zero bytes (a token can't be empty)."""
    return b"" if tok == "-" else bytes.fromhex(tok)


def _key(opt) -> str:
    return "-" if opt[0] == "none" else opt[1].hex()


def run_lines(lines):
    s = Session()
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(s.run_line(line))
    return out
