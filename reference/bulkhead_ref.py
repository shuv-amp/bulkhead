#!/usr/bin/env python3
"""Bulkhead reference model: the executable specification.

This file is written independently of the Rust crate `bulkhead-core`. Both must
produce identical integers for every input. `diff_runner.py` feeds the same
random cases to both and fails on the first disagreement.

Python integers are unbounded, so every place where Rust must detect overflow
is checked here against an explicit limit (U64_MAX, U128_MAX, I128_MAX).

Units:
  amounts        integer base units of a mint (u64)
  times          milliseconds (i64) for the limiter, seconds for EMA and floor
  prices         Pyth-style mantissa with a base-10 exponent
  value          integer units of 1e-18 USD
"""
from __future__ import annotations

BPS = 10_000
TAU_S = 86_400
COST_MAX_MS = 1 << 61
MIN_LOOSEN_DELAY_S = 259_200
MIN_UPGRADE_DELAY_S = 259_200
MAX_LOOSEN_DELAY_S = 2_592_000   # 30 days: above it, one key could stall governance (docs/15, A7)
MAX_UPGRADE_DELAY_S = 2_592_000
MAX_SLOTS = 8
VALUE_DECIMALS = 18

U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
U128_MAX = (1 << 128) - 1
I128_MAX = (1 << 127) - 1

EM_BPF = 0xF7
EM_SBPF = 0x107


def ceil_div(a: int, b: int) -> int:
    """ceil(a / b) for a >= 0, b > 0."""
    return -(-a // b)


# ---------------------------------------------------------------------------
# Limiter: two GCRA buckets that must both conform
# ---------------------------------------------------------------------------

def capacity_from_ref(reference: int, bps: int, floor: int, cap: int) -> int:
    """C = clamp(floor(reference * bps / BPS), floor, cap); cap == 0 means no cap."""
    c = min(reference * bps // BPS, U64_MAX)   # saturate; bps > BPS is rejected by the program
    if c < floor:
        c = floor
    if cap > 0 and c > cap:
        c = cap
    return c


def cost_ms(amount: int, capacity: int, window_ms: int) -> int:
    """Time a request of `amount` consumes in a bucket, rounded up, saturated."""
    return min(ceil_div(amount * window_ms, capacity), COST_MAX_MS)


class Limiter:
    """Dual-bucket GCRA with FIFO reservations.

    A request is instant only if it conforms to BOTH buckets and the lane is not
    frozen. Otherwise it becomes a ticket whose ETA is the earliest time it would
    conform, but never earlier than now + min_queue_delay or the end of a freeze.
    Queued requests reserve capacity exactly like instant ones (FIFO).
    """

    def __init__(self, c1: int, w1: int, c2: int, w2: int, d: int, horizon: int):
        self.c1, self.w1, self.c2, self.w2 = c1, w1, c2, w2
        self.d, self.horizon = d, horizon
        self.tat1 = 0
        self.tat2 = 0

    def request(self, now: int, amount: int, frozen_until: int):
        if amount <= 0:
            return ("X", "ZeroAmount")
        if self.c1 == 0 or self.c2 == 0:
            return ("X", "LaneClosed")
        nt1 = max(self.tat1, now) + cost_ms(amount, self.c1, self.w1)
        nt2 = max(self.tat2, now) + cost_ms(amount, self.c2, self.w2)
        frozen = now < frozen_until
        if (not frozen) and nt1 - now <= self.w1 and nt2 - now <= self.w2:
            self.tat1, self.tat2 = nt1, nt2
            return ("I", nt1, nt2)
        eta = max(now + self.d, nt1 - self.w1, nt2 - self.w2)
        if frozen:
            eta = max(eta, frozen_until)
        if eta - now > self.horizon:
            return ("X", "QueueFull")
        self.tat1, self.tat2 = nt1, nt2
        return ("Q", eta, nt1, nt2)

    def reset_backlog(self, now: int, pending_tickets: int):
        """Clamp each bucket to 'just emptied'. Only legal with no pending tickets."""
        if pending_tickets != 0:
            return ("X", "TicketsPending")
        if self.tat1 > now + self.w1:
            self.tat1 = now + self.w1
        if self.tat2 > now + self.w2:
            self.tat2 = now + self.w2
        return ("Z", self.tat1, self.tat2)

    def available_now(self, now: int) -> int:
        """Largest amount that would be instant right now (ignoring freezes)."""
        out = None
        for tat, c, w in ((self.tat1, self.c1, self.w1), (self.tat2, self.c2, self.w2)):
            backlog = max(tat, now) - now
            room = w - backlog
            a = 0 if room <= 0 else room * c // w
            out = a if out is None else min(out, a)
        return min(out, U64_MAX)


def max_unbacked_over(c1: int, w1: int, c2: int, w2: int, t_ms: int) -> int:
    """Upper bound on unbacked value an attacker can be paid within t_ms of starting."""
    return min(c1 * (w1 + t_ms) // w1, c2 * (w2 + t_ms) // w2)


# ---------------------------------------------------------------------------
# Reference balance (EMA with a linear step)
# ---------------------------------------------------------------------------

def ema_update(reference: int, last_s: int, balance: int, now_s: int, initialized: bool) -> int:
    if not initialized:
        return balance
    dt = max(0, now_s - last_s)
    f = min(dt, TAU_S)
    if balance >= reference:
        return reference + (balance - reference) * f // TAU_S
    return reference - (reference - balance) * f // TAU_S


# ---------------------------------------------------------------------------
# Value conversion and conservative prices
# ---------------------------------------------------------------------------

def pow10(k: int):
    if k > 38:
        return None                          # 10^39 > U128_MAX; also avoids huge powers
    return 10 ** k


def value_v(amount: int, mantissa: int, expo: int, decimals: int, weight_bps: int, round_up: bool):
    """Value of `amount` base units at price mantissa*10^expo, times weight_bps/BPS,
    in units of 1e-18 USD. Returns None on any u128 overflow or if the result
    does not fit in i128 (callers treat None as fail-closed)."""
    if amount == 0 or mantissa == 0 or weight_bps == 0:
        return 0
    num = amount * mantissa
    if num > U128_MAX:
        return None
    num *= weight_bps
    if num > U128_MAX:
        return None
    shift = VALUE_DECIMALS + expo - decimals
    if shift >= 0:
        p = pow10(shift)
        if p is None:
            return None
        num *= p
        if num > U128_MAX:
            return None
        den = BPS
    else:
        p = pow10(-shift)
        if p is None:
            return None
        den = BPS * p
        if den > U128_MAX:
            return None
    v = ceil_div(num, den) if round_up else num // den
    return v if v <= I128_MAX else None


def conservative_price(price: int, conf: int, ema: int, conf_mult_bps: int):
    """(lo, hi) mantissas. lo = min(spot, ema) - k, hi = max(spot, ema) + k,
    k = ceil(conf * conf_mult_bps / BPS). Non-positive spot or ema -> None."""
    if price <= 0 or ema <= 0:
        return None
    k = ceil_div(conf * conf_mult_bps, BPS)
    lo = max(0, min(price, ema) - k)
    hi = max(price, ema) + k
    return (lo, hi)


def price_is_usable(price: int, conf: int, publish_time: int, now: int, max_age_s: int, max_conf_bps: int) -> bool:
    if price <= 0:
        return False
    if publish_time > now or now - publish_time > max_age_s:
        return False
    return conf * BPS <= max_conf_bps * price


# ---------------------------------------------------------------------------
# Backed lane: per-owner shadow ledger
# ---------------------------------------------------------------------------
# Pricing for a mint is one of:
#   ("N",)                              not allowlisted (worth 0 as collateral, cannot be borrowed backed)
#   ("U",)                              allowlisted but no valid price supplied
#   ("P", lo, hi, expo, decimals, haircut_bps, liability_bps)


def contribution(net: int, pricing):
    """Signed value of one position; None means 'unknown' (fail closed)."""
    if net == 0:
        return 0
    kind = pricing[0]
    if net > 0:
        if kind != "P":
            return 0
        _, lo, _hi, expo, dec, haircut, _liab = pricing
        v = value_v(net, lo, expo, dec, haircut, False)
        return 0 if v is None else v
    # liability
    if kind != "P":
        return None
    _, _lo, hi, expo, dec, _haircut, liab = pricing
    v = value_v(-net, hi, expo, dec, liab, True)
    return None if v is None else -v


def health(positions: dict, lookup) -> int | None:
    total = 0
    for mint, net in positions.items():
        c = contribution(net, lookup(mint))
        if c is None:
            return None
        total += c
        if total > I128_MAX or total < -(I128_MAX + 1):
            return None
    return total


def _valid(positions: dict, mint, b: int, lookup, h_others) -> bool:
    n = positions.get(mint, 0)
    after = n - b
    others_liab = any(v < 0 for m, v in positions.items() if m != mint)
    if not others_liab and after >= 0:
        return True                          # own deposit back, nobody owes anything: no prices
    pj = lookup(mint)
    if after >= 0 and pj[0] == "N":
        return True                          # zero-valued collateral: withdrawing it cannot lower health
    if pj[0] != "P":
        return False
    if after < 0 and mint not in positions and len(positions) >= MAX_SLOTS:
        return False                         # a new liability needs a free slot
    if h_others is None:
        return False
    cj = contribution(after, pj)
    if cj is None:
        return False
    return h_others + cj >= 0


def backed_amount(positions: dict, mint, amount: int, lookup) -> int:
    """Largest b <= amount that may be paid through the backed lane."""
    if amount <= 0:
        return 0
    n = positions.get(mint, 0)
    others_liab = any(v < 0 for m, v in positions.items() if m != mint)
    if not others_liab and n >= amount:
        return amount
    if all(v <= 0 for v in positions.values()):
        return 0                            # no collateral at all: nothing can be backed
    others = {m: v for m, v in positions.items() if m != mint}
    h_others = health(others, lookup)
    if _valid(positions, mint, amount, lookup, h_others):
        return amount                       # the largest valid b <= amount, by definition
    lo, hi = 0, amount - 1                  # invariant: b = lo is acceptable
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _valid(positions, mint, mid, lookup, h_others):
            lo = mid
        else:
            hi = mid - 1
    return lo


# ---------------------------------------------------------------------------
# Change classification (tighten = instant, loosen = 72h + veto)
# ---------------------------------------------------------------------------

def cap_tighter_or_equal(old: int, new: int) -> bool:
    """abs_cap: 0 means 'no cap'."""
    if new == old:
        return True
    if old == 0:
        return new > 0
    return 0 < new <= old


def classify_limits(old: list, new: list) -> str:
    """Fields: bps1, w1_s, bps2, w2_s, d_s, floor1, floor2, cap1, cap2."""
    bps1, w1, bps2, w2, d, f1, f2, c1, c2 = old
    nbps1, nw1, nbps2, nw2, nd, nf1, nf2, nc1, nc2 = new
    tight = (nbps1 <= bps1 and nw1 >= w1 and nbps2 <= bps2 and nw2 >= w2 and nd >= d
             and nf1 <= f1 and nf2 <= f2
             and cap_tighter_or_equal(c1, nc1) and cap_tighter_or_equal(c2, nc2))
    return "T" if tight else "L"


def classify_asset(old, new) -> str:
    """Fields: allowlisted, haircut, liability, conf_mult, max_age_s, max_conf_bps, feed."""
    if old is None:
        return "L"
    oa, oh, ol, oc, oage, oconf, ofeed = old
    na, nh, nl, nc, nage, nconf, nfeed = new
    if not na:
        return "T"                           # disabled (or stays disabled): only removes value
    if not oa:
        return "L"                           # enabling is always a loosening
    tight = nh <= oh and nl >= ol and nc >= oc and nage <= oage and nconf <= oconf and nfeed == ofeed
    return "T" if tight else "L"


def classify_delay(old_s: int, new_s: int) -> str:
    if new_s < MIN_LOOSEN_DELAY_S or new_s > MAX_LOOSEN_DELAY_S:
        return "X"                           # invalid, never accepted
    return "T" if new_s >= old_s else "L"


# ---------------------------------------------------------------------------
# Floor (Tier 0): ELF header check for SIMD-0500
# ---------------------------------------------------------------------------

def elf_info(header: bytes):
    """(e_machine, e_flags) of a 64-bit little-endian ELF, else None."""
    if len(header) < 52 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        return None
    e_machine = int.from_bytes(header[18:20], "little")
    e_flags = int.from_bytes(header[48:52], "little")
    if e_machine not in (EM_BPF, EM_SBPF):
        return None
    return (e_machine, e_flags)


def deployable_after_simd0500(info) -> bool:
    """After SIMD-0500 loader-v3 deploys only sBPF v3: e_flags exactly 3.
    (e_flags 4 decodes to V4, which agave does not enable; 5+ is reserved.)"""
    return info is not None and info[0] == EM_BPF and info[1] == 3


# ---------------------------------------------------------------------------
# Floor (Tier 0): loader-v3 accounts, snapshots, restores, the abort binary
# ---------------------------------------------------------------------------
import struct

BUFFER_DATA_OFFSET = 37          # u32 tag + Option<Pubkey> (1 + 32)
PROGRAMDATA_DATA_OFFSET = 45     # u32 tag + u64 slot + Option<Pubkey> (1 + 32)
PROGRAM_ACCOUNT_LEN = 36         # u32 tag + Pubkey


def _option_key(data: bytes, at: int):
    """('none',) / ('some', key) / None if malformed."""
    if len(data) <= at:
        return None
    if data[at] == 0:
        return ("none",)
    if data[at] == 1 and len(data) >= at + 33:
        return ("some", bytes(data[at + 1:at + 33]))
    return None


def buffer_authority(data: bytes):
    if len(data) < BUFFER_DATA_OFFSET or struct.unpack_from("<I", data, 0)[0] != 1:
        return None
    return _option_key(data, 4)


def program_programdata(data: bytes):
    if len(data) < PROGRAM_ACCOUNT_LEN or struct.unpack_from("<I", data, 0)[0] != 2:
        return None
    return bytes(data[4:36])


def programdata_header(data: bytes):
    """(slot, option_key) or None."""
    if len(data) < PROGRAMDATA_DATA_OFFSET or struct.unpack_from("<I", data, 0)[0] != 3:
        return None
    k = _option_key(data, 12)
    if k is None:
        return None
    return (struct.unpack_from("<Q", data, 4)[0], k)


def snapshot_matches(buffer_program: bytes, programdata_program: bytes) -> bool:
    """Upgrading from this buffer leaves programdata unchanged: Upgrade copies the
    buffer to the front and zero-fills the rest."""
    n = len(buffer_program)
    if n == 0 or n > len(programdata_program):
        return False
    return programdata_program[:n] == buffer_program and not any(programdata_program[n:])


def can_restore(source: str, buffer_id: int, approved_id: int, quorum_ok: bool, vetoed: bool,
                now_s: int, eta_s: int, expires_s: int) -> bool:
    """source 'S' (snapshot: quorum only) or 'P' (proposed: approved+quorum, or delay passed)."""
    if source == "S":
        return quorum_ok
    fast = quorum_ok and buffer_id == approved_id
    slow = (not vetoed) and eta_s <= now_s < expires_s
    return fast or slow


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Reference murmur3 (x86, 32-bit); solana-sbpf hashes syscall names with it."""
    mask = 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593

    def rotl(x, r):
        return ((x << r) | (x >> (32 - r))) & mask

    h = seed
    blocks = len(data) // 4
    for b in range(blocks):
        (k,) = struct.unpack_from("<I", data, 4 * b)
        k = rotl((k * c1) & mask, 15) * c2 & mask
        h = (rotl(h ^ k, 13) * 5 + 0xE6546B64) & mask
    tail = data[4 * blocks:]
    k = 0
    for i, byte in enumerate(tail):
        k |= byte << (8 * i)
    if tail:
        k = rotl((k * c1) & mask, 15) * c2 & mask
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h


FLOOR_ABORT_CODE = 0x464C4F52   # b"FLOR"
ABORT_MESSAGE = (b"Program stopped by its Bulkhead Floor guardians. "
                 b"The stop moves no funds. Restart needs a guardian quorum.")


def _insn(opc: int, dst: int, src: int, imm: int) -> bytes:
    return struct.pack("<BBhi", opc, (src << 4) | dst, 0, imm)


def _elf(segments, entry: int) -> bytes:
    """segments: list of (p_flags, vaddr, payload). sBPF v3 strict layout."""
    ehdr_len, phdr_len = 64, 56
    header = struct.pack("<4sBBBBB7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, bytes(7),
                         3, EM_BPF, 1, entry, ehdr_len, 0, 3, ehdr_len, phdr_len,
                         len(segments), 64, 0, 0)
    offset = ehdr_len + phdr_len * len(segments)
    phdrs, body = b"", b""
    for flags, vaddr, payload in segments:
        phdrs += struct.pack("<IIQQQQQQ", 1, flags, offset, vaddr, vaddr, len(payload), len(payload), 0)
        body += payload
        offset += len(payload)
    return header + phdrs + body


def abort_elf() -> bytes:
    text_vaddr = 1 << 32
    rodata = ABORT_MESSAGE + bytes(-len(ABORT_MESSAGE) % 8)
    text = (_insn(0xB7, 1, 0, 0)
            + _insn(0xB7, 2, 0, len(ABORT_MESSAGE))
            + _insn(0x85, 0, 0, struct.unpack("<i", struct.pack("<I", murmur3_32(b"sol_log_")))[0])
            + _insn(0xB7, 0, 0, FLOOR_ABORT_CODE)
            + _insn(0x95, 0, 0, 0))
    return _elf([(4, 0, rodata), (1, text_vaddr, text)], text_vaddr)


def abort_elf_minimal() -> bytes:
    text_vaddr = 1 << 32
    text = _insn(0xB7, 0, 0, FLOOR_ABORT_CODE) + _insn(0x95, 0, 0, 0)
    return _elf([(1, text_vaddr, text)], text_vaddr)


def is_canonical_abort(program: bytes) -> bool:
    return program in (abort_elf(), abort_elf_minimal())


# ---------------------------------------------------------------------------
# Governance timing (G4, G5)
# ---------------------------------------------------------------------------
CHANGE_EXPIRY_S = 604_800
MAX_FREEZE_S = 86_400
MIN_HEARTBEAT_INTERVAL_S = 86_400
MAX_HEARTBEAT_INTERVAL_S = 30 * 86_400


def schedule(now_s: int, klass: str, protocol_delay_s: int):
    """(executable_s, expires_s). Tighten: now. Loosen: now + max(delay, 72h)."""
    delay = 0 if klass == "T" else max(protocol_delay_s, MIN_LOOSEN_DELAY_S)
    executable = now_s + delay
    return (executable, executable + CHANGE_EXPIRY_S)


def can_execute(executable_s: int, expires_s: int, now_s: int, vetoed: bool, executed: bool, abdicated: bool) -> str:
    if abdicated:
        return "Abdicated"
    if executed:
        return "AlreadyExecuted"
    if vetoed:
        return "Vetoed"
    if now_s < executable_s:
        return "NotYetExecutable"
    if now_s >= expires_s:
        return "Expired"
    return "OK"


def freeze_until(current: int, now_s: int, secs: int):
    if secs <= 0 or secs > MAX_FREEZE_S:
        return None
    return max(current, now_s + secs)


def guardian_alive(last_heartbeat_s: int, interval_s: int, now_s: int) -> bool:
    return (MIN_HEARTBEAT_INTERVAL_S <= interval_s <= MAX_HEARTBEAT_INTERVAL_S
            and now_s >= last_heartbeat_s and now_s - last_heartbeat_s <= interval_s)


def quorum(approvals: int, alive: int, threshold: int) -> bool:
    return threshold > 0 and bin(approvals & alive & 0xFF).count("1") >= threshold


MIN_GUARDIAN_THRESHOLD = 2


def can_eject(approvals: int, alive: int, threshold: int, target: int, count: int) -> bool:
    """A live quorum of the other guardians ejects `target`; >= threshold must remain."""
    if not (0 <= target < count <= 8) or threshold < MIN_GUARDIAN_THRESHOLD:
        return False
    if count - 1 < threshold:
        return False
    members = (1 << count) - 1            # slots at or above `count` hold no guardian
    others = approvals & members & ~(1 << target)
    return quorum(others, alive, threshold)


def abdicate(mask: int, kind: int) -> int:
    return mask if kind >= 32 else mask | (1 << kind)


def is_abdicated(mask: int, kind: int) -> bool:
    return kind < 32 and (mask >> kind) & 1 == 1
