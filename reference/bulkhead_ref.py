#!/usr/bin/env python3
"""Bulkhead reference model: the executable specification.

This file states the mechanism of docs/03 in its own terms, not the Rust
crate's: the limiter as rates and virtual finish times, the valuation as one
exact rational rounded once, the ledger rule on the ledger after the payment
with its soundness checked from scratch, the overflow domain as closed bounds
rather than a chain of checked products (`09`, finding 140). The Rust crate
`bulkhead-core` must produce identical integers for every input;
`diff_runner.py` feeds the same random cases to both and fails on the first
disagreement. Where the mechanism fixes an implementation detail (the search's
midpoint where soundness is not an interval), it is named as such.

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
MAX_LOOSEN_DELAY_S = 30 * 86_400  # same cap as the Vault and Floor programs
MIN_UPGRADE_DELAY_S = 259_200
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
# Stated from the mechanism (docs/03 §2), not from the Rust code. A bucket is
# a rate `C/W` (base units per millisecond) with a burst of `C`. Its state is
# one instant, the theoretical arrival time TAT: the moment the bucket is
# empty again. A request of `u` at time `t` is given the virtual finish time
#
#     finish(u, t) = max(TAT, t) + ⌈u · W / C⌉ ms
#
# (the exact time its share of the rate takes, rounded up to a whole
# millisecond, never more than COST_MAX_MS), and it conforms when that finish
# lies within one window of now: finish − t ≤ W. The arithmetic below is
# exact (fractions.Fraction), with rounding applied once, where the mechanism
# says so.

from fractions import Fraction
from math import ceil, floor


def capacity_from_ref(reference: int, bps: int, floor_: int, cap: int) -> int:
    """C = clamp(⌊reference · bps / 10 000⌋, floor_, cap); cap == 0 means no cap.
    A u64 result, saturated."""
    c = min(floor(Fraction(reference * bps, BPS)), U64_MAX)
    c = max(c, floor_)
    if cap > 0:
        c = min(c, cap)
    return c


def cost_ms(amount: int, capacity: int, window_ms: int) -> int:
    """Whole milliseconds a request of `amount` takes at the bucket's rate,
    rounded up, never more than COST_MAX_MS."""
    return min(ceil(Fraction(amount * window_ms, capacity)), COST_MAX_MS)


class Limiter:
    """Dual-bucket GCRA with FIFO reservations.

    A request is instant only if it conforms to BOTH buckets and the lane is not
    frozen. Otherwise it becomes a ticket whose ETA is the earliest moment at
    which it would have conformed to both (each bucket's finish minus its
    window), never earlier than now + the minimum delay, nor than the end of a
    freeze. A queued request reserves its finish times exactly as an instant
    one does, so later requests queue behind it (FIFO), and a cancellation
    gives nothing back.
    """

    def __init__(self, c1: int, w1: int, c2: int, w2: int, d: int, horizon: int):
        self.c1, self.w1, self.c2, self.w2 = c1, w1, c2, w2
        self.d, self.horizon = d, horizon
        self.tat1 = 0
        self.tat2 = 0

    def _finish(self, now: int, amount: int):
        """Each bucket's virtual finish time for this request."""
        return (max(self.tat1, now) + cost_ms(amount, self.c1, self.w1),
                max(self.tat2, now) + cost_ms(amount, self.c2, self.w2))

    def request(self, now: int, amount: int, frozen_until: int):
        if amount <= 0:
            return ("X", "ZeroAmount")
        if self.c1 == 0 or self.c2 == 0:
            return ("X", "LaneClosed")        # a bucket with no capacity: the lane is shut
        f1, f2 = self._finish(now, amount)
        conforms = f1 - now <= self.w1 and f2 - now <= self.w2
        frozen = now < frozen_until
        if conforms and not frozen:
            self.tat1, self.tat2 = f1, f2
            return ("I", f1, f2)
        # The earliest moment it would have conformed to both buckets, pushed
        # to the minimum delay and past any freeze.
        eta = max(now + self.d, f1 - self.w1, f2 - self.w2)
        if frozen:
            eta = max(eta, frozen_until)
        if eta - now > self.horizon:
            return ("X", "QueueFull")         # nothing reserved
        self.tat1, self.tat2 = f1, f2
        return ("Q", eta, f1, f2)

    def reset_backlog(self, now: int, pending_tickets: int):
        """With no ticket pending, each bucket is at most "just emptied": its
        TAT is brought back to now + W where it lay beyond. That is a full
        bucket's worth of waiting, never less than one, so G1's bound keeps
        (docs/03 §2.5, the resets case)."""
        if pending_tickets != 0:
            return ("X", "TicketsPending")
        self.tat1 = min(self.tat1, now + self.w1)
        self.tat2 = min(self.tat2, now + self.w2)
        return ("Z", self.tat1, self.tat2)

    def set_windows(self, now: int, w1: int, w2: int):
        """New windows keep each bucket's *used fraction*: a backlog of
        `b` ms in a window `W` is the share `b / W` of the bucket, and that
        share is carried into the new window, rounded toward "more used"
        (never more than COST_MAX_MS of backlog, never past i64). A bucket
        with no backlog, or a window no valid config has, is left as it is."""
        def carried(tat: int, old_w: int, new_w: int) -> int:
            backlog = tat - now
            if backlog <= 0 or old_w <= 0 or new_w <= 0:
                return tat
            share = Fraction(backlog, old_w)                  # used fraction of the old window
            new_backlog = min(ceil(share * new_w), COST_MAX_MS)
            return min(now + new_backlog, I64_MAX)
        self.tat1 = carried(self.tat1, self.w1, w1)
        self.tat2 = carried(self.tat2, self.w2, w2)
        self.w1, self.w2 = w1, w2
        return ("W", self.tat1, self.tat2)

    def available_now(self, now: int) -> int:
        """The largest amount instant right now (freezes aside): the amount
        whose exact cost fits the room each bucket has left, ⌊room · C / W⌋,
        the smaller of the two, as a u64."""
        def room_of(tat: int, c: int, w: int) -> int:
            room = w - (max(tat, now) - now)            # ms of the window not yet reserved
            return 0 if room <= 0 else floor(Fraction(room * c, w))
        return min(room_of(self.tat1, self.c1, self.w1), room_of(self.tat2, self.c2, self.w2), U64_MAX)


def max_unbacked_over(c1: int, w1: int, c2: int, w2: int, t_ms: int) -> int:
    """G1: the most an attacker starting at a full bucket is paid within
    `t_ms`: one burst plus the refill over `t_ms`, `C · (W + t) / W`, floored;
    both buckets apply, so the smaller bound does."""
    bound = lambda c, w: floor(Fraction(c * (w + t_ms), w))
    return min(bound(c1, w1), bound(c2, w2))


# ---------------------------------------------------------------------------
# Reference balance (EMA with a linear step) and the low-water balance
# ---------------------------------------------------------------------------

def ema_update(reference: int, last_s: int, balance: int, now_s: int, initialized: bool) -> int:
    """The reference moves the share `min(elapsed, τ) / τ` of the way toward
    the balance, in whole units, truncated toward where it was (so it never
    overshoots). A first touch takes the balance itself."""
    if not initialized:
        return balance
    share = Fraction(min(max(0, now_s - last_s), TAU_S), TAU_S)
    gap = balance - reference
    step = floor(share * abs(gap))
    return reference + step if gap >= 0 else reference - step


LOW_WINDOW_S = 1_800


def window_low_touch(prev: int, cur: int, window: int, balance: int, now_s: int, initialized: bool):
    """The low-water balance: the least balance any touch saw, before its
    operation, in the current aligned 30-minute window and the one before.
    State is (least of the previous window, least of this one, which window
    "this" is). A first touch, or one after at least a whole idle window, has
    no history but the balance itself; a touch in the next window rolls the
    windows; a touch in the same window (or at a clock that stepped back)
    only ever lowers this window's least."""
    w = now_s // LOW_WINDOW_S
    if not initialized or w > window + 1:
        return balance, balance, w
    if w == window + 1:
        return cur, balance, w
    return prev, min(cur, balance), window


# ---------------------------------------------------------------------------
# Value conversion and conservative prices
# ---------------------------------------------------------------------------

def value_v(amount: int, mantissa: int, expo: int, decimals: int, weight_bps: int, round_up: bool):
    """The value of `amount` base units at the price `mantissa · 10^expo`
    (per whole token of `decimals` decimals), weighted by `weight_bps / 10 000`,
    in units of 1e-18 USD:

        value = amount · mantissa · 10^(18 + expo − decimals) · weight / 10 000

    exactly, then floored (collateral) or ceiled (a liability). None, which
    every caller reads as "unknown, fail closed", when the computation leaves
    the program's 128-bit domain: the exponent gap `18 + expo − decimals`
    beyond ±38 (10^39 has no u128), the numerator `amount · mantissa · weight ·
    10^max(gap, 0)` or the denominator `10 000 · 10^max(−gap, 0)` above
    U128_MAX, or a result above I128_MAX. A zero amount, price or weight is
    worth exactly 0."""
    if amount == 0 or mantissa == 0 or weight_bps == 0:
        return 0
    gap = VALUE_DECIMALS + expo - decimals
    if abs(gap) > 38:
        return None
    numerator = amount * mantissa * weight_bps * 10 ** max(gap, 0)
    denominator = BPS * 10 ** max(-gap, 0)
    if numerator > U128_MAX or denominator > U128_MAX:
        return None
    exact = Fraction(numerator, denominator)
    v = ceil(exact) if round_up else floor(exact)
    return v if v <= I128_MAX else None


def conservative_price(price: int, conf: int, ema: int, conf_mult_bps: int):
    """The bracket collateral and liabilities are valued at: `k` sigmas of
    confidence (rounded up), taken off the lower of spot and EMA for `lo` (not
    below 0) and added to the higher for `hi`. Spot and EMA must be positive."""
    if price <= 0 or ema <= 0:
        return None
    k = ceil(Fraction(conf * conf_mult_bps, BPS))
    return (max(0, min(price, ema) - k), max(price, ema) + k)


def price_is_usable(price: int, conf: int, publish_time: int, now: int, max_age_s: int, max_conf_bps: int) -> bool:
    """A positive price, published no later than now and no more than
    `max_age_s` ago, whose confidence is at most `max_conf_bps` of it."""
    if price <= 0 or not 0 <= now - publish_time <= max_age_s:
        return False
    return Fraction(conf, price) <= Fraction(max_conf_bps, BPS)


# ---------------------------------------------------------------------------
# Backed lane: per-owner shadow ledger
# ---------------------------------------------------------------------------
# Pricing for a mint is one of:
#   ("N",)                              not allowlisted (worth 0 as collateral, cannot be borrowed backed)
#   ("U",)                              allowlisted but no valid price supplied
#   ("P", lo, hi, expo, decimals, haircut_bps, liability_bps)
#
# The rule (docs/03 §4.4), stated here on the ledger *after* the payment:
# paying `b` of mint `j` is sound when the owner then
#   1. owes nothing anywhere, and holds `j` (net ≥ 0): no prices needed (G2); or
#   2. holds `j`, and `j` is not allowlisted: it was worth 0 as collateral; or
#   3. otherwise: `j` is priced, a new liability has a free slot, every
#      liability is priced, and health ≥ 0, where health is the sum of the
#      collateral at `lo` times the haircut and the liabilities at `hi` times
#      the liability weight. Collateral whose value leaves the 128-bit domain
#      counts 0; a liability whose value does makes health unknown.
# The backed amount is the largest sound `b ≤ a`.


def contribution(net: int, pricing):
    """Signed value of one position; None means 'unknown' (fail closed)."""
    if net == 0:
        return 0
    if pricing[0] != "P":
        return 0 if net > 0 else None
    _, lo, hi, expo, dec, haircut, liab = pricing
    if net > 0:
        v = value_v(net, lo, expo, dec, haircut, False)
        return 0 if v is None else v
    v = value_v(-net, hi, expo, dec, liab, True)
    return None if v is None else -v


def health(positions: dict, lookup):
    """Sum of contributions, or None if any is unknown or the sum leaves i128."""
    total = 0
    for mint, net in positions.items():
        c = contribution(net, lookup(mint))
        if c is None:
            return None
        total += c
    return total if -(I128_MAX + 1) <= total <= I128_MAX else None


def _after(positions: dict, mint, b: int) -> dict:
    """The ledger after paying `b` of `mint` (a zero position is removed)."""
    after = dict(positions)
    net = after.pop(mint, 0) - b
    if net != 0:
        after[mint] = net
    return after


def sound_after(positions: dict, mint, b: int, lookup) -> bool:
    """Whether paying `b` of `mint` leaves the ledger sound (the rule above)."""
    after = _after(positions, mint, b)
    net_after = after.get(mint, 0)
    liabilities = [m for m, v in after.items() if v < 0]
    if net_after >= 0 and not liabilities:
        return True                                           # rule 1 (G2)
    pricing = lookup(mint)
    if net_after >= 0 and pricing[0] == "N":
        return True                                           # rule 2
    if pricing[0] != "P":
        return False                                          # j must be priced
    if net_after < 0 and mint not in positions and len(positions) >= MAX_SLOTS:
        return False                                          # a new liability needs a free slot
    h = health(after, lookup)
    return h is not None and h >= 0                           # every liability priced, health ≥ 0


def backed_amount(positions: dict, mint, amount: int, lookup) -> int:
    """The largest sound `b ≤ amount`, found by bisection over [0, amount]
    (0 is always sound). Soundness is an interval below the largest sound
    amount everywhere but where a collateral value leaves the 128-bit domain
    and so counts 0 (docs/03 §4.4): there the search may stop at a sound
    amount below the largest, which is conservative, and the on-chain program
    is specified to stop at the same one, so the midpoint is fixed as
    `lo + ⌈(hi − lo) / 2⌉` (`09`, finding 4)."""
    if amount <= 0:
        return 0
    if sound_after(positions, mint, amount, lookup):
        return amount
    lo, hi = 0, amount - 1
    while lo < hi:
        mid = lo + ceil_div(hi - lo, 2)
        if sound_after(positions, mint, mid, lookup):
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
    if not MIN_LOOSEN_DELAY_S <= new_s <= MAX_LOOSEN_DELAY_S:
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
GUARDIAN_MARGIN = 2


def guardian_set_ok(count: int, threshold: int) -> bool:
    """At least two to undo a stop, and two keys more than that, so after any two
    faults (lost or rogue) short of a rogue quorum the honest guardians still eject
    a rogue (findings 96, 107)."""
    return count <= 8 and MIN_GUARDIAN_THRESHOLD <= threshold <= count - GUARDIAN_MARGIN


def guardian_set_parse(b: bytes, forbidden: list):
    """`[count][count x 32 key][threshold][interval i64 LE]` -> (keys, count, threshold,
    interval, used) or the name of the first rule it breaks, checked in this order:
    a missing count byte, the count (2..8), the full length, each key (not zero, not
    forbidden, not repeated), the threshold (guardian_set_ok), the interval (1-30 days)."""
    if len(b) < 1:
        return "Truncated"
    count = b[0]
    if not 2 <= count <= 8:
        return "BadCount"
    used = 1 + 32 * count + 1 + 8
    if len(b) < used:
        return "Truncated"
    keys = [bytes(b[1 + 32 * i:33 + 32 * i]) for i in range(count)]
    seen = set()
    for k in keys:
        if k == bytes(32) or k in forbidden or k in seen:
            return "BadKey"
        seen.add(k)
    threshold = b[1 + 32 * count]
    if not guardian_set_ok(count, threshold):
        return "BadThreshold"
    interval = int.from_bytes(b[2 + 32 * count:used], "little", signed=True)
    if not MIN_HEARTBEAT_INTERVAL_S <= interval <= MAX_HEARTBEAT_INTERVAL_S:
        return "BadInterval"
    return (keys, count, threshold, interval, used)


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
