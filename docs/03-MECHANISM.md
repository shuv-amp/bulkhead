# 03 — Mechanism and algorithms

All of this is implemented once, in `crates/bulkhead-core` (pure Rust, zero dependencies, `no_std`, checked arithmetic). An independent Python model (`reference/bulkhead_ref.py`) must agree on every input. `09-VERIFICATION.md` explains how that is checked. Every worked example below is a golden case (`reference/golden/cases.txt`, labelled `G-n`), so the numbers in this file are test outputs, not prose.

Notation:
- Amounts are `u64` base units.
- Limiter times are milliseconds.
- `BPS = 10 000`. `⌈x/y⌉` rounds up; `⌊x/y⌋` rounds down.

## 1. Default parameters and why

| Parameter | Default | Why this value |
|---|---|---|
| Burst bucket `C_s / W_s` | 2% of reference / 1 hour | A bot freeze in 2 min bounds loss at 2.07% of a vault. It must be calibrated so ordinary unbacked flow (yield, bonuses) never queues. |
| Daily bucket `C_l / W_l` | 5% of reference / 24 hours | Caps the patient attacker: 24h of total silence costs 10%, not 50% (Drift model $55M vs $275M) |
| Minimum queue delay `D` | 6 hours | A ticket can't settle before a human in any timezone has had time to look |
| Queue horizon | 7 days | Tickets further out are meaningless; reject instead of queueing forever |
| Loosen delay | 72 hours, **constant minimum** | Longest timelock measured on Solana is 24h; 72h covers a weekend everywhere |
| Freeze per call | ≤ 24 hours (re-freezable) | A malicious guardian can only grief, and a live quorum of the others ejects it at once (§9) |
| Ticket extension | ≤ 24h per call, ≤ 7 days total | Room to investigate without an infinite lock |
| EMA time constant | 24 hours | A deposit spike before an attack moves the capacity only `dt/24h` of the way |
| Positions per owner | 8 | Enough for multi-collateral users; bounds compute |
| Floor upgrade delay | 72 hours, constant minimum | Same reasoning as the loosen delay |

Per-vault calibration may raise `C_s`, `C_l` (for example, perps with large honest profit days). Raising them is a loosening, so it takes 72h after seal.

## 2. The unbacked lane: dual-bucket GCRA

This is the classic dual token bucket: ATM's dual GCRA for VBR traffic (peak and sustained cell rates) and IETF IntServ's T-SPEC (RFC 2212). Network calculus (Le Boudec & Thiran) gives the conformant flow's arrival curve `α(T) = min_k(C_k + C_k·T/W_k)`, which is exactly our G1 bound. What is ours is the combination with **reserved** tickets and the backed lane (`14 §1–2`).

### 2.1 One bucket

A bucket has capacity `C` (base units) and window `W` (ms). Its whole state is one timestamp, the theoretical arrival time `TAT`.

```
cost(u)  = min(⌈u · W / C⌉, 2^61)                  (u·W computed in u128)
new_tat  = max(TAT, now) + cost(u)
conforms ⇔ new_tat − now ≤ W
```

A full bucket (idle) has `TAT ≤ now` and allows exactly `C` at once. It refills at `C/W`.

### 2.2 Two buckets and the request rule

```
request(now, u, frozen_until):
    u == 0                       → Err(ZeroAmount)
    C_s == 0 or C_l == 0         → Err(LaneClosed)          (a tightened-to-zero lane)
    nt_s = max(TAT_s, now) + cost_s(u);  nt_l = max(TAT_l, now) + cost_l(u)
    frozen = now < frozen_until
    if !frozen and nt_s − now ≤ W_s and nt_l − now ≤ W_l:
        TAT_s, TAT_l = nt_s, nt_l;  return Instant
    eta = max(now + D, nt_s − W_s, nt_l − W_l, frozen ? frozen_until : −∞)
    if eta − now > horizon:       return Err(QueueFull)       (state unchanged)
    TAT_s, TAT_l = nt_s, nt_l;   return Queued{eta}            (capacity reserved)
```

Rules, each required by the proof in §2.5:
- **Queued requests reserve capacity** (TAT moves exactly as for instant ones). Tickets are FIFO, and later requests can't jump ahead of reserved ones.
- **Cancelling a ticket does not refund** its reservation.
- **`reset_backlog(now)`** clamps each `TAT_k` to at most `now + W_k` ("just emptied", not full). It is **only legal when zero tickets are pending**. It exists so a cancelled attack doesn't block honest flows for days.
- A freeze queues every unbacked request and blocks settlement. The backed lane is untouched.

### 2.3 Worked examples (golden)

**G-1: the burst.** 10,000,000 USDC vault; `C_s` = 200,000 USDC / 1h; `C_l` = 500,000 USDC / 24h; `D` = 6h. One request per minute from 16:05:18 UTC, the Drift cadence:

| Minute | Request | Result |
|---|---|---|
| 0 | 150,000 | instant |
| 1 | 50,000 | instant (burst now used: 200,000) |
| 2 | 10,000 | ticket, ETA +6h 00m (the minimum delay) |
| 3 | 400,000 | ticket, ETA +6h 00m |
| 4 | 1,000,000 | ticket, ETA +53h 12m (the daily bucket decides) |

The attacker is paid exactly `C_s` = 200,000 instantly. Everything else waits in public.

**G-2: the patient attacker** takes only the refill, 200,000 every hour:
- Requests 1 and 2 are instant.
- Request 3 (600,000 in 2 hours) exceeds the daily bucket (500,000 plus 2h of refill) and becomes a ticket.

With one bucket, this attacker would be paid 200,000 every hour forever.

**G-4: reset after cleanup.**
- A 2,000,000 USDC request becomes a ticket due in 72h.
- `reset_backlog` is refused while it is pending (`TicketsPending`).
- After guardians cancel it, reset clamps both buckets to "just emptied": 0 available now, 20,833 USDC one hour later (daily-bucket refill).

**G-5: horizon.** A 100,000,000 USDC request would wait more than 7 days. It is rejected, and the state is unchanged.

### 2.4 The attack bound (G1), computed (golden G-6)

`max_unbacked_over(T) = min(C_s·(W_s+T)/W_s, C_l·(W_l+T)/W_l)` for the 10M USDC vault:

| Nobody freezes for | Bound | Share of vault |
|---|---|---|
| 2 minutes | 206,666 USDC | 2.07% |
| 1 hour | 400,000 USDC | 4.0% |
| 2.5 hours | 552,083 USDC | 5.5% |
| 24 hours | 1,000,000 USDC | 10.0% |
| 9 days | 5,000,000 USDC | 50.0% |

### 2.5 Proof of G1

**Claim.** Fix a bucket `(C, W)`, a start `t0` and `T ≥ 0`. Let `R` be the set of unbacked requests made at times `≥ t0` and paid (instantly, or as a ticket that was not cancelled) by `t0 + T`. Then `Σ_{r∈R} u_r ≤ C·(W + T)/W`. Both buckets apply, so the minimum of the two bounds applies.

**Proof (no resets).**
1. Every request, counted or not, sets `TAT ← max(TAT, now) + cost ≥ TAT + cost`. So `TAT` never decreases.
2. Let `r_1` be the first request in `R`, at time `τ_1 ≥ t0`. Just after it, `TAT ≥ max(TAT, τ_1) + cost_1 ≥ t0 + cost_1`.
3. By step 1, just after the last request `r_m ∈ R`: `TAT = nt_m ≥ t0 + Σ_{r∈R} cost_r`. Uncounted requests in between only add.
4. `r_m` is paid by `t0+T`, and its payout time is ≥ its conformance time `nt_m − W`:
   - instant: `nt_m − now ≤ W` and `now ≤ t0+T`;
   - ticket: `eta ≥ nt_m − W`.

   So `nt_m ≤ t0 + T + W`.
5. Therefore `Σ cost_r ≤ T + W`. Since `cost_r ≥ u_r·W/C`, we get `Σ u_r ≤ C·(T + W)/W`. ∎

**With resets.** Suppose a reset happens at time `ρ` in `[t0, t0+T]` with zero pending tickets.
- Every counted request made before `ρ` was paid or cancelled by `ρ`. The argument above on `[t0, ρ]` gives `Σ_before ≤ C·(ρ − t0 + W)/W`.
- After `ρ`, `TAT ≥ ρ + W` if it was clamped, or `≥ ρ` if it wasn't. If clamped, the same argument from `ρ` with a starting backlog of `W` gives `Σ_after ≤ C·(t0 + T − ρ)/W`. If not clamped, the reset changed nothing.
- The sum is `≤ C·(T + W)/W`. Several resets follow by induction. ∎

**Why each rule is needed.**
- *Refund on cancel:* `TAT` could fall below the value that the paid requests alone imply, crediting idle time back to the attacker.
- *Reset with pending tickets:* the pending tickets' reservations disappear, but the tickets are still paid, so they are counted twice.
- *Non-reserving tickets:* instant requests could consume the refill while tickets also settle.

The property test `g1_dual_bucket_bound_holds_with_freezes_cancels_and_resets` checks the claim with random freezes, cancellations and legal resets. It asserts non-trivial coverage: about 13k instant, 92k tickets, 1.1k resets and 23k frozen-queued at the default depth.

### 2.6 What G1 does not say

- It bounds the **unbacked** lane only. The backed lane is bounded by G3 instead.
- It is per vault. A protocol with vaults `v` loses at most `Σ_v bound_v`. With every vault at the same percentages, that is the same percentage of TVL.
- It assumes capacity is constant over the window. Capacity comes from `min(reference, live balance)` (§3): the reference moves at most `dt/24h` toward the live balance, and the live balance changes with every payment. Using the maximum capacity over the window keeps the bound valid.

## 3. The reference balance (EMA)

```
ema_update(ref, last_s, balance, now_s, initialized):
    if !initialized: return balance
    f = min(max(0, now_s − last_s), 86 400)
    return ref + ⌊(balance − ref) · f / 86 400⌋        (toward balance, truncated toward ref)
base       = min(ref, balance)                     (capacity_base; balance before the operation)
capacity_k = clamp(⌊base · bps_k / 10 000⌋, floor_k, cap_k if cap_k > 0)   (saturating at u64::MAX)
```

It is updated on every touch, **before** the operation.

**Why the lower of the two** (`15`, A1). The reference alone rises slowly, which is the point (G-8), but it also falls slowly: after a large backed exit or a bank run, capacity stayed sized for money that had left (7.8× the daily bound on what was left, in the adversarial test). With `min`, money that arrives still counts slowly and money that leaves stops counting at once. It only ever lowers a capacity, so it is a tightening at every instant. Every unbacked payout also shrinks the base, so a burst is 2% of what is in the vault at each payout: 100,000 of a 10,000,000 vault, then 99,000 of the 9,900,000 left (S8).

**Absolute caps** (`cap_k`, in tokens; 0 means none). `min` does not help against capital the attacker parks in the vault itself: deposit, wait for the reference, drain while the deposit is still there, then take it back through the backed lane (`15`, A1b: 19.8% of the honest depositors' money in a 2-minute attack on a 10M vault next to 90M parked). Caps near the vault's honest size bring that back to the G1 bound (2.1%). Setting or lowering a cap is a tightening (instant); raising it is a loosening (72h). Calibration sets both (`07 §4`).

**G-8:** an attacker deposits 100,000,000 USDC into a 10,000,000 USDC vault one minute before attacking. The reference moves from 10,000,000 to 10,069,444 (1/1440 of the way), so capacity rises 0.7%, not 11×.

## 4. The backed lane: the shadow ledger

### 4.1 State and updates

Each owner has up to 8 positions `(mint, net: i128)`. Zero entries are removed.
- `deposit`: the program measures the vault balance before and after the transfer, then credits `net += received`. Transfer-fee mints credit what actually arrived. If there is no free slot, the deposit still happens but earns no backing (conservative).
- `release`, backed part `b`: `net −= b`. A negative `net` is a backed borrow.
- Unbacked payouts never touch the ledger. Profits and bonuses don't create debt against the owner's future withdrawals.

Backing is **non-transferable** and **pays only its owner**. The recipient token account's owner must equal the ledger's owner.

### 4.2 Pricing

For an allowlisted mint with a valid Pyth `PriceUpdateV2`, the program checks:
- the account owner is the Pyth receiver program;
- verification level is Full;
- the feed id matches the asset config;
- `now − publish_time ≤ max_age`;
- `conf · 10 000 ≤ max_conf_bps · price`.

Then:

```
k  = ⌈conf · conf_mult_bps / 10 000⌉
lo = max(0, min(price, ema) − k)          collateral valued at lo
hi = max(price, ema) + k                  liabilities valued at hi
```

A one-block spike can't raise `lo` or lower `hi`. The attacker must also move Pyth's EMA and keep confidence tight (G-10: SOL $150.00 ± 0.075 with EMA $151.00 and multiplier 2.0 gives lo $149.85, hi $151.15).

### 4.3 Value and health

```
value(amount, mantissa, expo, decimals, w_bps, up) = amount·mantissa·w_bps·10^(18+expo−decimals) / 10 000
                                                     (floor, or ceil if up; None on any u128 overflow)
contribution(net > 0) = value(net, lo, haircut, floor)   if allowlisted and priced, else 0
contribution(net < 0) = −value(|net|, hi, liability, ceil) if priced, else UNKNOWN
health = Σ contributions   (UNKNOWN if any term is unknown)
```

Asymmetry on purpose:
- Unpriced **collateral** counts as 0. That only lowers health, so the client may omit prices it doesn't need.
- An unpriced **liability** makes health unknown. We can't bound what is owed.

### 4.4 The rule: how much of a payout is backed

For a request of `a` units of mint `j` to owner `o`, with `n = net_j`, the backed amount is the largest `b ≤ a` such that paying `b` leaves the ledger **sound**:
1. **Nobody owes anything** after the payout (no liabilities, and `n − b ≥ 0`). Always sound. **No prices needed.** This is G2.
2. **Someone owes, but `j` is not allowlisted** and `n − b ≥ 0`. Sound. `j` was worth 0 as collateral, so withdrawing it can't lower health.
3. **Otherwise** all of these must hold:
   - `j` must be priced;
   - a new liability needs a free slot;
   - every liability must be priced;
   - `health ≥ 0` after the payout.

Soundness is monotone in `b` (health after is non-increasing in `b`), so the valid set is an interval `[0, b_max]`. The core computes `b_max` as follows:
1. **No collateral:** if no position is above zero, return 0. Every payout would create or deepen a liability nothing covers. This exactly equals the search result, and is the common case of a payout to someone who deposited nothing.
2. **Full amount valid:** if paying the whole amount is valid, return it (the largest valid `b ≤ a`, by definition).
3. **Otherwise:** binary search on `[0, a − 1]` (≤ 64 steps).

On-chain, rules 1 and 2 take a priced borrow from ~73k to ~17k compute units (`05 §10`).

**One exception to monotonicity, found by the differential.** Collateral whose value computation overflows u128 counts as 0 (fail closed; the intermediate product overflows only for positions worth on the order of $3·10¹⁶ or more). There, paying *less* can be invalid while paying *more* is valid. In that region the search may stop below the true maximum, which is conservative. An earlier early exit ("if one unit is invalid, nothing is") assumed an interval and was rejected when the differential caught it (`09 §4`). The Rust core and the Python reference run the identical search, and 20 regression fixtures pin such cases. Golden E7 pins the search itself there: with the valid set `[4, 6]`, a request of 7 is paid 0 through the backed lane and a request of 6 is paid 6. (Mutation testing showed the search's upper bound was otherwise untested, `09 §6`.)

**Important correction to the original spec.** An earlier draft treated *any* unpriced mint as "zero-valued collateral, safe to withdraw." That is wrong for an **allowlisted** mint that backs a loan: omitting its price would release the collateral while the loan stays. Rule 2 applies only to mints that are **not allowlisted**, which could never have backed anything. The property test `fail_closed_and_price_monotone` checks that removing or worsening any price never increases the backed amount.

### 4.5 Worked examples (golden G-11)

Assets:
- USDC: lo 0.9998, hi 1.0002, haircut 99%, liability 101%.
- SOL: lo 149.70, hi 151.15, haircut 85%, liability 105%.
- CVT: not allowlisted.

| Case | Situation | Backed | Reading |
|---|---|---|---|
| E1 | Depositor of 1,000 USDC withdraws it; no prices passed | **1,000 USDC** | G2: no oracle dependency in a bank run |
| E2 | Deposited 10 SOL; asks to borrow 5,000 USDC | **1,259.60 USDC** | health = 10 × 149.70 × 0.85 = $1,272.45; ÷ (1.0002 × 1.01) |
| E3 | Owes 1,200 USDC; asks to withdraw all 10 SOL | **0.4732 SOL** | only the collateral not spoken for |
| E4 | Same, but the client omitted the SOL price | **0** | fail closed (G7) |
| E5 | 750M CVT deposited; asks for 71.4M USDC (Drift) | **0** | junk backs nothing, so all of it goes to the limiter |
| E6 | Same owner withdraws their own 750M CVT | **750M CVT** | harmless; it was worth 0 |
| E7 | Synthetic: collateral whose value overflows u128 at 4 units or more; 1 unit of another mint owed; asks for 7, then 6 | **0**, then **6** | The overflow region: conservative, and identical in both implementations |

In E2 the other 3,740.40 USDC is unbacked and goes to the limiter. The protocol's own risk engine would normally refuse such a borrow first. Bulkhead is not the protocol's risk engine; it bounds what happens when that engine is wrong or compromised.

### 4.6 Guarantees of the ledger

- **G2.** If the ledger has no liabilities, `b ≥ min(a, n)` with no price accounts. *Proof:* case 1 holds for every `b ≤ n`. ∎ (Property: `g2_own_deposit_always_comes_back_without_prices`; exhaustive: `g2_and_fail_closed_without_prices`.)
  - **What G2 promises precisely:** Bulkhead never throttles, freezes or prices the return of an owner's own deposit.
  - **What it doesn't promise:** that the tokens are in the vault. Lending moves deposits out, and a bounded unbacked loss (at most G1) reduces what the pool holds; the protocol's own rules decide who bears that.
  - The program-vs-model differential found our earlier wording ("always comes back") overclaimed this (`09 §4`).
- **G3.** After any backed payment the ledger is sound by construction. `debit_backed` re-checks soundness and refuses (`Unsound`) otherwise. The property test checks soundness with an independent third formulation of the rule, plus maximality (`b + 1` is unsound).
- **Conservation.** Backing pays only its owner and is created only by tokens that actually arrived from that owner. So across all owners, backed payouts can't exceed what owners put in, valued at conservative prices when each payout happens. A fully compromised protocol controlling any number of accounts gets, beyond its own deposits, **only the unbacked budget** (G1).

### 4.7 Calibration rule for weights

Set each Bulkhead haircut at or above the protocol's own maximum LTV plus 5 points, so that ordinary borrows are 100% backed. Example: haircut 85% for a protocol that lends at 80% LTV.

Liquidations:
- the liquidator's repayment is a deposit, which creates backing;
- the seized collateral is paid to the liquidator: the part the repayment backs goes backed, the bonus goes unbacked.

Size the buckets so a liquidation cascade fits inside them (`07 §4`, step 5). More than the bonus is unbacked: the repayment backs collateral at the conservative high price times the liability weight, so in the crash scenario (`08` S11) 14–17% of each liquidation goes to the limiter with a 5% bonus.

### 4.8 Special flows

| Flow | What happens | Why it is correct |
|---|---|---|
| Bank run (depositors withdraw own funds) | Backed, instant, no prices, even while frozen | G2 |
| Borrow within the haircut | Backed | G3 |
| Borrow against an unlisted token | Unbacked, so limiter | The Drift, Mango, Cashio, Loopscale class |
| Interest above net deposit | Unbacked (small) | Yield is not a deposit |
| Perps profit above deposit | Unbacked | Fake-PnL drains (Mango) are capped. Calibrate for honest big days. |
| Receipt token transferred, then redeemed by the new holder | New holder has no backing, so unbacked | Documented limitation; vault-share products must size the buckets for secondary-market redemptions |
| Flash loan (specified; not in this build, `07 §6`) | `flash_release` + a top-level `flash_repay` of the exact amount in the same transaction; ledger and limiter untouched | Net zero within one transaction; checked by instruction introspection |
| Admin fee withdrawal | Unbacked | The Raydium-2022 pattern is capped |

## 5. Change classification

A change is **Tighten** only if every field moves in the safe direction or stays equal. Anything else, including mixed changes, is **Loosen**.

| Change | Tighten when | Otherwise |
|---|---|---|
| Limits (per vault / mint gate) | `short_bps' ≤`, `short_window' ≥`, `long_bps' ≤`, `long_window' ≥`, `min_queue_delay' ≥`, `floor' ≤` (both), each cap tighter or equal (`0` = no cap, so `0 → x` tightens) | Loosen |
| Asset, existing | new is disabled; or all of: `haircut' ≤`, `liability' ≥`, `conf_mult' ≥`, `max_age' ≤`, `max_conf' ≤`, same feed | Loosen |
| Asset, new | never | Loosen |
| Loosen delay | `new ≥ old` (and never below 72h, else rejected) | Loosen |
| Guardians, admin, lifeboat destination, guardian threshold | never | Loosen |

Examples (golden G-12):
- halving `short_bps` tightens;
- halving the window loosens;
- lowering `short_bps` while raising `long_bps` loosens;
- adding a cap tightens;
- disabling an asset tightens;
- a new asset loosens;
- a delay of 3,600s is rejected.

**Soundness properties.**
- `tighten_never_raises_the_bound`: for any reference balance and horizon, the G1 bound under the new config is ≤ the old one.
- `tighten_asset_never_adds_value`: collateral value never rises and liability value never falls.

**Known liveness caveat.** A compromised admin can tighten instantly (for example, capacity 0 closes the unbacked lane), and undoing that takes 72h. That is denial of service on unbacked flows, not theft. Own-deposit exits keep working. We publish this.

## 6. Tickets, freezes, lifeboat

| Action | Who | Effect | Limits |
|---|---|---|---|
| `settle_ticket` | anyone (crank) | Pays the stored recipient once `now ≥ eta` and not frozen | Only the stored recipient |
| `cancel_ticket` | any guardian, admin | Ticket closed; tokens stay in the vault; the protocol decides by governance whether to re-release | No refund of reservation (§2.5) |
| `extend_ticket` | any guardian | `eta += x` | ≤ 24h per call, ≤ 7 days total |
| `freeze` | any guardian, admin | `frozen_until = max(frozen_until, now + x)` | `x ≤ 24h`; re-freezable |
| `unfreeze` | guardian quorum | `frozen_until = now` | |
| `reset_backlog` | admin or guardian | §2.2 | Only with zero pending tickets |
| `lifeboat_move` | admin | Vault → lifeboat, instant, any amount | Destination is the lifeboat PDA only |
| `lifeboat_return` | admin | Lifeboat → vault, instant | |
| `lifeboat_exit` | admin proposes; anyone executes after delay | Lifeboat → committed destination | ≥ 72h; guardian veto; destination committed ≥ 72h earlier |

## 7. The worst-case attestation

```
instant_now = available_now = min_k ⌊(W_k − backlog_k) · C_k / W_k⌋,   backlog_k = max(TAT_k, now) − now
worst_T     = min_k C_k · (W_k + T) / W_k
worst_1h    = worst_T at T = 3 600 000 ms
worst_24h   = worst_T at T = 86 400 000 ms
```

`available_now` is exact for the limiter: that amount would be instant and one unit more would not. The property `available_now_is_exact` checks it. The on-chain `attest` field is that amount capped at the vault token balance (or zero while frozen), because a transfer cannot pay more than the account holds.

`worst_T` is the G1 bound from §2.4, starting from a full bucket, and it is the minimum of both buckets. For the 10M USDC vault, `worst_1h` is 400,000 and `worst_24h` is 1,000,000 (golden G-6). The on-chain fields are this bound. They are a property of the capacities, so a configured floor can make them larger than the tokens currently in the vault; `balance` is reported beside them.

## 8. Floor helpers

- `elf_info(header)` reads `e_machine` (offset 18) and `e_flags` (offset 48).
- `deployable_after_simd0500` is true only for `e_machine = 0xF7` and `e_flags == 3`. Golden G-13: a v3 header passes, v0 fails, and so does `e_flags 4`, the regression for an earlier `≥ 3` check.
- `upgrade_eta(now, requested) = now + max(requested, 72h)`.
- `snapshot_matches(buffer, region)`: the buffer is non-empty, equals the region's prefix, and the rest of the region is zero. Kani proves this is exactly "upgrading from this buffer leaves the region unchanged" against a model of loader-v3 `Upgrade` (`09 §5`).
- `can_restore(source, buffer, approved, quorum, vetoed, now, eta, expires)`:
  - **Snapshot:** a live quorum, instantly (it can't introduce new code).
  - **Proposed fix:** a quorum that approved exactly this frozen buffer; or no veto and `eta ≤ now < expires`.
- `buffer_authority`, `programdata_header`, `program_programdata`: loader-v3 account parsers, proved panic-free and accepting only their own account kind.
- `ABORT_ELF`, `ABORT_ELF_MINIMAL`: the abort binaries, assembled from source (`06 §5`).

## 9. Governance timing (`bulkhead-core::governance`)

```
schedule(now, Tighten, _)     = executable now,                     expires now + 7d
schedule(now, Loosen, delay)  = executable now + max(delay, 72h),    expires executable + 7d
can_execute(s, t, vetoed, executed, abdicated) = OK only if none of those and executable ≤ t < expires
freeze_until(cur, now, secs)  = max(cur, now + secs) for 0 < secs ≤ 24h, else InvalidDuration
guardian_alive(last, interval, t) = interval ∈ [1d, 30d] and 0 ≤ t − last ≤ interval
quorum(approvals, alive, k)   = k > 0 and |approvals ∧ alive| ≥ k          (dead guardians never count)
can_eject(appr, alive, k, g, n) = g < n ≤ 8, k ≥ 2, n > k, and quorum(appr ∧ members(n) ∧ ¬bit(g), alive, k)
abdicate(mask, kind)          = mask | bit(kind)                         (never clears a bit)
```

In the program, `abdicate` needs the admin **and** a live guardian quorum, and an abdicated kind refuses only loosening: tightening it still applies at once. An admin key alone, possibly stolen, could otherwise give up `SetAdmin` and keep the protocol locked to it forever (`15`, A3).

**Why ejection exists: the Security Council model.**
- Any single live guardian may *stop* things (freeze, veto, cancel, abort).
- A live quorum can always *undo* a minority: unfreeze, restore, eject.
- Without ejection, one malicious guardian could veto its own removal forever and keep re-freezing, or, under Floor, keep re-aborting after every restore. Rotating it would never finish.
- Ejection adds no new trust: a guardian quorum can already restore approved code under Floor, so the quorum is trusted, and any minority is not.
- Its property test found that the first version counted bitmap slots above the guardian count; both implementations shared that bug (`09 §4`).

Golden G-14:
- a loosening proposed with a 1h protocol delay still becomes executable only after 72h;
- it is refused 1s before, and after a veto or expiry;
- a 25h freeze is rejected; a shorter freeze never shortens an existing one;
- a guardian is alive at exactly 7 days and dead 1s later;
- a quorum of 3 fails when one approver is dead;
- abdication is permanent.

Why each rule exists: `14 §3–4`.

## 10. Rounding and overflow table

| Quantity | Rounding / overflow rule | Why |
|---|---|---|
| `cost` | ceil; saturates at 2^61 ms | The requester pays at least the exact time; TAT can't overflow |
| capacity | floor; saturates at `u64::MAX` | Smaller budget. (Saturation was a real bug; see `09 §4`.) |
| EMA step | truncate toward the old reference | Moves slowly in both directions, never overshoots |
| collateral value | floor; overflow → 0 | Conservative |
| liability value | ceil; overflow → unknown → nothing backed | Conservative |
| health sum | checked; overflow → unknown | Conservative |
| ETA | computed exactly in ms; the program stores seconds rounded up | Never early |
