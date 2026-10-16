# 04 — Threat model

A security product with a bug is worse than no product. This file lists every adversary we design against, what they can take, and what remains. If a row says "residual," we say it publicly.

## 1. Assets and trust boundaries

| Asset | Held by | Who can move it |
|---|---|---|
| Vault tokens | Token account owned by a Bulkhead Vault PDA | Only Bulkhead instructions: release, settle, flash, lifeboat |
| Mint authority (mint gate) | Bulkhead MintGate PDA | Only Bulkhead `mint` (limited) |
| Protected program's code | Upgrade authority = Floor PDA | Only Floor: delayed upgrade, abort, restore |
| Configuration | Bulkhead Protocol account | Tighten: admin instantly. Loosen: admin after 72h, vetoable. |
| Bulkhead / Floor code | Their own upgrade authorities | Devnet: a disclosed team key. Mainnet: burned after audit. |

**Trust assumptions we make (and state):**
1. The Solana runtime, loaders and token programs behave as specified.
2. Pyth's receiver programs (the default `rec5EKMG…` and the pro-compatible `rec2HHDD…`) and Full verification are sound for allowlisted feeds. Since 26 Aug 2026, Full verification on Solana means signatures from 3 of the Pyth Pro guardian set's 5 keys (before: 13 of Wormhole's 19). The backed lane trusts a verified price completely, so this key set is part of the trusted base for borrowing against collateral (`15`, A9).
3. At least one guardian is honest and awake within the queue delay (6h) for tickets. Freeze speed only changes how much of the burst/refill is used; see G1.
4. Bulkhead's own code is correct. This is the largest risk (T10) and gets the most verification.

## 2. Adversaries

| # | Adversary | Capability | Bulkhead's bound | Residual (stated publicly) |
|---|---|---|---|---|
| T1 | **Protocol admin key compromised** (Drift) | Any protocol setting; can propose Bulkhead changes; can tighten | Unbacked outflow ≤ G1 bound until freeze; loosening waits 72h and is vetoable; emergency moves only to the lifeboat | Can tighten to 0 (DoS of the unbacked lane ≥ 72h). Own-deposit exits keep working while the tokens are in the vault, and the key cannot put loans in depositors' names to take that away: a backed loan needs the borrower's signature (finding 74). The key can still park the vault in the lifeboat when no freeze is in force (G2 does not promise the tokens are in the vault, `00` D24); a guardian freeze stops `lifeboat_move` (`Frozen`, finding 72), so a quorum's `lifeboat_return` sticks while it lasts. |
| T2 | **Protocol upgrade key compromised** | Arbitrary protocol code signing as the caller PDA | Vault: same as T1, every outflow still goes through Bulkhead, with one exception: a malicious program can create a backed loan for any user who signs one of its transactions (that signature is the loan's consent) and move the proceeds out in the same transaction; loss up to that user's collateral × haircut (`09`, finding 89). Use Floor with the Vault. Floor: a new binary waits ≥ 72h, any guardian vetoes; any guardian can stop the program; a quorum restores the verified snapshot in one instruction. | Without Floor, the attacker can brick the protocol program (funds stay in Bulkhead vaults; the lifeboat can move them to the committed destination after 72h) |
| T3 | **Protocol logic bug** (Mango, Cashio, Loopscale) | Wrong internal accounting | Backed lane uses Bulkhead's own ledger and prices; everything else goes through the limiter | Genuine appreciation of real collateral is real value, not a loss. Minting outside the vault (Cashio's fake collateral minting CASH sold elsewhere) is not covered until mint gates ship; a manipulated price of an allowlisted token is T5 |
| T4 | **Atomic single-transaction drain** (44% of incidents; 4 KB since 15 Sep) | Many steps in one transaction or bundle | The limiter runs inside every release, so one transaction's new requests get at most the available burst | Tickets already due can be settled together in one transaction or bundle (19 fit one legacy transaction; finding 102); each was public and cancellable for at least the queue delay first (6h by default) |
| T5 | **Oracle manipulation of an allowlisted asset** | Move Pyth spot | `lo = min(spot, EMA) − k`, `hi = max + k`; confidence ceiling; allowlist only deep assets; haircuts; a forged price needs the verifying key set (assumption 2) | A sustained, multi-venue manipulation of a major asset: not bounded by G1 and not stopped by a freeze; the loss is the attacker's collateral × its overvaluation, or a whole vault if prices were forged (`09`, finding 89) |
| T6 | **Client omits or substitutes price accounts** | Wrong or missing accounts | Price PDA/owner/feed checks; unpriced collateral = 0; unpriced liability = unknown, so nothing is backed | None (property: fail closed) |
| T7 | **Malicious guardian** (a minority) | Freeze (≤ 24h, repeatable), cancel, extend, veto, Floor abort | Can't move funds or pick recipients (G5). A live quorum of the other guardians **ejects it at once** (a rotation alone would never finish: the guardian could veto its own removal). Under Floor, the quorum restores the snapshot in the same transaction. | Denial of service until the quorum acts. A malicious *quorum* is Security-Council power and out of scope; the status page checks the set against the on-chain parts of L2BEAT's bar (≥ 8 members, ≥ 75% threshold). During a freeze, own-deposit returns and backed payouts continue; only unbacked payouts wait, including a liquidation's bonus. |
| T8 | **Guardian + admin collusion** | Both roles | Still no instruction moves funds outside G1 or to non-committed destinations | DoS; unbacked budget |
| T9 | **Durable-nonce pre-signed transactions** (Drift vector) | Stale approvals executed later | Every Bulkhead/Floor proposal has an expiry; loosenings are public for 72h before they can execute | Bulkhead can't stop the protocol's own pre-signed admin actions (T1 bound applies) |
| T10 | **Bug in Bulkhead or Floor** | Everything | Zero-dependency core; three independent formulations (Rust, Python, property predicate); golden + differential + property tests; program-vs-model differential; negative tests; audits; staged TVL caps; immutability | **Correlated risk across every integrator.** The #1 risk; §4. |
| T11 | **Token-2022 extensions** | Permanent delegate, transfer hook, pausable, transfer fee, confidential transfer | `create_vault` rejects permanent delegate, transfer hook, confidential transfer, non-transferable, pausable. Transfer fee is allowed (credits the net received). | The issuer of any mint can still freeze it (mint freeze authority); disclosed per vault |
| T12 | **Rent / compute spam** | Many tickets or ledgers | Payer pays rent; tickets reserve capacity and stop at the 7-day horizon; per-instruction CU budget | Spam costs the spammer |
| T13 | **Honest whale queues a huge unbacked request** | Locks the unbacked lane (FIFO) | Horizon rejects over 7 days; guardians cancel; `reset_backlog` after cleanup | Unbacked flows wait during review |
| T14 | **Receipt-token transfer** | New holder redeems without backing | Unbacked, so limiter | Vault-share products must size buckets for secondary redemptions |
| T15 | **Flash-loan abuse** | Intra-transaction liquidity | `flash_release` needs an exact top-level `flash_repay` in the same transaction (instruction introspection); no nesting; ledger and limiter untouched | None known |
| T16 | **SIMD-0500 one-way door** | After activation, a pre-v3 binary can't be redeployed | Floor records the protected binary's version at registration, upgrade and restore; the status page and `tools/floor_check.py` flag pre-v3 programs | A pre-v3 protocol stays stopped until it ships a v3 build |
| T17 | **Oracle outage** (Pyth unavailable) | No prices | Cross-asset borrows go unbacked, so limiter; own-deposit exits unaffected | Ordinary borrowing slows during the outage |
| T18 | **Lifeboat destination compromised** | Receives lifeboat exits | Exits wait 72h; guardian veto; the destination can only change through a 72h loosening | If unnoticed for 72h, the lifeboat contents |
| T19 | **Genesis import fraud** | Admin imports fake backing before seal | Σ imported per mint ≤ vault balance at seal; imports emitted as events; **seal itself waits 72h** so anyone can compare imports with the protocol's own ledger; nothing loosens while the seal is under review | A protocol malicious at launch is out of scope for any tool |
| T19b | **A stolen admin key before the seal** | Before the seal every configuration change is instant (genesis) and nothing can be paid out, own deposits included: the key could swap in its own guardians, park the deposits in the lifeboat and take them out through an exit about 6 days later, with no honest veto and no way out for depositors | The lifeboat is shut until the seal (`NotSealed`, `09` finding 86), so pre-seal deposits cannot leave by any path before the seal's public 72h review; from the seal a depositor's own deposit leaves instantly (G2), and an exit still waits 72h. What remains is the genesis trust itself: the admin chooses guardians, limits and imported backing, and a seal proposed by a stolen key cannot be vetoed by guardians it replaced. Run the pre-seal checklist (`07 §2`): admin as a multisig, recovery key at registration, a short public genesis, deposits only after the seal | A window of at least 72h (the seal review) plus 72h (an exit), in public, during which every depositor can withdraw |
| T20 | **Front-running `settle_ticket`** | Anyone cranks | Pays only the stored recipient | None |
| T21 | **Clock skew** (refill faster than real time) | Push `Clock::unix_timestamp` ahead | Solana's clock is the stake-weighted median ("50% of the stake"); Agave bounds each timestamp to within 25% of the expected epoch time | Needs a stake majority; even then G1 measured in wall-clock time stretches by at most 1.25× |
| T22 | **Censoring or delaying a guardian's freeze** (congestion, spam) | Freeze lands later | G1 bounds loss as a function of when the freeze lands; the guardian bot sends a freeze in its own loop: no preflight, to every configured RPC every 400 ms, from at least 100,000 µL/CU (more if recent fees are higher), signed again at twice the price after each 6 s without confirmation, up to the cap, for 90 s; it reads from the next RPC when an endpoint fails (`07 §6`; `09`, findings 51 and 82); every guardian can freeze independently | Loss grows along the published G1 curve until the freeze lands |
| T23 | **Pool liquidity** (backed claims exceed what the vault holds) | Lending moves deposits out; bounded unbacked losses (G1) reduce the pool | Bulkhead never *blocks* an own-deposit return (G2) and never pays more than the vault holds; the protocol's own rules allocate a bounded loss | A last withdrawer can find the pool short by at most what left through the unbacked lane (found by the program-vs-model differential, `09 §4`) |
| T24 | **A stop that lands late** (Floor) | New code is visible from the next slot; a program is upgraded at most once per slot | Guardians send stops with a priority fee, to several RPCs; a stop is a person's decision, sent with `cloud/guardian/stop.mjs`, which re-sends every slot at a rising price (4.1 s plain; 15–44 s under an extension flood, `09` finding 77) | One runtime-level interaction affecting every upgrade-based stop is under responsible disclosure (`SECURITY.md`); Vault's in-path limits don't depend on a stop |
| T25 | **Forged or truncated log events** (misleading the guardian) | Any program can write a `Program data:` line in a transaction that touches the protocol account; logs past 10,000 bytes are truncated | The guardian counts an event only when the Vault or Floor program emitted it, reads the freeze state and new tickets from the chain every cycle, and takes a truncated transaction's outflow from the vault's token balances (`15`, A13) | None known; the on-chain bound never depended on the guardian's view |
| T26 | **A patient attacker outlasting the freeze** (T1 with the key still held) | Wait for a 24h freeze to end, take the next burst, repeat daily | The Cloud guardian's incident hold: after a breach freeze it renews the freeze before it ends, until a guardian quorum unfreezes (the program's only early unfreeze), for at most 7 days by default. Own-deposit exits work throughout (G2) | Past the hold, or with every guardian down: one burst per freeze period, inside the G1 bound. The response the hold buys time for is the admin's replacement (a 72h loosening) or the recovery key |
| T27 | **Blinding the guardian by waiting** (a quiet protocol; an RPC with short history) | Stay quiet until the node forgets the guardian's last-read signature, then attack | The guardian keeps the slot it last read and, when its RPC no longer has the signature, reads on from that slot (`09`, finding 49); it also scans active tickets every 60 s, and every guardian watches independently | A node that forgets whole slots it still has to serve would hide what happened in them; configure endpoints with full history (`rpcs`) |

## 3. Invariants and where they are tested

`core` = `crates/bulkhead-core/tests/`. `diff` = the Python-vs-Rust differential runner. `program` = `programs/tests` (the real runtime via LiteSVM).

| ID | Invariant | Tested by |
|---|---|---|
| I1 | G1 bound for every vault/mint gate, with freezes, cancels, legal resets | core `g1_dual_bucket_bound…`; exhaustive `g1_holds_for_every_three_request_sequence`; program: S1, S8 and the 12,000-step program-vs-model differential |
| I2 | No instant unbacked payout while frozen; ETA ≥ now + D; ETA ≥ frozen_until when frozen; ETA − now ≤ horizon | core (same test) |
| I3 | Tickets FIFO without freezes/cancels/resets | core `tickets_are_fifo` |
| I4 | `reset_backlog` fails with pending tickets | core; golden G-4 |
| I5 | G2: own deposit returns without prices | core `g2_…`; golden E1; program S4 |
| I6 | G3: backed payouts leave the ledger sound, and the amount is maximal | core `g3_…` (third formulation) |
| I7 | Fail closed: removing or worsening a price never increases the backed amount | core `fail_closed_and_price_monotone` |
| I8 | Backed payouts pay only the ledger owner | program: backing is derived from the recipient account's owner; Harbor `WITHDRAW` requires the user to own the recipient; differential |
| I9 | Tighten never raises the G1 bound; asset tighten never adds value | core `tighten_never_raises_the_bound`, `tighten_asset_never_adds_value` |
| I10 | Loosening can't execute before its ETA; veto blocks it; expired proposals can't execute | program S7 (`s7_…`, `an_unvetoed_loosening…`); Floor `proposals_expire…`, `a_new_guardian_set…` |
| I11 | Guardian-only instructions never transfer tokens | program-vs-model differential (balance checked around every freeze and cancel) |
| I12 | No token leaves a vault except release, settle, lifeboat | program-vs-model differential (vault balance equals the model after every step) |
| I13 | Releases fail before the seal | program `nothing_can_be_released_before_the_seal…` |
| I14 | `vault.queued_amount == Σ pending tickets` | program-vs-model differential, after every step |
| I15 | Floor: no new binary before 72h unless a quorum approved that exact frozen buffer during a restore, or the snapshot is restored | 53 Floor tests on the real loader (`programs/tests/tests/floor.rs`) |
| I16 | Python reference and Rust core agree on every input | diff (6,943,561 identical lines in the final 6-seed run; 36 fixtures with expected outputs) |

## 4. The #1 risk: a bug in Bulkhead itself

If Bulkhead is wrong, every integrator is wrong at the same time. What we do about it, in order:
1. **Keep the program small.** All math lives in one zero-dependency crate with no allocation and no unsafe code.
2. **Say every rule three ways.** Rust core, Python reference, property-test predicate. They must agree on millions of random cases.
3. **Test the program against the model.** Random instruction sequences on the real runtime, compared with the core model after every step (I1, I11, I12, I14): 12,000 steps across 24 seeds, identical (`09 §7`).
4. **Negative tests** for every account check in `05 §5`.
5. **Two audits before mainnet** (one Solana specialist, one formal-methods reviewer for the core). Public bug bounty.
6. **Staged TVL caps** with the first design partner. Then burn the upgrade authority: immutability is the product.

The hackathon build is unaudited and devnet-only, and says so in `SECURITY.md`.
