# Bulkhead — Full-Tree Security Audit

**Date:** 24 October 2026
**Scope:** every line of `programs/vault`, `programs/floor`, `programs/harbor`, `crates/bulkhead-core`, the Cloud guardian (`cloud/guardian`, `cloud/lib`, `cloud/status`), the deploy tooling (`cloud/deploy`), the Python tools (`tools/`, `reference/`), the build/CI/CD surface (`.github/workflows`, `Cargo.lock`, `deny.toml`, `scripts/`), and the git history (secret scan).
**Method:** hostile line-by-line review of all on-chain and off-chain code, hand-traced attack transactions, numeric edge-case derivation, supply-chain inspection, and a full-tree + full-history secrets scan. ~17,500 lines of security-relevant code read in full.
**Reviewer:** independent AI-agent review (ZCode). This is **not** a substitute for a human audit; it is a full-tree adversarial pass in the style of `docs/16` and `docs/17`.


**Status (5 Nov 2026).** Kept as written on 24 Oct; what became of each item is recorded in `09 §4`:

| Item | Status |
|---|---|
| F-01 owner checks in the guardian | Fixed, finding 146 |
| F-02 `floor_check.py` private RPCs | Fixed, finding 148 |
| F-03, F-07, F-11 status page | Fixed, finding 147 |
| F-04 Pyth `write_authority` | Stated; no stronger documented check exists. The verifying key set is trust assumption 2 in `04` |
| F-05 single upgrade key | Open, operational: the team's keys. `17 §3` item 7 commits to a timelocked multisig or Floor before the TVL-capped phase |
| F-06 Harbor raw-byte owner check, F-08 `e_machine` flag | Informational; unchanged (a demo program; the gate is exact by design) |
| F-09 release on any `v*` tag | Open, operational: a GitHub tag ruleset restricting who may push `v*` |
| F-10 decay to delay-only | (a) watchdog, finding 151; (b) a recovery key and outside heartbeat monitoring are launch requirements, `04` T29; (c) instead of a dead-man switch, the recovery key vetoes while no guardian is alive, finding 154; a bounded switch is left for the audit |

---

## 1. Executive summary

**No Critical or High severity, directly exploitable findings were identified in the on-chain programs.** Every money route was traced end to end; the rate-limiting, ledger-soundness, and governance invariants held under every attack sequence I constructed. The codebase's own findings ledger (`docs/09` §4, `docs/15`, `docs/16`, `docs/17`) has already caught and fixed a large class of issues, and this review confirms those fixes are actually present in the code, not just documented.

What this review did find:

| Severity | Count | Summary |
|---|---|---|
| Medium | 2 | Operational: devnet upgrade authority is a single team key (known, disclosed — re-flagged); guardian-liveness decay — when no guardian is live, every on-chain guarantee degrades to *delay-only* protection (F-10) |
| Low | 5 | Guardian does not verify account *owner* on reads; `floor_check.py` accepts arbitrary RPC URLs; status page will query any RPC named in a link; status-page *trust laundering* via a crafted link naming real ids + a lying RPC; Pyth `write_authority` not checked |
| Informational | 5 | Harbor demo raw-byte owner check; lossy `Number()` in a display line; sBPF `e_machine` readiness flag; tag-push release publication; malicious-integrator registration is permissionless by design (scope boundary, §10.4) |
| Residual (already documented by the team, verified real) | 5 | A1b uncapped base widening, A2 patient-attacker pacing, queue settlement burst (finding 102), rogue-RPC detection suppression, oracle risk on the backed lane (T5) |

§10 contains the dedicated **attack-scope analysis**: the adversary matrix, sixteen traced attack chains with their verified blast radius, and the scope boundaries of what Bulkhead does and does not defend.

Headline strengths confirmed by this review (evidence in §5):

- **Arithmetic is fail-closed end to end**: `overflow-checks = true` in the release profile (panics → transaction failure), checked/ceil-rounded `u128`/`i128` math in the core, `COST_MAX_MS` TAT saturation so limiter arithmetic cannot overflow `i64`.
- **Every account is re-derived and type-checked**: canonical PDA derivation, exact-length layouts with discriminators, cross-account consistency checks (protocol ↔ vault ↔ mint ↔ token program), duplicate-account and vault/protocol-PDA recipient refusal.
- **The G2 "own money never held" precondition is correctly enforced** — the fast path requires *no liability anywhere*, not just a positive balance in the withdrawn mint.
- **Floor's buffer immutability argument is sound**: once a buffer's authority is Floor's PDA, only Floor can release it, and no instruction does so except `execute_release` (which also closes the config) — so "frozen at propose ⇒ frozen at execute" holds without re-checking.
- **The guardian bot cannot be turned into a money-moving or signature-oracle device**: it only signs locally-built freeze/cancel/veto/heartbeat instructions; no transaction is ever constructed from RPC-supplied instruction bytes.
- **No secrets in the tree or the entire git history**; key files are permission-checked (`0600` enforced, key bytes never quoted in errors); CI is SHA-pinned with empty default permissions and no `pull_request_target`.

---

## 2. Scope, method, and what was *not* audited

Read in full: all of `programs/vault/src` (12 files), `programs/floor/src` (9 files), `programs/harbor/src`, `crates/bulkhead-core/src` (12 files), `cloud/guardian/*.mjs`, `cloud/lib/*.mjs`, `cloud/status/` (page + snapshot), `cloud/deploy/*.mjs` (key handling and structure), `.github/workflows/*.yml`, `deny.toml`, workspace `Cargo.toml`, `Cargo.lock` (dependency inspection), `scripts/` (safety scan of every script), `tools/*.py` and `reference/*.py` (network/subprocess/eval scan), `SECURITY.md`/`DISCLOSURE.md`.

Scanned (not line-by-line): `cloud/e2e/*` and `cloud/test/*` (test tooling), `fuzz/` targets, `crates/bulkhead-diff` (test-only line protocol), `programs/tests`, `docs/*` (consulted for intended invariants), git history (automated secret-file and credential-pattern scan).

Not audited: the correctness of the Kani proof *statements* beyond a vacuity skim of `proofs.rs` (assumptions are range-bounds for tractability, standard for bounded proofs, and the README labels them as bounded); the Python reference's algorithmic equivalence to Rust (that is the differential test suite's job); the accuracy of marketing/prose claims in `docs/` other than where they state security properties.

---

## 3. Money-route map (every path tokens can move)

The Vault program owns token accounts through two PDAs (`vault-tokens`, `lifeboat-tokens`), each owned by the vault PDA. Six instructions move tokens; nothing else can, because no other instruction produces a token CPI signed by the vault PDA.

| # | Route | Who authorizes | Limits applied | Edge behavior |
|---|---|---|---|---|
| 1 | `deposit` (user → vault) | Source authority signs; protocol's `bulkhead-caller` PDA signs the CPI | none (deposits never throttled) | Credit = actual balance delta (fee-on-transfer accounted); ledger-full → whole deposit reverts (finding 132 fix); `received` overflow-checked |
| 2 | `release` (vault → recipient) | Protocol's caller PDA only (quote mode is read-only) | Backed ≤ ledger-sound amount at conservative Pyth prices (loan needs the owner's own signature; a freeze caps backing at own balance — findings 74/90/98); unbacked ≤ dual-bucket GCRA; excess queued ≥ 6 h | `backed + instant > balance` → refuse (covers lifeboat parking); recipient may not be the vault/protocol PDA (finding 89) or the vault's own token account; ticket PDA is payer+nonce-addressed so queued releases never race |
| 3 | `settle_ticket` (vault → recipient) | **Anyone**, only when due and not frozen | Amount fixed at queue time; reservation was already consumed | Re-reads the recipient's *current* owner; refuses vault/protocol PDA ownership; balance short → ticket stays pending; double-settle impossible (account closed after settle); rent → the ticket's payer |
| 4 | `lifeboat_move` (vault → lifeboat) | Admin, post-seal + one loosen-delay, and **not while frozen** | Fee-bearing mints refused entirely (finding 97) | Lifeboat balance tracked as actual, not gross; pre-seal and under-review windows closed (findings 86/88) |
| 5 | `lifeboat_return` (lifeboat → vault) | Admin alone, or a live guardian quorum | — | Clamps any pending exit to the real balance |
| 6 | `execute_lifeboat_exit` (lifeboat → committed destination) | The destination itself signs; exit executable only after ≥ 72 h, unvetoed, unfrozen, proposed by the *current* admin, and the destination must predate the proposal by ≥ 72 h | Destination swap after proposal → negative settled-age → refused | Destination must not be an account owned by this program (stranded-funds refusal, finding 85) |

Everything else (`freeze`, `unfreeze`, `heartbeat`, `eject`, `abdicate`, `reset_backlog`, `propose/veto/execute/cancel change`, `veto/cancel/extend ticket`, `attest`, `quote`, seal instructions, `replace_recovery`) moves **no tokens** — verified by instruction-by-instruction inspection. Floor moves no tokens ever; it only moves *rent* of buffers/config to the owner and signs loader-v3 CPIs (`Upgrade`, `SetAuthority[Checked]`, `Close`-of-buffer) under its own authority PDA.

**Non-deposit inflows** (a plain SPL transfer straight into the vault's token account, bypassing `deposit`) are uncredited: they raise the live balance but not the ledger, and the capacity base (`min(reference, live, low-water)`) lags them via the 24 h EMA and the 30–60 min low-water window. Parking capital this way to widen the base is the documented A1b residual; absolute caps bound it and are flagged as `UNCAPPED` on the status page.

---

## 4. Findings

Severity scale: Critical (direct loss of funds / limit bypass) · High (limit weakening, soundness break, or theft-grade griefing) · Medium (incorrect behavior under plausible conditions, or operational keys) · Low (defense-in-depth gap) · Informational.

### F-01 · Low · Guardian decodes accounts without verifying the account owner

**Where:** `cloud/lib/solana.mjs:313` (`Rpc.account`), `cloud/guardian/main.mjs:444` (`readDecoded`), `cloud/guardian/main.mjs:1109` (`readProtocolAccount`).

Every chain read decodes `getAccountInfo` bytes without checking `value.owner` equals the expected program id (Vault or Floor). A compromised or malicious RPC endpoint could serve a fabricated "protocol" or "ticket" account.

**Impact analysis (why this is Low, not High):** the guardian signs only instructions it builds itself, and the on-chain program re-validates every account, so fabricated data cannot move funds and at worst causes:
- a *suppressed* freeze — but this requires every endpoint to be complicit simultaneously; endpoints are genesis-hash pinned per endpoint (finding 114), slot/signature cross-checked, and cross-checked against monotonically-growing account counters (finding 138), so one lying endpoint is detected and one all-lying endpoint set is the documented rogue-RPC residual;
- a *spurious* freeze — fail-closed direction;
- a *rejected* cancel (`WrongTicket` etc.) — retried, no harm.

**Recommendation:** add an `owner` check to `Rpc.account`/`readDecoded` (one line per call site: compare `acc.owner` with the expected program id; fail loud). This converts a silent-trust read into an explicit one and would also catch operator misconfiguration (wrong cluster ids).

### F-02 · Low · `tools/floor_check.py` will POST to any http(s) URL supplied via `--rpc`

**Where:** `tools/floor_check.py:65-68,105,196`.

The scheme is validated (http/https only — good), but any host, including private network ranges, is accepted, defaulting to public mainnet. A user tricked into running a copy-pasted command with an attacker-supplied URL sends JSON-RPC POSTs to it from the operator's machine (an SSRF-by-operator vector; responses could also be attacker-forged since the tool prints what the RPC says).

**Impact:** Low — read-only diagnostic, run by the operator, output is a report the README frames as untrusted ("trust it only as far as you trust that RPC"). **Recommendation:** optionally warn or refuse on RFC1918/loopback/link-local targets unless `--allow-private-rpc` is passed.

### F-03 · Low · Status page queries any RPC named in a link

**Where:** `cloud/status/index.html` (RPC URL taken from the query string; fetches from the reader's browser).

A crafted link makes a reader's browser issue RPC POSTs to an attacker-chosen endpoint. Responses stay in the reader's browser (no exfil path to the attacker), and the page itself warns about trusting the RPC. All dynamic content is HTML-escaped (`esc()`), including the `warnings` array — I traced every unescaped template interpolation in the file and all are numeric or static, so **no XSS** (this was the primary thing to rule out here).

**Recommendation:** Informational-to-Low; optionally show the RPC host more prominently or refuse `localhost`/private hosts, since a link could point a reader's browser at an internal RPC they did not intend to expose.

### F-04 · Low · Pyth price accounts: `write_authority` not checked

**Where:** `programs/vault/src/pyth.rs:79-96`.

The program checks the account owner (both known Pyth receivers), the `PriceUpdateV2` discriminator, `Full` verification level, feed id, freshness, confidence width, and price positivity — but not the account's `write_authority` field. The trust placed in the receiver programs' semantics (only Wormhole-verified updates reach a `Full` account) is the same trust every standard Pyth integrator takes, and oracle risk on the backed lane is explicitly excluded from the threat model's guarantees (T5, finding 90's freeze-cap mitigation).

**Recommendation:** if Pyth ever documents a stronger check (e.g. a canonical write authority value), add it; otherwise document the assumption in `docs/04` next to T5. No action required now.

### F-05 · Medium (operational) · Devnet upgrade authority is a single team key

**Where:** `SECURITY.md` (disclosed), all three devnet programs.

Known and honestly disclosed, but as an auditor it must be flagged with weight: until the post-audit burn, *the weakest link in the entire system is the Bulkhead team key itself*. A compromise of that one key upgrades the Vault or Floor program to arbitrary code with no timelock — exactly the class of event Bulkhead exists to prevent in its customers. Floor cannot protect Bulkhead's own programs (it does not hold its own key).

**Recommendation:** don't wait for the audit. Move all three devnet upgrade authorities behind a timelocked multisig now (Squads with a time lock, or register the programs under their own Floor with a different team quorum as guardians), so even the devnet story has *no* single-key upgrade path. Keep the burn as the final step.

### F-06 · Informational · Harbor demo checks token-account ownership by raw byte offsets

**Where:** `programs/harbor/src/lib.rs:82` (`d.len() < 64 || d[32..64] != user`), also `:94` (admin read from raw protocol-account bytes at `72..104`).

The demo reads raw offsets without verifying the account is owned by the token program / by Bulkhead. Harbor is *deliberately* naive and the Vault re-validates everything on the receiving side, so nothing security-relevant depends on these reads; the byte-offset admin read is additionally layout-coupled to the Vault state layout and will silently misbehave if the layout changes. Demo-only.

### F-07 · Informational · Lossy `Number()` on a u64 balance in a display line

**Where:** `cloud/deploy/vault-check.mjs:105,107` — `Number(balance) / 1e6` for a log line. BigInt discipline is otherwise excellent (all threshold math is BigInt; `policy.mjs` even documents why). Display-only; harmless at test-USDC magnitudes.

### F-08 · Informational · `deployable_after_simd0500` requires `e_machine == EM_BPF (0xF7)`

**Where:** `crates/bulkhead-core/src/floor.rs:61-63`.

`elf_info` accepts both `EM_BPF` and `EM_SBPF (0x107)`, but the SIMD-0500 readiness predicate requires `EM_BPF` specifically. This field is informational (Floor's `elf_is_v3` status flag; nothing gates on it), so no security impact — but if the v3 toolchain in actual use emits `EM_SBPF`, the readiness flag will read pessimistic. Re-confirm against agave's accepted machine id when SIMD-0500 activation approaches.

### F-09 · Informational · Release workflow publishes on any `v*` tag push

**Where:** `.github/workflows/release.yml` — anyone with tag-push rights triggers a release. The job only builds from the tag in a digest-pinned image with attestations and publishes artifacts; **nothing deploys** (deploy is a manual, key-held act per `scripts/deploy.sh`). With SHA-pinned actions, `permissions: {}` plus explicit per-job scopes, and `persist-credentials: false`, this is acceptable. Note it so the team keeps tag-push protected.

### F-10 · Medium (scope/operational) · All guarantees decay to delay-only protection when no guardian is live

**Where:** design-level (G5's liveness rule), `crates/bulkhead-core/src/governance.rs:103`, both programs' veto paths.

Every emergency brake in the system that depends on a guardian — vetoing a loosening, vetoing a lifeboat exit, vetoing a Floor proposal or release, unfreezing, ejecting a rogue, restoring a stopped program — requires a **live** (heart-beating) guardian, and guardian sets can only be replaced by a delayed admin proposal (`SET_GUARDIANS` is always a Loosen). Now compose two failures:

1. **Ops failure:** all guardians' heartbeats lapse (bot down past its interval, security firms' keys offline). Dead guardians cannot act and cannot revive themselves; only a new set (a 72 h, vetoable proposal — which needs nobody's veto to *pass*) brings guardianship back.
2. **Key theft in that window:** the admin key proposes maximal loosening (bps to 10 000, i.e. 100 % of the base per window, floors up, caps off). With no live guardian, nothing can veto. 72 h later it executes; a single release of the entire vault now *conforms instantly* (100 % per window passes both buckets). Same for Floor: a dead-guardian program's only remaining protection is the upgrade delay itself.

This is not a code bug — it is the design's explicit dependency ("Only guardians that heartbeat count"), and the heartbeat bounds (1–30 day intervals) plus alerts exist precisely to prevent it. But the compositional failure mode deserves top-line statement: **the 72-hour window is only as strong as the liveliest guardian**, and guardian *liveness* is an operational property, not an on-chain one.

**Recommendations:** (a) alert on guardian staleness through a channel that does not depend on the guardian bot itself being alive (the bot's `floorAlerts`/set-shape checks help only while the bot runs); (b) make multi-guardian, multi-operator setups (the docs' "operations key + Cloud bot + two security firms") a hard launch requirement, not a suggestion; (c) consider an on-chain countdown that widens freeze powers or tightens limits automatically toward the conservative end when no guardian has heart-beat for N days — a "dead-man switch" that converts liveness loss into a tightening rather than into delay-only protection.

### F-11 · Low · Status-page trust laundering: real ids + lying RPC

**Where:** `cloud/status/index.html` (RPC URL from the query string; `KNOWN_VAULTS`/`KNOWN_FLOORS` banners key off the *ids*, not the data's source).

The page's anti-impersonation warning fires only when the Vault/Floor program ids are *not* the published ones. An attacker who sends a depositor a link naming the **real** vault/protocol/mint ids but `rpc=<attacker's RPC>` gets a page that renders attacker-controlled account data under the real ids — e.g. "worst case right now: 0.02 now, at most X in an hour", frozen-staus "no", guardians "4 of 4 live" — with no banner, because the ids check out. The only defenses are the small print ("Trust it only as far as you trust that RPC") and the reader noticing the host in the source line. This is a phishing-grade vector aimed at the humans around the machine, which is exactly the population the page exists to inform.

**Recommendations:** display the RPC host prominently at the top (not only in the source footer); fetch and show the cluster **genesis hash** and compare it against the known devnet/mainnet hashes, refusing to render "live" styling when it does not match; optionally cross-fetch the headline numbers from a second independent public RPC when the link's RPC is not one of the well-known defaults.



## 5. Verified-safe areas (what was attacked, and why it held)

This section is the evidence behind the executive summary's verdict. Each item was an active attack hypothesis that failed, with the reason.

### 5.1 Limiter (core `limiter.rs` + call sites)

- **Overflow:** `cost_ms` saturates at `COST_MAX_MS = 2^61`; TAT sums stay `< 2^62` in `i64`; window values are `u32` seconds so `window_ms = s*1000` cannot overflow `i64`. Release profile has `overflow-checks = true` — any residual unchecked op panics (tx fails, fail-closed) rather than wraps.
- **Instant/queue boundary:** `Instant` requires *both* buckets conforming and not frozen; `QueueFull` rejects **before** state mutation, so rejected requests cannot burn capacity; queued requests still consume TAT (required for G1).
- **Rounding:** all costs are `ceil`; `available_now` floors. Every rounding direction is against the payer.
- **Window-change refill attack** (lengthen window = tightening applied instantly): `rescale_windows` preserves the *used fraction* with ceiling rounding — a just-drained bucket cannot refill by re-proposing windows (the program calls it in `apply`, `programs/vault/src/governance.rs:176`).
- **Clock-backwards:** TAT uses `max(tat, now)`; `touch_reference` clamps `ref_updated_s` monotonically; `reset_backlog` uses `max(t, ref_updated_s)` (finding 101 fix verified).
- **Base manipulation:** `unbacked_base = min(reference_EMA, live, low-water)`; flash-loan deposits are caught by the low-water window (finding 65), drain-shrink by the live balance (A1), fresh parking by the EMA (A1b — the documented residual, bounded only by absolute caps).
- **`reset_backlog` abuse:** requires zero pending tickets and only clamps to "just emptied" — never more than a fresh bucket; the claim that G1 survives it is correct because a fresh bucket is the G1 starting assumption.

### 5.2 Ledger and pricing (core `ledger.rs`, `value.rs`, `price.rs`; program `pyth.rs`)

- **Misclassifying unbacked as backed:** `backed_amount`'s G2 fast path requires *no liability in any other mint* **and** `net(mint) ≥ amount` — i.e. the owner owes nothing anywhere. The deposit-then-withdraw-while-owing sequence correctly falls to the health check.
- **Consent:** a loan (release beyond own balance) requires the owner's signature among the instruction's signers; the caller PDA's own signature is explicitly *not* consent, including for pooled-caller integrators (findings 74/98, verified at `custody.rs:345`).
- **Freeze reach:** while frozen, backing is capped at the owner's own balance (finding 90) — the unfreezable lane cannot be used to drain via loans during an incident; G2 own-deposit exits still work.
- **Oracle hostility:** negative/zero price or EMA → refuse; confidence wider than the config cap → unusable; stale → unusable; collateral-valuation overflow → counts as zero; liability unpriceable → health unknown → nothing backed (G7 holds in every branch). `value_v` bounds the decimal shift to `10^38` and uses checked multiplies; `hi` uses `checked_add`, `lo` uses `saturating_sub`.
- **Fee-on-transfer / weird tokens:** deposit credits the *actual* balance delta; the Token-2022 policy refuses `PermanentDelegate`, `TransferHook`, confidential transfers, `NonTransferable`, `Pausable`, close-authority mints, frozen default states, and (for the lifeboat) any fee-capable mint; interest-bearing/scaled-UI mints can never be priced as collateral (finding 68). The multisig-length trap (355 bytes) in account parsing is explicitly handled.
- **Ledger corruption:** `Backing::ledger` rejects duplicate mints/zero entries; layouts are exact-length with discriminators; a Change account cannot be read as a Ticket (type-cosplay test in `state.rs`).

### 5.3 Account validation (both programs)

Every loader re-derives the canonical PDA (`expect_pda`) and cross-checks the stored protocol/mint/token-program/token-account fields against the passed accounts; vault↔protocol ownership is enforced on every touch; recipients may not be the vault's own token account, nor accounts owned by the vault or protocol PDAs (finding 89), re-checked at ticket settle with the *current* owner; duplicate accounts are refused. The pre-funded-PDA grief on creation is handled by top-up+allocate+assign. `create_pda` requires empty data + system ownership. Rent of closed tickets/configs goes only to the recorded payer/owner.

### 5.4 Governance (core `classify.rs`/`governance.rs` + both programs)

- **Classification directions re-derived independently:** every field of `classify_limits`/`classify_asset` moves the safe way or the change is a Loosen (72 h, public, vetoable, expiring). Cap semantics (`0` = none) are handled so removing a cap is a Loosen. Delay is hard-bounded to [72 h, 30 d] in *both* programs (the unbounded-delay self-lock is closed).
- **Quorum/bitmap math:** `signer_bits` can only set bits for occupied slots (no phantom-quorum), duplicate signers set one bit, non-guardian signers error; `can_eject` masks membership, excludes the target, requires `count > threshold` (a quorum remains reachable after ejection); Floor's `eject` clears shifted approvals and withdraws pending guardian-set proposals; ejection bumps the version counter that stales pending `SET_GUARDIANS`.
- **Proposal integrity:** the Vault's `execute_change` re-parses the payload against *current* state, requires the proposer to still hold the role (findings 87/133), and requires the target's version to be unchanged since proposal (staleness). Floor's approvals name the proposal id (finding 58) and `can_restore` requires quorum approval of *that exact* buffer for the fast path. The lifeboat exit requires the current admin as proposer (issue #66) and the settled destination (swap-after-proposal yields a negative age and is refused).
- **Recovery key:** cannot be admin, guardian, or (as target) collide with any of them; only proposes `SET_ADMIN`/`SET_RECOVERY`; the owner cannot cancel its proposals; `replace_recovery` (admin + live quorum) stales everything the old key queued.
- **Seal:** registrar must prove it currently holds the program's upgrade authority (parsed from the loader programdata) or sign through the program's caller PDA; a seal under review freezes all loosenings (T19); execution requires every vault enumerated and `imports + deposits ≤ vault + lifeboat − pending-exit` balances.

### 5.5 Floor-specific

- **Upgrade authority escape:** the only paths that sign `SetAuthority[Checked]` as Floor are `execute_release` (after the full delay, unvetoed, with the new authority's own signature or the owner's for none) and `register` (the *current* authority signs the handover in the same instruction — there is no window where Floor holds the authority with someone else's guardians). `Close` is reachable only for buffers via `check_frozen_buffer`'s narrow acceptance; the program account itself is never closable through Floor.
- **Byte-swap between propose and execute:** the buffer must be frozen (authority = Floor's PDA) *at propose*; once frozen only Floor can unfreeze it and no instruction does before release; `execute_code` re-checks the address equals `pending_target` and that it is neither the staged abort nor the pinned snapshot. Approvals are per-id. I could not construct a path where the buffer that executes differs from the buffer that was public for 72 h.
- **Snapshot identity:** `snapshot_identical` compares the full buffer bytes to programdata with the ELF-extent length rule and trailing-zero rule (findings 88/115/116); `pin_snapshot` and the stop-time re-verification both run it against the *live bytes*; `restore_snapshot` requires `snapshot_valid` set at abort time plus a live quorum. Re-pin tolerance (finding 66) and the spill-to-config fix (finding 88's rent-grab) are present.
- **Abort binary:** `is_canonical_abort` is an exact byte match against the two embedded constants (a const-built sBPF v3 ELF that logs and returns `Custom(0x464C4F52)`) — a staged "abort" cannot be arbitrary code. Stage replacement needs a live quorum. The owner may stop only while no guardian quorum is live (anti stop-restore ping-pong).
- **Loader parsing:** offsets/tags match loader-v3 (`BUFFER_DATA_OFFSET 37`, `PROGRAMDATA_DATA_OFFSET 45`, tags 1/2/3); `elf_extent` uses checked arithmetic throughout, caps segment/section counts, and reads no attacker-influenced field as an authority.

### 5.6 Guardian bot and Cloud

- **Key hygiene:** key files must be `0600` (refused otherwise), key bytes never appear in error text, state files are `0600` + fsync + atomic rename + directory fsync; a pid lock prevents two guardians on one state file (finding 139).
- **Signature authority:** every sent transaction is built from locally-constructed instructions (`cloud/lib/bulkhead.mjs` builders match the program's account layouts exactly — cross-checked field by field); nothing auto-signs RPC-supplied transactions or instruction data.
- **RPC trust:** per-endpoint genesis-hash pinning (finding 114), failover on failure only, periodic slot-lag and missing-signature cross-checks, and a monotonic-counter cross-check that catches a censoring primary serving decoy traffic (finding 138). `minContextSlot` is used on state reads to defeat load-balancer lag. (See F-01 for the remaining owner-check gap.)
- **Event parsing:** exact per-event field counts, protocol attribution on every Vault event (finding 64), unknown/foreign events dropped-not-misread, decoder exceptions contained per-event (finding 139). Amount math is BigInt end to end (the one intentional `Number()` is a fee percentile, not an amount). The log parser (`parseLogs`) tracks the invoke stack, so a `Program data:` line forged by any other program attributes to that program and is filtered; all its regexes are anchored and linear (no ReDoS); non-base64 payloads are skipped. `ingestOne`'s truncated-log fallback reconstructs unexplained outflows from *balances and transfers*, so even a log-capped tx is counted.
- **Crash containment:** every loop step is wrapped (`step`/`stepOutcome` → stall alerts, finding 71); `unhandledRejection`/`uncaughtException` → `fatal` (alert + exit 1) under the systemd unit's restart; a dead guardian stops heartbeating and *loses* its on-chain powers (fail-closed), reviving only within its interval. A crash-looping guardian therefore cannot silently watch — it either recovers or loudly disappears.
- **Send safety:** freeze uses the escalating no-preflight multi-endpoint loop with idempotency (`settled()` reads the protocol account; `already frozen` short-circuit; earlier signatures watched); budget-refusal fallback re-sends without the budget (finding 47); `AlreadyProcessed` treated as success (finding 82); blockhash-expiry detected and reported rather than double-spent; cancels re-validate the ticket (id/payer/address reuse) before sending and treat peer-cancellation as success.
- **Status page:** every interpolation either escaped or numeric; generation-guarded rendering (no stale overwrite).

### 5.7 Supply chain and CI/CD

- **Dependencies:** `bulkhead-core` has **zero** dependencies (verified). Vault/Floor/Harbor depend only on `pinocchio =0.11.2` (exact pin) plus a host-only `solana-address 2.x` for off-chain tests. No git dependencies, no path escapes, no typo-squats in the lock; `deny.toml` denies unknown sources, wildcards, and yanked crates and flags unmaintained ones; advisory scanning is wired into CI (`scripts/deny.sh`). I found no known-vulnerable versions among the shipped crates by inspection; keep CI's advisory check authoritative.
- **Workflows:** actions pinned by full commit SHA; `permissions: {}` at the top with narrow per-job grants; `persist-credentials: false`; no `pull_request_target`; PR file lists are consumed only by a `set -euo pipefail` case-matching script (no shell interpolation of PR content). Release builds happen in a digest-pinned Docker image with Sigstore attestations and SHA256SUMS; CI never deploys.
- **Secrets:** full-tree and full-history scans found no keypairs, mnemonics, API tokens, or credential-bearing URLs. `scripts/copilot.py` takes its token from env/`.env` (untracked). Deploy keys are passed as file arguments, never embedded.
- **Toolchain:** Rust `1.92.0` pinned; fuzz nightly pinned; installers referenced in docs are versioned.

---

## 6. CWE-class risk matrix

Bulkhead is bespoke, unpackaged software, so no CVE identifiers exist for it; the meaningful question is which CWE classes apply and whether they are mitigated. Every class I probed:

| CWE | Class | Status in Bulkhead |
|---|---|---|
| 190/680/1284 | Integer overflow/wrap | **Mitigated**: `overflow-checks = true` in release; checked `u128/i128` math; TAT saturation; shift bounds in `value_v`. Any panic fails the tx (fail-closed) |
| 20/347 | Improper input validation / signature verification | **Mitigated on-chain**: canonical PDA re-derivation, exact layouts, signer checks, cross-field checks. **Gap (Low)**: guardian-side owner check on account reads (F-01) |
| 682 | Incorrect computation | **Mitigated**: rounding directions audited (ceil against the payer, floor for collateral); binary-search corner documented conservative |
| 284/269 | Improper access control / privilege | **Mitigated**: per-instruction authority matrix verified (admin vs live guardian vs quorum vs anyone); recovery-key powers minimal and disjoint |
| 362/367 | Race conditions (TOCTOU) | **Mitigated on-chain** (atomic); off-chain idempotency + settled() + minContextSlot; ticket addresses payer+nonce so queued releases can't collide |
| 400/770 | Resource exhaustion / DoS | **Partially by design**: a stolen admin can always halt (freeze, tighten, close lanes) — never drain; CU bounded (fixed-size loops ≤ 9 slots/8 guardians; byte compares are the loader's cost); guardian has backoff and per-target isolation |
| 918 | SSRF | **Low, tool-side only** (F-02, F-03); the guardian's own endpoints are operator-configured and genesis-pinned |
| 79 | XSS | **Mitigated** on the status page (all dynamic strings escaped; verified interpolation-by-interpolation) |
| 200/532 | Information exposure / secrets in logs | **Mitigated**: no secrets in tree/history; key bytes excluded from errors; alert URLs never logged |
| 22 | Path traversal | No attacker-influenced file paths in the runtime path; statefile path is operator config |
| 502 | Deserialization of untrusted data | Fixed-length, discriminator-checked manual layouts with bounds-checked readers; unknown layouts rejected, not guessed |
| 670 | Always-false control flow (the abort binary) | **Verified by construction**: canonical abort is an exact-byte sBPF v3 ELF that logs and returns an error |
| 494/829 | Malicious update / unverified upload | **This is the product**: Floor's delay/veto/quorum-restore verified; **residual** is Bulkhead's own devnet team key (F-05) |
| 345/346 | Origin validation (oracle) | Pyth receiver ownership + Full level + feed id + freshness/conf gates (F-04 for the residual `write_authority` note); oracle risk excluded from G-guarantees by design |
| 732 | Incorrect permission assignment | Key files permission-checked; state files 0600; instance lock |

---

## 7. Guarantee assessment (G1–G9 as stated in the README)

| G | Claim | This review's assessment |
|---|---|---|
| G1 | Unbacked outflow ≤ `min_k C_k(W_k+T)/W_k` | **Holds** in the code paths reviewed: TAT math, ceil costs, no-refund-on-cancel, `reset_backlog` ≤ fresh bucket, rescale-preserves-fraction, base = min(EMA, live, low). The known exceptions are documented, not accidental: same-clock-hour settlement bursts of *due* tickets (finding 102), and A1b base widening on uncapped vaults |
| G2 | Own deposit never throttled/frozen/priced | **Holds**, and the precondition ("owes nothing") is genuinely enforced: the fast path requires no liability in any mint |
| G3 | Backed payouts leave the ledger sound at conservative prices | **Holds**: health checked pre-debit, re-checked in `debit_backed`, fail-closed on any unknown |
| G4 | Tighten instant; loosen ≥ 72 h, public, vetoable | **Holds**: classification directions independently re-derived; delay hard-bounded [72 h, 30 d]; seal review blocks last-minute loosening |
| G5 | Guardians stop, never steal; liveness; ejection | **Holds**: no guardian-only instruction moves tokens; unfreeze/eject/restore are quorum-gated over live guardians; set rules (threshold+2, ≤ 8, forbidden keys) enforced at every parse |
| G6 | Lifeboat: Bulkhead-held only, 72 h exits to pre-committed destination | **Holds**: settled-destination check survives destination swaps (negative age refused), destination signs, freeze blocks execution, proposer must still be admin |
| G7 | Missing/stale/wide prices, unknown assets, overflow only reduce backing | **Holds** in every branch traced (zero-price, wide-conf, stale, overflow→0-collateral, unpriceable-liability→unknown-health) |
| G8 | Floor: 72 h deploys, instant single-guardian stop, quorum restore byte-identical | **Holds**: exact-byte canonical abort, snapshot identity with ELF-extent rule, per-id approvals, no byte-swap path found |
| G9 | Upgrade authorities burned after audit | **Pending by design**; re-flagged as F-05 with a "don't wait" recommendation |

---

## 8. Residual risks (documented by the team; verified real, restated for the record)

1. **A1b — parked capital widens an uncapped base.** Real: the EMA and low-window only slow it. Absolute caps are the bound and they are *optional* configuration. The status page flags `UNCAPPED`; make caps a hard launch-checklist item (the team already says this — enforce it in `vault-check`/integration review as a refusal, not a warning).
2. **A2 — patient attacker under the bot's thresholds.** Real and honestly disclosed by the bot itself (drip/sustained alerts). On-chain limits are the only bound; humans decide.
3. **Finding 102 — due tickets settle in a burst.** Queued requests reserve capacity when *asked*, not when paid; several due tickets can land in one clock hour. Documented; consider an explicit per-hour settlement cap if integrators need a hard clock-hour bound.
4. **Rogue-RPC detection suppression.** Requires all endpoints complicit; mitigated by genesis pinning + three cross-checks (F-01 tightens this further).
5. **Oracle risk on the backed lane (T5).** Pyth trust is excluded from the guarantees; a manipulated-but-Full, fresh, tight-confidence price is a backed-lane loan vector bounded only by haircuts and the collateral actually deposited. The freeze-cap rule (finding 90) stops *new* loans during an incident — that mitigation is present in code.

---

## 9. Prioritized recommendations

1. **Now:** F-05 — put the devnet upgrade authorities behind a timelocked multisig (or a Floor quorum) instead of a single team key.
2. **Now:** F-10 — treat guardian liveness as a production SLO: staleness alerts on a channel independent of the guardian bot, multi-operator guardians as a hard launch requirement, and consider the on-chain dead-man switch (auto-tightening when no guardian heartbeats) so liveness loss converts to safety, not to delay-only protection.
3. **Now:** F-01 — one-line owner check on every guardian account read; fail loud on mismatch.
4. **Before any mainnet-adjacent deployment:** make absolute caps mandatory in the integration checklist (refuse `create_vault`/seal tooling on uncapped configs, or default caps on); this closes A1b operationally.
5. **Cheap hardening:** F-11 status-page genesis-hash display + prominent RPC host; F-02/F-03 private-range warnings in `floor_check.py` and the status page.
6. **Watch items:** F-08 (`e_machine` readiness flag at SIMD-0500 activation), F-09 (keep tag-push protected), F-04 (Pyth `write_authority` guidance).
7. **Process:** continue refusing real funds until a human audit; this review, like `docs/16`/`17`, does not substitute for one.

---

## 10. Attack-scope analysis

This section answers the question directly: *for each adversary, what can they actually reach?* Every chain below was traced instruction-by-instruction through the code; "outcome" is the verified end state, not a guess.

### 10.1 Adversary matrix

| Adversary | Entry points | Worst verified outcome | Bounded by |
|---|---|---|---|
| Thief with the **protocol's admin key** (the Drift scenario) | `release` via the protocol's CPI, `freeze`, tightenings, loosen proposals, lifeboat, imports (pre-seal) | Outflow within the on-chain limits (≤ 4 % asked/first hour, ≤ 10 %/day at defaults); anything above queued ≥ 6 h in public, cancellable; instant halt of unbacked lane + indefinite freeze DoS; 72 h-public attempts to loosen/open the lifeboat | Limits, queue delay, guardian vetoes, recovery key, depositors' G2 exits |
| Thief with the protocol's **upgrade key** (malicious new code) | deploys new program code | For a Floor-registered program: **nothing until 72 h public**, any live guardian stops the program in one instruction; a quorum restores the old bytes. For an unregistered program: full malicious code — Floor is opt-in | Floor's delay/veto/stop/restore |
| Thief with **one guardian key** | freeze, veto, stop, cancel tickets, heartbeat | Indefinite freeze/re-freeze + ticket-cancel DoS until a live quorum of the others ejects it; **zero token movement** (no guardian instruction moves tokens — verified per instruction) | Ejection by a live quorum; nothing else |
| Thief with **two guardian keys in a threshold-2 set** (the documented T7 corner) | the above + quorum powers | Unfreeze at will, veto honest tightenings-of-approvals, eject honest guardians one by one down to a rogue-only set, keep a Floor program stopped forever | Set-shape rule (`threshold + 2` margin) at creation; ejection race before count drops to `threshold`; **still zero token movement** |
| **Rogue or dead RPC endpoint(s)** | all guardian reads | Detection suppression or spurious freezes; failed sends; **no signing of attacker-influenced transactions** (all signed ixs are built locally) and no theft | Genesis-hash pinning per endpoint, slot/signature cross-checks, monotonic-counter cross-check; all-endpoints-complicit is required for suppression |
| **Malicious depositor / flash-loan rider** | `deposit` + `release` in one tx | Nothing beyond their own balance leaves backed; base not widened (low-water window sees the pre-deposit balance); flash-loaned capital buys no capacity | G2 soundness precondition, EMA + low-water base, `backed + instant > balance` guard |
| **Malicious Pyth-class oracle** (thin/manipulated feed allowlisted by admin) | backed lane pricing | Over-valued collateral → larger sound-backed loans than honest prices would allow | Haircuts/liability weights, conf/staleness gates, freeze stops *new* loans (finding 90), 72 h public window on the allowlisting itself, oracle risk excluded from G-guarantees (T5) |
| **Malicious Token-2022 issuer** | vault holding their mint | With a refused extension (PermanentDelegate, TransferHook, confidential, NonTransferable, Pausable, close-authority, frozen-default): **cannot be held** — policy refuses at `create_vault`/`upsert_asset`. Fee-bearing: refused in the lifeboat path; fee-on-transfer handled by actual-delta deposit crediting | The extension whitelist (walked extension-type by extension-type) |
| **Griefer with no keys** | permissionless ixs: `settle_ticket` (only of due, unfrozen tickets — pays the ticket's fixed recipient), `execute_change`/`execute_seal` (only of due, unvetoed, unexpired, still-valid proposals), `stage_abort`/`pin_snapshot` (quorum-checked canonical bytes only), `heartbeat` (own slot only), `attest`/`quote` (read-only) | Executing someone's due change slightly early-within-window; nothing else — every permissionless path re-validates the full precondition set | Verified per instruction in §5 |
| **Thief with the *Bulkhead team* key** (pre-audit, F-05) | devnet upgrade authority | Arbitrary Vault/Floor/Harbor code with no timelock — total system compromise *on devnet* | Nothing but disclosure and the audit milestone; see F-05's multisig recommendation |
| **Attacker of the humans** (phishing the status page, F-11) | crafted status-page link | Fake "safe" readings rendered under real ids | RPC-host small print only, today |

### 10.2 Traced attack chains (selected, with verified outcomes)

1. **S8-style one-transaction drain, attacker-sized payouts.** Steal admin → single tx: several `release` calls sized exactly to the remaining bucket. Each release consumes TAT *within* the transaction (the vault account's writes are visible to the next instruction in the same tx), so the sum is still bounded by the dual-bucket conforming set: ≤ ~2 % instant, remainder queued ≥ 6 h. **Outcome: bounded by G1, exactly as claimed.**
2. **Flash-loan base widening.** One tx: borrow 50 M USDC → `deposit` → `release` against the widened balance → repay. `touch_reference` runs *before* each op with the pre-op balance, so the low-water window records the pre-deposit balance; capacity base = min(EMA, live, low-water) never sees the borrowed capital. **Outcome: base unchanged; attack fails** (finding 65's protection, verified in code).
3. **Loan-consent imposition.** Compromised admin orders a release *beyond* a depositor's own balance, trying to mint a "backed" loan against an honest collateral holder's position and drain via the unfreezable lane. `custody.rs:345` caps backing at the owner's own balance unless the owner's key itself signed the transaction — the caller PDA's signature is explicitly not consent. **Outcome: excess goes unbacked → limited and freezable** (findings 74/98).
4. **Freeze-dodging via loans.** During a freeze, backed is capped at `own` (finding 90), so a thief can't pre-load collateral and keep borrowing through the incident; G2 self-exits still work. **Outcome: freeze reaches every lane except owners' own deposits — by design.**
5. **Ticket games.** Early settle (refused: `eta_s`), double settle (impossible: account closed), settle-after-cancel (account closed), settle-to-reassigned-recipient (re-validated against the *current* owner; only vault/protocol-PDA ownership refuses — the recipient was the possibly-compromised admin's choice anyway, and the amount was already rate-limited when queued). Address-reuse confusion in the guardian's cancels: the ticket *id* is re-checked against the account at the address before sending (`WrongTicket`). **Outcome: no new outflow surface.**
6. **Loosening ladder.** Stolen admin proposes bps → 10 000 (100 %/window), floors up, caps off, windows down, queue delay down — every field's unsafe direction is a `Loosen`: ≥ 72 h public, vetoable by any one live guardian, expiring, stale if the target moved, executable only while the proposer still holds the role. With a live guardian: vetoed. With **no** live guardian: it executes after 72 h — **this is F-10, the single most important scope boundary.**
7. **Lifeboat laundering.** Park funds in the lifeboat then exit to a fresh address: exit needs the destination committed ≥ 72 h *before proposal* (a post-proposal swap produces a negative settled-age and is refused), plus ≥ 72 h proposal delay, plus veto, plus the destination key itself must sign, plus no freeze. Returning funds needs only the admin or a quorum. Rent/spill of the abort refund goes to Floor's config, not the stopper (finding 88). **Outcome: the lifeboat is a roundabout 72 h+ public corridor, not an escape hatch.**
8. **Pre-seal hostage-taking.** Depositors' pre-seal deposits cannot be released at all (`NotSealed`), and a malicious pre-seal admin can simply never seal — funds locked. What the admin *cannot* do is reassign depositors' credits: ledger credits are bound to depositor keys, imports are separate public claims, and the seal refuses to execute while `imports + deposits > vault + lifeboat balance`, so over-claiming blocks the seal rather than paying out. **Outcome: pre-seal worst case = DoS (documented), never theft.**
9. **Floor byte-smuggling.** Propose buffer A (public 72 h), swap to buffer B before execution: `pending_target` is an address, B ≠ A fails; a *new* proposal resets id/approvals. Re-freeze the buffer in between: impossible — the buffer's authority is Floor's PDA, and no instruction releases a frozen buffer's authority except `execute_release`, which also destroys the config. Approvals collected for A don't count for B (id-checked). **Outcome: what executes is what was public.**
10. **Stop/restore ping-pong.** One rogue guardian stops a Floor program; honest quorum restores; rogue stops again — repeatable until the rogue is ejected (quorum of others, instant). The owner cannot stop at all while a quorum is live. Abort binaries are exact-byte canonical, so a stop can never install anything but the always-fail ELF. **Outcome: DoS until ejection; no code smuggling.**
11. **Guardian kill-chain via crafted logs.** Attacker emits `Program data:` lines from their own program or a memo: events attribute to the *emitting* program (invoke-stack tracking in `parseLogs`), so foreign events are dropped; unknown layouts are dropped-not-misread (`decodeOrOther`); decode throws are contained per event (finding 139); every regex in the parser is anchored and linear (no ReDoS). A parse failure anywhere else in the loop surfaces as a per-step stall alert, and an uncaught exception exits loudly (`fatal`) under a supervisor restart — while a dead guardian *loses* its on-chain powers until it heartbeats again (fail-closed). **Outcome: no guardian crash-loop or blind-loop found; the cost of killing the bot is the bot's own powers.**
12. **Statefile/persistence attacks.** Torn statefile (fsync + rename + dir fsync), two guardians on one file (pid lock, finding 139), wrong-protocol state (refused loudly), restart forgetfulness (cursors + spent approvals + protocol slot persisted; finding 137's anti-regression slot). **Outcome: restarts degrade latency, not safety.**
13. **Fake Bulkhead deployment against users.** Anyone can deploy a copy of the (open-source) Vault program or register a malicious "protocol" with the *real* Vault and generous config. Depositors who don't verify program ids or read `attest` can be shown a real-looking but attacker-configured system. The on-chain limits still honestly bound *that* vault, but its own admin can loosen them after 72 h with its own guardians never vetoing. **Outcome: Bulkhead hardens an honest protocol; it is not (and cannot be) a depositor-protection primitive against a hostile integrator.** The mitigations are the published ids (SECURITY.md), the status page's unpublished-deployment banners, and `attest` for routers/curators. This is a scope boundary to state in every integration doc.
14. **Multi-release batching in one 4,096-byte tx (SIMD-0296).** More accounts per tx does not help the attacker: each in-tx release sees the previous one's TAT update, so the conforming set is the same bound as sequential releases; the per-tx ticket creations are payer+nonce-addressed and cannot collide. **Outcome: tx-size growth does not widen G1.**
15. **Direct SPL transfers into vault accounts** (bypassing `deposit`): uncredited, and the base lags them via EMA/low-water; to count at full weight the capital must sit through the 24 h EMA — the documented A1b parking attack, bounded only by absolute caps. **Outcome: known residual; make caps mandatory (§9).**
16. **Guardian ejection endgame.** Two rogues in a 2-of-4 set eject honest guardians (each ejection valid: quorum of others, count > threshold) until only rogues remain — full governance control of unfreeze/veto/eject/restore, **and still no instruction that moves a token**. Honest recourse: none on-chain at that point (the set shape rule only guards *new* sets); recovery-key rotation of the admin (72 h) is the remaining path. **Outcome: governance capture = DoS, never theft — the deepest verified property of the whole design.**

### 10.3 The blast-radius summary

Across every adversary: **theft requires either (a) outflow within the configured limits sustained over time with no human response (A2/A1b residuals), (b) a live-guardian vacuum for 72+ hours (F-10), or (c) compromise of Bulkhead's own upgrade key pre-burn (F-05).** Everything else — including total admin compromise, total guardian compromise short of a rogue quorum, rogue RPCs, oracle games, and token-issuer malice — degrades to bounded outflow or denial of service, never silent loss.

### 10.4 Scope boundaries worth stating in the docs verbatim

1. Bulkhead bounds *how fast*, not *whether*: an unresponsive world still loses the limits' worth per window, plus every *due* queued ticket in a burst (finding 102).
2. The 72-hour windows are veto windows, not justice systems: with no live guardian they are simply delays (F-10).
3. Bulkhead hardens honest integrators; it cannot protect depositors from an integrator that registers malicious config on day one (chain 13).
4. A stolen admin can always *halt* (freeze, tighten to zero, close lanes). Availability is explicitly not guaranteed against the admin key — only against everyone else.
5. Floor protects *new code*; a drain through the existing code's admin instructions is Vault's job (the two-tier table, verified).

## 11. Verdict

For a system whose entire purpose is to be the component an attacker cannot turn off, the code reads like it was written by people who assumed every key — including their own — would eventually be stolen. The on-chain programs survived a full hostile trace of every money route; the off-chain guardian cannot be weaponized; the supply chain is unusually clean. The findings above are hardening items and operational posture, not exploitable breaks. The strongest remaining risks are the ones the team has already written down: the pre-audit team key, uncapped bases, the patient attacker, and the burst settlement of due tickets.
