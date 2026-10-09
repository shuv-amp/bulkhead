# 16. Pre-audit engagement report (9 Oct 2026)

**What this is.** This is an internal engagement run the way an audit firm runs one. Six reviewers each took one scope; none had worked on the code before. Each one researched public vulnerability checklists and real post-mortems first, then reviewed line by line, and proved each finding with a test against the real runtime (LiteSVM, the Agave loader, the mainnet feature set). The audited commit is `9aae0c4`; the fixes follow in the commit that adds this file.

**What this is not.** It is not an independent audit. The reviewers are AI agents, they share blind spots with the people who wrote the code, and they cannot vouch for anything. Mainnet funds need at least one audit by a named, independent firm. This report is meant to make that audit faster and its findings fewer: it lists what was checked, what was found, what changed, and what is left to decide.

## 1. Scope and method

| Reviewer | Scope | Method |
|---|---|---|
| Vault custody | `custody.rs`, `brakes.rs`, `token.rs`, `state.rs`, the core ledger, limiter and EMA | Invariants (solvency, G1, G2, ticket accounting, ledger soundness), then account substitution, aliasing, ordering within a transaction, arithmetic edges, Token-2022 behaviour |
| Vault governance | `governance.rs`, `genesis.rs`, `lifeboat.rs`; the core governance and classification | Every role, every way a role's power can change, every state machine (change, seal, exit, recovery), attacked with a stolen admin, a stolen recovery key, a rogue minority and a lost key |
| Floor | `programs/floor`, the core floor rules | Checked against the current Agave loader source (4.2.2 as LiteSVM bundles it, 4.3.0, master) and the feature-gate state read from mainnet, devnet and testnet |
| Oracle, tokens, math | `pyth.rs`, `token.rs`, the core math, the Python reference | Checked against Pyth's and Token-2022's current documentation and sources; adversarial math (`diff_runner.py`, `extreme_diff.py`) |
| Vulnerability classes | All on-chain code (Vault tags 0–29, Floor 0–13, Harbor 0–3) | 39 classes from Sealevel attacks, Neodyme, Sec3, Helius, Trail of Bits and Pinocchio guidance, swept across all 48 handlers; clippy with cast and indexing lints |
| Economics and design | The guarantees, against real incidents | Mango, Cashio, Wormhole, Crema, Nirvana, Solend, Loopscale, Cetus, Euler, Bybit and Drift (April 2026): would Bulkhead have stopped each one, bounded it, or not helped? |

## 2. Results

No finding allows a theft without a key. Every proven issue needed a key compromise, an admin mistake, a runtime change or an integration mistake. Each one is fixed, or stated with the reason it is not.

| Severity | Found | Fixed | Stated / to decide |
|---|---|---|---|
| High | 1 code + 3 design | 1 | 3 (§4) |
| Medium | 7 | 6 | 1 |
| Low | 9 | 6 | 3 |
| Informational | 12 | 2 | 10 |

| ID | Severity | Finding | Status |
|---|---|---|---|
| 88a | High | Before the seal, a stolen admin key swaps the guardians, proposes the seal (which locks the recovery key out), then seals and parks the vault in one transaction | Fixed: the lifeboat opens a loosen delay after the seal; the recovery key's `SetAdmin` applies during a seal review and ends it |
| 88b | Medium | A stolen admin key closes a vault for good by tightening an abdicated kind to the extreme | Fixed: tightening an abdicated kind takes a live guardian quorum |
| 88c | Low | Oracle settings unbounded (price of any age, no margin, confidence as wide as the price, zero feed) | Fixed: bounded in `consts.rs` |
| 88d | Medium | Floor: a snapshot shorter than its ELF passes identity but is not redeployable; pinned by anyone, it takes the quorum's restore away (pre-v3 programs) | Fixed: `elf_extent` |
| 88e | Low/Medium | Floor: the staged abort binary cannot be replaced, so a runtime change breaking it breaks every stop | Fixed: a live quorum replaces it |
| 88f | Low (Medium after SIMD-0433) | Floor: the stop's spill is chosen by whoever stops; with SIMD-0433 it would receive the programdata's excess rent | Fixed: the spill is the config |
| 87a | Low | A replaced admin's queued loosenings still execute | Fixed: only the current admin's or recovery key's changes execute |
| 87b | Low | More than 10 vaults can never seal | Fixed: at most 10 before the seal |
| 87c | Low | Harbor's REGISTER is first-come | Stated, with the remedy (`07` §2) |
| 89 | Low | A payout to an account the protocol PDA owns | Fixed; an account another Vault PDA owns is stated |
| AUD-2 | Medium | A lost guardian key plus a rogue guardian lock a 2-of-3 set's governance | To decide (§4) |
| E1–E3 | High (design) | The backed lane has no brake; loan consent is any signature in the transaction; liquidations queue in a crash | To decide (§4) |
| E4–E8 | Medium–Low | Patient drain and the bot's allowlist; queue griefing; optional caps; instant lifeboat move after the window | Stated (`09`, finding 89); §4 |
| Others | Info | Freezes do not stop `execute_change` or `execute_exit` (vetoes do); role overlaps the destination may have; re-proposals clear vetoes; delegate deposits; the second Pyth receiver; SIMD-0500 and release to none | Stated in `09` 87–89 |

The prior fixes in each scope were re-checked and hold: findings 56, 63, 65, 66, 67, 68, 72, 74, 75, 78 and 85. Two did not hold: 79 and 85 covered `execute_exit` but not `release` and `settle` (finding 89), and 86 was incomplete (finding 88a).

## 3. External assumptions, checked against current reality

| Assumption | Current reality | Status |
|---|---|---|
| Loader-v3: CPI only for Upgrade, SetAuthority(Checked), Close; one upgrade per slot; `ExtendProgram` needs no authority | Agave `program-runtime/src/cpi.rs` and `bpf_loader`; SIMD-0431 active on mainnet (slot 432,864,000) | OK; finding 77 stands |
| `Upgrade` keeps the programdata size | SIMD-0433 (`loader_v3_set_program_data_to_elf_length`) is in Agave master and absent on every cluster as of 9 Oct; it shrinks programdata on every upgrade | At risk: a pre-extension must be redone after each install; 88f fixed the spill |
| SIMD-0500 | Expected with Agave 4.4 (November 2026); refuses pre-v3 deploys and `SetAuthority` to none for them | Disclosed (`06` §5, `09` 88) |
| Runtime-enforced frozen buffers | SIMD discussion #588 would let programs CPI `Write`; then only Floor's own code keeps buffers frozen (it never writes) | Watch |
| PriceUpdateV2 layout, Full verification only, receiver `rec5EKMG…` | Pyth's sources and published address list | OK |
| Receiver `rec2HHDD…` | Not on Pyth's published list; same upgrade authority as `rec5EKMG…` on-chain | Watch (finding 89) |
| Token-2022 extensions 0–28; only metadata and group extensions can be added after creation; PermissionedBurn is a co-signer | The token-2022 interface source and Solana's documentation | OK |

## 4. Decisions for the team (before a lending integration)

1. **A brake on the backed lane (E1). Done (finding 90):** a guardian's freeze now stops new loans; own deposits still leave. What remains: a loan against allowlisted collateral is bounded by haircuts and Pyth until the first freeze. Options: a rate limit on new backed liabilities per mint, using the same dual bucket; a guardian freeze of new backed liabilities (own-deposit returns stay free, so G2 is unchanged); bot alerts on backed-borrow spikes. Recommended: the second, plus the alerts.
2. **Loan consent (E2).** Today any signature of the owner in the transaction consents. A compromised protocol program gets that signature in any ordinary transaction. Options: Floor required alongside the Vault (cheap; it does not cover a bug in honest code); an explicit consent the program cannot forge, such as an Ed25519-signed intent with amount and nonce, or a top-level Vault instruction checked by introspection. Recommended: require Floor now, and design the explicit consent before a lending integration.
3. **Liquidations in a crash (E3).** The unbacked part of a liquidation queues behind the limiter (6h by default), and liquidators paid late stop liquidating. Options: a liquidation lane valued at spot, or its own bucket; and a replay of real Pyth history at program level as a launch gate.
4. **Guardian liveness (AUD-2).** With 2 of 3 guardians, one lost key plus one rogue guardian lock governance for good. Options: require `count ≥ threshold + 2` in production (3-of-5 with independent operators); ignore a guardian's veto of a change that only replaces dead or ejected guardians; a freeze budget per guardian. Recommended: the operational rule now, and a protocol change after the audit. **Done for the rule:** `07` §6 states it, and the guardian warns about a smaller set (an alert on mainnet).
5. **Caps (E6) and the bot's allowlist (E4).** Caps should be required at the seal, or `attest` and the status page should show "uncapped". **Done for the display:** the status page shows UNCAPPED, the guardian alerts once for each uncapped vault it watches, and `vault-check` requires devnet's caps; requiring them at the seal is still to decide. The bot's allowlist should be a budget per owner, not an exemption.
6. **Queue share (E5).** A limit per owner on reserved queue capacity, so one owner's tickets cannot fill the queue.

## 5. Launch recommendation

The reviewers' verdict matches `README`'s caution. The unbacked-lane mathematics is well verified, and the custody, pricing and Floor code held up against every class checked. The economic perimeter around it (§4) is not finished. A guarded mainnet launch is reasonable with all of these:
- an independent audit;
- Floor alongside every Vault;
- caps set;
- at least 3-of-5 independent guardians with the operations checklist (`07` §6);
- the pre-seal checklist (`07` §2);
- staged TVL caps;
- integrators that do not lend first (treasuries, vaults with non-transferable shares).

Lending integrators wait for §4.1 to §4.3.

## 6. Sources

- Solana and loader: github.com/anza-xyz/agave (`programs/bpf_loader`, `program-runtime/src/cpi.rs`, `feature-set`), the v4.3.0 release notes, solana.com/upgrades/sbpfv3-programs, SIMD discussion #588.
- Pyth: docs.pyth.network (contract addresses, best practices, EMA aggregation), pyth-crosschain `price_update.rs`.
- Token-2022: github.com/solana-program/token-2022 (`interface/src/extension/mod.rs`), the Solana token extension documentation (permissioned burn).
- Vulnerability classes: coral-xyz/sealevel-attacks, Neodyme "Solana smart contracts: common pitfalls", Sec3 X-ray, Helius program security guide, trailofbits/solana-lints, anza-xyz/pinocchio.
- Incidents: Halborn, Hypernative, BleepingComputer and QuillAudits on Drift (April 2026); Halborn, Blockworks and The Block on Loopscale (April 2025); CertiK and Ackee on Mango; Ackee on Crema and Solend; Dedaub on Cetus; Decrypt and Fortune on the Solend whale (June 2022); The Block on the 10 Oct 2025 crash.
- Governance: L2BEAT Stages and the Stage 1 Security Council requirements; Optimism's Stage 1 spec; the Beanstalk post-mortems.
