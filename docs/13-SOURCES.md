# 13 — Sources

Accessed 26–27 Sep 2026 unless noted. Re-check any figure before putting it on a slide.

## Drift incident
- Chainalysis, "Lessons from the Drift hack": https://www.chainalysis.com/blog/lessons-from-the-drift-hack/
- BlockSec, multisig governance compromise via durable nonces: https://blocksec.com/blog/drift-protocol-incident-multisig-governance-compromise-via-durable-nonce-exploitation
- Halborn, "Explained: The Drift Hack (April 2026)": https://www.halborn.com/blog/post/explained-the-drift-hack-april-2026
- Bitcoin.com, timeline incl. 27 Mar timelock removal: https://news.bitcoin.com/drift-protocol-hack-2026-what-happened-who-lost-money-and-whats-next/
- Drift, Incident Recovery Update (16 Apr 2026): https://www.drift.trade/updates/incident-recovery-update-april-16-2026-now
- Drift protocol-v2 source, commit `13e8e9b` (23 Jun 2026), `programs/drift/src/instructions/admin.rs` (`handle_update_withdraw_guard_threshold`, `AdminUpdateSpotMarket`), read 27 Sep 2026: https://github.com/drift-labs/protocol-v2
- TRM Labs attribution (search result): https://www.trmlabs.com/resources/blog/north-korean-hackers-attack-drift-protocol-in-285-million-heist

## Incident statistics
- Zhou, Xiong, Ernstberger, Chaliasos, Wang, Wang, Qin, Wattenhofer, Song, Gervais. "SoK: Decentralized Finance (DeFi) Attacks." IEEE S&P 2023. arXiv 2208.13035v3: https://arxiv.org/abs/2208.13035 (Table VI; §V-A)
- Chainalysis, 2024 private key compromise share (search result): https://www.chainalysis.com/blog/crypto-hacking-stolen-funds-2025/
- STRIDE first findings (June 2026): https://stride.asymmetric.re/first-findings

## Solana protocol changes
- SIMD-0500, Disable deployment of SBPF v0/v1/v2: https://github.com/solana-foundation/solana-improvement-documents/pull/500
- QEDGen readiness issue (SIMD-0500 planned for Agave v4.4): https://github.com/QEDGen/solana-skills/issues/426 · tracking https://github.com/QEDGen/solana-skills/issues/430
- Agave releases: https://github.com/anza-xyz/agave/releases
- Anza, migrating to SBPFv3: https://www.anza.xyz/blog/migrating-solana-programs-to-sbpfv3
- Larger transactions (SIMD-0296, 4,096 bytes, 15 Sep 2026): https://solana.com/upgrades/larger-transaction-sizes

## Runtime, loader and toolchain (source read 26–27 Sep 2026; used in `05`, `06`, `01 §5`)
- agave, master `f771659` (26 Sep 2026): https://github.com/anza-xyz/agave
  - `program-runtime/src/cpi.rs`, `check_authorized_program`: the loader-v3 instructions a program may invoke by CPI
  - `programs/bpf_loader/src/lib.rs`: `Upgrade` (copy the buffer, zero-fill the rest; once per slot), `SetAuthority`, `Close`
  - `syscalls/src/lib.rs`: `max_sbpf_version` is V3
  - `feature-set/src/lib.rs`: feature ids for `disable_sbpf_v0_v1_v2_deployment` (SIMD-0500, `B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g`), sBPF v3 deployment and the abandoned loader-v4 (`LoaderV4WasAbandoned11111111111111111111111`)
- Activation slots: `getAccountInfo` on each feature account, public mainnet and devnet RPC, 26–27 Sep 2026
- solana-sbpf, `933e358` (24 Sep 2026): https://github.com/anza-xyz/sbpf
  - `src/elf.rs`: `get_sbpf_version` and the strict v3 ELF parser (SIMD-0189)
  - `src/ebpf.rs`: `hash_symbol_name` (murmur3, seed 0) for syscall ids
- Loader-v3 account layouts: `solana-loader-v3-interface` 8.0.1 (`state.rs`), https://github.com/anza-xyz/solana-sdk
- Agave CLI v4.3.0 (cargo-build-sbf `--arch v3`, platform-tools v1.57, solana-test-validator): https://github.com/anza-xyz/agave/releases · installer https://release.anza.xyz/v4.3.0/install
- Pinocchio 0.11.2 (the on-chain framework): https://github.com/anza-xyz/pinocchio
- LiteSVM 0.16.0 (program tests): https://github.com/LiteSVM/litesvm
- Pyth `PriceUpdateV2` layout: https://github.com/pyth-network/pyth-crosschain, `target_chains/solana/pyth_solana_receiver_sdk/src/price_update.rs`
- Token-2022 `ExtensionType` numbering: https://github.com/solana-program/token-2022
- Dean Little, sbpf-asm-abort, commit `fa0727d` (10 Sep 2026); our read of its `deploy/sbpf-asm-abort.so` header: https://github.com/deanmlittle/sbpf-asm-abort
- Project 0 (marginfi v2), commit `35b5c66` (16 Sep 2026), read 27 Sep; paths in `01 §9`: https://github.com/0dotxyz/marginfi-v2
- RFC 8032 (Ed25519; test vector 1 in `cloud/test`): https://www.rfc-editor.org/rfc/rfc8032
- curve25519-dalek (behind `solana-address`'s on-curve check, used to generate `tools/testdata/curve25519_vectors.json`): https://github.com/dalek-cryptography/curve25519-dalek

## Governance census
- solgov (Colosseum Frontier) API: https://api.solgov.xyz/api/state · https://github.com/EdgeVault/solgov · snapshot `evidence/solgov_state_2026-09-26.json.gz`
- solana-upgrade-watch (on-chain spot checks): https://github.com/simonvellin/solana-upgrade-watch

## Market
- DefiLlama API: https://api.llama.fi/v2/chains · https://api.llama.fi/protocols · https://stablecoins.llama.fi/stablecoinchains

## Prior art and adjacent tools
- Dean Little, sbpf-asm-abort (pattern credited; no license, not copied): https://github.com/deanmlittle/sbpf-asm-abort
- Spark ALM Controller: https://github.com/sparkdotfi/spark-alm-controller · https://docs.spark.fi/dev/spark-liquidity-layer/spark-alm-controller
- Wormhole Governor whitepaper: https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0007_governor.md
- Squads v5: https://squads.xyz/blog/squads-protocol-v5 · spending limits https://docs.squads.so/main/development/reference/spending-limits
- EIP-7265: https://ethereum-magicians.org/t/eip-7265-circuit-breaker-standard/14909
- Phylax Credible Layer: https://github.com/phylaxsystems/credible-layer-whitepaper
- Hypernative on Solana: https://www.hypernative.io/blog/solana-network-and-projects-building-on-it-are-now-secured-by-hypernative
- Solana ecosystem security (Range, Hypernative, Riverguard): https://solana.com/news/solana-ecosystem-security
- Sentinel: https://github.com/hand1111/sentinel · Holdfast: https://github.com/Yonkoo11/holdfast
- solana-asm/shield: https://github.com/solana-asm/shield
- svmscope: https://svmscope.vercel.app/watch
- QEDGen: https://github.com/QEDGen/solana-skills

## Colosseum
- Crypto World's Fair: https://colosseum.com/worldsfair
- Colosseum Frontier (6 Apr – 11 May 2026): https://blog.colosseum.com/announcing-the-solana-frontier-hackathon/

## Founder record
- SP-Differ: https://github.com/shuv-amp/sp-differ
- BIP-352 test vector crediting @shuv-amp (merged 17 Apr 2026): https://github.com/bitcoin/bips/pull/2142
- Bitcoin Core PRs merged 24 Aug 2026: https://github.com/bitcoin/bitcoin/pull/34697 · https://github.com/bitcoin/bitcoin/pull/36025

## State of the art (docs/14, researched 26 Sep 2026)
- Wormhole NTT Solana rate limiter (source read): https://github.com/wormhole-foundation/native-token-transfers/blob/main/solana/programs/example-native-token-transfers/src/queue/rate_limit.rs · docs https://wormhole.com/docs/products/token-transfers/native-token-transfers/configuration/rate-limiting/
- Chainlink CCIP rate limits: https://docs.chain.link/ccip/concepts/rate-limit-management/how-rate-limits-work
- ERC-7281 (xERC20): https://ethereum-magicians.org/t/erc-7281-sovereign-bridged-tokens/14979
- Kamino klend withdrawal caps (source read): https://github.com/Kamino-Finance/klend/blob/master/programs/klend/src/lending_market/withdrawal_cap_operations.rs
- MetaMorpho timelocks: https://docs.morpho.org/curate/concepts/timelock/ · https://github.com/morpho-org/metamorpho
- Aave Risk Stewards: https://github.com/aave-dao/aave-v3-risk-stewards · https://github.com/aave-dao/aave-v4-risk-stewards
- Maker DC-IAM (auto-line): https://github.com/makerdao/dss-auto-line
- Zodiac Roles v2 allowances: https://docs.roles.gnosisguild.org/general/allowances
- Lido GateSeal (archived): https://github.com/lidofinance/gate-seals · CircuitBreaker: https://github.com/lidofinance/circuit-breaker
- Lido Dual Governance: https://github.com/lidofinance/dual-governance/blob/develop/docs/mechanism.md
- L2BEAT Stages: https://l2beat.com/stages · Security Council requirements (search summary): https://medium.com/l2beat/stages-update-security-council-requirements-4c79cea8ef52
- Le Boudec & Thiran, Network Calculus (tutorial): https://leboudec.github.io/netcal/resources/NetCalTutSigmetrics2002v6.pdf
- RFC 2212 (IntServ Guaranteed Service, T-SPEC): https://datatracker.ietf.org/doc/html/rfc2212 · ITU-T I.371: https://www.itu.int/rec/T-REC-I.371-200403-I/en
- Chainlink on rate limits and bridge hacks (search result): https://x.com/chainlink/status/1773034006939881664
- Kani Rust Verifier: https://github.com/model-checking/kani · paper (ASE '26): https://arxiv.org/abs/2607.01504
- cargo-mutants: https://mutants.rs/
- Certora Solana Prover / CVLR: https://docs.certora.com/en/latest/docs/solana/index.html · https://github.com/Certora/cvlr-solana · Squads v4 verification: https://squads.xyz/blog/certora-formal-verification-squads-protocol-v4
- Trident: https://github.com/Ackee-Blockchain/trident
- Firedancer differential conformance: https://github.com/firedancer-io/solfuzz-agave · https://github.com/firedancer-io/test-vectors
- SpecTrum (spec-guided differential fuzzing, 2026): https://arxiv.org/pdf/2608.17738
- sealevel-attacks: https://github.com/coral-xyz/sealevel-attacks
- Pyth best practices (confidence intervals): https://docs.pyth.network/price-feeds/core/best-practices
- STRIDE framework (40 controls): https://stride.asymmetric.re/framework
- Colosseum Frontier winners: https://blog.colosseum.com/announcing-the-winners-of-the-solana-frontier-hackathon/
