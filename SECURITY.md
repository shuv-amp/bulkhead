# Security

**Status: unaudited. Not deployed to mainnet. Do not protect real funds with this code.**

## What exists and how it is checked

| Component | State | Checked by |
|---|---|---|
| `bulkhead-core` (the math) | Built | An independent Python reference with a differential runner, golden vectors, property tests, exhaustive checks, 15 Kani harnesses, mutation testing (`docs/09-VERIFICATION.md`) |
| Programs: Floor, Vault, and Harbor (a demo protocol) | Built for sBPF v3 | LiteSVM on the real agave runtime and loader (scenarios, negative tests, compute), a program-vs-model differential, and an end-to-end run on a local validator |
| Bulkhead Cloud (guardian bot, status page, client) | Built | Unit tests, a JavaScript-vs-Python differential, the end-to-end run |
| Devnet deployment | Deployed 28 Sep 2026; upgraded in place 29 Sep, 6 Oct, 7 Oct, twice on 8 Oct and five times on 9 Oct (below) | All three programs run the canonical build (Linux x86_64; CI publishes it) of PR #61 (Harbor unchanged since PR #35), matched byte for byte with the upgrade authority checked |

None of this is an audit. The mainnet path:
1. two independent audits (a Solana specialist, and a formal-methods review of the core);
2. prover rules for the programs;
3. verifiable builds;
4. a public bug bounty;
5. a TVL-capped first partner;
6. then burning the upgrade authorities (`docs/09-VERIFICATION.md §9`).

## Devnet deployment

Devnet only; test tokens only. The upgrade authority of all three programs is a **team-held key**:
`71tqq65ovwE4akm8T5UhfkGE1fJ7qBx5wid11Z5GbHBP`. It can replace the code of any of them. On mainnet it would be burned after audit (G9).

| Program | Devnet id | sha256 of the deployed code (Agave v4.3.0, platform-tools v1.57, sBPF v3) |
|---|---|---|
| Floor | `HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E` | `505688c7d2be2330c761a343f33691fb8057fdc26d182093a1ece0a2e98b12b0` (upgraded in place 9 Oct, PR #61: a snapshot at least the live ELF's declared length, a quorum may replace the abort binary, the stop's spill is the config, `09` finding 88; earlier on 9 Oct `58159d04deaa89b3476eed9143765cb704c6f0e72e9ba3b844912aa607bd9cbe`, PR #57: `close_buffer` never closes a buffer identical to the live code while the program runs, `09` finding 85; earlier on 9 Oct `e06a86e79fae1246b5fd7432cf59b535c75312337fdefae2b3962f8e43a0b9c9`, PR #52, after extending its program data by 10,240 bytes: `close_buffer` returns orphaned buffers' rent, a release closes the abort buffer and the pin and needs the new authority's signature, `09` findings 78 and 80; earlier on 8 Oct `ff8bda423405722fede5786083be0e67a42128e98193ad743681df711c64dfde`, PR #35: a stop accepts any snapshot identical to the live code, finding 66; no key both guardian and recovery key; a delay raise passes a recovery proposal; a cut-off recovery key is refused, findings 63 and 70; earlier on 8 Oct `913b2eca965e7fb8b5ef50a8ff9b137422fb7fc4a20e713e54af689dafa0c05b`: `replace_recovery`, a dead recovery proposal frees the slot, no key both guardian and recovery key, `09` finding 62; 7 Oct to 8 Oct `ef013d0109c6a8dba26489b36872e24b38f2fc039e0d49a5ec819efc2df45e01`, the first version of that change; until then `d04e4b555a3b6ef7f7cb945db66323f92965e20fff00adbab2c9b3f675d115bc`, after it was upgraded in place 7 Oct twice: to `3639b131071f92a54e4649bc11c01fe2729309d040f783ceb1fa66d6ad051dfa`, a stop must name the pinned snapshot, `09` finding 53; then to this, findings 57 and 58; 6 Oct to 7 Oct `844f46784b5831bea63b7d775dc43ad28a9044a588416f0ae9f002eca901f623`; until then `ef2b349b77473643e942afe23e190e7a3ae0e9eda2636d78c58c3b719c324dba`) |
| Vault | `HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b` | `e1493007c3e24d045c9681f5d058d01452682ca7d851169e96b093b25df23562` (upgraded in place 9 Oct, PR #61: the lifeboat opens a loosen delay after the seal, the recovery key ends a seal review, abdicated tightenings need a quorum, bounded oracle settings, a replaced admin's queue never executes, at most 10 vaults before the seal, `09` findings 87–89; earlier on 9 Oct `9ec83cc928ccdfcb063615940c211e39ccc2cab33d6d76325e6d16328abacdd8`, PR #59: the lifeboat opens with the seal, `09` finding 86; earlier on 9 Oct `8cf8d1633345f78b60bc0132a903e595206588a35f46fcdd48a9d64812a33f24`, PR #57: the lifeboat exit's destination signs, `09` finding 85; earlier on 9 Oct `ecf2c2260ffda4902d4fd387dcf6489ff681e8fc330aa7d869ffc02e8555c177`, PR #52: a lifeboat exit never pays an account this program owns, `09` finding 79; earlier on 9 Oct `cb1971efcfaee5b815b091cc68fa21fa20fe9a66049a11df4fbb42b4ba2a4b97`, PR #49: a backed loan needs the borrower's signature, finding 74; settle reports a short vault and the reference clock never steps back, 75; earlier on 8 Oct `b53ce331aef9bfc6bf746002390f9df74968972a11f18e3d261ad307a8ec033b`, PR #35, after extending its program data by 10,240 bytes: the low-water base, finding 65; events name their protocol, 64; ticket ids, 67; rescaling mints never priced, 68; lifeboat, seal and admin edges, 72; and findings 63 and 70; earlier on 8 Oct `067434af00cc949e17e3d8a6dae397fae9be6a7594dd7d47ee5d614e94877382`: `replace_recovery`, which obeys the seal review and abdication, and no key both guardian and recovery key, `09` finding 62; 7 Oct to 8 Oct `3173b14ab6856e76c499f2104c781a6d058a00e1ee803be8da0260f3e5ed659b`, the first version of that change; until then `aba7e697fa1fb6bb171c657bd913e6c8062bd1889df477851864e7b15e3d67c3`, after it was upgraded in place 7 Oct: delisted collateral stays locked while its loan is open, `09` finding 56, critical, and finding 57; 6 Oct to 7 Oct `c73b058de016ff05adf8b7a36d97beac47d3f970f429af1be0dff34bc3b2cdae`, after it was upgraded in place 6 Oct three times: to `e1961181e062cc6641da9940354cab7cea8f22809d89fe76b97708d26ff2592c`; to `b8a2fbf89cac8012e141e9262fc4fe539e501c260aac000630b37411658921c5`, whose token-account and mint readers are split into pure functions so the fuzzers test the code the program runs; then to this, the same source built on Linux x86_64, the canonical build host (`09`, finding 43); 29 Sep to 6 Oct `79b0a47ff3086fe2389e5ac089560f530a7d4089fcd5d12814a30132a62d9c93`; until 29 Sep `466cc17beb71ebb1f342cec5bc6ac10c333b58e7d537d675fd57bc3a6eca22eb`) |
| Harbor (demo) | `6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh` | `543be60b25b557ea0a58f0c4d2133f67954172006d2a21490217cb4010adeb40` (upgraded in place 6 Oct; until then `d91a8ac28a3d2bffe07de80f20028a09a1f15c8e7639e5551250c9b54cb712f2`) |

`scripts/verify-deployed.sh` matched all three byte for byte on 9 Oct, against CI's binaries of PR #61 (Floor and Vault upgraded that day), with `EXPECT_AUTHORITY` set to the team key. Release binaries are Linux x86_64 builds: CI's (each pull request's `programs` artifact, with `SHA256SUMS`), or `scripts/build-programs-docker.sh` on any machine with Docker. A build on macOS has the same instructions in another order, so its Vault hash differs.

The demo market's admin and guardian keys are also team-held. On devnet that is the point: S1 plays the attacker with the admin key.

## Reporting a vulnerability

Please report privately. Do not open a public issue. Email the maintainer listed on the GitHub profile of `shuv-amp`. We will acknowledge within 72 hours and credit you unless you prefer otherwise.

## Responsible disclosure by us

While building Floor, we found an interaction in the Solana runtime that affects **every upgrade-based emergency stop**. That includes a team's own emergency patch, a bare abort binary, and Floor's stop.
- The delay it can cause is bounded.
- It is not specific to Bulkhead.
- Vault's in-path limits don't depend on any stop.

We reported it privately, and it has been acknowledged. We will publish the details and Floor's mitigations once a fix ships, or earlier if the maintainers agree.

## Known limitations (by design; `docs/04-THREAT-MODEL.md`)

- A compromised admin can tighten limits instantly, including closing the unbacked lane. That is denial of service. Owners taking back their own deposits are unaffected, unless the admin parks the vault in the lifeboat: a guardian quorum returns it, and a freeze stops the admin parking it again (`docs/04-THREAT-MODEL.md` T1).
- **A compromised Vault admin or Floor owner key** (`docs/15-ADVERSARIAL-REVIEW.md` A4): the optional recovery key proposes its replacement, which the compromised key cannot cancel; after the seal it executes after the loosen delay unless a guardian vetoes it. A compromised recovery key is replaced at once by the admin (or owner) with a live guardian quorum (`replace_recovery`). Residual: the denial of service above lasts until that replacement executes (at least 72h), and a protocol registered without a recovery key has no such path. It is still never theft.
- The guardian bot bounds a greedy attacker within seconds, not a patient one: an attacker who keeps every window under its thresholds is bounded only by the on-chain limits (A2).
- In a fast crash, the default limits can queue honest liquidations for 6 hours (`docs/08-SCENARIOS.md` S11). Lending markets must size their limits for a cascade, which also raises what a thief can take.
- A malicious guardian can freeze, cancel, extend, veto or stop the program. That is denial of service, never theft. It lasts until a live quorum of the other guardians ejects that guardian, which takes effect instantly.
- G2 bounds only what Bulkhead does to an owner taking back their own deposit. Whether the tokens are actually in the vault depends on the pool's liquidity (`docs/03-MECHANISM.md §4.6`).
- Receipt tokens transferred to a new holder carry no backing. Their redemptions use the rate-limited lane.
- A Floor stop takes effect in the next slot at the earliest, because new code becomes visible only from the next slot.
- Anyone, holding no key, can delay a Floor stop: loader-v3's `ExtendProgram` is permissionless on mainnet and devnet, and an `Upgrade` (a stop is one) is refused in a slot where the program was extended. An attacker who lands an extension ahead of the stop in every slot holds it off until the program reaches the loader's 10 MiB maximum: for a 200 KB program about 1,000 slots (~7 minutes) and ~53 SOL of rent (SIMD-0431 makes each extension at least 10,240 bytes). Pre-extending the protected program to the maximum removes this (`docs/06-FLOOR.md` §6; `docs/09`, finding 77).
- Once SIMD-0500 is active, a Floor stop of a pre-v3 program can only be undone with an sBPF v3 build.
- Mint gates and flash loans are specified (`docs/03-MECHANISM.md §4.8`) but not built.
- Immutable means unpatchable. After the upgrade authorities are burned (G9), a bug in Bulkhead cannot be fixed in place: the upgrade path is a new deployment, and funds move to it through each protocol's lifeboat exit (at least 72h, to a destination committed 72h earlier). Until the burn, the team key above can replace the code of every protected vault, which is why it is disclosed and why the burn is step 6 of the mainnet path.
