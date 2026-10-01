# Security

**Status: unaudited. Not deployed to mainnet. Do not protect real funds with this code.**

## What exists and how it is checked

| Component | State | Checked by |
|---|---|---|
| `bulkhead-core` (the math) | Built | An independent Python reference with a differential runner, golden vectors, property tests, exhaustive checks, 13 Kani harnesses, mutation testing (`docs/09-VERIFICATION.md`) |
| Programs: Floor, Vault, and Harbor (a demo protocol) | Built for sBPF v3 | LiteSVM on the real agave runtime and loader (scenarios, negative tests, compute), a program-vs-model differential, and an end-to-end run on a local validator |
| Bulkhead Cloud (guardian bot, status page, client) | Built | Unit tests, a JavaScript-vs-Python differential, the end-to-end run |
| Devnet deployment | Deployed 28 Sep 2026; Vault upgraded in place 29 Sep (below) | Those binaries match commit `422bd1f`. This tree's A7–A13 fixes change the program bytes and are not on devnet until the next in-place upgrade, so `scripts/verify-deployed.sh` against devnet fails until then |

None of this is an audit. The mainnet path:
1. two independent audits (a Solana specialist, and a formal-methods review of the core);
2. prover rules for the programs;
3. verifiable builds;
4. a public bug bounty;
5. a TVL-capped first partner;
6. then burning the upgrade authorities (`docs/09-VERIFICATION.md §8`).

## Devnet deployment

Devnet only; test tokens only. The upgrade authority of all three programs is a **team-held key**:
`71tqq65ovwE4akm8T5UhfkGE1fJ7qBx5wid11Z5GbHBP`. It can replace the code of any of them. On mainnet it would be burned after audit (G9).

| Program | Devnet id | sha256 of the deployed code (Agave v4.3.0, platform-tools v1.57, sBPF v3) |
|---|---|---|
| Floor | `HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E` | `ef2b349b77473643e942afe23e190e7a3ae0e9eda2636d78c58c3b719c324dba` |
| Vault | `HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b` | `79b0a47ff3086fe2389e5ac089560f530a7d4089fcd5d12814a30132a62d9c93` (upgraded in place 29 Sep; until then `466cc17beb71ebb1f342cec5bc6ac10c333b58e7d537d675fd57bc3a6eca22eb`) |
| Harbor (demo) | `6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh` | `d91a8ac28a3d2bffe07de80f20028a09a1f15c8e7639e5551250c9b54cb712f2` |

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

- A compromised admin can tighten limits instantly, including closing the unbacked lane. That is denial of service. Owners taking back their own deposits are unaffected.
- A malicious guardian can freeze, cancel, extend, veto or stop the program. That is denial of service, never theft. It lasts until a live quorum of the other guardians ejects that guardian, which takes effect instantly.
- G2 bounds only what Bulkhead does to an owner taking back their own deposit. Whether the tokens are actually in the vault depends on the pool's liquidity (`docs/03-MECHANISM.md §4.6`).
- Receipt tokens transferred to a new holder carry no backing. Their redemptions use the rate-limited lane.
- A Floor stop takes effect in the next slot at the earliest, because new code becomes visible only from the next slot.
- Once SIMD-0500 is active, a Floor stop of a pre-v3 program can only be undone with an sBPF v3 build.
- Mint gates and flash loans are specified (`docs/03-MECHANISM.md §4.8`) but not built.
