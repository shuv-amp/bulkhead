//! Bulkhead core: the math that decides how fast value may leave a protected vault.
//!
//! Everything here is pure and deterministic. The on-chain program, the
//! differential worker and the tests all call this crate; nothing re-implements it.
//! An independent Python model (`reference/bulkhead_ref.py`) must agree with it
//! on every input, which `reference/diff_runner.py` checks.
//!
//! Modules:
//! - [`limiter`]: two GCRA buckets (hourly burst, daily cap) with FIFO tickets.
//! - [`ema`]: the slow-moving reference balance capacities are computed from.
//! - [`value`] and [`price`]: exact integer valuation at conservative prices.
//! - [`ledger`]: the per-owner shadow ledger that decides the backed amount.
//! - [`classify`]: whether a config change tightens (instant) or loosens (delayed).
//! - [`governance`]: when changes execute, freezes, guardian liveness, quorum, abdication.
//! - [`floor`]: Tier 0 helpers (ELF version check for SIMD-0500, upgrade timing).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod classify;
pub mod consts;
pub mod ema;
pub mod floor;
pub mod governance;
pub mod ledger;
pub mod limiter;
pub mod math;
pub mod price;
pub mod value;

#[cfg(kani)]
mod proofs;
