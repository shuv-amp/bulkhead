//! Constants that define Bulkhead's guarantees. None of them can be changed by
//! any account at runtime; changing one means deploying a different program.

/// Basis points denominator.
pub const BPS: u128 = 10_000;

/// Time constant of the reference-balance EMA (24 hours).
pub const TAU_S: i64 = 86_400;

/// Saturation for the time cost of a single request, so TAT arithmetic never overflows.
pub const COST_MAX_MS: i64 = 1 << 61;

/// Minimum delay for any loosening change. A proposal can ask for more, never less.
pub const MIN_LOOSEN_DELAY_S: i64 = 259_200;

/// Minimum delay for a Tier 0 program upgrade (same 72 hours, same reason).
pub const MIN_UPGRADE_DELAY_S: i64 = 259_200;

/// Longest loosen delay a protocol can set (30 days). Raising the delay is a
/// tightening and applies at once, so without a bound one key could put every
/// later loosening, admin and guardian replacement included, out of reach
/// (docs/15, A7).
pub const MAX_LOOSEN_DELAY_S: i64 = 2_592_000;

/// Longest upgrade delay Floor accepts, for the same reason (30 days).
pub const MAX_UPGRADE_DELAY_S: i64 = 2_592_000;

/// Longest single freeze a guardian can apply. Guardians may re-freeze.
pub const MAX_FREEZE_S: i64 = 86_400;

/// Longest a guardian can extend one ticket per call, and in total.
pub const MAX_TICKET_EXTENSION_S: i64 = 86_400;
pub const MAX_TICKET_TOTAL_EXTENSION_S: i64 = 604_800;

/// Unbacked requests whose ETA would be further out than this are rejected.
pub const QUEUE_HORIZON_S: i64 = 604_800;

/// Positions per owner in the shadow ledger.
pub const MAX_SLOTS: usize = 8;

/// Value unit is 1e-18 USD.
pub const VALUE_DECIMALS: i32 = 18;

/// ELF machine ids accepted by the Solana loaders.
pub const EM_BPF: u16 = 0xF7;
pub const EM_SBPF: u16 = 0x107;
