//! Governance timing rules (G4, G5): when a change may execute, how long a
//! freeze lasts, which guardians are alive, and what an abdication forbids.
//!
//! Prior art these rules follow (see docs/14-STATE-OF-THE-ART.md):
//! - Tighten now, loosen after the current delay: MetaMorpho vaults.
//! - Guardian liveness heartbeats; a guardian who stops heart-beating loses
//!   its powers: Lido CircuitBreaker.
//! - Abdication (permanently giving up a power): Morpho Vaults V2.
//! - Guardians may freeze, only a quorum may unfreeze: Aave's 2026 steward
//!   design ("freeze markets, not unfreeze them").

use crate::classify::Class;
use crate::consts::{MAX_FREEZE_S, MIN_LOOSEN_DELAY_S};

/// A loosening that became executable must execute within this window or expire
/// (limits the life of pre-signed transactions; see the Drift durable-nonce vector).
pub const CHANGE_EXPIRY_S: i64 = 604_800;
/// Guardian heartbeat interval bounds (Lido CircuitBreaker pattern).
pub const MIN_HEARTBEAT_INTERVAL_S: i64 = 86_400;
pub const MAX_HEARTBEAT_INTERVAL_S: i64 = 30 * 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub executable_s: i64,
    pub expires_s: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovError {
    NotYetExecutable,
    Vetoed,
    Expired,
    AlreadyExecuted,
    Abdicated,
    InvalidDuration,
}

impl GovError {
    pub fn code(&self) -> &'static str {
        match self {
            GovError::NotYetExecutable => "NotYetExecutable",
            GovError::Vetoed => "Vetoed",
            GovError::Expired => "Expired",
            GovError::AlreadyExecuted => "AlreadyExecuted",
            GovError::Abdicated => "Abdicated",
            GovError::InvalidDuration => "InvalidDuration",
        }
    }
}

/// When a proposed change becomes executable. A tightening executes now; a
/// loosening waits `max(protocol_delay, MIN_LOOSEN_DELAY_S)`. Both expire
/// `CHANGE_EXPIRY_S` after becoming executable.
pub fn schedule(now_s: i64, class: Class, protocol_delay_s: i64) -> Schedule {
    let delay = match class {
        Class::Tighten => 0,
        Class::Loosen => protocol_delay_s.max(MIN_LOOSEN_DELAY_S),
    };
    let executable_s = now_s + delay;
    Schedule {
        executable_s,
        expires_s: executable_s + CHANGE_EXPIRY_S,
    }
}

/// Whether a scheduled change may execute now.
pub fn can_execute(
    s: &Schedule,
    now_s: i64,
    vetoed: bool,
    executed: bool,
    abdicated: bool,
) -> Result<(), GovError> {
    if abdicated {
        return Err(GovError::Abdicated);
    }
    if executed {
        return Err(GovError::AlreadyExecuted);
    }
    if vetoed {
        return Err(GovError::Vetoed);
    }
    if now_s < s.executable_s {
        return Err(GovError::NotYetExecutable);
    }
    if now_s >= s.expires_s {
        return Err(GovError::Expired);
    }
    Ok(())
}

/// New `frozen_until` after a guardian freezes for `secs` (1..=MAX_FREEZE_S).
/// A freeze only ever extends, never shortens, an existing freeze.
pub fn freeze_until(current_frozen_until: i64, now_s: i64, secs: i64) -> Result<i64, GovError> {
    if secs <= 0 || secs > MAX_FREEZE_S {
        return Err(GovError::InvalidDuration);
    }
    Ok(current_frozen_until.max(now_s + secs))
}

/// A guardian is alive if it heart-beat within its interval. Dead guardians
/// cannot freeze, veto, approve or abort; reviving one is a loosening (72h).
pub fn guardian_alive(last_heartbeat_s: i64, interval_s: i64, now_s: i64) -> bool {
    (MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval_s)
        && now_s >= last_heartbeat_s
        && now_s - last_heartbeat_s <= interval_s
}

/// Quorum over live guardians only: `approvals` and `alive` are bitmaps over
/// the guardian list (≤ 8 guardians); a threshold of 0 is never a quorum.
/// Callers must set bits only for slots that hold a guardian (the programs
/// build both bitmaps from the guardian list). `can_eject` masks by count
/// itself; its property test found that an unmasked bitmap over-counts.
pub fn quorum(approvals: u8, alive: u8, threshold: u8) -> bool {
    threshold > 0 && (approvals & alive).count_ones() >= threshold as u32
}

/// Minimum guardian threshold. One key alone can stop things, never undo a
/// stop: unfreeze, restore and eject always need at least two live guardians.
pub const MIN_GUARDIAN_THRESHOLD: u8 = 2;

/// Whether a live quorum of the *other* guardians may eject guardian `target`
/// immediately (the L2BEAT Security Council model: any single guardian may
/// stop, a quorum may always undo a minority). Without this, one malicious
/// guardian could veto its own removal forever and keep re-freezing (or, under
/// Floor, keep re-aborting after every restore).
///
/// Rules: `target` is a current guardian; its own approval never counts; the
/// quorum is over live guardians; after ejection at least `threshold`
/// guardians remain, so a quorum stays reachable. Bitmaps are over the
/// guardian list (≤ 8); bits at or above `count` are ignored, since no
/// guardian sits in those slots.
pub fn can_eject(approvals: u8, alive: u8, threshold: u8, target: u8, count: u8) -> bool {
    if target >= count || count > 8 {
        return false;
    }
    let members = ((1u16 << count) - 1) as u8;
    let others = approvals & members & !(1u8 << target);
    threshold >= MIN_GUARDIAN_THRESHOLD && count > threshold && quorum(others, alive, threshold)
}

/// Abdication bitmap over change kinds (Morpho V2 pattern): once a kind is
/// abdicated it can never be proposed or executed again. Abdicating is always
/// a tightening and is itself irreversible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Abdications(pub u32);

impl Abdications {
    pub fn is_abdicated(&self, kind: u8) -> bool {
        kind < 32 && self.0 & (1u32 << kind) != 0
    }
    /// Returns the new bitmap; never clears a bit.
    pub fn abdicate(&self, kind: u8) -> Abdications {
        if kind >= 32 {
            return *self;
        }
        Abdications(self.0 | (1u32 << kind))
    }
}
