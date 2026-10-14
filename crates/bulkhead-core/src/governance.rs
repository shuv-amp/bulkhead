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
    // Checked: with times far apart (a negative heartbeat, say) the gap
    // overflows i64, and such a guardian is not alive (never a panic).
    (MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval_s)
        && now_s
            .checked_sub(last_heartbeat_s)
            .is_some_and(|gap| (0..=interval_s).contains(&gap))
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

/// Whether a guardian set of `count` keys may use `threshold`: at least two to
/// undo a stop, and fewer than all of them, so the others can always reach a
/// quorum without a rogue and eject it (finding 96: in an n-of-n set nobody
/// can be ejected, so one guardian kept a program stopped for good). A set
/// therefore has at least 3 keys. Both programs check every set with this.
pub fn guardian_set_ok(count: u8, threshold: u8) -> bool {
    count <= 8 && threshold >= MIN_GUARDIAN_THRESHOLD && threshold < count
}

/// Most guardians a set may hold (bitmaps over the set are a `u8`).
pub const MAX_GUARDIANS: usize = 8;

/// A validated guardian set, as an instruction carries it:
/// `[count u8][count × 32 key][threshold u8][interval i64 LE]`. Floor and the
/// Vault both parse every set with `GuardianSet::parse`, so the two can never
/// disagree on what a valid set is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardianSet {
    pub keys: [[u8; 32]; MAX_GUARDIANS],
    pub count: u8,
    pub threshold: u8,
    pub interval_s: i64,
}

/// Why a guardian set was refused; each program maps these to its own errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardianSetError {
    /// Fewer bytes than the set's count says it carries.
    Truncated,
    /// Fewer than two guardians, or more than `MAX_GUARDIANS`.
    BadCount,
    /// A zero key, a forbidden key (the admin or owner, the recovery key), or
    /// a duplicate.
    BadKey,
    /// Not `2 ≤ threshold < count` (`guardian_set_ok`).
    BadThreshold,
    /// A heartbeat interval outside 1–30 days.
    BadInterval,
}

impl GuardianSet {
    /// Whether `key` is one of the set's guardians.
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        guardian_index(&self.keys, self.count, key).is_some()
    }

    /// Encoded length of a set of `count` keys.
    pub const fn encoded_len(count: usize) -> usize {
        1 + 32 * count + 1 + 8
    }

    /// Parses and validates a set at the start of `b`; returns it and the
    /// number of bytes it used. The whole encoding must be present before any
    /// key is judged, so a short payload is always `Truncated`.
    pub fn parse(
        b: &[u8],
        forbidden: [&[u8; 32]; 2],
    ) -> Result<(GuardianSet, usize), GuardianSetError> {
        let count = *b.first().ok_or(GuardianSetError::Truncated)? as usize;
        if !(MIN_GUARDIAN_THRESHOLD as usize..=MAX_GUARDIANS).contains(&count) {
            return Err(GuardianSetError::BadCount);
        }
        let len = Self::encoded_len(count);
        if b.len() < len {
            return Err(GuardianSetError::Truncated);
        }
        let mut keys = [[0u8; 32]; MAX_GUARDIANS];
        for i in 0..count {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b[1 + 32 * i..1 + 32 * i + 32]);
            if k == [0; 32] || forbidden.contains(&&k) || keys[..i].contains(&k) {
                return Err(GuardianSetError::BadKey);
            }
            keys[i] = k;
        }
        let threshold = b[1 + 32 * count];
        if !guardian_set_ok(count as u8, threshold) {
            return Err(GuardianSetError::BadThreshold);
        }
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&b[2 + 32 * count..len]);
        let interval_s = i64::from_le_bytes(iv);
        if !(MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval_s) {
            return Err(GuardianSetError::BadInterval);
        }
        Ok((
            GuardianSet {
                keys,
                count: count as u8,
                threshold,
                interval_s,
            },
            len,
        ))
    }
}

/// Index of `key` among the first `count` guardians (a count above the slots
/// there are reads every slot, as `alive_mask` does).
pub fn guardian_index(keys: &[[u8; 32]], count: u8, key: &[u8; 32]) -> Option<usize> {
    keys.iter().take(count as usize).position(|g| g == key)
}

/// Bitmap of the first `count` guardians that heart-beat within `interval_s`
/// of `now_s`; never a bit for an empty slot.
pub fn alive_mask(heartbeats: &[i64], count: u8, interval_s: i64, now_s: i64) -> u8 {
    let mut mask = 0u8;
    for (i, last) in heartbeats.iter().take(count.min(8) as usize).enumerate() {
        if guardian_alive(*last, interval_s, now_s) {
            mask |= 1 << i;
        }
    }
    mask
}

/// Why a list of signers was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    NotSigner,
    NotGuardian,
}

/// Bitmap of the guardians among `signers` (`(key, is_signer)` pairs, in
/// order). Every entry must sign and be one of the first `count` guardians; a
/// guardian listed twice sets one bit.
pub fn signer_bits<I: IntoIterator<Item = ([u8; 32], bool)>>(
    keys: &[[u8; 32]],
    count: u8,
    signers: I,
) -> Result<u8, SignerError> {
    let mut bits = 0u8;
    for (k, signed) in signers {
        if !signed {
            return Err(SignerError::NotSigner);
        }
        let i = guardian_index(keys, count, &k).ok_or(SignerError::NotGuardian)?;
        bits |= 1 << i;
    }
    Ok(bits)
}

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
/// abdicated, loosening it can never be proposed or executed again. Tightening
/// it still applies at once. Abdicating is irreversible.
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
