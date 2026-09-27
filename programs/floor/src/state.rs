//! `FloorConfig`: one account per protected program, PDA `["floor", program]`.
//!
//! Stored as a fixed little-endian byte layout (no framework, no unsafe casts).
//! `load` copies it into a plain struct; `store` writes it back. The layout is
//! versioned by its 8-byte discriminator.

use crate::error::FloorError;
use pinocchio::error::ProgramError;

pub const DISCRIMINATOR: [u8; 8] = *b"FLOORv01";
pub const MAX_GUARDIANS: usize = 8;
/// Largest proposal payload (a full guardian set: 1 + 8·32 + 1 + 8).
pub const MAX_PAYLOAD: usize = 266;

pub const STATUS_LIVE: u8 = 0;
pub const STATUS_ABORTED: u8 = 1;

/// Proposal kinds. Each waits the upgrade delay and any live guardian can veto.
pub mod kind {
    pub const NONE: u8 = 0;
    /// Install new code while live. Target: a Floor-owned buffer.
    pub const UPGRADE: u8 = 1;
    /// Install a fix while aborted. Target: a Floor-owned buffer. A live
    /// guardian quorum that approves this exact buffer may execute it at once.
    pub const RESTORE: u8 = 2;
    /// Hand the upgrade authority to `target` and close Floor for this program.
    pub const RELEASE_AUTHORITY: u8 = 3;
    /// Replace guardians, threshold and heartbeat interval (payload).
    pub const SET_GUARDIANS: u8 = 4;
    /// Replace the owner. Target: the new owner.
    pub const SET_OWNER: u8 = 5;
    /// Lower the upgrade delay (payload: i64). Raising it is instant.
    pub const SET_DELAY: u8 = 6;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub program: [u8; 32],
    pub programdata: [u8; 32],
    pub owner: [u8; 32],
    pub guardians: [[u8; 32]; MAX_GUARDIANS],
    pub last_heartbeat: [i64; MAX_GUARDIANS],
    pub guardian_count: u8,
    pub threshold: u8,
    pub status: u8,
    /// Live code is sBPF v3 (deployable after SIMD-0500). Updated on every install.
    pub elf_is_v3: u8,
    pub config_bump: u8,
    pub authority_bump: u8,
    /// The pinned snapshot was verified byte-identical to the code that was live
    /// at the moment of the abort.
    pub snapshot_valid: u8,
    pub heartbeat_interval_s: i64,
    pub upgrade_delay_s: i64,
    /// Pre-staged canonical abort buffer (zero = none).
    pub abort_buffer: [u8; 32],
    /// Pinned snapshot buffer (zero = none).
    pub snapshot_buffer: [u8; 32],
    pub aborted_at: i64,
    pub pending_kind: u8,
    pub pending_vetoed: u8,
    pub pending_approvals: u8,
    pub pending_id: u64,
    pub pending_target: [u8; 32],
    pub pending_eta: i64,
    pub pending_expires: i64,
    pub pending_payload_len: u16,
    pub pending_payload: [u8; MAX_PAYLOAD],
}

// Byte offsets.
const O_DISC: usize = 0;
const O_PROGRAM: usize = 8;
const O_PROGRAMDATA: usize = 40;
const O_OWNER: usize = 72;
const O_GUARDIANS: usize = 104; // 8 × 32
const O_HEARTBEATS: usize = 360; // 8 × 8
const O_COUNT: usize = 424;
const O_THRESHOLD: usize = 425;
const O_STATUS: usize = 426;
const O_V3: usize = 427;
const O_CONFIG_BUMP: usize = 428;
const O_AUTH_BUMP: usize = 429;
const O_SNAP_VALID: usize = 430;
const O_INTERVAL: usize = 432;
const O_DELAY: usize = 440;
const O_ABORT_BUF: usize = 448;
const O_SNAP_BUF: usize = 480;
const O_ABORTED_AT: usize = 512;
const O_P_KIND: usize = 520;
const O_P_VETOED: usize = 521;
const O_P_APPROVALS: usize = 522;
const O_P_ID: usize = 528;
const O_P_TARGET: usize = 536;
const O_P_ETA: usize = 568;
const O_P_EXPIRES: usize = 576;
const O_P_LEN: usize = 584;
const O_P_PAYLOAD: usize = 586;
/// Total size, with room reserved for later fields.
pub const LEN: usize = O_P_PAYLOAD + MAX_PAYLOAD + 64;
const _: () = assert!(O_P_PAYLOAD + MAX_PAYLOAD <= LEN && O_P_LEN + 2 == O_P_PAYLOAD);

fn k32(d: &[u8], o: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&d[o..o + 32]);
    k
}
fn i64_at(d: &[u8], o: usize) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    i64::from_le_bytes(b)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    i64_at(d, o) as u64
}

impl Config {
    pub fn load(d: &[u8]) -> Result<Config, ProgramError> {
        if d.len() != LEN || d[O_DISC..O_DISC + 8] != DISCRIMINATOR {
            return Err(FloorError::NotAFloorConfig.into());
        }
        let mut guardians = [[0u8; 32]; MAX_GUARDIANS];
        let mut last_heartbeat = [0i64; MAX_GUARDIANS];
        for i in 0..MAX_GUARDIANS {
            guardians[i] = k32(d, O_GUARDIANS + 32 * i);
            last_heartbeat[i] = i64_at(d, O_HEARTBEATS + 8 * i);
        }
        let mut pending_payload = [0u8; MAX_PAYLOAD];
        pending_payload.copy_from_slice(&d[O_P_PAYLOAD..O_P_PAYLOAD + MAX_PAYLOAD]);
        let len = u16::from_le_bytes([d[O_P_LEN], d[O_P_LEN + 1]]);
        let c = Config {
            program: k32(d, O_PROGRAM),
            programdata: k32(d, O_PROGRAMDATA),
            owner: k32(d, O_OWNER),
            guardians,
            last_heartbeat,
            guardian_count: d[O_COUNT],
            threshold: d[O_THRESHOLD],
            status: d[O_STATUS],
            elf_is_v3: d[O_V3],
            config_bump: d[O_CONFIG_BUMP],
            authority_bump: d[O_AUTH_BUMP],
            snapshot_valid: d[O_SNAP_VALID],
            heartbeat_interval_s: i64_at(d, O_INTERVAL),
            upgrade_delay_s: i64_at(d, O_DELAY),
            abort_buffer: k32(d, O_ABORT_BUF),
            snapshot_buffer: k32(d, O_SNAP_BUF),
            aborted_at: i64_at(d, O_ABORTED_AT),
            pending_kind: d[O_P_KIND],
            pending_vetoed: d[O_P_VETOED],
            pending_approvals: d[O_P_APPROVALS],
            pending_id: u64_at(d, O_P_ID),
            pending_target: k32(d, O_P_TARGET),
            pending_eta: i64_at(d, O_P_ETA),
            pending_expires: i64_at(d, O_P_EXPIRES),
            pending_payload_len: len,
            pending_payload,
        };
        if c.guardian_count as usize > MAX_GUARDIANS || len as usize > MAX_PAYLOAD {
            return Err(FloorError::NotAFloorConfig.into());
        }
        Ok(c)
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        if d.len() != LEN {
            return Err(FloorError::NotAFloorConfig.into());
        }
        d[O_DISC..O_DISC + 8].copy_from_slice(&DISCRIMINATOR);
        d[O_PROGRAM..O_PROGRAM + 32].copy_from_slice(&self.program);
        d[O_PROGRAMDATA..O_PROGRAMDATA + 32].copy_from_slice(&self.programdata);
        d[O_OWNER..O_OWNER + 32].copy_from_slice(&self.owner);
        for i in 0..MAX_GUARDIANS {
            d[O_GUARDIANS + 32 * i..O_GUARDIANS + 32 * i + 32].copy_from_slice(&self.guardians[i]);
            d[O_HEARTBEATS + 8 * i..O_HEARTBEATS + 8 * i + 8]
                .copy_from_slice(&self.last_heartbeat[i].to_le_bytes());
        }
        d[O_COUNT] = self.guardian_count;
        d[O_THRESHOLD] = self.threshold;
        d[O_STATUS] = self.status;
        d[O_V3] = self.elf_is_v3;
        d[O_CONFIG_BUMP] = self.config_bump;
        d[O_AUTH_BUMP] = self.authority_bump;
        d[O_SNAP_VALID] = self.snapshot_valid;
        d[O_INTERVAL..O_INTERVAL + 8].copy_from_slice(&self.heartbeat_interval_s.to_le_bytes());
        d[O_DELAY..O_DELAY + 8].copy_from_slice(&self.upgrade_delay_s.to_le_bytes());
        d[O_ABORT_BUF..O_ABORT_BUF + 32].copy_from_slice(&self.abort_buffer);
        d[O_SNAP_BUF..O_SNAP_BUF + 32].copy_from_slice(&self.snapshot_buffer);
        d[O_ABORTED_AT..O_ABORTED_AT + 8].copy_from_slice(&self.aborted_at.to_le_bytes());
        d[O_P_KIND] = self.pending_kind;
        d[O_P_VETOED] = self.pending_vetoed;
        d[O_P_APPROVALS] = self.pending_approvals;
        d[O_P_ID..O_P_ID + 8].copy_from_slice(&self.pending_id.to_le_bytes());
        d[O_P_TARGET..O_P_TARGET + 32].copy_from_slice(&self.pending_target);
        d[O_P_ETA..O_P_ETA + 8].copy_from_slice(&self.pending_eta.to_le_bytes());
        d[O_P_EXPIRES..O_P_EXPIRES + 8].copy_from_slice(&self.pending_expires.to_le_bytes());
        d[O_P_LEN..O_P_LEN + 2].copy_from_slice(&self.pending_payload_len.to_le_bytes());
        d[O_P_PAYLOAD..O_P_PAYLOAD + MAX_PAYLOAD].copy_from_slice(&self.pending_payload);
        Ok(())
    }

    /// Index of `key` among the current guardians.
    pub fn guardian_index(&self, key: &[u8; 32]) -> Option<usize> {
        self.guardians[..self.guardian_count as usize]
            .iter()
            .position(|g| g == key)
    }

    /// Bitmap of guardians that heart-beat within the interval (current slots only).
    pub fn alive_mask(&self, now_s: i64) -> u8 {
        let mut mask = 0u8;
        for i in 0..self.guardian_count as usize {
            if bulkhead_core::governance::guardian_alive(
                self.last_heartbeat[i],
                self.heartbeat_interval_s,
                now_s,
            ) {
                mask |= 1 << i;
            }
        }
        mask
    }

    pub fn clear_pending(&mut self) {
        self.pending_kind = kind::NONE;
        self.pending_vetoed = 0;
        self.pending_approvals = 0;
        self.pending_target = [0; 32];
        self.pending_eta = 0;
        self.pending_expires = 0;
        self.pending_payload_len = 0;
        self.pending_payload = [0; MAX_PAYLOAD];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_round_trips_and_fits() {
        let mut c = Config {
            program: [1; 32],
            programdata: [2; 32],
            owner: [3; 32],
            guardians: [[4; 32]; MAX_GUARDIANS],
            last_heartbeat: [5; MAX_GUARDIANS],
            guardian_count: 3,
            threshold: 2,
            status: STATUS_ABORTED,
            elf_is_v3: 1,
            config_bump: 254,
            authority_bump: 253,
            snapshot_valid: 1,
            heartbeat_interval_s: 604_800,
            upgrade_delay_s: 259_200,
            abort_buffer: [6; 32],
            snapshot_buffer: [7; 32],
            aborted_at: 99,
            pending_kind: kind::RESTORE,
            pending_vetoed: 1,
            pending_approvals: 0b101,
            pending_id: 42,
            pending_target: [8; 32],
            pending_eta: 1_000,
            pending_expires: 2_000,
            pending_payload_len: 3,
            pending_payload: [9; MAX_PAYLOAD],
        };
        c.guardians[1] = [10; 32];
        let mut buf = [0u8; LEN];
        c.store(&mut buf).unwrap();
        assert_eq!(Config::load(&buf).unwrap(), c);
        buf[0] ^= 1;
        assert!(Config::load(&buf).is_err());
    }
}
