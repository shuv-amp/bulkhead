//! Account layouts. Each is a fixed little-endian record with an 8-byte
//! discriminator, read and written field by field (no unsafe casts), in the
//! order listed. PDAs are in `lib.rs` (`seeds` module).

use crate::error::VaultError;
use bulkhead_core::classify::{AssetConfig, LimitConfig};
use bulkhead_core::consts::MAX_SLOTS;
use pinocchio::error::ProgramError;

pub const MAX_GUARDIANS: usize = 8;
pub const MAX_PAYLOAD: usize = 300;

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

pub struct R<'a> {
    d: &'a [u8],
    o: usize,
}

impl<'a> R<'a> {
    pub fn new(d: &'a [u8], disc: &[u8; 8], len: usize) -> Result<R<'a>, ProgramError> {
        if d.len() != len || d[..8] != *disc {
            return Err(VaultError::WrongAccountType.into());
        }
        Ok(R { d, o: 8 })
    }
    pub fn args(d: &'a [u8]) -> R<'a> {
        R { d, o: 0 }
    }
    /// Whether every byte has been read.
    pub fn is_empty(&self) -> bool {
        self.o >= self.d.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let s = self
            .d
            .get(self.o..self.o + n)
            .ok_or(VaultError::InvalidInstruction)?;
        self.o += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool, ProgramError> {
        Ok(self.u8()? != 0)
    }
    pub fn u16(&mut self) -> Result<u16, ProgramError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64, ProgramError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u128(&mut self) -> Result<u128, ProgramError> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn i128(&mut self) -> Result<i128, ProgramError> {
        Ok(i128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn key(&mut self) -> Result<[u8; 32], ProgramError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.d[self.o.min(self.d.len())..];
        self.o = self.d.len();
        s
    }
    pub fn limits(&mut self) -> Result<LimitConfig, ProgramError> {
        Ok(LimitConfig {
            short_bps: self.u16()?,
            short_window_s: self.u32()?,
            long_bps: self.u16()?,
            long_window_s: self.u32()?,
            min_queue_delay_s: self.u32()?,
            short_floor: self.u64()?,
            long_floor: self.u64()?,
            short_cap: self.u64()?,
            long_cap: self.u64()?,
        })
    }
    pub fn asset_config(&mut self) -> Result<AssetConfig, ProgramError> {
        Ok(AssetConfig {
            allowlisted: self.bool()?,
            haircut_bps: self.u32()?,
            liability_bps: self.u32()?,
            conf_mult_bps: self.u32()?,
            max_age_s: self.u32()?,
            max_conf_bps: self.u32()?,
            feed_id: self.key()?,
        })
    }
}

pub struct W<'a> {
    d: &'a mut [u8],
    o: usize,
}

impl<'a> W<'a> {
    pub fn new(d: &'a mut [u8], disc: &[u8; 8], len: usize) -> Result<W<'a>, ProgramError> {
        if d.len() != len {
            return Err(VaultError::WrongAccountType.into());
        }
        d[..8].copy_from_slice(disc);
        Ok(W { d, o: 8 })
    }
    fn put(&mut self, b: &[u8]) {
        self.d[self.o..self.o + b.len()].copy_from_slice(b);
        self.o += b.len();
    }
    pub fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    pub fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }
    pub fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.put(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.put(&v.to_le_bytes());
    }
    pub fn u128(&mut self, v: u128) {
        self.put(&v.to_le_bytes());
    }
    pub fn i128(&mut self, v: i128) {
        self.put(&v.to_le_bytes());
    }
    pub fn key(&mut self, v: &[u8; 32]) {
        self.put(v);
    }
    pub fn zeros(&mut self, n: usize) {
        for _ in 0..n {
            self.u8(0);
        }
    }
    pub fn limits(&mut self, c: &LimitConfig) {
        self.u16(c.short_bps);
        self.u32(c.short_window_s);
        self.u16(c.long_bps);
        self.u32(c.long_window_s);
        self.u32(c.min_queue_delay_s);
        self.u64(c.short_floor);
        self.u64(c.long_floor);
        self.u64(c.short_cap);
        self.u64(c.long_cap);
    }
    pub fn asset_config(&mut self, c: &AssetConfig) {
        self.bool(c.allowlisted);
        self.u32(c.haircut_bps);
        self.u32(c.liability_bps);
        self.u32(c.conf_mult_bps);
        self.u32(c.max_age_s);
        self.u32(c.max_conf_bps);
        self.key(&c.feed_id);
    }
}

pub const LIMITS_LEN: usize = 2 + 4 + 2 + 4 + 4 + 8 * 4;
pub const ASSET_CONFIG_LEN: usize = 1 + 4 * 5 + 32;

// ---------------------------------------------------------------------------
// Protocol: ["protocol", protocol_program]
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol {
    pub protocol_program: [u8; 32],
    /// The protocol's signer PDA `["bulkhead-caller"]` under its own program id.
    pub caller: [u8; 32],
    pub admin: [u8; 32],
    pub guardians: [[u8; 32]; MAX_GUARDIANS],
    pub last_heartbeat: [i64; MAX_GUARDIANS],
    pub guardian_count: u8,
    pub threshold: u8,
    pub sealed: bool,
    pub bump: u8,
    pub heartbeat_interval_s: i64,
    pub loosen_delay_s: i64,
    pub frozen_until: i64,
    pub abdications: u32,
    pub vault_count: u32,
    pub next_ticket_id: u64,
    pub next_change_id: u64,
    pub lifeboat_destination: [u8; 32],
    /// When the current lifeboat destination took effect.
    pub destination_set_s: i64,
    pub seal_executable_s: i64,
    pub seal_expires_s: i64,
    pub seal_vetoed: bool,
    /// One counter per protocol-level change kind (guardians, admin,
    /// destination, delay, recovery), bumped whenever that value changes. A
    /// pending change records it and goes stale if it moved. In the old padding.
    pub versions: [u32; 5],
    /// The recovery key (all zero: none). It may only propose a new admin or
    /// a new recovery key; each waits the delay, any guardian can veto it, and
    /// the admin cannot cancel it (docs/15, A4). The admin with a live guardian
    /// quorum replaces it at once (`replace_recovery`). In the old padding.
    pub recovery: [u8; 32],
    /// When the seal executed (0: before finding 88, or not sealed). The
    /// lifeboat opens a loosen delay after it. In the old padding.
    pub sealed_at: i64,
}

impl Protocol {
    pub const DISC: [u8; 8] = *b"BHPROTv1";
    pub const LEN: usize = 8
        + 32 * 3
        + 32 * MAX_GUARDIANS
        + 8 * MAX_GUARDIANS
        + 4
        + 8 * 3
        + 4 * 2
        + 8 * 2
        + 32
        + 8 * 3
        + 1
        + 64;

    pub fn load(d: &[u8]) -> Result<Protocol, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        let protocol_program = r.key()?;
        let caller = r.key()?;
        let admin = r.key()?;
        let mut guardians = [[0u8; 32]; MAX_GUARDIANS];
        for g in guardians.iter_mut() {
            *g = r.key()?;
        }
        let mut last_heartbeat = [0i64; MAX_GUARDIANS];
        for h in last_heartbeat.iter_mut() {
            *h = r.i64()?;
        }
        let p = Protocol {
            protocol_program,
            caller,
            admin,
            guardians,
            last_heartbeat,
            guardian_count: r.u8()?,
            threshold: r.u8()?,
            sealed: r.bool()?,
            bump: r.u8()?,
            heartbeat_interval_s: r.i64()?,
            loosen_delay_s: r.i64()?,
            frozen_until: r.i64()?,
            abdications: r.u32()?,
            vault_count: r.u32()?,
            next_ticket_id: r.u64()?,
            next_change_id: r.u64()?,
            lifeboat_destination: r.key()?,
            destination_set_s: r.i64()?,
            seal_executable_s: r.i64()?,
            seal_expires_s: r.i64()?,
            seal_vetoed: r.bool()?,
            versions: [r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?],
            recovery: r.key()?,
            sealed_at: r.i64()?,
        };
        if p.guardian_count as usize > MAX_GUARDIANS {
            return Err(VaultError::WrongAccountType.into());
        }
        Ok(p)
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol_program);
        w.key(&self.caller);
        w.key(&self.admin);
        for g in &self.guardians {
            w.key(g);
        }
        for h in &self.last_heartbeat {
            w.i64(*h);
        }
        w.u8(self.guardian_count);
        w.u8(self.threshold);
        w.bool(self.sealed);
        w.u8(self.bump);
        w.i64(self.heartbeat_interval_s);
        w.i64(self.loosen_delay_s);
        w.i64(self.frozen_until);
        w.u32(self.abdications);
        w.u32(self.vault_count);
        w.u64(self.next_ticket_id);
        w.u64(self.next_change_id);
        w.key(&self.lifeboat_destination);
        w.i64(self.destination_set_s);
        w.i64(self.seal_executable_s);
        w.i64(self.seal_expires_s);
        w.bool(self.seal_vetoed);
        for v in self.versions {
            w.u32(v);
        }
        w.key(&self.recovery);
        w.i64(self.sealed_at);
        Ok(())
    }

    pub fn guardian_index(&self, key: &[u8; 32]) -> Option<usize> {
        self.guardians[..self.guardian_count as usize]
            .iter()
            .position(|g| g == key)
    }

    /// Bitmap of live guardians; bits only for occupied slots.
    pub fn alive_mask(&self, now_s: i64) -> u8 {
        let mut m = 0u8;
        for i in 0..self.guardian_count as usize {
            if bulkhead_core::governance::guardian_alive(
                self.last_heartbeat[i],
                self.heartbeat_interval_s,
                now_s,
            ) {
                m |= 1 << i;
            }
        }
        m
    }
}

// ---------------------------------------------------------------------------
// Vault: ["vault", protocol, mint]; its token account: ["vault-tokens", protocol, mint]
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub protocol: [u8; 32],
    pub mint: [u8; 32],
    pub token_program: [u8; 32],
    pub token_account: [u8; 32],
    pub limits: LimitConfig,
    pub tat_short_ms: i64,
    pub tat_long_ms: i64,
    pub ref_balance: u64,
    pub ref_updated_s: i64,
    pub ref_initialized: bool,
    pub decimals: u8,
    pub bump: u8,
    pub token_bump: u8,
    pub pending_tickets: u32,
    pub queued_amount: u64,
    pub frozen_until: i64,
    /// Backing imported at genesis (must be covered by the balance at seal).
    pub imported: u64,
    pub total_in: u128,
    pub backed_out: u128,
    pub unbacked_out: u128,
    pub settled: u128,
    pub cancelled: u128,
    /// Tokens currently parked in the lifeboat (a separate Bulkhead-held account).
    pub lifeboat_amount: u64,
    pub exit_amount: u64,
    /// When the pending exit was proposed (the destination must predate it by 72h).
    pub exit_proposed_s: i64,
    pub exit_executable_s: i64,
    pub exit_expires_s: i64,
    pub exit_vetoed: bool,
    /// Bumped whenever `limits` change; see `Protocol::versions`.
    pub limits_version: u32,
    /// Low-water balance over the last one to two windows (finding 65). In
    /// the reserved tail: an account written before reads zeros, which the
    /// first touch replaces (its window is long past).
    pub low: bulkhead_core::ema::WindowLow,
    /// Who proposed the pending exit (the admin then). It executes only while
    /// that key is still the admin, like a change (issue #66). In the reserved
    /// tail: an exit proposed by an older build reads zeros and must be
    /// proposed again.
    pub exit_proposer: [u8; 32],
}

impl Vault {
    pub const DISC: [u8; 8] = *b"BHVAULT1";
    pub const LEN: usize =
        8 + 32 * 4 + LIMITS_LEN + 8 * 4 + 1 + 1 + 1 + 1 + 4 + 8 * 3 + 16 * 5 + 8 * 5 + 1 + 64;

    pub fn load(d: &[u8]) -> Result<Vault, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        Ok(Vault {
            protocol: r.key()?,
            mint: r.key()?,
            token_program: r.key()?,
            token_account: r.key()?,
            limits: r.limits()?,
            tat_short_ms: r.i64()?,
            tat_long_ms: r.i64()?,
            ref_balance: r.u64()?,
            ref_updated_s: r.i64()?,
            ref_initialized: r.bool()?,
            decimals: r.u8()?,
            bump: r.u8()?,
            token_bump: r.u8()?,
            pending_tickets: r.u32()?,
            queued_amount: r.u64()?,
            frozen_until: r.i64()?,
            imported: r.u64()?,
            total_in: r.u128()?,
            backed_out: r.u128()?,
            unbacked_out: r.u128()?,
            settled: r.u128()?,
            cancelled: r.u128()?,
            lifeboat_amount: r.u64()?,
            exit_amount: r.u64()?,
            exit_proposed_s: r.i64()?,
            exit_executable_s: r.i64()?,
            exit_expires_s: r.i64()?,
            exit_vetoed: r.bool()?,
            limits_version: r.u32()?,
            low: bulkhead_core::ema::WindowLow {
                prev: r.u64()?,
                cur: r.u64()?,
                window: r.i64()?,
            },
            exit_proposer: r.key()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol);
        w.key(&self.mint);
        w.key(&self.token_program);
        w.key(&self.token_account);
        w.limits(&self.limits);
        w.i64(self.tat_short_ms);
        w.i64(self.tat_long_ms);
        w.u64(self.ref_balance);
        w.i64(self.ref_updated_s);
        w.bool(self.ref_initialized);
        w.u8(self.decimals);
        w.u8(self.bump);
        w.u8(self.token_bump);
        w.u32(self.pending_tickets);
        w.u64(self.queued_amount);
        w.i64(self.frozen_until);
        w.u64(self.imported);
        w.u128(self.total_in);
        w.u128(self.backed_out);
        w.u128(self.unbacked_out);
        w.u128(self.settled);
        w.u128(self.cancelled);
        w.u64(self.lifeboat_amount);
        w.u64(self.exit_amount);
        w.i64(self.exit_proposed_s);
        w.i64(self.exit_executable_s);
        w.i64(self.exit_expires_s);
        w.bool(self.exit_vetoed);
        w.u32(self.limits_version);
        w.u64(self.low.prev);
        w.u64(self.low.cur);
        w.i64(self.low.window);
        w.key(&self.exit_proposer);
        Ok(())
    }

    pub fn limiter_state(&self) -> bulkhead_core::limiter::LimiterState {
        bulkhead_core::limiter::LimiterState {
            tat_short_ms: self.tat_short_ms,
            tat_long_ms: self.tat_long_ms,
        }
    }

    pub fn set_limiter_state(&mut self, s: bulkhead_core::limiter::LimiterState) {
        self.tat_short_ms = s.tat_short_ms;
        self.tat_long_ms = s.tat_long_ms;
    }
}

// ---------------------------------------------------------------------------
// Asset: ["asset", protocol, mint]
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub protocol: [u8; 32],
    pub mint: [u8; 32],
    pub config: AssetConfig,
    pub decimals: u8,
    pub bump: u8,
    /// Bumped whenever `config` changes; see `Protocol::versions`.
    pub version: u32,
}

impl Asset {
    pub const DISC: [u8; 8] = *b"BHASSET1";
    pub const LEN: usize = 8 + 64 + ASSET_CONFIG_LEN + 2 + 32;

    pub fn load(d: &[u8]) -> Result<Asset, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        Ok(Asset {
            protocol: r.key()?,
            mint: r.key()?,
            config: r.asset_config()?,
            decimals: r.u8()?,
            bump: r.u8()?,
            version: r.u32()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol);
        w.key(&self.mint);
        w.asset_config(&self.config);
        w.u8(self.decimals);
        w.u8(self.bump);
        w.u32(self.version);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Backing: ["backing", protocol, owner]; the owner's shadow ledger
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backing {
    pub protocol: [u8; 32],
    pub owner: [u8; 32],
    pub bump: u8,
    pub positions: [([u8; 32], i128); MAX_SLOTS],
}

impl Backing {
    pub const DISC: [u8; 8] = *b"BHBACKG1";
    pub const LEN: usize = 8 + 64 + 1 + 48 * MAX_SLOTS + 7;

    pub fn load(d: &[u8]) -> Result<Backing, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        let protocol = r.key()?;
        let owner = r.key()?;
        let bump = r.u8()?;
        let mut positions = [([0u8; 32], 0i128); MAX_SLOTS];
        for p in positions.iter_mut() {
            *p = (r.key()?, r.i128()?);
        }
        Ok(Backing {
            protocol,
            owner,
            bump,
            positions,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol);
        w.key(&self.owner);
        w.u8(self.bump);
        for (m, n) in &self.positions {
            w.key(m);
            w.i128(*n);
        }
        w.zeros(7);
        Ok(())
    }

    /// The core ledger. Empty slots are (zero mint, 0).
    pub fn ledger(&self) -> Result<bulkhead_core::ledger::Ledger, ProgramError> {
        let mut list = [([0u8; 32], 0i128); MAX_SLOTS];
        let mut n = 0;
        for &(m, net) in &self.positions {
            if net != 0 {
                list[n] = (m, net);
                n += 1;
            }
        }
        bulkhead_core::ledger::Ledger::from_positions(&list[..n])
            .map_err(|_| VaultError::LedgerCorrupt.into())
    }

    pub fn set_ledger(&mut self, l: &bulkhead_core::ledger::Ledger) {
        self.positions = [([0u8; 32], 0i128); MAX_SLOTS];
        for (slot, p) in self.positions.iter_mut().zip(l.positions()) {
            *slot = (p.mint, p.net);
        }
    }
}

// ---------------------------------------------------------------------------
// Ticket: ["ticket", protocol, payer, nonce_le] (the payer names its own)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub protocol: [u8; 32],
    pub vault: [u8; 32],
    pub recipient: [u8; 32],
    pub recipient_owner: [u8; 32],
    pub payer: [u8; 32],
    pub id: u64,
    pub amount: u64,
    pub created_s: i64,
    pub eta_s: i64,
    pub extended_s: i64,
    pub bump: u8,
}

impl Ticket {
    pub const DISC: [u8; 8] = *b"BHTICKT1";
    pub const LEN: usize = 8 + 32 * 5 + 8 * 5 + 1 + 7;

    pub fn load(d: &[u8]) -> Result<Ticket, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        Ok(Ticket {
            protocol: r.key()?,
            vault: r.key()?,
            recipient: r.key()?,
            recipient_owner: r.key()?,
            payer: r.key()?,
            id: r.u64()?,
            amount: r.u64()?,
            created_s: r.i64()?,
            eta_s: r.i64()?,
            extended_s: r.i64()?,
            bump: r.u8()?,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol);
        w.key(&self.vault);
        w.key(&self.recipient);
        w.key(&self.recipient_owner);
        w.key(&self.payer);
        w.u64(self.id);
        w.u64(self.amount);
        w.i64(self.created_s);
        w.i64(self.eta_s);
        w.i64(self.extended_s);
        w.u8(self.bump);
        w.zeros(7);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Change: ["change", protocol, id_le]; a proposed configuration change
// ---------------------------------------------------------------------------

/// Change kinds. Tightenings apply at proposal; everything else waits.
pub mod change {
    /// Target: vault. Payload: LimitConfig.
    pub const SET_LIMITS: u8 = 0;
    /// Target: mint. Payload: AssetConfig.
    pub const UPSERT_ASSET: u8 = 1;
    /// Payload: guardian set.
    pub const SET_GUARDIANS: u8 = 2;
    /// Target: new admin.
    pub const SET_ADMIN: u8 = 3;
    /// Target: new lifeboat destination (a token-account owner).
    pub const SET_LIFEBOAT_DESTINATION: u8 = 4;
    /// Payload: i64 seconds.
    pub const SET_LOOSEN_DELAY: u8 = 5;
    /// Target: new recovery key (all zero: none). Proposed by the recovery
    /// key, or by the admin while there is none.
    pub const SET_RECOVERY: u8 = 6;
    pub const COUNT: u8 = 7;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub protocol: [u8; 32],
    pub id: u64,
    pub kind: u8,
    pub vetoed: bool,
    pub executed: bool,
    pub bump: u8,
    pub target: [u8; 32],
    pub proposer: [u8; 32],
    pub created_s: i64,
    pub executable_s: i64,
    pub expires_s: i64,
    pub payload_len: u16,
    pub payload: [u8; MAX_PAYLOAD],
    /// The target's version when proposed; execution requires it unchanged.
    pub base_version: u32,
}

impl Change {
    pub const DISC: [u8; 8] = *b"BHCHNG01";
    pub const LEN: usize = 8 + 32 + 8 + 4 + 32 * 2 + 8 * 3 + 2 + MAX_PAYLOAD + 6;

    pub fn load(d: &[u8]) -> Result<Change, ProgramError> {
        let mut r = R::new(d, &Self::DISC, Self::LEN)?;
        let protocol = r.key()?;
        let id = r.u64()?;
        let kind = r.u8()?;
        let vetoed = r.bool()?;
        let executed = r.bool()?;
        let bump = r.u8()?;
        let target = r.key()?;
        let proposer = r.key()?;
        let created_s = r.i64()?;
        let executable_s = r.i64()?;
        let expires_s = r.i64()?;
        let payload_len = r.u16()?;
        let mut payload = [0u8; MAX_PAYLOAD];
        payload.copy_from_slice(r.take(MAX_PAYLOAD)?);
        let base_version = r.u32()?;
        if payload_len as usize > MAX_PAYLOAD {
            return Err(VaultError::WrongAccountType.into());
        }
        Ok(Change {
            protocol,
            id,
            kind,
            vetoed,
            executed,
            bump,
            target,
            proposer,
            created_s,
            executable_s,
            expires_s,
            payload_len,
            payload,
            base_version,
        })
    }

    pub fn store(&self, d: &mut [u8]) -> Result<(), ProgramError> {
        let mut w = W::new(d, &Self::DISC, Self::LEN)?;
        w.key(&self.protocol);
        w.u64(self.id);
        w.u8(self.kind);
        w.bool(self.vetoed);
        w.bool(self.executed);
        w.u8(self.bump);
        w.key(&self.target);
        w.key(&self.proposer);
        w.i64(self.created_s);
        w.i64(self.executable_s);
        w.i64(self.expires_s);
        w.u16(self.payload_len);
        w.put(&self.payload);
        w.u32(self.base_version);
        w.zeros(2);
        Ok(())
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_layout_round_trips() {
        let lim = LimitConfig {
            short_bps: 200,
            short_window_s: 3600,
            long_bps: 500,
            long_window_s: 86_400,
            min_queue_delay_s: 21_600,
            short_floor: 1,
            long_floor: 2,
            short_cap: 3,
            long_cap: 4,
        };
        let mut p = Protocol {
            protocol_program: [1; 32],
            caller: [2; 32],
            admin: [3; 32],
            guardians: [[4; 32]; MAX_GUARDIANS],
            last_heartbeat: [5; MAX_GUARDIANS],
            guardian_count: 3,
            threshold: 2,
            sealed: true,
            bump: 250,
            heartbeat_interval_s: 604_800,
            loosen_delay_s: 259_200,
            frozen_until: 7,
            abdications: 9,
            vault_count: 2,
            next_ticket_id: 11,
            next_change_id: 12,
            lifeboat_destination: [6; 32],
            destination_set_s: 13,
            seal_executable_s: 14,
            seal_expires_s: 15,
            seal_vetoed: true,
            versions: [7, 8, 9, u32::MAX, 11],
            recovery: [12; 32],
            sealed_at: 16,
        };
        p.guardians[2] = [9; 32];
        let mut buf = [0u8; Protocol::LEN];
        p.store(&mut buf).unwrap();
        assert_eq!(Protocol::load(&buf).unwrap(), p);

        let v = Vault {
            protocol: [1; 32],
            mint: [2; 32],
            token_program: [3; 32],
            token_account: [4; 32],
            limits: lim,
            tat_short_ms: -1,
            tat_long_ms: 2,
            ref_balance: 3,
            low: bulkhead_core::ema::WindowLow {
                prev: 4,
                cur: 5,
                window: 6,
            },
            ref_updated_s: 4,
            ref_initialized: true,
            decimals: 6,
            bump: 7,
            token_bump: 8,
            pending_tickets: 9,
            queued_amount: 10,
            frozen_until: 11,
            imported: 12,
            total_in: 13,
            backed_out: 14,
            unbacked_out: 15,
            settled: 16,
            cancelled: 17,
            lifeboat_amount: 18,
            exit_amount: 19,
            exit_proposed_s: 22,
            exit_executable_s: 20,
            exit_expires_s: 21,
            exit_vetoed: true,
            limits_version: 41,
            exit_proposer: [42; 32],
        };
        let mut buf = [0u8; Vault::LEN];
        v.store(&mut buf).unwrap();
        assert_eq!(Vault::load(&buf).unwrap(), v);

        let b = Backing {
            protocol: [1; 32],
            owner: [2; 32],
            bump: 3,
            positions: [([4; 32], -5); MAX_SLOTS],
        };
        let mut buf = [0u8; Backing::LEN];
        b.store(&mut buf).unwrap();
        assert_eq!(Backing::load(&buf).unwrap(), b);

        let c = Change {
            protocol: [1; 32],
            id: 2,
            kind: change::SET_LIMITS,
            vetoed: true,
            executed: false,
            bump: 3,
            target: [4; 32],
            proposer: [5; 32],
            created_s: 6,
            executable_s: 7,
            expires_s: 8,
            payload_len: 9,
            payload: [10; MAX_PAYLOAD],
            base_version: 0xDEAD_BEEF,
        };
        let mut buf = [0u8; Change::LEN];
        c.store(&mut buf).unwrap();
        assert_eq!(Change::load(&buf).unwrap(), c);
        // A Change can never be read as a Ticket (type cosplay).
        assert!(Ticket::load(&buf[..Ticket::LEN.min(buf.len())]).is_err());
    }
}
