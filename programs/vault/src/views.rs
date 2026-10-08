//! Views: the worst case, readable on-chain.

use crate::*;
use bulkhead_core::limiter::{available_now, max_unbacked_over, params_from_config};

// ---------------------------------------------------------------------------
// 22. attest
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault, 2 vault token account.
// Returns (return data, 64 bytes, little-endian):
//   available_now u64   unbacked amount that would pay out instantly right now
//   worst_1h      u64   most unbacked outflow possible if nobody freezes for 1 hour
//   worst_24h     u64   the same for 24 hours
//   balance       u64   vault token balance
//   frozen_until  i64   max(protocol, vault) freeze end
//   queued        u64   total in pending tickets
//   loosen_delay  i64   seconds any loosening must wait
//   pending u32 | live_guardians u8 | guardian_count u8 | sealed u8 | pad u8
//
// Any program can CPI into this: a curator, router or insurer can read a
// venue's live worst case and refuse to route funds when it is too large.
pub fn attest(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    if key(acc(accounts, 2)?) != v.token_account {
        return Err(VaultError::WrongVault.into());
    }
    let t = now()?;
    let balance = token::balance(acc(accounts, 2)?)?;
    let mut v2 = v.clone();
    touch_reference(&mut v2, balance, t);
    let params = params_from_config(&v2.limits, unbacked_base(&v2, balance));
    let frozen = p.frozen_until.max(v.frozen_until);
    let now_ms = t.saturating_mul(1_000);
    let instant = if t < frozen {
        0
    } else {
        available_now(&v.limiter_state(), &params, now_ms).min(balance)
    };
    let cap = |x: u128| x.min(u64::MAX as u128) as u64;
    let alive = p.alive_mask(t).count_ones() as u8;
    let mut out = [0u8; 64];
    out[0..8].copy_from_slice(&instant.to_le_bytes());
    out[8..16].copy_from_slice(&cap(max_unbacked_over(&params, 3_600_000)).to_le_bytes());
    out[16..24].copy_from_slice(&cap(max_unbacked_over(&params, 86_400_000)).to_le_bytes());
    out[24..32].copy_from_slice(&balance.to_le_bytes());
    out[32..40].copy_from_slice(&frozen.to_le_bytes());
    out[40..48].copy_from_slice(&v.queued_amount.to_le_bytes());
    out[48..56].copy_from_slice(&p.loosen_delay_s.to_le_bytes());
    out[56..60].copy_from_slice(&v.pending_tickets.to_le_bytes());
    out[60] = alive;
    out[61] = p.guardian_count;
    out[62] = p.sealed as u8;
    pinocchio::cpi::set_return_data(&out);
    Ok(())
}
