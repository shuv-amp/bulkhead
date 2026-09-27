//! Is a configuration change a tightening (applies instantly) or a loosening
//! (waits at least `MIN_LOOSEN_DELAY_S`, public, vetoable by any guardian)?
//!
//! A change is `Tighten` only if every field moves in the safe direction or
//! stays equal. Anything mixed is `Loosen`. Identity, guardian, admin and
//! lifeboat-destination changes are always `Loosen` (handled by the program).

use crate::consts::MIN_LOOSEN_DELAY_S;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Tighten,
    Loosen,
}

/// Limiter configuration as stored per vault / mint gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitConfig {
    pub short_bps: u16,
    pub short_window_s: u32,
    pub long_bps: u16,
    pub long_window_s: u32,
    pub min_queue_delay_s: u32,
    pub short_floor: u64,
    pub long_floor: u64,
    /// 0 = no cap.
    pub short_cap: u64,
    /// 0 = no cap.
    pub long_cap: u64,
}

/// Valuation configuration per allowlisted mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetConfig {
    pub allowlisted: bool,
    pub haircut_bps: u32,
    pub liability_bps: u32,
    pub conf_mult_bps: u32,
    pub max_age_s: u32,
    pub max_conf_bps: u32,
    pub feed_id: [u8; 32],
}

fn cap_tighter_or_equal(old: u64, new: u64) -> bool {
    if new == old {
        return true;
    }
    if old == 0 {
        return new > 0;
    }
    new > 0 && new <= old
}

pub fn classify_limits(old: &LimitConfig, new: &LimitConfig) -> Class {
    let tight = new.short_bps <= old.short_bps
        && new.short_window_s >= old.short_window_s
        && new.long_bps <= old.long_bps
        && new.long_window_s >= old.long_window_s
        && new.min_queue_delay_s >= old.min_queue_delay_s
        && new.short_floor <= old.short_floor
        && new.long_floor <= old.long_floor
        && cap_tighter_or_equal(old.short_cap, new.short_cap)
        && cap_tighter_or_equal(old.long_cap, new.long_cap);
    if tight {
        Class::Tighten
    } else {
        Class::Loosen
    }
}

pub fn classify_asset(old: Option<&AssetConfig>, new: &AssetConfig) -> Class {
    let old = match old {
        None => return Class::Loosen, // a new asset can only add value
        Some(o) => o,
    };
    if !new.allowlisted {
        return Class::Tighten; // disabling only removes value
    }
    if !old.allowlisted {
        return Class::Loosen;
    }
    let tight = new.haircut_bps <= old.haircut_bps
        && new.liability_bps >= old.liability_bps
        && new.conf_mult_bps >= old.conf_mult_bps
        && new.max_age_s <= old.max_age_s
        && new.max_conf_bps <= old.max_conf_bps
        && new.feed_id == old.feed_id;
    if tight {
        Class::Tighten
    } else {
        Class::Loosen
    }
}

/// Changing the loosen delay itself. Below the constant minimum is rejected.
pub fn classify_delay(old_s: i64, new_s: i64) -> Option<Class> {
    if new_s < MIN_LOOSEN_DELAY_S {
        return None;
    }
    Some(if new_s >= old_s {
        Class::Tighten
    } else {
        Class::Loosen
    })
}
