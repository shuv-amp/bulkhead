//! Line protocol shared with `reference/protocol.py`.
//!
//! Each input line is one command; each produces exactly one output line.
//! The same case files drive the golden tests (fixed expected outputs) and the
//! differential runner (Python reference vs this worker on random cases).
//! See `reference/protocol.py` for the command table.

use bulkhead_core::classify::{self, AssetConfig, Class, LimitConfig};
use bulkhead_core::ema::ema_update;
use bulkhead_core::floor;
use bulkhead_core::governance;
use bulkhead_core::ledger::{Ledger, Mint, PricedAsset, Pricing};
use bulkhead_core::limiter::{self, Bucket, Decision, LimiterParams, LimiterState};
use bulkhead_core::price;
use bulkhead_core::value::value_v;

#[derive(Default)]
pub struct Session {
    limiter: Option<(LimiterParams, LimiterState)>,
}

fn mint(id: u64) -> Mint {
    let mut m = [0u8; 32];
    m[..8].copy_from_slice(&id.to_le_bytes());
    m
}

fn class(c: Class) -> &'static str {
    match c {
        Class::Tighten => "T",
        Class::Loosen => "L",
    }
}

struct Tok<'a> {
    it: std::str::SplitWhitespace<'a>,
}

impl<'a> Tok<'a> {
    fn next(&mut self) -> Result<&'a str, String> {
        self.it.next().ok_or_else(|| "missing token".to_string())
    }
    fn p<T: std::str::FromStr>(&mut self) -> Result<T, String> {
        let t = self.next()?;
        t.parse::<T>().map_err(|_| format!("bad token {t}"))
    }
    fn b(&mut self) -> Result<bool, String> {
        Ok(self.p::<u8>()? != 0)
    }
}

impl Session {
    pub fn run_line(&mut self, line: &str) -> Result<String, String> {
        let mut t = Tok {
            it: line.split_whitespace(),
        };
        let cmd = t.next()?;
        match cmd {
            "L" => {
                let p = LimiterParams {
                    short: Bucket {
                        capacity: t.p()?,
                        window_ms: t.p()?,
                    },
                    long: Bucket {
                        capacity: t.p()?,
                        window_ms: t.p()?,
                    },
                    min_queue_delay_ms: t.p()?,
                    horizon_ms: t.p()?,
                };
                self.limiter = Some((p, LimiterState::default()));
                Ok("L ok".into())
            }
            "R" => {
                let (p, s) = self.limiter.as_mut().ok_or("no limiter")?;
                let now: i64 = t.p()?;
                let amount: u64 = t.p()?;
                let frozen_until: i64 = t.p()?;
                Ok(match limiter::request(s, p, now, amount, frozen_until) {
                    Ok(Decision::Instant) => format!("I {} {}", s.tat_short_ms, s.tat_long_ms),
                    Ok(Decision::Queued { eta_ms }) => {
                        format!("Q {} {} {}", eta_ms, s.tat_short_ms, s.tat_long_ms)
                    }
                    Err(e) => format!("X {}", e.code()),
                })
            }
            "Z" => {
                let (p, s) = self.limiter.as_mut().ok_or("no limiter")?;
                let now: i64 = t.p()?;
                let pending: u32 = t.p()?;
                Ok(match limiter::reset_backlog(s, p, now, pending) {
                    Ok(()) => format!("Z {} {}", s.tat_short_ms, s.tat_long_ms),
                    Err(e) => format!("X {}", e.code()),
                })
            }
            "A" => {
                let (p, s) = self.limiter.as_ref().ok_or("no limiter")?;
                let now: i64 = t.p()?;
                Ok(format!("A {}", limiter::available_now(s, p, now)))
            }
            "M" => {
                let p = LimiterParams {
                    short: Bucket {
                        capacity: t.p()?,
                        window_ms: t.p()?,
                    },
                    long: Bucket {
                        capacity: t.p()?,
                        window_ms: t.p()?,
                    },
                    min_queue_delay_ms: 0,
                    horizon_ms: 0,
                };
                let tm: i64 = t.p()?;
                Ok(format!("M {}", limiter::max_unbacked_over(&p, tm)))
            }
            "K" => {
                let (r, bps, fl, cap): (u64, u16, u64, u64) = (t.p()?, t.p()?, t.p()?, t.p()?);
                Ok(format!("K {}", limiter::capacity_from_ref(r, bps, fl, cap)))
            }
            "E" => {
                let (r, last, bal, now, init): (u64, i64, u64, i64, bool) =
                    (t.p()?, t.p()?, t.p()?, t.p()?, t.b()?);
                Ok(format!("E {}", ema_update(r, last, bal, now, init)))
            }
            "V" => {
                let (a, m, e, d, w, up): (u128, u128, i32, u8, u32, bool) =
                    (t.p()?, t.p()?, t.p()?, t.p()?, t.p()?, t.b()?);
                Ok(match value_v(a, m, e, d, w, up) {
                    Some(v) => format!("V {v}"),
                    None => "V NONE".into(),
                })
            }
            "P" => {
                let (pr, conf, ema, mult): (i64, u64, i64, u32) = (t.p()?, t.p()?, t.p()?, t.p()?);
                Ok(match price::conservative(pr, conf, ema, mult) {
                    Some(b) => format!("P {} {}", b.lo, b.hi),
                    None => "P NONE".into(),
                })
            }
            "U" => {
                let (pr, conf, publ, now, age, mc): (i64, u64, i64, i64, i64, u32) =
                    (t.p()?, t.p()?, t.p()?, t.p()?, t.p()?, t.p()?);
                Ok(format!(
                    "U {}",
                    price::is_usable(pr, conf, publ, now, age, mc) as u8
                ))
            }
            "B" => {
                let amount: u64 = t.p()?;
                let j: u64 = t.p()?;
                let nassets: usize = t.p()?;
                let mut assets: Vec<(Mint, Pricing)> = Vec::with_capacity(nassets);
                for _ in 0..nassets {
                    let id: u64 = t.p()?;
                    let kind = t.next()?;
                    let (lo, hi, expo, dec, hc, lb): (u128, u128, i32, u8, u32, u32) =
                        (t.p()?, t.p()?, t.p()?, t.p()?, t.p()?, t.p()?);
                    let pr = match kind {
                        "N" => Pricing::NotAllowlisted,
                        "U" => Pricing::Unpriced,
                        "P" => Pricing::Priced(PricedAsset {
                            lo,
                            hi,
                            expo,
                            decimals: dec,
                            haircut_bps: hc,
                            liability_bps: lb,
                        }),
                        k => return Err(format!("bad kind {k}")),
                    };
                    assets.push((mint(id), pr));
                }
                let npos: usize = t.p()?;
                let mut stored: Vec<(Mint, i128)> = Vec::with_capacity(npos);
                for _ in 0..npos {
                    let id: u64 = t.p()?;
                    let net: i128 = t.p()?;
                    stored.push((mint(id), net));
                }
                let ledger =
                    Ledger::from_positions(&stored).map_err(|e| format!("bad ledger {e:?}"))?;
                let lookup = |m: &Mint| {
                    assets
                        .iter()
                        .find(|(k, _)| k == m)
                        .map(|(_, p)| *p)
                        .unwrap_or(Pricing::NotAllowlisted)
                };
                let b = ledger.backed_amount(&mint(j), amount, &lookup);
                let h = match ledger.health(&lookup) {
                    Some(h) => h.to_string(),
                    None => "NONE".into(),
                };
                Ok(format!("B {b} {h}"))
            }
            "CL" => {
                let read = |t: &mut Tok| -> Result<LimitConfig, String> {
                    Ok(LimitConfig {
                        short_bps: t.p()?,
                        short_window_s: t.p()?,
                        long_bps: t.p()?,
                        long_window_s: t.p()?,
                        min_queue_delay_s: t.p()?,
                        short_floor: t.p()?,
                        long_floor: t.p()?,
                        short_cap: t.p()?,
                        long_cap: t.p()?,
                    })
                };
                let old = read(&mut t)?;
                let new = read(&mut t)?;
                Ok(format!(
                    "CL {}",
                    class(classify::classify_limits(&old, &new))
                ))
            }
            "CA" => {
                let exists = t.b()?;
                let read = |t: &mut Tok| -> Result<AssetConfig, String> {
                    Ok(AssetConfig {
                        allowlisted: t.b()?,
                        haircut_bps: t.p()?,
                        liability_bps: t.p()?,
                        conf_mult_bps: t.p()?,
                        max_age_s: t.p()?,
                        max_conf_bps: t.p()?,
                        feed_id: mint(t.p()?),
                    })
                };
                let old = read(&mut t)?;
                let new = read(&mut t)?;
                let o = if exists { Some(&old) } else { None };
                Ok(format!("CA {}", class(classify::classify_asset(o, &new))))
            }
            "CD" => {
                let (o, n): (i64, i64) = (t.p()?, t.p()?);
                Ok(match classify::classify_delay(o, n) {
                    Some(c) => format!("CD {}", class(c)),
                    None => "CD X".into(),
                })
            }
            "F" => {
                let hex = t.next()?;
                let bytes = decode_hex(hex)?;
                let info = floor::elf_info(&bytes);
                Ok(match info {
                    Some(i) => format!(
                        "F {} {} {}",
                        i.e_machine,
                        i.e_flags,
                        floor::deployable_after_simd0500(info) as u8
                    ),
                    None => "F NONE".into(),
                })
            }
            "GS" => {
                let now: i64 = t.p()?;
                let class = match t.next()? {
                    "T" => Class::Tighten,
                    "L" => Class::Loosen,
                    k => return Err(format!("bad class {k}")),
                };
                let delay: i64 = t.p()?;
                let s = governance::schedule(now, class, delay);
                Ok(format!("GS {} {}", s.executable_s, s.expires_s))
            }
            "GX" => {
                let s = governance::Schedule {
                    executable_s: t.p()?,
                    expires_s: t.p()?,
                };
                let now: i64 = t.p()?;
                let (v, ex, ab) = (t.b()?, t.b()?, t.b()?);
                Ok(match governance::can_execute(&s, now, v, ex, ab) {
                    Ok(()) => "GX OK".into(),
                    Err(e) => format!("GX {}", e.code()),
                })
            }
            "GF" => {
                let (cur, now, secs): (i64, i64, i64) = (t.p()?, t.p()?, t.p()?);
                Ok(match governance::freeze_until(cur, now, secs) {
                    Ok(u) => format!("GF {u}"),
                    Err(e) => format!("GF {}", e.code()),
                })
            }
            "GH" => {
                let (last, interval, now): (i64, i64, i64) = (t.p()?, t.p()?, t.p()?);
                Ok(format!(
                    "GH {}",
                    governance::guardian_alive(last, interval, now) as u8
                ))
            }
            "GQ" => {
                let (ap, al, th): (u8, u8, u8) = (t.p()?, t.p()?, t.p()?);
                Ok(format!("GQ {}", governance::quorum(ap, al, th) as u8))
            }
            "GA" => {
                let (mask, kind): (u32, u8) = (t.p()?, t.p()?);
                let m2 = governance::Abdications(mask).abdicate(kind);
                Ok(format!("GA {} {}", m2.0, m2.is_abdicated(kind) as u8))
            }
            "GJ" => {
                let (ap, al, th, target, count): (u8, u8, u8, u8, u8) =
                    (t.p()?, t.p()?, t.p()?, t.p()?, t.p()?);
                Ok(format!(
                    "GJ {}",
                    governance::can_eject(ap, al, th, target, count) as u8
                ))
            }
            "FH" => {
                let bytes = decode_hex_or_empty(t.next()?)?;
                Ok(format!("FH {}", floor::murmur3_32(&bytes)))
            }
            "FB" => {
                let bytes = decode_hex_or_empty(t.next()?)?;
                Ok(match floor::buffer_authority(&bytes) {
                    None => "FB NONE".into(),
                    Some(a) => format!("FB {}", opt_key(a)),
                })
            }
            "FP" => {
                let bytes = decode_hex_or_empty(t.next()?)?;
                Ok(match floor::programdata_header(&bytes) {
                    None => "FP NONE".into(),
                    Some(h) => format!("FP {} {}", h.slot, opt_key(h.upgrade_authority)),
                })
            }
            "FG" => {
                let bytes = decode_hex_or_empty(t.next()?)?;
                Ok(match floor::program_programdata(&bytes) {
                    None => "FG NONE".into(),
                    Some(k) => format!("FG {}", encode_hex(&k)),
                })
            }
            "FS" => {
                let buf = decode_hex_or_empty(t.next()?)?;
                let region = decode_hex_or_empty(t.next()?)?;
                Ok(format!(
                    "FS {}",
                    floor::snapshot_matches(&buf, &region) as u8
                ))
            }
            "FC" => {
                let bytes = decode_hex_or_empty(t.next()?)?;
                Ok(format!("FC {}", floor::is_canonical_abort(&bytes) as u8))
            }
            "FA" => Ok(format!(
                "FA {} {}",
                encode_hex(&floor::ABORT_ELF),
                encode_hex(&floor::ABORT_ELF_MINIMAL)
            )),
            "FR" => {
                let source = match t.next()? {
                    "S" => floor::RestoreSource::Snapshot,
                    "P" => floor::RestoreSource::Proposed,
                    k => return Err(format!("bad source {k}")),
                };
                let (buf, approved): (u8, u8) = (t.p()?, t.p()?);
                let (quorum_ok, vetoed) = (t.b()?, t.b()?);
                let (now, eta, expires): (i64, i64, i64) = (t.p()?, t.p()?, t.p()?);
                let ok = floor::can_restore(
                    source,
                    &[buf; 32],
                    &[approved; 32],
                    quorum_ok,
                    vetoed,
                    now,
                    eta,
                    expires,
                );
                Ok(format!("FR {}", ok as u8))
            }
            other => Err(format!("unknown command {other}")),
        }
    }
}

/// Like `decode_hex`, but `-` stands for zero bytes (a token can't be empty).
fn decode_hex_or_empty(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" {
        Ok(Vec::new())
    } else {
        decode_hex(s)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn opt_key(k: Option<[u8; 32]>) -> String {
    match k {
        Some(k) => encode_hex(&k),
        None => "-".into(),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex".to_string()))
        .collect()
}
