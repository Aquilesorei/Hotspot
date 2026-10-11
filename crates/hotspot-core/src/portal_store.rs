//! Coupons and sessions of a portal profile, kept by the root engine in its own directory
//! (never in a user's files). Times are unix seconds so they survive restarts and reboots.
//!
//! A coupon's time belongs to the coupon, shared by all its devices: in real-time mode it runs
//! from the first activation; in connected mode it runs while any of its devices is connected.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::constants::{PORTAL_HISTORY_MAX, 
    COUPON_CODE_LEN, NAME_MAX_CHARS, PASSPHRASE_ALPHABET, PHONE_DIGITS, PORTAL_DEVICES_PER_COUPON, PORTAL_DIR,
    PORTAL_MAX_DURATION_MIN, PORTAL_PURGE_AFTER_SECS,
};
use crate::error::{HotspotError as E, Result};
use crate::models::{normalize_mac, validate_country_code, TimeMode};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coupon {
    /// Stored without the dash: `HX7K29QM`, shown as `HX7K-29QM`.
    pub code: String,
    pub duration_min: u64,
    pub time_mode: TimeMode,
    pub max_devices: u32,
    pub created: u64,
    pub activated: Option<u64>,
    /// Real-time mode: when the time runs out (activation + duration, pushed back by extensions).
    #[serde(default)]
    pub expires: Option<u64>,
    /// Connected mode only: seconds spent so far.
    #[serde(default)]
    pub used_secs: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponState {
    New,
    InUse,
    UsedUp,
    Revoked,
}

impl Coupon {
    pub fn display_code(&self) -> String {
        let (a, b) = self.code.split_at(self.code.len() / 2);
        format!("{a}-{b}")
    }

    pub fn remaining_secs(&self, now: u64) -> u64 {
        if self.revoked {
            return 0;
        }
        let total = self.duration_min * 60;
        match (self.time_mode, self.activated) {
            (_, None) => total,
            (TimeMode::Real, Some(at)) => self.expires.unwrap_or(at + total).saturating_sub(now),
            (TimeMode::Connected, Some(_)) => total.saturating_sub(self.used_secs),
        }
    }

    pub fn state(&self, now: u64) -> CouponState {
        match (self.revoked, self.activated, self.remaining_secs(now)) {
            (true, _, _) => CouponState::Revoked,
            (false, None, _) => CouponState::New,
            (false, Some(_), 0) => CouponState::UsedUp,
            (false, Some(_), _) => CouponState::InUse,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub coupon: String,
    pub mac: String,
    /// Personal data: cleared `PORTAL_PURGE_AFTER_SECS` after the session ends.
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    /// E.164: `+919876543210`.
    pub phone: Option<String>,
    pub started: u64,
    pub ended: Option<u64>,
    /// Ended because the coupon ran out (extending the coupon reopens it), not by hand.
    #[serde(default)]
    pub expired: bool,
    /// Ended by the admin: this device can't sign in again with this coupon.
    #[serde(default)]
    pub kicked: bool,
    /// Personal data too: purged with the session.
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub history: Vec<Visit>,
}

/// The device joined (`connected`) or left the network at `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Visit {
    pub at: u64,
    pub connected: bool,
}

impl Session {
    fn online(&self) -> bool {
        self.history.last().is_some_and(|v| v.connected)
    }

    fn mark(&mut self, now: u64, connected: bool) {
        if connected {
            self.last_seen = Some(now);
        }
        if self.online() != connected {
            self.history.push(Visit { at: now, connected });
            if self.history.len() > PORTAL_HISTORY_MAX {
                self.history.remove(0);
            }
        }
    }

    fn end(&mut self, now: u64) {
        self.mark(now, false);
        self.ended = Some(now);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    /// The coupon ran out.
    Expired,
    /// Signed out by the admin.
    SignedOut,
    /// Moved to another coupon, or the coupon was revoked.
    Ended,
}

/// What the portal page shows a signed-in device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub left_secs: u64,
    pub total_secs: u64,
    pub time_mode: TimeMode,
}

/// What a device typed in the portal form.
#[derive(Debug, Clone)]
pub struct SignIn {
    pub first_name: String,
    pub last_name: String,
    pub country_code: String,
    pub phone: String,
    pub code: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PortalStore {
    #[serde(default)]
    pub coupons: Vec<Coupon>,
    #[serde(default)]
    pub sessions: Vec<Session>,
}

/// One file per profile. The name is arbitrary text, so it's hex-encoded into the file name.
pub fn store_path(dir: &Path, profile: &str) -> PathBuf {
    let hex: String = profile.bytes().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("{hex}.json"))
}

pub fn default_dir() -> PathBuf {
    PORTAL_DIR.into()
}

/// Admin actions on a portal profile's coupons and sessions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PortalAction {
    List,
    CreateCoupons { count: u32, duration_min: u64, time_mode: TimeMode, max_devices: u32 },
    Revoke { code: String },
    Extend { code: String, minutes: u64 },
    EndSession { mac: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CouponView {
    /// `HX7K-29QM`
    pub code: String,
    pub duration_min: u64,
    pub time_mode: TimeMode,
    pub max_devices: u32,
    pub devices: usize,
    pub state: CouponState,
    pub remaining_secs: u64,
    pub created: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub coupon: String,
    pub mac: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub started: u64,
    pub ended: Option<u64>,
    pub remaining_secs: u64,
    pub state: SessionState,
    pub online: bool,
    pub ip: Option<String>,
    pub last_seen: Option<u64>,
    pub history: Vec<Visit>,
}

impl PortalStore {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| E::command(format!("read {}", path.display()), e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Root-only: it holds names and phone numbers.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(self).expect("store is serializable").as_bytes())?;
        f.sync_all()?;
        Ok(fs::rename(&tmp, path)?) // never a half-written file after a crash
    }

    pub fn create_coupons(&mut self, count: u32, duration_min: u64, time_mode: TimeMode, max_devices: u32, now: u64) -> Result<Vec<Coupon>> {
        if !(1..=PORTAL_MAX_DURATION_MIN).contains(&duration_min) {
            return Err(E::invalid_profile(format!("coupon duration must be 1 to {PORTAL_MAX_DURATION_MIN} minutes")));
        }
        if !PORTAL_DEVICES_PER_COUPON.contains(&max_devices) {
            return Err(E::invalid_profile("devices per coupon out of range"));
        }
        if !(1..=500).contains(&count) {
            return Err(E::invalid_profile("create 1 to 500 coupons at a time"));
        }
        let mut created = Vec::new();
        while created.len() < count as usize {
            let code = random_code()?;
            if self.coupons.iter().chain(&created).any(|c: &Coupon| c.code == code) {
                continue;
            }
            created.push(Coupon {
                code,
                duration_min,
                time_mode,
                max_devices,
                created: now,
                activated: None,
                expires: None,
                used_secs: 0,
                revoked: false,
            });
        }
        self.coupons.extend(created.iter().cloned());
        Ok(created)
    }

    fn coupon_mut(&mut self, code: &str) -> Result<&mut Coupon> {
        let code = canonical_code(code);
        self.coupons.iter_mut().find(|c| c.code == code).ok_or(E::CouponInvalid)
    }

    /// Checks the form and the coupon, then opens a session. A device signing in again with
    /// the same coupon gets its session back.
    pub fn redeem(&mut self, form: &SignIn, mac: &str, now: u64) -> Result<u64> {
        let mac = normalize_mac(mac)?;
        let first_name = clean_name(&form.first_name, "first name")?;
        let last_name = clean_name(&form.last_name, "last name")?;
        let phone = clean_phone(&form.country_code, &form.phone)?;
        let code = canonical_code(&form.code);

        if self.sessions.iter().any(|s| s.coupon == code && s.mac == mac && s.kicked) {
            return Err(E::CouponKicked);
        }
        let active_devices = self.sessions.iter().filter(|s| s.coupon == code && s.ended.is_none() && s.mac != mac).count();
        let already_here = self.sessions.iter().any(|s| s.coupon == code && s.ended.is_none() && s.mac == mac);
        let coupon = self.coupon_mut(&code)?;
        if coupon.revoked || (coupon.activated.is_some() && coupon.remaining_secs(now) == 0) {
            return Err(E::CouponUsedUp);
        }
        if !already_here && active_devices >= coupon.max_devices as usize {
            return Err(E::CouponFull(coupon.max_devices));
        }
        if coupon.activated.is_none() {
            coupon.activated = Some(now);
            coupon.expires = (coupon.time_mode == TimeMode::Real).then(|| now + coupon.duration_min * 60);
        }
        let remaining = coupon.remaining_secs(now);
        // a device topping up with a new coupon leaves its old one, or both would be charged
        for s in self.sessions.iter_mut().filter(|s| s.mac == mac && s.coupon != code && s.ended.is_none()) {
            s.end(now);
        }
        if !already_here {
            self.sessions.push(Session {
                coupon: code.clone(),
                mac: mac.clone(),
                first_name: Some(first_name),
                last_name: Some(last_name),
                phone: Some(phone),
                started: now,
                ended: None,
                expired: false,
                kicked: false,
                ip: None,
                last_seen: None,
                history: Vec::new(),
            });
        }
        if let Some(s) = self.sessions.iter_mut().find(|s| s.coupon == code && s.mac == mac && s.ended.is_none()) {
            s.mark(now, true);
        }
        Ok(remaining)
    }

    /// Remaining seconds by coupon code: one pass, so lookups don't rescan the coupon list.
    fn remaining_by_code(&self, now: u64) -> HashMap<&str, u64> {
        self.coupons.iter().map(|c| (c.code.as_str(), c.remaining_secs(now))).collect()
    }

    /// Devices allowed through the portal right now.
    pub fn allowed_macs(&self, now: u64) -> HashSet<String> {
        let remaining = self.remaining_by_code(now);
        self.sessions
            .iter()
            .filter(|s| s.ended.is_none() && remaining.get(s.coupon.as_str()).is_some_and(|&r| r > 0))
            .map(|s| s.mac.clone())
            .collect()
    }

    /// Advances time by `elapsed` seconds: connected-mode coupons spend it if one of their devices
    /// is in `connected`. Ends sessions whose coupon ran out, and forgets sessions (with their
    /// names and phone numbers) and spent coupons `PORTAL_PURGE_AFTER_SECS` after they ended.
    /// Returns the MACs whose session just ended.
    pub fn tick(&mut self, now: u64, elapsed: u64, connected: &HashSet<String>) -> Vec<String> {
        let present: HashSet<&str> = self
            .sessions
            .iter()
            .filter(|s| s.ended.is_none() && connected.contains(&s.mac))
            .map(|s| s.coupon.as_str())
            .collect();
        let spending: HashSet<String> = present.into_iter().map(String::from).collect();
        for coupon in self.coupons.iter_mut().filter(|c| c.time_mode == TimeMode::Connected && c.activated.is_some()) {
            if spending.contains(&coupon.code) {
                coupon.used_secs = coupon.used_secs.saturating_add(elapsed);
            }
        }
        let remaining: HashMap<String, u64> = self.remaining_by_code(now).into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let mut ended = Vec::new();
        for s in self.sessions.iter_mut().filter(|s| s.ended.is_none()) {
            s.mark(now, connected.contains(&s.mac));
            if remaining.get(&s.coupon).copied().unwrap_or(0) == 0 {
                s.end(now);
                s.expired = true;
                ended.push(s.mac.clone());
            }
        }
        let old = |at: u64| now.saturating_sub(at) >= PORTAL_PURGE_AFTER_SECS;
        self.sessions.retain(|s| !s.ended.is_some_and(old));
        let in_use: HashSet<String> = self.sessions.iter().map(|s| s.coupon.clone()).collect();
        self.coupons.retain(|c| {
            let spent = c.revoked || remaining.get(&c.code).is_some_and(|&r| r == 0) && c.activated.is_some();
            !(spent && !in_use.contains(&c.code) && old(c.activated.unwrap_or(c.created)))
        });
        ended
    }

    pub fn apply(&mut self, action: PortalAction, now: u64) -> Result<()> {
        match action {
            PortalAction::List => Ok(()),
            PortalAction::CreateCoupons { count, duration_min, time_mode, max_devices } => {
                self.create_coupons(count, duration_min, time_mode, max_devices, now).map(drop)
            }
            PortalAction::Revoke { code } => self.revoke(&code),
            PortalAction::Extend { code, minutes } => self.extend(&code, minutes, now),
            PortalAction::EndSession { mac } => self.end_session(&mac, now),
        }
    }

    /// Newest first, for the UI.
    pub fn views(&self, now: u64) -> (Vec<CouponView>, Vec<SessionView>) {
        let display = |code: &str| self.coupons.iter().find(|c| c.code == code).map_or(code.to_string(), Coupon::display_code);
        let remaining = |code: &str| self.coupons.iter().find(|c| c.code == code).map_or(0, |c| c.remaining_secs(now));
        let coupons = self
            .coupons
            .iter()
            .rev()
            .map(|c| CouponView {
                code: c.display_code(),
                duration_min: c.duration_min,
                time_mode: c.time_mode,
                max_devices: c.max_devices,
                devices: self.sessions.iter().filter(|s| s.coupon == c.code && s.ended.is_none()).count(),
                state: c.state(now),
                remaining_secs: c.remaining_secs(now),
                created: c.created,
            })
            .collect();
        let sessions = self
            .sessions
            .iter()
            .rev()
            .map(|s| SessionView {
                coupon: display(&s.coupon),
                mac: s.mac.clone(),
                first_name: s.first_name.clone(),
                last_name: s.last_name.clone(),
                phone: s.phone.clone(),
                started: s.started,
                ended: s.ended,
                remaining_secs: if s.ended.is_some() { 0 } else { remaining(&s.coupon) },
                state: match (s.ended, s.expired, s.kicked) {
                    (None, ..) => SessionState::Active,
                    (_, true, _) => SessionState::Expired,
                    (_, _, true) => SessionState::SignedOut,
                    _ => SessionState::Ended,
                },
                online: s.ended.is_none() && s.online(),
                ip: s.ip.clone(),
                last_seen: s.last_seen,
                history: s.history.clone(),
            })
            .collect();
        (coupons, sessions)
    }

    pub fn revoke(&mut self, code: &str) -> Result<()> {
        self.coupon_mut(code)?.revoked = true;
        Ok(())
    }

    /// Adds minutes of access, counted from now if the coupon had run out.
    pub fn extend(&mut self, code: &str, minutes: u64, now: u64) -> Result<()> {
        let coupon = self.coupon_mut(code)?;
        if coupon.revoked {
            return Err(E::invalid_profile("a revoked coupon can't be extended"));
        }
        let total = coupon.duration_min.saturating_add(minutes);
        if total > PORTAL_MAX_DURATION_MIN {
            return Err(E::invalid_profile(format!("coupon duration can't exceed {PORTAL_MAX_DURATION_MIN} minutes")));
        }
        coupon.duration_min = total;
        if let (TimeMode::Real, Some(at)) = (coupon.time_mode, coupon.activated) {
            let expires = coupon.expires.unwrap_or(at + (total - minutes) * 60);
            coupon.expires = Some(expires.max(now) + minutes * 60);
        }
        let code = coupon.code.clone();
        for s in self.sessions.iter_mut().filter(|s| s.coupon == code && s.expired) {
            (s.ended, s.expired) = (None, false);
        }
        Ok(())
    }

    pub fn end_session(&mut self, mac: &str, now: u64) -> Result<()> {
        let mac = normalize_mac(mac)?;
        for s in self.sessions.iter_mut().filter(|s| s.mac == mac && s.ended.is_none()) {
            s.end(now);
            s.kicked = true;
        }
        Ok(())
    }

    /// The access of a device that is signed in.
    pub fn access_for(&self, mac: &str, now: u64) -> Option<Access> {
        let mac = normalize_mac(mac).ok()?;
        let session = self.sessions.iter().find(|s| s.mac == mac && s.ended.is_none())?;
        let coupon = self.coupons.iter().find(|c| c.code == session.coupon)?;
        Some(Access {
            left_secs: coupon.remaining_secs(now),
            total_secs: coupon.duration_min * 60,
            time_mode: coupon.time_mode,
        })
    }

    /// The device's current address, from its DHCP lease or the portal request.
    pub fn note_ip(&mut self, mac: &str, ip: &str) {
        for s in self.sessions.iter_mut().filter(|s| s.mac == mac && s.ended.is_none()) {
            s.ip = Some(ip.to_string());
        }
    }
}

fn canonical_code(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// Upper case only: codes are typed on phones, often by someone else reading them out.
fn random_code() -> Result<String> {
    let alphabet: Vec<u8> = PASSPHRASE_ALPHABET.iter().copied().filter(|b| !b.is_ascii_lowercase()).collect();
    let limit = 256 - 256 % alphabet.len();
    let mut urandom = fs::File::open("/dev/urandom")?;
    let mut out = String::with_capacity(COUPON_CODE_LEN);
    let mut buf = [0u8; 32];
    while out.len() < COUPON_CODE_LEN {
        std::io::Read::read_exact(&mut urandom, &mut buf)?;
        for &b in buf.iter().filter(|&&b| (b as usize) < limit).take(COUPON_CODE_LEN - out.len()) {
            out.push(alphabet[b as usize % alphabet.len()] as char);
        }
    }
    Ok(out)
}

fn clean_name(input: &str, field: &str) -> Result<String> {
    let name = input.trim();
    let count = name.chars().count();
    if count == 0 || count > NAME_MAX_CHARS || name.chars().any(char::is_control) {
        return Err(E::invalid_profile(format!("{field}: 1 to {NAME_MAX_CHARS} characters")));
    }
    Ok(name.into())
}

/// E.164: the country code plus the national number, 15 digits at most.
fn clean_phone(country_code: &str, number: &str) -> Result<String> {
    validate_country_code(country_code)?;
    let digits: String = number.chars().filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')')).collect();
    let digits = digits.trim_start_matches('0');
    let total = country_code.len() - 1 + digits.len();
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !PHONE_DIGITS.contains(&digits.len()) || total > 15 {
        return Err(E::invalid_profile("phone number: digits only, as you would dial it in your country"));
    }
    Ok(format!("{country_code}{digits}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(code: &str) -> SignIn {
        SignIn {
            first_name: "Asha".into(),
            last_name: "Rao".into(),
            country_code: "+91".into(),
            phone: "98765 43210".into(),
            code: code.into(),
        }
    }

    const MAC_A: &str = "12:5a:7a:56:8a:d6";
    const MAC_B: &str = "34:c9:3d:79:c4:67";

    #[test]
    fn real_time_coupon_shared_by_devices() {
        let mut store = PortalStore::default();
        let c = store.create_coupons(1, 60, TimeMode::Real, 2, 1000).unwrap().remove(0);
        assert_eq!(c.code.len(), COUPON_CODE_LEN);
        assert_eq!(c.state(1000), CouponState::New);

        // typed lower case with a dash: still accepted
        let typed = c.display_code().to_lowercase();
        assert_eq!(store.redeem(&form(&typed), MAC_A, 1000).unwrap(), 3600);
        assert_eq!(store.redeem(&form(&c.code), MAC_B, 1600).unwrap(), 3000);
        assert!(matches!(store.redeem(&form(&c.code), "aa:bb:cc:dd:ee:ff", 1700), Err(E::CouponFull(2))));
        assert_eq!(store.redeem(&form(&c.code), MAC_A, 1700).unwrap(), 2900); // same device again
        assert_eq!(store.sessions[0].phone.as_deref(), Some("+919876543210"));
        assert_eq!(store.allowed_macs(1700).len(), 2);

        assert_eq!(store.tick(4600, 2, &HashSet::new()), [MAC_A, MAC_B]);
        assert!(store.allowed_macs(4600).is_empty());
        assert!(matches!(store.redeem(&form(&c.code), MAC_A, 4700), Err(E::CouponUsedUp)));

        // a used-up real-time coupon comes back for an hour from now
        store.extend(&c.code, 60, 90000).unwrap();
        assert_eq!(store.coupons[0].remaining_secs(90000), 3600);
        assert_eq!(store.allowed_macs(90000).len(), 2);
        store.tick(93600, 2, &HashSet::new());

        // 30 days after the end: sessions (names, phones) and the spent coupon are gone
        store.tick(93600 + PORTAL_PURGE_AFTER_SECS, 2, &HashSet::new());
        assert!(store.sessions.is_empty() && store.coupons.is_empty());
    }

    #[test]
    fn connected_time_only_counts_while_present() {
        let mut store = PortalStore::default();
        let code = store.create_coupons(1, 1, TimeMode::Connected, 1, 0).unwrap().remove(0).code;
        store.redeem(&form(&code), MAC_A, 0).unwrap();
        let here: HashSet<String> = [MAC_A.to_string()].into();
        store.tick(1000, 30, &HashSet::new()); // away: nothing spent
        assert_eq!(store.coupons[0].remaining_secs(1000), 60);
        assert!(store.tick(1002, 30, &here).is_empty());
        assert_eq!(store.tick(1004, 30, &here), [MAC_A]);
    }

    #[test]
    fn bad_input_and_admin_actions() {
        let mut store = PortalStore::default();
        let code = store.create_coupons(1, 10, TimeMode::Real, 1, 0).unwrap().remove(0).code;
        assert!(matches!(store.redeem(&form("NOPE-NOPE"), MAC_A, 0), Err(E::CouponInvalid)));
        assert!(store.redeem(&SignIn { phone: "12ab".into(), ..form(&code) }, MAC_A, 0).is_err());
        assert!(store.redeem(&SignIn { first_name: " ".into(), ..form(&code) }, MAC_A, 0).is_err());
        assert!(store.redeem(&SignIn { country_code: "91".into(), ..form(&code) }, MAC_A, 0).is_err());
        assert!(store.redeem(&form(&code), "not a mac", 0).is_err());

        store.redeem(&form(&code), MAC_A, 0).unwrap();
        store.tick(600, 2, &HashSet::new());
        store.extend(&code, 5, 600).unwrap();
        assert_eq!(store.allowed_macs(600).len(), 1);

        // signed out by the admin: the same coupon doesn't let this device back in
        store.end_session(MAC_A, 610).unwrap();
        assert!(matches!(store.redeem(&form(&code), MAC_A, 620), Err(E::CouponKicked)));

        store.revoke(&code).unwrap();
        assert!(store.allowed_macs(600).is_empty());
        assert!(store.extend(&code, 5, 700).is_err());
        assert!(store.create_coupons(1, 0, TimeMode::Real, 1, 0).is_err());
    }

    #[test]
    fn connection_history() {
        let mut store = PortalStore::default();
        let code = store.create_coupons(1, 60, TimeMode::Real, 1, 0).unwrap()[0].code.clone();
        store.redeem(&form(&code), MAC_A, 10).unwrap();
        let here: HashSet<String> = [MAC_A.to_string()].into();
        store.tick(20, 10, &here);
        store.tick(30, 10, &HashSet::new());
        store.tick(40, 10, &here);
        let (_, views) = store.views(40);
        let visits: Vec<(u64, bool)> = views[0].history.iter().map(|v| (v.at, v.connected)).collect();
        assert_eq!(visits, [(10, true), (30, false), (40, true)]);
        assert!(views[0].online && views[0].last_seen == Some(40) && views[0].state == SessionState::Active);
        store.tick(3610, 0, &here);
        let (_, views) = store.views(3610);
        assert_eq!((views[0].state, views[0].online), (SessionState::Expired, false));
        assert_eq!(views[0].history.last().map(|v| v.connected), Some(false));
    }

    #[test]
    fn topping_up_leaves_the_old_coupon() {
        let mut store = PortalStore::default();
        let codes: Vec<String> = store.create_coupons(2, 30, TimeMode::Connected, 1, 0).unwrap().into_iter().map(|c| c.code).collect();
        store.redeem(&form(&codes[0]), MAC_A, 0).unwrap();
        store.redeem(&form(&codes[1]), MAC_A, 100).unwrap();
        let here: HashSet<String> = [MAC_A.to_string()].into();
        store.tick(102, 60, &here);
        assert_eq!((store.coupons[0].used_secs, store.coupons[1].used_secs), (0, 60));
    }

    #[test]
    fn store_round_trip_and_file_names() {
        let dir = std::env::temp_dir().join(format!("hs-portal-{}", std::process::id()));
        let path = dir.join("p.json");
        let mut store = PortalStore::default();
        store.create_coupons(3, 30, TimeMode::Real, 1, 0).unwrap();
        store.save(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(PortalStore::load(&path).unwrap().coupons.len(), 3);
        fs::remove_dir_all(&dir).unwrap();
        assert!(store_path(Path::new("/x"), "../etc").ends_with("2e2e2f657463.json"));
    }
}
