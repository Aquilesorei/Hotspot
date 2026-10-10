use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::constants::{BAND_5GHZ_MIN_MHZ, DEFAULT_DNS, DEFAULT_SUBNET, PASSPHRASE_LEN, PROFILES_FILE, SSID_LEN};
use super::normalize_mac;
use crate::error::{HotspotError as E, Result};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotProfile {
    pub name: String,
    pub ssid: String,
    pub passphrase: String,
    #[serde(default = "default_subnet")]
    pub subnet: Ipv4Net,
    #[serde(default = "default_dns")]
    pub upstream_dns: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<String>,
}

fn default_subnet() -> Ipv4Net { DEFAULT_SUBNET.parse().unwrap() }
fn default_dns() -> Vec<IpAddr> { vec![IpAddr::V4(DEFAULT_DNS)] }
impl HotspotProfile {
    pub fn new(name: &str, ssid: &str, passphrase: &str) -> Self {
        Self {
            name: name.into(),
            ssid: ssid.into(),
            passphrase: passphrase.into(),
            subnet: default_subnet(),
            upstream_dns: default_dns(),
            blocked: Vec::new(),
        }
    }



    pub fn validate(&self) -> Result<()> {
        self.validate_ssid()?;
        self.validate_passphrase()?;
        for mac in &self.blocked {
            normalize_mac(mac)?;
        }

        if self.name.trim().is_empty() {
            return Err(E::invalid_profile("profile name is required"));
        }
        if self.name == self.ssid {
            return Err(E::invalid_profile("profile name must differ from the SSID"));
        }
        if self.subnet.prefix_len() != 24 {
            return Err(E::invalid_profile("subnet: only /24 is supported in v1"));
        }
        if self.upstream_dns.is_empty() {
            return Err(E::invalid_profile("at least one upstream DNS server is required"));
        }
        Ok(())
    }

    fn validate_ssid(&self) -> Result<()> {

        if !SSID_LEN.contains(&self.ssid.len()) {
            return Err(E::invalid_profile(format!("SSID: {} to {} bytes", SSID_LEN.start(), SSID_LEN.end())));
        }
        if self.ssid.chars().any(char::is_control) {
            return Err(E::invalid_profile("SSID: control characters are not allowed"));
        }
        Ok(())
    }

    fn validate_passphrase(&self) -> Result<()> {
        let len_ok = PASSPHRASE_LEN.contains(&self.passphrase.len());
        let printable_ascii = self.passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b));

        if !(len_ok && printable_ascii) {
            return Err(E::invalid_profile(format!(
                "passphrase: {} to {} printable ASCII characters",
                PASSPHRASE_LEN.start(),
                PASSPHRASE_LEN.end()
            )));
        }
        Ok(())
    }

    pub fn gateway(&self) -> Ipv4Addr { offset(self.subnet.network(), 1) }

    pub fn gateway_cidr(&self) -> String { format!("{}/{}", self.gateway(), self.subnet.prefix_len()) }


    /// `ctrl_dir`: control socket directory used by `hostapd_cli`.
    pub fn hostapd_conf(&self, ap: &str, channel: u32, freq_mhz: u32, ctrl_dir: &Path) -> String {
        let hw_mode = if freq_mhz < BAND_5GHZ_MIN_MHZ { "g" } else { "a" };
        format!(
            "interface={ap}\ndriver=nl80211\nssid={}\nhw_mode={hw_mode}\nchannel={channel}\nieee80211n=1\n\
             wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={}\nctrl_interface={}\n",
            self.ssid,
            self.passphrase,
            ctrl_dir.display()
        )
    }
}

pub(crate) fn offset(a: Ipv4Addr, n: u32) -> Ipv4Addr { Ipv4Addr::from(u32::from(a) + n) }

/// The user behind sudo or pkexec, from /etc/passwd (name:x:uid:gid:gecos:home:shell).
fn invoking_passwd() -> Option<Vec<String>> {
    let (value, field) = [("SUDO_USER", 0), ("PKEXEC_UID", 2)]
        .into_iter()
        .find_map(|(var, field)| std::env::var(var).ok().map(|v| (v, field)))?;
    fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .map(|l| l.split(':').map(String::from).collect::<Vec<_>>())
        .find(|f| f.get(field) == Some(&value))
}

pub fn invoking_user() -> Option<String> {
    invoking_passwd().map(|f| f[0].clone())
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileStore {
    #[serde(default, rename = "profile")]
    profiles: Vec<HotspotProfile>,
}

impl ProfileStore {
    pub fn store(name: &str, ssid: &str, passphrase: &str, path: Option<&Path>) -> Result<PathBuf> {
        Self::upsert(Some(name), HotspotProfile::new(name, ssid, passphrase), path)
    }

    /// Replaces the profile `old_name` (renaming it if `p.name` differs), or adds `p` when `old_name` is None.
    pub fn upsert(old_name: Option<&str>, p: HotspotProfile, path: Option<&Path>) -> Result<PathBuf> {
        p.validate()?;
        let path = Self::resolve(path)?;
        let mut s = Self::load(&path)?;
        if Some(p.name.as_str()) != old_name && s.profiles.iter().any(|q| q.name == p.name) {
            return Err(E::ProfileExists(p.name));
        }
        match s.profiles.iter().position(|q| Some(q.name.as_str()) == old_name) {
            Some(i) => s.profiles[i] = p,
            None => s.profiles.push(p),
        }
        s.save(&path)?;
        Ok(path)
    }

    pub fn delete(name: &str, path: Option<&Path>) -> Result<()> {
        let path = Self::resolve(path)?;
        let mut s = Self::load(&path)?;
        let before = s.profiles.len();
        s.profiles.retain(|q| q.name != name);
        if s.profiles.len() == before {
            return Err(E::ProfileNotFound(name.into()));
        }
        s.save(&path)
    }

    /// By name, otherwise by SSID.
    pub fn get(key: &str, path: Option<&Path>) -> Result<HotspotProfile> {
        let profiles = Self::list(path)?;
        if let Some(p) = profiles.iter().find(|p| p.name == key) {
            return Ok(p.clone());
        }
        let mut by_ssid = profiles.into_iter().filter(|p| p.ssid == key);
        match (by_ssid.next(), by_ssid.next()) {
            (Some(p), None) => Ok(p),
            (Some(_), Some(_)) => Err(E::invalid_profile(format!(
                "several profiles have SSID {key}: use the profile name"
            ))),
            _ => Err(E::ProfileNotFound(key.into())),
        }
    }

    pub fn list(path: Option<&Path>) -> Result<Vec<HotspotProfile>> {
        Ok(Self::load(&Self::resolve(path)?)?.profiles)
    }

    fn resolve(path: Option<&Path>) -> Result<PathBuf> {
        if let Some(p) = path {
            return Ok(p.into());
        }
        // under sudo or pkexec, HOME is /root
        let home = invoking_passwd()
            .and_then(|f| f.get(5).cloned())
            .or_else(|| std::env::var("HOME").ok())
            .ok_or_else(|| E::invalid_profile("HOME not found"))?;
        Ok(PathBuf::from(home).join(PROFILES_FILE))
    }

    fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(E::invalid_profile),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// 0600: the passphrase is stored in plain text.
    fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let s = toml::to_string(self).map_err(E::invalid_profile)?;
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(s.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(ssid: &str, pass: &str) -> HotspotProfile { HotspotProfile::new("maison", ssid, pass) }

    #[test]
    fn validation() {
        assert!(p(&"a".repeat(32), "motdepasse").validate().is_ok());
        assert!(p(&"a".repeat(33), "motdepasse").validate().is_err());
        assert!(p(&"é".repeat(16), "motdepasse").validate().is_ok());
        assert!(p(&"é".repeat(17), "motdepasse").validate().is_err());
        assert!(p("Test", &"x".repeat(7)).validate().is_err());
        assert!(p("Test", &"x".repeat(8)).validate().is_ok());
        assert!(p("Test", &"x".repeat(63)).validate().is_ok());
        assert!(p("Test", &"x".repeat(64)).validate().is_err());
        assert!(p("Test\nchannel=1", "motdepasse").validate().is_err());
        assert!(p("Test", "motde\npasse").validate().is_err());
        assert!(p("maison", "motdepasse").validate().is_err());
    }

    #[test]
    fn hostapd_mode_follows_freq() {
        assert!(p("T", "motdepasse").hostapd_conf("ap0", 4, 2427, Path::new("/run/x/hostapd")).contains("hw_mode=g\nchannel=4\n"));
        assert!(p("T", "motdepasse").hostapd_conf("ap0", 149, 5745, Path::new("/run/x/hostapd")).contains("hw_mode=a\nchannel=149\n"));
    }

    #[test]
    fn toml_defaults() {
        let s: ProfileStore = toml::from_str("[[profile]]\nname='m'\nssid='TestHS'\npassphrase='motdepasse123'\n").unwrap();
        assert_eq!(s.profiles[0].gateway_cidr(), "192.168.12.1/24");
    }

    #[test]
    fn profile_store() {
        let f = std::env::temp_dir().join(format!("hs-profiles-{}.toml", std::process::id()));
        let path = Some(f.as_path());
        assert_eq!(ProfileStore::store("maison", "TestHS", "motdepasse123", path).unwrap(), f);
        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        ProfileStore::store("maison", "TestHS2", "motdepasse123", path).unwrap();
        ProfileStore::store("bureau", "Office", "motdepasse123", path).unwrap();
        assert!(ProfileStore::store("x", "S", "court", path).is_err());

        assert_eq!(ProfileStore::list(path).unwrap().len(), 2);
        assert_eq!(ProfileStore::get("maison", path).unwrap().ssid, "TestHS2");
        assert_eq!(ProfileStore::get("Office", path).unwrap().name, "bureau");
        assert!(matches!(ProfileStore::get("nope", path), Err(E::ProfileNotFound(_))));

        ProfileStore::store("bureau2", "Office", "motdepasse123", path).unwrap();
        assert!(matches!(ProfileStore::get("Office", path), Err(E::InvalidProfile(_))));

        let renamed = HotspotProfile::new("office", "Office", "motdepasse123");
        ProfileStore::upsert(Some("bureau"), renamed.clone(), path).unwrap();
        assert!(matches!(ProfileStore::get("bureau", path), Err(E::ProfileNotFound(_))));
        assert!(matches!(ProfileStore::upsert(Some("bureau2"), renamed.clone(), path), Err(E::ProfileExists(_))));
        assert!(matches!(ProfileStore::upsert(None, renamed, path), Err(E::ProfileExists(_))));

        ProfileStore::delete("office", path).unwrap();
        assert!(matches!(ProfileStore::delete("office", path), Err(E::ProfileNotFound(_))));
        assert_eq!(ProfileStore::list(path).unwrap().len(), 2);
        fs::remove_file(&f).unwrap();
    }
}
