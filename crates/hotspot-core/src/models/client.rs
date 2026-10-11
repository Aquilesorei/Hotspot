use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{HotspotError, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Client {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub connected_secs: u64,
    pub internet_cut: bool,
    pub down_bytes: u64,
    pub up_bytes: u64,
    /// Temporary access: the device gets blocked when this reaches 0.
    pub expires_in_secs: Option<u64>,
    pub speed_limit_mbps: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "BlockedRepr")]
pub struct BlockedDevice {
    pub mac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Profiles written before names were kept store a bare MAC string.
#[derive(Deserialize)]
#[serde(untagged)]
enum BlockedRepr {
    Mac(String),
    Full { mac: String, name: Option<String> },
}

impl From<BlockedRepr> for BlockedDevice {
    fn from(r: BlockedRepr) -> Self {
        match r {
            BlockedRepr::Mac(mac) => Self { mac, name: None },
            BlockedRepr::Full { mac, name } => Self { mac, name },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceUsage {
    pub mac: String,
    pub down_bytes: u64,
    pub up_bytes: u64,
}

/// What happened while the hotspot runs, for the CLI (text) and the UI (JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Restarted { channel: u32, freq_mhz: u32 },
    UplinkLost { iface: String },
    WrongPassword { mac: String },
    Clients { clients: Vec<Client> },
    InternetCutAll { cut: bool },
    Usage { usage: Vec<DeviceUsage> },
    AccessExpired { mac: String },
    /// The profile's blocked list changed: the caller saves it to the profile file.
    BlockedChanged { blocked: Vec<BlockedDevice> },
    Error { message: String },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Restarted { channel, freq_mhz } => write!(
                f,
                "uplink moved to channel {channel} ({freq_mhz} MHz): hotspot restarted, clients were disconnected"
            ),
            Event::UplinkLost { iface } => write!(f, "uplink {iface} lost: hotspot stopped"),
            Event::WrongPassword { mac } => {
                write!(f, "{mac} used the wrong password: forget the network on the device, then reconnect")
            }
            Event::Clients { clients } => {
                let list: Vec<String> = clients
                    .iter()
                    .map(|c| {
                        let ip = c.ip.as_deref().map(|ip| format!(", {ip}")).unwrap_or_default();
                        let cut = if c.internet_cut { ", internet cut" } else { "" };
                        format!("{} ({}{ip}{cut})", c.hostname.as_deref().unwrap_or("unknown"), c.mac)
                    })
                    .collect();
                if list.is_empty() {
                    write!(f, "clients: none")
                } else {
                    write!(f, "clients: {}", list.join(", "))
                }
            }
            Event::Usage { usage } => {
                let list: Vec<String> =
                    usage.iter().map(|u| format!("{} ↓{} ↑{}", u.mac, u.down_bytes, u.up_bytes)).collect();
                write!(f, "usage: {}", list.join(", "))
            }
            Event::AccessExpired { mac } => write!(f, "{mac}: temporary access expired, device blocked"),
            Event::InternetCutAll { cut: true } => write!(f, "internet cut for every client"),
            Event::InternetCutAll { cut: false } => write!(f, "internet restored for every client"),
            Event::BlockedChanged { blocked } => {
                let list: Vec<String> = blocked
                    .iter()
                    .map(|b| b.name.as_ref().map_or(b.mac.clone(), |n| format!("{n} ({})", b.mac)))
                    .collect();
                if list.is_empty() {
                    write!(f, "blocked: none")
                } else {
                    write!(f, "blocked: {}", list.join(", "))
                }
            }
            Event::Error { message } => write!(f, "error: {message}"),
        }
    }
}

/// Orders sent to a running hotspot. `mac: None` means every client.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Stop,
    CutInternet { mac: Option<String> },
    RestoreInternet { mac: Option<String> },
    Block { mac: String },
    Unblock { mac: String },
    /// `minutes: None` removes the time limit.
    AllowFor { mac: String, minutes: Option<u32> },
    /// `mbps: None` removes the limit.
    LimitSpeed { mac: String, mbps: Option<u32> },
}

/// Lowercase `aa:bb:cc:dd:ee:ff`. Rejects anything else: the value ends up in an nft command.
pub fn normalize_mac(s: &str) -> Result<String> {
    let mac = s.trim().to_ascii_lowercase();
    let groups: Vec<&str> = mac.split(':').collect();
    let valid = groups.len() == 6 && groups.iter().all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()));
    if valid {
        Ok(mac)
    } else {
        Err(HotspotError::InvalidMac(s.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_validation() {
        assert_eq!(normalize_mac(" 34:C9:3D:79:C4:67 ").unwrap(), "34:c9:3d:79:c4:67");
        for bad in ["34:c9:3d:79:c4", "34:c9:3d:79:c4:6g", "34-c9-3d-79-c4-67", "34:c9:3d:79:c4:67 } drop", ""] {
            assert!(normalize_mac(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn events_to_json() {
        let e = Event::WrongPassword { mac: "12:5a:7a:56:8a:d6".into() };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"event":"wrong_password","mac":"12:5a:7a:56:8a:d6"}"#);
        let c = Client { mac: "aa:bb:cc:dd:ee:ff".into(), hostname: None, ip: None, connected_secs: 5, internet_cut: true, ..Default::default() };
        let e = serde_json::to_value(Event::Clients { clients: vec![c] }).unwrap();
        assert_eq!(e["event"], "clients");
        assert_eq!(e["clients"][0]["internet_cut"], true);
    }

    #[test]
    fn blocked_list_reads_old_and_new_format() {
        #[derive(Deserialize)]
        struct P {
            blocked: Vec<BlockedDevice>,
        }
        let p: P = toml::from_str(r#"blocked = ["aa:bb:cc:dd:ee:ff", { mac = "12:5a:7a:56:8a:d6", name = "REDMI" }]"#).unwrap();
        assert_eq!(p.blocked[0], BlockedDevice { mac: "aa:bb:cc:dd:ee:ff".into(), name: None });
        assert_eq!(p.blocked[1].name.as_deref(), Some("REDMI"));
    }

    #[test]
    fn commands_from_json() {
        let c: Command = serde_json::from_str(r#"{"cmd":"cut_internet","mac":"34:c9:3d:79:c4:67"}"#).unwrap();
        assert_eq!(c, Command::CutInternet { mac: Some("34:c9:3d:79:c4:67".into()) });
        let c: Command = serde_json::from_str(r#"{"cmd":"restore_internet","mac":null}"#).unwrap();
        assert_eq!(c, Command::RestoreInternet { mac: None });
    }
}
