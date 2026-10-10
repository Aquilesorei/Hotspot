use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{HotspotError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Client {
    pub mac: String,
    pub hostname: Option<String>,
    pub connected_secs: u64,
    pub internet_cut: bool,
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
    /// The profile's blocked list changed: the caller saves it to the profile file.
    BlockedChanged { blocked: Vec<String> },
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
                        let cut = if c.internet_cut { ", internet cut" } else { "" };
                        format!("{} ({}{cut})", c.hostname.as_deref().unwrap_or("unknown"), c.mac)
                    })
                    .collect();
                if list.is_empty() {
                    write!(f, "clients: none")
                } else {
                    write!(f, "clients: {}", list.join(", "))
                }
            }
            Event::InternetCutAll { cut: true } => write!(f, "internet cut for every client"),
            Event::InternetCutAll { cut: false } => write!(f, "internet restored for every client"),
            Event::BlockedChanged { blocked } => write!(f, "blocked: {}", blocked.join(", ")),
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
        let c = Client { mac: "aa:bb:cc:dd:ee:ff".into(), hostname: None, connected_secs: 5, internet_cut: true };
        let e = serde_json::to_value(Event::Clients { clients: vec![c] }).unwrap();
        assert_eq!(e["event"], "clients");
        assert_eq!(e["clients"][0]["internet_cut"], true);
    }

    #[test]
    fn commands_from_json() {
        let c: Command = serde_json::from_str(r#"{"cmd":"cut_internet","mac":"34:c9:3d:79:c4:67"}"#).unwrap();
        assert_eq!(c, Command::CutInternet { mac: Some("34:c9:3d:79:c4:67".into()) });
        let c: Command = serde_json::from_str(r#"{"cmd":"restore_internet","mac":null}"#).unwrap();
        assert_eq!(c, Command::RestoreInternet { mac: None });
    }
}
