use serde::Serialize;

use super::{BlockedDevice, Client, UplinkInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HotspotState { Stopped, Running, Failed }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Forwarding { Ok, Unverified { reason: String } }

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub state: HotspotState,
    pub uplink: Option<UplinkInfo>,
    pub ap_channel: Option<u32>,
    pub clients: Vec<Client>,
    pub internet_cut_all: bool,
    pub blocked: Vec<BlockedDevice>,
    pub forwarding: Forwarding,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.uplink {
            Some(up) => write!(
                f,
                "{:?} on channel {} ({} MHz), uplink {} ({})",
                self.state,
                up.channel,
                up.freq_mhz,
                up.iface,
                up.ssid.as_deref().unwrap_or("?")
            )?,
            None => write!(f, "{:?}", self.state)?,
        }
        if let Forwarding::Unverified { reason } = &self.forwarding {
            write!(f, "\nwarning: internet access for clients is not guaranteed ({reason})")?;
        }
        Ok(())
    }
}
