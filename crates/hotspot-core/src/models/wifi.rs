use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct WifiAdapter(String);

impl WifiAdapter {
    pub fn new(kernel_name: impl Into<String>) -> Self { Self(kernel_name.into()) }
    pub fn name(&self) -> &str { &self.0 }
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkInfo {
    pub iface: String,
    pub wifi_adapter: WifiAdapter,
    pub channel: u32,
    pub freq_mhz: u32,
    pub width_mhz: Option<u32>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub number: u32,
    pub freq_mhz: u32,
    pub no_ir: bool,
    pub radar: bool,
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelClass { Free, Restricted, Disabled }

impl ChannelInfo {
    pub fn class(&self) -> ChannelClass {
        if self.disabled { ChannelClass::Disabled }
        else if self.no_ir || self.radar { ChannelClass::Restricted }
        else { ChannelClass::Free }
    }
}

#[derive(Debug, Clone)]
pub struct PhyCaps {
    pub channels: Vec<ChannelInfo>,
    pub ap_sta: bool,
}

/// Read-only look at the upstream and the card, usable without root (before starting).
#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    pub uplink: UplinkInfo,
    pub ap_sta: bool,
}
