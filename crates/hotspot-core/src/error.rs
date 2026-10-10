pub type Result<T> = std::result::Result<T, HotspotError>;

#[derive(thiserror::Error, Debug)]
pub enum HotspotError {
    #[error("root privileges required")]
    NotRoot,

    #[error("hotspot already running")]
    AlreadyRunning,

    #[error("hotspot is not running")]
    NotRunning,

    #[error("invalid MAC address: {0}")]
    InvalidMac(String),

    #[error("a profile named {0} already exists")]
    ProfileExists(String),

    #[error("no Wi-Fi interface found")]
    NoWifiInterface,

    #[error("interface {0} is not connected to a network")]
    UplinkNotConnected(String),

    #[error("channel {channel} ({freq_mhz} MHz) is disabled in this region")]
    ChannelNotAllowedForAp { channel: u32, freq_mhz: u32 },

    #[error("the Wi-Fi card does not support concurrent AP+STA")]
    ConcurrentApStaUnsupported,

    #[error("failed to create AP interface: {0}")]
    ApIfaceCreateFailed(String),

    #[error("hostapd failed:\n{0}")]
    HostapdFailed(String),

    #[error("hostapd did not report AP-ENABLED in time")]
    HostapdTimeout,

    #[error("dnsmasq failed:\n{0}")]
    DnsmasqFailed(String),

    #[error("firewall error ({tool}): {msg}")]
    FirewallError { tool: String, msg: String },

    #[error("profile {0} not found")]
    ProfileNotFound(String),

    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("command `{cmd}` failed: {stderr}")]
    CommandFailed { cmd: String, stderr: String },
}

impl HotspotError {
    pub fn command(cmd: impl Into<String>, stderr: impl ToString) -> Self {
        Self::CommandFailed { cmd: cmd.into(), stderr: stderr.to_string() }
    }

    pub fn firewall(tool: impl Into<String>, msg: impl ToString) -> Self {
        Self::FirewallError { tool: tool.into(), msg: msg.to_string() }
    }

    pub fn invalid_profile(msg: impl ToString) -> Self {
        Self::InvalidProfile(msg.to_string())
    }
}
