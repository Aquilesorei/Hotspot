use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::time::Duration;

pub(crate) mod bin {
    pub const NMCLI: &str = "nmcli";
    pub const IW: &str = "iw";
    pub const IP: &str = "ip";
    pub const FIREWALL_CMD: &str = "firewall-cmd";
    pub const NFT: &str = "nft";
    pub const IPTABLES: &str = "iptables";
    pub const HOSTAPD: &str = "hostapd";
    pub const HOSTAPD_CLI: &str = "hostapd_cli";
    pub const DNSMASQ: &str = "dnsmasq";
    pub const KILL: &str = "kill";
    pub const PGREP: &str = "pgrep";
    pub const TC: &str = "tc";
}

// System
pub const RUNTIME_DIR: &str = "/run/hotspot-core";
/// The background service's socket. Members of `SERVICE_GROUP` may use it.
pub const CONTROL_SOCKET: &str = "/run/hotspot.sock";
pub const SERVICE_GROUP: &str = "hotspot";
pub(crate) const HOSTAPD_CONF: &str = "hostapd.conf";
pub(crate) const HOSTAPD_CTRL: &str = "hostapd";
pub(crate) const DNSMASQ_LEASES: &str = "dnsmasq.leases";
pub(crate) const STATE_FILE: &str = "state.json";
pub(crate) const PROFILES_FILE: &str = ".config/hotspot/profiles.toml";
pub(crate) const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
pub(crate) const NM_UNMANAGED_CONF_PATH: &str = "/etc/NetworkManager/conf.d/99-ap0-unmanaged.conf";

// Network
pub(crate) const AP_IFACE: &str = "ap0";
pub(crate) const FIREWALLD_ZONE: &str = "trusted";
pub(crate) const NAT_TABLE: &str = "hsnat";
pub(crate) const FWD_CHAIN: &str = "clients";
pub(crate) const INPUT_CHAIN: &str = "host_input";
pub(crate) const CUT_IFACES_SET: &str = "cut_ifaces";
pub(crate) const CUT_MACS_SET: &str = "cut_macs";
pub(crate) const USAGE_DOWN_SET: &str = "usage_down";
pub(crate) const USAGE_UP_SET: &str = "usage_up";
pub(crate) const DOCKER_USER: &str = "DOCKER-USER";
pub(crate) const DEFAULT_SUBNET: &str = "192.168.12.0/24";
pub(crate) const DEFAULT_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
pub(crate) const DHCP_FIRST: u32 = 10;
pub(crate) const DHCP_LAST: u32 = 100;
pub(crate) const DHCP_LEASE: &str = "12h";
pub(crate) const BAND_5GHZ_MIN_MHZ: u32 = 3000;

// hostapd events (stdout)
pub(crate) const AP_ENABLED: &str = "AP-ENABLED";
pub(crate) const AP_STA_CONNECTED: &str = "AP-STA-CONNECTED";
pub(crate) const AP_STA_DISCONNECTED: &str = "AP-STA-DISCONNECTED";
pub(crate) const AP_STA_PSK_MISMATCH: &str = "AP-STA-POSSIBLE-PSK-MISMATCH";

// dnsmasq log: `DHCPACK(ap0) <ip> <mac> [hostname]`
pub(crate) const DHCPACK: &str = "DHCPACK(";

// Profile validation
pub(crate) const SSID_LEN: RangeInclusive<usize> = 1..=32;
pub(crate) const PASSPHRASE_LEN: RangeInclusive<usize> = 8..=63;
pub(crate) const MAX_CLIENTS: RangeInclusive<u32> = 1..=255;

// Captive portal
pub(crate) const PORTAL_DEFAULT_COUNTRY_CODE: &str = "+91";
/// 10/15/30 min, 1/2/3/5 h, 1/3 days, 1 week, 1/6 months, 1 year (a month counts 30 days).
pub(crate) const PORTAL_DEFAULT_DURATIONS_MIN: [u64; 13] =
    [10, 15, 30, 60, 120, 180, 300, 1440, 4320, 10080, 43200, 259200, 525600];
pub(crate) const PORTAL_MAX_DURATION_MIN: u64 = 5 * 525600;
pub(crate) const PORTAL_DEVICES_PER_COUPON: RangeInclusive<u32> = 1..=32;
pub(crate) const PORTAL_DIR: &str = "/var/lib/hotspot/portal";
pub(crate) const PORTAL_PORT: u16 = 8080;
/// Resolved by dnsmasq to the gateway on portal networks. `.internal` is reserved by ICANN for
/// private networks: browsers open it instead of searching for it, and it never hits a real site.
pub const PORTAL_HOSTNAME: &str = "wifi.internal";
pub(crate) const PORTAL_MAX_FAILURES: u32 = 5;
pub(crate) const PORTAL_LOCKOUT: Duration = Duration::from_secs(10 * 60);
/// Connected-time accounting changes every tick: persist it at this pace (state changes save at once).
pub(crate) const PORTAL_SAVE_EVERY: Duration = Duration::from_secs(30);
pub(crate) const PORTAL_ALLOWED_SET: &str = "portal_allowed";
pub(crate) const PORTAL_CHAIN: &str = "portal_redirect";
pub(crate) const ARP_TABLE: &str = "/proc/net/arp";
/// Names and phone numbers are erased this long after a session ends.
pub(crate) const PORTAL_PURGE_AFTER_SECS: u64 = 30 * 24 * 3600;
/// Connections and disconnections kept per session; older ones are dropped.
pub(crate) const PORTAL_HISTORY_MAX: usize = 200;
pub(crate) const COUPON_CODE_LEN: usize = 8;
pub(crate) const NAME_MAX_CHARS: usize = 64;
/// National number length, without the country code.
pub(crate) const PHONE_DIGITS: RangeInclusive<usize> = 4..=14;
pub(crate) const SPEED_LIMIT_MBPS: RangeInclusive<u32> = 1..=1000;
pub(crate) const GUEST_MINUTES: RangeInclusive<u32> = 1..=24 * 60;
pub(crate) const GENERATED_PASSPHRASE_LEN: usize = 16;
/// No 0/O, 1/l/I: generated passwords get typed by hand on phones.
pub(crate) const PASSPHRASE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// Timeouts and limits
pub(crate) const TICK: Duration = Duration::from_secs(2);
pub(crate) const HOSTAPD_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DNSMASQ_STARTUP: Duration = Duration::from_millis(500);
pub(crate) const KILL_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const KILL_POLL: Duration = Duration::from_millis(100);
pub(crate) const RESTART_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const MAX_RESTARTS: usize = 3;
pub(crate) const LOG_LINES: usize = 20;
/// Byte counters change all the time: report them at this pace, not on every tick.
pub(crate) const USAGE_REPORT_EVERY: Duration = Duration::from_secs(10);
