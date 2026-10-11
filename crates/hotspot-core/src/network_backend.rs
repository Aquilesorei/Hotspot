use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::path::Path;
use std::process::Child;

use crate::error::Result;
use crate::portal_http::{PageInfo, PortalRequest, PortalServer};
use crate::models::{DnsmasqArgs, PhyCaps, UplinkInfo, WifiAdapter};

pub trait NetworkBackend {
    fn detect_wifi_iface(&self) -> Result<String>;
    fn uplink_info(&self, iface: &str) -> Result<UplinkInfo>;
    fn adapter_caps(&self, adapter: &WifiAdapter) -> Result<PhyCaps>;

    fn ensure_unmanaged_conf(&self) -> Result<()>;


    fn is_root(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
    }

    fn create_ap_iface(&self, base: &str, ap: &str) -> Result<()>;
    fn delete_ap_iface(&self, ap: &str) -> Result<()>;
    fn link_up(&self, iface: &str) -> Result<()>;
    fn add_addr(&self, iface: &str, cidr: &str) -> Result<()>;

    fn get_ip_forward(&self) -> Result<bool>;
    fn set_ip_forward(&self, on: bool) -> Result<()>;

    fn firewalld_running(&self) -> bool;
    fn firewalld_add_iface(&self, zone: &str, iface: &str) -> Result<()>;
    fn firewalld_remove_iface(&self, zone: &str, iface: &str) -> Result<()>;
    fn firewalld_zone_of(&self, iface: &str) -> Option<String>;
    fn nft_install_nat(&self, uplink: &str) -> Result<()>;
    fn nft_remove_nat(&self) -> Result<()>;
    /// Drops forwarded traffic coming from `iface` (every client).
    fn nft_cut_iface(&self, iface: &str, cut: bool) -> Result<()>;
    /// Drops forwarded traffic from one client. `mac` must be normalized.
    fn nft_cut_mac(&self, mac: &str, cut: bool) -> Result<()>;
    fn nft_nat_present(&self) -> bool;
    /// Captive portal on `ap`: devices not in the allowed set only reach DHCP, DNS and the portal
    /// (their HTTP goes to `gateway:port`). Goes in our NAT table, so it disappears with it.
    fn nft_install_portal(&self, ap: &str, gateway: &str, port: u16) -> Result<()>;
    /// `mac` must be normalized.
    fn nft_portal_allow(&self, mac: &str, allow: bool) -> Result<()>;
    /// MAC of a neighbour IP on `ap`, from the kernel's ARP table.
    fn mac_of(&self, ap: &str, ip: &str) -> Option<String>;
    /// Starts the portal's web server; `None` where there is no network (tests).
    fn serve_portal(&self, addr: SocketAddr, page: PageInfo, requests: Sender<PortalRequest>) -> Result<Option<PortalServer>>;
    /// Bytes forwarded to and from each client IP since the table was created: ip -> (down, up).
    fn nft_usage(&self) -> Result<HashMap<String, (u64, u64)>>;
    /// Replaces every speed limit on `ap` with `limits` (client IP, Mbit/s), down and up.
    fn tc_limits(&self, ap: &str, limits: &[(String, u32)]) -> Result<()>;
    fn forward_blocked(&self) -> bool;

    fn iptables(&self, args: &[&str]) -> Result<bool>;

    fn spawn_hostapd(&self, conf: &Path) -> Result<Child>;
    /// Refuses `mac` and disconnects it now, or lets it join again. Uses hostapd's control socket in `ctrl_dir`.
    fn block_client(&self, ctrl_dir: &Path, ap: &str, mac: &str, block: bool) -> Result<()>;
    fn spawn_dnsmasq(&self, args: &DnsmasqArgs) -> Result<Child>;

    /// Checks /proc/<pid>/cmdline too: the pid may have been reused by another program.
    fn is_running(&self, pid: u32, name: &str) -> bool;
    fn stop_process(&self, pid: u32, name: &str);
    fn pgrep(&self, pattern: &str) -> Vec<u32>;
}
