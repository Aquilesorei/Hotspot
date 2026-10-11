use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use super::profile::offset;
use crate::constants::{DHCP_FIRST, DHCP_LAST, DNSMASQ_LEASES};
use super::ProfileKind;
use super::HotspotProfile;

#[derive(Debug, Clone)]
pub struct DnsmasqArgs {
    pub iface: String,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub upstream_dns: Vec<IpAddr>,
    pub leasefile: PathBuf,
    /// Portal networks: `PORTAL_HOSTNAME` resolves to this gateway.
    pub portal_gateway: Option<Ipv4Addr>,
}

impl DnsmasqArgs {
    pub fn new(p: &HotspotProfile, ap: &str, runtime_dir: &Path) -> Self {
        Self {
            iface: ap.into(),
            range_start: offset(p.subnet.network(), DHCP_FIRST),
            range_end: offset(p.subnet.network(), DHCP_LAST),
            upstream_dns: p.upstream_dns.clone(),
            leasefile: runtime_dir.join(DNSMASQ_LEASES),
            portal_gateway: (p.kind == ProfileKind::Portal).then(|| p.gateway()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_range() {
        let p = HotspotProfile::new("maison", "T", "motdepasse");
        let a = DnsmasqArgs::new(&p, "ap0", Path::new("/run/x"));
        assert_eq!(a.range_start, Ipv4Addr::new(192, 168, 12, 10));
        assert_eq!(a.range_end, Ipv4Addr::new(192, 168, 12, 100));
        assert_eq!(p.gateway_cidr(), "192.168.12.1/24");
        assert_eq!(a.portal_gateway, None);
        let portal = DnsmasqArgs::new(&HotspotProfile::new_portal("cafe", "Cafe"), "ap0", Path::new("/run/x"));
        assert_eq!(portal.portal_gateway, Some(Ipv4Addr::new(192, 168, 12, 1)));
    }
}
