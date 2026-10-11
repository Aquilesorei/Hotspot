use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::path::Path;
use std::process::{Child, Stdio};
use std::thread::sleep;
use std::time::Instant;

use crate::network_backend::NetworkBackend;
use crate::error::{HotspotError, Result};
use crate::models::{DnsmasqArgs, PhyCaps, UplinkInfo, WifiAdapter};
use crate::parse;
use crate::portal_http::{PageInfo, PortalRequest, PortalServer};
use crate::constants::{PORTAL_HOSTNAME, 
    bin, AP_IFACE, ARP_TABLE, CUT_IFACES_SET, CUT_MACS_SET, PORTAL_ALLOWED_SET, PORTAL_CHAIN, USAGE_DOWN_SET, USAGE_UP_SET, DHCP_LEASE, FWD_CHAIN, INPUT_CHAIN, IP_FORWARD, KILL_POLL, KILL_TIMEOUT, NAT_TABLE,
    NM_UNMANAGED_CONF_PATH,
};
use crate::runner::{command, run, run_ok, run_unit, succeeds};

pub struct SystemBackend;

fn fw_run(tool: &str, args: &[&str]) -> Result<()> {
    run_unit(tool, args).map_err(|e| HotspotError::firewall(tool, e))
}

fn firewalld_iface(op: &str, zone: &str, iface: &str) -> Result<()> {
    fw_run(bin::FIREWALL_CMD, &[&format!("--zone={zone}"), &format!("--{op}-interface={iface}")])
}

fn spawn(program: &str, args: &[String]) -> Result<Child> {
    Ok(command(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn nm_unmanaged_conf() -> String {
    format!("[keyfile]\nunmanaged-devices=interface-name:{AP_IFACE}\n")
}


fn install_unmanaged_conf(conf_path: &Path) -> Result<bool> {
    let conf = nm_unmanaged_conf();
    if fs::read_to_string(conf_path).is_ok_and(|current| current == conf) {
        return Ok(false);
    }
    fs::write(conf_path, conf)
        .map_err(|e| HotspotError::command(format!("write {}", conf_path.display()), e))?;
    run_ok(bin::NMCLI, &["general", "reload", "conf"])?;
    Ok(true)
}

fn nft_set_element(set: &str, value: &str, add: bool) -> Result<()> {
    let op = if add { "add" } else { "delete" };
    fw_run(bin::NFT, &[op, "element", "ip", NAT_TABLE, set, "{", value, "}"])
}

fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z')))
}

impl NetworkBackend for SystemBackend {
    fn detect_wifi_iface(&self) -> Result<String> {
        let out = run_ok(bin::NMCLI, &["-t", "-f", "DEVICE,TYPE", "device"])?;
        parse::wifi_ifaces(&out.stdout).into_iter().next().ok_or(HotspotError::NoWifiInterface)
    }

    fn uplink_info(&self, iface: &str) -> Result<UplinkInfo> {
        let info = parse::iw_info(&run_ok(bin::IW, &["dev", iface, "info"])?.stdout);
        let not_connected = || HotspotError::UplinkNotConnected(iface.into());
        let (channel, freq_mhz, width_mhz) = info.channel.ok_or_else(not_connected)?;
        let (ssid, bssid) = parse::iw_link(&run_ok(bin::IW, &["dev", iface, "link"])?.stdout).ok_or_else(not_connected)?;
        Ok(UplinkInfo {
            iface: iface.into(),
            wifi_adapter: info.adapter.ok_or_else(|| HotspotError::command(format!("iw dev {iface} info"), "missing `wiphy N` line"))?,
            channel,
            freq_mhz,
            width_mhz,
            ssid,
            bssid,
        })
    }

    fn adapter_caps(&self, adapter: &WifiAdapter) -> Result<PhyCaps> {
        let info = run_ok(bin::IW, &["phy", adapter.name(), "info"])?.stdout;
        Ok(PhyCaps { channels: parse::phy_channels(&info), ap_sta: parse::supports_ap_sta(&info) })
    }

    fn ensure_unmanaged_conf(&self) -> Result<()> {
        install_unmanaged_conf(Path::new(NM_UNMANAGED_CONF_PATH)).map(drop)
    }

    fn create_ap_iface(&self, base: &str, ap: &str) -> Result<()> {
        let _ = run(bin::IW, &["dev", ap, "del"]);
        run_unit(bin::IW, &["dev", base, "interface", "add", ap, "type", "__ap"])
            .map_err(|e| HotspotError::ApIfaceCreateFailed(e.to_string()))?;
        // before link up, so no link-local address appears: our nft filters are IPv4 only
        // and IPv6 would reach the host through the `trusted` zone
        Ok(fs::write(format!("/proc/sys/net/ipv6/conf/{ap}/disable_ipv6"), "1\n")?)
    }

    fn delete_ap_iface(&self, ap: &str) -> Result<()> {
        run_unit(bin::IW, &["dev", ap, "del"])
    }

    fn link_up(&self, iface: &str) -> Result<()> {
        run_unit(bin::IP, &["link", "set", "dev", iface, "up"])
    }

    fn add_addr(&self, iface: &str, cidr: &str) -> Result<()> {
        run_unit(bin::IP, &["addr", "add", cidr, "dev", iface])
    }

    fn get_ip_forward(&self) -> Result<bool> {
        Ok(fs::read_to_string(IP_FORWARD)?.trim() == "1")
    }

    fn set_ip_forward(&self, on: bool) -> Result<()> {
        Ok(fs::write(IP_FORWARD, if on { "1\n" } else { "0\n" })?)
    }

    fn firewalld_running(&self) -> bool {
        succeeds(bin::FIREWALL_CMD, &["--state"])
    }

    fn firewalld_add_iface(&self, zone: &str, iface: &str) -> Result<()> {
        firewalld_iface("add", zone, iface)
    }

    fn firewalld_remove_iface(&self, zone: &str, iface: &str) -> Result<()> {
        firewalld_iface("remove", zone, iface)
    }

    fn firewalld_zone_of(&self, iface: &str) -> Option<String> {
        run_ok(bin::FIREWALL_CMD, &[&format!("--get-zone-of-interface={iface}")])
            .ok()
            .map(|o| o.stdout.trim().to_string())
    }

    fn nft_install_nat(&self, uplink: &str) -> Result<()> {
        let _ = run(bin::NFT, &["delete", "table", "ip", NAT_TABLE]);
        let cut_ifaces = format!("@{CUT_IFACES_SET}");
        let cut_macs = format!("@{CUT_MACS_SET}");
        let usage_down = format!("@{USAGE_DOWN_SET}");
        let usage_up = format!("@{USAGE_UP_SET}");
        let steps: [&[&str]; 18] = [
            &["add", "table", "ip", NAT_TABLE],
            &["add", "chain", "ip", NAT_TABLE, "post", "{ type nat hook postrouting priority 100; }"],
            &["add", "rule", "ip", NAT_TABLE, "post", "oifname", uplink, "masquerade"],
            &["add", "set", "ip", NAT_TABLE, CUT_IFACES_SET, "{ type ifname; }"],
            &["add", "set", "ip", NAT_TABLE, CUT_MACS_SET, "{ type ether_addr; }"],
            // a drop in any forward chain is final, even if Docker's chain accepts
            &["add", "chain", "ip", NAT_TABLE, FWD_CHAIN, "{ type filter hook forward priority 0; }"],
            &["add", "rule", "ip", NAT_TABLE, FWD_CHAIN, "iifname", &cut_ifaces, "drop"],
            &["add", "rule", "ip", NAT_TABLE, FWD_CHAIN, "ether", "saddr", &cut_macs, "drop"],
            // after the drops, so cut traffic isn't counted
            &["add", "set", "ip", NAT_TABLE, USAGE_DOWN_SET, "{ type ipv4_addr; size 65535; flags dynamic; }"],
            &["add", "set", "ip", NAT_TABLE, USAGE_UP_SET, "{ type ipv4_addr; size 65535; flags dynamic; }"],
            &["add", "rule", "ip", NAT_TABLE, FWD_CHAIN, "oifname", AP_IFACE, "update", &usage_down, "{ ip daddr counter }"],
            &["add", "rule", "ip", NAT_TABLE, FWD_CHAIN, "iifname", AP_IFACE, "update", &usage_up, "{ ip saddr counter }"],
            // clients may only reach DHCP and DNS on this computer: the firewalld zone `trusted`
            // would otherwise expose every local service (SSH, dev servers…)
            &["add", "chain", "ip", NAT_TABLE, INPUT_CHAIN, "{ type filter hook input priority 0; }"],
            &["add", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", AP_IFACE, "ct", "state", "established,related", "accept"],
            &["add", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", AP_IFACE, "udp", "dport", "{ 53, 67 }", "accept"],
            &["add", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", AP_IFACE, "tcp", "dport", "53", "accept"],
            &["add", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", AP_IFACE, "icmp", "type", "echo-request", "accept"],
            &["add", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", AP_IFACE, "drop"],
        ];
        steps.iter().try_for_each(|args| fw_run(bin::NFT, args))
    }

    fn nft_remove_nat(&self) -> Result<()> {
        fw_run(bin::NFT, &["delete", "table", "ip", NAT_TABLE])
    }

    fn nft_cut_iface(&self, iface: &str, cut: bool) -> Result<()> {
        nft_set_element(CUT_IFACES_SET, &format!("\"{iface}\""), cut)
    }

    fn nft_cut_mac(&self, mac: &str, cut: bool) -> Result<()> {
        nft_set_element(CUT_MACS_SET, mac, cut)
    }

    fn nft_install_portal(&self, ap: &str, gateway: &str, port: u16) -> Result<()> {
        let allowed = format!("@{PORTAL_ALLOWED_SET}");
        let target = format!("{gateway}:{port}");
        let port = port.to_string();
        let steps: [&[&str]; 6] = [
            &["add", "set", "ip", NAT_TABLE, PORTAL_ALLOWED_SET, "{ type ether_addr; }"],
            &["add", "chain", "ip", NAT_TABLE, PORTAL_CHAIN, "{ type nat hook prerouting priority dstnat; }"],
            // http://<gateway>/ shows signed-in devices their time left
            &["add", "rule", "ip", NAT_TABLE, PORTAL_CHAIN, "iifname", ap, "ip", "daddr", gateway, "tcp", "dport", "80", "dnat", "to", &target],
            &["add", "rule", "ip", NAT_TABLE, PORTAL_CHAIN, "iifname", ap, "ether", "saddr", "!=", &allowed, "tcp", "dport", "80",
                "dnat", "to", &target],
            &["add", "rule", "ip", NAT_TABLE, FWD_CHAIN, "iifname", ap, "ether", "saddr", "!=", &allowed, "drop"],
            // insert, not add: host_input ends with a drop for everything else from ap0
            &["insert", "rule", "ip", NAT_TABLE, INPUT_CHAIN, "iifname", ap, "tcp", "dport", &port, "accept"],
        ];
        steps.iter().try_for_each(|args| fw_run(bin::NFT, args))
    }

    fn nft_portal_allow(&self, mac: &str, allow: bool) -> Result<()> {
        nft_set_element(PORTAL_ALLOWED_SET, mac, allow)
    }

    fn serve_portal(&self, addr: SocketAddr, page: PageInfo, requests: Sender<PortalRequest>) -> Result<Option<PortalServer>> {
        Ok(Some(PortalServer::start(addr, page, requests)?))
    }

    fn mac_of(&self, ap: &str, ip: &str) -> Option<String> {
        parse::arp_mac(&fs::read_to_string(ARP_TABLE).ok()?, ap, ip)
    }

    fn nft_nat_present(&self) -> bool {
        succeeds(bin::NFT, &["list", "table", "ip", NAT_TABLE])
    }

    fn nft_usage(&self) -> Result<HashMap<String, (u64, u64)>> {
        let read = |set| -> Result<HashMap<String, u64>> {
            Ok(parse::nft_set_counters(&run_ok(bin::NFT, &["-j", "list", "set", "ip", NAT_TABLE, set])?.stdout))
        };
        let (down, up) = (read(USAGE_DOWN_SET)?, read(USAGE_UP_SET)?);
        let ips: std::collections::BTreeSet<&String> = down.keys().chain(up.keys()).collect();
        Ok(ips
            .into_iter()
            .map(|ip| (ip.clone(), (down.get(ip).copied().unwrap_or(0), up.get(ip).copied().unwrap_or(0))))
            .collect())
    }

    fn tc_limits(&self, ap: &str, limits: &[(String, u32)]) -> Result<()> {
        let _ = run(bin::TC, &["qdisc", "del", "dev", ap, "root"]);
        let _ = run(bin::TC, &["qdisc", "del", "dev", ap, "ingress"]);
        if limits.is_empty() {
            return Ok(());
        }
        let tc = |args: &[&str]| run_unit(bin::TC, args);
        // down: htb classes on ap0's egress; up: policing on its ingress (no ifb needed)
        tc(&["qdisc", "add", "dev", ap, "root", "handle", "1:", "htb", "default", "1"])?;
        tc(&["class", "add", "dev", ap, "parent", "1:", "classid", "1:1", "htb", "rate", "10gbit"])?;
        tc(&["qdisc", "add", "dev", ap, "handle", "ffff:", "ingress"])?;
        for (i, (ip, mbps)) in limits.iter().enumerate() {
            let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| HotspotError::command(bin::TC, format!("bad client IP {ip}")))?;
            let host = format!("{ip}/32");
            let class = format!("1:{:x}", i + 16);
            let rate = format!("{mbps}mbit");
            tc(&["class", "add", "dev", ap, "parent", "1:", "classid", &class, "htb", "rate", &rate, "ceil", &rate])?;
            tc(&["filter", "add", "dev", ap, "parent", "1:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "dst", &host, "flowid", &class])?;
            tc(&["filter", "add", "dev", ap, "parent", "ffff:", "protocol", "ip", "prio", "1", "u32", "match", "ip", "src", &host,
                "police", "rate", &rate, "burst", "64k", "drop", "flowid", ":1"])?;
        }
        Ok(())
    }

    fn forward_blocked(&self) -> bool {
        run(bin::NFT, &["list", "ruleset"]).is_ok_and(|o| {
            o.stdout.lines().any(|l| l.contains("hook forward") && l.contains("policy drop"))
        })
    }

    fn iptables(&self, args: &[&str]) -> Result<bool> {
        Ok(run(bin::IPTABLES, args)?.success())
    }

    fn spawn_hostapd(&self, conf: &Path) -> Result<Child> {
        spawn(bin::HOSTAPD, &[conf.display().to_string()])
    }

    fn block_client(&self, ctrl_dir: &Path, ap: &str, mac: &str, block: bool) -> Result<()> {
        let ctl = |args: &[&str]| -> Result<()> {
            let dir = ctrl_dir.display().to_string();
            let mut full = vec!["-p", &dir, "-i", ap];
            full.extend(args);
            // hostapd_cli exits 0 even on failure: the answer is on stdout
            let out = run_ok(bin::HOSTAPD_CLI, &full)?;
            match out.stdout.trim() {
                "OK" => Ok(()),
                other => Err(HotspotError::command(format!("{} {}", bin::HOSTAPD_CLI, full.join(" ")), other)),
            }
        };
        if block {
            ctl(&["deny_acl", "ADD_MAC", mac])?;
            ctl(&["deauthenticate", mac])
        } else {
            ctl(&["deny_acl", "DEL_MAC", mac])
        }
    }

    fn spawn_dnsmasq(&self, a: &DnsmasqArgs) -> Result<Child> {
        // --no-daemon: the only tested option; logs to stderr
        let mut args = vec![
            "--no-daemon".to_string(),
            format!("--interface={}", a.iface),
            "--bind-interfaces".into(),
            "--except-interface=lo".into(),
            format!("--dhcp-range={},{},{DHCP_LEASE}", a.range_start, a.range_end),
            format!("--dhcp-leasefile={}", a.leasefile.display()),
            "--no-resolv".into(),
            "--log-dhcp".into(),
        ];
        args.extend(a.upstream_dns.iter().map(|d| format!("--server={d}")));
        args.extend(a.portal_gateway.map(|g| format!("--address=/{PORTAL_HOSTNAME}/{g}")));
        spawn(bin::DNSMASQ, &args)
    }

    fn is_running(&self, pid: u32, name: &str) -> bool {
        let is_ours = fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|c| String::from_utf8_lossy(&c).contains(name));
        is_ours && alive(pid)
    }

    fn stop_process(&self, pid: u32, name: &str) {
        if !self.is_running(pid, name) {
            return;
        }
        let pid_s = pid.to_string();
        let _ = run(bin::KILL, &["-TERM", &pid_s]);
        let deadline = Instant::now() + KILL_TIMEOUT;
        while alive(pid) && Instant::now() < deadline {
            sleep(KILL_POLL);
        }
        if alive(pid) {
            let _ = run(bin::KILL, &["-KILL", &pid_s]);
        }
    }

    fn pgrep(&self, pattern: &str) -> Vec<u32> {
        run(bin::PGREP, &["-f", pattern])
            .map(|o| o.stdout.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmanaged_conf_already_in_place_does_nothing() {
        let path = std::env::temp_dir().join("hs-init-test.conf");
        fs::write(&path, nm_unmanaged_conf()).unwrap();
        assert!(!install_unmanaged_conf(&path).unwrap());
        fs::remove_file(&path).ok();
    }
}
