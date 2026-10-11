use std::collections::HashMap;

use crate::models::{ChannelInfo, WifiAdapter};


pub fn wifi_ifaces(nmcli_output: &str) -> Vec<String> {
    nmcli_output
        .lines()
        .filter_map(|l| l.rsplit_once(':'))
        .filter(|(_, ty)| *ty == "wifi")
        .map(|(dev, _)| dev.to_string())
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub struct IwInfo {
    pub adapter: Option<WifiAdapter>,
    /// (channel, frequency MHz, width MHz)
    pub channel: Option<(u32, u32, Option<u32>)>,
}

pub fn iw_info(out: &str) -> IwInfo {
    let mut info = IwInfo { adapter: None, channel: None };
    for l in out.lines().map(str::trim) {
        if let Some(n) = l.strip_prefix("wiphy ") {
            info.adapter = Some(WifiAdapter::new(format!("phy{}", n.trim())));
        } else if let Some(rest) = l.strip_prefix("channel ") {
            // "4 (2427 MHz), width: 20 MHz, center1: 2427 MHz"
            let ch = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            let freq = between(rest, "(", " MHz)").and_then(|s| s.parse().ok());
            let width = between(rest, "width: ", " MHz").and_then(|s| s.parse().ok());
            if let (Some(ch), Some(freq)) = (ch, freq) {
                info.channel = Some((ch, freq, width));
            }
        }
    }
    info
}

pub fn iw_link(out: &str) -> Option<(Option<String>, Option<String>)> {
    if out.trim_start().starts_with("Not connected") {
        return None;
    }
    let mut ssid = None;
    let mut bssid = None;
    for l in out.lines().map(str::trim) {
        if let Some(s) = l.strip_prefix("SSID: ") {
            ssid = Some(s.to_string());
        } else if let Some(s) = l.strip_prefix("Connected to ") {
            bssid = s.split_whitespace().next().map(str::to_string);
        }
    }
    Some((ssid, bssid))
}

pub fn phy_channels(out: &str) -> Vec<ChannelInfo> {
    out.lines()
        .map(str::trim)
        .filter_map(|l| {
            // "* 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)"
            let rest = l.strip_prefix("* ")?;
            let (freq, rest) = rest.split_once(" MHz [")?;
            let (num, flags) = rest.split_once(']')?;
            Some(ChannelInfo {
                number: num.parse().ok()?,
                freq_mhz: freq.parse::<f64>().ok()? as u32,
                no_ir: flags.contains("no IR"),
                radar: flags.contains("radar detection"),
                disabled: flags.contains("disabled"),
            })
        })
        .collect()
}

pub fn supports_ap_sta(out: &str) -> bool {
    let Some((_, section)) = out.split_once("valid interface combinations:") else {
        return false;
    };
    let body: Vec<&str> = section
        .lines()
        .skip(1)
        .map(str::trim)
        .take_while(|l| l.starts_with("* #{") || l.starts_with("total") || l.contains("<="))
        .collect();
    body.join(" ")
        .split("* #{")
        .any(|combo| combo.contains("managed") && combo.split(|c: char| !c.is_alphanumeric() && c != '-').any(|w| w == "AP"))
}

/// `nft -j list set ip <table> <set>` -> bytes per element, for sets updated with `{ ip daddr counter }`.
pub fn nft_set_counters(json: &str) -> HashMap<String, u64> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return HashMap::new() };
    v["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["set"]["elem"].as_array())
        .flatten()
        .filter_map(|e| {
            let e = &e["elem"];
            Some((e["val"].as_str()?.to_string(), e["counter"]["bytes"].as_u64()?))
        })
        .collect()
}

fn between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)? + i;
    Some(&s[i..j])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ChannelClass;

    const NMCLI: &str = "wlo1:wifi\nlo:loopback\ndocker0:bridge\np2p-dev-wlo1:wifi-p2p\n";

    const IW_INFO: &str = "Interface wlo1\n\tifindex 2\n\twdev 0x1\n\taddr 02:b7:66:49:79:d9\n\ttype managed\n\twiphy 0\n\tchannel 4 (2427 MHz), width: 20 MHz, center1: 2427 MHz\n\ttxpower 22.00 dBm\n";
    const IW_INFO_DOWN: &str = "Interface wlo1\n\tifindex 2\n\ttype managed\n\twiphy 0\n\ttxpower 22.00 dBm\n";

    const IW_LINK: &str = "Connected to c6:19:72:05:ba:d0 (on wlo1)\n\tSSID: Redmi Note 15 Pro\n\tfreq: 2412.0\n";

    const PHY: &str = "\
Wiphy phy0
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (22.0 dBm)
\t\t\t* 2427.0 MHz [4] (22.0 dBm)
\t\t\t* 2484.0 MHz [14] (disabled)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180.0 MHz [36] (22.0 dBm) (no IR)
\t\t\t* 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)
\t\t\t* 5745.0 MHz [149] (22.0 dBm)
\t\t\t* 5825.0 MHz [165] (22.0 dBm) (no IR)
\t\t\t* 5885.0 MHz [177] (disabled)
\tBand 4:
\t\tFrequencies:
\t\t\t* 5955.0 MHz [1] (disabled)
\tvalid interface combinations:
\t\t * #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
\t\t   total <= 3, #channels <= 2
\t\t * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1, #{ P2P-device } <= 1,
\t\t   total <= 3, #channels <= 1
\tHT Capability overrides:
\t\t * MCS: ff ff ff ff ff ff ff ff ff ff
";

    #[test]
    fn nmcli_keeps_only_wifi() {
        assert_eq!(wifi_ifaces(NMCLI), vec!["wlo1"]);
    }

    #[test]
    fn iw_info_connected_and_not() {
        let i = iw_info(IW_INFO);
        assert_eq!(i.adapter, Some(WifiAdapter::new("phy0")));
        assert_eq!(i.channel, Some((4, 2427, Some(20))));
        assert_eq!(iw_info(IW_INFO_DOWN).channel, None);
    }

    #[test]
    fn iw_link_connected_and_not() {
        assert_eq!(
            iw_link(IW_LINK),
            Some((Some("Redmi Note 15 Pro".into()), Some("c6:19:72:05:ba:d0".into())))
        );
        assert_eq!(iw_link("Not connected.\n"), None);
    }

    #[test]
    fn phy_classes_by_freq() {
        let chans = phy_channels(PHY);
        let class = |f| chans.iter().find(|c| c.freq_mhz == f).unwrap().class();
        assert_eq!(class(2412), ChannelClass::Free);
        assert_eq!(class(5745), ChannelClass::Free);
        assert_eq!(class(5180), ChannelClass::Restricted);
        assert_eq!(class(5260), ChannelClass::Restricted);
        assert_eq!(class(5885), ChannelClass::Disabled);
        // 6 GHz channel 1 (disabled) must not affect 2.4 GHz channel 1
        assert_eq!(class(5955), ChannelClass::Disabled);
        assert_eq!(chans.iter().filter(|c| c.number == 1).count(), 2);
    }

    #[test]
    fn nft_counters() {
        let json = r#"{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"set": {"family": "ip", "name": "usage_down",
            "table": "hsnat", "type": "ipv4_addr", "flags": ["dynamic"], "elem": [
            {"elem": {"val": "192.168.12.100", "counter": {"packets": 12, "bytes": 3400}}},
            {"elem": {"val": "192.168.12.101", "counter": {"packets": 1, "bytes": 60}}}]}}]}"#;
        let c = nft_set_counters(json);
        assert_eq!(c["192.168.12.100"], 3400);
        assert_eq!(c.len(), 2);
        assert!(nft_set_counters("not json").is_empty());
    }

    #[test]
    fn ap_sta_combination() {
        assert!(supports_ap_sta(PHY));
        assert!(!supports_ap_sta(&PHY.replace("#{ AP, ", "#{ ")));
    }
}
