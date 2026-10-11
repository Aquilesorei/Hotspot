# Hotspot

Shares a Wi-Fi connection as a hotspot on the same card (AP + STA), on Fedora.
Uses hostapd, dnsmasq, nftables and firewalld.

- `hotspot-core`: engine (Rust library)
- `hotspot-cli`: command line and background service
- `hotspot-ui`: desktop app (Slint) with tray icon

Profiles are either password-protected or open with a captive portal that asks for a coupon code.

Install: `./install.sh --service`, then log out and back in once.
