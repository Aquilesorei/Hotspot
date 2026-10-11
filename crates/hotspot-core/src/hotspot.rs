//! state.json doubles as an undo stack: each resource is recorded before it is created,
//! and `teardown` undoes whatever is recorded.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::network_backend::NetworkBackend;
use crate::constants::{
    bin, AP_ENABLED, AP_IFACE as AP, AP_STA_CONNECTED, AP_STA_DISCONNECTED, AP_STA_PSK_MISMATCH, DHCPACK,
    DNSMASQ_LEASES, DNSMASQ_STARTUP, DOCKER_USER, FIREWALLD_ZONE as ZONE, GUEST_MINUTES, HOSTAPD_CONF, HOSTAPD_CTRL, SPEED_LIMIT_MBPS,
    HOSTAPD_TIMEOUT, LOG_LINES, MAX_RESTARTS, PORTAL_LOCKOUT, PORTAL_MAX_FAILURES, PORTAL_PORT, PORTAL_SAVE_EVERY, USAGE_REPORT_EVERY, NAT_TABLE, RESTART_WINDOW, RUNTIME_DIR, STATE_FILE, TICK,
};
use crate::portal_http::{PageInfo, PortalRequest, PortalServer};
use crate::portal_store::{self, PortalAction, PortalStore, SignIn};
use crate::system::SystemBackend;
use crate::error::{HotspotError, Result};
use crate::forward::{docker_install, docker_installed, docker_present, docker_remove};
use crate::models::{
    normalize_mac, ProfileKind, BlockedDevice, ChannelClass, Client, Command, DeviceUsage, DnsmasqArgs, Event, Forwarding, HotspotProfile,
    HotspotState, Probe, Status, UplinkInfo,
};

type Log = Arc<Mutex<VecDeque<String>>>;

/// Filled by the threads reading hostapd and dnsmasq output.
#[derive(Default)]
struct Live {
    clients: Vec<(String, Instant)>,
    /// From dnsmasq's DHCPACK lines, by MAC: (ip, hostname).
    leases: HashMap<String, (String, Option<String>)>,
    events: Vec<Event>,
}

type Shared = Arc<Mutex<Live>>;

/// A running portal profile: its coupons, the web server, and who is let through.
struct PortalRuntime {
    profile: String,
    path: PathBuf,
    store: PortalStore,
    _server: Option<PortalServer>,
    /// Where the redirect points: the server may have fallen back to a free port.
    port: u16,
    requests: Receiver<PortalRequest>,
    /// MACs currently in the nft allowed set.
    allowed: HashSet<String>,
    /// Wrong codes per MAC: (count, since).
    failures: HashMap<String, (u32, Instant)>,
    /// Connected time is measured with the monotonic clock: a wall-clock jump (NTP after a
    /// boot with a wrong RTC) must not charge or refund hours.
    last_tick: Instant,
    carry: Duration,
    last_save: Instant,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RunState {
    uplink_iface: String,
    ap_iface: String,
    channel: u32,
    freq_mhz: u32,
    hostapd_pid: Option<u32>,
    dnsmasq_pid: Option<u32>,
    prev_ip_forward: Option<bool>,
    created: Created,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Created {
    ap_iface: bool,
    addr: bool,
    firewalld_zone: Option<String>,
    nft_table: bool,
    docker_rules: bool,
}

pub struct Hotspot<B: NetworkBackend> {
    backend: B,
    runtime_dir: PathBuf,
    state: HotspotState,
    run: Option<RunState>,
    profile: Option<HotspotProfile>,
    uplink: Option<UplinkInfo>,
    forwarding: Forwarding,
    hostapd: Option<Child>,
    dnsmasq: Option<Child>,
    hostapd_log: Log,
    dnsmasq_log: Log,
    live: Shared,
    cut_all: bool,
    cut_macs: BTreeSet<String>,
    /// Temporary access deadlines by MAC; the device gets blocked when one passes.
    deadlines: HashMap<String, Instant>,
    /// Speed limits by MAC, applied by IP once the device has a lease.
    speed: BTreeMap<String, u32>,
    applied_speed: Vec<(String, u32)>,
    /// Bytes by client IP: (down, up).
    usage: HashMap<String, (u64, u64)>,
    /// Last client list reported, to send `Event::Clients` only on change.
    reported_clients: Vec<Client>,
    reported_usage: (Instant, HashMap<String, (u64, u64)>),
    portal: Option<PortalRuntime>,
    /// Where portal coupons and sessions are kept (root-owned).
    portal_dir: PathBuf,
    restarts: Vec<Instant>,
}

impl<B: NetworkBackend> Hotspot<B> {
    pub fn new(backend: B, runtime_dir: PathBuf) -> Self {
        Self {
            backend,
            runtime_dir,
            state: HotspotState::Stopped,
            run: None,
            profile: None,
            uplink: None,
            forwarding: Forwarding::Ok,
            hostapd: None,
            dnsmasq: None,
            hostapd_log: Log::default(),
            dnsmasq_log: Log::default(),
            live: Shared::default(),
            cut_all: false,
            cut_macs: BTreeSet::new(),
            deadlines: HashMap::new(),
            speed: BTreeMap::new(),
            applied_speed: Vec::new(),
            usage: HashMap::new(),
            reported_clients: Vec::new(),
            reported_usage: (Instant::now(), HashMap::new()),
            portal: None,
            portal_dir: portal_store::default_dir(),
            restarts: Vec::new(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn start(&mut self, p: &HotspotProfile) -> Result<Status> {
        
        p.validate()?;
        if !self.backend.is_root() {
            return Err(HotspotError::NotRoot);
        }
        if self.run.is_some() {
            return Err(HotspotError::AlreadyRunning);
        }
        self.check_previous_run()?;
        self.backend.ensure_unmanaged_conf()?;
        fs::create_dir_all(&self.runtime_dir)?;
        fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700))?;

        self.profile = Some(p.clone());
        match self.start_steps(p) {
            Ok(()) => {
                self.state = HotspotState::Running;
                Ok(self.status())
            }
            Err(e) => {
                self.teardown();
                self.state = HotspotState::Failed;
                Err(e)
            }
        }
    }

    fn start_steps(&mut self, p: &HotspotProfile) -> Result<()> {
        let iface = self.backend.detect_wifi_iface()?;
        let up = self.backend.uplink_info(&iface)?;
        let caps = self.backend.adapter_caps(&up.wifi_adapter)?;
        // by frequency: 6 GHz channel numbers overlap with 2.4 GHz ones
        let restricted = match caps.channels.iter().find(|c| c.freq_mhz == up.freq_mhz).map(|c| c.class()) {
            Some(ChannelClass::Disabled) => {
                return Err(HotspotError::ChannelNotAllowedForAp { channel: up.channel, freq_mhz: up.freq_mhz })
            }
            Some(ChannelClass::Restricted) => {
                eprintln!("warning: channel {} ({} MHz) is restricted (no IR / radar), trying anyway", up.channel, up.freq_mhz);
                true
            }
            _ => false,
        };
        if !caps.ap_sta {
            return Err(HotspotError::ConcurrentApStaUnsupported);
        }
        self.run = Some(RunState {
            uplink_iface: iface.clone(),
            ap_iface: AP.into(),
            channel: up.channel,
            freq_mhz: up.freq_mhz,
            ..Default::default()
        });
        self.uplink = Some(up.clone());

        self.st().created.ap_iface = true;
        self.save()?;
        self.backend.create_ap_iface(&iface, AP)?;
        self.backend.link_up(AP)?; // otherwise hostapd: Beacon set failed: -2

        let conf = self.runtime_dir.join(HOSTAPD_CONF);
        write_private(&conf, &p.hostapd_conf(AP, up.channel, up.freq_mhz, &self.ctrl_dir()))?;

        self.hostapd_log.lock().unwrap().clear();
        let mut child = self.backend.spawn_hostapd(&conf)?;
        self.st().hostapd_pid = Some(child.id());
        let rx = drain(&mut child, self.hostapd_log.clone(), self.live.clone(), on_hostapd_line);
        self.hostapd = Some(child);
        self.save()?;
        if let Err(timed_out) = wait_for(&rx, AP_ENABLED, HOSTAPD_TIMEOUT) {
            if timed_out {
                return Err(HotspotError::HostapdTimeout);
            }
            let mut log = tail(&self.hostapd_log);
            if restricted {
                log.push_str("\n(restricted channel: the failure may be caused by regulatory rules)");
            }
            return Err(HotspotError::HostapdFailed(log));
        }
        for b in &p.blocked {
            warn(self.backend.block_client(&self.ctrl_dir(), AP, &b.mac, true));
        }

        self.st().created.addr = true;
        self.backend.add_addr(AP, &p.gateway_cidr())?;
        let prev = self.backend.get_ip_forward()?;
        self.st().prev_ip_forward = Some(prev);
        self.save()?;
        self.backend.set_ip_forward(true)?;

        if self.backend.firewalld_running() {
            self.st().created.firewalld_zone = Some(ZONE.into());
            self.save()?;
            self.backend.firewalld_add_iface(ZONE, AP)?;
        }

        self.st().created.nft_table = true;
        self.save()?;
        self.backend.nft_install_nat(&iface)?;
        self.reapply_cuts()?;
        if p.kind == ProfileKind::Portal {
            self.start_portal(p)?;
        }

        if docker_present(&self.backend) {
            self.st().created.docker_rules = true;
            self.save()?;
            docker_install(&self.backend, AP, &iface)?;
        }
        self.forwarding = if !self.st().created.docker_rules && self.backend.forward_blocked() {
            Forwarding::Unverified {
                reason: "a forward chain with policy drop exists and no supported firewall was found: internet access not guaranteed".into(),
            }
        } else {
            Forwarding::Ok
        };

        self.dnsmasq_log.lock().unwrap().clear();
        let mut child = self.backend.spawn_dnsmasq(&DnsmasqArgs::new(p, AP, &self.runtime_dir))?;
        self.st().dnsmasq_pid = Some(child.id());
        drain(&mut child, self.dnsmasq_log.clone(), self.live.clone(), on_dnsmasq_line);
        self.dnsmasq = Some(child);
        self.save()?;
        thread::sleep(DNSMASQ_STARTUP);
        if self.dnsmasq.as_mut().unwrap().try_wait()?.is_some() {
            return Err(HotspotError::DnsmasqFailed(tail(&self.dnsmasq_log)));
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.teardown();
        self.cut_all = false;
        self.cut_macs.clear();
        self.deadlines.clear();
        self.speed.clear();
        self.usage.clear();
        self.reported_clients.clear();
        self.live.lock().unwrap().leases.clear();
        Ok(())
    }

    pub fn status(&self) -> Status {
        let live = self.live.lock().unwrap();
        let clients = live
            .clients
            .iter()
            .map(|(mac, since)| {
                let ip = live.leases.get(mac).map(|(ip, _)| ip.clone());
                let (down_bytes, up_bytes) = ip.as_ref().and_then(|ip| self.usage.get(ip)).copied().unwrap_or_default();
                Client {
                    mac: mac.clone(),
                    hostname: live.leases.get(mac).and_then(|(_, host)| host.clone()),
                    ip,
                    connected_secs: since.elapsed().as_secs(),
                    internet_cut: self.cut_macs.contains(mac),
                    down_bytes,
                    up_bytes,
                    expires_in_secs: self.deadlines.get(mac).map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
                    speed_limit_mbps: self.speed.get(mac).copied(),
                }
            })
            .collect();
        Status {
            state: self.state,
            uplink: self.uplink.clone(),
            ap_channel: self.run.as_ref().map(|r| r.channel),
            clients,
            internet_cut_all: self.cut_all,
            blocked: self.profile.as_ref().map(|p| p.blocked.clone()).unwrap_or_default(),
            forwarding: self.forwarding.clone(),
        }
    }

    /// Upstream and card capabilities, read-only: works without root and without starting.
    pub fn probe(&self) -> Result<Probe> {
        let uplink = self.backend.uplink_info(&self.backend.detect_wifi_iface()?)?;
        let ap_sta = self.backend.adapter_caps(&uplink.wifi_adapter)?.ap_sta;
        Ok(Probe { uplink, ap_sta })
    }

    /// `mac: None` cuts or restores internet for every client. Clients stay connected to the Wi-Fi.
    pub fn set_internet_cut(&mut self, mac: Option<&str>, cut: bool) -> Result<()> {
        if self.run.is_none() {
            return Err(HotspotError::NotRunning);
        }
        match mac {
            None if cut != self.cut_all => {
                self.backend.nft_cut_iface(AP, cut)?;
                self.cut_all = cut;
            }
            Some(mac) => {
                let mac = normalize_mac(mac)?;
                if cut != self.cut_macs.contains(&mac) {
                    self.backend.nft_cut_mac(&mac, cut)?;
                    if cut {
                        self.cut_macs.insert(mac);
                    } else {
                        self.cut_macs.remove(&mac);
                    }
                }
            }
            None => {}
        }
        Ok(())
    }

    /// The nft sets live in our table: recreating it (start, reconcile) empties them.
    fn reapply_cuts(&self) -> Result<()> {
        if self.cut_all {
            self.backend.nft_cut_iface(AP, true)?;
        }
        for mac in &self.cut_macs {
            self.backend.nft_cut_mac(mac, true)?;
        }
        Ok(())
    }

    /// Returns the new blocked list. Kept in the profile so a restart re-applies it;
    /// saving it to the profile file is up to the caller.
    pub fn set_blocked(&mut self, mac: &str, block: bool) -> Result<Vec<BlockedDevice>> {
        if self.run.is_none() {
            return Err(HotspotError::NotRunning);
        }
        let mac = normalize_mac(mac)?;
        let ctrl_dir = self.ctrl_dir();
        let name = self.live.lock().unwrap().leases.get(&mac).and_then(|(_, host)| host.clone());
        let profile = self.profile.as_mut().expect("profile is known while running");
        if block != profile.blocked.iter().any(|b| b.mac == mac) {
            self.backend.block_client(&ctrl_dir, AP, &mac, block)?;
            if block {
                profile.blocked.push(BlockedDevice { mac, name });
            } else {
                profile.blocked.retain(|b| b.mac != mac);
            }
        }
        Ok(profile.blocked.clone())
    }

    /// The device gets blocked after `minutes`; `None` removes the limit. Not saved: it ends with the session.
    pub fn set_time_limit(&mut self, mac: &str, minutes: Option<u32>) -> Result<()> {
        if self.run.is_none() {
            return Err(HotspotError::NotRunning);
        }
        let mac = normalize_mac(mac)?;
        match minutes {
            Some(m) if !GUEST_MINUTES.contains(&m) => {
                return Err(HotspotError::invalid_profile(format!(
                    "time limit must be {} to {} minutes",
                    GUEST_MINUTES.start(),
                    GUEST_MINUTES.end()
                )))
            }
            Some(m) => self.deadlines.insert(mac, Instant::now() + Duration::from_secs(u64::from(m) * 60)),
            None => self.deadlines.remove(&mac),
        };
        Ok(())
    }

    /// Download and upload limit for one device; `None` removes it.
    pub fn set_speed_limit(&mut self, mac: &str, mbps: Option<u32>) -> Result<()> {
        if self.run.is_none() {
            return Err(HotspotError::NotRunning);
        }
        let mac = normalize_mac(mac)?;
        match mbps {
            Some(m) if !SPEED_LIMIT_MBPS.contains(&m) => {
                return Err(HotspotError::invalid_profile(format!(
                    "speed limit must be {} to {} Mbit/s",
                    SPEED_LIMIT_MBPS.start(),
                    SPEED_LIMIT_MBPS.end()
                )))
            }
            Some(m) => self.speed.insert(mac, m),
            None => self.speed.remove(&mac),
        };
        self.apply_speed()
    }

    /// Limits are set per IP, which a device only has once DHCP answered: re-run on every tick.
    fn apply_speed(&mut self) -> Result<()> {
        let wanted: Vec<(String, u32)> = {
            let live = self.live.lock().unwrap();
            self.speed.iter().filter_map(|(mac, mbps)| live.leases.get(mac).map(|(ip, _)| (ip.clone(), *mbps))).collect()
        };
        if wanted != self.applied_speed {
            self.backend.tc_limits(AP, &wanted)?;
            self.applied_speed = wanted;
        }
        Ok(())
    }

    fn start_portal(&mut self, p: &HotspotProfile) -> Result<()> {
        let settings = p.portal.clone().unwrap_or_default();
        let path = portal_store::store_path(&self.portal_dir, &p.name);
        let store = PortalStore::load(&path)?;
        let gateway = p.gateway();
        let (tx, rx) = mpsc::channel();
        let page = PageInfo { ssid: p.ssid.clone(), country_code: settings.country_code };
        let server = self.backend.serve_portal(SocketAddr::from((gateway, PORTAL_PORT)), page, tx)?;
        let port = server.as_ref().map_or(PORTAL_PORT, PortalServer::port);
        self.backend.nft_install_portal(AP, &gateway.to_string(), port)?;
        self.portal = Some(PortalRuntime {
            profile: p.name.clone(),
            path,
            store,
            _server: server,
            port,
            requests: rx,
            allowed: HashSet::new(),
            failures: HashMap::new(),
            last_tick: Instant::now(),
            carry: Duration::ZERO,
            last_save: Instant::now(),
        });
        self.sync_portal()
    }

    /// Makes the nft allowed set match the sessions that still have time.
    fn sync_portal(&mut self) -> Result<()> {
        let Some(rt) = self.portal.as_mut() else { return Ok(()) };
        let wanted = rt.store.allowed_macs(portal_store::now());
        for mac in wanted.difference(&rt.allowed) {
            self.backend.nft_portal_allow(mac, true)?;
        }
        for mac in rt.allowed.difference(&wanted) {
            self.backend.nft_portal_allow(mac, false)?;
        }
        rt.allowed = wanted;
        Ok(())
    }

    /// After our nft table was recreated: the portal rules and allowed set went with it.
    fn reinstall_portal(&mut self) -> Result<()> {
        let Some(rt) = self.portal.as_mut() else { return Ok(()) };
        rt.allowed.clear();
        let gateway = self.profile.as_ref().map(HotspotProfile::gateway).expect("profile is known while running");
        self.backend.nft_install_portal(AP, &gateway.to_string(), rt.port)?;
        self.sync_portal()
    }

    /// Answers the forms submitted since the last call.
    fn serve_portal(&mut self, events: &mut Vec<Event>) {
        let Some(rt) = self.portal.as_ref() else { return };
        let requests: Vec<PortalRequest> = rt.requests.try_iter().collect();
        for req in requests {
            let from_lease =
                self.live.lock().unwrap().leases.iter().find(|(_, (ip, _))| *ip == req.ip).map(|(mac, _)| mac.clone());
            let result = match from_lease.or_else(|| self.backend.mac_of(AP, &req.ip)) {
                Some(mac) => {
                    let signed_in = match &req.form {
                        Some(form) => self.portal_sign_in(&mac, &req.ip, form, events).map(drop),
                        None => Ok(()),
                    };
                    signed_in.and_then(|()| {
                        let rt = self.portal.as_ref().ok_or("The portal is not running.")?;
                        rt.store.access_for(&mac, portal_store::now()).ok_or_else(|| "not signed in".to_string())
                    })
                }
                None => Err("We couldn't identify your device. Turn Wi-Fi off and on, then try again.".into()),
            };
            let _ = req.reply.send(result);
        }
    }

    /// Checks one sign-in; wrong codes count towards a lockout for that device.
    fn portal_sign_in(&mut self, mac: &str, ip: &str, form: &SignIn, events: &mut Vec<Event>) -> std::result::Result<u64, String> {
        let rt = self.portal.as_mut().ok_or("The portal is not running.")?;
        if let Some((count, since)) = rt.failures.get(mac) {
            if since.elapsed() >= PORTAL_LOCKOUT {
                rt.failures.remove(mac);
            } else if *count >= PORTAL_MAX_FAILURES {
                let wait = (PORTAL_LOCKOUT - since.elapsed()).as_secs() / 60 + 1;
                return Err(format!("Too many wrong codes. Try again in {wait} min."));
            }
        }
        match rt.store.redeem(form, mac, portal_store::now()) {
            Ok(secs) => {
                rt.failures.remove(mac);
                rt.store.note_ip(mac, ip);
                if let Err(e) = rt.store.save(&rt.path) {
                    eprintln!("warning: could not save portal data: {e}");
                }
                rt.last_save = Instant::now();
                events.push(Event::PortalSignIn {
                    mac: mac.into(),
                    name: format!("{} {}", form.first_name.trim(), form.last_name.trim()),
                    coupon: form.code.trim().to_uppercase(),
                    remaining_secs: secs,
                });
                self.sync_portal().map_err(|e| e.to_string())?;
                Ok(secs)
            }
            Err(e @ (HotspotError::CouponInvalid | HotspotError::CouponUsedUp | HotspotError::CouponFull(_))) => {
                rt.failures.entry(mac.into()).or_insert((0, Instant::now())).0 += 1;
                Err(e.to_string())
            }
            Err(HotspotError::InvalidProfile(message)) => Err(capitalize(&message)),
            Err(e) => Err(e.to_string()),
        }
    }

    fn portal_tick(&mut self, events: &mut Vec<Event>) {
        let (connected, leases): (HashSet<String>, Vec<(String, String)>) = {
            let live = self.live.lock().unwrap();
            let connected = live.clients.iter().map(|(mac, _)| mac.clone()).collect();
            (connected, live.leases.iter().map(|(mac, (ip, _))| (mac.clone(), ip.clone())).collect())
        };
        let Some(rt) = self.portal.as_mut() else { return };
        for (mac, ip) in &leases {
            rt.store.note_ip(mac, ip);
        }
        let now = portal_store::now();
        rt.carry += rt.last_tick.elapsed();
        rt.last_tick = Instant::now();
        let elapsed = rt.carry.as_secs();
        rt.carry -= Duration::from_secs(elapsed);
        let ended = rt.store.tick(now, elapsed, &connected);
        if !ended.is_empty() || rt.last_save.elapsed() >= PORTAL_SAVE_EVERY {
            if let Err(e) = rt.store.save(&rt.path) {
                eprintln!("warning: could not save portal data: {e}");
            }
            rt.last_save = Instant::now();
        }
        events.extend(ended.into_iter().map(|mac| Event::PortalSessionEnded { mac }));
        warn(self.sync_portal());
    }

    /// Applies the 30-day purge to every portal profile's file, not only the running one.
    /// The service calls it now and then.
    pub fn purge_portal_files(&self) {
        let Ok(entries) = fs::read_dir(&self.portal_dir) else { return };
        let running = self.portal.as_ref().map(|rt| rt.path.clone());
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().is_none_or(|x| x != "json") || Some(&path) == running.as_ref() {
                continue;
            }
            let purged = PortalStore::load(&path).and_then(|mut store| {
                store.tick(portal_store::now(), 0, &HashSet::new());
                store.save(&path)
            });
            if let Err(e) = purged {
                eprintln!("warning: could not purge {}: {e}", path.display());
            }
        }
    }

    /// Admin actions; on the running profile they apply live, otherwise straight to its file.
    fn portal_command(&mut self, profile: &str, action: PortalAction) -> Result<Event> {
        let now = portal_store::now();
        let changes = action != PortalAction::List;
        let (coupons, sessions) = match self.portal.as_mut().filter(|rt| rt.profile == profile) {
            Some(rt) => {
                rt.store.apply(action, now)?;
                if changes {
                    rt.store.save(&rt.path)?;
                }
                let views = rt.store.views(now);
                self.sync_portal()?;
                views
            }
            None => {
                let path = portal_store::store_path(&self.portal_dir, profile);
                let mut store = PortalStore::load(&path)?;
                let expired = !store.tick(now, 0, &HashSet::new()).is_empty();
                store.apply(action, now)?;
                if changes || expired {
                    store.save(&path)?;
                }
                store.views(now)
            }
        };
        Ok(Event::PortalData { profile: profile.into(), coupons, sessions })
    }

    /// One command from a caller (CLI, service). Per-client changes show up in the next
    /// `Event::Clients`; the others get their own event.
    pub fn handle(&mut self, cmd: Command) -> Result<Option<Event>> {
        let (mac, cut) = match cmd {
            Command::Stop => return Ok(None),
            Command::Portal { profile, action } => return self.portal_command(&profile, action).map(Some),
            Command::AllowFor { mac, minutes } => return self.set_time_limit(&mac, minutes).map(|_| None),
            Command::LimitSpeed { mac, mbps } => return self.set_speed_limit(&mac, mbps).map(|_| None),
            Command::Block { mac } => return Ok(Some(Event::BlockedChanged { blocked: self.set_blocked(&mac, true)? })),
            Command::Unblock { mac } => return Ok(Some(Event::BlockedChanged { blocked: self.set_blocked(&mac, false)? })),
            Command::CutInternet { mac } => (mac, true),
            Command::RestoreInternet { mac } => (mac, false),
        };
        self.set_internet_cut(mac.as_deref(), cut)?;
        Ok(mac.is_none().then_some(Event::InternetCutAll { cut }))
    }

    fn ctrl_dir(&self) -> PathBuf {
        self.runtime_dir.join(HOSTAPD_CTRL)
    }

    /// Whether a hotspot is running on this machine, started by any process (reads state.json).
    pub fn is_active(&self) -> bool {
        let Some(st) = self.load_state() else { return false };
        [(st.hostapd_pid, bin::HOSTAPD), (st.dnsmasq_pid, bin::DNSMASQ)]
            .into_iter()
            .any(|(pid, name)| pid.is_some_and(|pid| self.backend.is_running(pid, name)))
    }

    pub fn recover(&mut self) -> Result<()> {
        if self.run.is_none() {
            let st = match self.load_state() {
                Some(st) => st,
                // state.json lost: try everything, each undo step is tolerant
                None => RunState {
                    uplink_iface: self.backend.detect_wifi_iface().unwrap_or_default(),
                    ap_iface: AP.into(),
                    hostapd_pid: self.backend.pgrep(&self.runtime_dir.join(HOSTAPD_CONF).display().to_string()).first().copied(),
                    dnsmasq_pid: self.backend.pgrep(&self.runtime_dir.join(DNSMASQ_LEASES).display().to_string()).first().copied(),
                    created: Created {
                        ap_iface: true,
                        addr: true,
                        firewalld_zone: Some(ZONE.into()),
                        nft_table: true,
                        docker_rules: true,
                    },
                    ..Default::default()
                },
            };
            self.run = Some(st);
        }
        self.teardown();
        Ok(())
    }

    fn tick(&mut self) -> Result<Option<Event>> {
        if self.state != HotspotState::Running {
            return Ok(None);
        }
        let exited = |c: &mut Option<Child>| c.as_mut().is_some_and(|c| !matches!(c.try_wait(), Ok(None)));
        let dead = if exited(&mut self.hostapd) {
            Some(HotspotError::HostapdFailed(tail(&self.hostapd_log)))
        } else if exited(&mut self.dnsmasq) {
            Some(HotspotError::DnsmasqFailed(tail(&self.dnsmasq_log)))
        } else {
            None
        };
        if let Some(e) = dead {
            self.teardown();
            self.state = HotspotState::Failed;
            return Err(e);
        }

        let (iface, freq) = self.run.as_ref().map(|r| (r.uplink_iface.clone(), r.freq_mhz)).unwrap();
        match self.backend.uplink_info(&iface) {
            Err(_) => {
                self.stop()?;
                return Ok(Some(Event::UplinkLost { iface }));
            }
            Ok(up) if up.freq_mhz != freq => {
                let now = Instant::now();
                self.restarts.retain(|t| now.duration_since(*t) < RESTART_WINDOW);
                self.teardown();
                if self.restarts.len() >= MAX_RESTARTS {
                    self.state = HotspotState::Failed;
                    return Err(HotspotError::command(
                        "automatic restart",
                        format!("more than {MAX_RESTARTS} restarts in {}s, giving up", RESTART_WINDOW.as_secs()),
                    ));
                }
                self.restarts.push(now);
                let p = self.profile.clone().expect("profile is known while Running");
                self.start(&p)?;
                return Ok(Some(Event::Restarted { channel: up.channel, freq_mhz: up.freq_mhz }));
            }
            Ok(up) => self.uplink = Some(up),
        }

        let b = &self.backend;
        let st = self.run.as_mut().unwrap();
        if let Some(zone) = &st.created.firewalld_zone {
            if b.firewalld_running() && b.firewalld_zone_of(AP).as_deref() != Some(zone.as_str()) {
                eprintln!("warning: {AP} is no longer in zone {zone} (firewall-cmd --reload?), reinstalling");
                warn(b.firewalld_add_iface(zone, AP));
            }
        }
        let nat_gone = st.created.nft_table && !b.nft_nat_present();
        if nat_gone {
            eprintln!("warning: nft table {NAT_TABLE} is gone, reinstalling");
            warn(b.nft_install_nat(&st.uplink_iface));
        }
        if docker_present(b) && !docker_installed(b, AP, &st.uplink_iface).unwrap_or(true) {
            eprintln!("warning: {DOCKER_USER} rules are missing, reinstalling");
            st.created.docker_rules = true;
            warn(docker_install(b, AP, &st.uplink_iface));
            self.forwarding = Forwarding::Ok;
        }
        if nat_gone {
            warn(self.reapply_cuts());
            warn(self.reinstall_portal());
        }
        match self.backend.nft_usage() {
            Ok(usage) => {
                self.usage = usage;
                self.report_usage();
            }
            Err(e) => eprintln!("warning: could not read data usage: {e}"),
        }
        warn(self.apply_speed());
        let mut portal_events = Vec::new();
        self.portal_tick(&mut portal_events);
        self.live.lock().unwrap().events.extend(portal_events);
        let expired: Vec<String> =
            self.deadlines.iter().filter(|(_, d)| **d <= Instant::now()).map(|(mac, _)| mac.clone()).collect();
        for mac in expired {
            self.deadlines.remove(&mac);
            match self.set_blocked(&mac, true) {
                Ok(blocked) => {
                    let mut live = self.live.lock().unwrap();
                    live.events.push(Event::AccessExpired { mac });
                    live.events.push(Event::BlockedChanged { blocked });
                }
                Err(e) => eprintln!("warning: could not block {mac} after its time limit: {e}"),
            }
        }
        self.save()?;
        Ok(None)
    }

    /// Periodic work, about every `TICK` while running: the watcher, then what happened since.
    pub fn poll(&mut self) -> Result<Vec<Event>> {
        let mut events: Vec<Event> = self.tick()?.into_iter().collect();
        events.extend(self.take_events());
        Ok(events)
    }

    fn report_usage(&mut self) {
        let (at, last) = &self.reported_usage;
        if at.elapsed() < USAGE_REPORT_EVERY || *last == self.usage {
            return;
        }
        let live = self.live.lock().unwrap();
        let usage = live
            .clients
            .iter()
            .filter_map(|(mac, _)| {
                let (ip, _) = live.leases.get(mac)?;
                let (down_bytes, up_bytes) = *self.usage.get(ip)?;
                Some(DeviceUsage { mac: mac.clone(), down_bytes, up_bytes })
            })
            .collect();
        drop(live);
        self.reported_usage = (Instant::now(), self.usage.clone());
        self.live.lock().unwrap().events.push(Event::Usage { usage });
    }

    /// Events from hostapd/dnsmasq output, plus `Event::Clients` when the list changed.
    pub fn take_events(&mut self) -> Vec<Event> {
        let mut events = std::mem::take(&mut self.live.lock().unwrap().events);
        self.serve_portal(&mut events);
        // connected time and countdowns change every second: compare without them
        let clients = self.status().clients;
        let comparable: Vec<Client> = clients
            .iter()
            .map(|c| Client {
                connected_secs: 0,
                expires_in_secs: c.expires_in_secs.map(|_| 0),
                down_bytes: 0,
                up_bytes: 0,
                ..c.clone()
            })
            .collect();
        if comparable != self.reported_clients {
            self.reported_clients = comparable;
            events.push(Event::Clients { clients });
        }
        events
    }

    /// Runs until `Command::Stop`, the sender being dropped, or the hotspot ending.
    pub fn supervise(&mut self, commands: &Receiver<Command>, mut on_event: impl FnMut(&Event)) -> Result<()> {
        let mut last_tick = Instant::now();
        loop {
            match commands.recv_timeout(TICK.saturating_sub(last_tick.elapsed())) {
                Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(cmd) => match self.handle(cmd) {
                    Ok(Some(ev)) => on_event(&ev),
                    Ok(None) => {}
                    Err(e) => on_event(&Event::Error { message: e.to_string() }),
                },
                Err(RecvTimeoutError::Timeout) => {}
            }
            if last_tick.elapsed() >= TICK {
                last_tick = Instant::now();
                if let Some(ev) = self.tick()? {
                    on_event(&ev);
                }
            }
            self.take_events().iter().for_each(&mut on_event);
            if self.state != HotspotState::Running {
                break;
            }
        }
        self.stop()
    }

    fn teardown(&mut self) {
        let Some(st) = self.run.take() else { return };
        if let Some(mut rt) = self.portal.take() {
            rt.store.tick(portal_store::now(), 0, &HashSet::new()); // everyone leaves with the network
            warn(rt.store.save(&rt.path)); // its web server stops when `rt` is dropped
        }
        let b = &self.backend;
        for (child, pid, name) in [(self.dnsmasq.take(), st.dnsmasq_pid, bin::DNSMASQ), (self.hostapd.take(), st.hostapd_pid, bin::HOSTAPD)] {
            if let Some(pid) = pid {
                b.stop_process(pid, name);
            }
            if let Some(mut c) = child {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        if st.created.docker_rules {
            docker_remove(b, &st.ap_iface, &st.uplink_iface);
        }
        if st.created.nft_table {
            warn(b.nft_remove_nat());
        }
        if let Some(zone) = &st.created.firewalld_zone {
            if b.firewalld_running() {
                warn(b.firewalld_remove_iface(zone, &st.ap_iface));
            }
        }
        if let Some(prev) = st.prev_ip_forward {
            warn(b.set_ip_forward(prev));
        }
        if st.created.ap_iface {
            warn(b.delete_ap_iface(&st.ap_iface)); // also removes the IP address
        }
        for f in [HOSTAPD_CONF, DNSMASQ_LEASES, STATE_FILE] {
            let _ = fs::remove_file(self.runtime_dir.join(f));
        }
        let _ = fs::remove_dir_all(self.ctrl_dir()); // socket left behind if hostapd was killed
        self.applied_speed.clear(); // tc qdiscs went away with the interface
        let mut live = self.live.lock().unwrap();
        live.clients.clear();
        live.events.clear();
        drop(live);
        self.uplink = None;
        self.forwarding = Forwarding::Ok;
        self.state = HotspotState::Stopped;
    }

    /// Refuses if another instance is running; cleans up if the previous one did not stop gracefully.
    fn check_previous_run(&mut self) -> Result<()> {
        if self.is_active() {
            return Err(HotspotError::AlreadyRunning);
        }
        if self.state_path().exists() {
            self.recover()?;
        }
        Ok(())
    }

    fn st(&mut self) -> &mut RunState {
        self.run.as_mut().expect("run is set before any resource is created")
    }

    fn state_path(&self) -> PathBuf {
        self.runtime_dir.join(STATE_FILE)
    }

    fn load_state(&self) -> Option<RunState> {
        serde_json::from_str(&fs::read_to_string(self.state_path()).ok()?).ok()
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self.run.as_ref().unwrap()).expect("RunState is serializable");
        Ok(fs::write(self.state_path(), json)?)
    }
}

impl Hotspot<SystemBackend> {
    pub fn system() -> Self {
        Self::new(SystemBackend, RUNTIME_DIR.into())
    }
}

impl<B: NetworkBackend> Drop for Hotspot<B> {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

fn warn(r: Result<()>) {
    if let Err(e) = r {
        eprintln!("warning (cleanup): {e}");
    }
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    let _ = fs::remove_file(path); // `mode` only applies on creation
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    Ok(f.write_all(content.as_bytes())?)
}

/// Must be read continuously: a full pipe blocks the process.
fn drain(child: &mut Child, log: Log, live: Shared, parse: fn(&mut Live, &str)) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    let streams: Vec<Box<dyn Read + Send>> = [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .collect();
    for stream in streams {
        let (tx, log, live) = (tx.clone(), log.clone(), live.clone());
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(std::result::Result::ok) {
                parse(&mut live.lock().unwrap(), &line);
                let mut l = log.lock().unwrap();
                if l.len() == LOG_LINES {
                    l.pop_front();
                }
                l.push_back(line.clone());
                drop(l);
                let _ = tx.send(line);
            }
        });
    }
    rx
}

/// `Err(true)` = timeout, `Err(false)` = process died.
fn wait_for(rx: &Receiver<String>, needle: &str, timeout: Duration) -> std::result::Result<(), bool> {
    let deadline = Instant::now() + timeout;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(l) if l.contains(needle) => return Ok(()),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => return Err(true),
            Err(RecvTimeoutError::Disconnected) => return Err(false),
        }
    }
}

fn tail(log: &Log) -> String {
    log.lock().unwrap().iter().cloned().collect::<Vec<_>>().join("\n")
}

/// `ap0: AP-STA-CONNECTED 34:c9:3d:79:c4:67`
fn on_hostapd_line(live: &mut Live, line: &str) {
    let mut words = line.split_whitespace();
    while let Some(w) = words.next() {
        let Some(mac) = words.clone().next() else { return };
        match w {
            AP_STA_CONNECTED => {
                if !live.clients.iter().any(|(m, _)| m == mac) {
                    live.clients.push((mac.into(), Instant::now()));
                }
            }
            AP_STA_DISCONNECTED => live.clients.retain(|(m, _)| m != mac),
            AP_STA_PSK_MISMATCH => live.events.push(Event::WrongPassword { mac: mac.into() }),
            _ => continue,
        }
        return;
    }
}

/// `dnsmasq-dhcp: 292180383 DHCPACK(ap0) 192.168.12.100 34:c9:3d:79:c4:67 pop-os`
fn on_dnsmasq_line(live: &mut Live, line: &str) {
    let mut words = line.split_whitespace().skip_while(|w| !w.starts_with(DHCPACK)).skip(1);
    if let (Some(ip), Some(mac)) = (words.next(), words.next()) {
        // an IP given to a new device no longer belongs to the one that had it
        live.leases.retain(|other, (old_ip, _)| other == mac || old_ip != ip);
        live.leases.insert(mac.into(), (ip.into(), words.next().map(String::from)));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::process::{Command as Process, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::models::{ChannelInfo, DnsmasqArgs, PhyCaps, TimeMode, WifiAdapter};

    #[derive(Debug, Default, PartialEq)]
    struct World {
        iface: bool,
        ip_forward: bool,
        fw: bool,
        nft: bool,
        rules: Vec<String>,
        cut_all: bool,
        cut_macs: Vec<String>,
        denied: Vec<String>,
        usage: HashMap<String, (u64, u64)>,
        tc: Vec<(String, u32)>,
        portal: bool,
        portal_allowed: Vec<String>,
    }

    struct Mock {
        calls: RefCell<Vec<String>>,
        w: RefCell<World>,
        fail: Option<&'static str>,
        freq: Cell<u32>, // 0 = uplink not connected
        docker: Option<bool>, // None = no iptables; Some(false) = no DOCKER-USER chain
        blocked: bool,
        running: bool,
    }

    impl Mock {
        fn new() -> Self {
            Self { calls: RefCell::default(), w: RefCell::default(), fail: None, freq: Cell::new(2427), docker: Some(true), blocked: true, running: false }
        }
        fn failing(step: &'static str) -> Self {
            Self { fail: Some(step), ..Self::new() }
        }
        fn hit(&self, name: &str) -> Result<()> {
            self.calls.borrow_mut().push(name.into());
            if self.fail == Some(name) {
                return Err(HotspotError::command(name, "injected"));
            }
            Ok(())
        }
        fn sh(script: &str) -> Result<Child> {
            Ok(Process::new("sh").args(["-c", script]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?)
        }
    }

    impl NetworkBackend for Mock {
        fn detect_wifi_iface(&self) -> Result<String> {
            self.hit("detect_wifi_iface").map(|_| "wlo1".into())
        }
        fn uplink_info(&self, iface: &str) -> Result<UplinkInfo> {
            self.hit("uplink_info")?;
            let f = self.freq.get();
            if f == 0 {
                return Err(HotspotError::UplinkNotConnected(iface.into()));
            }
            Ok(UplinkInfo {
                iface: iface.into(),
                wifi_adapter: WifiAdapter::new("phy0"),
                channel: if f < 3000 { (f - 2407) / 5 } else { (f - 5000) / 5 },
                freq_mhz: f,
                width_mhz: Some(20),
                ssid: Some("Redmi Note 15 Pro".into()),
                bssid: None,
            })
        }
        fn adapter_caps(&self, _: &WifiAdapter) -> Result<PhyCaps> {
            self.hit("adapter_caps")?;
            let c = |number, freq_mhz, no_ir, disabled| ChannelInfo { number, freq_mhz, no_ir, radar: false, disabled };
            let channels = vec![c(1, 2412, false, false), c(4, 2427, false, false), c(36, 5180, true, false), c(177, 5885, false, true), c(1, 5955, false, true)];
            Ok(PhyCaps { channels, ap_sta: true })
        }
        fn ensure_unmanaged_conf(&self) -> Result<()> {
            Ok(())
        }
        fn is_root(&self) -> bool {
            true
        }
        fn create_ap_iface(&self, _: &str, _: &str) -> Result<()> {
            self.hit("create_ap_iface")?;
            self.w.borrow_mut().iface = true;
            Ok(())
        }
        fn delete_ap_iface(&self, _: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete_ap_iface".into());
            let mut w = self.w.borrow_mut();
            w.iface = false;
            w.tc.clear(); // qdiscs go away with the interface
            w.usage.clear();
            Ok(())
        }
        fn link_up(&self, _: &str) -> Result<()> {
            self.hit("link_up")
        }
        fn add_addr(&self, _: &str, _: &str) -> Result<()> {
            self.hit("add_addr")
        }
        fn get_ip_forward(&self) -> Result<bool> {
            Ok(self.w.borrow().ip_forward)
        }
        fn set_ip_forward(&self, on: bool) -> Result<()> {
            self.hit("set_ip_forward")?;
            self.w.borrow_mut().ip_forward = on;
            Ok(())
        }
        fn firewalld_running(&self) -> bool {
            true
        }
        fn firewalld_add_iface(&self, _: &str, _: &str) -> Result<()> {
            self.hit("firewalld_add_iface")?;
            self.w.borrow_mut().fw = true;
            Ok(())
        }
        fn firewalld_remove_iface(&self, _: &str, _: &str) -> Result<()> {
            self.calls.borrow_mut().push("firewalld_remove_iface".into());
            self.w.borrow_mut().fw = false;
            Ok(())
        }
        fn firewalld_zone_of(&self, _: &str) -> Option<String> {
            self.w.borrow().fw.then(|| "trusted".into())
        }
        fn nft_install_nat(&self, _: &str) -> Result<()> {
            self.hit("nft_install_nat")?;
            let mut w = self.w.borrow_mut();
            (w.nft, w.cut_all, w.portal) = (true, false, false);
            w.cut_macs.clear();
            w.portal_allowed.clear();
            Ok(())
        }
        fn nft_remove_nat(&self) -> Result<()> {
            self.calls.borrow_mut().push("nft_remove_nat".into());
            let mut w = self.w.borrow_mut();
            (w.nft, w.cut_all, w.portal) = (false, false, false);
            w.cut_macs.clear();
            w.portal_allowed.clear();
            Ok(())
        }
        fn nft_cut_iface(&self, _: &str, cut: bool) -> Result<()> {
            self.hit("nft_cut_iface")?;
            self.w.borrow_mut().cut_all = cut;
            Ok(())
        }
        fn nft_cut_mac(&self, mac: &str, cut: bool) -> Result<()> {
            self.hit("nft_cut_mac")?;
            let macs = &mut self.w.borrow_mut().cut_macs;
            macs.retain(|m| m != mac);
            if cut {
                macs.push(mac.into());
            }
            Ok(())
        }
        fn nft_nat_present(&self) -> bool {
            self.w.borrow().nft
        }
        fn nft_install_portal(&self, _: &str, _: &str, _: u16) -> Result<()> {
            self.hit("nft_install_portal")?;
            self.w.borrow_mut().portal = true;
            Ok(())
        }
        fn nft_portal_allow(&self, mac: &str, allow: bool) -> Result<()> {
            let allowed = &mut self.w.borrow_mut().portal_allowed;
            allowed.retain(|m| m != mac);
            if allow {
                allowed.push(mac.into());
            }
            Ok(())
        }
        fn mac_of(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        fn serve_portal(&self, _: SocketAddr, _: PageInfo, _: mpsc::Sender<PortalRequest>) -> Result<Option<PortalServer>> {
            Ok(None)
        }
        fn nft_usage(&self) -> Result<HashMap<String, (u64, u64)>> {
            Ok(self.w.borrow().usage.clone())
        }
        fn tc_limits(&self, _: &str, limits: &[(String, u32)]) -> Result<()> {
            self.hit("tc_limits")?;
            self.w.borrow_mut().tc = limits.to_vec();
            Ok(())
        }
        fn forward_blocked(&self) -> bool {
            self.blocked
        }
        fn iptables(&self, args: &[&str]) -> Result<bool> {
            self.calls.borrow_mut().push(format!("iptables {}", args[0]));
            let Some(chain) = self.docker else {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            };
            let rule = args[1..].join(" ");
            let mut w = self.w.borrow_mut();
            Ok(match args[0] {
                "-S" => chain,
                "-C" => w.rules.contains(&rule),
                "-I" if self.fail == Some("iptables -I") => false,
                "-I" => {
                    w.rules.push(rule);
                    true
                }
                "-D" => {
                    w.rules.retain(|r| *r != rule);
                    true
                }
                _ => unreachable!(),
            })
        }
        fn spawn_hostapd(&self, _: &Path) -> Result<Child> {
            self.hit("spawn_hostapd")?;
            if self.fail == Some("hostapd dies") {
                return Mock::sh("echo 'nl80211: Beacon set failed: -2'; exit 1");
            }
            Mock::sh("echo 'ap0: AP-ENABLED'; echo 'ap0: AP-STA-CONNECTED 34:c9:3d:79:c4:67'; exec sleep 30")
        }
        fn block_client(&self, _: &Path, _: &str, mac: &str, block: bool) -> Result<()> {
            self.hit("block_client")?;
            let denied = &mut self.w.borrow_mut().denied;
            denied.retain(|m| m != mac);
            if block {
                denied.push(mac.into());
            }
            Ok(())
        }
        fn spawn_dnsmasq(&self, _: &DnsmasqArgs) -> Result<Child> {
            self.hit("spawn_dnsmasq")?;
            if self.fail == Some("dnsmasq dies") {
                return Mock::sh("echo 'dnsmasq: failed to create listening socket' >&2; exit 2");
            }
            Mock::sh("exec sleep 30")
        }
        fn is_running(&self, _: u32, _: &str) -> bool {
            self.running
        }
        fn stop_process(&self, _: u32, name: &str) {
            self.calls.borrow_mut().push(format!("stop {name}"));
            if name == bin::HOSTAPD {
                self.w.borrow_mut().denied.clear(); // the deny list lives in hostapd's memory
            }
        }
        fn pgrep(&self, _: &str) -> Vec<u32> {
            vec![]
        }
    }

    fn hotspot(m: Mock) -> Hotspot<Mock> {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("hs-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        Hotspot::new(m, dir)
    }

    fn profile() -> HotspotProfile {
        HotspotProfile::new("maison", "TestHS", "motdepasse123")
    }

    fn clean(h: &Hotspot<Mock>) -> bool {
        *h.backend().w.borrow() == World::default() && fs::read_dir(&h.runtime_dir).map_or(true, |mut d| d.next().is_none())
    }

    const ORDER: &[&str] = &[
        "detect_wifi_iface",
        "uplink_info",
        "adapter_caps",
        "create_ap_iface",
        "link_up",
        "spawn_hostapd",
        "add_addr",
        "set_ip_forward",
        "firewalld_add_iface",
        "nft_install_nat",
        "iptables -S",
        "iptables -C",
        "iptables -I",
        "iptables -C",
        "iptables -I",
        "spawn_dnsmasq",
    ];

    #[test]
    fn full_start_then_stop_twice() {
        let mut h = hotspot(Mock::new());
        let s = h.start(&profile()).unwrap();
        assert_eq!(s.state, HotspotState::Running);
        assert_eq!(s.ap_channel, Some(4));
        assert_eq!(s.forwarding, Forwarding::Ok);
        assert_eq!(*h.backend().calls.borrow(), ORDER);
        assert_eq!(h.backend().w.borrow().rules.len(), 2);
        assert!(h.runtime_dir.join("state.json").exists());
        assert_eq!(fs::metadata(h.runtime_dir.join("hostapd.conf")).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(matches!(h.start(&profile()), Err(HotspotError::AlreadyRunning)));

        thread::sleep(Duration::from_millis(100));
        assert_eq!(h.status().clients[0].mac, "34:c9:3d:79:c4:67");

        h.stop().unwrap();
        assert!(clean(&h));
        assert_eq!(h.status().state, HotspotState::Stopped);
        h.stop().unwrap();
    }

    #[test]
    fn failure_at_each_step_rolls_everything_back() {
        for step in [
            "detect_wifi_iface",
            "uplink_info",
            "adapter_caps",
            "create_ap_iface",
            "link_up",
            "spawn_hostapd",
            "hostapd dies",
            "add_addr",
            "set_ip_forward",
            "firewalld_add_iface",
            "nft_install_nat",
            "iptables -I",
            "spawn_dnsmasq",
            "dnsmasq dies",
        ] {
            let mut h = hotspot(Mock::failing(step));
            assert!(h.start(&profile()).is_err(), "{step}");
            assert!(clean(&h), "{step} : reste {:?}", h.backend().w.borrow());
            assert_eq!(h.status().state, HotspotState::Failed);
        }
    }

    #[test]
    fn hostapd_failure_carries_log() {
        let mut h = hotspot(Mock::failing("hostapd dies"));
        match h.start(&profile()) {
            Err(HotspotError::HostapdFailed(log)) => assert!(log.contains("Beacon set failed")),
            r => panic!("{:?}", r.map(|s| s.state)),
        }
    }

    #[test]
    fn disabled_channel_refused_before_any_change() {
        let m = Mock::new();
        m.freq.set(5885);
        let mut h = hotspot(m);
        assert!(matches!(h.start(&profile()), Err(HotspotError::ChannelNotAllowedForAp { channel: 177, freq_mhz: 5885 })));
        assert!(!h.backend().calls.borrow().contains(&"create_ap_iface".to_string()));
    }

    #[test]
    fn restricted_channel_still_tried() {
        let m = Mock::new();
        m.freq.set(5180);
        let mut h = hotspot(m);
        assert_eq!(h.start(&profile()).unwrap().ap_channel, Some(36));
    }

    #[test]
    fn docker_scenarios() {
        for docker in [None, Some(false)] {
            let mut h = hotspot(Mock { docker, ..Mock::new() });
            assert!(matches!(h.start(&profile()).unwrap().forwarding, Forwarding::Unverified { .. }));
        }
        let mut h = hotspot(Mock { docker: None, blocked: false, ..Mock::new() });
        assert_eq!(h.start(&profile()).unwrap().forwarding, Forwarding::Ok);

        let m = Mock::new();
        m.w.borrow_mut().rules = vec![
            "DOCKER-USER -i ap0 -o wlo1 -j ACCEPT".into(),
            "DOCKER-USER -i wlo1 -o ap0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".into(),
        ];
        let mut h = hotspot(m);
        h.start(&profile()).unwrap();
        assert!(!h.backend().calls.borrow().contains(&"iptables -I".to_string()));
        assert_eq!(h.backend().w.borrow().rules.len(), 2);

        h.backend().w.borrow_mut().rules.clear();
        h.backend().w.borrow_mut().fw = false;
        h.backend().w.borrow_mut().nft = false;
        assert_eq!(h.tick().unwrap(), None);
        let w = h.backend().w.borrow();
        assert!(w.fw && w.nft && w.rules.len() == 2);
    }

    #[test]
    fn tick_restarts_on_channel_change_and_stops_on_uplink_loss() {
        let mut h = hotspot(Mock::new());
        h.start(&profile()).unwrap();
        h.backend().freq.set(5180);
        assert!(h.tick().unwrap().unwrap().to_string().contains("channel 36"));
        assert_eq!(h.status().ap_channel, Some(36));
        assert_eq!(h.status().state, HotspotState::Running);

        h.backend().freq.set(0);
        assert!(h.tick().unwrap().unwrap().to_string().contains("lost"));
        assert!(clean(&h));
    }

    #[test]
    fn recover_from_partial_state() {
        let mut h = hotspot(Mock::new());
        fs::create_dir_all(&h.runtime_dir).unwrap();
        fs::write(
            h.state_path(),
            r#"{"uplink_iface":"wlo1","ap_iface":"ap0","channel":4,"freq_mhz":2427,
                "hostapd_pid":4242,"dnsmasq_pid":null,"prev_ip_forward":null,
                "created":{"ap_iface":true,"addr":false,"firewalld_zone":null,"nft_table":true,"docker_rules":false}}"#,
        )
        .unwrap();
        {
            let mut w = h.backend().w.borrow_mut();
            w.iface = true;
            w.nft = true;
        }
        h.recover().unwrap();
        assert!(clean(&h));
        assert!(h.backend().calls.borrow().contains(&"stop hostapd".to_string()));
    }

    #[test]
    fn previous_run_live_or_stale() {
        let stale = r#"{"uplink_iface":"wlo1","ap_iface":"ap0","channel":4,"freq_mhz":2427,
            "hostapd_pid":4242,"dnsmasq_pid":4243,"prev_ip_forward":null,
            "created":{"ap_iface":true,"addr":false,"firewalld_zone":null,"nft_table":true,"docker_rules":false}}"#;

        let mut h = hotspot(Mock { running: true, ..Mock::new() });
        assert!(!h.is_active());
        fs::create_dir_all(&h.runtime_dir).unwrap();
        fs::write(h.state_path(), stale).unwrap();
        assert!(h.is_active());
        assert!(matches!(h.start(&profile()), Err(HotspotError::AlreadyRunning)));

        let mut h = hotspot(Mock::new());
        fs::create_dir_all(&h.runtime_dir).unwrap();
        fs::write(h.state_path(), stale).unwrap();
        assert!(!h.is_active());
        h.backend().w.borrow_mut().nft = true;
        assert_eq!(h.start(&profile()).unwrap().state, HotspotState::Running);
        assert!(h.backend().calls.borrow().contains(&"stop hostapd".to_string()));
    }

    #[test]
    fn output_parsing() {
        let mut live = Live::default();
        on_hostapd_line(&mut live, "ap0: AP-STA-CONNECTED 34:c9:3d:79:c4:67");
        on_hostapd_line(&mut live, "ap0: AP-STA-CONNECTED 34:c9:3d:79:c4:67");
        on_hostapd_line(&mut live, "ap0: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff");
        on_hostapd_line(&mut live, "ap0: AP-STA-DISCONNECTED 34:c9:3d:79:c4:67");
        on_hostapd_line(&mut live, "ap0: AP-STA-POSSIBLE-PSK-MISMATCH 12:5a:7a:56:8a:d6");
        let macs: Vec<&str> = live.clients.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(macs, ["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(live.events, [Event::WrongPassword { mac: "12:5a:7a:56:8a:d6".into() }]);

        on_dnsmasq_line(&mut live, "dnsmasq-dhcp: 292180383 DHCPREQUEST(ap0) 192.168.12.100 34:c9:3d:79:c4:67");
        on_dnsmasq_line(&mut live, "dnsmasq-dhcp: 292180383 DHCPACK(ap0) 192.168.12.100 34:c9:3d:79:c4:67 pop-os");
        on_dnsmasq_line(&mut live, "dnsmasq-dhcp: 292180384 DHCPACK(ap0) 192.168.12.101 aa:bb:cc:dd:ee:ff");
        // .100 goes to a new device: the old owner loses it
        on_dnsmasq_line(&mut live, "dnsmasq-dhcp: 292180385 DHCPACK(ap0) 192.168.12.100 de:ad:be:ef:00:01");
        assert!(!live.leases.contains_key("34:c9:3d:79:c4:67"));
        live.leases.remove("de:ad:be:ef:00:01");
        on_dnsmasq_line(&mut live, "dnsmasq-dhcp: 292180383 DHCPACK(ap0) 192.168.12.100 34:c9:3d:79:c4:67 pop-os");
        assert_eq!(live.leases["34:c9:3d:79:c4:67"], ("192.168.12.100".into(), Some("pop-os".into())));
        assert_eq!(live.leases["aa:bb:cc:dd:ee:ff"], ("192.168.12.101".into(), None));
        assert_eq!(live.leases.len(), 2);
    }

    #[test]
    fn internet_cut() {
        let mut h = hotspot(Mock::new());
        assert!(matches!(h.set_internet_cut(None, true), Err(HotspotError::NotRunning)));
        h.start(&profile()).unwrap();

        h.set_internet_cut(Some("34:C9:3D:79:C4:67"), true).unwrap();
        h.set_internet_cut(None, true).unwrap();
        assert!(matches!(h.set_internet_cut(Some("nope } drop"), true), Err(HotspotError::InvalidMac(_))));
        thread::sleep(Duration::from_millis(100));
        let s = h.status();
        assert!(s.internet_cut_all && s.clients[0].internet_cut);
        assert_eq!(h.backend().w.borrow().cut_macs, ["34:c9:3d:79:c4:67"]);

        // table recreated behind our back: reconcile puts the cuts back
        h.backend().w.borrow_mut().nft = false;
        h.tick().unwrap();
        let w = h.backend().w.borrow();
        assert!(w.cut_all && w.cut_macs == ["34:c9:3d:79:c4:67"]);
        drop(w);

        h.set_internet_cut(None, false).unwrap();
        assert!(!h.backend().w.borrow().cut_all);
        h.stop().unwrap();
        assert!(clean(&h));
        assert!(!h.status().internet_cut_all);
    }

    #[test]
    fn blocking() {
        let mut p = profile();
        p.blocked = vec![BlockedDevice { mac: "aa:bb:cc:dd:ee:ff".into(), name: None }];
        let macs = |list: Vec<BlockedDevice>| list.into_iter().map(|b| b.mac).collect::<Vec<_>>();
        let mut h = hotspot(Mock::new());
        h.start(&p).unwrap();
        assert_eq!(h.backend().w.borrow().denied, ["aa:bb:cc:dd:ee:ff"]);

        h.live.lock().unwrap().leases.insert("12:5a:7a:56:8a:d6".into(), ("192.168.12.100".into(), Some("REDMI".into())));
        assert_eq!(macs(h.set_blocked("12:5A:7A:56:8A:D6", true).unwrap()), ["aa:bb:cc:dd:ee:ff", "12:5a:7a:56:8a:d6"]);
        assert_eq!(macs(h.set_blocked("aa:bb:cc:dd:ee:ff", false).unwrap()), ["12:5a:7a:56:8a:d6"]);
        assert_eq!(h.status().blocked, [BlockedDevice { mac: "12:5a:7a:56:8a:d6".into(), name: Some("REDMI".into()) }]);

        // an automatic restart keeps the list
        h.backend().freq.set(5180);
        h.tick().unwrap();
        assert_eq!(h.backend().w.borrow().denied, ["12:5a:7a:56:8a:d6"]);
    }

    #[test]
    fn usage_time_and_speed_limits() {
        let mut h = hotspot(Mock::new());
        h.start(&profile()).unwrap();
        thread::sleep(Duration::from_millis(100));
        let mac = "34:c9:3d:79:c4:67";
        h.live.lock().unwrap().leases.insert(mac.into(), ("192.168.12.100".into(), None));
        h.backend().w.borrow_mut().usage.insert("192.168.12.100".into(), (3400, 60));

        h.set_speed_limit(mac, Some(5)).unwrap();
        assert_eq!(h.backend().w.borrow().tc, [("192.168.12.100".to_string(), 5)]);
        assert!(h.set_speed_limit(mac, Some(0)).is_err());
        h.set_time_limit(mac, Some(30)).unwrap();
        assert!(h.set_time_limit(mac, Some(0)).is_err());

        h.tick().unwrap();
        let c = &h.status().clients[0];
        assert_eq!((c.down_bytes, c.up_bytes, c.speed_limit_mbps), (3400, 60, Some(5)));
        assert!(c.expires_in_secs.unwrap() > 29 * 60);

        // deadline passes: the device gets blocked and both events are queued
        h.deadlines.insert(mac.into(), Instant::now());
        h.tick().unwrap();
        assert_eq!(h.backend().w.borrow().denied, [mac]);
        let events = std::mem::take(&mut h.live.lock().unwrap().events);
        assert_eq!(events[0], Event::AccessExpired { mac: mac.into() });
        assert!(matches!(&events[1], Event::BlockedChanged { blocked } if blocked[0].mac == mac));

        h.set_speed_limit(mac, None).unwrap();
        assert!(h.backend().w.borrow().tc.is_empty());
        h.stop().unwrap();
        assert!(clean(&h));
    }

    #[test]
    fn speed_limit_survives_automatic_restart() {
        let mut h = hotspot(Mock::new());
        h.start(&profile()).unwrap();
        let mac = "34:c9:3d:79:c4:67";
        h.live.lock().unwrap().leases.insert(mac.into(), ("192.168.12.100".into(), None));
        h.set_speed_limit(mac, Some(5)).unwrap();

        h.backend().freq.set(5180); // upstream changes channel: ap0 and its qdiscs are recreated
        h.tick().unwrap();
        assert!(h.backend().w.borrow().tc.is_empty());
        h.tick().unwrap();
        assert_eq!(h.backend().w.borrow().tc, [("192.168.12.100".to_string(), 5)]);
    }

    fn sign_in(code: &str) -> SignIn {
        SignIn {
            first_name: "Asha".into(),
            last_name: "Rao".into(),
            country_code: "+91".into(),
            phone: "9876543210".into(),
            code: code.into(),
        }
    }

    #[test]
    fn captive_portal_end_to_end() {
        let mut h = hotspot(Mock::new());
        h.portal_dir = h.runtime_dir.with_extension("portal");
        let profile = HotspotProfile::new_portal("cafe", "Cafe WiFi");
        let create = PortalAction::CreateCoupons { count: 2, duration_min: 60, time_mode: TimeMode::Real, max_devices: 1 };
        // coupons can be made before the hotspot runs
        let Some(Event::PortalData { coupons, .. }) = h.handle(Command::Portal { profile: "cafe".into(), action: create }).unwrap() else {
            panic!()
        };
        let code = coupons[0].code.clone();

        h.start(&profile).unwrap();
        assert!(h.backend().w.borrow().portal);
        let mac = "12:5a:7a:56:8a:d6";
        let mut events = vec![];
        for _ in 0..PORTAL_MAX_FAILURES {
            assert!(h.portal_sign_in(mac, "192.168.12.50", &sign_in("WRONG-CODE"), &mut events).is_err());
        }
        let locked = h.portal_sign_in(mac, "192.168.12.50", &sign_in(&code), &mut events).unwrap_err();
        assert!(locked.contains("Too many wrong codes"), "{locked}");
        h.portal.as_mut().unwrap().failures.clear();

        assert_eq!(h.portal_sign_in(mac, "192.168.12.50", &sign_in(&code), &mut events).unwrap(), 3600);
        assert_eq!(h.backend().w.borrow().portal_allowed, [mac]);
        assert!(matches!(&events[0], Event::PortalSignIn { name, .. } if name == "Asha Rao"));

        // our nft table vanished: the portal rules and the allowed device come back
        h.backend().w.borrow_mut().nft = false;
        h.tick().unwrap();
        let w = h.backend().w.borrow();
        assert!(w.portal && w.portal_allowed == [mac]);
        drop(w);

        // time runs out
        h.portal.as_mut().unwrap().store.coupons.iter_mut().for_each(|c| c.expires = c.expires.map(|e| e - 3600));
        h.tick().unwrap();
        assert!(h.backend().w.borrow().portal_allowed.is_empty());
        assert!(h.take_events().iter().any(|e| matches!(e, Event::PortalSessionEnded { .. })));

        h.stop().unwrap();
        assert!(clean(&h));
        // data survived the stop
        let list = Command::Portal { profile: "cafe".into(), action: PortalAction::List };
        let Some(Event::PortalData { sessions, .. }) = h.handle(list).unwrap() else { panic!() };
        assert_eq!(sessions[0].phone.as_deref(), Some("+919876543210"));
        fs::remove_dir_all(&h.portal_dir).unwrap();
    }

    #[test]
    fn supervise_runs_commands_and_reports_events() {
        let mut h = hotspot(Mock::new());
        h.start(&profile()).unwrap();
        let (tx, rx) = mpsc::channel();
        tx.send(Command::CutInternet { mac: Some("34:c9:3d:79:c4:67".into()) }).unwrap();
        tx.send(Command::CutInternet { mac: Some("bad".into()) }).unwrap();
        tx.send(Command::Block { mac: "aa:bb:cc:dd:ee:ff".into() }).unwrap();
        tx.send(Command::CutInternet { mac: None }).unwrap();
        tx.send(Command::Stop).unwrap();
        let mut events = vec![];
        h.supervise(&rx, |e| events.push(e.clone())).unwrap();

        assert!(events.iter().any(|e| matches!(e, Event::Error { message } if message.contains("bad"))));
        assert!(events.iter().any(|e| matches!(e, Event::Clients { clients } if clients[0].internet_cut)));
        assert!(events.contains(&Event::BlockedChanged { blocked: vec![BlockedDevice { mac: "aa:bb:cc:dd:ee:ff".into(), name: None }] }));
        assert!(events.contains(&Event::InternetCutAll { cut: true }));
        assert!(clean(&h));
    }
}
