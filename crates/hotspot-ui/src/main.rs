mod qr;

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use hotspot_core::{
    generate_passphrase, BlockedDevice as Blocked, HotspotError, HotspotProfile, Probe, ProfileStore, CONTROL_SOCKET,
};
use serde_json::{json, Value};
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};

slint::include_modules!();

const PROBE_EVERY: Duration = Duration::from_secs(5);
const CLIENT_TIME_REFRESH: Duration = Duration::from_secs(30);
const COPIED_FOR: Duration = Duration::from_secs(2);
/// pkexec exit codes when the user dismisses the dialog or isn't allowed.
const PKEXEC_DENIED: [i32; 2] = [126, 127];
const TIME_PRESETS_MIN: [u32; 3] = [30, 60, 120];
const SPEED_PRESETS_MBPS: [u32; 3] = [1, 5, 10];
const TRAY_SYNC: Duration = Duration::from_secs(1);
/// `hotspot-ui --tray`: start with only the tray icon, as the login autostart entry does.
const TRAY_FLAG: &str = "--tray";
/// Only if the renderer can't report its first frame.
const TRAY_START_HIDE_FALLBACK: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Ui {
    profiles: Vec<HotspotProfile>,
    /// stdin of `pkexec hotspot-cli start --json`; dropping it stops the hotspot.
    pkexec: Option<ChildStdin>,
    /// Which pkexec run is current: a restart starts a new one before the old one has exited.
    pkexec_run: u64,
    /// Connection to the background service, when it is installed (`install.sh --service`).
    service: Option<UnixStream>,
    clients: Vec<ClientEntry>,
    pending_restart: bool,
    failure_shown: bool,
    edit_original: Option<String>,
    /// MACs already announced by a notification during this session.
    seen: HashSet<String>,
    /// Stays false until the Settings section exists.
    notifications_off: bool,
}

struct ClientEntry {
    mac: String,
    hostname: Option<String>,
    ip: Option<String>,
    internet_cut: bool,
    since: Instant,
    down: u64,
    up: u64,
    expires_at: Option<Instant>,
    speed: Option<u32>,
}

thread_local! {
    static UI: RefCell<Ui> = RefCell::default();
}

fn ui<R>(f: impl FnOnce(&mut Ui) -> R) -> R {
    UI.with(|u| f(&mut u.borrow_mut()))
}

/// The UI never runs network commands itself: it goes through hotspot-cli, installed next to it.
fn cli_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("hotspot-cli")))
        .unwrap_or_else(|| "hotspot-cli".into())
}

fn band(freq_mhz: u32) -> &'static str {
    match freq_mhz {
        0..=2999 => "2.4 GHz",
        3000..=5924 => "5 GHz",
        _ => "6 GHz",
    }
}

fn connected_label(secs: u64) -> String {
    match secs / 60 {
        0 => "Connected just now".into(),
        m @ 1..=59 => format!("Connected {m} min"),
        m => format!("Connected {} h {} min", m / 60, m % 60),
    }
}

fn human_bytes(n: u64) -> String {
    match n {
        0..1_000 => format!("{n} B"),
        1_000..1_000_000 => format!("{:.0} kB", n as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", n as f64 / 1e6),
        _ => format!("{:.2} GB", n as f64 / 1e9),
    }
}

fn expires_label(at: Instant) -> String {
    match at.saturating_duration_since(Instant::now()).as_secs() / 60 {
        0 => "Expires in under a minute".into(),
        m @ 1..=59 => format!("Expires in {m} min"),
        m => format!("Expires in {} h {} min", m / 60, m % 60),
    }
}

fn notify(title: &str, body: &str) {
    if ui(|u| u.notifications_off) {
        return;
    }
    let _ = Command::new("notify-send").args(["--app-name=Hotspot", "--icon=hotspot", title, body]).spawn();
}

/// The profile whose aliases name the devices: the running one, else the selected one.
fn naming_profile(state: &AppState) -> Option<HotspotProfile> {
    let running = state.get_running_profile();
    let name = if running.is_empty() { state.get_current().name } else { running };
    ui(|u| u.profiles.iter().find(|p| p.name == name.as_str()).cloned())
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

fn push_notice(app: &MainWindow, id: &str, kind: NoticeKind, title: &str, body: &str, dismissible: bool) {
    let state = app.global::<AppState>();
    let mut notices: Vec<Notice> = state.get_notices().iter().filter(|n| n.id != id).collect();
    let summary = body.split_whitespace().collect::<Vec<_>>().join(" ");
    notices.push(Notice {
        id: id.into(),
        kind,
        title: title.into(),
        body: summary.into(),
        dismissible,
        details: if body.contains('\n') { body.into() } else { SharedString::new() },
    });
    // design.md §4.1: error, then not-supported, then warnings, then transient notices
    let rank = |n: &Notice| match (n.kind, n.dismissible) {
        (NoticeKind::Error, _) => 0,
        (NoticeKind::Warn, false) => 1,
        _ => 2,
    };
    notices.sort_by_key(rank);
    state.set_notices(model(notices));
}

fn remove_notice(app: &MainWindow, id: &str) {
    let state = app.global::<AppState>();
    let notices: Vec<Notice> = state.get_notices().iter().filter(|n| n.id != id).collect();
    state.set_notices(model(notices));
}

fn remove_notices_with_prefix(app: &MainWindow, prefix: &str) {
    let state = app.global::<AppState>();
    let notices: Vec<Notice> = state.get_notices().iter().filter(|n| !n.id.starts_with(prefix)).collect();
    state.set_notices(model(notices));
}

fn load_profiles(app: &MainWindow, keep: Option<&str>) {
    let state = app.global::<AppState>();
    let profiles = ProfileStore::list(None).unwrap_or_else(|e| {
        push_notice(app, "profiles", NoticeKind::Error, "Couldn't read profiles", &e.to_string(), true);
        Vec::new()
    });
    let rows: Vec<Profile> = profiles
        .iter()
        .map(|p| Profile {
            name: p.name.as_str().into(),
            ssid: p.ssid.as_str().into(),
            password: p.passphrase.as_str().into(),
            hidden: p.hidden,
            max_clients: p.max_clients.map(|n| n.to_string()).unwrap_or_default().into(),
        })
        .collect();
    let labels: Vec<SharedString> = if profiles.is_empty() {
        vec!["No profile".into()]
    } else {
        profiles.iter().map(|p| format!("{} — {}", p.name, p.ssid).into()).collect()
    };
    let keep = keep.map(str::to_owned).or_else(|| Some(state.get_current().name.to_string()));
    let selected = keep.and_then(|name| profiles.iter().position(|p| p.name == name)).unwrap_or(0);

    state.set_profiles(model(rows));
    state.set_profile_labels(model(labels));
    if profiles.is_empty() {
        state.set_selected(-1);
        state.set_blocked(model(Vec::new()));
        if state.get_idle() {
            state.set_phase(Phase::NoProfile);
        }
    } else {
        state.set_selected(selected as i32);
        state.set_blocked(blocked_model(&profiles[selected].blocked, Some(&profiles[selected])));
        if state.get_phase() == Phase::NoProfile {
            state.set_phase(Phase::Stopped);
        }
    }
    ui(|u| u.profiles = profiles);
}

fn blocked_model(list: &[Blocked], profile: Option<&HotspotProfile>) -> ModelRc<BlockedDevice> {
    let name = |b: &Blocked| profile.and_then(|p| p.display_name(&b.mac, b.name.as_deref())).or(b.name.clone());
    model(list.iter().map(|b| BlockedDevice { mac: b.mac.as_str().into(), name: name(b).unwrap_or_default().into() }).collect())
}

fn form_max(state: &AppState) -> Result<Option<u32>, String> {
    let text = state.get_form_max();
    match text.trim() {
        "" => Ok(None),
        t => t.parse().map(Some).map_err(|_| "max devices must be a number".into()),
    }
}

fn form_profile(state: &AppState) -> HotspotProfile {
    let mut p = HotspotProfile::new(&state.get_form_name(), &state.get_form_ssid(), &state.get_form_password());
    p.hidden = state.get_form_hidden();
    p.max_clients = form_max(state).ok().flatten();
    p
}

fn message(e: HotspotError) -> String {
    match e {
        HotspotError::InvalidProfile(m) => m,
        e => e.to_string(),
    }
}

fn validate_form(app: &MainWindow) {
    let state = app.global::<AppState>();
    let p = form_profile(&state);
    let errors = p.field_errors();
    let original = ui(|u| u.edit_original.clone());
    let duplicate = ui(|u| u.profiles.iter().any(|q| q.name == p.name && Some(&q.name) != original.as_ref()));
    let name_error = errors.name.or(duplicate.then(|| "a profile with this name already exists".into()));
    state.set_form_name_error(name_error.unwrap_or_default().into());
    state.set_form_ssid_error(errors.ssid.unwrap_or_default().into());
    state.set_form_password_error(errors.passphrase.unwrap_or_default().into());
    state.set_form_ssid_bytes(p.ssid.len() as i32);
    // the range check lives in the core's validate(): run it on a profile that is valid otherwise
    let max_error = form_max(&state).err().or_else(|| {
        let check = HotspotProfile { max_clients: p.max_clients, ..HotspotProfile::new("a", "b", "password") };
        check.validate().err().map(message)
    });
    state.set_form_max_error(max_error.unwrap_or_default().into());
}

fn open_form(app: &MainWindow, edit: bool) {
    let state = app.global::<AppState>();
    let current = state.get_current();
    let (name, ssid, password) = if edit { (current.name, current.ssid, current.password) } else { Default::default() };
    state.set_form_hidden(edit && current.hidden);
    state.set_form_max(if edit { current.max_clients } else { SharedString::new() });
    ui(|u| u.edit_original = edit.then(|| name.to_string()));
    state.set_form_name(name);
    state.set_form_ssid(ssid);
    state.set_form_password(password);
    state.set_form_password_revealed(false);
    state.set_form_attempted(false);
    state.set_sheet(if edit { Sheet::ProfileEdit } else { Sheet::ProfileNew });
    validate_form(app);
}

fn save_form(app: &MainWindow) {
    let state = app.global::<AppState>();
    let original = ui(|u| u.edit_original.clone());
    let base = ui(|u| original.as_ref().and_then(|name| u.profiles.iter().find(|p| &p.name == name).cloned()));
    let form = form_profile(&state);
    let profile = match base {
        Some(base) => HotspotProfile {
            name: form.name,
            ssid: form.ssid,
            passphrase: form.passphrase,
            hidden: form.hidden,
            max_clients: form.max_clients,
            ..base
        },
        None => form,
    };
    match ProfileStore::upsert(original.as_deref(), profile.clone(), None) {
        Ok(_) => {
            if state.get_running_profile().as_str() == original.as_deref().unwrap_or_default() {
                state.set_running_profile(profile.name.as_str().into());
            }
            state.set_sheet(Sheet::None);
            load_profiles(app, Some(&profile.name));
        }
        Err(e) => push_notice(app, "profiles", NoticeKind::Error, "Couldn't save the profile", &e.to_string(), true),
    }
}

/// Saving the running profile with a change that ends up in hostapd.conf needs a restart.
fn needs_restart(app: &MainWindow) -> bool {
    let state = app.global::<AppState>();
    let current = state.get_current();
    state.get_editing_running()
        && (current.ssid != state.get_form_ssid()
            || current.password != state.get_form_password()
            || current.hidden != state.get_form_hidden()
            || current.max_clients.trim() != state.get_form_max().trim())
}

/// `hotspot-cli probe --json` in a thread: it shells out to iw and nmcli, too slow for the UI thread.
fn spawn_probe(weak: Weak<MainWindow>) {
    std::thread::spawn(move || {
        let result = Command::new(cli_path())
            .args(["probe", "--json"])
            .output()
            .ok()
            .and_then(|out| serde_json::from_slice::<Probe>(&out.stdout).ok());
        let _ = weak.upgrade_in_event_loop(move |app| apply_probe(&app, result));
    });
}

fn apply_probe(app: &MainWindow, probe: Option<Probe>) {
    let state = app.global::<AppState>();
    let Some(probe) = probe else {
        state.set_upstream(Upstream::default());
        state.set_unsupported(Unsupported::NoUpstream);
        remove_notice(app, "unsupported");
        return;
    };
    let up = probe.uplink;
    state.set_upstream(Upstream {
        connected: true,
        ssid: up.ssid.clone().unwrap_or_default().into(),
        iface: up.iface.as_str().into(),
        channel: up.channel as i32,
        freq_mhz: up.freq_mhz as i32,
        band: band(up.freq_mhz).into(),
    });
    if probe.ap_sta {
        state.set_unsupported(Unsupported::None);
        remove_notice(app, "unsupported");
    } else {
        state.set_unsupported(Unsupported::NoApSta);
        let body = format!(
            "{} doesn't support access point and client mode at the same time (AP+STA), so the hotspot can't run while this computer is connected to {}.",
            up.iface,
            up.ssid.unwrap_or_default()
        );
        push_notice(app, "unsupported", NoticeKind::Warn, "This Wi-Fi card can't share and stay connected", &body, false);
    }
}

fn set_phase(app: &MainWindow, phase: Phase) {
    let state = app.global::<AppState>();
    if state.get_phase() != phase {
        state.set_password_revealed(false);
        state.set_qr_shown(false);
    }
    state.set_phase(phase);
}

fn send(cmd: Value) {
    ui(|u| {
        let _ = match (u.pkexec.as_mut(), u.service.as_mut()) {
            (Some(stdin), _) => writeln!(stdin, "{cmd}"),
            (None, Some(stream)) => writeln!(stream, "{cmd}"),
            (None, None) => Ok(()),
        };
    });
}

/// Talks to the background service if it runs; otherwise the UI falls back to pkexec.
fn connect_service(app: &MainWindow) {
    let stream = match UnixStream::connect(CONTROL_SOCKET) {
        Ok(s) => s,
        // the service runs, but this session doesn't have the group yet (usermod needs a new login)
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let body = "The hotspot service is installed, but this session can't use it yet. Log out and back \
                        in once. Until then, the app asks for your password and quitting it stops the hotspot.";
            push_notice(app, "service", NoticeKind::Warn, "Log out and back in to finish the setup", body, true);
            return;
        }
        Err(_) => return,
    };
    let Ok(reader) = stream.try_clone() else { return };
    ui(|u| u.service = Some(stream));
    app.global::<AppState>().set_service(true);
    let weak = app.as_weak();
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<Value>(&line) {
                let _ = weak.upgrade_in_event_loop(move |app| on_event(&app, event));
            }
        }
        let _ = weak.upgrade_in_event_loop(|app| on_service_lost(&app));
    });
}

fn on_service_lost(app: &MainWindow) {
    let state = app.global::<AppState>();
    ui(|u| u.service = None);
    state.set_service(false);
    if !state.get_idle() {
        handle_stopped(app);
    }
    let body = "The hotspot service stopped. The app will ask for your password to start the hotspot.";
    push_notice(app, "service", NoticeKind::Warn, "Lost the connection to the hotspot service", body, true);
}

fn start(app: &MainWindow) {
    let state = app.global::<AppState>();
    let name = state.get_current().name.to_string();
    if ui(|u| u.service.is_some()) {
        // the service never reads our files: it gets the whole profile
        let Some(profile) = ui(|u| u.profiles.iter().find(|p| p.name == name).cloned()) else { return };
        remove_notice(app, "failed");
        remove_notice(app, "upstream-lost");
        state.set_running_profile(name.into());
        ui(|u| u.failure_shown = false);
        set_phase(app, Phase::Starting);
        send(json!({ "cmd": "start", "profile": profile }));
        return;
    }
    let spawned = Command::new("pkexec")
        .arg(cli_path())
        .args(["start", "--profile", &name, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            push_notice(app, "failed", NoticeKind::Error, "Couldn't start the hotspot", &format!("pkexec: {e}"), true);
            return;
        }
    };
    remove_notice(app, "failed");
    remove_notice(app, "upstream-lost");
    state.set_running_profile(name.into());
    set_phase(app, Phase::Authorizing);
    let run = ui(|u| {
        u.pkexec = child.stdin.take();
        u.pkexec_run += 1;
        u.failure_shown = false;
        u.pkexec_run
    });

    let stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let weak = app.as_weak();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<Value>(&line) {
                let _ = weak.upgrade_in_event_loop(move |app| on_event(&app, event));
            }
        }
        let code = child.wait().ok().and_then(|s| s.code());
        let stderr = errors.join().unwrap_or_default();
        let _ = weak.upgrade_in_event_loop(move |app| on_exit(&app, run, code, stderr));
    });
}

fn on_event(app: &MainWindow, event: Value) {
    let state = app.global::<AppState>();
    match event["event"].as_str().unwrap_or_default() {
        "starting" => set_phase(app, Phase::Starting),
        "hello" if event["status"]["state"] == "running" => {
            state.set_running_profile(event["profile"].as_str().unwrap_or_default().into());
            set_phase(app, Phase::Running);
            // blocks made while no window was open (e.g. a guest whose time ran out) get saved now
            let blocked: Vec<Blocked> = serde_json::from_value(event["status"]["blocked"].clone()).unwrap_or_default();
            if naming_profile(&state).is_some_and(|p| p.blocked != blocked) {
                apply_blocked(app, blocked);
            }
            set_clients(app, &event["status"]["clients"], false);
            state.set_internet_cut_all(event["status"]["internet_cut_all"].as_bool().unwrap_or(false));
        }
        "stopped" => handle_stopped(app),
        "started" => {
            set_phase(app, Phase::Running);
            set_clients(app, &event["status"]["clients"], true);
            state.set_internet_cut_all(event["status"]["internet_cut_all"].as_bool().unwrap_or(false));
            if event["status"]["forwarding"]["state"] == "unverified" {
                let body = "Devices can connect, but a firewall on this computer may be blocking forwarding.";
                push_notice(app, "forwarding", NoticeKind::Warn, "Devices may not have internet", body, false);
            }
        }
        "clients" => set_clients(app, &event["clients"], true),
        "usage" => {
            ui(|u| {
                for item in event["usage"].as_array().into_iter().flatten() {
                    if let Some(c) = u.clients.iter_mut().find(|c| c.mac == item["mac"].as_str().unwrap_or_default()) {
                        c.down = item["down_bytes"].as_u64().unwrap_or(c.down);
                        c.up = item["up_bytes"].as_u64().unwrap_or(c.up);
                    }
                }
            });
            refresh_clients(app);
        }
        "internet_cut_all" => state.set_internet_cut_all(event["cut"].as_bool().unwrap_or(false)),
        "blocked_changed" => {
            let blocked: Vec<Blocked> = serde_json::from_value(event["blocked"].clone()).unwrap_or_default();
            apply_blocked(app, blocked);
        }
        "wrong_password" => {
            let mac = event["mac"].as_str().unwrap_or_default();
            let body = format!("{mac} couldn't join. Forget the network on the device, then reconnect.");
            push_notice(app, &format!("psk-{mac}"), NoticeKind::Info, "A device used the wrong password", &body, true);
            notify("A device used the wrong password", &body);
        }
        "access_expired" => {
            let mac = event["mac"].as_str().unwrap_or_default();
            let name = ui(|u| u.clients.iter().find(|c| c.mac == mac).and_then(|c| c.hostname.clone()));
            let name = naming_profile(&state).and_then(|p| p.display_name(mac, name.as_deref())).unwrap_or(mac.into());
            let body = format!("{name} was blocked when its time ran out. Unblock it in Blocked devices.");
            push_notice(app, &format!("expired-{mac}"), NoticeKind::Info, "Temporary access ended", &body, true);
            notify("Temporary access ended", &body);
        }
        "restarted" => {
            let channel = event["channel"].as_i64().unwrap_or_default();
            let freq = event["freq_mhz"].as_u64().unwrap_or_default() as u32;
            let mut up = state.get_upstream();
            (up.channel, up.freq_mhz, up.band) = (channel as i32, freq as i32, band(freq).into());
            state.set_upstream(up);
            ui(|u| u.clients.clear());
            refresh_clients(app);
            let body = format!("Upstream moved to channel {channel}: hotspot restarted, devices were disconnected.");
            push_notice(app, "channel-changed", NoticeKind::Info, "Hotspot restarted", &body, true);
        }
        "uplink_lost" => {
            let body = format!("The connection to {} was lost, so the hotspot was turned off.", state.get_upstream().ssid);
            push_notice(app, "upstream-lost", NoticeKind::Warn, "Hotspot stopped", &body, true);
        }
        "error" => {
            let message = event["message"].as_str().unwrap_or_default();
            if state.get_busy() {
                ui(|u| u.failure_shown = true);
                push_notice(app, "failed", NoticeKind::Error, "Couldn't start the hotspot", message, true);
            } else {
                push_notice(app, "command", NoticeKind::Error, "That didn't work", message, true);
            }
        }
        _ => {}
    }
}

/// pkexec'd hotspot-cli exited. Usually a "stopped" event came first and there is nothing left to do.
fn on_exit(app: &MainWindow, run: u64, code: Option<i32>, stderr: String) {
    if ui(|u| u.pkexec.is_none() || u.pkexec_run != run) {
        return;
    }
    let state = app.global::<AppState>();
    let cancelled = state.get_phase() == Phase::Authorizing && code.is_some_and(|c| PKEXEC_DENIED.contains(&c));
    if state.get_busy() && !cancelled && !ui(|u| u.failure_shown) {
        let details = stderr.trim().trim_start_matches("Error: ");
        let details = if details.is_empty() { "hotspot-cli exited unexpectedly" } else { details };
        push_notice(app, "failed", NoticeKind::Error, "Couldn't start the hotspot", details, true);
    }
    handle_stopped(app);
}

fn handle_stopped(app: &MainWindow) {
    let state = app.global::<AppState>();
    let restart = ui(|u| {
        u.pkexec = None;
        u.clients.clear();
        u.seen.clear();
        std::mem::take(&mut u.pending_restart)
    });
    refresh_clients(app);
    state.set_internet_cut_all(false);
    state.set_running_profile(SharedString::new());
    remove_notice(app, "forwarding");
    remove_notices_with_prefix(app, "psk-");
    set_phase(app, if state.get_profiles().row_count() == 0 { Phase::NoProfile } else { Phase::Stopped });
    spawn_probe(app.as_weak());
    if restart {
        start(app);
    }
}

/// `announce: false` for devices that were already there when this window connected.
fn set_clients(app: &MainWindow, clients: &Value, announce: bool) {
    let now = Instant::now();
    let entries = clients
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| ClientEntry {
            mac: c["mac"].as_str().unwrap_or_default().into(),
            hostname: c["hostname"].as_str().map(String::from),
            ip: c["ip"].as_str().map(String::from),
            internet_cut: c["internet_cut"].as_bool().unwrap_or(false),
            since: now - Duration::from_secs(c["connected_secs"].as_u64().unwrap_or(0)),
            down: c["down_bytes"].as_u64().unwrap_or(0),
            up: c["up_bytes"].as_u64().unwrap_or(0),
            expires_at: c["expires_in_secs"].as_u64().map(|s| now + Duration::from_secs(s)),
            speed: c["speed_limit_mbps"].as_u64().map(|m| m as u32),
        })
        .collect::<Vec<_>>();
    let newcomers: Vec<(String, Option<String>)> = ui(|u| {
        let new = entries.iter().filter(|c| !u.seen.contains(&c.mac)).map(|c| (c.mac.clone(), c.hostname.clone())).collect();
        u.seen.extend(entries.iter().map(|c| c.mac.clone()));
        u.clients = entries;
        new
    });
    let profile = naming_profile(&app.global::<AppState>());
    for (mac, hostname) in newcomers.into_iter().filter(|_| announce) {
        let name = profile.as_ref().and_then(|p| p.display_name(&mac, hostname.as_deref())).unwrap_or(mac);
        notify("Device connected", &format!("{name} joined the hotspot"));
    }
    refresh_clients(app);
}

/// Longest-connected first, as in design.md §7.4.
fn refresh_clients(app: &MainWindow) {
    let state = app.global::<AppState>();
    let blocked: Vec<BlockedDevice> = state.get_blocked().iter().collect();
    let profile = naming_profile(&state);
    let rows: Vec<Client> = ui(|u| {
        u.clients.sort_by_key(|c| c.since);
        u.clients
            .iter()
            .map(|c| Client {
                mac: c.mac.as_str().into(),
                ip: c.ip.clone().unwrap_or_default().into(),
                hostname: profile
                    .as_ref()
                    .and_then(|p| p.display_name(&c.mac, c.hostname.as_deref()))
                    .or(c.hostname.clone())
                    .unwrap_or_default()
                    .into(),
                connected: connected_label(c.since.elapsed().as_secs()).into(),
                internet_cut: c.internet_cut,
                blocked: blocked.iter().any(|b| b.mac == c.mac.as_str()),
                usage: if c.down + c.up > 0 {
                    format!("↓ {} · ↑ {}", human_bytes(c.down), human_bytes(c.up)).into()
                } else {
                    SharedString::new()
                },
                expires: c.expires_at.map(expires_label).unwrap_or_default().into(),
                speed: c.speed.map(|m| format!("{m} Mbit/s")).unwrap_or_default().into(),
            })
            .collect()
    });
    app.global::<AppState>().set_clients(model(rows));
}

/// Asks D-Bus whether a StatusNotifierItem host runs (KDE, or GNOME with the AppIndicator
/// extension). Without one the tray icon is invisible, so the window must never hide into it.
fn tray_available() -> bool {
    Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.kde.StatusNotifierWatcher",
        ])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("boolean true"))
}

fn autostart_file() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join("autostart/hotspot.desktop"))
}

fn set_autostart(on: bool) -> std::io::Result<()> {
    let Some(file) = autostart_file() else { return Ok(()) };
    if !on {
        return match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let exe = std::env::current_exe()?;
    std::fs::create_dir_all(file.parent().expect("autostart dir"))?;
    std::fs::write(
        &file,
        format!(
            // no StartupNotify: it shows a "launching" task in the taskbar, waiting for a window that
            // a tray-only start never opens
            "[Desktop Entry]\nType=Application\nName=Hotspot\nComment=Wi-Fi hotspot in the system tray\n\
             Exec={} {TRAY_FLAG}\nIcon=hotspot\nTerminal=false\nStartupNotify=false\nX-GNOME-Autostart-enabled=true\n",
            exe.display()
        ),
    )
}

fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    let mut child = Command::new("wl-copy").stdin(Stdio::piped()).spawn()?;
    child.stdin.take().expect("piped stdin").write_all(text.as_bytes())?;
    child.wait()?;
    Ok(())
}

/// Aliases are plain profile data: the UI saves them itself, no root needed.
fn rename_device(app: &MainWindow, mac: &str, alias: &str) {
    let state = app.global::<AppState>();
    let Some(mut profile) = naming_profile(&state) else { return };
    if alias.is_empty() {
        profile.aliases.remove(mac);
    } else {
        profile.aliases.insert(mac.into(), alias.into());
    }
    let name = profile.name.clone();
    match ProfileStore::upsert(Some(&name), profile, None) {
        Ok(_) => {
            state.set_dialog(Dialog::None);
            load_profiles(app, None);
            refresh_clients(app);
        }
        Err(e) => state.set_dialog_error(message(e).into()),
    }
}

/// The engine changed the blocked list. Update the cached profile right away rather than
/// re-reading the file: with pkexec, hotspot-cli writes it a moment after sending the event.
/// With the service, saving it is our job, since the service never writes user files.
fn apply_blocked(app: &MainWindow, blocked: Vec<Blocked>) {
    let state = app.global::<AppState>();
    let Some(name) = naming_profile(&state).map(|p| p.name) else { return };
    ui(|u| {
        if let Some(p) = u.profiles.iter_mut().find(|p| p.name == name) {
            p.blocked = blocked.clone();
        }
    });
    if ui(|u| u.service.is_some()) {
        let saved = ProfileStore::get(&name, None)
            .and_then(|current| ProfileStore::upsert(Some(&name), HotspotProfile { blocked: blocked.clone(), ..current }, None));
        if let Err(e) = saved {
            push_notice(app, "profiles", NoticeKind::Error, "Couldn't save the blocked list", &e.to_string(), true);
        }
    }
    if state.get_current().name == name.as_str() {
        let profile = naming_profile(&state);
        state.set_blocked(blocked_model(&blocked, profile.as_ref()));
    }
    refresh_clients(app);
}

fn unblock_offline(app: &MainWindow, mac: &str) {
    let name = app.global::<AppState>().get_current().name.to_string();
    let Some(mut profile) = ui(|u| u.profiles.iter().find(|p| p.name == name).cloned()) else { return };
    profile.blocked.retain(|b| b.mac != mac);
    match ProfileStore::upsert(Some(&name), profile, None) {
        Ok(_) => load_profiles(app, Some(&name)),
        Err(e) => push_notice(app, "profiles", NoticeKind::Error, "Couldn't save the profile", &e.to_string(), true),
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let app = MainWindow::new()?;
    let state = app.global::<AppState>();
    load_profiles(&app, None);
    spawn_probe(app.as_weak());

    let probe_timer = Timer::default();
    probe_timer.start(TimerMode::Repeated, PROBE_EVERY, {
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade().filter(|a| a.global::<AppState>().get_idle()) {
                spawn_probe(app.as_weak());
            }
        }
    });
    let clients_timer = Timer::default();
    clients_timer.start(TimerMode::Repeated, CLIENT_TIME_REFRESH, {
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade().filter(|a| a.global::<AppState>().get_phase() == Phase::Running) {
                refresh_clients(&app);
            }
        }
    });

    macro_rules! on {
        ($setter:ident, |$app:ident $(, $arg:ident)*| $body:expr) => {{
            let weak = app.as_weak();
            state.$setter(move |$($arg),*| {
                let $app = weak.unwrap();
                $body
            });
        }};
    }

    on!(on_select_profile, |app, i| {
        let state = app.global::<AppState>();
        state.set_selected(i);
        state.set_password_revealed(false);
        let profile = ui(|u| u.profiles.get(i as usize).cloned());
        let blocked = profile.as_ref().map(|p| p.blocked.clone()).unwrap_or_default();
        state.set_blocked(blocked_model(&blocked, profile.as_ref()));
    });
    on!(on_dismiss_notice, |app, id| remove_notice(&app, &id));
    on!(on_start, |app| start(&app));
    on!(on_stop, |app| {
        set_phase(&app, Phase::Stopping);
        send(json!({ "cmd": "stop" }));
    });
    on!(on_set_cut_all, |_app, cut| send(json!({ "cmd": if cut { "cut_internet" } else { "restore_internet" }, "mac": null })));
    on!(on_set_client_cut, |_app, mac, cut| {
        send(json!({ "cmd": if cut { "cut_internet" } else { "restore_internet" }, "mac": mac.as_str() }));
    });
    on!(on_block, |_app, mac| send(json!({ "cmd": "block", "mac": mac.as_str() })));
    on!(on_unblock, |app, mac| {
        let state = app.global::<AppState>();
        if state.get_phase() == Phase::Running && state.get_current().name == state.get_running_profile() {
            send(json!({ "cmd": "unblock", "mac": mac.as_str() }));
        } else {
            unblock_offline(&app, &mac);
        }
    });
    on!(on_unblock_all, |app| {
        let state = app.global::<AppState>();
        let blocked: Vec<SharedString> = state.get_blocked().iter().map(|b| b.mac).collect();
        if state.get_phase() == Phase::Running && state.get_current().name == state.get_running_profile() {
            for mac in blocked {
                send(json!({ "cmd": "unblock", "mac": mac.as_str() }));
            }
        } else {
            for mac in blocked {
                unblock_offline(&app, &mac);
            }
        }
    });
    on!(on_toggle_qr, |app| {
        let state = app.global::<AppState>();
        if !state.get_qr_shown() {
            let current = state.get_current();
            match qr::render(&qr::wifi_payload(&current.ssid, &current.password, current.hidden)) {
                Some(image) => state.set_qr_image(image),
                None => return,
            }
        }
        state.set_qr_shown(!state.get_qr_shown());
    });
    on!(on_new_profile, |app| open_form(&app, false));
    on!(on_edit_profile, |app| open_form(&app, true));
    on!(on_open_blocked, |app| app.global::<AppState>().set_sheet(Sheet::Blocked));
    on!(on_close_sheet, |app| {
        app.global::<AppState>().set_sheet(Sheet::None);
        ui(|u| u.edit_original = None);
    });
    on!(on_form_changed, |app| validate_form(&app));
    on!(on_save_profile, |app| {
        if needs_restart(&app) {
            let state = app.global::<AppState>();
            state.set_dialog_count(state.get_clients().row_count() as i32);
            state.set_dialog(Dialog::Restart);
        } else {
            save_form(&app);
        }
    });
    on!(on_confirm_dialog, |app| {
        let state = app.global::<AppState>();
        let dialog = state.get_dialog();
        state.set_dialog(Dialog::None);
        match dialog {
            Dialog::Restart => {
                save_form(&app);
                ui(|u| u.pending_restart = true);
                set_phase(&app, Phase::Stopping);
                send(json!({ "cmd": "stop" }));
            }
            Dialog::Delete => {
                let name = state.get_current().name.to_string();
                match ProfileStore::delete(&name, None) {
                    Ok(()) => {
                        state.set_sheet(Sheet::None);
                        load_profiles(&app, None);
                    }
                    Err(e) => push_notice(&app, "profiles", NoticeKind::Error, "Couldn't delete the profile", &e.to_string(), true),
                }
            }
            Dialog::Close => {
                send(json!({ "cmd": "stop" }));
                let _ = slint::quit_event_loop();
            }
            Dialog::BlockAll => {
                for client in state.get_clients().iter() {
                    send(json!({ "cmd": "block", "mac": client.mac.as_str() }));
                }
            }
            Dialog::Rename | Dialog::TimeLimit | Dialog::SpeedLimit | Dialog::None => {}
        }
    });
    on!(on_generate_password, |app| {
        let state = app.global::<AppState>();
        match generate_passphrase() {
            Ok(p) => {
                state.set_form_password(p.into());
                state.set_form_password_revealed(true);
                validate_form(&app);
            }
            Err(e) => push_notice(&app, "generate", NoticeKind::Error, "Couldn't generate a password", &e.to_string(), true),
        }
    });
    on!(on_open_dialog, |app, dialog, mac| {
        let state = app.global::<AppState>();
        let client = ui(|u| u.clients.iter().find(|c| c.mac == mac.as_str()).map(|c| (c.expires_at.is_some(), c.speed.is_some())));
        let (has_time, has_speed) = client.unwrap_or_default();
        let presets: Vec<SharedString> = match dialog {
            Dialog::TimeLimit => vec!["30 min".into(), "1 h".into(), "2 h".into()],
            Dialog::SpeedLimit => SPEED_PRESETS_MBPS.iter().map(|m| format!("{m} Mbit/s").into()).collect(),
            _ => Vec::new(),
        };
        let alias = naming_profile(&state).and_then(|p| p.aliases.get(mac.as_str()).cloned());
        state.set_dialog_presets(model(presets));
        state.set_dialog_input(if dialog == Dialog::Rename { alias.unwrap_or_default().into() } else { SharedString::new() });
        state.set_dialog_error(SharedString::new());
        state.set_dialog_can_remove(match dialog {
            Dialog::TimeLimit => has_time,
            Dialog::SpeedLimit => has_speed,
            _ => false,
        });
        state.set_dialog_mac(mac);
        state.set_dialog(dialog);
    });
    on!(on_dialog_preset, |app, i| {
        let state = app.global::<AppState>();
        let mac = state.get_dialog_mac();
        match state.get_dialog() {
            Dialog::TimeLimit => send(json!({ "cmd": "allow_for", "mac": mac.as_str(), "minutes": TIME_PRESETS_MIN[i as usize] })),
            Dialog::SpeedLimit => send(json!({ "cmd": "limit_speed", "mac": mac.as_str(), "mbps": SPEED_PRESETS_MBPS[i as usize] })),
            _ => {}
        }
        state.set_dialog(Dialog::None);
    });
    on!(on_dialog_remove, |app| {
        let state = app.global::<AppState>();
        let mac = state.get_dialog_mac();
        match state.get_dialog() {
            Dialog::TimeLimit => send(json!({ "cmd": "allow_for", "mac": mac.as_str(), "minutes": null })),
            Dialog::SpeedLimit => send(json!({ "cmd": "limit_speed", "mac": mac.as_str(), "mbps": null })),
            _ => {}
        }
        state.set_dialog(Dialog::None);
    });
    on!(on_dialog_apply, |app| {
        let state = app.global::<AppState>();
        let mac = state.get_dialog_mac().to_string();
        let input = state.get_dialog_input().trim().to_string();
        let dialog = state.get_dialog();
        if dialog == Dialog::Rename {
            rename_device(&app, &mac, &input);
            return;
        }
        let Ok(n) = input.parse::<u32>() else {
            state.set_dialog_error("Enter a whole number, or pick one of the choices above.".into());
            return;
        };
        match dialog {
            Dialog::TimeLimit => send(json!({ "cmd": "allow_for", "mac": mac, "minutes": n })),
            _ => send(json!({ "cmd": "limit_speed", "mac": mac, "mbps": n })),
        }
        state.set_dialog(Dialog::None);
    });

    let copied_timer = Timer::default();
    let copied_timer = std::rc::Rc::new(copied_timer);
    on!(on_copy_password, |app| {
        let state = app.global::<AppState>();
        match copy_to_clipboard(&state.get_current().password) {
            Ok(()) => {
                state.set_copied(true);
                let weak = app.as_weak();
                copied_timer.start(TimerMode::SingleShot, COPIED_FOR, move || {
                    if let Some(app) = weak.upgrade() {
                        app.global::<AppState>().set_copied(false);
                    }
                });
            }
            Err(e) => push_notice(&app, "copy", NoticeKind::Error, "Couldn't copy the password", &format!("wl-copy: {e}"), true),
        }
    });

    app.window().on_close_requested({
        let weak = app.as_weak();
        move || {
            let app = weak.unwrap();
            let state = app.global::<AppState>();
            let devices = state.get_clients().row_count();
            if state.get_tray() {
                // the tray icon brings the window back; without the service, this process keeps the hotspot
                CloseRequestResponse::HideWindow
            } else if state.get_phase() == Phase::Running && devices > 0 {
                state.set_dialog_count(devices as i32);
                state.set_dialog(Dialog::Close);
                CloseRequestResponse::KeepWindowShown
            } else {
                let _ = slint::quit_event_loop();
                CloseRequestResponse::HideWindow
            }
        }
    });

    let tray = Tray::new()?;
    tray.on_show_window({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let _ = app.show();
            }
        }
    });
    tray.on_toggle({
        let weak = app.as_weak();
        move || {
            let Some(app) = weak.upgrade() else { return };
            let state = app.global::<AppState>();
            if state.get_phase() == Phase::Running {
                set_phase(&app, Phase::Stopping);
                send(json!({ "cmd": "stop" }));
            } else if state.get_can_start() {
                start(&app);
            }
        }
    });
    let autostart_on = autostart_file().is_some_and(|f| f.exists());
    if autostart_on {
        let _ = set_autostart(true); // refresh entries written by older versions
    }
    tray.set_autostart(autostart_on);
    tray.on_autostart_toggled({
        let weak = app.as_weak();
        move |on| {
            if let Err(e) = set_autostart(on) {
                if let Some(app) = weak.upgrade() {
                    push_notice(&app, "autostart", NoticeKind::Error, "Couldn't change Start at login", &e.to_string(), true);
                }
            }
        }
    });
    tray.on_quit(|| {
        // without the service, quitting closes hotspot-cli's stdin: it stops and cleans up
        let _ = slint::quit_event_loop();
    });
    let tray_timer = Timer::default();
    tray_timer.start(TimerMode::Repeated, TRAY_SYNC, {
        let (weak, tray) = (app.as_weak(), tray.as_weak());
        move || {
            let (Some(app), Some(tray)) = (weak.upgrade(), tray.upgrade()) else { return };
            let state = app.global::<AppState>();
            tray.set_running(state.get_phase() == Phase::Running);
            tray.set_busy(state.get_busy() || state.get_phase() == Phase::Stopping);
            tray.set_can_start(state.get_can_start());
        }
    });

    connect_service(&app);
    let has_tray = tray_available();
    state.set_tray(has_tray);
    // On KDE Wayland a window hidden before its first frame never appears again: show it,
    // and hide it right after that first frame. A fixed delay is not enough at login,
    // when the compositor is busy.
    app.show()?;
    if has_tray && std::env::args().any(|a| a == TRAY_FLAG) {
        let weak = app.as_weak();
        let hidden = std::cell::Cell::new(false);
        let notifier = app.window().set_rendering_notifier(move |state, _| {
            if matches!(state, slint::RenderingState::AfterRendering) && !hidden.replace(true) {
                let weak = weak.clone();
                // not from inside the renderer callback
                slint::Timer::single_shot(Duration::ZERO, move || {
                    if let Some(app) = weak.upgrade() {
                        let _ = app.hide();
                    }
                });
            }
        });
        if notifier.is_err() {
            let weak = app.as_weak();
            slint::Timer::single_shot(TRAY_START_HIDE_FALLBACK, move || {
                if let Some(app) = weak.upgrade() {
                    let _ = app.hide();
                }
            });
        }
    }
    slint::run_event_loop_until_quit()
}
