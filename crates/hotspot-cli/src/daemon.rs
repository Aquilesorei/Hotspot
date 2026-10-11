//! `hotspot-cli daemon`: the engine as a root service, driven over a Unix socket.
//!
//! Same JSON lines as `start --json`, plus `{"cmd":"start","profile":{...}}`: the client sends the
//! whole profile, so the service never reads a user's files.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{chown, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::Context;
use hotspot_core::{Command, Hotspot, HotspotProfile, HotspotState, CONTROL_SOCKET, SERVICE_GROUP};
use serde_json::{json, Value};

const TICK: Duration = Duration::from_secs(2);
/// A client that stops reading must not freeze the engine: past this, it gets dropped.
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

enum Msg {
    Connected(UnixStream),
    Line(String),
}


pub fn run() -> anyhow::Result<()> {
    let _ = fs::remove_file(CONTROL_SOCKET);
    let listener = UnixListener::bind(CONTROL_SOCKET).with_context(|| format!("bind {CONTROL_SOCKET}"))?;
    restrict_socket()?;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            let Ok(reader) = stream.try_clone() else { continue };
            let _ = tx.send(Msg::Connected(stream));
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(reader).lines().map_while(Result::ok) {
                    if tx.send(Msg::Line(line)).is_err() {
                        return;
                    }
                }
            });
        }
    });

    let mut hotspot = Hotspot::system();
    let mut clients: Vec<UnixStream> = Vec::new();
    let mut running_profile: Option<String> = None;
    let mut last_tick = Instant::now();
    loop {
        let mut out: Vec<Value> = Vec::new();
        match rx.recv_timeout(TICK.saturating_sub(last_tick.elapsed())) {
            Ok(Msg::Connected(mut stream)) => {
                let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
                let hello = json!({ "event": "hello", "status": hotspot.status(), "profile": running_profile });
                if writeln!(stream, "{hello}").is_ok() {
                    clients.push(stream);
                }
            }
            Ok(Msg::Line(line)) => out.extend(handle_line(&mut hotspot, &mut running_profile, &line)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => anyhow::bail!("socket listener stopped"),
        }
        if hotspot.status().state == HotspotState::Running {
            if last_tick.elapsed() >= TICK {
                last_tick = Instant::now();
                match hotspot.poll() {
                    Ok(events) => out.extend(events.iter().map(to_json)),
                    Err(e) => out.push(json!({ "event": "error", "message": e.to_string() })),
                }
            }
            out.extend(hotspot.take_events().iter().map(to_json));
            if hotspot.status().state != HotspotState::Running {
                let _ = hotspot.stop();
                running_profile = None;
                out.push(json!({ "event": "stopped" }));
            }
        } else {
            last_tick = Instant::now();
        }
        // a client that went away is dropped on the first failed write
        for event in out {
            clients.retain_mut(|c| writeln!(c, "{event}").is_ok());
        }
    }
}

fn handle_line(hotspot: &mut Hotspot<hotspot_core::SystemBackend>, running: &mut Option<String>, line: &str) -> Vec<Value> {
    let error = |message: String| vec![json!({ "event": "error", "message": message })];
    let value: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return error(format!("bad command: {e}")),
    };
    match value["cmd"].as_str() {
        Some("status") => return vec![json!({ "event": "hello", "status": hotspot.status(), "profile": running })],
        // another client already started it: say so without telling everyone it stopped
        Some("start") if hotspot.status().state == HotspotState::Running => {
            return error(format!("hotspot already running with profile {}", running.as_deref().unwrap_or("?")))
        }
        Some("start") => {
            // whoever sent start waits in "starting": always end with started or stopped
            let profile: HotspotProfile = match serde_json::from_value(value["profile"].clone()) {
                Ok(p) => p,
                Err(e) => return vec![json!({ "event": "error", "message": format!("bad profile: {e}") }), json!({ "event": "stopped" })],
            };
            let mut out = vec![json!({ "event": "starting" })];
            match hotspot.start(&profile) {
                Ok(status) => {
                    *running = Some(profile.name.clone());
                    out.push(json!({ "event": "started", "status": status, "profile": profile.name }));
                }
                Err(e) => {
                    out.push(json!({ "event": "error", "message": e.to_string() }));
                    out.push(json!({ "event": "stopped" }));
                }
            }
            return out;
        }
        _ => {}
    }
    match serde_json::from_value::<Command>(value) {
        Ok(Command::Stop) => {
            let _ = hotspot.stop();
            *running = None;
            vec![json!({ "event": "stopped" })]
        }
        Ok(cmd) => match hotspot.handle(cmd) {
            Ok(event) => event.iter().map(to_json).collect(),
            Err(e) => error(e.to_string()),
        },
        Err(e) => error(format!("bad command: {e}")),
    }
}

fn to_json(event: &hotspot_core::Event) -> Value {
    serde_json::to_value(event).expect("Event is serializable")
}

/// rw for root and the `hotspot` group; root only if the group doesn't exist.
fn restrict_socket() -> anyhow::Result<()> {
    let gid = fs::read_to_string("/etc/group").ok().and_then(|groups| {
        groups.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&SERVICE_GROUP)).then(|| f.get(2)?.parse::<u32>().ok()).flatten()
        })
    });
    match gid {
        Some(gid) => {
            chown(CONTROL_SOCKET, Some(0), Some(gid))?;
            fs::set_permissions(CONTROL_SOCKET, fs::Permissions::from_mode(0o660))?;
        }
        None => {
            eprintln!("warning: group {SERVICE_GROUP} not found, only root can use {CONTROL_SOCKET}");
            fs::set_permissions(CONTROL_SOCKET, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
