mod daemon;

use std::io::BufRead;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::mpsc;

use clap::{Parser, Subcommand};
use anyhow::{bail, Context};
use hotspot_core::{invoking_user, BlockedDevice, Command, Event, Hotspot, HotspotProfile, ProfileStore};
use serde_json::json;

#[derive(Parser)]
#[command(about = "Share Wi-Fi while staying connected to Wi-Fi")]
struct Cli {

    #[arg(long, global = true)]
    profiles: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {

    Start {
        #[arg(long)]
        profile: String,
        /// One JSON event per line on stdout, JSON commands on stdin (for the UI)
        #[arg(long)]
        json: bool,
    },

    /// Run the engine as a background service on a Unix socket (root, for systemd)
    Daemon,

    /// Upstream Wi-Fi and card support, without root
    Probe {
        #[arg(long)]
        json: bool,
    },

    Stop,

    Add {
        name: String,
        #[arg(long)]
        ssid: String,
        #[arg(long)]
        passphrase: String,
    },

    List,

    /// Internal: prints a profile as JSON (run as the calling user)
    #[command(hide = true)]
    ProfileJson { key: String },

    /// Internal: saves a profile's blocked list, given as JSON (run as the calling user)
    #[command(hide = true)]
    SetBlocked { name: String, blocked: String },
}

const RUNUSER: &str = "runuser";

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = cli.profiles.as_deref();

    if let (Some(user), Cmd::Add { .. } | Cmd::List | Cmd::ProfileJson { .. } | Cmd::SetBlocked { .. }) = (caller(), &cli.cmd) {
        let status = as_user(&user, path, &[]).args(std::env::args_os().skip(1)).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    match cli.cmd {
        Cmd::Add { name, ssid, passphrase } => {
            let written = ProfileStore::store(&name, &ssid, &passphrase, path)?;
            println!("profile {name} saved to {}", written.display());
        }
        Cmd::List => {
            for p in ProfileStore::list(path)? {
                println!("{}\tSSID={}\t{}", p.name, p.ssid, p.subnet);
            }
        }
        Cmd::Stop => {
            Hotspot::system().recover()?;
            println!("stopped");
        }
        Cmd::Probe { json } => match (Hotspot::system().probe(), json) {
            (Ok(probe), true) => println!("{}", serde_json::to_string(&probe)?),
            (Err(e), true) => {
                println!("{}", json!({ "error": e.to_string() }));
                std::process::exit(1);
            }
            (Ok(probe), false) => {
                let up = &probe.uplink;
                println!("uplink {} ({}) on channel {} ({} MHz)", up.iface, up.ssid.as_deref().unwrap_or("?"), up.channel, up.freq_mhz);
                println!("AP+STA supported: {}", probe.ap_sta);
            }
            (Err(e), false) => return Err(e.into()),
        },
        Cmd::Start { profile, json } => start(&profile, path, json)?,
        Cmd::Daemon => daemon::run()?,
        Cmd::ProfileJson { key } => println!("{}", serde_json::to_string(&ProfileStore::get(&key, path)?)?),
        Cmd::SetBlocked { name, blocked } => {
            let p = ProfileStore::get(&name, path)?;
            let blocked = serde_json::from_str(&blocked)?;
            ProfileStore::upsert(Some(&p.name), HotspotProfile { blocked, ..p.clone() }, path)?;
        }
    }
    Ok(())
}

fn start(profile: &str, path: Option<&Path>, json: bool) -> anyhow::Result<()> {
    let print = |text: String, value: serde_json::Value| {
        if json {
            println!("{value}");
        } else {
            println!("{text}");
        }
    };
    let p = load_profile(profile, path)?;
    if json {
        println!("{}", json!({ "event": "starting" })); // authorization passed, the UI can say so
    }
    let mut hotspot = Hotspot::system();
    match hotspot.start(&p) {
        Ok(status) => print(status.to_string(), json!({ "event": "started", "status": status })),
        Err(e) => {
            print(format!("error: {e}"), json!({ "event": "error", "message": e.to_string() }));
            std::process::exit(1);
        }
    }
    if !json {
        println!(
            "Commands: cut [mac], restore [mac], block <mac>, unblock <mac>, allow <mac> <minutes|off>, \
             limit <mac> <mbps|off>. Enter or `stop` to quit."
        );
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            let parsed = if json { serde_json::from_str(&line).map_err(|e| e.to_string()) } else { parse_text(&line) };
            match parsed {
                Ok(cmd) => {
                    let stop = cmd == Command::Stop;
                    if tx.send(cmd).is_err() || stop {
                        return;
                    }
                }
                Err(e) if json => println!("{}", json!({ "event": "error", "message": e })),
                Err(e) => println!("error: {e}"),
            }
        }
        let _ = tx.send(Command::Stop); // stdin closed: the UI went away
    });

    hotspot.supervise(&rx, |event| {
        if !json && matches!(event, Event::Usage { .. }) {
            return; // byte counters every few seconds would drown the terminal
        }
        print(event.to_string(), serde_json::to_value(event).expect("Event is serializable"));
        if let Event::BlockedChanged { blocked } = event {
            if let Err(e) = save_blocked(&p, blocked, path) {
                eprintln!("warning: could not save the blocked list: {e:#}");
            }
        }
    })?;
    print("stopped".into(), json!({ "event": "stopped" }));
    Ok(())
}

/// Under sudo or pkexec, the user whose profile file we use. Profile files are then read and written
/// as that user, never as root: they live in a directory the user controls, where a symlink could
/// redirect a root write onto a system file.
fn caller() -> Option<String> {
    let root = std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0);
    if root { invoking_user() } else { None }
}

fn as_user(user: &str, path: Option<&Path>, args: &[&str]) -> Process {
    let mut c = Process::new(RUNUSER);
    c.args(["-u", user, "--"]).arg(std::env::current_exe().expect("own executable path"));
    if let Some(p) = path {
        c.arg("--profiles").arg(p);
    }
    c.args(args);
    c
}

fn load_profile(key: &str, path: Option<&Path>) -> anyhow::Result<HotspotProfile> {
    let Some(user) = caller() else { return Ok(ProfileStore::get(key, path)?) };
    let out = as_user(&user, path, &["profile-json", key]).output().context(RUNUSER)?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let p: HotspotProfile = serde_json::from_slice(&out.stdout)?;
    p.validate()?;
    Ok(p)
}

fn save_blocked(p: &HotspotProfile, blocked: &[BlockedDevice], path: Option<&Path>) -> anyhow::Result<()> {
    let Some(user) = caller() else {
        // re-read: the profile may have changed (aliases, settings) since the hotspot started
        let current = ProfileStore::get(&p.name, path)?;
        ProfileStore::upsert(Some(&p.name), HotspotProfile { blocked: blocked.to_vec(), ..current }, path)?;
        return Ok(());
    };
    let json = serde_json::to_string(blocked)?;
    let out = as_user(&user, path, &["set-blocked", &p.name, &json]).output().context(RUNUSER)?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn parse_text(line: &str) -> Result<Command, String> {
    let mut words = line.split_whitespace();
    let (cmd, mac, value) = (words.next(), words.next().map(String::from), words.next());
    // "off" removes the limit; anything else must be a number
    let number = || match value {
        Some("off") => Ok(None),
        Some(v) => v.parse().map(Some).map_err(|_| format!("not a number: {v}")),
        None => Err(format!("missing value: {line}")),
    };
    Ok(match (cmd, mac) {
        (Some("allow"), Some(mac)) => Command::AllowFor { mac, minutes: number()? },
        (Some("limit"), Some(mac)) => Command::LimitSpeed { mac, mbps: number()? },
        (None | Some("stop"), _) => Command::Stop,
        (Some("cut"), mac) => Command::CutInternet { mac },
        (Some("restore"), mac) => Command::RestoreInternet { mac },
        (Some("block"), Some(mac)) => Command::Block { mac },
        (Some("unblock"), Some(mac)) => Command::Unblock { mac },
        _ => return Err(format!("unknown command: {line}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_commands() {
        let mac = || Some("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(parse_text(""), Ok(Command::Stop));
        assert_eq!(parse_text("stop"), Ok(Command::Stop));
        assert_eq!(parse_text("cut"), Ok(Command::CutInternet { mac: None }));
        assert_eq!(parse_text("cut aa:bb:cc:dd:ee:ff"), Ok(Command::CutInternet { mac: mac() }));
        assert_eq!(parse_text("restore aa:bb:cc:dd:ee:ff"), Ok(Command::RestoreInternet { mac: mac() }));
        assert_eq!(parse_text("block aa:bb:cc:dd:ee:ff"), Ok(Command::Block { mac: mac().unwrap() }));
        assert!(parse_text("block").is_err());
        assert_eq!(parse_text("allow aa:bb:cc:dd:ee:ff 30"), Ok(Command::AllowFor { mac: mac().unwrap(), minutes: Some(30) }));
        assert_eq!(parse_text("limit aa:bb:cc:dd:ee:ff off"), Ok(Command::LimitSpeed { mac: mac().unwrap(), mbps: None }));
        assert!(parse_text("limit aa:bb:cc:dd:ee:ff fast").is_err());
        assert!(parse_text("allow aa:bb:cc:dd:ee:ff").is_err());
        assert!(parse_text("reboot").is_err());
    }
}
