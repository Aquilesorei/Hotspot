use std::io::BufRead;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::mpsc;

use clap::{Parser, Subcommand};
use anyhow::{bail, Context};
use hotspot_core::{invoking_user, Command, Event, Hotspot, HotspotProfile, ProfileStore};
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

    /// Internal: saves a profile's blocked list (run as the calling user)
    #[command(hide = true)]
    SetBlocked { name: String, macs: Vec<String> },
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
        Cmd::ProfileJson { key } => println!("{}", serde_json::to_string(&ProfileStore::get(&key, path)?)?),
        Cmd::SetBlocked { name, macs } => {
            let p = ProfileStore::get(&name, path)?;
            ProfileStore::upsert(Some(&p.name), HotspotProfile { blocked: macs, ..p.clone() }, path)?;
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
    let mut hotspot = Hotspot::system();
    match hotspot.start(&p) {
        Ok(status) => print(status.to_string(), json!({ "event": "started", "status": status })),
        Err(e) => {
            print(format!("error: {e}"), json!({ "event": "error", "message": e.to_string() }));
            std::process::exit(1);
        }
    }
    if !json {
        println!("Commands: cut [mac], restore [mac], block <mac>, unblock <mac>. Enter or `stop` to quit.");
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

fn save_blocked(p: &HotspotProfile, blocked: &[String], path: Option<&Path>) -> anyhow::Result<()> {
    let Some(user) = caller() else {
        ProfileStore::upsert(Some(&p.name), HotspotProfile { blocked: blocked.to_vec(), ..p.clone() }, path)?;
        return Ok(());
    };
    let mut args = vec!["set-blocked", p.name.as_str()];
    args.extend(blocked.iter().map(String::as_str));
    let out = as_user(&user, path, &args).output().context(RUNUSER)?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn parse_text(line: &str) -> Result<Command, String> {
    let mut words = line.split_whitespace();
    let (cmd, mac) = (words.next(), words.next().map(String::from));
    Ok(match (cmd, mac) {
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
        assert!(parse_text("reboot").is_err());
    }
}
