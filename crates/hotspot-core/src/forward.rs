use crate::network_backend::NetworkBackend;
use crate::constants::{bin, DOCKER_USER};
use crate::error::{HotspotError, Result};

/// An `accept` in our own table is not enough: Docker's `policy drop` wins,
/// so the rules must go into its `DOCKER-USER` chain.
/// Always with `-o uplink`: without it, clients could reach Docker containers.
fn rules<'a>(ap: &'a str, uplink: &'a str) -> [Vec<&'a str>; 2] {
    [
        vec![DOCKER_USER, "-i", ap, "-o", uplink, "-j", "ACCEPT"],
        vec![DOCKER_USER, "-i", uplink, "-o", ap, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
}

fn with<'a>(op: &'a str, rule: &[&'a str]) -> Vec<&'a str> {
    std::iter::once(op).chain(rule.iter().copied()).collect()
}

pub fn docker_present(b: &impl NetworkBackend) -> bool {
    b.iptables(&["-S", DOCKER_USER]).unwrap_or(false)
}

pub fn docker_installed(b: &impl NetworkBackend, ap: &str, uplink: &str) -> Result<bool> {
    for rule in rules(ap, uplink) {
        if !b.iptables(&with("-C", &rule))? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn docker_install(b: &impl NetworkBackend, ap: &str, uplink: &str) -> Result<()> {
    for rule in rules(ap, uplink) {
        if b.iptables(&with("-C", &rule))? {
            continue;
        }
        if !b.iptables(&with("-I", &rule))? {
            return Err(HotspotError::firewall(bin::IPTABLES, rule.join(" ")));
        }
    }
    Ok(())
}

pub fn docker_remove(b: &impl NetworkBackend, ap: &str, uplink: &str) {
    for rule in rules(ap, uplink) {
        let _ = b.iptables(&with("-D", &rule));
    }
}
