use std::process::{Command, Output};

use crate::error::{HotspotError, Result};

pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl From<Output> for CmdOutput {
    fn from(out: Output) -> Self {
        Self {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// English output: the parsers depend on the exact text.
pub fn command(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env("LC_ALL", "C");
    c
}

pub fn run(program: &str, args: &[&str]) -> Result<CmdOutput> {
    command(program)
        .args(args)
        .output()
        .map(CmdOutput::from)
        .map_err(|e| HotspotError::command(format!("{program} {}", args.join(" ")), e))
}

pub fn run_ok(program: &str, args: &[&str]) -> Result<CmdOutput> {
    let out = run(program, args)?;
    if out.success() {
        return Ok(out);
    }
    Err(HotspotError::command(
        format!("{program} {}", args.join(" ")),
        [out.stderr.trim(), out.stdout.trim()].join(" ").trim(),
    ))
}

pub fn run_unit(program: &str, args: &[&str]) -> Result<()> {
    run_ok(program, args).map(drop)
}

pub fn succeeds(program: &str, args: &[&str]) -> bool {
    run(program, args).is_ok_and(|o| o.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout() {
        let out = run("echo", &["bonjour"]).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "bonjour\n");
    }

    #[test]
    fn nonzero_exit_is_not_an_error() {
        assert_eq!(run("false", &[]).unwrap().code, Some(1));
    }

    #[test]
    fn run_ok_fails_on_nonzero_exit() {
        assert!(run_ok("true", &[]).is_ok());
        match run_ok("sh", &["-c", "echo out; echo err >&2; exit 3"]) {
            Err(HotspotError::CommandFailed { stderr, .. }) => assert_eq!(stderr, "err out"),
            _ => panic!(),
        }
    }
}