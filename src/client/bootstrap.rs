//! Client-side bootstrap: run the system `ssh` binary to invoke the server
//! agent, and parse the single JSON line it prints.

use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::config::Config;
use crate::proto::control::ControlResponse;

pub async fn create(cfg: &Config, cols: u16, rows: u16) -> Result<ControlResponse> {
    run_ssh(
        cfg,
        &["__serve", "create", "--cols", &cols.to_string(), "--rows", &rows.to_string()],
    )
    .await
}

pub async fn attach(cfg: &Config, id: &str) -> Result<ControlResponse> {
    run_ssh(cfg, &["__serve", "attach", id]).await
}

pub async fn ls(cfg: &Config) -> Result<ControlResponse> {
    run_ssh(cfg, &["__serve", "ls"]).await
}

pub async fn kill(cfg: &Config, id: &str) -> Result<ControlResponse> {
    run_ssh(cfg, &["__serve", "kill", id]).await
}

/// Shell script run remotely via `sh -s`: execs ~/.thther/bin/thther-<version>,
/// installing the matching release binary first if it is missing.
const REMOTE_BOOTSTRAP: &str = include_str!("remote_bootstrap.sh");

async fn run_ssh(cfg: &Config, remote_args: &[&str]) -> Result<ControlResponse> {
    let target = cfg.require_ssh_target()?;
    let mut cmd = Command::new("ssh");
    // -T: no PTY; -o BatchMode: fail fast instead of hanging on a prompt.
    cmd.arg("-T").arg("-o").arg("BatchMode=yes").arg(target);
    cmd.args(["sh", "-s", "--", env!("CARGO_PKG_VERSION")]);
    cmd.args(remote_args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawning ssh")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(REMOTE_BOOTSTRAP.as_bytes())
            .await
            .context("sending bootstrap script to ssh")?;
    }
    let out = child.wait_with_output().await.context("waiting for ssh")?;
    if !out.status.success() {
        bail!(
            "ssh to '{target}' failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("empty response from server agent"))?;
    serde_json::from_str(line.trim())
        .with_context(|| format!("parsing agent response: {line:?}"))
}
