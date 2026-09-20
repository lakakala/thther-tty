//! The `__serve` agent: runs on the server, invoked by the client over SSH.
//! It talks to the (possibly just-spawned) daemon via the unix control socket,
//! then prints the daemon's JSON response to stdout for the client to parse.

use anyhow::Result;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config::{base_dir, control_socket_path, daemon_log_path};
use crate::proto::control::{ControlRequest, ControlResponse};

pub async fn run(req: ControlRequest) -> Result<()> {
    let resp = obtain(req).await;
    // Exactly one JSON line on stdout — the client reads this.
    println!("{}", serde_json::to_string(&resp)?);
    Ok(())
}

async fn obtain(req: ControlRequest) -> ControlResponse {
    if let Ok(r) = try_request(&req).await {
        return r;
    }
    // Daemon not reachable.
    match &req {
        ControlRequest::Create { .. } => {
            if let Err(e) = spawn_daemon() {
                return ControlResponse::Err { message: format!("spawn daemon: {e:#}") };
            }
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Ok(r) = try_request(&req).await {
                    return r;
                }
            }
            ControlResponse::Err { message: "daemon did not come up".into() }
        }
        ControlRequest::Ls => ControlResponse::Ls { sessions: Vec::new() },
        _ => ControlResponse::Err { message: "no daemon running".into() },
    }
}

async fn try_request(req: &ControlRequest) -> Result<ControlResponse> {
    let sock = control_socket_path();
    let conn = UnixStream::connect(&sock).await?;
    let (r, mut w) = conn.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    w.flush().await?;

    let mut reader = BufReader::new(r);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await?;
    Ok(serde_json::from_str(resp_line.trim())?)
}

/// Launch the daemon fully detached: setsid, stdio redirected to a log file, so
/// the SSH command (this agent) can exit and let ssh return promptly.
fn spawn_daemon() -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(daemon_log_path())?;
    let log2 = log.try_clone()?;

    let mut cmd = Command::new(exe);
    cmd.arg("__daemon");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(log2));
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()?; // detached; do not wait
    Ok(())
}
