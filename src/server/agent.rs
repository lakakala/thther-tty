//! The `__serve` agent: runs on the server, invoked by the client over SSH.
//! It talks to the (possibly just-spawned) daemon via the unix control socket,
//! then prints the daemon's JSON response to stdout for the client to parse.

use anyhow::{bail, Context, Result};
use std::io::ErrorKind;
use std::num::NonZeroU16;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config::{base_dir, control_socket_path, daemon_log_path, Config};
use crate::proto::control::{ControlRequest, ControlResponse};

pub async fn run(req: ControlRequest, port: Option<NonZeroU16>) -> Result<()> {
    let resp = obtain(req, port)
        .await
        .unwrap_or_else(|e| ControlResponse::Err { message: format!("{e:#}") });
    // Exactly one JSON line on stdout — the client reads this.
    println!("{}", serde_json::to_string(&resp)?);
    Ok(())
}

async fn obtain(req: ControlRequest, port: Option<NonZeroU16>) -> Result<ControlResponse> {
    let create = matches!(req, ControlRequest::Create { .. });
    let list = matches!(req, ControlRequest::Ls);
    let req = match port {
        Some(port) => ControlRequest::OnPort { port: port.get(), request: Box::new(req) },
        None => req,
    };
    let sock = control_socket_path();
    if let Some(r) = try_request_at(&sock, &req).await? {
        return Ok(r);
    }
    // Only a missing/refused control socket permits starting a new daemon.
    // Protocol failures must never replay an operation or start another daemon.
    if create {
        let cfg = Config::load()?;
        let port = port.or(cfg.port);
        start_and_request(&sock, &req, port).await.with_context(|| {
            let selection = port.map_or_else(
                || format!("TCP port range {}-{}", cfg.port_range[0], cfg.port_range[1]),
                |port| format!("TCP port {port}"),
            );
            format!(
                "starting daemon on {selection}; see server log {}",
                daemon_log_path().display()
            )
        })
    } else if list {
        Ok(ControlResponse::Ls { sessions: Vec::new() })
    } else {
        bail!("no daemon running")
    }
}

async fn start_and_request(
    sock: &Path,
    req: &ControlRequest,
    port: Option<NonZeroU16>,
) -> Result<ControlResponse> {
    let mut child = spawn_daemon(port).context("spawn daemon")?;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(r) = try_request_at(sock, req).await? {
            return Ok(r);
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("daemon exited with {status}");
            }
        }
    }
    bail!("daemon did not come up")
}

/// None means there is no listener. Once connected, failures are errors rather
/// than a reason to retry: the daemon may already have performed the operation.
async fn try_request_at(sock: &Path, req: &ControlRequest) -> Result<Option<ControlResponse>> {
    let conn = match UnixStream::connect(sock).await {
        Ok(conn) => conn,
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("connect to {}", sock.display())),
    };
    let result = tokio::time::timeout(Duration::from_secs(5), exchange(conn, req))
        .await
        .context("daemon control request timed out")
        .and_then(|r| r);
    let response = if let ControlRequest::OnPort { port, .. } = req {
        result.with_context(|| {
            format!(
                "daemon could not process the request for TCP port {port}; if it is an older version, \
                 upgrade and manually restart it (restarting ends its sessions)"
            )
        })?
    } else {
        result.context("daemon control request failed")?
    };
    Ok(Some(response))
}

async fn exchange(conn: UnixStream, req: &ControlRequest) -> Result<ControlResponse> {
    let (r, mut w) = conn.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    w.flush().await?;

    let mut reader = BufReader::new(r);
    let mut resp_line = String::new();
    if reader.read_line(&mut resp_line).await? == 0 {
        bail!("daemon closed the connection without a response");
    }
    serde_json::from_str(resp_line.trim()).context("invalid daemon response")
}

/// Launch the daemon fully detached: setsid, stdio redirected to a log file, so
/// the SSH command (this agent) can exit and let ssh return promptly.
fn spawn_daemon(port: Option<NonZeroU16>) -> Result<Child> {
    std::fs::create_dir_all(base_dir())?;
    let exe = std::env::current_exe()?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(daemon_log_path())?;
    let log2 = log.try_clone()?;

    let mut cmd = Command::new(exe);
    cmd.arg("__daemon");
    if let Some(port) = port {
        cmd.arg("--port").arg(port.to_string());
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log));
    cmd.stderr(Stdio::from(log2));
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    Ok(cmd.spawn()?) // detached; only poll for startup failure
}
