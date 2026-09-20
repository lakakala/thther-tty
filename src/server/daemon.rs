//! The persistent per-user daemon: one TCP listener (single-port multiplexing),
//! one unix control socket, and all live sessions. Detached from the SSH process
//! tree via setsid so it survives the client and the SSH connection.

use anyhow::{Context, Result};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use crate::config::{control_socket_path, runtime_dir, Config};
use crate::proto::control::{ControlRequest, ControlResponse};
use crate::proto::crypto::{derive_key, Opener, Sealer, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT};
use crate::proto::frame::{read_frame, write_frame, Frame};
use crate::proto::handshake::{self, STATUS_NO_SESSION};

use super::registry::Registry;
use super::session::{spawn_session, SessionShared};

/// Idle read timeout on a session TCP connection; the client heartbeats well
/// under this, so hitting it means the peer is gone.
const READ_IDLE: Duration = Duration::from_secs(20);
/// Writer wakeup cadence: re-checks supersede/ended and pings the client.
const WRITER_TICK: Duration = Duration::from_secs(5);

pub async fn run() -> Result<()> {
    // Detach from the controlling terminal / SSH process group and ignore SIGHUP.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let cfg = Config::load().unwrap_or_default();
    let registry = Arc::new(Registry::new());

    let sock_path = control_socket_path();
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    set_mode(&dir, 0o700);

    // If a live daemon already owns the socket, step aside.
    if UnixStream::connect(&sock_path).await.is_ok() {
        tracing::info!("another daemon is alive; exiting");
        return Ok(());
    }
    let _ = std::fs::remove_file(&sock_path); // clear any stale socket
    let uds = UnixListener::bind(&sock_path)
        .with_context(|| format!("bind control socket {}", sock_path.display()))?;
    set_mode(&sock_path, 0o600);

    let (tcp, port) = bind_tcp_in_range(cfg.port_range).await?;
    tracing::info!("daemon up: tcp 0.0.0.0:{port}, control {}", sock_path.display());

    // TCP accept loop.
    {
        let registry = registry.clone();
        tokio::spawn(async move {
            loop {
                match tcp.accept().await {
                    Ok((stream, peer)) => {
                        let registry = registry.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_tcp(stream, registry).await {
                                tracing::debug!("tcp conn from {peer} ended: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("tcp accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // Control accept loop.
    loop {
        let (conn, _) = uds.accept().await?;
        let registry = registry.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control(conn, registry, cfg, port).await {
                tracing::debug!("control conn ended: {e:#}");
            }
        });
    }
}

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

async fn bind_tcp_in_range(range: [u16; 2]) -> Result<(TcpListener, u16)> {
    let (lo, hi) = (range[0], range[1]);
    for port in lo..=hi {
        if let Ok(l) = TcpListener::bind(("0.0.0.0", port)).await {
            return Ok((l, port));
        }
    }
    anyhow::bail!("no free TCP port in range {lo}-{hi}")
}

fn new_session_id(registry: &Registry) -> String {
    let mut rng = rand::thread_rng();
    loop {
        let n: u32 = rng.gen();
        let id = format!("{n:08x}");
        if !registry.contains(&id) {
            return id;
        }
    }
}

async fn handle_control(
    conn: UnixStream,
    registry: Arc<Registry>,
    cfg: Config,
    port: u16,
) -> Result<()> {
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let req: ControlRequest = serde_json::from_str(line.trim())?;
    let resp = match req {
        ControlRequest::Create { cols, rows } => {
            let id = new_session_id(&registry);
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            match spawn_session(id, &shell, cols.max(1), rows.max(1), cfg.ring_bytes, registry.clone()) {
                Ok(s) => ControlResponse::Bootstrap {
                    port,
                    id: s.id.clone(),
                    psk_hex: hex::encode(s.current_psk()),
                },
                Err(e) => ControlResponse::Err { message: format!("spawn failed: {e:#}") },
            }
        }
        ControlRequest::Attach { id } => match registry.get(&id) {
            None => ControlResponse::Err { message: "no such session".into() },
            Some(s) if s.is_ended() => ControlResponse::Err { message: "session ended".into() },
            Some(s) if s.is_busy() => {
                ControlResponse::Err { message: "session busy (already attached)".into() }
            }
            Some(s) => ControlResponse::Bootstrap {
                port,
                id: s.id.clone(),
                psk_hex: hex::encode(s.rotate_psk()),
            },
        },
        ControlRequest::Ls => ControlResponse::Ls { sessions: registry.list() },
        ControlRequest::Kill { id } => match registry.get(&id) {
            Some(s) => {
                s.kill();
                ControlResponse::Ok
            }
            None => ControlResponse::Err { message: "no such session".into() },
        },
    };

    let mut out = serde_json::to_string(&resp)?;
    out.push('\n');
    let mut conn = reader.into_inner();
    conn.write_all(out.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

async fn handle_tcp(stream: TcpStream, registry: Arc<Registry>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();

    let hello = handshake::server_recv(&mut r).await?;
    let session = match registry.get(&hello.session_id) {
        Some(s) if !s.is_ended() => s,
        _ => {
            handshake::server_send_err(&mut w, STATUS_NO_SESSION).await?;
            anyhow::bail!("no such session {}", hello.session_id);
        }
    };

    let psk = session.current_psk();
    let server_nonce = handshake::random_nonce();
    let total = session.current_total();
    handshake::server_send_ok(&mut w, &server_nonce, total).await?;

    let key = derive_key(&psk, &hello.client_nonce, &server_nonce);
    let mut sealer = Sealer::new(&key, DIR_SERVER_TO_CLIENT);
    let mut opener = Opener::new(&key, DIR_CLIENT_TO_SERVER);

    // Authenticate: the first client frame must open to Hello. A wrong PSK fails
    // the AEAD tag here and we drop the connection.
    match read_frame(&mut r, &mut opener).await {
        Ok(Frame::Hello) => {}
        _ => anyhow::bail!("auth failed"),
    }
    write_frame(&mut w, &mut sealer, &Frame::Hello).await?;

    let epoch = session.become_active();
    let (pong_tx, pong_rx) = tokio::sync::mpsc::channel::<()>(8);

    let sess_r = session.clone();
    tokio::select! {
        _ = server_reader(r, opener, sess_r, pong_tx) => {}
        _ = server_writer(w, sealer, session.clone(), hello.offset, pong_rx, epoch) => {}
    }
    session.leave(epoch);
    Ok(())
}

async fn server_reader(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut opener: Opener,
    session: Arc<SessionShared>,
    pong_tx: tokio::sync::mpsc::Sender<()>,
) {
    loop {
        let f = match tokio::time::timeout(READ_IDLE, read_frame(&mut r, &mut opener)).await {
            Ok(Ok(f)) => f,
            _ => break, // EOF, decrypt error, or idle => peer gone
        };
        match f {
            Frame::Data(b) => session.send_input(b),
            Frame::Resize { cols, rows } => session.resize(cols, rows),
            Frame::Ping => {
                if pong_tx.send(()).await.is_err() {
                    break;
                }
            }
            _ => {}
        }
    }
}

async fn server_writer(
    mut w: tokio::net::tcp::OwnedWriteHalf,
    mut sealer: Sealer,
    session: Arc<SessionShared>,
    start_offset: u64,
    mut pong_rx: tokio::sync::mpsc::Receiver<()>,
    epoch: u64,
) {
    let mut cursor = start_offset;
    loop {
        if !session.is_current(epoch) {
            break; // superseded by a newer connection
        }

        // Register the wakeup intent before draining, to avoid lost notifications.
        let notified = session.data_ready.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let (nc, bytes) = session.read_from(cursor);
        if !bytes.is_empty() {
            cursor = nc;
            if write_frame(&mut w, &mut sealer, &Frame::Data(bytes)).await.is_err() {
                break;
            }
            continue;
        }
        if session.is_ended() {
            let _ = write_frame(&mut w, &mut sealer, &Frame::Ended).await;
            break;
        }

        tokio::select! {
            _ = &mut notified => {}
            p = pong_rx.recv() => {
                if p.is_none() { break; }
                if write_frame(&mut w, &mut sealer, &Frame::Pong).await.is_err() { break; }
            }
            _ = tokio::time::sleep(WRITER_TICK) => {
                // Ping so a silently-dead client trips the peer's read timeout.
                if write_frame(&mut w, &mut sealer, &Frame::Ping).await.is_err() { break; }
            }
        }
    }
}
