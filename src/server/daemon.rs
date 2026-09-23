//! The persistent per-user daemon: one TCP listener (single-port multiplexing),
//! one unix control socket, and all live sessions. Detached from the SSH process
//! tree via setsid so it survives the client and the SSH connection.

use anyhow::{Context, Result};
use rand::Rng;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

use crate::config::{control_socket_path, runtime_dir, Config};
use crate::proto::control::{ControlRequest, ControlResponse};
use crate::proto::crypto::{
    derive_key, Opener, Sealer, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT,
};
use crate::proto::frame::{read_frame, write_frame, Frame};
use crate::proto::handshake::{self, STATUS_NO_SESSION};

use super::registry::Registry;
use super::session::{spawn_session, SessionShared};

/// Idle read timeout on a session TCP connection; the client heartbeats well
/// under this, so hitting it means the peer is gone.
const READ_IDLE: Duration = Duration::from_secs(20);
/// Writer wakeup cadence: re-checks supersede/ended and pings the client.
const WRITER_TICK: Duration = Duration::from_secs(5);

pub async fn run(port: Option<NonZeroU16>) -> Result<()> {
    // Detach from the controlling terminal / SSH process group and ignore SIGHUP.
    unsafe {
        libc::setsid();
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let mut cfg = Config::load()?;
    cfg.port = port.or(cfg.port);
    let registry = Arc::new(Registry::new());

    let sock_path = control_socket_path();
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    set_mode(&dir, 0o700);

    // Serialize the live-socket check and publication across concurrent starts.
    // Otherwise a second daemon can unlink the first one's control socket.
    let startup_lock = tokio::task::spawn_blocking(move || -> Result<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.join("daemon.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open startup lock {}", path.display()))?;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(file);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("lock daemon startup");
            }
        }
    })
    .await??;

    // If a live daemon already owns the socket, step aside.
    if UnixStream::connect(&sock_path).await.is_ok() {
        tracing::info!("another daemon is alive; exiting");
        return Ok(());
    }
    // Publish the control socket only after TCP binding succeeds, so agents
    // cannot submit session operations to a daemon that failed to start.
    let (tcp, port) = bind_tcp(&cfg).await?;
    let _ = std::fs::remove_file(&sock_path); // clear any stale socket
    let uds = UnixListener::bind(&sock_path)
        .with_context(|| format!("bind control socket {}", sock_path.display()))?;
    set_mode(&sock_path, 0o600);

    tracing::info!("daemon up: tcp 0.0.0.0:{port}, control {}", sock_path.display());
    drop(startup_lock);

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

async fn bind_tcp(cfg: &Config) -> Result<(TcpListener, u16)> {
    if let Some(port) = cfg.port {
        let listener = TcpListener::bind(("0.0.0.0", port.get()))
            .await
            .with_context(|| format!("bind TCP port {port}"))?;
        return Ok((listener, port.get()));
    }
    bind_tcp_in_range(cfg.port_range).await
}

async fn bind_tcp_in_range(range: [u16; 2]) -> Result<(TcpListener, u16)> {
    let (lo, hi) = (range[0], range[1]);
    anyhow::ensure!(
        lo != 0 && lo <= hi,
        "invalid TCP port range {lo}-{hi}; expected 1 <= low <= high <= 65535"
    );
    for port in lo..=hi {
        if let Ok(l) = TcpListener::bind(("0.0.0.0", port)).await {
            return Ok((l, port));
        }
    }
    anyhow::bail!("no free TCP port in range {lo}-{hi}")
}

#[cfg(test)]
mod port_tests {
    use super::*;

    #[tokio::test]
    async fn occupied_fixed_port_never_falls_back_to_range() {
        let occupied = TcpListener::bind(("0.0.0.0", 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let cfg = Config { port: NonZeroU16::new(port), ..Config::default() };
        let error = bind_tcp(&cfg).await.unwrap_err();
        assert!(error.to_string().contains(&format!("bind TCP port {port}")));
        assert!(error.chain().any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

    #[tokio::test]
    async fn invalid_ranges_are_rejected() {
        for range in [[0, 0], [0, 60000], [61000, 60000]] {
            assert!(bind_tcp_in_range(range)
                .await
                .unwrap_err()
                .to_string()
                .contains("invalid TCP port range"));
        }
    }

    #[tokio::test]
    async fn wrong_port_preserves_sessions_and_keys() {
        let registry = Arc::new(Registry::new());
        let cfg = Config::default();
        let session =
            spawn_session("port-test".into(), "/bin/sh", 80, 24, cfg.ring_bytes, registry.clone())
                .unwrap();
        struct Cleanup(Arc<SessionShared>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                self.0.kill();
            }
        }
        let _cleanup = Cleanup(session.clone());
        let key = session.current_psk();
        for request in [
            ControlRequest::Create { cols: 80, rows: 24 },
            ControlRequest::Attach { id: session.id.clone() },
            ControlRequest::Ls,
            ControlRequest::Kill { id: session.id.clone() },
        ] {
            let response = execute_control(
                ControlRequest::OnPort { port: 62001, request: Box::new(request) },
                &registry,
                &cfg,
                62000,
            );
            match response {
                ControlResponse::Err { message } => {
                    assert!(message.contains("62000") && message.contains("62001"));
                }
                _ => panic!("wrong-port operation was accepted"),
            }
            assert_eq!(registry.list().len(), 1);
            assert_eq!(session.current_psk(), key);
            assert!(!session.is_ended());
        }
        let response = execute_control(
            ControlRequest::OnPort {
                port: 62000,
                request: Box::new(ControlRequest::Attach { id: session.id.clone() }),
            },
            &registry,
            &cfg,
            62000,
        );
        assert!(matches!(response, ControlResponse::Bootstrap { port: 62000, .. }));
        assert_ne!(session.current_psk(), key);
        assert!(
            matches!(execute_control(ControlRequest::Ls, &registry, &cfg, 62000), ControlResponse::Ls { sessions } if sessions.len() == 1)
        );
    }
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
    let resp = execute_control(req, &registry, &cfg, port);

    let mut out = serde_json::to_string(&resp)?;
    out.push('\n');
    let mut conn = reader.into_inner();
    conn.write_all(out.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

fn execute_control(
    mut req: ControlRequest,
    registry: &Arc<Registry>,
    cfg: &Config,
    port: u16,
) -> ControlResponse {
    // Validate before creating a PTY, rotating a key, or touching a session.
    while let ControlRequest::OnPort { port: expected, request } = req {
        if expected != port {
            return ControlResponse::Err {
                message: format!(
                    "daemon is listening on TCP port {port}, but TCP port {expected} was requested; \
                     use port {port} or manually restart the daemon to change ports \
                     (restarting ends its sessions)"
                ),
            };
        }
        req = *request;
    }
    match req {
        ControlRequest::OnPort { .. } => unreachable!("port constraints were unwrapped above"),
        ControlRequest::Create { cols, rows } => {
            let id = new_session_id(&registry);
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            match spawn_session(
                id,
                &shell,
                cols.max(1),
                rows.max(1),
                cfg.ring_bytes,
                registry.clone(),
            ) {
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
    }
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
