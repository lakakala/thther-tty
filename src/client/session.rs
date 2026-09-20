//! The interactive client session: raw-mode terminal bridged to the encrypted
//! TCP channel, with automatic reconnect on network blips and offset-based
//! resume so no output is lost or duplicated.

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::sync::mpsc;

use crate::proto::crypto::{derive_key, Opener, Sealer, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT};
use crate::proto::frame::{read_frame, write_frame, Frame};
use crate::proto::handshake;

use super::reconnect::Backoff;

/// The detach prefix key: Ctrl-\ (0x1c), followed by 'd'.
const DETACH_PREFIX: u8 = 0x1c;
const DETACH_KEY: u8 = b'd';

#[derive(Debug, Clone, Copy, PartialEq)]
enum Outcome {
    /// Shell exited on the server.
    Ended,
    /// User pressed the detach sequence.
    Detached,
    /// Network dropped; caller should reconnect.
    Disconnected,
}

/// Run the interactive session, reconnecting through blips, until the shell
/// exits or the user detaches.
pub async fn run_interactive(host: &str, port: u16, id: &str, psk: [u8; 32]) -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let result = drive(host, port, id, psk).await;
    let _ = crossterm::terminal::disable_raw_mode();
    // Move to a fresh line so the shell prompt isn't glued to session output.
    println!();
    result
}

async fn drive(host: &str, port: u16, id: &str, psk: [u8; 32]) -> Result<()> {
    let received = Arc::new(AtomicU64::new(0));
    let mut stdin_rx = spawn_stdin_reader();
    let mut winch = signal(SignalKind::window_change())?;
    let mut backoff = Backoff::new();
    let mut established_once = false;

    loop {
        match connect_once(host, port, id, psk, received.clone(), &mut stdin_rx, &mut winch).await {
            Ok(Outcome::Ended) => {
                eprint!("\r\n[thther] session ended\r\n");
                return Ok(());
            }
            Ok(Outcome::Detached) => {
                eprint!("\r\n[thther] detached (session {id} still running)\r\n");
                return Ok(());
            }
            Ok(Outcome::Disconnected) => {
                // We were connected, so restart the backoff schedule.
                established_once = true;
                backoff.reset();
            }
            Err(e) => {
                if !established_once {
                    // Never connected: real failure, don't loop forever.
                    return Err(e);
                }
                // Blip during a reconnect attempt; keep trying.
            }
        }
        let delay = backoff.next_delay();
        eprint!("\r\n[thther] connection lost, reconnecting...\r\n");
        tokio::time::sleep(delay).await;
    }
}

async fn connect_once(
    host: &str,
    port: u16,
    id: &str,
    psk: [u8; 32],
    received: Arc<AtomicU64>,
    stdin_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    winch: &mut Signal,
) -> Result<Outcome> {
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();

    let client_nonce = handshake::random_nonce();
    let offset = received.load(Ordering::SeqCst);
    handshake::client_send(&mut w, id, &client_nonce, offset).await?;
    let (server_nonce, _server_total) = handshake::client_recv(&mut r).await?;

    let key = derive_key(&psk, &client_nonce, &server_nonce);
    let mut sealer = Sealer::new(&key, DIR_CLIENT_TO_SERVER);
    let mut opener = Opener::new(&key, DIR_SERVER_TO_CLIENT);

    write_frame(&mut w, &mut sealer, &Frame::Hello).await?;
    match read_frame(&mut r, &mut opener).await? {
        Frame::Hello => {}
        _ => anyhow::bail!("bad server hello"),
    }

    // Sync current terminal size to the PTY.
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        write_frame(&mut w, &mut sealer, &Frame::Resize { cols, rows }).await?;
    }

    let (pong_tx, mut pong_rx) = mpsc::channel::<()>(8);
    let mut reader = tokio::spawn(client_reader(r, opener, received.clone(), pong_tx));

    let writer_outcome = tokio::select! {
        ro = &mut reader => ro.unwrap_or(Outcome::Disconnected),
        wo = client_writer(&mut w, &mut sealer, stdin_rx, winch, &mut pong_rx, received.clone()) => wo,
    };
    reader.abort();
    Ok(writer_outcome)
}

async fn client_reader(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut opener: Opener,
    received: Arc<AtomicU64>,
    pong_tx: mpsc::Sender<()>,
) -> Outcome {
    let mut stdout = tokio::io::stdout();
    loop {
        match read_frame(&mut r, &mut opener).await {
            Ok(Frame::Data(b)) => {
                if stdout.write_all(&b).await.is_err() {
                    return Outcome::Disconnected;
                }
                let _ = stdout.flush().await;
                received.fetch_add(b.len() as u64, Ordering::SeqCst);
            }
            Ok(Frame::Ended) => return Outcome::Ended,
            Ok(Frame::Ping) => {
                if pong_tx.send(()).await.is_err() {
                    return Outcome::Disconnected;
                }
            }
            Ok(_) => {}
            Err(_) => return Outcome::Disconnected,
        }
    }
}

async fn client_writer(
    w: &mut tokio::net::tcp::OwnedWriteHalf,
    sealer: &mut Sealer,
    stdin_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    winch: &mut Signal,
    pong_rx: &mut mpsc::Receiver<()>,
    received: Arc<AtomicU64>,
) -> Outcome {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut prefix_pending = false;

    loop {
        tokio::select! {
            maybe = stdin_rx.recv() => {
                let bytes = match maybe {
                    Some(b) => b,
                    None => return Outcome::Detached, // local stdin closed
                };
                let mut out = Vec::with_capacity(bytes.len());
                for &b in &bytes {
                    if prefix_pending {
                        prefix_pending = false;
                        if b == DETACH_KEY {
                            return Outcome::Detached;
                        }
                        out.push(DETACH_PREFIX);
                        if b == DETACH_PREFIX {
                            prefix_pending = true;
                        } else {
                            out.push(b);
                        }
                    } else if b == DETACH_PREFIX {
                        prefix_pending = true;
                    } else {
                        out.push(b);
                    }
                }
                if !out.is_empty()
                    && write_frame(w, sealer, &Frame::Data(out)).await.is_err()
                {
                    return Outcome::Disconnected;
                }
            }
            _ = winch.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    if write_frame(w, sealer, &Frame::Resize { cols, rows }).await.is_err() {
                        return Outcome::Disconnected;
                    }
                }
            }
            p = pong_rx.recv() => {
                if p.is_none() {
                    return Outcome::Disconnected;
                }
                if write_frame(w, sealer, &Frame::Pong).await.is_err() {
                    return Outcome::Disconnected;
                }
            }
            _ = tick.tick() => {
                let off = received.load(Ordering::SeqCst);
                if write_frame(w, sealer, &Frame::Ack(off)).await.is_err()
                    || write_frame(w, sealer, &Frame::Ping).await.is_err()
                {
                    return Outcome::Disconnected;
                }
            }
        }
    }
}

/// A dedicated OS thread reads raw stdin bytes (raw mode delivers per keystroke)
/// and forwards them over a channel that outlives individual TCP connections.
fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<Vec<u8>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}
