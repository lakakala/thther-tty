//! The interactive client session: raw-mode terminal bridged to the encrypted
//! TCP channel, with automatic reconnect on network blips and offset-based
//! resume within the server's retained history. Missing history is reported.

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, Signal, SignalKind};
use tokio::sync::{mpsc, oneshot};

use crate::proto::crypto::{
    derive_key, Opener, Sealer, DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT,
};
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

/// These errors cannot be repaired by reconnecting to the network.
#[derive(Debug, thiserror::Error)]
enum FatalSessionError {
    #[error("terminal output failed: {0}")]
    Output(#[source] std::io::Error),
    #[error("terminal protocol error: {0}")]
    Protocol(&'static str),
}

/// One stdout handle and one committed offset for the entire client session.
struct SessionOutput<W> {
    writer: W,
    received: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> SessionOutput<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            received: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn accept(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(FatalSessionError::Protocol("output offset overflow"))?;
        let received = self.received.load(Ordering::SeqCst);
        if end <= received {
            return Ok(());
        }
        if offset > received {
            // CAN cancels a possible incomplete escape sequence before the
            // local notice. Notice bytes are never counted as remote output.
            let notice = format!(
                "\x18\r\n[thther] output gap: {} bytes unavailable\r\n",
                offset - received
            );
            self.writer
                .write_all(notice.as_bytes())
                .await
                .map_err(FatalSessionError::Output)?;
        }
        let skip = received.saturating_sub(offset) as usize;
        self.writer
            .write_all(&data[skip..])
            .await
            .map_err(FatalSessionError::Output)?;
        self.writer
            .flush()
            .await
            .map_err(FatalSessionError::Output)?;
        self.received.store(end, Ordering::SeqCst);
        Ok(())
    }
}

/// Run the interactive session, reconnecting through blips, until the shell
/// exits or the user detaches.
pub async fn run_interactive(host: &str, port: u16, id: &str, psk: [u8; 32]) -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let result = drive(host, port, id, psk).await;
    let _ = crossterm::terminal::disable_raw_mode();
    // Move to a fresh line so the shell prompt isn't glued to session output.
    // stdout itself may be the reason the session failed (e.g. a closed pipe).
    // Restore the terminal and return that error instead of panicking here.
    use std::io::Write;
    let _ = writeln!(std::io::stdout());
    result
}

async fn drive(host: &str, port: u16, id: &str, psk: [u8; 32]) -> Result<()> {
    let mut output = SessionOutput::new(tokio::io::stdout());
    let mut stdin_rx = spawn_stdin_reader();
    let mut winch = signal(SignalKind::window_change())?;
    let mut backoff = Backoff::new();
    let mut established_once = false;

    loop {
        match connect_once(host, port, id, psk, &mut output, &mut stdin_rx, &mut winch).await {
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
                if !established_once
                    || e.is::<FatalSessionError>()
                    || e.is::<handshake::Rejection>()
                {
                    // Initial failures and terminal/protocol errors are final.
                    return Err(e);
                }
                // Blip during a reconnect attempt; keep trying.
            }
        }
        let delay = backoff.next_delay();
        tokio::time::sleep(delay).await;
    }
}

async fn connect_once<W: AsyncWrite + Unpin>(
    host: &str,
    port: u16,
    id: &str,
    psk: [u8; 32],
    output: &mut SessionOutput<W>,
    stdin_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    winch: &mut Signal,
) -> Result<Outcome> {
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();

    let client_nonce = handshake::random_nonce();
    let received = output.received.clone();
    let offset = received.load(Ordering::SeqCst);
    handshake::client_send(&mut w, id, &client_nonce, offset).await?;
    let (server_nonce, server_total) = handshake::client_recv(&mut r).await?;
    if offset > server_total {
        return Err(handshake::Rejection::BadOffset.into());
    }

    let key = derive_key(&psk, &client_nonce, &server_nonce);
    let mut sealer = Sealer::new(&key, DIR_CLIENT_TO_SERVER);
    let mut opener = Opener::new(&key, DIR_SERVER_TO_CLIENT);

    write_frame(&mut w, &mut sealer, &Frame::Hello).await?;
    match read_frame(&mut r, &mut opener).await? {
        Frame::Hello => {}
        _ => return Err(FatalSessionError::Protocol("bad server hello").into()),
    }

    // Sync current terminal size to the PTY.
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        write_frame(&mut w, &mut sealer, &Frame::Resize { cols, rows }).await?;
    }

    let (pong_tx, mut pong_rx) = mpsc::channel::<()>(8);
    let (stop_tx, stop_rx) = oneshot::channel();
    let reader = client_reader(r, opener, output, pong_tx, stop_rx);
    tokio::pin!(reader);

    tokio::select! {
        ro = &mut reader => ro,
        wo = client_writer(&mut w, &mut sealer, stdin_rx, winch, &mut pong_rx, received) => {
            // Stop only at network/control waits, never in the middle of a
            // stdout write/flush/offset commit. Await before reconnecting or
            // restoring cooked mode so no old output task can outlive us.
            let _ = stop_tx.send(());
            drop(pong_rx);
            let ro = reader.await?;
            Ok(if ro == Outcome::Ended { ro } else { wo })
        }
    }
}

async fn client_reader<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut r: R,
    mut opener: Opener,
    output: &mut SessionOutput<W>,
    pong_tx: mpsc::Sender<()>,
    mut stop: oneshot::Receiver<()>,
) -> Result<Outcome> {
    loop {
        let frame = tokio::select! {
            biased;
            _ = &mut stop => return Ok(Outcome::Disconnected),
            frame = read_frame(&mut r, &mut opener) => frame,
        };
        match frame {
            Ok(Frame::Output { offset, data }) => {
                output.accept(offset, &data).await?;
            }
            Ok(Frame::Ended) => return Ok(Outcome::Ended),
            Ok(Frame::Ping) => {
                tokio::select! {
                    _ = &mut stop => return Ok(Outcome::Disconnected),
                    sent = pong_tx.send(()) => {
                        if sent.is_err() {
                            return Ok(Outcome::Disconnected);
                        }
                    }
                }
            }
            Ok(Frame::Pong) => {}
            Ok(_) => return Err(FatalSessionError::Protocol("unexpected server frame").into()),
            Err(_) => return Ok(Outcome::Disconnected),
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

#[cfg(test)]
mod tests;
