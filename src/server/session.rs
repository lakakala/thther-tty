//! A persistent server-side session: a PTY running the user's shell, a replay
//! ring buffer, and the state machine that lets exactly one TCP connection be
//! "active" at a time while surviving detach/reconnect.

use anyhow::Result;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, PtySize};
use rand::RngCore;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

use crate::proto::frame::MAX_OUTPUT_BYTES;

use super::registry::Registry;

pub enum PtyMsg {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// Ring buffer of recent PTY output, indexed by absolute output byte offset.
struct RingBuf {
    data: VecDeque<u8>,
    start: u64,
    cap: usize,
}

impl RingBuf {
    fn new(cap: usize) -> Self {
        RingBuf {
            data: VecDeque::new(),
            start: 0,
            cap,
        }
    }
    fn total(&self) -> u64 {
        self.start + self.data.len() as u64
    }
    fn append(&mut self, bytes: &[u8]) {
        self.data.extend(bytes.iter().copied());
        if self.data.len() > self.cap {
            let drop_n = self.data.len() - self.cap;
            self.data.drain(0..drop_n);
            self.start += drop_n as u64;
        }
    }
    /// A bounded chunk at/after `offset`; returns (actual_start, bytes).
    /// The actual start can exceed the requested offset after eviction, even
    /// when an empty buffer retains no bytes at all.
    fn read_from(&self, offset: u64) -> (u64, Vec<u8>) {
        let total = self.total();
        if offset >= total {
            return (total, Vec::new());
        }
        let from = offset.max(self.start);
        let idx = (from - self.start) as usize;
        let out: Vec<u8> = self
            .data
            .iter()
            .skip(idx)
            .take(MAX_OUTPUT_BYTES)
            .copied()
            .collect();
        (from, out)
    }
}

pub struct SessionShared {
    pub id: String,
    pub started: u64,
    pub cmd: String,

    ring: Mutex<RingBuf>,
    /// Fired when new output is buffered or the session ends.
    pub data_ready: Notify,
    pub ended: AtomicBool,

    psk: Mutex<[u8; 32]>,
    /// Incremented each time a TCP connection becomes active; a connection is
    /// current iff its captured epoch still matches.
    active_epoch: AtomicU64,
    /// Whether a connection currently believes itself active (busy flag).
    connected: AtomicBool,

    to_pty: Mutex<Sender<PtyMsg>>,
    killer: Mutex<Option<Box<dyn ChildKiller + Send + Sync>>>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_psk() -> [u8; 32] {
    let mut p = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut p);
    p
}

impl SessionShared {
    pub fn current_total(&self) -> u64 {
        self.ring.lock().unwrap().total()
    }
    pub fn read_from(&self, offset: u64) -> (u64, Vec<u8>) {
        self.ring.lock().unwrap().read_from(offset)
    }
    pub fn current_psk(&self) -> [u8; 32] {
        *self.psk.lock().unwrap()
    }
    pub fn rotate_psk(&self) -> [u8; 32] {
        let new = random_psk();
        *self.psk.lock().unwrap() = new;
        new
    }
    pub fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
    pub fn is_busy(&self) -> bool {
        self.connected.load(Ordering::SeqCst) && !self.is_ended()
    }
    pub fn status_str(&self) -> String {
        if self.is_busy() {
            "attached"
        } else {
            "detached"
        }
        .to_string()
    }

    /// Take over as the active connection, superseding any prior one.
    pub fn become_active(&self) -> u64 {
        let e = self.active_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.connected.store(true, Ordering::SeqCst);
        e
    }
    pub fn is_current(&self, epoch: u64) -> bool {
        self.active_epoch.load(Ordering::SeqCst) == epoch
    }
    /// Called when a connection ends; clears the busy flag only if it was the
    /// current one (so a blip-takeover doesn't get its flag cleared by the old
    /// connection tearing down).
    pub fn leave(&self, epoch: u64) {
        if self.is_current(epoch) {
            self.connected.store(false, Ordering::SeqCst);
        }
    }

    pub fn send_input(&self, bytes: Vec<u8>) {
        let _ = self.to_pty.lock().unwrap().send(PtyMsg::Input(bytes));
    }
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self
            .to_pty
            .lock()
            .unwrap()
            .send(PtyMsg::Resize { cols, rows });
    }
    pub fn kill(&self) {
        if let Some(k) = self.killer.lock().unwrap().as_mut() {
            let _ = k.kill();
        }
    }

    fn mark_ended(&self, registry: &Registry) {
        if !self.ended.swap(true, Ordering::SeqCst) {
            self.data_ready.notify_waiters();
            registry.remove(&self.id);
        }
    }
}

/// Spawn a new session: open a PTY, launch $SHELL, wire up reader/writer/reaper
/// threads, and register it.
pub fn spawn_session(
    id: String,
    shell: &str,
    cols: u16,
    rows: u16,
    ring_bytes: usize,
    registry: Arc<Registry>,
) -> Result<Arc<SessionShared>> {
    let pty = native_pty_system();
    let pair = pty.openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let mut cmd = CommandBuilder::new(shell);
    cmd.env(
        "TERM",
        std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
    );
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let child = pair.slave.spawn_command(cmd)?;
    let killer = child.clone_killer();

    // Dropping the slave in the parent lets the master reader see EOF when the
    // shell exits.
    drop(pair.slave);

    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let master = pair.master;

    let (tx, rx) = channel::<PtyMsg>();

    let shared = Arc::new(SessionShared {
        id: id.clone(),
        started: now_secs(),
        cmd: shell.to_string(),
        ring: Mutex::new(RingBuf::new(ring_bytes)),
        data_ready: Notify::new(),
        ended: AtomicBool::new(false),
        psk: Mutex::new(random_psk()),
        active_epoch: AtomicU64::new(0),
        connected: AtomicBool::new(false),
        to_pty: Mutex::new(tx),
        killer: Mutex::new(Some(killer)),
    });

    // Reader thread: PTY output -> ring buffer.
    {
        let shared = shared.clone();
        let registry = registry.clone();
        let mut reader = reader;
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        shared.ring.lock().unwrap().append(&buf[..n]);
                        shared.data_ready.notify_waiters();
                    }
                }
            }
            shared.mark_ended(&registry);
        });
    }

    // Writer/control thread: owns master + writer.
    {
        let mut writer = writer;
        let master = master;
        std::thread::spawn(move || {
            use std::io::Write;
            while let Ok(msg) = rx.recv() {
                match msg {
                    PtyMsg::Input(bytes) => {
                        if writer.write_all(&bytes).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                    }
                    PtyMsg::Resize { cols, rows } => {
                        let _ = master.resize(PtySize {
                            rows,
                            cols,
                            pixel_width: 0,
                            pixel_height: 0,
                        });
                    }
                }
            }
        });
    }

    // Reaper thread: wait on the child so it doesn't linger as a zombie.
    {
        let shared = shared.clone();
        let registry = registry.clone();
        let mut child = child;
        std::thread::spawn(move || {
            let _ = child.wait();
            shared.mark_ended(&registry);
        });
    }

    registry.insert(shared.clone());
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_returns_absolute_start_and_reconnect_stays_caught_up() {
        let mut ring = RingBuf::new(32);
        ring.append(&[b'x'; 100]);
        ring.append(b"\x1b]10;?\x07prompt> ");
        let (offset, bytes) = ring.read_from(0);
        assert_eq!(offset, ring.total() - 32);
        assert_eq!(bytes.len(), 32);
        let mut cursor = offset + bytes.len() as u64;
        for _ in 0..3 {
            assert_eq!(ring.read_from(cursor), (cursor, Vec::new()));
        }
        ring.append(b"next");
        let (offset, bytes) = ring.read_from(cursor);
        assert_eq!(offset, cursor);
        assert_eq!(bytes, b"next");
        cursor = offset + bytes.len() as u64;
        assert_eq!(cursor, ring.total());
    }

    #[test]
    fn output_is_chunked_and_later_eviction_reports_another_gap() {
        let mut ring = RingBuf::new(MAX_OUTPUT_BYTES * 3);
        ring.append(&vec![b'a'; MAX_OUTPUT_BYTES * 3]);
        let (offset, bytes) = ring.read_from(0);
        assert_eq!(offset, 0);
        assert_eq!(bytes.len(), MAX_OUTPUT_BYTES);
        let cursor = offset + bytes.len() as u64;
        ring.append(&vec![b'b'; MAX_OUTPUT_BYTES * 2]);
        let (offset, bytes) = ring.read_from(cursor);
        assert_eq!(offset, (MAX_OUTPUT_BYTES * 2) as u64);
        assert_eq!(bytes.len(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn zero_capacity_still_reports_absolute_position() {
        let mut ring = RingBuf::new(0);
        ring.append(b"missing");
        assert_eq!(ring.read_from(0), (7, Vec::new()));
        assert_eq!(ring.read_from(7), (7, Vec::new()));
    }
}
