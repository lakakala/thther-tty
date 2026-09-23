//! Control-plane messages between the SSH-invoked agent and the daemon
//! (JSON, one object per line over the unix socket), and the bootstrap reply
//! the agent prints to stdout for the client to parse.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Require the daemon's listening port before performing any operation.
    /// A distinct operation ensures older daemons cannot silently ignore it.
    OnPort { port: u16, request: Box<ControlRequest> },
    /// Create a new session; returns port/id/psk.
    Create { cols: u16, rows: u16 },
    /// Attach to an existing detached session; mints a fresh psk. Rejected if
    /// the session currently has an active connection.
    Attach { id: String },
    /// List sessions.
    Ls,
    /// Terminate a session.
    Kill { id: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    /// Unix seconds when the session started.
    pub started: u64,
    /// "attached" or "detached".
    pub status: String,
    pub cmd: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlResponse {
    /// For Create / Attach: everything the client needs to dial the TCP channel.
    Bootstrap {
        port: u16,
        id: String,
        psk_hex: String,
    },
    Ls {
        sessions: Vec<SessionInfo>,
    },
    Ok,
    Err {
        message: String,
    },
}
