//! Plaintext TCP handshake performed before switching to encrypted frames.
//!
//! The handshake carries the session id, both random nonces, and the client's
//! resume offset. PSK knowledge is proven implicitly: both sides derive the key
//! from the PSK + nonces, and the first encrypted `Hello` frame fails to open if
//! the PSK is wrong.

use super::crypto::NONCE_LEN;
use anyhow::{bail, Result};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"THT1";
const VERSION: u8 = 1;
pub const SESSION_ID_LEN: usize = 8;

pub const STATUS_OK: u8 = 0;
pub const STATUS_NO_SESSION: u8 = 1;

pub struct ClientHello {
    pub session_id: String,
    pub client_nonce: [u8; NONCE_LEN],
    pub offset: u64,
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

/// Client side: send the hello, return our nonce (already inside `hello`).
pub async fn client_send<W: AsyncWrite + Unpin>(
    w: &mut W,
    session_id: &str,
    client_nonce: &[u8; NONCE_LEN],
    offset: u64,
) -> Result<()> {
    if session_id.len() != SESSION_ID_LEN {
        bail!("session id must be {SESSION_ID_LEN} chars");
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(session_id.as_bytes());
    buf.extend_from_slice(client_nonce);
    buf.extend_from_slice(&offset.to_be_bytes());
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Client side: read the server response. Returns (server_nonce, server_total).
pub async fn client_recv<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<([u8; NONCE_LEN], u64)> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status).await?;
    match status[0] {
        STATUS_OK => {
            let mut nonce = [0u8; NONCE_LEN];
            r.read_exact(&mut nonce).await?;
            let mut total = [0u8; 8];
            r.read_exact(&mut total).await?;
            Ok((nonce, u64::from_be_bytes(total)))
        }
        STATUS_NO_SESSION => bail!("server: no such session"),
        other => bail!("server: unknown status {other}"),
    }
}

/// Server side: read the client hello.
pub async fn server_recv<R: AsyncRead + Unpin>(r: &mut R) -> Result<ClientHello> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).await?;
    if &magic != MAGIC {
        bail!("bad magic");
    }
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver).await?;
    if ver[0] != VERSION {
        bail!("version mismatch");
    }
    let mut id = [0u8; SESSION_ID_LEN];
    r.read_exact(&mut id).await?;
    let session_id = String::from_utf8(id.to_vec())?;
    let mut client_nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut client_nonce).await?;
    let mut offset = [0u8; 8];
    r.read_exact(&mut offset).await?;
    Ok(ClientHello {
        session_id,
        client_nonce,
        offset: u64::from_be_bytes(offset),
    })
}

/// Server side: reply OK with our nonce + current total offset.
pub async fn server_send_ok<W: AsyncWrite + Unpin>(
    w: &mut W,
    server_nonce: &[u8; NONCE_LEN],
    server_total: u64,
) -> Result<()> {
    let mut buf = Vec::new();
    buf.push(STATUS_OK);
    buf.extend_from_slice(server_nonce);
    buf.extend_from_slice(&server_total.to_be_bytes());
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Server side: reply with an error status.
pub async fn server_send_err<W: AsyncWrite + Unpin>(w: &mut W, status: u8) -> Result<()> {
    w.write_all(&[status]).await?;
    w.flush().await?;
    Ok(())
}
