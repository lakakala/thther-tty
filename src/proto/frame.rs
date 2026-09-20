//! Framing over the encrypted session channel.
//!
//! Wire record: [u32 BE ciphertext_len][ciphertext]. The ciphertext decrypts to
//! a plaintext frame: [u8 type][payload]. Only `Data` payload bytes advance the
//! resume offset; control frames do not.

use super::crypto::{Opener, Sealer};
use anyhow::{anyhow, bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const T_DATA: u8 = 0;
const T_RESIZE: u8 = 1;
const T_PING: u8 = 2;
const T_PONG: u8 = 3;
const T_ACK: u8 = 4;
const T_HELLO: u8 = 5;
const T_ENDED: u8 = 6;

/// Magic carried in the first encrypted `Hello` frame; a wrong PSK makes the
/// AEAD tag fail before we ever parse this, so it is a belt-and-suspenders check.
pub const HELLO_MAGIC: &[u8] = b"THTHER-HELLO-1";

/// Records larger than this are rejected to bound memory.
const MAX_RECORD: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum Frame {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Ping,
    Pong,
    /// Bytes the peer has received so far (server uses it to trim its buffer).
    Ack(u64),
    Hello,
    /// Session ended (shell exited); the client should stop and not reconnect.
    Ended,
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Data(b) => {
                let mut v = Vec::with_capacity(1 + b.len());
                v.push(T_DATA);
                v.extend_from_slice(b);
                v
            }
            Frame::Resize { cols, rows } => {
                let mut v = Vec::with_capacity(5);
                v.push(T_RESIZE);
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
                v
            }
            Frame::Ping => vec![T_PING],
            Frame::Pong => vec![T_PONG],
            Frame::Ack(n) => {
                let mut v = Vec::with_capacity(9);
                v.push(T_ACK);
                v.extend_from_slice(&n.to_be_bytes());
                v
            }
            Frame::Hello => {
                let mut v = Vec::with_capacity(1 + HELLO_MAGIC.len());
                v.push(T_HELLO);
                v.extend_from_slice(HELLO_MAGIC);
                v
            }
            Frame::Ended => vec![T_ENDED],
        }
    }

    fn decode(pt: &[u8]) -> Result<Frame> {
        let (&t, rest) = pt.split_first().ok_or_else(|| anyhow!("empty frame"))?;
        Ok(match t {
            T_DATA => Frame::Data(rest.to_vec()),
            T_RESIZE => {
                if rest.len() != 4 {
                    bail!("bad resize frame");
                }
                Frame::Resize {
                    cols: u16::from_be_bytes([rest[0], rest[1]]),
                    rows: u16::from_be_bytes([rest[2], rest[3]]),
                }
            }
            T_PING => Frame::Ping,
            T_PONG => Frame::Pong,
            T_ACK => {
                if rest.len() != 8 {
                    bail!("bad ack frame");
                }
                let mut a = [0u8; 8];
                a.copy_from_slice(rest);
                Frame::Ack(u64::from_be_bytes(a))
            }
            T_HELLO => {
                if rest != HELLO_MAGIC {
                    bail!("bad hello magic");
                }
                Frame::Hello
            }
            T_ENDED => Frame::Ended,
            other => bail!("unknown frame type {other}"),
        })
    }
}

/// Seal and write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    sealer: &mut Sealer,
    frame: &Frame,
) -> Result<()> {
    let ct = sealer.seal(&frame.encode())?;
    if ct.len() as u64 > MAX_RECORD as u64 {
        bail!("record too large");
    }
    w.write_all(&(ct.len() as u32).to_be_bytes()).await?;
    w.write_all(&ct).await?;
    w.flush().await?;
    Ok(())
}

/// Read and open one frame. Returns Err on EOF or auth failure.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    opener: &mut Opener,
) -> Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_RECORD {
        bail!("bad record length {len}");
    }
    let mut ct = vec![0u8; len as usize];
    r.read_exact(&mut ct).await?;
    let pt = opener.open(&ct)?;
    Frame::decode(&pt)
}
