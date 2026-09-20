//! AEAD for the TCP session channel.
//!
//! Each TCP connection derives a fresh key from the session PSK plus random
//! nonces exchanged during the handshake, so reconnects never reuse a
//! (key, nonce) pair. Records are sealed with ChaCha20-Poly1305 using a
//! per-direction monotonic counter as the nonce.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;

pub const DIR_CLIENT_TO_SERVER: u8 = 0;
pub const DIR_SERVER_TO_CLIENT: u8 = 1;

/// Derive the per-connection symmetric key from the PSK and both nonces.
pub fn derive_key(psk: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; KEY_LEN] {
    let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"thther-v1-session-key", &mut okm)
        .expect("hkdf expand");
    okm
}

/// Seals outgoing records with a monotonic per-direction counter.
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    dir: u8,
    counter: u64,
}

/// Opens incoming records, checking the counter increases monotonically.
pub struct Opener {
    cipher: ChaCha20Poly1305,
    dir: u8,
    counter: u64,
}

fn nonce_for(dir: u8, counter: u64) -> Nonce {
    // 12-byte nonce = [dir][counter LE (8 bytes)][0,0,0]
    let mut n = [0u8; 12];
    n[0] = dir;
    n[1..9].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&n)
}

impl Sealer {
    pub fn new(key: &[u8; KEY_LEN], dir: u8) -> Sealer {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Sealer { cipher, dir, counter: 0 }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_for(self.dir, self.counter);
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce counter exhausted"))?;
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("seal failed"))
    }
}

impl Opener {
    pub fn new(key: &[u8; KEY_LEN], dir: u8) -> Opener {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Opener { cipher, dir, counter: 0 }
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_for(self.dir, self.counter);
        let pt = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| anyhow!("decrypt/auth failed"))?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce counter exhausted"))?;
        Ok(pt)
    }
}
