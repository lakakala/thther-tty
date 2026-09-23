//! Configuration loaded from ~/.thther/config.toml.
//!
//! The same file is read on both sides. The client reads `ssh_target` / `tcp_host`;
//! both sides read `port`, and the server-side daemon reads `port_range`.
//! Missing keys fall back to defaults,
//! and the file itself is optional: the client can be pointed at a host with `-t`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::num::NonZeroU16;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Argument handed to the system `ssh` binary, e.g. "user@host" or an
    /// ~/.ssh/config Host alias. Required for client operations, unless the
    /// client passes `-t`, which overrides this.
    #[serde(default)]
    pub ssh_target: Option<String>,

    /// Host the client dials for the independent TCP channel. Defaults to the
    /// host part of `ssh_target` (after any `user@`).
    #[serde(default)]
    pub tcp_host: Option<String>,

    /// Fixed server TCP port. The client forwards it to the server; on the
    /// server it takes precedence over port_range when starting the daemon.
    #[serde(default)]
    pub port: Option<NonZeroU16>,

    /// Inclusive [low, high] TCP port range the daemon may bind (server side).
    #[serde(default = "default_port_range")]
    pub port_range: [u16; 2],

    /// Per-session replay ring buffer size in bytes (server side).
    #[serde(default = "default_ring_bytes")]
    pub ring_bytes: usize,
}

fn default_port_range() -> [u16; 2] {
    [60000, 61000]
}
fn default_ring_bytes() -> usize {
    256 * 1024
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ssh_target: None,
            tcp_host: None,
            port: None,
            port_range: default_port_range(),
            ring_bytes: default_ring_bytes(),
        }
    }
}

impl Config {
    pub fn with_client_overrides(
        mut self,
        target: Option<String>,
        port: Option<NonZeroU16>,
    ) -> Self {
        if let Some(target) = target {
            self.ssh_target = Some(target);
            self.tcp_host = None;
        }
        self.port = port.or(self.port);
        self
    }

    pub fn path() -> PathBuf {
        base_dir().join("config.toml")
    }

    /// Load config; a missing file yields defaults (so the server side works
    /// out of the box, and only the client complains about a missing target).
    pub fn load() -> Result<Config> {
        let p = Config::path();
        match std::fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).with_context(|| format!("parsing {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// The SSH target, erroring with a helpful message if unset.
    pub fn require_ssh_target(&self) -> Result<&str> {
        self.ssh_target.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "no ssh target; pass -t user@host or set ssh_target in {}",
                Config::path().display()
            )
        })
    }

    /// Host to dial for the TCP channel.
    pub fn resolve_tcp_host(&self) -> Result<String> {
        if let Some(h) = &self.tcp_host {
            return Ok(h.clone());
        }
        let target = self.require_ssh_target()?;
        let host = target.rsplit('@').next().unwrap_or(target);
        Ok(host.to_string())
    }
}

/// ~/.thther, created if absent.
pub fn base_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".thther")
    } else {
        PathBuf::from("/tmp/.thther")
    }
}

/// Runtime dir for the control socket + daemon state.
/// Prefers $XDG_RUNTIME_DIR/thther, falls back to ~/.thther.
pub fn runtime_dir() -> PathBuf {
    let d = if let Ok(x) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(x).join("thther")
    } else {
        base_dir()
    };
    d
}

pub fn control_socket_path() -> PathBuf {
    runtime_dir().join("control.sock")
}

pub fn daemon_log_path() -> PathBuf {
    base_dir().join("daemon.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_port_config_and_client_precedence() {
        let cfg: Config =
            toml::from_str("ssh_target = 'old-host'\ntcp_host = 'old-ip'\nport = 62000\n").unwrap();
        let changed_target = cfg.clone().with_client_overrides(Some("new-host".into()), None);
        assert_eq!(changed_target.ssh_target.as_deref(), Some("new-host"));
        assert!(changed_target.tcp_host.is_none());
        assert_eq!(changed_target.port.unwrap().get(), 62000);
        let overridden = cfg.with_client_overrides(None, NonZeroU16::new(62001));
        assert_eq!(overridden.port.unwrap().get(), 62001);
        let defaults: Config = toml::from_str("").unwrap();
        assert!(defaults.port.is_none());
        assert_eq!(defaults.port_range, [60000, 61000]);
    }

    #[test]
    fn config_rejects_invalid_fixed_ports() {
        for port in ["0", "-1", "65536", "'62000'", "1.5"] {
            assert!(toml::from_str::<Config>(&format!("port = {port}")).is_err(), "{port}");
        }
        for port in [1, 65535] {
            let cfg: Config = toml::from_str(&format!("port = {port}")).unwrap();
            assert_eq!(cfg.port.unwrap().get(), port);
        }
    }
}
