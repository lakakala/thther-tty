//! thther — a TCP-based, mosh-like persistent remote terminal.
//!
//! One binary, several modes (all client modes take `-t user@host`, which
//! overrides `ssh_target` in the config file):
//!   thther                 create a new session and attach (interactive)
//!   thther attach <id>     reattach to a detached session
//!   thther ls              list sessions
//!   thther kill <id>       terminate a session
//!   thther __serve <op>    (internal) server agent, invoked over SSH
//!   thther __daemon        (internal) the persistent per-user daemon

mod client;
mod config;
mod proto;
mod server;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::num::NonZeroU16;

use config::Config;
use proto::control::{ControlRequest, ControlResponse};

#[derive(Parser)]
#[command(name = "thther", version, about = "Persistent remote terminal over SSH+TCP")]
struct Cli {
    /// SSH target ("user@host" or an ~/.ssh/config alias); overrides
    /// `ssh_target` in config.toml, so no config file is needed.
    #[arg(short = 't', long = "target", global = true, value_name = "TARGET")]
    target: Option<String>,

    /// Server TCP listening port (1-65535); overrides config port, not the SSH port.
    #[arg(long, global = true, value_name = "PORT")]
    port: Option<NonZeroU16>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Reattach to a detached session.
    Attach { id: String },
    /// List sessions on the configured host.
    Ls,
    /// Terminate a session.
    Kill { id: String },

    /// (internal) Server-side agent invoked over SSH.
    #[command(name = "__serve", hide = true)]
    Serve {
        #[command(subcommand)]
        op: ServeOp,
    },
    /// (internal) The persistent per-user daemon.
    #[command(name = "__daemon", hide = true)]
    Daemon,

    /// (internal/advanced) Attach directly to a session by host/port/id/psk,
    /// skipping SSH bootstrap. Used for testing and no-SSH setups.
    #[command(name = "__connect", hide = true)]
    Connect {
        #[arg(long)]
        host: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        psk: String,
    },
}

#[derive(Subcommand)]
enum ServeOp {
    Create {
        #[arg(long)]
        cols: u16,
        #[arg(long)]
        rows: u16,
    },
    Attach {
        id: String,
    },
    Ls,
    Kill {
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli).await {
        eprintln!("thther: {e:#}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let target = cli.target;
    let port = cli.port;
    match cli.cmd {
        // --- server-internal modes ---
        Some(Cmd::Daemon) => {
            init_daemon_tracing();
            server::daemon::run(port).await
        }
        Some(Cmd::Serve { op }) => {
            let req = match op {
                ServeOp::Create { cols, rows } => ControlRequest::Create { cols, rows },
                ServeOp::Attach { id } => ControlRequest::Attach { id },
                ServeOp::Ls => ControlRequest::Ls,
                ServeOp::Kill { id } => ControlRequest::Kill { id },
            };
            server::agent::run(req, port).await
        }

        // --- client modes ---
        Some(Cmd::Attach { id }) => client_attach(load_client_config(target, port)?, &id).await,
        Some(Cmd::Ls) => client_ls(load_client_config(target, port)?).await,
        Some(Cmd::Kill { id }) => client_kill(load_client_config(target, port)?, &id).await,
        Some(Cmd::Connect { host, id, psk }) => {
            let port = port.context("--port is required for __connect")?.get();
            let psk = parse_psk(&psk)?;
            client::session::run_interactive(&host, port, &id, psk).await
        }
        None => client_create(load_client_config(target, port)?).await,
    }
}

/// Client-side config: the file, with `-t` taking precedence over it.
///
/// An explicit target also drops `tcp_host`, which is paired with the
/// configured `ssh_target` and would otherwise dial the wrong host.
fn load_client_config(target: Option<String>, port: Option<NonZeroU16>) -> Result<Config> {
    Ok(Config::load()?.with_client_overrides(target, port))
}

fn init_daemon_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("THTHER_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

fn parse_psk(psk_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(psk_hex)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("psk must be 32 bytes"))
}

async fn client_create(cfg: Config) -> Result<()> {
    let host = cfg.resolve_tcp_host()?;
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    match client::bootstrap::create(&cfg, cols, rows).await? {
        ControlResponse::Bootstrap { port, id, psk_hex } => {
            let psk = parse_psk(&psk_hex)?;
            eprintln!("[thther] session {id} on {host}:{port}");
            client::session::run_interactive(&host, port, &id, psk).await
        }
        ControlResponse::Err { message } => bail!("{message}"),
        _ => bail!("unexpected response"),
    }
}

async fn client_attach(cfg: Config, id: &str) -> Result<()> {
    let host = cfg.resolve_tcp_host()?;
    match client::bootstrap::attach(&cfg, id).await? {
        ControlResponse::Bootstrap { port, id, psk_hex } => {
            let psk = parse_psk(&psk_hex)?;
            eprintln!("[thther] reattaching to {id} on {host}:{port}");
            client::session::run_interactive(&host, port, &id, psk).await
        }
        ControlResponse::Err { message } => bail!("{message}"),
        _ => bail!("unexpected response"),
    }
}

async fn client_ls(cfg: Config) -> Result<()> {
    match client::bootstrap::ls(&cfg).await? {
        ControlResponse::Ls { sessions } => {
            if sessions.is_empty() {
                println!("no sessions");
            } else {
                println!("{:<10} {:<10} {:<20} CMD", "ID", "STATUS", "STARTED");
                for s in sessions {
                    println!("{:<10} {:<10} {:<20} {}", s.id, s.status, fmt_time(s.started), s.cmd);
                }
            }
            Ok(())
        }
        ControlResponse::Err { message } => bail!("{message}"),
        _ => bail!("unexpected response"),
    }
}

async fn client_kill(cfg: Config, id: &str) -> Result<()> {
    match client::bootstrap::kill(&cfg, id).await? {
        ControlResponse::Ok => {
            println!("killed {id}");
            Ok(())
        }
        ControlResponse::Err { message } => bail!("{message}"),
        _ => bail!("unexpected response"),
    }
}

fn fmt_time(secs: u64) -> String {
    // Simple relative-free display: seconds since epoch is fine for MVP.
    format!("@{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_global_and_validated() {
        for operation in [vec![], vec!["ls"], vec!["attach", "abc"], vec!["kill", "abc"]] {
            for before in [true, false] {
                let mut args = vec!["thther", "-t", "user@host"];
                if before {
                    args.extend(["--port", "62000"]);
                }
                args.extend(operation.iter().copied());
                if !before {
                    args.extend(["--port", "62000"]);
                }
                let cli = Cli::try_parse_from(args).unwrap();
                assert_eq!(cli.port.unwrap().get(), 62000);
                assert_eq!(cli.target.as_deref(), Some("user@host"));
            }
        }
        for port in ["0", "-1", "65536", "invalid"] {
            assert!(Cli::try_parse_from(["thther", "--port", port]).is_err(), "{port}");
        }
        for port in ["1", "65535"] {
            assert!(Cli::try_parse_from(["thther", "--port", port]).is_ok());
        }
    }

    #[tokio::test]
    async fn direct_connect_keeps_its_port_argument() {
        let args = ["thther", "__connect", "--host", "localhost", "--id", "abc", "--psk", "bad"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(dispatch(cli).await.unwrap_err().to_string().contains("--port is required"));
        let cli = Cli::try_parse_from(args.into_iter().chain(["--port", "62000"])).unwrap();
        assert_eq!(cli.port.unwrap().get(), 62000);
        assert!(matches!(cli.cmd, Some(Cmd::Connect { .. })));
    }
}
