# thther

A TCP-based, mosh-like persistent remote terminal with SSH bootstrap and
detach/attach. SSH is used **only** to authenticate and start the server; the
interactive terminal then runs over an independent, encrypted **TCP** channel
whose lifetime is decoupled from SSH. So you get mosh-style network-blip
resilience *without UDP*, plus explicit detach/attach like tmux.

## Why

- **mosh** needs UDP, which corporate firewalls often block.
- **tmux-over-ssh / dtach** persist a session but the channel dies with SSH and
  there is no "network recovered, resume" behavior.

`thther` gives you: pure TCP, auto-reconnect on blips (exact resume within the
retained output history), and reattach after the client process fully exits.

## Architecture

```
[local client] --system ssh--> [server __serve agent] --unix socket--> [__daemon]
      |                                                                     |
      +------------------ independent encrypted TCP (host:port) ------------+
```

- **client** — raw-mode terminal bridged to the encrypted TCP channel; detects
  blips and reconnects with offset-based resume.
- **`__serve` agent** — thin process launched over SSH as
  `~/.thther/bin/thther-<version> __serve …` (auto-installed on first connect);
  talks to the daemon over a unix socket, mints a PSK, prints `{port,id,psk}`.
  Spawns the daemon (setsid, detached) if it is not already running.
- **`__daemon`** — one persistent per-user process. Binds a single TCP port
  (single-port multiplexing for all sessions), owns every session's PTY + shell +
  replay ring buffer. Survives the client and SSH via `setsid`.

Key design points (all tested — see below):

- SSH only bootstraps; the TCP session outlives it.
- Channel secured with a per-session PSK; each TCP connection derives a fresh
  ChaCha20-Poly1305 key from the PSK + handshake nonces (safe across reconnects).
- Detach (`Ctrl-\` then `d`) leaves the session running; shell exit reaps it.
- Reconnect: a same-process network blip reconnects with the in-memory PSK and
  resumes from the client's committed absolute output offset. Each server
  output frame carries its actual starting offset, so buffer eviction cannot
  cause repeated output on later reconnects. Missing history is reported as
  `[thther] output gap: N bytes unavailable`. A fresh
  `thther attach <id>` re-runs SSH and rotates the PSK.
- A second attach is rejected only while a connection is *active*; a detached
  session accepts a new attach.

## Install

### Homebrew (macOS / Linux)

```
brew tap lakakala/tap
brew trust lakakala/tap   # newer Homebrew requires trusting third-party taps
brew install thther
```

or in one step:

```
brew install lakakala/tap/thther
```

### Prebuilt binaries

Each tagged release on the
[Releases page](https://github.com/lakakala/thther-tty/releases) ships:

- `thther-<tag>-x86_64-unknown-linux-gnu.tar.gz`
- `thther-<tag>-aarch64-unknown-linux-gnu.tar.gz`
- `thther-<tag>-aarch64-apple-darwin.tar.gz`

each with a `.sha256` checksum. Starting with v0.1.3, Linux x86_64 and
aarch64 releases are built in AlmaLinux 8 containers with a glibc 2.28
baseline, supporting AlmaLinux 8 / RHEL 8 and newer systems with glibc
≥ 2.28. Earlier releases require glibc ≥ 2.35; on older systems build
from source.

### Build from source

Install a C compiler and the stable Rust toolchain. On AlmaLinux 8:

```sh
sudo dnf install -y gcc binutils git tar gzip curl ca-certificates libstdc++
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
. "$HOME/.cargo/env"
```

Then build from the project directory:

```
cargo build --release --locked      # -> target/release/thther
```

### Server

The server needs no manual install. The client always runs
`~/.thther/bin/thther-<version>` on the server, where `<version>` is the
client's own version — a `thther` on the server's `PATH` is never used, so the
bootstrap agent matches the client. Compatibility with an already running
daemon is checked separately. If that file is missing, the server downloads the matching
release binary (checksum-verified) on first connect. This needs Linux
x86_64/aarch64, `curl` or `wget`, and access to github.com.

Without GitHub access, copy the right binary to
`~/.thther/bin/thther-<version>` on the server yourself and `chmod +x` it.

### Upgrading to v0.1.6

v0.1.6 uses terminal protocol 2 and requires upgrading both client and server.
It fixes repeated replay after output-buffer eviction and interrupted stdout
writes, which could cause terminal queries to run again and their responses to
appear as shell input. Create/attach checks the daemon's protocol before
creating a session or changing its key; an older daemon is rejected.

Installing a matching server binary does not upgrade an already running daemon.
Finish work in its sessions using the old client, then manually stop that user's
old `thther __daemon` process. The next create starts the new daemon. Stopping
the daemon ends its sessions; thther does not stop or migrate them automatically.
Before a release is published, manually install the built matching server binary
at `~/.thther/bin/thther-0.1.6` instead of relying on automatic download.

The reconnect fix preserves normal terminal queries and keyboard input. It does
not filter all terminal responses, eliminate delayed responses after an
application exits, or provide a terminal-state snapshot for a fresh attach.

## Configure

No config file is needed: pass the SSH target on the command line with
`-t/--target`, exactly as you would hand it to `ssh`.

```
thther -t user@host
```

To avoid repeating it, put it in `~/.thther/config.toml` instead; `-t` always
wins over the file.

```toml
ssh_target = "user@host"      # handed to the system `ssh` (aliases from ~/.ssh/config work)
tcp_host   = "host"           # optional; where the client dials TCP (defaults to host of ssh_target)
port       = 62000           # optional; fixed server TCP port (not the SSH port)
port_range = [60000, 61000]   # server: daemon binds one free port in this range (open it in the firewall)
ring_bytes = 262144           # per-session replay buffer
```

To specify the SSH port for a connection, use `-p/--ssh-port`:

```sh
thther -t user@host --ssh-port 2222
thther -t user@host -p 2222 --port 62000
thther -t user@host attach <id> --ssh-port 2222
```

`-p/--ssh-port` accepts 1 through 65535 and works before or after any client
subcommand, including `ls` and `kill`. It overrides the SSH port in
`~/.ssh/config`; when omitted, system SSH uses its usual configuration and
default port. This option is command-line only, with no `ssh_port` TOML setting.

To specify the server's TCP listening port from the client:

```sh
thther -t user@host --port 62000
thther -t user@host attach <id> --port 62000
thther -t user@host ls --port 62000
```

`--port` works before or after any client subcommand, including `kill`. It must
be between 1 and 65535 and does not change the SSH port (use `--ssh-port` or
`~/.ssh/config` for that). A fixed port is used exactly: if binding fails, the daemon
reports an error instead of selecting another port.

Both machines can have their own `~/.thther/config.toml`. For a **new daemon**,
the priority is: client `--port`, client config `port`, server config `port`,
then server config `port_range` (default `[60000, 61000]`). The client forwards
its chosen port over SSH without modifying the server's configuration. A
client config `port` also applies when `-t` selects another host; override it
with `--port` if needed. Client `port_range` is not forwarded to the server.

All sessions for a server user share one daemon and one TCP port. If the daemon
is already running, a client-specified port must match its actual port;
otherwise the command fails before changing any sessions or keys. Without a
client-specified port, commands use the existing daemon's port. Server config
changes only take effect at daemon startup. To change a running daemon's port,
finish any work in its sessions, stop that user's `thther __daemon` process,
then create a new session with the desired port. Stopping the daemon ends its
sessions; thther does not automatically restart it or migrate sessions.

An older daemon may need to be upgraded and manually restarted before it can
accept port-constrained requests. Startup errors include the server log path
(`~/.thther/daemon.log`), which contains details such as a port already in use.
Invalid server configuration is reported instead of silently using defaults.

Open the fixed `port`, or the ports the daemon may choose from `port_range`,
inbound on the server firewall.

## Use

```
thther               # create a new session and attach
thther attach <id>   # reattach to a detached session
thther ls            # list sessions on the configured host
thther kill <id>     # terminate a session
```

`-t user@host` works with every one of these, before or after the subcommand,
and overrides `ssh_target` from the config file:

```
thther -t user@host
thther -t user@host ls
thther -t user@host attach <id>
thther kill <id> -t user@host
```

Inside a session, press `Ctrl-\` then `d` to detach (the session keeps running).

## Verify (end-to-end)

Run `cargo test --locked` for protocol, replay, and connection regressions.
Tests cover bounded output frames, buffer eviction followed by repeated TCP
reconnects over a real PTY, interrupted writes/flushes, a terminal that replies
to color/cursor/mode queries, and rejection of incompatible daemons without
changing sessions or keys.

`ssh localhost` must work passwordless; copy the built binary to
`~/.thther/bin/thther-<version>`.
Two harnesses in the repo history / scratch exercise everything:

- interactive shell over an SSH-bootstrapped session; detach; `thther ls`;
  `thther attach`; `thther kill`
- reject concurrent attach while active; attach after detach rotates the PSK;
  old PSK and wrong PSK are rejected (AEAD auth)
- **in-process blip** (a TCP proxy cut mid-stream): the client auto-reconnects
  and every output line arrives **exactly once** (offset resume, no loss/dup)
- `SIGWINCH` resize propagates to the remote PTY

## Status

MVP. Server is Linux-only. Not yet: multi-client mirroring, idle timeout,
cross-server session persistence.
