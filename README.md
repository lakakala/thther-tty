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

`thther` gives you: pure TCP, auto-reconnect on blips (exact resume, no loss or
duplication), and reattach after the client process fully exits.

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
  resumes from the client's received byte offset (no loss/dup). A fresh
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

each with a `.sha256` checksum. Linux builds require glibc ≥ 2.35 (Ubuntu
22.04, Debian 12, RHEL 10 or newer); on older systems build from source.

### Build from source

```
cargo build --release      # -> target/release/thther
```

### Server

The server needs no manual install. The client always runs
`~/.thther/bin/thther-<version>` on the server, where `<version>` is the
client's own version — a `thther` on the server's `PATH` is never used, so both
ends always match. If that file is missing, the server downloads the matching
release binary (checksum-verified) on first connect. This needs Linux
x86_64/aarch64, `curl` or `wget`, and access to github.com.

Without GitHub access, copy the right binary to
`~/.thther/bin/thther-<version>` on the server yourself and `chmod +x` it.

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
port_range = [60000, 61000]   # server: daemon binds one free port in this range (open it in the firewall)
ring_bytes = 262144           # per-session replay buffer
```

Open (at least one port of) `port_range` inbound on the server firewall.

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
