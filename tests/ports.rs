#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    root: PathBuf,
    daemon: Option<Child>,
    #[cfg(target_os = "linux")]
    detached_pid: Option<i32>,
}

impl Server {
    fn new(config: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "thther-port-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>(),
        ));
        fs::create_dir_all(root.join(".thther")).unwrap();
        fs::create_dir_all(root.join("run/thther")).unwrap();
        fs::write(root.join(".thther/config.toml"), config).unwrap();
        Self {
            root,
            daemon: None,
            #[cfg(target_os = "linux")]
            detached_pid: None,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_thther"));
        command
            .env("HOME", &self.root)
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("SHELL", "/bin/sh")
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null());
        command
    }

    fn socket(&self) -> PathBuf {
        self.root.join("run/thther/control.sock")
    }

    fn start(&mut self, port: Option<u16>) {
        let mut command = self.command();
        command.arg("__daemon");
        if let Some(port) = port {
            command.args(["--port", &port.to_string()]);
        }
        let log = fs::File::create(self.root.join("daemon-test.log")).unwrap();
        self.daemon = Some(command.stdout(Stdio::null()).stderr(log).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.daemon.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "daemon exited {status}: {}",
                    fs::read_to_string(self.root.join("daemon-test.log")).unwrap()
                );
            }
            if UnixStream::connect(self.socket()).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "daemon startup timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn agent(&self, args: &[&str]) -> Value {
        let output = self.command().arg("__serve").args(args).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn request(&self, request: Value) -> Value {
        let mut socket = UnixStream::connect(self.socket()).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        writeln!(socket, "{request}").unwrap();
        let mut response = String::new();
        BufReader::new(socket).read_line(&mut response).unwrap();
        serde_json::from_str(&response).unwrap()
    }

    #[cfg(target_os = "linux")]
    fn track_detached_daemon(&mut self) {
        use std::os::fd::AsRawFd;
        let socket = UnixStream::connect(self.socket()).unwrap();
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&cred) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert!(cred.pid > 0);
        self.detached_pid = Some(cred.pid);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.as_mut() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
        #[cfg(target_os = "linux")]
        if let Some(pid) = self.detached_pid {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn available_port() -> u16 {
    TcpListener::bind(("0.0.0.0", 0)).unwrap().local_addr().unwrap().port()
}

#[test]
fn server_config_and_cli_choose_the_listener() {
    for cli_override in [false, true] {
        let occupied = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let wanted = available_port();
        let configured = if cli_override { occupied_port } else { wanted };
        let mut server = Server::new(&format!(
            "port = {configured}\nport_range = [{occupied_port}, {occupied_port}]"
        ));
        server.start(cli_override.then_some(wanted));
        assert!(TcpStream::connect(("127.0.0.1", wanted)).is_ok());
        let port = wanted.to_string();
        let created = server.agent(&["create", "--cols", "80", "--rows", "24", "--port", &port]);
        assert_eq!(created["bootstrap"]["port"], wanted, "{created}");
        let id = created["bootstrap"]["id"].as_str().unwrap();
        assert_eq!(
            server.agent(&["ls", "--port", &port])["ls"]["sessions"].as_array().unwrap().len(),
            1
        );
        assert_eq!(server.agent(&["attach", id, "--port", &port])["bootstrap"]["port"], wanted);
        // Legacy requests still use the same listener and sessions.
        assert_eq!(
            server.request(json!({"op": "ls"}))["ls"]["sessions"].as_array().unwrap().len(),
            1
        );
        assert_eq!(server.agent(&["kill", id, "--port", &port]), json!("ok"));
    }
}

#[test]
fn port_range_remains_supported_without_a_fixed_port() {
    let wanted = available_port();
    let mut server = Server::new(&format!("port_range = [{wanted}, {wanted}]"));
    server.start(None);
    let created = server.agent(&["create", "--cols", "80", "--rows", "24"]);
    assert_eq!(created["bootstrap"]["port"], wanted, "{created}");
    assert_eq!(server.agent(&["kill", created["bootstrap"]["id"].as_str().unwrap()]), json!("ok"));
}

#[test]
fn wrong_port_requests_leave_the_running_daemon_intact() {
    let wanted = available_port();
    let mut server = Server::new("");
    server.start(Some(wanted));
    let created = server.agent(&["create", "--cols", "80", "--rows", "24"]);
    let id = created["bootstrap"]["id"].as_str().unwrap();
    let wrong = if wanted == 65535 { wanted - 1 } else { wanted + 1 }.to_string();
    for args in [
        vec!["create", "--cols", "80", "--rows", "24"],
        vec!["attach", id],
        vec!["ls"],
        vec!["kill", id],
    ] {
        let mut args = args;
        args.extend(["--port", &wrong]);
        let response = server.agent(&args);
        let error = response["err"]["message"].as_str().unwrap();
        assert!(error.contains(&wanted.to_string()) && error.contains(&wrong), "{error}");
        let listed = server.agent(&["ls"]);
        assert_eq!(listed["ls"]["sessions"].as_array().unwrap().len(), 1);
        assert_eq!(listed["ls"]["sessions"][0]["id"], id);
    }
    assert_eq!(server.agent(&["kill", id]), json!("ok"));
}

#[test]
fn startup_failure_reports_port_and_server_log() {
    let occupied = TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let port = occupied.local_addr().unwrap().port().to_string();
    let server = Server::new("");
    let response = server.agent(&["create", "--cols", "80", "--rows", "24", "--port", &port]);
    let error = response["err"]["message"].as_str().unwrap();
    assert!(error.contains(&port) && error.contains("daemon.log"), "{error}");
    let log = fs::read_to_string(server.root.join(".thther/daemon.log")).unwrap();
    assert!(log.contains(&format!("bind TCP port {port}")), "{log}");
    assert!(UnixStream::connect(server.socket()).is_err());
}

#[test]
fn malformed_server_config_is_not_ignored() {
    let server = Server::new("port = 0");
    let response = server.agent(&["create", "--cols", "80", "--rows", "24"]);
    let error = response["err"]["message"].as_str().unwrap();
    assert!(error.contains("config.toml"), "{error}");
    let output = server.command().arg("__daemon").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("config.toml"));
    assert!(UnixStream::connect(server.socket()).is_err());
}

#[test]
fn older_daemon_rejection_does_not_retry_or_spawn() {
    let server = Server::new("");
    let listener = UnixListener::bind(server.socket()).unwrap();
    let old_daemon = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut line = String::new();
        BufReader::new(socket).read_line(&mut line).unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["op"], "on_port");
        assert_eq!(request["request"]["op"], "create");
        // Old daemons close the connection on an unknown operation.
        listener
    });
    let response = server.agent(&["create", "--cols", "80", "--rows", "24", "--port", "62000"]);
    let listener = old_daemon.join().unwrap();
    let error = response["err"]["message"].as_str().unwrap();
    assert!(error.contains("older version") && error.contains("manually restart"), "{error}");
    assert!(!server.root.join(".thther/daemon.log").exists());
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn client_forwards_configured_port_and_cli_override_over_ssh() {
    let client = Server::new("ssh_target = 'configured-host'\nport = 62000");
    let bin = client.root.join("bin");
    fs::create_dir(&bin).unwrap();
    let ssh = bin.join("ssh");
    fs::write(&ssh, "#!/bin/sh\ncat > /dev/null\nprintf '%s\\n' \"$@\" > \"$THTHER_TEST_SSH_ARGS\"\nprintf '%s\\n' '{\"ls\":{\"sessions\":[]}}'\n").unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    let path = std::env::join_paths(paths).unwrap();
    for (args, expected) in [
        (vec!["-t", "other-host", "ls"], "62000"),
        (vec!["-t", "other-host", "ls", "--port", "62001"], "62001"),
    ] {
        let args_file = client.root.join("ssh-args");
        let output = client
            .command()
            .args(args)
            .env("PATH", &path)
            .env("THTHER_TEST_SSH_ARGS", &args_file)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let forwarded = fs::read_to_string(args_file).unwrap();
        let forwarded: Vec<_> = forwarded.lines().collect();
        assert_eq!(&forwarded[..4], ["-T", "-o", "BatchMode=yes", "other-host"]);
        assert_eq!(
            &forwarded[4..],
            ["sh", "-s", "--", env!("CARGO_PKG_VERSION"), "--port", expected, "__serve", "ls"]
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn agent_starts_a_detached_daemon_on_the_requested_port() {
    let occupied = TcpListener::bind(("0.0.0.0", 0)).unwrap();
    let configured = occupied.local_addr().unwrap().port();
    let wanted = available_port();
    let mut server = Server::new(&format!("port = {configured}"));
    let response =
        server.agent(&["create", "--cols", "80", "--rows", "24", "--port", &wanted.to_string()]);
    // Track the daemon before assertions so failures still clean up its process.
    if UnixStream::connect(server.socket()).is_ok() {
        server.track_detached_daemon();
    }
    assert_eq!(response["bootstrap"]["port"], wanted, "{response}");
    assert!(TcpStream::connect(("127.0.0.1", wanted)).is_ok());
    let id = response["bootstrap"]["id"].as_str().unwrap();
    assert_eq!(server.agent(&["kill", id]), json!("ok"));
}

#[cfg(target_os = "linux")]
#[test]
fn simultaneous_starts_share_one_daemon_and_reject_the_other_port() {
    let mut server = Server::new("");
    let first_port = available_port();
    let mut second_port = available_port();
    while second_port == first_port {
        second_port = available_port();
    }
    let mut agents = Vec::new();
    for port in [first_port, second_port] {
        agents.push(
            server
                .command()
                .args([
                    "__serve",
                    "create",
                    "--cols",
                    "80",
                    "--rows",
                    "24",
                    "--port",
                    &port.to_string(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let responses: Vec<Value> = agents
        .into_iter()
        .map(|agent| {
            let output = agent.wait_with_output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            serde_json::from_slice(&output.stdout).unwrap()
        })
        .collect();
    if UnixStream::connect(server.socket()).is_ok() {
        server.track_detached_daemon();
    }
    assert_eq!(
        responses.iter().filter(|r| r.get("bootstrap").is_some()).count(),
        1,
        "{responses:?}"
    );
    let rejected = responses.iter().find_map(|r| r["err"]["message"].as_str()).unwrap();
    assert!(
        rejected.contains(&first_port.to_string()) && rejected.contains(&second_port.to_string()),
        "{rejected}"
    );
    let listed = server.agent(&["ls"]);
    assert_eq!(listed["ls"]["sessions"].as_array().unwrap().len(), 1);
    let id = listed["ls"]["sessions"][0]["id"].as_str().unwrap();
    assert_eq!(server.agent(&["kill", id]), json!("ok"));
}
