use super::*;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;

const QUERIES: &[u8] = b"\x1b]10;?\x07\x1b]11;?\x1b\\\x1b[6n\x1b[?12$p";

const QUERY_REPLIES: [(&[u8], &[u8]); 4] = [
    (b"\x1b]10;?\x07", b"\x1b]10;rgb:cccc/dddd/eeee\x07"),
    (b"\x1b]11;?\x1b\\", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
    (b"\x1b[6n", b"\x1b[2;3R"),
    (b"\x1b[?12$p", b"\x1b[?12;2$y"),
];

struct ReplyingTerminal {
    output: Vec<u8>,
    replies: [usize; 4],
    input: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncWrite for ReplyingTerminal {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Deliberately split queries across stdout writes.
        let n = data.len().min(2);
        self.output.extend_from_slice(&data[..n]);
        for (i, (query, reply)) in QUERY_REPLIES.iter().enumerate() {
            let count = self
                .output
                .windows(query.len())
                .filter(|w| *w == *query)
                .count();
            for _ in self.replies[i]..count {
                self.input.send(reply.to_vec()).unwrap();
            }
            self.replies[i] = count;
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn reconnect_at_shell_prompt_does_not_generate_extra_terminal_replies() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let psk = [7; 32];
        let base = 1_000_000;
        let prompt = b"\r\nbash$ ";
        let first_end = base + (QUERIES.len() + prompt.len()) as u64;
        let server = tokio::spawn(async move {
            for connection in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let hello = handshake::server_recv(&mut socket).await.unwrap();
                assert_eq!(hello.offset, if connection == 0 { 0 } else { first_end });
                let nonce = handshake::random_nonce();
                handshake::server_send_ok(&mut socket, &nonce, first_end)
                    .await
                    .unwrap();
                let key = derive_key(&psk, &hello.client_nonce, &nonce);
                let mut opener = Opener::new(&key, DIR_CLIENT_TO_SERVER);
                let mut sealer = Sealer::new(&key, DIR_SERVER_TO_CLIENT);
                assert!(matches!(
                    read_frame(&mut socket, &mut opener).await.unwrap(),
                    Frame::Hello
                ));
                write_frame(&mut socket, &mut sealer, &Frame::Hello)
                    .await
                    .unwrap();
                if connection == 0 || connection == 3 {
                    let mut data = QUERIES.to_vec();
                    if connection == 0 {
                        data.extend_from_slice(prompt);
                    }
                    let offset = if connection == 0 { base } else { first_end };
                    write_frame(&mut socket, &mut sealer, &Frame::Output { offset, data })
                        .await
                        .unwrap();
                    let expected: Vec<u8> = QUERY_REPLIES
                        .iter()
                        .flat_map(|(_, reply)| reply.iter().copied())
                        .collect();
                    let mut replies = Vec::new();
                    while replies.len() < expected.len() {
                        if let Frame::Data(data) =
                            read_frame(&mut socket, &mut opener).await.unwrap()
                        {
                            replies.extend(data);
                        }
                    }
                    assert_eq!(replies, expected);
                }
                // Reconnects while sitting at the prompt must send no stale
                // query responses. Ping/Pong gives a deterministic barrier.
                write_frame(&mut socket, &mut sealer, &Frame::Ping)
                    .await
                    .unwrap();
                loop {
                    match read_frame(&mut socket, &mut opener).await.unwrap() {
                        Frame::Pong => break,
                        Frame::Data(data) => panic!("unexpected terminal input: {data:?}"),
                        _ => {}
                    }
                }
                if connection == 3 {
                    write_frame(&mut socket, &mut sealer, &Frame::Ended)
                        .await
                        .unwrap();
                }
                // Otherwise close TCP to exercise repeated connection cleanup.
            }
        });
        let (input, mut input_rx) = mpsc::unbounded_channel();
        let terminal = ReplyingTerminal {
            output: Vec::new(),
            replies: [0; 4],
            input,
        };
        let mut output = SessionOutput::new(terminal);
        let mut winch = signal(SignalKind::window_change()).unwrap();
        for connection in 0..4 {
            let outcome = connect_once(
                "127.0.0.1",
                port,
                "12345678",
                psk,
                &mut output,
                &mut input_rx,
                &mut winch,
            )
            .await
            .unwrap();
            assert_eq!(
                outcome,
                if connection == 3 {
                    Outcome::Ended
                } else {
                    Outcome::Disconnected
                }
            );
            assert_eq!(
                output.writer.replies,
                if connection == 3 { [2; 4] } else { [1; 4] }
            );
        }
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn overlaps_and_gaps_use_absolute_offsets() {
    let mut output = SessionOutput::new(Vec::new());
    output.accept(0, b"hello").await.unwrap();
    output.accept(0, b"hello").await.unwrap();
    output.accept(3, b"lo world").await.unwrap();
    assert_eq!(output.writer, b"hello world");
    assert_eq!(output.received.load(Ordering::SeqCst), 11);
    output.accept(20, b"!").await.unwrap();
    output.accept(20, b"!").await.unwrap();
    assert_eq!(
        output.writer,
        b"hello world\x18\r\n[thther] output gap: 9 bytes unavailable\r\n!"
    );
    assert_eq!(output.received.load(Ordering::SeqCst), 21);
    // A zero-capacity server can report a gap with no retained payload.
    output.accept(30, b"").await.unwrap();
    assert_eq!(output.received.load(Ordering::SeqCst), 30);
    output.accept(30, QUERIES).await.unwrap();
    assert!(output.writer.ends_with(QUERIES));
}

#[derive(Clone, Copy)]
enum GateAt {
    Write,
    Flush,
}

/// Models stdout accepting a partial write, or finishing the write but not
/// yet its flush. The test decides exactly when it may commit the output.
struct GatedWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
    at: GateAt,
    blocked: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    released: bool,
}

impl GatedWriter {
    fn gate(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.released {
            return Poll::Ready(Ok(()));
        }
        if let Some(blocked) = self.blocked.take() {
            let _ = blocked.send(());
        }
        match Pin::new(&mut self.release).poll(cx) {
            Poll::Ready(_) => {
                self.released = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GatedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = self.bytes.lock().unwrap().len();
        if matches!(self.at, GateAt::Write) && written >= 3 {
            std::task::ready!(self.gate(cx))?;
        }
        let n = if written == 0 {
            buf.len().min(3)
        } else {
            buf.len()
        };
        self.bytes.lock().unwrap().extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.at, GateAt::Flush) {
            self.gate(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stopping_reader_finishes_partial_writes_and_flush_before_committing() {
    for at in [GateAt::Write, GateAt::Flush] {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let (blocked_tx, blocked_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let mut output = SessionOutput::new(GatedWriter {
            bytes: bytes.clone(),
            at,
            blocked: Some(blocked_tx),
            release: release_rx,
            released: false,
        });
        let received = output.received.clone();
        let (mut wire, reader) = tokio::io::duplex(4096);
        let (stop_tx, stop_rx) = oneshot::channel();
        let (pong_tx, _pong_rx) = mpsc::channel(8);
        let key = [9; 32];
        let mut task = tokio::spawn(async move {
            let result = client_reader(
                reader,
                Opener::new(&key, DIR_SERVER_TO_CLIENT),
                &mut output,
                pong_tx,
                stop_rx,
            )
            .await;
            (result, output)
        });
        write_frame(
            &mut wire,
            &mut Sealer::new(&key, DIR_SERVER_TO_CLIENT),
            &Frame::Output {
                offset: 0,
                data: QUERIES.to_vec(),
            },
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(2), blocked_rx)
            .await
            .unwrap()
            .unwrap();
        stop_tx.send(()).unwrap();
        assert!(timeout(Duration::from_millis(20), &mut task).await.is_err());
        assert_eq!(received.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
        let (result, mut output) = timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap(), Outcome::Disconnected);
        assert_eq!(received.load(Ordering::SeqCst), QUERIES.len() as u64);
        assert_eq!(*bytes.lock().unwrap(), QUERIES);
        // Even an overlapping retransmission must not trigger the queries again.
        output.accept(0, QUERIES).await.unwrap();
        assert_eq!(*bytes.lock().unwrap(), QUERIES);
    }
}

struct FailingWriter {
    flush: bool,
}
impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.flush {
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stdout_errors_are_fatal_and_never_commit_the_frame() {
    for flush in [false, true] {
        let mut output = SessionOutput::new(FailingWriter { flush });
        let error = output.accept(0, QUERIES).await.unwrap_err();
        assert!(error.is::<FatalSessionError>());
        assert_eq!(output.received.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_truncated_encrypted_frame_never_reaches_stdout() {
    let key = [6; 32];
    let mut wire = Vec::new();
    write_frame(
        &mut wire,
        &mut Sealer::new(&key, DIR_SERVER_TO_CLIENT),
        &Frame::Output {
            offset: 0,
            data: QUERIES.to_vec(),
        },
    )
    .await
    .unwrap();
    wire.truncate(wire.len() - 3);
    let mut output = SessionOutput::new(Vec::new());
    let (_stop_tx, stop_rx) = oneshot::channel();
    let (pong_tx, _pong_rx) = mpsc::channel(8);
    let outcome = client_reader(
        wire.as_slice(),
        Opener::new(&key, DIR_SERVER_TO_CLIENT),
        &mut output,
        pong_tx,
        stop_rx,
    )
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Disconnected);
    assert!(output.writer.is_empty());
    assert_eq!(output.received.load(Ordering::SeqCst), 0);
}

/// Complete an actual encrypted connection, keeping the peer alive until the
/// test releases it. This also exercises connect_once's cooperative cleanup.
async fn mock_server(listener: TcpListener, psk: [u8; 32], done: oneshot::Receiver<()>) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let hello = handshake::server_recv(&mut socket).await.unwrap();
    let nonce = handshake::random_nonce();
    handshake::server_send_ok(&mut socket, &nonce, QUERIES.len() as u64)
        .await
        .unwrap();
    let key = derive_key(&psk, &hello.client_nonce, &nonce);
    let mut opener = Opener::new(&key, DIR_CLIENT_TO_SERVER);
    let mut sealer = Sealer::new(&key, DIR_SERVER_TO_CLIENT);
    assert!(matches!(
        read_frame(&mut socket, &mut opener).await.unwrap(),
        Frame::Hello
    ));
    write_frame(&mut socket, &mut sealer, &Frame::Hello)
        .await
        .unwrap();
    write_frame(
        &mut socket,
        &mut sealer,
        &Frame::Output {
            offset: 0,
            data: QUERIES.to_vec(),
        },
    )
    .await
    .unwrap();
    let _ = done.await;
}

#[tokio::test]
async fn detach_waits_for_output_commit_before_returning() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let psk = [3; 32];
    let (done_tx, done_rx) = oneshot::channel();
    let server = tokio::spawn(mock_server(listener, psk, done_rx));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (blocked_tx, blocked_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let mut output = SessionOutput::new(GatedWriter {
        bytes: bytes.clone(),
        at: GateAt::Flush,
        blocked: Some(blocked_tx),
        release: release_rx,
        released: false,
    });
    let received = output.received.clone();
    let (input_tx, mut input_rx) = mpsc::unbounded_channel();
    let mut client = tokio::spawn(async move {
        let mut winch = signal(SignalKind::window_change()).unwrap();
        connect_once(
            "127.0.0.1",
            port,
            "12345678",
            psk,
            &mut output,
            &mut input_rx,
            &mut winch,
        )
        .await
    });
    timeout(Duration::from_secs(2), blocked_rx)
        .await
        .unwrap()
        .unwrap();
    input_tx.send(vec![DETACH_PREFIX, DETACH_KEY]).unwrap();
    assert!(timeout(Duration::from_millis(20), &mut client)
        .await
        .is_err());
    assert_eq!(received.load(Ordering::SeqCst), 0);
    release_tx.send(()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), client)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Outcome::Detached
    );
    assert_eq!(received.load(Ordering::SeqCst), QUERIES.len() as u64);
    assert_eq!(*bytes.lock().unwrap(), QUERIES);
    let _ = done_tx.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn input_preserves_queries_keys_and_paste_with_split_detach_prefix() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(("127.0.0.1", port));
    let (client, server) = tokio::join!(client, listener.accept());
    let (_, mut writer) = client.unwrap().into_split();
    let (mut reader, _) = server.unwrap().0.into_split();
    let key = [4; 32];
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (_pong_tx, mut pong_rx) = mpsc::channel(8);
    let mut winch = signal(SignalKind::window_change()).unwrap();
    let mut sealer = Sealer::new(&key, DIR_CLIENT_TO_SERVER);
    let mut opener = Opener::new(&key, DIR_CLIENT_TO_SERVER);
    let bytes =
        b"\x1b[A\x1b[200~echo hello\x1b[201~\x1b]10;rgb:ffff/ffff/ffff\x07\x1b[2;3R\x1b[?12;2$y";
    let writer_task = client_writer(
        &mut writer,
        &mut sealer,
        &mut rx,
        &mut winch,
        &mut pong_rx,
        Arc::new(AtomicU64::new(0)),
    );
    let peer = async {
        tx.send(bytes.to_vec()).unwrap();
        loop {
            if let Frame::Data(data) = read_frame(&mut reader, &mut opener).await.unwrap() {
                assert_eq!(data, bytes);
                break;
            }
        }
        tx.send(vec![DETACH_PREFIX]).unwrap();
        tx.send(vec![DETACH_KEY]).unwrap();
    };
    let (outcome, ()) = timeout(Duration::from_secs(2), async {
        tokio::join!(writer_task, peer)
    })
    .await
    .unwrap();
    assert_eq!(outcome, Outcome::Detached);
}
