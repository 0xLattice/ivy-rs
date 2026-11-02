//! Ivy byte streams over WebSockets. Binary message boundaries carry no meaning:
//! reads concatenate payloads, and writes split them into at most 64 KiB messages.
//! HTTP upgrades and TLS peer verification finish before Ivy authenticates keys.
use futures_util::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::{
    tungstenite::{
        self,
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};
pub const MAX_OUTBOUND_FRAME: usize = 64 * 1024;
pub const MAX_INBOUND_MESSAGE: usize = 1024 * 1024;
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);
fn settings() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(MAX_OUTBOUND_FRAME)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * MAX_OUTBOUND_FRAME + 1024)
        .max_message_size(Some(MAX_INBOUND_MESSAGE))
        .max_frame_size(Some(MAX_INBOUND_MESSAGE))
}
fn error(error: tungstenite::Error) -> io::Error {
    match error {
        tungstenite::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}
pub struct WebSocketByteStream<S> {
    socket: WebSocketStream<S>,
    pending: Vec<u8>,
    offset: usize,
    closed: bool,
}
pub type ClientStream = WebSocketByteStream<MaybeTlsStream<TcpStream>>;
impl<S> WebSocketByteStream<S> {
    fn new(socket: WebSocketStream<S>) -> Self {
        Self {
            socket,
            pending: vec![],
            offset: 0,
            closed: false,
        }
    }
}
/// Opens ws:// or wss://. WSS validates the certificate against WebPKI roots.
pub async fn connect(url: &str) -> io::Result<ClientStream> {
    let (socket, _) = timeout(
        UPGRADE_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(url, Some(settings()), true),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket upgrade timed out"))?
    .map_err(error)?;
    Ok(WebSocketByteStream::new(socket))
}
/// Accepts only upgrades for `path` (usually `/ivy`). The transport never trusts
/// forwarding headers; callers retain the observed address of their TCP peer.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    path: &str,
) -> io::Result<WebSocketByteStream<S>> {
    let expected = path.to_owned();
    #[allow(clippy::result_large_err)]
    let callback = move |request: &Request, response: Response| {
        if request.uri().path() == expected {
            Ok(response)
        } else {
            Err(tungstenite::http::Response::builder()
                .status(404)
                .body(Some("not found".into()))
                .expect("valid HTTP response"))
        }
    };
    let socket = timeout(
        UPGRADE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(settings())),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "WebSocket upgrade timed out"))?
    .map_err(error)?;
    Ok(WebSocketByteStream::new(socket))
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if this.offset < this.pending.len() {
                let count = output.remaining().min(this.pending.len() - this.offset);
                output.put_slice(&this.pending[this.offset..this.offset + count]);
                this.offset += count;
                if this.offset == this.pending.len() {
                    this.pending.clear();
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => {
                    this.pending = bytes.to_vec();
                    this.offset = 0;
                }
                Some(Ok(Message::Ping(_))) => match Pin::new(&mut this.socket).poll_flush(cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(error(e))),
                    Poll::Pending => return Poll::Pending,
                    _ => {}
                },
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    this.closed = true;
                }
                Some(Ok(_)) => {
                    this.closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Ivy requires binary WebSocket messages",
                    )));
                }
                Some(Err(e)) => {
                    this.closed = true;
                    return Poll::Ready(Err(error(e)));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket is closed",
            )));
        }
        std::task::ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(error)?;
        let count = bytes.len().min(MAX_OUTBOUND_FRAME);
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut this.socket)
            .start_send(Message::Binary(bytes[..count].to_vec().into()))
            .map_err(error)?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(error)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(error)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    #[tokio::test]
    async fn supplied_websocket_drives_full_node_and_flushes_large_records() {
        use ivy::node::{SuppliedDirection, SuppliedStream};
        use ivy_core::core::{CoreSettings, Effect, Event, Request, RequestResult};
        use tokio::sync::mpsc;
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_config =
                ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
            let server_key = server_config.peer_key();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let websocket = accept(tcp, "/ivy").await.unwrap();
                let mut peer = ivy::accept(websocket, &server_config, |_| true)
                    .await
                    .unwrap();
                let (topic, payload) = peer.recv().await.unwrap();
                assert_eq!(topic, "large");
                peer.send("echo", &payload).await.unwrap();
                // Keep the stream alive until the client acknowledges delivery.
                let _ = peer.recv().await;
            });
            let (commands, rx) = mpsc::channel(32);
            let (notifications, mut effects) = mpsc::channel(32);
            let (streams, incoming) = mpsc::channel(1);
            let node = tokio::spawn(ivy::node::run_with_supplied(
                TcpListener::bind("127.0.0.1:0").await.unwrap(),
                ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[2; 32])),
                CoreSettings::default(),
                rx,
                notifications,
                Some(incoming),
                ivy_core::NullLedger,
            ));
            streams
                .send(SuppliedStream {
                    stream: Box::new(connect(&format!("ws://{address}/ivy")).await.unwrap()),
                    direction: SuppliedDirection::Connect {
                        request: 99,
                        endpoint: ivy_core::PeerEndpoint {
                            public_key: server_key.hex(),
                            host: "127.0.0.1".into(),
                            port: address.port(),
                        },
                    },
                    observed_host: Some("127.0.0.1".into()),
                })
                .await
                .unwrap();
            let mut connected = false;
            loop {
                match effects.recv().await.unwrap() {
                    Effect::PeerConnected(token, peer) => {
                        assert_eq!(peer.key, server_key);
                        commands.send(Event::Delivered(token)).await.unwrap();
                        commands
                            .send(Event::Request(
                                100,
                                Request::Send {
                                    peer: peer.key,
                                    session_id: Some(peer.session_id),
                                    message: ivy_core::Message::PeerMessage {
                                        topic: "large".into(),
                                        payload: vec![42; 200_000],
                                    },
                                },
                            ))
                            .await
                            .unwrap();
                    }
                    Effect::Completed(99, RequestResult::Connected) => connected = true,
                    Effect::Deliver(
                        token,
                        peer,
                        ivy_core::Message::PeerMessage { topic, payload },
                    ) => {
                        assert!(connected);
                        assert_eq!(peer.key, server_key);
                        assert_eq!(topic, "echo");
                        assert_eq!(payload, vec![42; 200_000]);
                        commands.send(Event::Delivered(token)).await.unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            commands.send(Event::Stop).await.unwrap();
            node.await.unwrap().unwrap();
            server.await.unwrap();
        })
        .await
        .expect("full node WebSocket exchange timed out");
    }
    #[tokio::test]
    async fn ivy_authentication_and_large_records_cross_binary_message_boundaries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_config = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        let server_key = server_config.peer_key();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let websocket = accept(tcp, "/ivy").await.unwrap();
            let mut ivy = ivy::accept(websocket, &server_config, |_| true)
                .await
                .unwrap();
            let (topic, bytes) = ivy.recv().await.unwrap();
            assert_eq!(topic, "large");
            assert_eq!(bytes.len(), 200_000);
            ivy.send("echo", &bytes).await.unwrap();
        });
        let websocket = connect(&format!("ws://{address}/ivy")).await.unwrap();
        let config = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[2; 32]));
        let mut ivy = ivy::connect(websocket, &config, server_key).await.unwrap();
        ivy.send("large", &vec![42; 200_000]).await.unwrap();
        let (topic, bytes) = ivy.recv().await.unwrap();
        assert_eq!(topic, "echo");
        assert_eq!(bytes, vec![42; 200_000]);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn controls_are_answered_and_text_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept(tcp, "/ivy").await.unwrap();
            let mut data = [0; 3];
            ws.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"abc");
            let error = ws.read_u8().await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        });
        let (mut raw, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ivy"))
            .await
            .unwrap();
        raw.send(Message::Ping(vec![1].into())).await.unwrap();
        raw.send(Message::Binary(b"abc".to_vec().into()))
            .await
            .unwrap();
        assert_eq!(
            raw.next().await.unwrap().unwrap(),
            Message::Pong(vec![1].into())
        );
        raw.send(Message::Text("not binary".into())).await.unwrap();
        server.await.unwrap();
    }
    #[tokio::test]
    async fn upgrade_path_is_checked() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(accept(tcp, "/ivy").await.is_err());
        });
        assert!(connect(&format!("ws://{address}/wrong")).await.is_err());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn one_write_is_split_into_bounded_messages() {
        let (a, b) = tokio::io::duplex(2 * MAX_OUTBOUND_FRAME + 1024);
        let server = tokio::spawn(async move {
            let mut ws = accept(a, "/ivy").await.unwrap();
            ws.write_all(&vec![7; MAX_OUTBOUND_FRAME + 1])
                .await
                .unwrap();
            ws.flush().await.unwrap();
        });
        let (mut raw, _) = tokio_tungstenite::client_async("ws://localhost/ivy", b)
            .await
            .unwrap();
        assert_eq!(raw.next().await.unwrap().unwrap().len(), MAX_OUTBOUND_FRAME);
        assert_eq!(raw.next().await.unwrap().unwrap().len(), 1);
        server.await.unwrap();
    }
}
