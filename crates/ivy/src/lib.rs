//! Ivy sessions over a byte stream, usually a `TcpStream`.
//!
//! `connect` dials a peer whose key you know; `accept` answers a peer that
//! dialed you. Either gives a `Connection` that sends and receives
//! application messages, each a topic and a payload.

use ivy_core::{frame, frame_length, Initiator, Message, PeerKey, Responder, Session};
use rand_core::OsRng;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use ivy_core::{Config, ListenAddress, PeerMetadata, SessionError, MIN_FRAME_SIZE};

/// How long a handshake may take, as in Swift Ivy.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// An authenticated session on a stream.
///
/// `send` and `recv` are cancel-safe: a partly read frame or partly written
/// record is kept and resumed by the next call, so either may sit in a
/// `select!` or under a timeout.
pub struct Connection<S> {
    stream: S,
    session: Session,
    /// Bytes read and not yet taken as a frame.
    inbound: Vec<u8>,
    /// Framed records not yet written.
    outbound: Vec<u8>,
}

/// Opens a session with the peer at the other end of `stream`, which must
/// hold `expected`.
pub async fn connect<S>(stream: S, config: &Config, expected: PeerKey) -> io::Result<Connection<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timed(async move {
        let mut stream = stream;
        let limit = config.metadata.max_frame_size;
        let (initiator, hello) = Initiator::start(config, expected, &mut OsRng).map_err(refused)?;
        stream.write_all(&frame(&hello)).await?;
        let reply = read_frame(&mut stream, limit).await?;
        let (session, finish) = initiator.receive(&reply).map_err(refused)?;
        stream.write_all(&frame(&finish)).await?;
        Ok(Connection::new(stream, session))
    })
    .await
}

/// Answers the peer that dialed on `stream`. `accepts` decides whether this
/// node talks to the key the peer proves it holds.
pub async fn accept<S>(
    stream: S,
    config: &Config,
    accepts: impl FnOnce(&PeerKey) -> bool,
) -> io::Result<Connection<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timed(async move {
        let mut stream = stream;
        let limit = config.metadata.max_frame_size;
        let hello = read_frame(&mut stream, limit).await?;
        let (waiting, reply) = Responder::new(config)
            .receive(&hello, accepts, &mut OsRng)
            .map_err(refused)?;
        stream.write_all(&frame(&reply)).await?;
        let finish = read_frame(&mut stream, limit).await?;
        let session = waiting.receive(&finish).map_err(refused)?;
        Ok(Connection::new(stream, session))
    })
    .await
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    fn new(stream: S, session: Session) -> Self {
        Self {
            stream,
            session,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }

    /// The key the peer proved it holds.
    pub fn peer(&self) -> PeerKey {
        self.session.peer()
    }

    pub fn peer_metadata(&self) -> &PeerMetadata {
        self.session.peer_metadata()
    }

    /// Sends an application message. Once this is called the message is
    /// queued: if the call is cancelled, the next `send` or `recv` finishes
    /// writing it.
    pub async fn send(&mut self, topic: &str, payload: &[u8]) -> io::Result<()> {
        self.queue(&Message::PeerMessage {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
        })
        .map_err(refused)?;
        self.flush().await
    }

    /// The next application message. The peer's keepalive pings are
    /// answered while waiting, so a peer keeps the session only while
    /// something is waiting here.
    pub async fn recv(&mut self) -> io::Result<(String, Vec<u8>)> {
        loop {
            self.flush().await?;
            let Some(record) = self.take_frame()? else {
                self.read_more().await?;
                continue;
            };
            match self.session.open(&record).map_err(refused)? {
                Some(Message::PeerMessage { topic, payload }) => return Ok((topic, payload)),
                // A pong too large for the frames the peer accepts is not
                // sent; the session goes on, as in Swift Ivy.
                Some(Message::Ping(nonce)) => _ = self.queue(&Message::Pong(nonce)),
                Some(Message::Pong(_)) | None => {}
            }
        }
    }

    fn queue(&mut self, message: &Message) -> Result<(), SessionError> {
        let record = self.session.seal(message)?;
        self.outbound.extend_from_slice(&frame(&record));
        Ok(())
    }

    /// Writes queued records. Each write either lands or is not taken from
    /// the queue, so cancelling this loses nothing.
    async fn flush(&mut self) -> io::Result<()> {
        while !self.outbound.is_empty() {
            let written = self.stream.write(&self.outbound).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.outbound.drain(..written);
        }
        self.stream.flush().await
    }

    /// The next whole frame's record, if one has arrived.
    fn take_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(header) = self.inbound.first_chunk::<4>() else {
            return Ok(None);
        };
        let length =
            frame_length(*header, self.session.max_inbound_frame_size()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "frame length out of range")
            })?;
        if self.inbound.len() < 4 + length {
            return Ok(None);
        }
        let record = self.inbound[4..4 + length].to_vec();
        self.inbound.drain(..4 + length);
        Ok(Some(record))
    }

    /// Reads what has arrived. A read either lands in `inbound` or reads
    /// nothing, so cancelling this loses nothing.
    async fn read_more(&mut self) -> io::Result<()> {
        self.inbound.reserve(64 * 1024);
        if self.stream.read_buf(&mut self.inbound).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

/// One frame, during the handshake: `connect` and `accept` run whole or not
/// at all, so this need not survive cancellation.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_frame_size: u32,
) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = frame_length(header, max_frame_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame length out of range"))?;
    let mut record = vec![0; length];
    stream.read_exact(&mut record).await?;
    Ok(record)
}

fn refused(error: SessionError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("ivy session: {error:?}"),
    )
}

async fn timed<T>(handshake: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ivy handshake timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tokio::io::duplex;
    use tokio::time::timeout;

    fn config(byte: u8) -> Config {
        Config::new(SigningKey::from_bytes(&[byte; 32]))
    }

    #[tokio::test]
    async fn sessions_carry_messages_both_ways_and_answer_pings() {
        let (a, b) = (config(1), config(2));
        let (left, right) = duplex(1 << 16);
        let expected = b.peer_key();
        let (dialer, listener) =
            tokio::join!(connect(left, &a, expected), accept(right, &b, |_| true));
        let (mut dialer, mut listener) = (dialer.unwrap(), listener.unwrap());
        assert_eq!(dialer.peer(), b.peer_key());
        assert_eq!(listener.peer(), a.peer_key());

        let payload: Vec<u8> = (0..200_000).map(|i| i as u8).collect();
        let (received, ()) = tokio::join!(listener.recv(), async {
            dialer.queue(&Message::Ping(42)).unwrap();
            dialer.send("swap", &payload).await.unwrap();
            // The pong comes back before anything else the listener sends.
            let record = timeout(
                Duration::from_secs(5),
                read_frame(&mut dialer.stream, u32::MAX),
            )
            .await
            .expect("the listener answers the ping")
            .unwrap();
            assert_eq!(dialer.session.open(&record), Ok(Some(Message::Pong(42))));
        });
        assert_eq!(received.unwrap(), ("swap".to_owned(), payload));

        listener.send("reply", b"ok").await.unwrap();
        assert_eq!(
            dialer.recv().await.unwrap(),
            ("reply".to_owned(), b"ok".to_vec())
        );
    }

    #[tokio::test]
    async fn a_cancelled_recv_loses_nothing() {
        let (a, b) = (config(1), config(2));
        let (left, right) = duplex(1 << 16);
        let (dialer, listener) =
            tokio::join!(connect(left, &a, b.peer_key()), accept(right, &b, |_| true));
        let (mut dialer, mut listener) = (dialer.unwrap(), listener.unwrap());

        // Half of one frame arrives, and the recv waiting on it is cancelled.
        dialer
            .queue(&Message::PeerMessage {
                topic: "one".into(),
                payload: vec![1; 1000],
            })
            .unwrap();
        let first = std::mem::take(&mut dialer.outbound);
        dialer
            .stream
            .write_all(&first[..first.len() / 2])
            .await
            .unwrap();
        assert!(timeout(Duration::from_millis(50), listener.recv())
            .await
            .is_err());

        // Then the rest of it, and a second message.
        dialer
            .stream
            .write_all(&first[first.len() / 2..])
            .await
            .unwrap();
        dialer.send("two", b"2").await.unwrap();
        assert_eq!(
            listener.recv().await.unwrap(),
            ("one".to_owned(), vec![1; 1000])
        );
        assert_eq!(
            listener.recv().await.unwrap(),
            ("two".to_owned(), b"2".to_vec())
        );
    }

    #[tokio::test]
    async fn a_cancelled_send_is_finished_by_the_next_call() {
        let (a, b) = (config(1), config(2));
        // A pipe too small for the message, so the send has to wait.
        let (left, right) = duplex(1024);
        let (dialer, listener) =
            tokio::join!(connect(left, &a, b.peer_key()), accept(right, &b, |_| true));
        let (mut dialer, mut listener) = (dialer.unwrap(), listener.unwrap());

        let payload = vec![7; 100_000];
        assert!(
            timeout(Duration::from_millis(50), dialer.send("big", &payload))
                .await
                .is_err()
        );
        let (sent, received) = tokio::join!(dialer.send("after", b"x"), async {
            (
                listener.recv().await.unwrap(),
                listener.recv().await.unwrap(),
            )
        });
        sent.unwrap();
        assert_eq!(received.0, ("big".to_owned(), payload));
        assert_eq!(received.1, ("after".to_owned(), b"x".to_vec()));
    }

    #[tokio::test]
    async fn dialing_the_wrong_key_fails() {
        let (a, b, c) = (config(1), config(2), config(3));
        let (left, right) = duplex(1 << 16);
        let (dialer, listener) =
            tokio::join!(connect(left, &a, c.peer_key()), accept(right, &b, |_| true));
        assert!(listener.is_err());
        assert!(dialer.is_err());
    }
}
