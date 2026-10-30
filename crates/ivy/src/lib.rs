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

pub use ivy_core::{Config, ListenAddress, PeerMetadata, SessionError};

/// How long a handshake may take, as in Swift Ivy.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// An authenticated session on a stream.
pub struct Connection<S> {
    stream: S,
    session: Session,
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
        Ok(Connection { stream, session })
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
        Ok(Connection { stream, session })
    })
    .await
}

impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// The key the peer proved it holds.
    pub fn peer(&self) -> PeerKey {
        self.session.peer()
    }

    pub fn peer_metadata(&self) -> &PeerMetadata {
        self.session.peer_metadata()
    }

    pub async fn send(&mut self, topic: &str, payload: &[u8]) -> io::Result<()> {
        self.write(&Message::PeerMessage {
            topic: topic.to_owned(),
            payload: payload.to_vec(),
        })
        .await
    }

    /// The next application message. The peer's keepalive pings are
    /// answered while waiting, so a peer keeps the session only while
    /// something is waiting here.
    pub async fn recv(&mut self) -> io::Result<(String, Vec<u8>)> {
        loop {
            let record =
                read_frame(&mut self.stream, self.session.max_inbound_frame_size()).await?;
            match self.session.open(&record).map_err(refused)? {
                Some(Message::PeerMessage { topic, payload }) => return Ok((topic, payload)),
                Some(Message::Ping(nonce)) => self.write(&Message::Pong(nonce)).await?,
                Some(Message::Pong(_)) | None => {}
            }
        }
    }

    async fn write(&mut self, message: &Message) -> io::Result<()> {
        let record = self.session.seal(message).map_err(refused)?;
        self.stream.write_all(&frame(&record)).await
    }
}

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
            dialer.write(&Message::Ping(42)).await.unwrap();
            dialer.send("swap", &payload).await.unwrap();
            // The pong comes back before anything else the listener sends.
            let record = read_frame(&mut dialer.stream, u32::MAX).await.unwrap();
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
    async fn dialing_the_wrong_key_fails() {
        let (a, b, c) = (config(1), config(2), config(3));
        let (left, right) = duplex(1 << 16);
        let (dialer, listener) =
            tokio::join!(connect(left, &a, c.peer_key()), accept(right, &b, |_| true));
        assert!(listener.is_err());
        assert!(dialer.is_err());
    }
}
