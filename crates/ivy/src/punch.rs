//! IPv4 TCP simultaneous open. The caller exchanges candidates over an already
//! authenticated session and controls whether private addresses are allowed.
use ivy_core::punch::Candidate;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout_at, Instant},
};
/// One attempt owns a listening port. Dropping it closes all unclaimed sockets;
/// a returned stream is independent and must still authenticate the expected key.
pub struct TcpPunch {
    accepted: mpsc::Receiver<io::Result<(TcpStream, SocketAddr)>>,
    acceptor: JoinHandle<()>,
    port: u16,
}
fn socket() -> io::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    Ok(socket)
}
impl TcpPunch {
    pub async fn prepare() -> io::Result<Self> {
        let socket = socket()?;
        socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
        let listener = socket.listen(4)?;
        let port = listener.local_addr()?.port();
        let (sender, accepted) = mpsc::channel(4);
        let acceptor = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok(stream) => {
                        // Before candidates arrive, retain at most four accepted
                        // streams. Excess streams close immediately, matching Swift.
                        match sender.try_send(Ok(stream)) {
                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
        Ok(Self {
            accepted,
            acceptor,
            port,
        })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Consumes the attempt, retaining only the winning connection. Host names
    /// and IPv6 are not TCP punch candidates. Private destinations require an
    /// explicit opt-in; filtering occurs before any socket is dialled.
    pub async fn connect(
        mut self,
        candidates: &[Candidate],
        allow_private: bool,
        deadline: Instant,
    ) -> io::Result<TcpStream> {
        let targets: Vec<_> = candidates
            .iter()
            .take(ivy_core::punch::MAX_CANDIDATES)
            .filter(|c| {
                c.transport == Candidate::TCP
                    && c.port != 0
                    && (allow_private || ivy_core::is_globally_routable(&c.host))
            })
            .filter_map(|c| {
                c.host
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|host| SocketAddr::V4(SocketAddrV4::new(host, c.port)))
            })
            .collect();
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no permitted IPv4 TCP candidates",
            ));
        }
        let port = self.port;
        let dial = async {
            loop {
                for target in &targets {
                    let socket = socket()?;
                    socket.bind(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::UNSPECIFIED,
                        port,
                    )))?;
                    let until = deadline.min(Instant::now() + Duration::from_millis(1500));
                    if let Ok(Ok(stream)) = timeout_at(until, socket.connect(*target)).await {
                        return Ok(stream);
                    }
                }
                sleep(Duration::from_millis(100)).await;
            }
        };
        let accept = async {
            loop {
                let (stream, address) = self.accepted.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "TCP punch listener stopped")
                })??;
                if targets.iter().any(|t| t.ip() == address.ip()) {
                    return Ok(stream);
                }
            }
        };
        timeout_at(deadline, async {
            tokio::select! {stream=dial=>stream,stream=accept=>stream}
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP punch deadline expired"))?
    }
}
impl Drop for TcpPunch {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn simultaneous_open_preserves_announced_ports_and_returns_ordered_stream() {
        let a = TcpPunch::prepare().await.unwrap();
        let b = TcpPunch::prepare().await.unwrap();
        let ap = a.port();
        let bp = b.port();
        let deadline = Instant::now() + Duration::from_secs(3);
        let ac = [Candidate {
            transport: 1,
            host: "127.0.0.1".into(),
            port: bp,
        }];
        let bc = [Candidate {
            transport: 1,
            host: "127.0.0.1".into(),
            port: ap,
        }];
        let (a, b) = tokio::join!(
            a.connect(&ac, true, deadline),
            b.connect(&bc, true, deadline)
        );
        let mut a = a.unwrap();
        let mut b = b.unwrap();
        assert_eq!(a.local_addr().unwrap().port(), ap);
        assert_eq!(b.local_addr().unwrap().port(), bp);
        assert_eq!(a.peer_addr().unwrap().port(), bp);
        assert_eq!(b.peer_addr().unwrap().port(), ap);
        a.write_all(b"punch").await.unwrap();
        let mut received = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), b.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"punch");
    }
    #[tokio::test]
    async fn private_candidates_require_explicit_permission() {
        let attempt = TcpPunch::prepare().await.unwrap();
        let result = attempt
            .connect(
                &[Candidate {
                    transport: 1,
                    host: "127.0.0.1".into(),
                    port: 9,
                }],
                false,
                Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
    #[tokio::test]
    async fn precandidate_acceptance_keeps_four_streams_and_closes_overflow() {
        let attempt = TcpPunch::prepare().await.unwrap();
        let address = (Ipv4Addr::LOCALHOST, attempt.port());
        let mut retained = vec![];
        for _ in 0..4 {
            retained.push(TcpStream::connect(address).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while attempt.accepted.len() < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut overflow = TcpStream::connect(address).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), overflow.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(attempt);
        for mut stream in retained {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
}
