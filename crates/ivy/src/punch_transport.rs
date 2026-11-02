//! Pluggable ordered-stream punch transports. Prepared attempts own their
//! resources; cancellation drops the future/attempt and never leaks a socket.
use crate::{node::TransportStream, punch::TcpPunch};
use ivy_core::punch::Candidate;
use std::{future::Future, io, pin::Pin};
use tokio::time::Instant;
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;
pub struct PunchedStream {
    pub stream: Box<dyn TransportStream>,
    pub observed_host: Option<String>,
    pub local_host: Option<String>,
}
pub trait PreparedPunch: Send {
    fn candidates(&self) -> Vec<Candidate>;
    fn connect(
        self: Box<Self>,
        candidates: Vec<Candidate>,
        allow_private: bool,
        deadline: Instant,
    ) -> TransportFuture<'static, PunchedStream>;
}
pub trait PunchTransport: Send + Sync {
    fn prepare(&self, hosts: Vec<String>) -> TransportFuture<'_, Box<dyn PreparedPunch>>;
}
#[derive(Default)]
pub struct TcpPunchTransport;
struct PreparedTcp {
    attempt: TcpPunch,
    candidates: Vec<Candidate>,
}
impl PunchTransport for TcpPunchTransport {
    fn prepare(&self, hosts: Vec<String>) -> TransportFuture<'_, Box<dyn PreparedPunch>> {
        Box::pin(async move {
            let attempt = TcpPunch::prepare().await?;
            let candidates = hosts
                .into_iter()
                .take(ivy_core::punch::MAX_CANDIDATES)
                .map(|host| Candidate {
                    transport: Candidate::TCP,
                    host,
                    port: attempt.port(),
                })
                .collect();
            Ok(Box::new(PreparedTcp {
                attempt,
                candidates,
            }) as Box<dyn PreparedPunch>)
        })
    }
}
impl PreparedPunch for PreparedTcp {
    fn candidates(&self) -> Vec<Candidate> {
        self.candidates.clone()
    }
    fn connect(
        self: Box<Self>,
        candidates: Vec<Candidate>,
        allow_private: bool,
        deadline: Instant,
    ) -> TransportFuture<'static, PunchedStream> {
        Box::pin(async move {
            let stream = self
                .attempt
                .connect(&candidates, allow_private, deadline)
                .await?;
            let observed_host = stream.peer_addr().ok().map(|a| a.ip().to_string());
            let local_host = stream.local_addr().ok().map(|a| a.ip().to_string());
            Ok(PunchedStream {
                stream: Box::new(stream),
                observed_host,
                local_host,
            })
        })
    }
}
