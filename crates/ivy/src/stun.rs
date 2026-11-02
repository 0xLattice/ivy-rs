//! Bounded UDP STUN discovery and a rate-limited binding responder.
use ivy_core::stun::{
    binding_reply, binding_request, parse_binding_reply, ObservedAddress, ReplyLimit,
};
use rand_core::{OsRng, RngCore};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    net::{lookup_host, UdpSocket},
    time::{sleep_until, timeout, Instant},
};
/// Tries configured servers in order, with retries at 500ms/1500ms and a 3s
/// deadline per query. Dropping the future cancels the socket and all retries.
pub async fn discover(servers: &[(String, u16)]) -> Option<ObservedAddress> {
    for (host, port) in servers {
        let Ok(Ok(mut addresses)) =
            timeout(Duration::from_secs(3), lookup_host((host.as_str(), *port))).await
        else {
            continue;
        };
        let Some(address) = addresses.next() else {
            continue;
        };
        if let Ok(Some(observed)) = query(address).await {
            return Some(observed);
        }
    }
    None
}
pub async fn query(remote: SocketAddr) -> io::Result<Option<ObservedAddress>> {
    let socket = UdpSocket::bind(if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    socket.connect(remote).await?;
    let mut transaction = [0; 12];
    OsRng.fill_bytes(&mut transaction);
    let request = binding_request(transaction);
    socket.send(&request).await?;
    let start = Instant::now();
    let mut retries = [Duration::from_millis(500), Duration::from_millis(1500)].into_iter();
    let mut retry = retries.next();
    let mut buf = [0u8; 65535];
    loop {
        tokio::select! {
            received=socket.recv(&mut buf)=>{let length=received?;if let Some(address)=parse_binding_reply(&buf[..length],transaction){return Ok(Some(address));}},
            _=sleep_until(start+Duration::from_secs(3))=>return Ok(None),
            _=async {if let Some(delay)=retry{sleep_until(start+delay).await}else{std::future::pending::<()>().await}}=>{socket.send(&request).await?;retry=retries.next();}
        }
    }
}
/// Runs until its future is cancelled. Replies never exceed the bounded codec
/// policy; IPv6 clients sharing a /64 share a per-second response budget.
pub async fn serve(socket: UdpSocket) -> io::Result<()> {
    let start = Instant::now();
    let mut limits = ReplyLimit::default();
    let mut buffer = [0; 513];
    loop {
        let (len, remote) = socket.recv_from(&mut buffer).await?;
        if let Some(reply) = binding_reply(&buffer[..len], remote.ip(), remote.port()) {
            if limits.allows(remote.ip(), start.elapsed()) {
                let _ = socket.send_to(&reply, remote).await;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn local_udp_binding_discovers_the_observed_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(serve(socket));
        let observed = query(address).await.unwrap().unwrap();
        assert_eq!(observed.host, "127.0.0.1");
        assert_ne!(observed.port, 0);
        server.abort();
        let _ = server.await;
    }
}
