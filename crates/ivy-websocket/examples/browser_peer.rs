//! Live browser-host interoperability peer. The fixed seed is test-only.
use std::io::Write;
#[tokio::main]
async fn main() {
    let config = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!(
        "READY {} {}",
        listener.local_addr().unwrap().port(),
        config.peer_key().hex()
    );
    std::io::stdout().flush().unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let stream = ivy_websocket::accept(stream, "/ivy").await.unwrap();
    let mut peer = ivy::accept(stream, &config, |_| true).await.unwrap();
    let (topic, payload) = peer.recv().await.unwrap();
    assert_eq!(topic, "browser-websocket");
    assert_eq!(payload, vec![6; 200_000]);
    peer.send("echo", &payload).await.unwrap();
    let _ = peer.recv().await;
}
