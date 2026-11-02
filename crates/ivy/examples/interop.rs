//! The Rust side of `interop/run.sh`. Keys are 32 copies of one byte, used
//! as an Ed25519 seed, as in the Swift program.
//!
//! listen <keyByte> <port>                -> answer one peer: echo "ping"
//!                                           messages back as "echo"
//! dial <keyByte> <port> <peerKeyByte>    -> send "ping", expect it echoed;
//!                                           idle past the peer's keepalive
//!                                           timeout, then do it again
//! keybits                                -> key work bits of each seed byte

use ed25519_dalek::SigningKey;
use ivy::{accept, connect, Config, Connection, ListenAddress, PeerMetadata};
use std::env;
use std::process::exit;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

fn key_config(byte: &str, port: u16) -> Config {
    let mut config = Config::new(SigningKey::from_bytes(&[byte.parse().unwrap(); 32]));
    // Not the defaults, so both encodings of metadata cross the wire.
    config.metadata = PeerMetadata::new(
        vec![ListenAddress {
            host: "127.0.0.1".into(),
            port,
        }],
        1 << 20,
    );
    config
}

fn check(condition: bool, what: &str) {
    println!("{} {what}", if condition { "ok  " } else { "FAIL" });
    if !condition {
        exit(1);
    }
}

async fn round_trip(connection: &mut Connection<TcpStream>, payload: &[u8]) -> bool {
    connection.send("ping", payload).await.unwrap();
    matches!(connection.recv().await, Ok((topic, echoed)) if topic == "echo" && echoed == payload)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == "keybits" {
        for byte in 0..=255u8 {
            println!(
                "{}",
                key_config(&byte.to_string(), 0).peer_key().work_bits()
            );
        }
        return;
    }
    let port: u16 = args[3].parse().unwrap();
    let config = key_config(&args[2], port);
    let address = format!("127.0.0.1:{port}");
    match args[1].as_str() {
        "listen" => {
            let listener = TcpListener::bind(&address).await.unwrap();
            println!("listening");
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = match accept(stream, &config, |_| true).await {
                Ok(connection) => connection,
                Err(error) => {
                    println!("REFUSED {error}");
                    exit(1);
                }
            };
            while let Ok((topic, payload)) = connection.recv().await {
                if topic == "ping" {
                    connection.send("echo", &payload).await.unwrap();
                }
            }
        }
        "dial" => {
            let peer = key_config(&args[4], 0).peer_key();
            let stream = TcpStream::connect(&address).await.unwrap();
            let mut connection = match connect(stream, &config, peer).await {
                Ok(connection) => connection,
                Err(error) => {
                    println!("FAIL session: {error}");
                    exit(1);
                }
            };
            check(true, "session authenticated");
            // Both implementations advertise the address they listen on.
            let listening = ListenAddress {
                host: "127.0.0.1".into(),
                port,
            };
            check(
                connection.peer_metadata().listen_addresses == [listening],
                "peer metadata received",
            );
            let payload: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
            check(round_trip(&mut connection, &payload).await, "message echoed back intact");
            // Waiting answers the peer's keepalive pings; nothing else comes.
            let idle = timeout(Duration::from_secs(5), connection.recv()).await;
            check(idle.is_err(), "idle past the peer's keepalive timeout");
            check(round_trip(&mut connection, b"again").await, "session still open after idling");
            println!("PASS");
        }
        _ => panic!("usage: interop listen <keyByte> <port> | dial <keyByte> <port> <peerKeyByte> | keybits"),
    }
}
