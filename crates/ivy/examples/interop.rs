//! The Rust side of `interop/run.sh`. Keys are 32 copies of one byte, used
//! as an Ed25519 seed, as in the Swift program.
//!
//! listen <keyByte> <port>                -> answer one peer: echo "ping"
//!                                           messages back as "echo"
//! dial <keyByte> <port> <peerKeyByte>    -> send "ping", expect it echoed

use ed25519_dalek::SigningKey;
use ivy::{accept, connect, Config};
use std::env;
use std::process::exit;
use tokio::net::{TcpListener, TcpStream};

fn key_config(byte: &str) -> Config {
    Config::new(SigningKey::from_bytes(&[byte.parse().unwrap(); 32]))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let config = key_config(&args[2]);
    let address = format!("127.0.0.1:{}", args[3]);
    match args[1].as_str() {
        "listen" => {
            let listener = TcpListener::bind(&address).await.unwrap();
            println!("listening");
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = accept(stream, &config, |_| true).await.unwrap();
            while let Ok((topic, payload)) = connection.recv().await {
                if topic == "ping" {
                    connection.send("echo", &payload).await.unwrap();
                }
            }
        }
        "dial" => {
            let peer = key_config(&args[4]).peer_key();
            let stream = TcpStream::connect(&address).await.unwrap();
            let mut connection = match connect(stream, &config, peer).await {
                Ok(connection) => connection,
                Err(error) => {
                    println!("FAIL session: {error}");
                    exit(1);
                }
            };
            println!("ok   session authenticated");
            let payload: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
            connection.send("ping", &payload).await.unwrap();
            let (topic, echoed) = connection.recv().await.unwrap();
            if topic != "echo" || echoed != payload {
                println!("FAIL message echoed back intact");
                exit(1);
            }
            println!("ok   message echoed back intact");
            println!("PASS");
        }
        _ => panic!("usage: interop listen <keyByte> <port> | dial <keyByte> <port> <peerKeyByte>"),
    }
}
