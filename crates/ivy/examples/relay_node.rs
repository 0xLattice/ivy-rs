//! Live relay interoperability harness; fixed seed keys are test-only.
use ed25519_dalek::SigningKey;
use ivy_core::core::{CoreSettings, Effect, Event, Request, RequestResult};
use ivy_core::{Config, ListenAddress, Message, PeerEndpoint};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{timeout, Duration},
};
fn key(n: u8) -> Config {
    Config::new(SigningKey::from_bytes(&[n; 32]))
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let role = &args[1];
    let seed: u8 = args[2].parse().unwrap();
    let port: u16 = args[3].parse().unwrap();
    let mut config = key(seed);
    config.metadata.listen_addresses.push(ListenAddress {
        host: "127.0.0.1".into(),
        port,
    });
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let (tx, rx) = mpsc::channel(128);
    let (notifications, mut effects) = mpsc::channel(128);
    let punching = std::env::var_os("IVY_PUNCH").is_some() && role != "carrier";
    let task = if punching {
        tokio::spawn(async move {
            use ivy::punch_node::{Command, Notification, Settings};
            let (commands, input) = mpsc::channel(128);
            let (output, mut events) = mpsc::channel(128);
            let mut rx = rx;
            let incoming = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if commands.send(Command::Node(event)).await.is_err() {
                        break;
                    }
                }
            });
            let outgoing = tokio::spawn(async move {
                while let Some(event) = events.recv().await {
                    if let Notification::Node(effect) = event {
                        if notifications.send(effect).await.is_err() {
                            break;
                        }
                    }
                }
            });
            let result = ivy::punch_node::run(
                listener,
                Settings {
                    config,
                    core: CoreSettings::default(),
                    punch: ivy_core::punch_connector::Options {
                        allow_private_candidates: true,
                        ..Default::default()
                    },
                    hosts: Some(vec!["127.0.0.1".into()]),
                },
                input,
                output,
                ivy_core::NullLedger,
            )
            .await;
            incoming.abort();
            outgoing.abort();
            result
        })
    } else {
        tokio::spawn(ivy::node::run(
            listener,
            config,
            CoreSettings {
                relay_enabled: role == "carrier",
                max_connections_per_netgroup: 8,
                ..CoreSettings::default()
            },
            rx,
            notifications,
        ))
    };
    let carrier = key(1).peer_key();
    let target = key(2).peer_key();
    let payload = vec![0x5a; 200_000];
    if role == "carrier" {
        println!("READY");
    } else {
        let carrier_port = args[4].parse().unwrap();
        tx.send(Event::Request(
            1,
            Request::Connect(PeerEndpoint {
                public_key: carrier.hex(),
                host: "127.0.0.1".into(),
                port: carrier_port,
            }),
        ))
        .await
        .unwrap();
    }
    let mut carrier_session = None;
    loop {
        let effect = timeout(Duration::from_secs(30), effects.recv())
            .await
            .expect("relay harness timed out")
            .expect("node stopped");
        match effect {
            Effect::PeerConnected(token, peer) => {
                if peer.key == carrier {
                    carrier_session = Some(peer.clone());
                }
                tx.send(Event::Delivered(token)).await.unwrap();
                if punching
                    && role == "dial"
                    && peer.key == target
                    && peer.route == ivy_core::core::AuthenticatedRoute::Direct
                {
                    tx.send(Event::Request(
                        3,
                        Request::Send {
                            peer: target,
                            session_id: Some(peer.session_id),
                            message: Message::PeerMessage {
                                topic: "ping".into(),
                                payload: payload.clone(),
                            },
                        },
                    ))
                    .await
                    .unwrap();
                }
            }
            Effect::Deliver(
                token,
                peer,
                Message::PeerMessage {
                    topic,
                    payload: received,
                },
            ) => {
                tx.send(Event::Delivered(token)).await.unwrap();
                if topic == "ping" {
                    tx.send(Event::Request(
                        10,
                        Request::Send {
                            peer: peer.key,
                            session_id: Some(peer.session_id),
                            message: Message::PeerMessage {
                                topic: "echo".into(),
                                payload: received,
                            },
                        },
                    ))
                    .await
                    .unwrap();
                } else if topic == "echo" && role == "dial" {
                    assert_eq!(peer.key, target);
                    assert_eq!(received, payload);
                    if punching {
                        assert_eq!(peer.route, ivy_core::core::AuthenticatedRoute::Direct);
                    }
                    tx.send(Event::Stop).await.unwrap();
                    task.await.unwrap().unwrap();
                    println!("PASS");
                    return;
                }
            }
            Effect::Deliver(token, _, _) => {
                tx.send(Event::Delivered(token)).await.unwrap();
            }
            Effect::Completed(1, RequestResult::Connected) => {
                if role == "dial" {
                    tx.send(Event::Request(
                        2,
                        Request::ConnectViaRelay {
                            carrier: carrier_session.clone().unwrap(),
                            target,
                        },
                    ))
                    .await
                    .unwrap();
                } else {
                    println!("READY");
                }
            }
            Effect::Completed(2, RequestResult::Connected) if !punching => {
                tx.send(Event::Request(
                    3,
                    Request::Send {
                        peer: target,
                        session_id: None,
                        message: Message::PeerMessage {
                            topic: "ping".into(),
                            payload: payload.clone(),
                        },
                    },
                ))
                .await
                .unwrap();
            }
            Effect::Completed(id, result)
                if id <= 3
                    && !matches!(result, RequestResult::Enqueued | RequestResult::Connected) =>
            {
                panic!("request {id}: {result:?}")
            }
            _ => {}
        }
    }
}
