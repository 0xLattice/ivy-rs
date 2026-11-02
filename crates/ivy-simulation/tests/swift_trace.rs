use ivy_core::{core::*, Config, Message, PeerEndpoint};
use ivy_simulation::SimulatedSignatureScheme;
use std::{collections::VecDeque, time::Duration};
fn config(seed: u8) -> Config {
    let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
    let key = config.peer_key();
    config.with_signature_scheme(SimulatedSignatureScheme::new(key))
}
fn at(seconds: u64) -> Timestamp {
    Timestamp {
        uptime: Duration::from_secs(seconds),
        unix_seconds: 1000 + seconds,
    }
}
fn endpoint(config: &Config) -> PeerEndpoint {
    PeerEndpoint {
        public_key: config.peer_key().hex(),
        host: "8.8.8.8".into(),
        port: 1234,
    }
}
#[test]
fn simulated_signature_trace_matches_every_swift_byte() {
    use ivy_core::SimulationRandom;
    let (ca, cb) = (config(1), config(2));
    let mut a = Core::new(&ca, CoreSettings::default(), SimulationRandom::seeded(1));
    let mut b = Core::new(&cb, CoreSettings::default(), SimulationRandom::seeded(2));
    a.step(Event::Start, at(0));
    b.step(Event::Start, at(0));
    let out = a.step(Event::Request(1, Request::Connect(endpoint(&cb))), at(0));
    let dial = out
        .iter()
        .find_map(|e| {
            if let Effect::Dial(id, _) = e {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap();
    let mut queue = VecDeque::from([
        (
            false,
            Event::ConnectionOpened {
                connection: 10,
                direction: ConnectionDirection::Inbound,
                observed_host: Some("8.8.4.4".into()),
            },
        ),
        (
            true,
            Event::ConnectionOpened {
                connection: 10,
                direction: ConnectionDirection::Outbound(dial),
                observed_host: Some("8.8.8.8".into()),
            },
        ),
    ]);
    let mut frames = Vec::new();
    for phase in 0..2 {
        if phase == 1 {
            queue.push_back((
                true,
                Event::Request(
                    2,
                    Request::Send {
                        peer: cb.peer_key(),
                        session_id: None,
                        message: Message::PeerMessage {
                            topic: "trace".into(),
                            payload: vec![1, 2, 3],
                        },
                    },
                ),
            ));
        }
        while let Some((side, event)) = queue.pop_front() {
            let out = if side {
                a.step(event, at(0))
            } else {
                b.step(event, at(0))
            };
            for effect in out {
                match effect {
                    Effect::Write(id, bytes) => {
                        frames.push(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
                        queue.push_back((!side, Event::Received(id, bytes)));
                        queue.push_back((side, Event::Writable(id)));
                    }
                    Effect::PeerConnected(token, _) | Effect::Deliver(token, _, _) => {
                        queue.push_back((side, Event::Delivered(token)))
                    }
                    Effect::Close(_) => panic!("unexpected close"),
                    _ => {}
                }
            }
        }
    }
    let expected: Vec<_> = include_str!("fixtures/swift-3.1.1-simulation-trace.hex")
        .lines()
        .collect();
    assert_eq!(frames.len(), 4);
    assert_eq!(frames, expected);
}

#[test]
fn real_crypto_rejects_simulated_signatures() {
    let fake = config(1);
    let real = Config::new(ed25519_dalek::SigningKey::from_bytes(&[2; 32]));
    let (_, hello) =
        ivy_core::Initiator::start_with_nonce(&fake, real.peer_key(), [0; 32], [1; 32]).unwrap();
    assert!(ivy_core::Responder::new(&real)
        .receive_with_nonce_source(&hello, |_| true, || [2; 32])
        .is_err());
}
