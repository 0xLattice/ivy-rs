use ivy_core::{
    core::{CoreSettings, Timestamp},
    Config, SimulationRandom,
};
use ivy_host::{
    codec::{decode, encode, Kind, Value},
    host::Host,
};
use std::{collections::VecDeque, time::Duration};
fn n(x: u64) -> Value {
    Value::Unsigned(x)
}
fn s(x: impl Into<String>) -> Value {
    Value::String(x.into())
}
fn b(x: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(x.into())
}
fn t(tag: u8, fields: Vec<Value>) -> Value {
    Value::Tagged { tag, fields }
}
fn f(v: Vec<Value>) -> Value {
    Value::Fields(v)
}
fn tag(v: &Value) -> (u8, &[Value]) {
    match v {
        Value::Tagged { tag, fields } => (*tag, fields),
        _ => panic!(),
    }
}
fn number(v: &Value) -> u64 {
    match v {
        Value::Unsigned(v) => *v,
        _ => panic!(),
    }
}
#[test]
fn binary_host_nodes_authenticate_and_deliver_large_payload() {
    let a = Config::new(ed25519_dalek::SigningKey::from_bytes(&[31; 32]));
    let z = Config::new(ed25519_dalek::SigningKey::from_bytes(&[32; 32]));
    let settings = CoreSettings {
        health_enabled: false,
        listen_port: Some(4001),
        ..Default::default()
    };
    let mut hosts = [
        Host::new(&a, settings.clone(), SimulationRandom::seeded(1)).unwrap(),
        Host::new(&z, settings, SimulationRandom::seeded(2)).unwrap(),
    ];
    let mut events = VecDeque::from([
        (0, t(0, vec![])),
        (1, t(0, vec![])),
        (
            1,
            t(
                13,
                vec![Value::Optional(Some(Box::new(f(vec![
                    s("8.8.4.4"),
                    n(55000),
                ]))))],
            ),
        ),
        (
            0,
            t(
                8,
                vec![
                    n(1),
                    t(
                        0,
                        vec![f(vec![s(z.peer_key().hex()), s("8.8.8.8"), n(4001)])],
                    ),
                ],
            ),
        ),
    ]);
    let mut connected = 0;
    let mut delivered = false;
    let mut completed = false;
    let mut steps = 0;
    while let Some((side, event)) = events.pop_front() {
        steps += 1;
        assert!(steps < 100000);
        let bytes = encode(Kind::Event, &event).unwrap();
        let bytes = hosts[side]
            .step(
                &bytes,
                Timestamp {
                    uptime: Duration::ZERO,
                    unix_seconds: 1000,
                },
            )
            .unwrap();
        let Value::List(effects) = decode(Kind::Effects, &bytes).unwrap() else {
            panic!()
        };
        for effect in effects {
            let (kind, v) = tag(&effect);
            match kind {
                0 => {
                    let host = Value::Optional(Some(Box::new(s("8.8.8.8"))));
                    let local = Value::Optional(Some(Box::new(s("10.0.0.2"))));
                    events.push_back((
                        1 - side,
                        t(3, vec![n(7), t(0, vec![]), host.clone(), local.clone()]),
                    ));
                    events.push_back((
                        side,
                        t(3, vec![n(7), t(1, vec![v[0].clone()]), host, local]),
                    ));
                }
                1 => {
                    let Value::Bytes(bytes) = &v[1] else { panic!() };
                    for chunk in bytes.chunks(17) {
                        events.push_back((1 - side, t(5, vec![v[0].clone(), b(chunk.to_vec())])));
                    }
                    events.push_back((side, t(6, vec![v[0].clone()])));
                }
                6 => {
                    if side == 0 {
                        let Value::Fields(peer) = &v[1] else { panic!() };
                        assert_eq!(
                            peer[3],
                            Value::List(vec![
                                f(vec![s("10.0.0.2"), n(4001)]),
                                f(vec![s("8.8.4.4"), n(4001)])
                            ])
                        );
                    }
                    connected += 1;
                    events.push_back((side, t(11, vec![v[0].clone()])));
                }
                9 if number(&v[0]) == 1 => {
                    assert_eq!(tag(&v[1]).0, 0);
                    assert_eq!(tag(&tag(&v[1]).1[0]).0, 0);
                    events.push_back((
                        side,
                        t(
                            8,
                            vec![
                                n(2),
                                t(
                                    3,
                                    vec![
                                        s(z.peer_key().hex()),
                                        s("host-message"),
                                        b(vec![9; 200_000]),
                                    ],
                                ),
                            ],
                        ),
                    ));
                }
                9 if number(&v[0]) == 2 => {
                    assert_eq!(tag(&v[1]).0, 1);
                    assert_eq!(tag(&tag(&v[1]).1[0]).0, 0);
                    completed = true;
                }
                5 => {
                    assert_eq!(side, 1);
                    assert_eq!(v[2], s("host-message"));
                    assert_eq!(v[3], b(vec![9; 200_000]));
                    delivered = true;
                    events.push_back((side, t(11, vec![v[0].clone()])));
                }
                _ => {}
            }
        }
    }
    assert_eq!(connected, 2);
    assert!(delivered && completed);
}
#[test]
fn configuration_defaults_map_to_runtime_without_stun() {
    let mut bytes = vec![2];
    bytes.extend([1; 32]);
    bytes.extend([0; 18]);
    let config = ivy_host::configuration::Configuration::decode(&bytes).unwrap();
    config.validate().unwrap();
    assert_eq!(config.listen_port, 4001);
    assert!(config.settings.stun_servers.is_empty());
    assert_eq!(config.settings.max_connections, 256);
}
