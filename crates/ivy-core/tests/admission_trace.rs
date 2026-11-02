use ivy_core::{core::*, Config, PeerEndpoint, SimulationRandom};
use std::{collections::BTreeMap, time::Duration};
fn at(seconds: u64) -> Timestamp {
    Timestamp {
        uptime: Duration::from_secs(seconds),
        unix_seconds: 1000 + seconds,
    }
}
fn endpoint(config: &Config, host: &str) -> PeerEndpoint {
    PeerEndpoint {
        public_key: config.peer_key().hex(),
        host: host.into(),
        port: 1234,
    }
}
fn node(config: &Config, capacity: usize, reserve: usize) -> Core<'_, SimulationRandom> {
    Core::new(
        config,
        CoreSettings {
            max_connections: capacity,
            reserved_outbound_connection_slots: reserve,
            max_connections_per_netgroup: 1,
            ..CoreSettings::default()
        },
        SimulationRandom::seeded(1),
    )
}
fn apply(
    node: &mut Core<SimulationRandom>,
    rows: &mut BTreeMap<String, String>,
    name: &str,
    event: Event,
    time: u64,
) -> Vec<Effect> {
    let effects = node.step(event, at(time));
    let mut normalized: Vec<_> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Dial(..) => Some("dial".into()),
            Effect::Write(..) => Some("write".into()),
            Effect::Close(id) => Some(format!("close:{id}")),
            Effect::PeerConnected(..) => Some("connected".into()),
            Effect::Completed(id, result) => Some(format!(
                "completed:{id}:{}",
                match result {
                    RequestResult::Connected => "connected",
                    RequestResult::Cancelled => "cancelled",
                    RequestResult::ConnectionInProgress => "connectionInProgress",
                    RequestResult::NoRelayAvailable => "noRelayAvailable",
                    RequestResult::Failed => "identityVerificationFailed",
                    RequestResult::ConnectFailed(ConnectError::NotRunning) => "notRunning",
                    RequestResult::ConnectFailed(ConnectError::InvalidPeerKey) => "invalidPeerKey",
                    RequestResult::ConnectFailed(ConnectError::PeerOutsideMode) =>
                        "peerOutsideMode",
                    RequestResult::ConnectFailed(ConnectError::StreamHasNoObservedHost) =>
                        "streamHasNoObservedHost",
                    _ => panic!("unexpected result {result:?}"),
                }
            )),
            _ => None,
        })
        .collect();
    normalized.sort();
    rows.insert(name.into(), normalized.join("|"));
    effects
}
fn dial(effects: &[Effect]) -> u64 {
    effects
        .iter()
        .find_map(|e| {
            if let Effect::Dial(id, _) = e {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap()
}
fn opened(id: u64, direction: ConnectionDirection, host: Option<&str>) -> Event {
    Event::ConnectionOpened {
        connection: id,
        direction,
        observed_host: host.map(str::to_owned),
    }
}
fn connect(id: u64, config: &Config, host: &str) -> Event {
    Event::Request(id, Request::Connect(endpoint(config, host)))
}
fn over(id: u64, config: &Config, host: &str, connection: u64) -> Event {
    Event::Request(
        id,
        Request::ConnectOver {
            endpoint: endpoint(config, host),
            connection,
            observed_host: Some(host.into()),
        },
    )
}
fn frame(effects: &[Effect]) -> Vec<u8> {
    effects
        .iter()
        .find_map(|e| {
            if let Effect::Write(_, bytes) = e {
                Some(bytes.clone())
            } else {
                None
            }
        })
        .unwrap()
}
#[test]
fn matches_actual_swift_cancellation_restart_binding_and_supplied_admission() {
    let configs: Vec<_> = (1..=3)
        .map(|n| Config::new(ed25519_dalek::SigningKey::from_bytes(&[n; 32])))
        .collect();
    let mut rows = BTreeMap::new();
    let mut a = node(&configs[0], 1, 0);
    a.step(Event::Start, at(0));
    let first = dial(&apply(
        &mut a,
        &mut rows,
        "cancel.reserve",
        connect(1, &configs[1], "8.8.8.8"),
        0,
    ));
    apply(&mut a, &mut rows, "cancel.caller", Event::Cancel(1), 0);
    apply(
        &mut a,
        &mut rows,
        "cancel.same-peer",
        connect(2, &configs[1], "8.8.8.8"),
        0,
    );
    apply(
        &mut a,
        &mut rows,
        "cancel.other-peer",
        connect(3, &configs[2], "1.1.1.1"),
        0,
    );
    apply(
        &mut a,
        &mut rows,
        "cancel.inbound-blocked",
        opened(10, ConnectionDirection::Inbound, Some("9.9.9.9")),
        0,
    );
    apply(
        &mut a,
        &mut rows,
        "cancel.clock-does-not-release",
        Event::Tick,
        100,
    );
    apply(
        &mut a,
        &mut rows,
        "cancel.transport-failed",
        Event::DialFailed(first),
        100,
    );
    let next = dial(&apply(
        &mut a,
        &mut rows,
        "restart.reserve",
        connect(4, &configs[1], "8.8.8.8"),
        100,
    ));
    apply(&mut a, &mut rows, "restart.stop", Event::Stop, 100);
    apply(&mut a, &mut rows, "restart.start", Event::Start, 100);
    apply(
        &mut a,
        &mut rows,
        "restart.abandoned-blocks",
        connect(5, &configs[1], "8.8.8.8"),
        100,
    );
    apply(
        &mut a,
        &mut rows,
        "restart.late-success",
        opened(11, ConnectionDirection::Outbound(next), Some("8.8.8.8")),
        100,
    );
    let disconnected = dial(&apply(
        &mut a,
        &mut rows,
        "disconnect.reserve",
        connect(6, &configs[1], "8.8.8.8"),
        100,
    ));
    apply(
        &mut a,
        &mut rows,
        "disconnect.command",
        Event::DisconnectPeer(configs[1].peer_key()),
        100,
    );
    apply(
        &mut a,
        &mut rows,
        "disconnect.late-success",
        opened(
            12,
            ConnectionDirection::Outbound(disconnected),
            Some("8.8.8.8"),
        ),
        100,
    );
    let mut b = node(&configs[0], 3, 0);
    b.step(Event::Start, at(0));
    let d1 = dial(&apply(
        &mut b,
        &mut rows,
        "observed.reserve-first",
        connect(20, &configs[1], "8.8.8.8"),
        0,
    ));
    apply(
        &mut b,
        &mut rows,
        "observed.first",
        opened(20, ConnectionDirection::Outbound(d1), Some("9.9.9.9")),
        0,
    );
    let d2 = dial(&apply(
        &mut b,
        &mut rows,
        "observed.reserve-second",
        connect(21, &configs[2], "1.1.1.1"),
        0,
    ));
    apply(
        &mut b,
        &mut rows,
        "observed.refuse-second",
        opened(21, ConnectionDirection::Outbound(d2), Some("9.9.9.9")),
        0,
    );
    let mut c = node(&configs[0], 3, 0);
    c.step(Event::Start, at(0));
    apply(
        &mut c,
        &mut rows,
        "supplied.inbound",
        opened(30, ConnectionDirection::Inbound, None),
        0,
    );
    apply(
        &mut c,
        &mut rows,
        "supplied.duplicate-id",
        over(30, &configs[1], "8.8.8.8", 30),
        0,
    );
    apply(
        &mut c,
        &mut rows,
        "supplied.native-reservation",
        connect(31, &configs[1], "8.8.8.8"),
        0,
    );
    apply(
        &mut c,
        &mut rows,
        "supplied.duplicate-peer",
        over(32, &configs[1], "8.8.8.8", 31),
        0,
    );
    let mut d = node(&configs[0], 1, 0);
    d.step(Event::Start, at(0));
    apply(
        &mut d,
        &mut rows,
        "supplied.full-reservation",
        connect(40, &configs[1], "8.8.8.8"),
        0,
    );
    apply(
        &mut d,
        &mut rows,
        "supplied.full",
        over(41, &configs[2], "1.1.1.1", 40),
        0,
    );

    // Reserve inbound first, then let an outgoing session win the only inbound
    // slot. The pending responder must recheck admission at promotion.
    let mut a = node(&configs[0], 2, 1);
    let mut b = node(&configs[1], 3, 0);
    let mut c = node(&configs[2], 3, 0);
    for node in [&mut a, &mut b, &mut c] {
        node.step(Event::Start, at(0));
    }
    let bd = dial(&b.step(connect(50, &configs[0], "8.8.8.8"), at(0)));
    let hello = frame(&b.step(
        opened(50, ConnectionDirection::Outbound(bd), Some("8.8.8.8")),
        at(0),
    ));
    apply(
        &mut a,
        &mut rows,
        "promotion.inbound-reserved",
        opened(50, ConnectionDirection::Inbound, Some("9.9.9.9")),
        0,
    );
    let reply = frame(&a.step(Event::Received(50, hello), at(0)));
    let finish = frame(&b.step(Event::Received(50, reply), at(0)));
    let ad = dial(&a.step(connect(60, &configs[2], "1.1.1.1"), at(0)));
    let hello = frame(&a.step(
        opened(60, ConnectionDirection::Outbound(ad), Some("1.1.1.1")),
        at(0),
    ));
    c.step(
        opened(60, ConnectionDirection::Inbound, Some("8.8.8.8")),
        at(0),
    );
    let reply = frame(&c.step(Event::Received(60, hello), at(0)));
    let connected = apply(
        &mut a,
        &mut rows,
        "promotion.outbound-wins",
        Event::Received(60, reply),
        0,
    );
    let token = connected
        .iter()
        .find_map(|e| {
            if let Effect::PeerConnected(token, _) = e {
                Some(*token)
            } else {
                None
            }
        })
        .unwrap();
    apply(
        &mut a,
        &mut rows,
        "promotion.outbound-delivered",
        Event::Delivered(token),
        0,
    );
    apply(
        &mut a,
        &mut rows,
        "promotion.inbound-refused",
        Event::Received(50, finish),
        0,
    );
    assert_eq!(a.authenticated_peers().len(), 1);
    assert_eq!(a.authenticated_peers()[0].key, configs[2].peer_key());
    let mut errors = node(&configs[0], 3, 0);
    apply(
        &mut errors,
        &mut rows,
        "errors.stopped",
        connect(80, &configs[1], "8.8.8.8"),
        0,
    );
    let invalid = PeerEndpoint {
        public_key: "bad".into(),
        host: "8.8.8.8".into(),
        port: 1234,
    };
    apply(
        &mut errors,
        &mut rows,
        "errors.invalid-before-stopped",
        Event::Request(81, Request::Connect(invalid.clone())),
        0,
    );
    apply(
        &mut errors,
        &mut rows,
        "errors.supplied-stopped",
        Event::Request(
            82,
            Request::ConnectOver {
                endpoint: endpoint(&configs[1], "8.8.8.8"),
                connection: 80,
                observed_host: None,
            },
        ),
        0,
    );
    errors.step(Event::Start, at(0));
    for (id, connection, host, label) in [
        (83, 81, None, "errors.supplied-no-host"),
        (84, 82, Some(String::new()), "errors.supplied-empty-host"),
    ] {
        apply(
            &mut errors,
            &mut rows,
            label,
            Event::Request(
                id,
                Request::ConnectOver {
                    endpoint: endpoint(&configs[1], "8.8.8.8"),
                    connection,
                    observed_host: host,
                },
            ),
            0,
        );
    }
    apply(
        &mut errors,
        &mut rows,
        "errors.supplied-invalid-key",
        Event::Request(
            85,
            Request::ConnectOver {
                endpoint: invalid,
                connection: 83,
                observed_host: None,
            },
        ),
        0,
    );
    let mut pinned = Core::new(
        &configs[0],
        CoreSettings {
            mode: CoreMode::Pinned(configs[1].peer_key()),
            ..Default::default()
        },
        SimulationRandom::seeded(1),
    );
    apply(
        &mut pinned,
        &mut rows,
        "errors.mode-before-stopped",
        connect(86, &configs[2], "8.8.8.8"),
        0,
    );
    pinned.step(Event::Start, at(0));
    apply(
        &mut pinned,
        &mut rows,
        "errors.mode-before-host",
        Event::Request(
            87,
            Request::ConnectOver {
                endpoint: endpoint(&configs[2], "8.8.8.8"),
                connection: 84,
                observed_host: None,
            },
        ),
        0,
    );
    let expected: BTreeMap<String, String> = include_str!("fixtures/swift-3.1.1-admission.tsv")
        .lines()
        .map(|line| {
            let (k, v) = line.split_once('\t').unwrap();
            (k.into(), v.into())
        })
        .collect();
    assert_eq!(rows, expected);
}
