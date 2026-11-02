use ivy_core::core::*;
use ivy_core::{Config, Message, PeerEndpoint, SimulationRandom};
use std::{collections::VecDeque, time::Duration};
fn at(s: u64) -> Timestamp {
    Timestamp {
        uptime: Duration::from_secs(s),
        unix_seconds: 1000 + s,
    }
}
fn exchange(
    nodes: &mut [Core<SimulationRandom>],
    events: Vec<(usize, Event)>,
    time: Timestamp,
) -> Vec<(usize, Effect)> {
    let mut queue: VecDeque<_> = events.into();
    let mut out = Vec::new();
    let mut steps = 0;
    while let Some((node, event)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 10000);
        for effect in nodes[node].step(event, time) {
            match &effect {
                Effect::Write(conn, bytes) => {
                    let other = match (*conn, node) {
                        (10, 0) => 1,
                        (10, 1) => 0,
                        (11, 1) => 2,
                        (11, 2) => 1,
                        (12, 0) => 2,
                        (12, 2) => 0,
                        _ => panic!("invalid link"),
                    };
                    queue.push_back((other, Event::Received(*conn, bytes.clone())));
                    queue.push_back((node, Event::Writable(*conn)));
                }
                Effect::PeerConnected(token, _) | Effect::Deliver(token, _, _) => {
                    queue.push_back((node, Event::Delivered(*token)))
                }
                Effect::StartJob(id, job) => {
                    let result = match job {
                        ContentJob::ReadVolume { root_cid, .. } => {
                            ContentJobResult::Entries(vec![ivy_core::ContentEntry {
                                cid: root_cid.clone(),
                                data: vec![9; 100_000],
                            }])
                        }
                        ContentJob::AuthorizeVolume { .. } => ContentJobResult::Authorized(true),
                        ContentJob::ReadBundle { root_cid } => {
                            ContentJobResult::Roots(vec![root_cid.clone(), "child".into()])
                        }
                    };
                    queue.push_back((node, Event::JobFinished(*id, result)));
                }
                _ => {}
            }
            out.push((node, effect));
        }
    }
    out
}
fn send(
    nodes: &mut [Core<SimulationRandom>],
    from: usize,
    to: ivy_core::PeerKey,
    id: u64,
    message: Message,
    time: Timestamp,
) -> Vec<(usize, Effect)> {
    exchange(
        nodes,
        vec![(
            from,
            Event::Request(
                id,
                Request::Send {
                    peer: to,
                    session_id: None,
                    message,
                },
            ),
        )],
        time,
    )
}
#[test]
fn relayed_endpoints_authenticate_forward_with_backpressure_and_expire() {
    let configs: Vec<_> = (51..54)
        .map(|n| {
            let mut config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[n; 32]));
            config.metadata.max_frame_size = ivy_core::MIN_FRAME_SIZE;
            config
        })
        .collect();
    let mut nodes: Vec<_> = configs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            Core::new(
                c,
                CoreSettings {
                    relay_enabled: i == 1,
                    mode: if i == 0 {
                        CoreMode::Pinned(configs[2].peer_key())
                    } else if i == 2 {
                        CoreMode::Pinned(configs[0].peer_key())
                    } else {
                        CoreMode::Overlay
                    },
                    carriers: if i == 1 {
                        vec![]
                    } else {
                        vec![PeerEndpoint {
                            public_key: configs[1].peer_key().hex(),
                            host: "8.8.8.8".into(),
                            port: 1234,
                        }]
                    },
                    health_enabled: false,
                    ..CoreSettings::default()
                },
                SimulationRandom::seeded(i as u64),
            )
        })
        .collect();
    let started: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.step(Event::Start, at(0)))
        .collect();
    for (from, to, conn) in [(0, 1, 10), (2, 1, 11)] {
        let out = started[from].clone();
        let dial = out
            .iter()
            .find_map(|e| match e {
                Effect::Dial(id, _) => Some(*id),
                _ => None,
            })
            .unwrap();
        exchange(
            &mut nodes,
            vec![
                (
                    to,
                    Event::ConnectionOpened {
                        connection: conn,
                        direction: ConnectionDirection::Inbound,
                        observed_host: None,
                    },
                ),
                (
                    from,
                    Event::ConnectionOpened {
                        connection: conn,
                        direction: ConnectionDirection::Outbound(dial),
                        observed_host: None,
                    },
                ),
            ],
            at(0),
        );
    }

    let carrier = nodes[0].authenticated_peers()[0].clone();
    assert_eq!(carrier.role, AuthenticatedPeerRole::Carrier);
    assert!(nodes[0].endpoint_peers().is_empty());
    let direct = nodes[0].step(
        Event::Request(
            2,
            Request::Connect(PeerEndpoint {
                public_key: configs[2].peer_key().hex(),
                host: "203.0.113.1".into(),
                port: 1234,
            }),
        ),
        at(1),
    );
    let dial = direct
        .iter()
        .find_map(|e| match e {
            Effect::Dial(id, _) => Some(*id),
            _ => None,
        })
        .unwrap();
    let connected = exchange(&mut nodes, vec![(0, Event::DialFailed(dial))], at(1));
    assert!(connected
        .iter()
        .any(|(n, e)| *n == 0 && matches!(e, Effect::Completed(2, RequestResult::Connected))));
    let endpoint = nodes[0]
        .authenticated_peers()
        .into_iter()
        .find(|p| p.key == configs[2].peer_key())
        .unwrap();
    let reverse = nodes[2]
        .authenticated_peers()
        .into_iter()
        .find(|p| p.key == configs[0].peer_key())
        .unwrap();
    assert_eq!(endpoint.session_id, reverse.session_id);
    assert_eq!(endpoint.role, AuthenticatedPeerRole::Endpoint);
    assert!(
        matches!(endpoint.route,AuthenticatedRoute::Relayed{carrier,..} if carrier==configs[1].peer_key())
    );
    let packet = Message::PeerMessage {
        topic: "relayed".into(),
        payload: vec![42; 2000],
    };
    let delivered = send(
        &mut nodes,
        0,
        configs[2].peer_key(),
        3,
        packet.clone(),
        at(2),
    );
    assert!(delivered.iter().any(|(n, e)| *n == 2
        && matches!(e,Effect::Deliver(_,peer,m) if peer.key==configs[0].peer_key() && *m==packet)));
    assert!(!delivered
        .iter()
        .any(|(n, e)| *n == 1 && matches!(e, Effect::Deliver(..))));
    assert!(delivered
        .iter()
        .any(|(n, e)| *n == 2 && matches!(e, Effect::PauseReading(11))));
    assert!(!delivered.iter().any(|(_,e)|matches!(e,Effect::Write(id,_)|Effect::PauseReading(id)|Effect::ResumeReading(id) if *id>=(1u64<<63))));
    nodes[2].step(Event::SetContentSource(true), at(3));
    let volumes = exchange(
        &mut nodes,
        vec![(
            0,
            Event::Request(
                4,
                Request::FetchVolume {
                    peer: endpoint.clone(),
                    root_cid: "root".into(),
                    bundle: true,
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(3),
    );
    assert!(volumes.iter().any(|(n,e)|*n==0 && matches!(e,Effect::Completed(4,RequestResult::Volume(response)) if response.volumes.len()==2 && response.ended && response.session_id==Some(endpoint.session_id))));
    // Keep carrier->target writes unflushed while the target still consumes
    // the preceding record, preserving authenticated sequence order.
    let filler = nodes[1].step(
        Event::Request(
            90,
            Request::Send {
                peer: configs[2].peer_key(),
                session_id: None,
                message: Message::PeerMessage {
                    topic: "fill".into(),
                    payload: vec![0; ivy_core::MIN_FRAME_SIZE as usize - 200],
                },
            },
        ),
        at(5),
    );
    let frame = filler
        .iter()
        .find_map(|e| match e {
            Effect::Write(11, bytes) => Some(bytes.clone()),
            _ => None,
        })
        .unwrap();
    exchange(&mut nodes, vec![(2, Event::Received(11, frame))], at(5));
    let blocked = send(
        &mut nodes,
        0,
        configs[2].peer_key(),
        5,
        packet.clone(),
        at(6),
    );
    assert!(blocked
        .iter()
        .any(|(n, e)| *n == 1 && matches!(e, Effect::PauseReading(10))));
    assert!(nodes[1].inbound_bytes() > 2000);
    let resumed = exchange(&mut nodes, vec![(1, Event::Writable(11))], at(7));
    assert!(resumed
        .iter()
        .any(|(n, e)| *n == 2 && matches!(e,Effect::Deliver(_,_,m) if *m==packet)));
    assert_eq!(nodes[1].inbound_bytes(), 0);
    let expired = exchange(&mut nodes, vec![(1, Event::Tick)], at(307));
    assert!(expired.iter().any(|(n, e)| *n == 0
        && matches!(e,Effect::PeerDisconnected(key) if *key==configs[2].peer_key())));
    assert!(expired.iter().any(|(n, e)| *n == 2
        && matches!(e,Effect::PeerDisconnected(key) if *key==configs[0].peer_key())));
    assert_eq!(nodes[0].authenticated_peers().len(), 1);
    let opening = nodes[0].step(
        Event::Request(
            601,
            Request::ConnectViaRelay {
                carrier,
                target: configs[2].peer_key(),
            },
        ),
        at(308),
    );
    let cancelled = nodes[0].step(Event::Cancel(601), at(308));
    assert_eq!(
        cancelled
            .iter()
            .filter(|e| matches!(e, Effect::Completed(601, RequestResult::Cancelled)))
            .count(),
        1
    );
    let late: Vec<_> = opening
        .iter()
        .chain(&cancelled)
        .filter_map(|e| match e {
            Effect::Write(10, bytes) => Some((1, Event::Received(10, bytes.clone()))),
            _ => None,
        })
        .collect();
    let late = exchange(&mut nodes, late, at(308));
    assert!(!late
        .iter()
        .any(|(_, e)| matches!(e, Effect::Completed(601, ..))));
    assert_eq!(nodes[0].endpoint_peers().len(), 0);
    assert_eq!(nodes[2].endpoint_peers().len(), 0);
    let upgraded_carrier = nodes[0].carrier_peers()[0].clone();
    exchange(
        &mut nodes,
        vec![(
            0,
            Event::Request(
                602,
                Request::ConnectViaRelay {
                    carrier: upgraded_carrier,
                    target: configs[2].peer_key(),
                },
            ),
        )],
        at(309),
    );
    let before = nodes[0].endpoint_peers()[0].clone();
    assert!(matches!(before.route, AuthenticatedRoute::Relayed { .. }));
    let upgraded = exchange(
        &mut nodes,
        vec![
            (
                2,
                Event::ConnectionOpened {
                    connection: 12,
                    direction: ConnectionDirection::Inbound,
                    observed_host: Some("8.8.4.4".into()),
                },
            ),
            (
                0,
                Event::Request(
                    603,
                    Request::ConnectOver {
                        endpoint: PeerEndpoint {
                            public_key: configs[2].peer_key().hex(),
                            host: "8.8.4.4".into(),
                            port: 0,
                        },
                        connection: 12,
                        observed_host: Some("8.8.4.4".into()),
                    },
                ),
            ),
        ],
        at(310),
    );
    assert!(upgraded
        .iter()
        .any(|(n, e)| *n == 0 && matches!(e, Effect::Completed(603, RequestResult::Connected))));
    assert!(matches!(
        nodes[0].endpoint_peers()[0].route,
        AuthenticatedRoute::Direct
    ));
    assert!(matches!(
        nodes[2].endpoint_peers()[0].route,
        AuthenticatedRoute::Direct
    ));
    assert_eq!(
        nodes[0].endpoint_peers()[0].session_id,
        nodes[2].endpoint_peers()[0].session_id
    );
    let delivered = send(
        &mut nodes,
        0,
        configs[2].peer_key(),
        604,
        Message::PeerMessage {
            topic: "upgraded".into(),
            payload: vec![4; 100],
        },
        at(311),
    );
    assert!(delivered.iter().any(|(n, e)| *n == 2
        && matches!(e,Effect::Deliver(_,_,Message::PeerMessage{topic,..}) if topic=="upgraded")));
}
