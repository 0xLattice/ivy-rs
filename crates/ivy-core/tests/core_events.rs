use ivy_core::core::*;
use ivy_core::{Config, Message, PeerEndpoint};
use rand_core::{CryptoRng, Error, RngCore};
use std::{collections::VecDeque, time::Duration};
struct TestRandom(u64);
impl RngCore for TestRandom {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            let n = self.next_u64().to_le_bytes();
            c.copy_from_slice(&n[..c.len()]);
        }
    }
    fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(b);
        Ok(())
    }
}
impl CryptoRng for TestRandom {}
fn config(n: u8) -> Config {
    Config::new(ed25519_dalek::SigningKey::from_bytes(&[n; 32]))
}
fn at(seconds: u64) -> Timestamp {
    Timestamp {
        uptime: Duration::from_secs(seconds),
        unix_seconds: 1000 + seconds,
    }
}
fn endpoint(c: &Config) -> PeerEndpoint {
    PeerEndpoint {
        public_key: c.peer_key().hex(),
        host: "8.8.8.8".into(),
        port: 1234,
    }
}
fn effects(
    a: &mut Core<TestRandom>,
    b: &mut Core<TestRandom>,
    initial: Vec<(bool, Event)>,
    now: Timestamp,
) -> Vec<(bool, Effect)> {
    let mut queue: VecDeque<_> = initial.into();
    let mut all = Vec::new();
    let mut steps = 0;
    while let Some((side, event)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 50000, "event loop failed to settle");
        let produced = if side {
            a.step(event, now)
        } else {
            b.step(event, now)
        };
        for effect in produced {
            match &effect {
                Effect::Write(id, bytes) => {
                    for fragment in bytes.chunks(17) {
                        queue.push_back((!side, Event::Received(*id, fragment.to_vec())));
                    }
                    queue.push_back((side, Event::Writable(*id)));
                }
                Effect::PeerConnected(token, _) | Effect::Deliver(token, _, _) => {
                    queue.push_back((side, Event::Delivered(*token)))
                }
                Effect::StartJob(id, job) => {
                    let result = match job {
                        ContentJob::ReadVolume { root_cid, .. } => {
                            ContentJobResult::Entries(vec![ivy_core::ContentEntry {
                                cid: root_cid.clone(),
                                data: vec![7; 100_000],
                            }])
                        }
                        ContentJob::ReadBundle { root_cid } => {
                            ContentJobResult::Roots(vec![root_cid.clone(), "child".into()])
                        }
                        ContentJob::AuthorizeVolume { .. } => ContentJobResult::Authorized(true),
                    };
                    queue.push_back((side, Event::JobFinished(*id, result)));
                }
                Effect::Close(id) => queue.push_back((!side, Event::Closed(*id))),
                _ => {}
            }
            all.push((side, effect));
        }
    }
    all
}
fn connect(a: &mut Core<TestRandom>, b: &mut Core<TestRandom>, b_config: &Config) {
    a.step(Event::Start, at(0));
    b.step(Event::Start, at(0));
    let out = a.step(
        Event::Request(1, Request::Connect(endpoint(b_config))),
        at(0),
    );
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
    let output = effects(
        a,
        b,
        vec![
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
        ],
        at(0),
    );
    assert_eq!(output.iter().filter(|(side,e)|*side&&matches!(e,Effect::Completed(1,RequestResult::Connected))).count(),1);
}
#[test]
fn deterministic_core_handshake_fragmentation_delivery_and_health() {
    let (ca, cb) = (config(1), config(2));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    assert_eq!(
        a.authenticated_peers()[0].session_id,
        b.authenticated_peers()[0].session_id
    );
    let message = Message::PeerMessage {
        topic: "core".into(),
        payload: vec![7; 1000],
    };
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                2,
                Request::Send {
                    peer: cb.peer_key(),
                    session_id: None,
                    message: message.clone(),
                },
            ),
        )],
        at(1),
    );
    assert!(out
        .iter()
        .any(|(side, e)| !*side && matches!(e,Effect::Deliver(_,_,m) if *m==message)));
    assert_eq!(a.inbound_bytes(), 0);
    assert_eq!(b.inbound_bytes(), 0);
    for time in [60, 120, 180, 240] {
        effects(
            &mut a,
            &mut b,
            vec![(true, Event::Tick), (false, Event::Tick)],
            at(time),
        );
    }
    assert_eq!(a.authenticated_peers().len(), 1);
    assert_eq!(b.authenticated_peers().len(), 1);
}
#[test]
fn cancellation_stop_and_late_dial_do_not_complete_twice() {
    let c = config(1);
    let other = config(2);
    let mut core = Core::new(&c, CoreSettings::default(), TestRandom(1));
    core.step(Event::Start, at(0));
    let out = core.step(Event::Request(5, Request::Connect(endpoint(&other))), at(0));
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
    let cancelled = core.step(Event::Cancel(5), at(1));
    assert_eq!(
        cancelled
            .iter()
            .filter(|e| matches!(e, Effect::Completed(5, RequestResult::Cancelled)))
            .count(),
        1
    );
    assert!(core.step(Event::Cancel(5), at(1)).is_empty());
    let late = core.step(
        Event::ConnectionOpened {
            connection: 1,
            direction: ConnectionDirection::Outbound(dial),
            observed_host: None,
        },
        at(2),
    );
    assert_eq!(late, vec![Effect::Close(1)]);
    core.step(Event::Request(6, Request::Connect(endpoint(&other))), at(3));
    let stop = core.step(Event::Stop, at(3));
    assert_eq!(
        stop.iter()
            .filter(|e| matches!(e, Effect::Completed(6, RequestResult::Cancelled)))
            .count(),
        1
    );
    assert!(core.step(Event::Tick, at(100)).is_empty());
}
#[test]
fn handshake_deadline_and_malformed_frame_close_without_allocation() {
    let c = config(1);
    let mut core = Core::new(&c, CoreSettings::default(), TestRandom(1));
    core.step(Event::Start, at(0));
    core.step(
        Event::ConnectionOpened {
            connection: 1,
            direction: ConnectionDirection::Inbound,
            observed_host: None,
        },
        at(0),
    );
    let out = core.step(Event::Tick, at(30));
    assert!(out.contains(&Effect::Close(1)));
    core.step(
        Event::ConnectionOpened {
            connection: 2,
            direction: ConnectionDirection::Inbound,
            observed_host: None,
        },
        at(31),
    );
    let out = core.step(Event::Received(2, u32::MAX.to_be_bytes().to_vec()), at(31));
    assert!(out.contains(&Effect::Close(2)));
    assert_eq!(core.inbound_bytes(), 0);
}
#[test]
fn send_backpressure_is_observable_and_writability_waiters_complete() {
    let (ca, cb) = (config(1), config(2));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    let request = || Request::Send {
        peer: cb.peer_key(),
        session_id: None,
        message: Message::PeerMessage {
            topic: "bulk".into(),
            payload: vec![0; WRITE_HIGH_WATER_MARK],
        },
    };
    let first = a.step(Event::Request(2, request()), at(1));
    assert!(first.contains(&Effect::Completed(2, RequestResult::Enqueued)));
    let second = a.step(Event::Request(3, request()), at(1));
    assert!(second.contains(&Effect::Completed(3, RequestResult::Backpressured)));
    assert!(a
        .step(
            Event::Request(
                4,
                Request::WaitUntilWritable {
                    peer: cb.peer_key(),
                    session_id: None
                }
            ),
            at(1)
        )
        .is_empty());
    assert_eq!(
        a.step(Event::Writable(10), at(2)),
        vec![Effect::Completed(4, RequestResult::Writable(true))]
    );
}

#[test]
fn exhausted_global_frame_budget_stalls_then_resumes_after_delivery() {
    use ivy_core::{frame, Initiator, Session, MIN_FRAME_SIZE};
    let mut receiver_config = config(9);
    receiver_config.metadata.max_frame_size = MIN_FRAME_SIZE;
    let settings = CoreSettings {
        max_inbound_bytes: MIN_FRAME_SIZE as usize + 4,
        ..CoreSettings::default()
    };
    let mut receiver = Core::new(&receiver_config, settings, TestRandom(9));
    receiver.step(Event::Start, at(0));
    let a = config(1);
    let c = config(3);
    fn attach(
        receiver: &mut Core<TestRandom>,
        local: &Config,
        remote: &Config,
        id: u64,
    ) -> Session {
        receiver.step(
            Event::ConnectionOpened {
                connection: id,
                direction: ConnectionDirection::Inbound,
                observed_host: Some(format!("8.{}.0.1", id)),
            },
            at(0),
        );
        let (initiator, hello) =
            Initiator::start(local, remote.peer_key(), &mut TestRandom(id)).unwrap();
        let effects = receiver.step(Event::Received(id, frame(&hello)), at(0));
        let reply = effects
            .iter()
            .find_map(|e| {
                if let Effect::Write(_, bytes) = e {
                    Some(&bytes[4..])
                } else {
                    None
                }
            })
            .unwrap();
        let (session, finish) = initiator.receive(reply).unwrap();
        let effects = receiver.step(Event::Received(id, frame(&finish)), at(0));
        let token = effects
            .iter()
            .find_map(|e| {
                if let Effect::PeerConnected(token, _) = e {
                    Some(*token)
                } else {
                    None
                }
            })
            .unwrap();
        receiver.step(Event::Delivered(token), at(0));
        session
    }
    let mut sender_a = attach(&mut receiver, &a, &receiver_config, 10);
    let mut sender_c = attach(&mut receiver, &c, &receiver_config, 20);
    let message = Message::PeerMessage {
        topic: "budget".into(),
        payload: vec![42; 40000],
    };
    let first = receiver.step(
        Event::Received(10, frame(&sender_a.seal(&message).unwrap())),
        at(1),
    );
    let token = first
        .iter()
        .find_map(|e| {
            if let Effect::Deliver(token, _, _) = e {
                Some(*token)
            } else {
                None
            }
        })
        .unwrap();
    let second = receiver.step(
        Event::Received(20, frame(&sender_c.seal(&message).unwrap())),
        at(1),
    );
    assert!(second.contains(&Effect::PauseReading(20)));
    assert!(!second
        .iter()
        .any(|e| matches!(e, Effect::Close(_) | Effect::Deliver(..))));
    assert!(receiver.inbound_bytes() <= MIN_FRAME_SIZE as usize);
    let released = receiver.step(Event::Delivered(token), at(2));
    assert!(released
        .iter()
        .any(|e| matches!(e,Effect::Deliver(_,peer,_) if peer.key==c.peer_key())));
    assert!(receiver.inbound_bytes() <= MIN_FRAME_SIZE as usize);
}

#[test]
fn session_bound_volume_and_bundle_fetches_run_source_jobs_and_complete_once() {
    let (ca, cb) = (config(1), config(2));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    b.step(Event::SetContentSource(true), at(0));
    let peer = a.authenticated_peers()[0].clone();
    for (request, bundle) in [(10, false), (11, true)] {
        let out = effects(
            &mut a,
            &mut b,
            vec![(
                true,
                Event::Request(
                    request,
                    Request::FetchVolume {
                        peer: peer.clone(),
                        root_cid: "root".into(),
                        bundle,
                        maximum_archive_bytes: 1024 * 1024,
                        maximum_entries: 100,
                    },
                ),
            )],
            at(1),
        );
        let completed: Vec<_> = out
            .iter()
            .filter_map(|(side, e)| {
                if *side {
                    if let Effect::Completed(id, RequestResult::Volume(response)) = e {
                        (*id == request).then_some(response)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].ended);
        assert_eq!(completed[0].volumes.len(), if bundle { 2 } else { 1 });
        assert_eq!(completed[0].volumes[0].entries[0].data, vec![7; 100_000]);
        assert_eq!(a.inbound_bytes(), 0);
        assert_eq!(b.inbound_bytes(), 0);
    }
    let stale = AuthenticatedPeer {
        session_id: [0; 32],
        ..peer
    };
    let out = a.step(
        Event::Request(
            12,
            Request::FetchVolume {
                peer: stale,
                root_cid: "root".into(),
                bundle: false,
                maximum_archive_bytes: 1024,
                maximum_entries: 100,
            },
        ),
        at(2),
    );
    assert!(out.iter().any(|e|matches!(e,Effect::Completed(12,RequestResult::Volume(response)) if response.failure==Some(ivy_core::VolumeReceiveError::NotSent))));
}

#[test]
fn cancelled_content_job_holds_reservation_until_callback_exits() {
    for termination in 0..3 {
        let (ca, cb) = (config(1), config(2));
        let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
        let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
        connect(&mut a, &mut b, &cb);
        b.step(Event::SetContentSource(true), at(0));
        let sent = a.step(
            Event::Request(
                10,
                Request::Send {
                    peer: cb.peer_key(),
                    session_id: None,
                    message: Message::VolumeRequest {
                        request_id: 99,
                        root_cid: "root".into(),
                    },
                },
            ),
            at(1),
        );
        let wire = sent
            .into_iter()
            .find_map(|e| {
                if let Effect::Write(_, bytes) = e {
                    Some(bytes)
                } else {
                    None
                }
            })
            .unwrap();
        let out = b.step(Event::Received(10, wire), at(1));
        let authorize = out
            .iter()
            .find_map(|e| {
                if let Effect::StartJob(id, ContentJob::AuthorizeVolume { .. }) = e {
                    Some(*id)
                } else {
                    None
                }
            })
            .unwrap();
        let out = b.step(
            Event::JobFinished(authorize, ContentJobResult::Authorized(true)),
            at(1),
        );
        let read = out
            .iter()
            .find_map(|e| {
                if let Effect::StartJob(id, ContentJob::ReadVolume { .. }) = e {
                    Some(*id)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(
            b.content_budget_usage(),
            (0, ivy_core::MAX_VOLUME_ARCHIVE_BYTES, 1)
        );
        let closed = b.step(
            match termination {
                0 => Event::Closed(10),
                1 => Event::Stop,
                _ => Event::Tick,
            },
            at(100),
        );
        assert!(closed.contains(&Effect::CancelJob(read)));
        assert_eq!(
            b.content_budget_usage(),
            (0, ivy_core::MAX_VOLUME_ARCHIVE_BYTES, 1)
        );
        b.step(
            Event::JobFinished(read, ContentJobResult::Entries(Vec::new())),
            at(101),
        );
        assert_eq!(b.content_budget_usage(), (0, 0, 0));
        assert!(b
            .step(
                Event::JobFinished(read, ContentJobResult::Entries(Vec::new())),
                at(101)
            )
            .is_empty());
    }
}

#[test]
fn seeded_core_trace_matches_swift_bodies_with_signature_derived_ids_normalized() {
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
    let expected: Vec<_> = include_str!("fixtures/swift-3.1.1-core-trace.hex")
        .lines()
        .collect();
    assert_eq!(frames.len(), 4);
    assert_eq!(expected.len(), 4);
    // CryptoKit randomizes otherwise valid Ed25519 signatures on macOS.
    // Hello signatures enter the session-ID transcript, so normalize only
    // signatures and their derived session IDs. All other bytes must match.
    for (index, (actual, expected)) in frames.iter().zip(&expected).enumerate() {
        let decode = |s: &str| {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let mut actual = decode(actual);
        let mut expected = decode(expected);
        assert_eq!(actual.len(), expected.len());
        actual.truncate(actual.len() - 64);
        expected.truncate(expected.len() - 64);
        if index >= 2 {
            actual[9..41].fill(0);
            expected[9..41].fill(0);
        }
        assert_eq!(actual, expected, "trace record {index}");
    }
    assert_eq!(&frames[2][18..82], &frames[3][18..82]);
    assert_eq!(&expected[2][18..82], &expected[3][18..82]);
}

#[test]
fn discovery_queries_authenticated_peer_and_completes_once() {
    let (ca, cb) = (config(31), config(32));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    let output = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                72,
                Request::FindNode {
                    target: "root".into(),
                },
            ),
        )],
        at(1),
    );
    let results: Vec<_> = output
        .iter()
        .filter_map(|(side, effect)| match effect {
            Effect::Completed(72, RequestResult::Endpoints(endpoints)) if *side => Some(endpoints),
            _ => None,
        })
        .collect();
    assert_eq!(results, vec![&vec![endpoint(&cb)]]);
    assert!(!output.iter().any(|(_, e)| matches!(e, Effect::Deliver(..))));
}

#[test]
fn discovery_timeout_cancel_and_unmatched_response_do_not_complete_twice() {
    let (ca, cb) = (config(33), config(34));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    a.step(
        Event::Request(
            73,
            Request::FindNode {
                target: "root".into(),
            },
        ),
        at(1),
    );
    let output = effects(
        &mut a,
        &mut b,
        vec![(
            false,
            Event::Request(
                74,
                Request::Send {
                    peer: ca.peer_key(),
                    session_id: None,
                    message: Message::Neighbors {
                        peers: vec![],
                        nonce: 0,
                    },
                },
            ),
        )],
        at(2),
    );
    assert!(!output
        .iter()
        .any(|(side, e)| *side && matches!(e, Effect::Completed(73, ..))));
    let expired = a.step(Event::Tick, at(17));
    assert_eq!(
        expired
            .iter()
            .filter(
                |e| matches!(e, Effect::Completed(73,RequestResult::Endpoints(v)) if v.is_empty())
            )
            .count(),
        1
    );
    assert!(!a
        .step(Event::Cancel(73), at(18))
        .iter()
        .any(|e| matches!(e, Effect::Completed(73, ..))));
    a.step(
        Event::Request(
            75,
            Request::FindNode {
                target: "other".into(),
            },
        ),
        at(19),
    );
    assert!(a
        .step(Event::Cancel(75), at(20))
        .iter()
        .any(|e| matches!(e, Effect::Completed(75, RequestResult::Cancelled))));
    assert!(!a
        .step(Event::Tick, at(40))
        .iter()
        .any(|e| matches!(e, Effect::Completed(75, ..))));
}

#[test]
fn provider_round_shares_walk_and_returns_announced_identity() {
    let (ca, mut cb) = (config(35), config(36));
    cb.metadata.listen_addresses.push(ivy_core::ListenAddress {
        host: "8.8.8.8".into(),
        port: 1234,
    });
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    b.step(
        Event::AnnounceProvider {
            root_cid: "root".into(),
            expires_at: 2000,
        },
        at(0),
    );
    connect(&mut a, &mut b, &cb);
    let output = effects(
        &mut a,
        &mut b,
        vec![
            (
                true,
                Event::Request(
                    81,
                    Request::DiscoverProviders {
                        root_cid: "root".into(),
                    },
                ),
            ),
            (
                true,
                Event::Request(
                    82,
                    Request::DiscoverProviders {
                        root_cid: "root".into(),
                    },
                ),
            ),
        ],
        at(1),
    );
    for id in [81, 82] {
        let results: Vec<_> = output
            .iter()
            .filter_map(|(side, e)| match e {
                Effect::Completed(r, RequestResult::Endpoints(es)) if *side && *r == id => Some(es),
                _ => None,
            })
            .collect();
        assert_eq!(results, vec![&vec![endpoint(&cb)]]);
    }
    let memberships = a.step(
        Event::Request(
            85,
            Request::ProviderMemberships {
                root_cid: "root".into(),
            },
        ),
        at(2),
    );
    assert!(memberships.iter().any(|effect| matches!(effect,
        Effect::Completed(85, RequestResult::ProviderMemberships(keys)) if keys == &vec![(cb.peer_key(), 2000)])));
    b.step(
        Event::StopProviding {
            root_cid: "root".into(),
        },
        at(2),
    );
    // Cached connected peers do not prevent a fresh query; cancelling one
    // waiter leaves the other request's shared walk alive.
    a.step(
        Event::Request(
            83,
            Request::DiscoverProviders {
                root_cid: "root".into(),
            },
        ),
        at(3),
    );
    a.step(
        Event::Request(
            84,
            Request::DiscoverProviders {
                root_cid: "root".into(),
            },
        ),
        at(3),
    );
    assert!(a
        .step(Event::Cancel(83), at(4))
        .iter()
        .any(|e| matches!(e, Effect::Completed(83, RequestResult::Cancelled))));
    a.step(Event::Tick, at(20));
    let ended = a.step(Event::Tick, at(36));
    assert_eq!(
        ended
            .iter()
            .filter(|e| matches!(e, Effect::Completed(84, RequestResult::Endpoints(_))))
            .count(),
        1
    );
    assert!(!ended.iter().any(|e| matches!(e, Effect::Completed(83, ..))));
    let expired = a.step(
        Event::Request(
            86,
            Request::ProviderMemberships {
                root_cid: "root".into(),
            },
        ),
        at(1000),
    );
    assert!(expired.iter().any(|effect| matches!(effect,
        Effect::Completed(86, RequestResult::ProviderMemberships(keys)) if keys.is_empty())));
}

#[test]
fn stop_cancels_provider_waiters_before_internal_walk_completion() {
    let (ca, cb) = (config(41), config(42));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    a.step(
        Event::Request(
            9999,
            Request::DiscoverProviders {
                root_cid: "root".into(),
            },
        ),
        at(1),
    );
    let effects = a.step(Event::Stop, at(2));
    let results: Vec<_> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Completed(9999, result) => Some(result),
            _ => None,
        })
        .collect();
    assert_eq!(results, vec![&RequestResult::Cancelled]);
    assert!(!a
        .step(Event::Tick, at(100))
        .iter()
        .any(|e| matches!(e, Effect::Completed(9999, ..))));
}

#[test]
fn core_rejects_invalid_runtime_limits_before_connecting() {
    let config = config(43);
    let invalid = CoreSettings {
        max_inbound_bytes: config.metadata.max_frame_size as usize,
        ..CoreSettings::default()
    };
    assert!(invalid.validate(&config).is_err());
    let mut core = Core::new(&config, invalid, TestRandom(1));
    core.step(Event::Start, at(0));
    let out = core.step(
        Event::Request(
            1,
            Request::FindNode {
                target: "root".into(),
            },
        ),
        at(0),
    );
    assert_eq!(out, vec![Effect::Completed(1, RequestResult::Failed)]);
    assert!(CoreSettings {
        mode: CoreMode::PrivateNetwork,
        relay_enabled: true,
        ..CoreSettings::default()
    }
    .validate(&config)
    .is_err());
    assert!(CoreSettings {
        health_enabled: false,
        keepalive_interval: Duration::ZERO,
        ..CoreSettings::default()
    }
    .validate(&config)
    .is_ok());
}

#[test]
fn multicandidate_fetch_skips_stale_sessions_and_keeps_last_named_session() {
    let (ca, cb) = (config(61), config(62));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    b.step(Event::SetContentSource(true), at(0));
    let peer = a.authenticated_peers()[0].clone();
    let mut stale = peer.clone();
    stale.session_id = [255; 32];
    let mut unavailable = peer.clone();
    unavailable.key = ca.peer_key();
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                101,
                Request::FetchFromSessions {
                    root_cid: "root".into(),
                    bundle: false,
                    peers: vec![stale.clone(), unavailable, peer.clone()],
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(1),
    );
    let results: Vec<_> = out
        .iter()
        .filter_map(|(side, e)| match e {
            Effect::Completed(101, RequestResult::Volume(r)) if *side => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].volumes.len(), 1);
    assert_eq!(results[0].session_id, Some(peer.session_id));
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                102,
                Request::FetchFromSessions {
                    root_cid: "root".into(),
                    bundle: false,
                    peers: vec![peer, stale],
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(2),
    );
    assert!(out.iter().any(|(side, e)| *side
        && matches!(e,Effect::Completed(102,RequestResult::Volume(r)) if r.volumes.is_empty())));
}

#[test]
fn retrieval_reads_local_first_and_falls_back_to_network_on_miss() {
    let (ca, cb) = (config(71), config(72));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    a.step(Event::SetContentSource(true), at(0));
    b.step(Event::SetContentSource(true), at(0));
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                201,
                Request::RetrieveVolume {
                    root_cid: "root".into(),
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(1),
    );
    assert!(!out.iter().any(|(_, e)| matches!(e, Effect::Write(..))));
    assert!(out.iter().any(|(side,e)|*side && matches!(e,Effect::Completed(201,RequestResult::Volume(r)) if r.volumes.len()==1 && r.served_by.is_none())));
    assert_eq!(a.content_budget_usage(), (0, 0, 0));
    let out = a.step(
        Event::Request(
            202,
            Request::RetrieveVolume {
                root_cid: "other".into(),
                maximum_archive_bytes: 200_000,
                maximum_entries: 10,
            },
        ),
        at(2),
    );
    let job = out
        .iter()
        .find_map(|e| match e {
            Effect::StartJob(job, _) => Some(*job),
            _ => None,
        })
        .unwrap();
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::JobFinished(job, ContentJobResult::Entries(vec![])),
        )],
        at(3),
    );
    assert!(out.iter().any(|(side,e)|*side && matches!(e,Effect::Completed(202,RequestResult::Volume(r)) if r.volumes.len()==1 && r.served_by==Some(cb.peer_key()))));
}

#[test]
fn cancelled_local_read_holds_budget_until_callback_returns() {
    let ca = config(73);
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    a.step(Event::Start, at(0));
    a.step(Event::SetContentSource(true), at(0));
    let out = a.step(
        Event::Request(
            203,
            Request::RetrieveVolume {
                root_cid: "root".into(),
                maximum_archive_bytes: 200_000,
                maximum_entries: 10,
            },
        ),
        at(1),
    );
    let job = out
        .iter()
        .find_map(|e| match e {
            Effect::StartJob(job, _) => Some(*job),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        a.content_budget_usage().1,
        ivy_core::MAX_VOLUME_ARCHIVE_BYTES
    );
    let out = a.step(Event::Cancel(203), at(2));
    assert!(out
        .iter()
        .any(|e| matches!(e,Effect::CancelJob(j) if *j==job)));
    assert_eq!(
        a.content_budget_usage().1,
        ivy_core::MAX_VOLUME_ARCHIVE_BYTES
    );
    let out = a.step(
        Event::JobFinished(job, ContentJobResult::Entries(vec![])),
        at(3),
    );
    assert_eq!(a.content_budget_usage(), (0, 0, 0));
    assert!(!out.iter().any(|e| matches!(e, Effect::Completed(203, ..))));
}

#[test]
fn deficient_content_suppression_expires_without_dropping_the_peer() {
    let (ca, cb) = (config(81), config(82));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    b.step(Event::SetContentSource(true), at(0));
    a.step(
        Event::ReportDeficientContent {
            root_cid: "root".into(),
            served_by: cb.peer_key(),
        },
        at(1),
    );
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                301,
                Request::RetrieveVolume {
                    root_cid: "root".into(),
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(2),
    );
    assert!(!out
        .iter()
        .any(|(side, e)| !*side && matches!(e, Effect::StartJob(..))));
    assert!(out.iter().any(|(side, e)| *side
        && matches!(e,Effect::Completed(301,RequestResult::Volume(r)) if r.volumes.is_empty())));
    assert_eq!(a.authenticated_peers().len(), 1);
    let out = effects(
        &mut a,
        &mut b,
        vec![(
            true,
            Event::Request(
                302,
                Request::RetrieveVolume {
                    root_cid: "root".into(),
                    maximum_archive_bytes: 200_000,
                    maximum_entries: 10,
                },
            ),
        )],
        at(32),
    );
    assert!(out.iter().any(|(side, e)| *side
        && matches!(e,Effect::Completed(302,RequestResult::Volume(r)) if r.volumes.len()==1)));
}

#[test]
fn retrieval_waits_for_per_peer_slot_instead_of_failing_capacity() {
    let (ca, cb) = (config(91), config(92));
    let mut a = Core::new(
        &ca,
        CoreSettings {
            max_outstanding_volume_requests_per_peer: 1,
            ..CoreSettings::default()
        },
        TestRandom(1),
    );
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    b.step(Event::SetContentSource(true), at(0));
    let peer = a.authenticated_peers()[0].clone();
    let requests = (401..403)
        .map(|id| {
            (
                true,
                Event::Request(
                    id,
                    Request::FetchFromSessions {
                        root_cid: format!("root{id}"),
                        bundle: false,
                        peers: vec![peer.clone()],
                        maximum_archive_bytes: 200_000,
                        maximum_entries: 10,
                    },
                ),
            )
        })
        .collect();
    let out = effects(&mut a, &mut b, requests, at(1));
    for id in 401..403 {
        let results: Vec<_> = out
            .iter()
            .filter_map(|(side, e)| match e {
                Effect::Completed(r, RequestResult::Volume(v)) if *side && *r == id => Some(v),
                _ => None,
            })
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].volumes.len(), 1);
        assert_eq!(results[0].failure, None);
    }
    assert_eq!(a.content_budget_usage(), (0, 0, 0));
}

#[test]
fn configured_peers_reconnect_with_backoff_and_stop_cancels_maintenance() {
    let (ca, cb) = (config(101), config(102));
    let settings = CoreSettings {
        bootstrap_peers: vec![endpoint(&cb)],
        health_enabled: false,
        ..CoreSettings::default()
    };
    let mut core = Core::new(&ca, settings, TestRandom(1));
    let first = core.step(Event::Start, at(0));
    let dial = first
        .iter()
        .find_map(|e| match e {
            Effect::Dial(id, _) => Some(*id),
            _ => None,
        })
        .unwrap();
    let stale = AuthenticatedPeer {
        key: cb.peer_key(),
        role: AuthenticatedPeerRole::Endpoint,
        route: AuthenticatedRoute::Direct,
        session_id: [0; 32],
        metadata: cb.metadata.clone(),
    };
    let refused = core.step(Event::Request(900, Request::Disconnect(stale)), at(0));
    assert!(refused.iter().any(|e| matches!(
        e,
        Effect::Completed(900, RequestResult::Disconnected(false))
    )));
    let failed = core.step(Event::DialFailed(dial), at(0));
    assert!(!failed.iter().any(|e| matches!(e, Effect::Completed(..))));
    let deadline = failed
        .iter()
        .find_map(|e| match e {
            Effect::WakeAt(t) => Some(*t),
            _ => None,
        })
        .unwrap();
    assert!((Duration::from_millis(500)..=Duration::from_millis(750)).contains(&deadline));
    let next = core.step(Event::Tick, at(1));
    let dial = next
        .iter()
        .find_map(|e| match e {
            Effect::Dial(id, _) => Some(*id),
            _ => None,
        })
        .unwrap();
    let failed = core.step(Event::DialFailed(dial), at(1));
    let deadline = failed
        .iter()
        .find_map(|e| match e {
            Effect::WakeAt(t) => Some(*t),
            _ => None,
        })
        .unwrap();
    assert!((Duration::from_millis(2000)..=Duration::from_millis(2250)).contains(&deadline));
    core.step(Event::Stop, at(2));
    assert!(!core
        .step(Event::Tick, at(100))
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
    assert!(core
        .step(Event::Start, at(101))
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
}

#[test]
fn caller_request_ids_never_collide_with_background_operations() {
    let (ca, cb) = (config(111), config(112));
    let mut core = Core::new(
        &ca,
        CoreSettings {
            bootstrap_peers: vec![endpoint(&cb)],
            ..CoreSettings::default()
        },
        TestRandom(1),
    );
    core.step(Event::Start, at(0));
    assert_eq!(core.pending_dial_ids().count(), 1);
    let result = core.step(
        Event::Request(
            1,
            Request::FindNode {
                target: "root".into(),
            },
        ),
        at(0),
    );
    assert!(result
        .iter()
        .any(|e| matches!(e,Effect::Completed(1,RequestResult::Endpoints(v)) if v.is_empty())));
    core.step(Event::Cancel(1), at(0));
    assert_eq!(core.pending_dial_ids().count(), 1);
    let result = core.step(
        Event::Request(
            u64::MAX,
            Request::FindNode {
                target: "root".into(),
            },
        ),
        at(0),
    );
    assert!(result.iter().any(
        |e| matches!(e,Effect::Completed(u64::MAX,RequestResult::Endpoints(v)) if v.is_empty())
    ));
}

#[test]
fn discovery_waits_for_complete_query_round_before_refilling_three_slots() {
    let configs: Vec<_> = (120..125).map(config).collect();
    let settings = CoreSettings {
        max_connections_per_netgroup: 8,
        health_enabled: false,
        ..CoreSettings::default()
    };
    let mut nodes: Vec<_> = configs
        .iter()
        .enumerate()
        .map(|(i, c)| Core::new(c, settings.clone(), TestRandom(i as u64 + 1)))
        .collect();
    for node in &mut nodes {
        node.step(Event::Start, at(0));
    }
    for (index, config) in configs.iter().enumerate().skip(1) {
        let conn = 10 + index as u64;
        let started = nodes[0].step(
            Event::Request(index as u64, Request::Connect(endpoint(config))),
            at(0),
        );
        let dial = started
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
                index,
                Event::ConnectionOpened {
                    connection: conn,
                    direction: ConnectionDirection::Inbound,
                    observed_host: Some("8.8.8.8".into()),
                },
            ),
            (
                0,
                Event::ConnectionOpened {
                    connection: conn,
                    direction: ConnectionDirection::Outbound(dial),
                    observed_host: Some("8.8.8.8".into()),
                },
            ),
        ]);
        while let Some((side, event)) = queue.pop_front() {
            for effect in nodes[side].step(event, at(0)) {
                match effect {
                    Effect::Write(id, bytes) => {
                        queue.push_back((
                            if side == 0 { index } else { 0 },
                            Event::Received(id, bytes),
                        ));
                        queue.push_back((side, Event::Writable(id)));
                    }
                    Effect::PeerConnected(token, _) => {
                        queue.push_back((side, Event::Delivered(token)))
                    }
                    _ => {}
                }
            }
        }
    }
    let first = nodes[0].step(
        Event::Request(
            900,
            Request::FindNode {
                target: "rounds".into(),
            },
        ),
        at(1),
    );
    let writes: Vec<_> = first
        .into_iter()
        .filter_map(|e| {
            if let Effect::Write(id, bytes) = e {
                Some((id, bytes))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(writes.len(), 3);
    let mut fourth = None;
    for (turn, (conn, bytes)) in writes.into_iter().enumerate() {
        nodes[0].step(Event::Writable(conn), at(1));
        let index = (conn - 10) as usize;
        for effect in nodes[index].step(Event::Received(conn, bytes), at(1)) {
            if let Effect::Write(_, reply) = effect {
                let output = nodes[0].step(Event::Received(conn, reply), at(1));
                let new_writes: Vec<_> = output
                    .into_iter()
                    .filter_map(|e| {
                        if let Effect::Write(id, bytes) = e {
                            Some((id, bytes))
                        } else {
                            None
                        }
                    })
                    .collect();
                if turn < 2 {
                    assert!(
                        new_writes.is_empty(),
                        "started next round before all replies"
                    );
                } else {
                    assert_eq!(new_writes.len(), 1);
                    fourth = new_writes.into_iter().next();
                }
            }
        }
    }
    let (conn, bytes) = fourth.unwrap();
    let index = (conn - 10) as usize;
    let replies = nodes[index].step(Event::Received(conn, bytes), at(1));
    let mut completed = 0;
    for effect in replies {
        if let Effect::Write(_, reply) = effect {
            completed+=nodes[0].step(Event::Received(conn,reply),at(1)).iter().filter(|e|matches!(e,Effect::Completed(900,RequestResult::Endpoints(peers)) if peers.len()==4)).count();
        }
    }
    assert_eq!(completed, 1);
}

#[test]
fn configured_connections_exhaust_direct_routes_before_backoff_and_cancel_cleanly() {
    let identity = config(91);
    let remote = config(92);
    let first = endpoint(&remote);
    let mut second = first.clone();
    second.host = "1.1.1.1".into();
    let mut core = Core::new(
        &identity,
        CoreSettings {
            bootstrap_peers: vec![first.clone(), second.clone()],
            ..CoreSettings::default()
        },
        TestRandom(1),
    );
    let dial = |effects: &[Effect], expected: &PeerEndpoint| {
        effects
            .iter()
            .find_map(|effect| match effect {
                Effect::Dial(id, endpoint) if endpoint == expected => Some(*id),
                _ => None,
            })
            .expect("expected immediate direct dial")
    };
    let first_id = dial(&core.step(Event::Start, at(0)), &first);
    let second_id = dial(&core.step(Event::DialFailed(first_id), at(0)), &second);
    let exhausted = core.step(Event::DialFailed(second_id), at(0));
    assert!(!exhausted.iter().any(|e| matches!(e, Effect::Dial(..))));
    assert!(!core
        .step(Event::Tick, at(0))
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
    let retry = dial(&core.step(Event::Tick, at(1)), &first);
    core.step(Event::Stop, at(1));
    // A late failed native dial cannot launch a remaining route after shutdown.
    assert!(!core
        .step(Event::DialFailed(retry), at(2))
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
}

#[test]
fn pending_outbound_reserves_netgroup_and_inbound_capacity() {
    let identity = config(98);
    let first = config(99);
    let second = config(100);
    let mut core = Core::new(
        &identity,
        CoreSettings {
            max_inbound_connections: 1,
            max_connections_per_netgroup: 1,
            ..CoreSettings::default()
        },
        TestRandom(1),
    );
    core.step(Event::Start, at(0));
    assert!(core
        .step(Event::Request(1, Request::Connect(endpoint(&first))), at(0))
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
    let blocked = core.step(
        Event::Request(2, Request::Connect(endpoint(&second))),
        at(0),
    );
    assert!(blocked.contains(&Effect::Completed(2, RequestResult::Failed)));
    assert!(!blocked.iter().any(|e| matches!(e, Effect::Dial(..))));
    let incoming = || Event::ConnectionOpened {
        connection: 200,
        direction: ConnectionDirection::Inbound,
        observed_host: Some("9.9.9.9".into()),
    };
    assert!(core.step(incoming(), at(0)).contains(&Effect::Close(200)));
    core.step(Event::Cancel(1), at(0));
    assert!(core.step(incoming(), at(0)).contains(&Effect::Close(200)));
    let dial = core.pending_dial_ids().next().unwrap();
    core.step(Event::DialFailed(dial), at(0));
    let admitted = core.step(incoming(), at(0));
    assert!(admitted.contains(&Effect::ResumeReading(200)));
    assert!(!admitted.contains(&Effect::Close(200)));
}

#[test]
fn restart_configured_does_not_disconnect_unconfigured_session() {
    let (ca, cb) = (config(101), config(102));
    let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
    let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
    connect(&mut a, &mut b, &cb);
    let before = a.authenticated_peers();
    let effects = a.step(Event::RestartConfigured(cb.peer_key()), at(1));
    assert!(!effects
        .iter()
        .any(|e| matches!(e, Effect::Close(_) | Effect::Dial(..))));
    assert_eq!(a.authenticated_peers(), before);
}

#[test]
fn explicit_disconnect_cancels_outbound_and_refuses_late_transport() {
    let local = config(103);
    let remote = config(104);
    let mut core = Core::new(&local, CoreSettings::default(), TestRandom(1));
    core.step(Event::Start, at(0));
    let effects = core.step(
        Event::Request(1, Request::Connect(endpoint(&remote))),
        at(0),
    );
    let dial = effects
        .iter()
        .find_map(|e| {
            if let Effect::Dial(id, _) = e {
                Some(*id)
            } else {
                None
            }
        })
        .unwrap();
    let cancelled = core.step(Event::DisconnectPeer(remote.peer_key()), at(0));
    assert!(!cancelled
        .iter()
        .any(|e| matches!(e, Effect::Completed(1, _))));
    assert_eq!(core.pending_dial_ids().count(), 1);
    let late = core.step(
        Event::ConnectionOpened {
            connection: 300,
            direction: ConnectionDirection::Outbound(dial),
            observed_host: Some("8.8.8.8".into()),
        },
        at(1),
    );
    assert!(late.contains(&Effect::Close(300)));
    assert!(late.contains(&Effect::Completed(1, RequestResult::Cancelled)));
    assert!(!late.iter().any(|e| matches!(e, Effect::Write(..))));
    assert!(core
        .step(
            Event::Request(2, Request::Connect(endpoint(&remote))),
            at(1)
        )
        .iter()
        .any(|e| matches!(e, Effect::Dial(..))));
}

#[test]
fn private_network_broadcast_is_suppressed_but_direct_send_is_available() {
    let (ca, cb) = (config(105), config(106));
    let mut a = Core::new(
        &ca,
        CoreSettings {
            mode: CoreMode::PrivateNetwork,
            ..CoreSettings::default()
        },
        TestRandom(1),
    );
    let mut b = Core::new(
        &cb,
        CoreSettings {
            mode: CoreMode::PrivateNetwork,
            ..CoreSettings::default()
        },
        TestRandom(2),
    );
    connect(&mut a, &mut b, &cb);
    assert!(!a
        .step(
            Event::Broadcast {
                topic: "private".into(),
                payload: vec![1]
            },
            at(1)
        )
        .iter()
        .any(|e| matches!(e, Effect::Write(..))));
    assert!(a
        .step(
            Event::Request(
                2,
                Request::Send {
                    peer: cb.peer_key(),
                    session_id: None,
                    message: Message::PeerMessage {
                        topic: "private".into(),
                        payload: vec![1]
                    }
                }
            ),
            at(1)
        )
        .contains(&Effect::Completed(2, RequestResult::Enqueued)));
}

#[test]
fn verified_responder_holds_disconnect_until_replacement_succeeds_or_fails() {
    for succeeds in [true, false] {
        let (ca, cb) = (config(107), config(108));
        let mut a = Core::new(&ca, CoreSettings::default(), TestRandom(1));
        let mut b = Core::new(&cb, CoreSettings::default(), TestRandom(2));
        connect(&mut a, &mut b, &cb);
        a.step(
            Event::ConnectionOpened {
                connection: 11,
                direction: ConnectionDirection::Inbound,
                observed_host: Some("9.9.9.9".into()),
            },
            at(0),
        );
        let (initiator, hello) =
            ivy_core::Initiator::start_with_nonce(&cb, ca.peer_key(), [0; 32], [77; 32]).unwrap();
        let response = a.step(Event::Received(11, ivy_core::frame(&hello)), at(0));
        let reply = response
            .iter()
            .find_map(|e| {
                if let Effect::Write(11, bytes) = e {
                    Some(bytes)
                } else {
                    None
                }
            })
            .unwrap();
        let (_, finish) = initiator.receive(&reply[4..]).unwrap();
        let closed = a.step(Event::Closed(10), at(0));
        assert!(!closed
            .iter()
            .any(|e| matches!(e, Effect::PeerDisconnected(_))));
        let resolved = a.step(
            if succeeds {
                Event::Received(11, ivy_core::frame(&finish))
            } else {
                Event::Closed(11)
            },
            at(0),
        );
        assert_eq!(
            resolved
                .iter()
                .filter(|e| matches!(e, Effect::PeerDisconnected(_)))
                .count(),
            usize::from(!succeeds)
        );
        assert_eq!(
            resolved
                .iter()
                .filter(|e| matches!(e, Effect::PeerConnected(..)))
                .count(),
            usize::from(succeeds)
        );
        assert!(
            !a.step(Event::Closed(11), at(0))
                .iter()
                .any(|e| matches!(e, Effect::PeerDisconnected(_)))
                || succeeds
        );
    }
}
