use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn application_shutdown_interrupts_backpressure_and_joins_sockets() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pair = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut remote = tokio::net::TcpStream::connect(pair.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = pair.accept().await.unwrap();
        let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[61; 32]));
        let other = Config::new(ed25519_dalek::SigningKey::from_bytes(&[62; 32]));
        let (commands, input) = mpsc::channel(4);
        let (output, mut effects) = mpsc::channel(1);
        let (streams, supplied) = mpsc::channel(1);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_application_with_shutdown(
            listener,
            config,
            CoreSettings::default(),
            input,
            output,
            Some(supplied),
            ivy_core::NullLedger,
            async {
                let _ = stopped.await;
            },
        ));
        streams
            .send(SuppliedStream {
                stream: Box::new(stream),
                direction: SuppliedDirection::Connect {
                    request: 19,
                    endpoint: PeerEndpoint {
                        public_key: other.peer_key().hex(),
                        host: "127.0.0.1".into(),
                        port: 1,
                    },
                },
                observed_host: Some("127.0.0.1".into()),
            })
            .await
            .unwrap();
        assert!(remote.read(&mut [0; 4096]).await.unwrap() > 0);
        for id in 20..24 {
            commands
                .send(Event::Request(
                    id,
                    Request::Connect(PeerEndpoint {
                        public_key: "invalid".into(),
                        host: "127.0.0.1".into(),
                        port: 1,
                    }),
                ))
                .await
                .unwrap();
        }
        while commands.capacity() != 4 || effects.len() != 1 {
            tokio::task::yield_now().await;
        }
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        remote.read_to_end(&mut Vec::new()).await.unwrap();
        assert!(effects.recv().await.is_some());
        assert!(effects.recv().await.is_none());
        // Shutdown returns only after both the listener and active socket close.
        TcpListener::bind(address).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn supplied_streams_preserve_application_request_ids_and_delivery_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let a = Config::new(ed25519_dalek::SigningKey::from_bytes(&[63; 32]));
        let b = Config::new(ed25519_dalek::SigningKey::from_bytes(&[64; 32]));
        let bkey = b.peer_key();
        let mut tasks = Vec::new();
        let mut stops = Vec::new();
        let mut inputs = Vec::new();
        let mut streams = Vec::new();
        let (events, mut incoming) = mpsc::channel(16);
        let mut pumps = JoinSet::new();
        for (index, config) in [a, b].into_iter().enumerate() {
            let (commands, input) = mpsc::channel(8);
            let (output, mut effects) = mpsc::channel(8);
            let (send, supplied) = mpsc::channel(2);
            let (stop, stopped) = tokio::sync::oneshot::channel();
            tasks.push(tokio::spawn(run_application_with_shutdown(
                TcpListener::bind("127.0.0.1:0").await.unwrap(),
                config,
                CoreSettings::default(),
                input,
                output,
                Some(supplied),
                ivy_core::NullLedger,
                async {
                    let _ = stopped.await;
                },
            )));
            let tx = events.clone();
            pumps.spawn(async move {
                while let Some(effect) = effects.recv().await {
                    if tx.send((index, effect)).await.is_err() {
                        break;
                    }
                }
            });
            inputs.push(commands);
            streams.push(send);
            stops.push(stop);
        }
        let (left, right) = tokio::io::duplex(4096);
        streams[1]
            .send(SuppliedStream {
                stream: Box::new(right),
                direction: SuppliedDirection::Inbound,
                observed_host: Some("127.0.0.1".into()),
            })
            .await
            .unwrap();
        streams[0]
            .send(SuppliedStream {
                stream: Box::new(left),
                direction: SuppliedDirection::ConnectWithLocal {
                    request: 9001,
                    endpoint: PeerEndpoint {
                        public_key: bkey.hex(),
                        host: "supplied".into(),
                        port: 0,
                    },
                    local_host: None,
                },
                observed_host: Some("127.0.0.1".into()),
            })
            .await
            .unwrap();
        let mut connected = false;
        let mut peer = None;
        let mut sent = false;
        let mut delivered = false;
        let mut completed = false;
        while !delivered || !completed {
            let (index, effect) = incoming.recv().await.unwrap();
            match effect {
                Effect::PeerConnected(token, value) => {
                    inputs[index].send(Event::Delivered(token)).await.unwrap();
                    if index == 0 {
                        peer = Some(value);
                    }
                }
                Effect::Completed(9001, RequestResult::Connected) => {
                    assert_eq!(index, 0);
                    connected = true;
                }
                Effect::Completed(9002, RequestResult::Enqueued) => {
                    assert_eq!(index, 0);
                    completed = true;
                }
                Effect::Completed(id, result) => {
                    panic!("unexpected application request ID {id}: {result:?}")
                }
                Effect::Deliver(token, _, Message::PeerMessage { topic, payload }) => {
                    assert_eq!(index, 1);
                    assert_eq!(topic, "application");
                    assert_eq!(payload, b"supplied");
                    inputs[index].send(Event::Delivered(token)).await.unwrap();
                    delivered = true;
                }
                _ => {}
            }
            if let (true, Some(peer), false) = (connected, peer.as_ref(), sent) {
                inputs[0]
                    .send(Event::Request(
                        9002,
                        Request::Send {
                            peer: peer.key,
                            session_id: Some(peer.session_id),
                            message: Message::PeerMessage {
                                topic: "application".into(),
                                payload: b"supplied".to_vec(),
                            },
                        },
                    ))
                    .await
                    .unwrap();
                sent = true;
            }
        }
        for stop in stops {
            stop.send(()).unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        pumps.abort_all();
        while pumps.join_next().await.is_some() {}
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn duplicate_active_ids_do_not_replace_cancellation_authority() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (commands, input) = mpsc::channel(16);
        let (output, mut effects) = mpsc::channel(16);
        let (streams, supplied) = mpsc::channel(4);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[65; 32]));
        let other = Config::new(ed25519_dalek::SigningKey::from_bytes(&[66; 32]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(run_application_with_shutdown(
            listener,
            config,
            CoreSettings::default(),
            input,
            output,
            Some(supplied),
            ivy_core::NullLedger,
            async {
                let _ = stopped.await;
            },
        ));
        for (id, supplied_primary) in [(77, true), (80, false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = PeerEndpoint {
                public_key: other.peer_key().hex(),
                host: "127.0.0.1".into(),
                port: address.port(),
            };
            if supplied_primary {
                let outbound = tokio::net::TcpStream::connect(address).await.unwrap();
                streams
                    .send(SuppliedStream {
                        stream: Box::new(outbound),
                        direction: SuppliedDirection::Connect {
                            request: id,
                            endpoint: endpoint.clone(),
                        },
                        observed_host: Some("127.0.0.1".into()),
                    })
                    .await
                    .unwrap();
            } else {
                commands
                    .send(Event::Request(id, Request::Connect(endpoint.clone())))
                    .await
                    .unwrap();
            }
            let (mut remote, _) = listener.accept().await.unwrap();
            assert!(remote.read(&mut [0; 4096]).await.unwrap() > 0);
            let invalid = PeerEndpoint {
                public_key: "invalid".into(),
                host: "127.0.0.1".into(),
                port: 1,
            };
            commands
                .send(Event::Request(id, Request::Connect(invalid.clone())))
                .await
                .unwrap();
            commands
                .send(Event::Request(id + 1, Request::Connect(invalid)))
                .await
                .unwrap();
            loop {
                if let Effect::Completed(done, _) = effects.recv().await.unwrap() {
                    assert_eq!(done, id + 1, "duplicate active command must be ignored");
                    break;
                }
            }
            let (duplicate, mut duplicate_remote) = tokio::io::duplex(4096);
            streams
                .send(SuppliedStream {
                    stream: Box::new(duplicate),
                    direction: SuppliedDirection::Connect {
                        request: id,
                        endpoint,
                    },
                    observed_host: Some("127.0.0.1".into()),
                })
                .await
                .unwrap();
            assert_eq!(
                duplicate_remote.read(&mut [0; 4096]).await.unwrap(),
                0,
                "duplicate supplied stream must close without starting another request"
            );
            commands.send(Event::Cancel(id)).await.unwrap();
            loop {
                if let Effect::Completed(done, result) = effects.recv().await.unwrap() {
                    assert_eq!(done, id);
                    assert_eq!(result, RequestResult::Cancelled);
                    break;
                }
            }
            remote.read_to_end(&mut Vec::new()).await.unwrap();
        }
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        while let Some(effect) = effects.recv().await {
            assert!(
                !matches!(effect, Effect::Completed(..)),
                "duplicate request completion"
            );
        }
    })
    .await
    .unwrap();
}
