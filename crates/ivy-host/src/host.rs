//! Stateful binary host boundary around the Rust event/effect engine.
use crate::{
    codec::{self, Kind, Value},
    configuration::*,
};
use ivy_core::{
    core::*, stun::ObservedAddress, ContentEntry, CoreEntropy, ListenAddress, Message, PeerKey,
    PeerMetadata, VolumeReceiveError,
};
use std::{collections::BTreeMap, time::Duration};
fn n(n: u64) -> Value {
    Value::Unsigned(n)
}
fn s(s: impl Into<String>) -> Value {
    Value::String(s.into())
}
fn b(b: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(b.into())
}
fn t(tag: u8, fields: Vec<Value>) -> Value {
    Value::Tagged { tag, fields }
}
fn f(fields: Vec<Value>) -> Value {
    Value::Fields(fields)
}
fn l(values: Vec<Value>) -> Value {
    Value::List(values)
}
fn o(value: Option<Value>) -> Value {
    Value::Optional(value.map(Box::new))
}
fn key(v: &Value) -> Option<PeerKey> {
    PeerKey::from_hex(string(v)?)
}
fn route_value(route: &AuthenticatedRoute) -> Value {
    match route {
        AuthenticatedRoute::Direct => t(0, vec![]),
        AuthenticatedRoute::Relayed { carrier, route_id } => t(
            1,
            vec![b(carrier.as_bytes().to_vec()), b(route_id.to_vec())],
        ),
    }
}
fn peer_value(peer: &AuthenticatedPeer) -> Value {
    f(vec![
        b(peer.key.as_bytes().to_vec()),
        n(if peer.role == AuthenticatedPeerRole::Endpoint {
            0
        } else {
            1
        }),
        route_value(&peer.route),
        l(peer
            .metadata
            .listen_addresses
            .iter()
            .map(|a| f(vec![s(&a.host), n(a.port as u64)]))
            .collect()),
        n(peer.metadata.max_frame_size as u64),
        b(peer.session_id.to_vec()),
    ])
}
fn peer(value: &Value) -> Option<AuthenticatedPeer> {
    let f = fields(value)?;
    let key = PeerKey::from_bytes(bytes(&f[0])?)?;
    let (tag, r) = tagged(&f[2])?;
    Some(AuthenticatedPeer {
        key,
        role: if unsigned(&f[1])? == 0 {
            AuthenticatedPeerRole::Endpoint
        } else {
            AuthenticatedPeerRole::Carrier
        },
        route: if tag == 0 {
            AuthenticatedRoute::Direct
        } else {
            AuthenticatedRoute::Relayed {
                carrier: PeerKey::from_bytes(bytes(&r[0])?)?,
                route_id: bytes(&r[1])?.try_into().ok()?,
            }
        },
        session_id: bytes(&f[5])?.try_into().ok()?,
        metadata: PeerMetadata {
            listen_addresses: list(&f[3])?
                .iter()
                .map(|v| {
                    let f = fields(v)?;
                    Some(ListenAddress {
                        host: string(&f[0])?.into(),
                        port: unsigned(&f[1])? as u16,
                    })
                })
                .collect::<Option<_>>()?,
            max_frame_size: unsigned(&f[4])? as u32,
        },
    })
}
fn entries(v: &Value) -> Option<Vec<ContentEntry>> {
    list(v)?
        .iter()
        .map(|v| {
            let f = fields(v)?;
            Some(ContentEntry {
                cid: string(&f[0])?.into(),
                data: bytes(&f[1])?.to_vec(),
            })
        })
        .collect()
}
fn entry_values(entries: &[ContentEntry]) -> Value {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| a.cid.as_bytes().cmp(b.cid.as_bytes()));
    l(entries
        .iter()
        .map(|e| f(vec![s(&e.cid), b(e.data.clone())]))
        .collect())
}
fn endpoint_value(e: &ivy_core::PeerEndpoint) -> Value {
    f(vec![s(&e.public_key), s(&e.host), n(e.port as u64)])
}
fn failure(error: Option<VolumeReceiveError>) -> Value {
    o(match error {
        Some(VolumeReceiveError::CallerBoundaryExceeded) => Some(n(0)),
        Some(VolumeReceiveError::LocalCapacityUnavailable) => Some(n(1)),
        Some(VolumeReceiveError::NotSent) => Some(n(2)),
        _ => None,
    })
}
#[derive(Clone)]
enum Expected {
    Connect(u8),
    Send(Option<PeerKey>),
    Writable,
    Volume(String),
    Bundle,
    Endpoints,
    Flag,
}
pub struct Host<'a, R: CoreEntropy> {
    core: Core<'a, R>,
    requests: BTreeMap<u64, Expected>,
    running: bool,
    mode: CoreMode,
    carriers: Vec<PeerKey>,
}
impl<'a, R: CoreEntropy> Host<'a, R> {
    pub fn new(
        config: &'a ivy_core::Config,
        settings: CoreSettings,
        entropy: R,
    ) -> Result<Self, &'static str> {
        settings.validate(config)?;
        Ok(Self {
            mode: settings.mode,
            carriers: settings
                .carriers
                .iter()
                .filter_map(|e| PeerKey::from_hex(&e.public_key))
                .collect(),
            core: Core::new(config, settings, entropy),
            requests: BTreeMap::new(),
            running: false,
        })
    }
    pub fn connected_peers(&self) -> Vec<AuthenticatedPeer> {
        self.core.authenticated_peers()
    }
    pub fn encoded_connected_peers(&self) -> Vec<u8> {
        let mut peers = self.core.endpoint_peers();
        peers.sort_by_key(|p| p.key);
        codec::encode(
            Kind::Peers,
            &l(peers.iter().map(|p| s(p.key.hex())).collect()),
        )
        .expect("valid peer list")
    }
    pub fn encoded_connected_endpoints(&self) -> Vec<u8> {
        codec::encode(
            Kind::Endpoints,
            &l(self
                .core
                .connected_peer_endpoints()
                .iter()
                .map(endpoint_value)
                .collect()),
        )
        .expect("valid endpoint list")
    }
    pub fn encoded_known_endpoints(&self) -> Vec<u8> {
        codec::encode(
            Kind::Endpoints,
            &l(self
                .core
                .known_peer_endpoints()
                .iter()
                .map(endpoint_value)
                .collect()),
        )
        .expect("valid endpoint list")
    }
    pub fn encoded_providers(&mut self, root: &str) -> Vec<u8> {
        codec::encode(
            Kind::Peers,
            &l(self
                .core
                .providers(root)
                .iter()
                .map(|k| s(k.hex()))
                .collect()),
        )
        .expect("valid provider list")
    }
    pub fn public_address(&self) -> Option<&ObservedAddress> {
        self.core.public_address()
    }
    pub fn step(&mut self, encoded: &[u8], now: Timestamp) -> Option<Vec<u8>> {
        let value = codec::decode(Kind::Event, encoded)?;
        let (tag, v) = tagged(&value)?;
        let event = match tag {
            0 => {
                self.running = true;
                Event::Start
            }
            1 => {
                self.running = false;
                Event::Stop
            }
            2 => Event::Tick,
            3 => {
                let (d, f) = tagged(&v[1])?;
                Event::ConnectionOpenedWithLocal {
                    connection: unsigned(&v[0])?,
                    direction: if d == 0 {
                        ConnectionDirection::Inbound
                    } else {
                        ConnectionDirection::Outbound(unsigned(&f[0])?)
                    },
                    observed_host: optional(&v[2])?
                        .map(string)
                        .transpose_option()?
                        .map(str::to_owned),
                    local_host: optional(&v[3])?
                        .map(string)
                        .transpose_option()?
                        .map(str::to_owned),
                }
            }
            4 => Event::DialFailed(unsigned(&v[0])?),
            5 => Event::Received(unsigned(&v[0])?, bytes(&v[1])?.to_vec()),
            6 => Event::Writable(unsigned(&v[0])?),
            7 => Event::Closed(unsigned(&v[0])?),
            8 => {
                let id = unsigned(&v[0])?;
                if self.requests.contains_key(&id) {
                    return self.encode_effects(vec![]);
                }
                let (tag, r) = tagged(&v[1])?;
                let expected = match tag {
                    0..=2 => {
                        let endpoint = endpoint(&r[0])?;
                        let key = PeerKey::from_hex(&endpoint.public_key);
                        let error = if key.is_none() {
                            1
                        } else if key.is_some_and(|k| {
                            !self.mode.allows_endpoint(k) && !self.carriers.contains(&k)
                        }) {
                            2
                        } else if !self.running {
                            0
                        } else if tag == 1
                            && optional(&r[2])?.and_then(string).is_none_or(str::is_empty)
                        {
                            6
                        } else if tag == 2 {
                            5
                        } else {
                            4
                        };
                        Expected::Connect(error)
                    }
                    3 => Expected::Send(key(&r[0])),
                    4 => Expected::Send(peer(&r[0]).map(|p| p.key)),
                    5 | 6 => Expected::Writable,
                    7 => Expected::Volume(string(&r[0])?.into()),
                    8 => Expected::Volume(string(&r[1])?.into()),
                    9 => Expected::Bundle,
                    10 | 11 => Expected::Endpoints,
                    12 | 13 => Expected::Flag,
                    14 => Expected::Volume(string(&r[1])?.into()),
                    _ => return None,
                };
                self.requests.insert(id, expected);
                let request = convert_request(tag, r);
                let Some(request) = request else {
                    return self.synthetic(
                        id,
                        if matches!(tag, 0..=2) {
                            RequestResult::Failed
                        } else {
                            RequestResult::NotConnected
                        },
                    );
                };
                Event::Request(id, request)
            }
            9 => Event::Cancel(unsigned(&v[0])?),
            10 => {
                let (tag, c) = tagged(&v[0])?;
                let key_field = match tag {
                    0 | 1 | 6 => Some(&c[0]),
                    4 => Some(&c[1]),
                    _ => None,
                };
                if key_field.is_some_and(|value| key(value).is_none()) {
                    return self.encode_effects(vec![]);
                }
                match tag {
                    0 => Event::DisconnectPeer(key(&c[0])?),
                    1 => Event::RestartConfigured(key(&c[0])?),
                    2 => Event::Broadcast {
                        topic: string(&c[0])?.into(),
                        payload: bytes(&c[1])?.to_vec(),
                    },
                    3 => Event::AnnounceProvider {
                        root_cid: string(&c[0])?.into(),
                        expires_at: unsigned(&c[1])?,
                    },
                    4 => Event::ReportDeficientContent {
                        root_cid: string(&c[0])?.into(),
                        served_by: key(&c[1])?,
                    },
                    5 => Event::SetContentSource(boolean(&c[0])?),
                    6 => Event::SetRelaying {
                        peer: key(&c[0])?,
                        relays: boolean(&c[1])?,
                    },
                    7 => Event::StopProviding {
                        root_cid: string(&c[0])?.into(),
                    },
                    _ => return None,
                }
            }
            11 => Event::Delivered(unsigned(&v[0])?),
            12 => {
                let (tag, j) = tagged(&v[1])?;
                Event::JobFinished(
                    unsigned(&v[0])?,
                    match tag {
                        0 => ContentJobResult::Entries(entries(&j[0])?),
                        1 => ContentJobResult::Roots(
                            list(&j[0])?
                                .iter()
                                .map(|v| string(v).map(str::to_owned))
                                .collect::<Option<_>>()?,
                        ),
                        2 => ContentJobResult::Authorized(boolean(&j[0])?),
                        _ => return None,
                    },
                )
            }
            13 => Event::PublicAddress(
                optional(&v[0])?
                    .map(|a| {
                        let a = fields(a)?;
                        Some(ObservedAddress {
                            host: string(&a[0])?.into(),
                            port: unsigned(&a[1])? as u16,
                        })
                    })
                    .transpose_option()?,
            ),
            _ => return None,
        };
        let effects = self.core.step(event, now);
        self.encode_effects(effects)
    }
    fn synthetic(&mut self, id: u64, result: RequestResult) -> Option<Vec<u8>> {
        self.encode_effects(vec![Effect::Completed(id, result)])
    }
    fn encode_effects(&mut self, effects: Vec<Effect>) -> Option<Vec<u8>> {
        let mut values = Vec::new();
        for effect in effects {
            values.push(match effect {
                Effect::Dial(id, endpoint) => t(0, vec![n(id), endpoint_value(&endpoint)]),
                Effect::Write(id, bytes) => t(1, vec![n(id), b(bytes)]),
                Effect::Close(id) => t(2, vec![n(id)]),
                Effect::PauseReading(id) => t(3, vec![n(id)]),
                Effect::ResumeReading(id) => t(4, vec![n(id)]),
                Effect::Deliver(token, peer, Message::PeerMessage { topic, payload }) => {
                    t(5, vec![n(token), peer_value(&peer), s(topic), b(payload)])
                }
                Effect::Deliver(..) => return None,
                Effect::PeerConnected(token, peer) => t(6, vec![n(token), peer_value(&peer)]),
                Effect::PeerDisconnected(key) => t(7, vec![s(key.hex())]),
                Effect::PublicAddressDiscovered(address) => {
                    t(8, vec![f(vec![s(address.host), n(address.port as u64)])])
                }
                Effect::Completed(id, result) => {
                    let expected = self.requests.remove(&id)?;
                    t(9, vec![n(id), self.result(expected, result)])
                }
                Effect::StartJob(id, job) => t(
                    10,
                    vec![
                        n(id),
                        match job {
                            ContentJob::ReadVolume {
                                root_cid,
                                max_data_bytes,
                            } => t(
                                0,
                                vec![
                                    s(root_cid),
                                    Value::Signed(max_data_bytes.min(i64::MAX as usize) as i64),
                                ],
                            ),
                            ContentJob::ReadBundle { root_cid } => t(1, vec![s(root_cid)]),
                            ContentJob::AuthorizeVolume { peer, root_cid } => {
                                t(2, vec![peer_value(&peer), s(root_cid)])
                            }
                        },
                    ],
                ),
                Effect::CancelJob(id) => t(11, vec![n(id)]),
                Effect::DiscoverPublicAddress => t(12, vec![]),
                Effect::WakeAt(at) => t(13, vec![duration_value(at)]),
            });
        }
        codec::encode(Kind::Effects, &l(values))
    }
    fn result(&self, expected: Expected, result: RequestResult) -> Value {
        match expected {
            Expected::Connect(error) => t(
                0,
                vec![match result {
                    RequestResult::Connected => t(0, vec![]),
                    RequestResult::ConnectFailed(error) => t(1, vec![n(error as u64)]),
                    RequestResult::ConnectionInProgress => t(1, vec![n(3)]),
                    RequestResult::NoRelayAvailable => t(1, vec![n(5)]),
                    RequestResult::Cancelled => t(2, vec![]),
                    _ => t(1, vec![n(error as u64)]),
                }],
            ),
            Expected::Send(key) => t(
                1,
                vec![match result {
                    RequestResult::Enqueued => t(
                        0,
                        vec![
                            s(key.map(|k| k.hex()).unwrap_or_default()),
                            route_value(
                                &self
                                    .core
                                    .authenticated_peers()
                                    .iter()
                                    .find(|p| Some(p.key) == key)
                                    .map(|p| p.route.clone())
                                    .unwrap_or(AuthenticatedRoute::Direct),
                            ),
                        ],
                    ),
                    RequestResult::Backpressured => t(1, vec![]),
                    RequestResult::LocallyRejected => t(3, vec![]),
                    _ => t(2, vec![]),
                }],
            ),
            Expected::Writable => t(
                2,
                vec![Value::Bool(matches!(result, RequestResult::Writable(true)))],
            ),
            Expected::Flag => t(
                6,
                vec![Value::Bool(matches!(
                    result,
                    RequestResult::Disconnected(true)
                ))],
            ),
            Expected::Endpoints => t(
                5,
                vec![l(if let RequestResult::Endpoints(e) = result {
                    e.iter().map(endpoint_value).collect()
                } else {
                    vec![]
                })],
            ),
            Expected::Volume(root) => {
                let (entries, served, error) = if let RequestResult::Volume(response) = result {
                    (
                        response
                            .volumes
                            .first()
                            .map(|v| entry_values(&v.entries))
                            .unwrap_or_else(|| l(vec![])),
                        response.served_by,
                        response.failure,
                    )
                } else {
                    (l(vec![]), None, Some(VolumeReceiveError::NotSent))
                };
                t(
                    3,
                    vec![f(vec![
                        s(root),
                        entries,
                        o(served.map(|k| s(k.hex()))),
                        failure(error),
                    ])],
                )
            }
            Expected::Bundle => {
                if let RequestResult::Volume(response) = result {
                    t(
                        4,
                        vec![
                            l(response
                                .volumes
                                .iter()
                                .map(|v| {
                                    f(vec![
                                        s(&v.root_cid),
                                        entry_values(&v.entries),
                                        o(response.served_by.map(|k| s(k.hex()))),
                                        failure(None),
                                    ])
                                })
                                .collect()),
                            Value::Bool(response.no_bundle),
                            Value::Bool(response.ended),
                            failure(response.failure),
                        ],
                    )
                } else {
                    t(
                        4,
                        vec![
                            l(vec![]),
                            Value::Bool(false),
                            Value::Bool(false),
                            failure(Some(VolumeReceiveError::NotSent)),
                        ],
                    )
                }
            }
        }
    }
}
fn duration_value(value: Duration) -> Value {
    f(vec![
        Value::Signed(value.as_secs().min(i64::MAX as u64) as i64),
        Value::Signed(value.subsec_nanos() as i64 * 1_000_000_000),
    ])
}
fn convert_request(tag: u8, r: &[Value]) -> Option<Request> {
    Some(match tag {
        0 => Request::Connect(endpoint(&r[0])?),
        1 => Request::ConnectOverWithLocal {
            endpoint: endpoint(&r[0])?,
            connection: unsigned(&r[1])?,
            observed_host: optional(&r[2])?
                .map(string)
                .transpose_option()?
                .map(str::to_owned),
            local_host: optional(&r[3])?
                .map(string)
                .transpose_option()?
                .map(str::to_owned),
        },
        2 => Request::ConnectViaAnyRelay(PeerKey::from_hex(&endpoint(&r[0])?.public_key)?),
        3 => Request::Send {
            peer: key(&r[0])?,
            session_id: None,
            message: Message::PeerMessage {
                topic: string(&r[1])?.into(),
                payload: bytes(&r[2])?.to_vec(),
            },
        },
        4 => {
            let peer = peer(&r[0])?;
            Request::Send {
                peer: peer.key,
                session_id: Some(peer.session_id),
                message: Message::PeerMessage {
                    topic: string(&r[1])?.into(),
                    payload: bytes(&r[2])?.to_vec(),
                },
            }
        }
        5 => Request::WaitUntilWritable {
            peer: key(&r[0])?,
            session_id: None,
        },
        6 => {
            let peer = peer(&r[0])?;
            Request::WaitUntilWritable {
                peer: peer.key,
                session_id: Some(peer.session_id),
            }
        }
        7 => Request::RetrieveVolume {
            root_cid: string(&r[0])?.into(),
            maximum_archive_bytes: size(&r[1])?,
            maximum_entries: size(&r[2])?.min(u16::MAX as usize) as u16,
        },
        8 => Request::FetchVolume {
            peer: peer(&r[0])?,
            root_cid: string(&r[1])?.into(),
            bundle: false,
            maximum_archive_bytes: size(&r[2])?,
            maximum_entries: size(&r[3])?.min(u16::MAX as usize) as u16,
        },
        9 => Request::FetchFromSessions {
            root_cid: string(&r[0])?.into(),
            bundle: true,
            peers: list(&r[1])?.iter().map(peer).collect::<Option<_>>()?,
            maximum_archive_bytes: usize::MAX,
            maximum_entries: u16::MAX,
        },
        10 => Request::FindNode {
            target: string(&r[0])?.into(),
        },
        11 => Request::DiscoverProviders {
            root_cid: string(&r[0])?.into(),
        },
        12 => Request::Recycle(peer(&r[0])?),
        13 => Request::Disconnect(peer(&r[0])?),
        14 => Request::FetchFromSessions {
            peers: list(&r[0])?.iter().map(peer).collect::<Option<_>>()?,
            root_cid: string(&r[1])?.into(),
            bundle: false,
            maximum_archive_bytes: size(&r[2])?,
            maximum_entries: size(&r[3])?.min(u16::MAX as usize) as u16,
        },
        _ => return None,
    })
}
trait TransposeOption<T> {
    fn transpose_option(self) -> Option<Option<T>>;
}
impl<T> TransposeOption<T> for Option<Option<T>> {
    fn transpose_option(self) -> Option<Option<T>> {
        match self {
            None => Some(None),
            Some(Some(v)) => Some(Some(v)),
            Some(None) => None,
        }
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    #[test]
    fn stopped_connect_validates_key_and_mode_before_running_state() {
        let config = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[6; 32]));
        let allowed = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let excluded = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
        let mut host = Host::new(
            &config,
            CoreSettings {
                mode: ivy_core::core::CoreMode::Pinned(allowed.peer_key()),
                ..CoreSettings::default()
            },
            ivy_core::SimulationRandom::seeded(1),
        )
        .unwrap();
        for (id, public_key, error) in [
            (1, "invalid".into(), 1),
            (2, excluded.peer_key().hex(), 2),
            (3, allowed.peer_key().hex(), 0),
        ] {
            let endpoint = endpoint_value(&ivy_core::PeerEndpoint {
                public_key,
                host: "8.8.8.8".into(),
                port: 4001,
            });
            let event =
                codec::encode(Kind::Event, &t(8, vec![n(id), t(0, vec![endpoint])])).unwrap();
            let effects = host.step(&event, Timestamp::default()).unwrap();
            assert_eq!(
                codec::decode(Kind::Effects, &effects),
                Some(l(vec![t(9, vec![n(id), t(0, vec![t(1, vec![n(error)])])])]))
            );
        }
    }
    #[test]
    fn duplicate_request_preserves_original_result_shape_and_invalid_command_is_noop() {
        let config = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[4; 32]));
        let remote = ivy_core::Config::new(ed25519_dalek::SigningKey::from_bytes(&[5; 32]));
        let mut host = Host::new(
            &config,
            CoreSettings::default(),
            ivy_core::SimulationRandom::seeded(1),
        )
        .unwrap();
        let now = Timestamp::default();
        let event = |value: Value| codec::encode(Kind::Event, &value).unwrap();
        host.step(&event(t(0, vec![])), now).unwrap();
        host.step(
            &event(t(
                8,
                vec![
                    n(42),
                    t(
                        0,
                        vec![endpoint_value(&ivy_core::PeerEndpoint {
                            public_key: remote.peer_key().hex(),
                            host: "8.8.8.8".into(),
                            port: 4001,
                        })],
                    ),
                ],
            )),
            now,
        )
        .unwrap();
        let duplicate = host
            .step(&event(t(8, vec![n(42), t(10, vec![s("root")])])), now)
            .unwrap();
        assert_eq!(codec::decode(Kind::Effects, &duplicate), Some(l(vec![])));
        let cancelled = host.step(&event(t(9, vec![n(42)])), now).unwrap();
        assert_eq!(
            codec::decode(Kind::Effects, &cancelled),
            Some(l(vec![t(9, vec![n(42), t(0, vec![t(2, vec![])])])]))
        );
        let ignored = host
            .step(&event(t(10, vec![t(0, vec![s("not-a-key")])])), now)
            .unwrap();
        assert_eq!(codec::decode(Kind::Effects, &ignored), Some(l(vec![])));
    }
}
