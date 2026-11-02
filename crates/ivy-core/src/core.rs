//! Deterministic direct-session event/effect runtime. Time and cryptographic
//! entropy are injected. The shell owns sockets and acknowledges deliveries.
mod content;
mod discovery;
mod records;
mod relay;
mod retrieval;
mod topology;
pub use crate::stun::ObservedAddress;
use crate::CoreEntropy;
use crate::{
    frame, frame_length, net_group, AwaitingFinish, Config, Initiator, Message, PeerEndpoint,
    PeerKey, PeerMetadata, Responder, Router, Session,
};
pub use content::{ContentJob, ContentJobResult, JobId};
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;
pub type ConnectionId = u64;
pub type RequestId = u64;
pub type DialId = u64;
pub type DeliveryToken = u64;
pub const WRITE_HIGH_WATER_MARK: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub uptime: Duration,
    pub unix_seconds: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticatedPeerRole {
    Endpoint,
    Carrier,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticatedRoute {
    Direct,
    Relayed {
        carrier: PeerKey,
        route_id: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub role: AuthenticatedPeerRole,
    pub route: AuthenticatedRoute,
    pub key: PeerKey,
    pub session_id: [u8; 32],
    pub metadata: PeerMetadata,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CoreMode {
    #[default]
    Overlay,
    PrivateNetwork,
    Pinned(PeerKey),
}
impl CoreMode {
    pub fn participates_in_public_discovery(self) -> bool {
        matches!(self, Self::Overlay)
    }
    pub fn uses_overlay_services(self) -> bool {
        !matches!(self, Self::PrivateNetwork)
    }
    pub fn allows_endpoint(self, key: PeerKey) -> bool {
        match self {
            Self::Pinned(expected) => key == expected,
            _ => true,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderReach {
    #[default]
    Walk,
    ConnectedPeers,
}
#[derive(Clone, Debug)]
pub struct CoreSettings {
    pub mode: CoreMode,
    /// None keeps explicit Config metadata; Some derives per-link advertisements.
    pub listen_port: Option<u16>,
    pub relay_enabled: bool,
    pub stun_servers: Vec<(String, u16)>,
    pub external_address: Option<ObservedAddress>,
    pub carriers: Vec<PeerEndpoint>,
    pub bootstrap_peers: Vec<PeerEndpoint>,
    pub relay_timeout: Duration,
    pub private_content_exchange_enabled: bool,
    pub max_connections: usize,
    pub reserved_outbound_connection_slots: usize,
    pub max_provider_walk_sessions: usize,
    pub provider_reach: ProviderReach,
    pub routing_refresh_interval: Duration,
    pub max_inbound_connections: usize,
    pub max_connections_per_netgroup: usize,
    pub max_inbound_bytes: usize,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Duration,
    pub stale_timeout: Duration,
    pub max_missed_pongs: u32,
    pub health_enabled: bool,
    pub bucket_size: usize,
    pub max_pending_requests: usize,
    pub max_concurrent_content_requests: usize,
    pub max_content_candidates: usize,
    pub max_outstanding_volume_requests_per_peer: usize,
    pub max_in_flight_volume_bytes: usize,
    pub request_timeout: Duration,
    pub max_routes_per_identity: usize,
    pub max_provider_records_per_peer: usize,
    pub max_provider_ttl_seconds: u64,
}
impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            mode: CoreMode::Overlay,
            listen_port: None,
            relay_enabled: false,
            stun_servers: vec![],
            external_address: None,
            carriers: vec![],
            bootstrap_peers: vec![],
            relay_timeout: Duration::from_secs(5),
            private_content_exchange_enabled: false,
            max_connections: 256,
            reserved_outbound_connection_slots: 0,
            max_provider_walk_sessions: 64,
            provider_reach: ProviderReach::Walk,
            routing_refresh_interval: Duration::from_secs(120),
            max_inbound_connections: 256,
            max_connections_per_netgroup: 2,
            max_inbound_bytes: 64 * 1024 * 1024,
            handshake_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(60),
            stale_timeout: Duration::from_secs(180),
            max_missed_pongs: 3,
            health_enabled: true,
            bucket_size: 20,
            max_pending_requests: 4096,
            max_concurrent_content_requests: 64,
            max_content_candidates: 8,
            max_outstanding_volume_requests_per_peer: 16,
            max_in_flight_volume_bytes: 128 * 1024 * 1024,
            request_timeout: Duration::from_secs(15),
            max_routes_per_identity: 3,
            max_provider_records_per_peer: 1024,
            max_provider_ttl_seconds: 86400,
        }
    }
}
impl CoreSettings {
    /// Validate all currently implemented runtime limits before opening sockets.
    pub fn validate(&self, config: &Config) -> Result<(), &'static str> {
        if self.reserved_outbound_connection_slots > self.max_connections
            || self.routing_refresh_interval.is_zero()
        {
            return Err("invalid routing/admission limits");
        }
        if self.max_connections == 0
            || self.max_connections_per_netgroup == 0
            || self.max_pending_requests == 0
            || self.max_concurrent_content_requests == 0
            || self.max_content_candidates == 0
            || self.max_outstanding_volume_requests_per_peer == 0
        {
            return Err("capacity limits must be positive");
        }
        if self.max_inbound_bytes < (config.metadata.max_frame_size as usize).saturating_add(4) {
            return Err("inbound budget must hold one maximum frame and header");
        }
        if self.max_routes_per_identity == 0
            || self.max_provider_ttl_seconds == 0
            || self.max_provider_records_per_peer == 0
            || self.max_in_flight_volume_bytes == 0
            || config.metadata.max_frame_size < crate::MIN_FRAME_SIZE
        {
            return Err("invalid route, provider, volume or frame limit");
        }
        if config.min_peer_key_bits > 256
            || !(1..=crate::wire::MAX_NEIGHBOR_COUNT).contains(&self.bucket_size)
            || self.request_timeout == Duration::ZERO
            || self.relay_timeout == Duration::ZERO
            || self.handshake_timeout == Duration::ZERO
        {
            return Err("invalid routing or timeout limit");
        }
        if self.health_enabled
            && (self.keepalive_interval == Duration::ZERO
                || self.stale_timeout <= self.keepalive_interval
                || self.max_missed_pongs == 0)
        {
            return Err("invalid peer health limits");
        }
        if self.mode == CoreMode::PrivateNetwork && self.relay_enabled {
            return Err("private network does not support relay transport");
        }
        if self.mode == CoreMode::Pinned(config.peer_key()) {
            return Err("local identity cannot also be pinned peer");
        }
        let mut carriers = std::collections::BTreeSet::new();
        for endpoint in &self.carriers {
            let key = PeerKey::from_hex(&endpoint.public_key).ok_or("invalid carrier key")?;
            if key == config.peer_key()
                || !carriers.insert(key)
                || self.mode == CoreMode::Pinned(key)
            {
                return Err("carrier identity role collision");
            }
            if endpoint.port == 0 || endpoint.host.is_empty() {
                return Err("invalid carrier endpoint");
            }
        }
        if self.mode == CoreMode::PrivateNetwork && !carriers.is_empty() {
            return Err("private network does not support carriers");
        }
        for endpoint in &self.bootstrap_peers {
            let key = PeerKey::from_hex(&endpoint.public_key).ok_or("invalid bootstrap key")?;
            if key == config.peer_key()
                || carriers.contains(&key)
                || !self.mode.allows_endpoint(key)
            {
                return Err("bootstrap identity role collision");
            }
            if endpoint.port == 0 || endpoint.host.is_empty() {
                return Err("invalid bootstrap endpoint");
            }
        }
        if self
            .external_address
            .as_ref()
            .is_some_and(|a| a.port == 0 || a.host.parse::<std::net::IpAddr>().is_err())
        {
            return Err("external address must be an IP literal and nonzero port");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound(DialId),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Connect(PeerEndpoint),
    ConnectOverWithLocal {
        endpoint: PeerEndpoint,
        connection: ConnectionId,
        observed_host: Option<String>,
        local_host: Option<String>,
    },
    ConnectOver {
        endpoint: PeerEndpoint,
        connection: ConnectionId,
        observed_host: Option<String>,
    },
    ConnectViaAnyRelay(PeerKey),
    ConnectViaRelay {
        carrier: AuthenticatedPeer,
        target: PeerKey,
    },
    DiscoverProviders {
        root_cid: String,
    },
    /// Snapshot of authenticated, unexpired provider cache memberships.
    ProviderMemberships {
        root_cid: String,
    },
    FindNode {
        target: String,
    },
    Send {
        peer: PeerKey,
        session_id: Option<[u8; 32]>,
        message: Message,
    },
    WaitUntilWritable {
        peer: PeerKey,
        session_id: Option<[u8; 32]>,
    },
    Disconnect(AuthenticatedPeer),
    Recycle(AuthenticatedPeer),
    RetrieveVolume {
        root_cid: String,
        maximum_archive_bytes: usize,
        maximum_entries: u16,
    },
    FetchFromSessions {
        root_cid: String,
        bundle: bool,
        peers: Vec<AuthenticatedPeer>,
        maximum_archive_bytes: usize,
        maximum_entries: u16,
    },
    FetchVolume {
        peer: AuthenticatedPeer,
        root_cid: String,
        bundle: bool,
        maximum_archive_bytes: usize,
        maximum_entries: u16,
    },
}
/// Swift IvyError wire discriminants, preserved across Core and host adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectError {
    NotRunning = 0,
    InvalidPeerKey = 1,
    PeerOutsideMode = 2,
    ConnectionInProgress = 3,
    IdentityVerificationFailed = 4,
    NoRelayAvailable = 5,
    StreamHasNoObservedHost = 6,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestResult {
    /// Specific connection refusal; `Failed` remains identity-verification failure.
    ConnectFailed(ConnectError),
    Connected,
    ConnectionInProgress,
    NoRelayAvailable,
    Failed,
    Cancelled,
    Enqueued,
    Backpressured,
    LocallyRejected,
    NotConnected,
    Writable(bool),
    Disconnected(bool),
    Volume(crate::VolumeResponse),
    Endpoints(Vec<PeerEndpoint>),
    ProviderMemberships(Vec<(PeerKey, u64)>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Start,
    Stop,
    RestartConfigured(PeerKey),
    DisconnectPeer(PeerKey),
    Broadcast {
        topic: String,
        payload: Vec<u8>,
    },
    PublicAddress(Option<ObservedAddress>),
    SetRelaying {
        peer: PeerKey,
        relays: bool,
    },
    Tick,
    ConnectionOpenedWithLocal {
        connection: ConnectionId,
        direction: ConnectionDirection,
        observed_host: Option<String>,
        local_host: Option<String>,
    },
    ConnectionOpened {
        connection: ConnectionId,
        direction: ConnectionDirection,
        observed_host: Option<String>,
    },
    DialFailed(DialId),
    Received(ConnectionId, Vec<u8>),
    Writable(ConnectionId),
    Closed(ConnectionId),
    Request(RequestId, Request),
    Cancel(RequestId),
    Delivered(DeliveryToken),
    SetContentSource(bool),
    AnnounceProvider {
        root_cid: String,
        expires_at: u64,
    },
    ReportDeficientContent {
        root_cid: String,
        served_by: PeerKey,
    },
    StopProviding {
        root_cid: String,
    },
    JobFinished(JobId, ContentJobResult),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Dial(DialId, PeerEndpoint),
    Write(ConnectionId, Vec<u8>),
    Close(ConnectionId),
    PauseReading(ConnectionId),
    ResumeReading(ConnectionId),
    PeerConnected(DeliveryToken, AuthenticatedPeer),
    PeerDisconnected(PeerKey),
    DiscoverPublicAddress,
    PublicAddressDiscovered(ObservedAddress),
    Deliver(DeliveryToken, AuthenticatedPeer, Message),
    Completed(RequestId, RequestResult),
    WakeAt(Duration),
    StartJob(JobId, ContentJob),
    CancelJob(JobId),
}
enum Handshake<'a> {
    Incoming,
    Initiating(Initiator<'a>),
    Finishing(AwaitingFinish<'a>),
    Established(Box<Session>),
}
struct Link<'a> {
    local_host: Option<String>,
    role: AuthenticatedPeerRole,
    route: Option<relay::RelayLink>,
    state: Option<Handshake<'a>>,
    endpoint: Option<PeerEndpoint>,
    inbound: VecDeque<u8>,
    header: Vec<u8>,
    expected_body: Option<usize>,
    body: Vec<u8>,
    charged: usize,
    stalled: bool,
    observed: Option<String>,
    inbound_direction: bool,
    deadline: Option<Duration>,
    blocked: Option<DeliveryToken>,
    held_bytes: usize,
    reading: bool,
    unflushed: usize,
    reserve_used: usize,
    connect_request: Option<RequestId>,
    last_activity: Duration,
    pending_ping: Option<u64>,
    missed_pongs: u32,
}
impl Link<'_> {
    fn peer(&self) -> Option<AuthenticatedPeer> {
        match &self.state {
            Some(Handshake::Established(s)) => Some(AuthenticatedPeer {
                role: self.role,
                route: self
                    .route
                    .as_ref()
                    .map(|r| AuthenticatedRoute::Relayed {
                        carrier: r.carrier_key,
                        route_id: r.route_id,
                    })
                    .unwrap_or(AuthenticatedRoute::Direct),
                key: s.peer(),
                session_id: s.id(),
                metadata: s.peer_metadata().clone(),
            }),
            _ => None,
        }
    }
    fn writable(&self) -> bool {
        self.unflushed <= WRITE_HIGH_WATER_MARK
    }
}
struct Dial {
    endpoint: PeerEndpoint,
    request: RequestId,
    cancelled: bool,
    abandoned: bool,
}
#[derive(Clone, Copy)]
enum Pending {
    Connecting,
    ProviderWalk(u64),
    AnnounceWalk,
    VolumeAttempt(u64),
    VolumeDiscovery(u64),
    VolumeConnect(u64),
    Maintain(PeerKey),
    RoutingRefresh,
    Writable(ConnectionId),
    LookupDial { lookup: u64, peer: PeerKey },
}
pub struct Core<'a, R: CoreEntropy> {
    config: &'a Config,
    settings: CoreSettings,
    rng: R,
    running: bool,
    now: Timestamp,
    next_id: u64,
    links: BTreeMap<ConnectionId, Link<'a>>,
    dials: BTreeMap<DialId, Dial>,
    pending: BTreeMap<RequestId, Pending>,
    user_requests: BTreeMap<RequestId, RequestId>,
    external_requests: BTreeMap<RequestId, RequestId>,
    deliveries: BTreeMap<DeliveryToken, ConnectionId>,
    router: Router,
    health_at: Option<Duration>,
    last_wake: Option<Duration>,
    effects: Vec<Effect>,
    ledger: Box<dyn crate::PeerLedger>,
    content: content::ContentState,
    discovery: discovery::DiscoveryState,
    records: records::RecordsState,
    relay: relay::RelayState,
    retrieval: retrieval::RetrievalState,
    topology: topology::TopologyState,
    public_address: Option<ObservedAddress>,
}
impl<'a, R: CoreEntropy> Core<'a, R> {
    pub fn new(config: &'a Config, settings: CoreSettings, rng: R) -> Self {
        let router = Router::new(config.peer_key(), settings.bucket_size);
        let records = records::RecordsState::new(config, &settings);
        Self {
            config,
            settings,
            rng,
            running: false,
            now: Timestamp::default(),
            next_id: 0,
            links: BTreeMap::new(),
            dials: BTreeMap::new(),
            pending: BTreeMap::new(),
            user_requests: BTreeMap::new(),
            external_requests: BTreeMap::new(),
            deliveries: BTreeMap::new(),
            router,
            health_at: None,
            last_wake: None,
            effects: Vec::new(),
            ledger: Box::new(crate::NullLedger),
            content: content::ContentState::default(),
            discovery: discovery::DiscoveryState::default(),
            records,
            relay: relay::RelayState::default(),
            retrieval: retrieval::RetrievalState::default(),
            topology: topology::TopologyState::default(),
            public_address: None,
        }
    }
    pub fn with_ledger(mut self, ledger: impl crate::PeerLedger + 'static) -> Self {
        self.ledger = Box::new(ledger);
        self
    }
    /// Transport-owned reservations, including canceled/abandoned attempts.
    /// Each remains live until ConnectionOpened or DialFailed is reported.
    pub fn pending_dial_ids(&self) -> impl Iterator<Item = DialId> + '_ {
        self.dials.keys().copied()
    }
    pub fn authenticated_peers(&self) -> Vec<AuthenticatedPeer> {
        self.links.values().filter_map(Link::peer).collect()
    }
    pub fn endpoint_peers(&self) -> Vec<AuthenticatedPeer> {
        self.authenticated_peers()
            .into_iter()
            .filter(|p| p.role == AuthenticatedPeerRole::Endpoint)
            .collect()
    }
    pub fn carrier_peers(&self) -> Vec<AuthenticatedPeer> {
        self.authenticated_peers()
            .into_iter()
            .filter(|p| p.role == AuthenticatedPeerRole::Carrier)
            .collect()
    }
    fn configured_carrier(&self, key: PeerKey) -> bool {
        self.settings
            .carriers
            .iter()
            .any(|e| PeerKey::from_hex(&e.public_key) == Some(key))
    }
    pub fn connected_peer_endpoints(&self) -> Vec<PeerEndpoint> {
        let mut endpoints: Vec<_> = self
            .links
            .values()
            .filter_map(|link| {
                let peer = link.peer()?;
                (peer.role == AuthenticatedPeerRole::Endpoint)
                    .then(|| link.endpoint.clone())
                    .flatten()
            })
            .collect();
        endpoints.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        endpoints
    }
    pub fn known_peer_endpoints(&self) -> Vec<PeerEndpoint> {
        self.router
            .all_peers()
            .map(|entry| entry.endpoint.clone())
            .collect()
    }
    fn local_metadata(&self, local_host: Option<&str>) -> PeerMetadata {
        let mut metadata = self.config.metadata.clone();
        if let Some(external) = &self.settings.external_address {
            metadata.listen_addresses = vec![crate::ListenAddress {
                host: external.host.clone(),
                port: external.port,
            }];
        } else if let Some(port) = self.settings.listen_port {
            metadata.listen_addresses.clear();
            if port != 0 {
                if let Some(public) = &self.public_address {
                    metadata.listen_addresses.push(crate::ListenAddress {
                        host: public.host.clone(),
                        port,
                    });
                }
                if let Some(host) =
                    local_host.filter(|h| !h.is_empty() && *h != "0.0.0.0" && *h != "::")
                {
                    metadata.listen_addresses.push(crate::ListenAddress {
                        host: host.into(),
                        port,
                    });
                }
            }
            metadata
                .listen_addresses
                .sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
            metadata.listen_addresses.dedup();
        }
        metadata
    }
    pub fn public_address(&self) -> Option<&ObservedAddress> {
        self.public_address.as_ref()
    }
    pub fn inbound_bytes(&self) -> usize {
        self.links.values().map(|l| l.charged).sum()
    }
    fn id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }
    fn internal_request_id(&mut self) -> RequestId {
        let mut id = self.id();
        while self.pending.contains_key(&id) {
            id = self.id();
        }
        id
    }
    fn complete(&mut self, id: RequestId, mut result: RequestResult) {
        if self.await_responder(id, &mut result) {
            return;
        }
        if self.connect_fallback(id, &mut result) {
            return;
        }
        self.finished_connect(id);
        match self.pending.remove(&id) {
            Some(Pending::Maintain(peer)) => self.maintained(peer, result),
            Some(Pending::RoutingRefresh) => self.routing_refresh_finished(),
            Some(Pending::VolumeDiscovery(id)) => self.retrieval_discovered(id, result),
            Some(Pending::VolumeConnect(retrieval)) => {
                self.retrieval_connected(retrieval, id, result)
            }
            Some(Pending::VolumeAttempt(id)) => self.retrieval_answer(id, result),
            Some(Pending::ProviderWalk(wire)) => self.provider_walk_finished(wire),
            Some(Pending::AnnounceWalk) => self.announce_walk_finished(id, result),
            Some(Pending::LookupDial { lookup, peer }) => {
                self.lookup_dial_completed(lookup, peer, result)
            }
            Some(_) => {
                if let Some(external) = self.external_requests.remove(&id) {
                    self.user_requests.remove(&external);
                    self.effects.push(Effect::Completed(external, result));
                }
            }
            None => {}
        }
        self.wake_connect_followers(id);
    }
    fn connection(&self, key: PeerKey, session: Option<[u8; 32]>) -> Option<ConnectionId> {
        self.links.iter().find_map(|(&id, l)| {
            l.peer()
                .filter(|p| p.key == key && session.is_none_or(|s| s == p.session_id))
                .map(|_| id)
        })
    }
    pub fn step(&mut self, event: Event, now: Timestamp) -> Vec<Effect> {
        self.now = Timestamp {
            uptime: now.uptime.max(self.now.uptime),
            unix_seconds: now.unix_seconds,
        };
        match event {
            Event::Start => {
                if !self.running && self.settings.validate(self.config).is_ok() {
                    self.running = true;
                    self.public_address = self.settings.external_address.clone();
                    if let Some(address) = &self.public_address {
                        self.effects
                            .push(Effect::PublicAddressDiscovered(address.clone()));
                    } else if self.settings.mode.participates_in_public_discovery()
                        && !self.settings.stun_servers.is_empty()
                    {
                        self.effects.push(Effect::DiscoverPublicAddress);
                    }
                    if self.settings.health_enabled {
                        self.health_at = Some(
                            self.now
                                .uptime
                                .saturating_add(self.settings.keepalive_interval),
                        );
                    }
                    self.start_topology();
                }
            }
            Event::Stop => self.stop(),
            Event::PublicAddress(address) => {
                if self.running && self.public_address.is_none() {
                    if let Some(address) = address {
                        self.public_address = Some(address.clone());
                        self.effects.push(Effect::PublicAddressDiscovered(address));
                    }
                }
            }
            Event::DisconnectPeer(peer) => self.disconnect_peer(peer),
            Event::Broadcast { topic, payload } => {
                if self.settings.mode.uses_overlay_services() {
                    let message = Message::PeerMessage { topic, payload };
                    for peer in self.endpoint_peers() {
                        if let Some(connection) = self.connection(peer.key, Some(peer.session_id)) {
                            self.send(connection, &message);
                        }
                    }
                }
            }
            Event::RestartConfigured(peer) => self.restart_configured(peer),
            Event::SetRelaying { peer, relays } => self.set_relaying(peer, relays),
            Event::Tick => self.tick(),
            Event::ConnectionOpenedWithLocal {
                connection,
                direction,
                observed_host,
                local_host,
            } => self.opened_with_local(connection, direction, observed_host, local_host),
            Event::ConnectionOpened {
                connection,
                direction,
                observed_host,
            } => self.opened(connection, direction, observed_host),
            Event::DialFailed(id) => {
                if let Some(d) = self.dials.remove(&id) {
                    let key = PeerKey::from_hex(&d.endpoint.public_key).expect("validated dial");
                    self.complete(d.request, RequestResult::Failed);
                    self.dial_reservation_released(key);
                }
            }
            Event::Received(id, bytes) => self.received(id, bytes),
            Event::Writable(id) => self.writable(id),
            Event::Closed(id) => self.close(id, false, true),
            Event::Request(external, request) => {
                if !self.user_requests.contains_key(&external) {
                    let id = self.internal_request_id();
                    self.user_requests.insert(external, id);
                    self.external_requests.insert(id, external);
                    self.pending.insert(id, Pending::Connecting);
                    self.request(id, request);
                }
            }
            Event::Cancel(external) => {
                if let Some(&id) = self.user_requests.get(&external) {
                    self.cancel(id);
                }
            }
            Event::Delivered(token) => self.delivered(token),
            Event::SetContentSource(enabled) => self.content_enabled(enabled),
            Event::AnnounceProvider {
                root_cid,
                expires_at,
            } => self.announce_provider(root_cid, expires_at),
            Event::ReportDeficientContent {
                root_cid,
                served_by,
            } => self.report_deficient(root_cid, served_by),
            Event::StopProviding { root_cid } => self.stop_providing(&root_cid),
            Event::JobFinished(job, result) => self.job_finished(job, result),
        }
        self.pump_responder_waiters();
        self.pump_content();
        self.pump_retrieval();
        self.pump_discovery();
        let stalled: Vec<_> = self
            .links
            .iter()
            .filter(|(_, l)| l.stalled)
            .map(|(&id, _)| id)
            .collect();
        for id in stalled {
            self.pump(id);
        }
        self.pump_relay_carriers();
        self.resolve_held_disconnects();
        let earliest = self
            .links
            .values()
            .filter_map(|l| l.deadline)
            .chain(self.health_at)
            .chain(self.content_deadline())
            .chain(self.discovery_deadline())
            .chain(self.records_deadline())
            .chain(self.relay_deadline())
            .chain(self.retrieval_deadline())
            .chain(self.topology_deadline())
            .min();
        if earliest != self.last_wake {
            self.last_wake = earliest;
            if let Some(t) = earliest {
                self.effects.push(Effect::WakeAt(t));
            }
        }
        std::mem::take(&mut self.effects)
    }
    fn stop(&mut self) {
        self.running = false;
        self.stop_topology();
        self.health_at = None;
        let requests: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&id, p)| {
                matches!(p, Pending::Connecting | Pending::Writable(_)).then_some(id)
            })
            .collect();
        for id in requests {
            self.cancel(id);
        }
        let internal: Vec<_> = self.pending.keys().copied().collect();
        for id in internal {
            self.cancel(id);
        }
        let ids: Vec<_> = self.links.keys().copied().collect();
        for id in ids {
            self.close(id, true, false);
        }
        for dial in self.dials.values_mut() {
            dial.abandoned = true;
        }
        self.deliveries.clear();
    }
    fn request(&mut self, id: RequestId, request: Request) {
        // Match Swift startConnect refusal precedence before runtime admission.
        let preflight = match &request {
            Request::Connect(endpoint)
            | Request::ConnectOver { endpoint, .. }
            | Request::ConnectOverWithLocal { endpoint, .. } => {
                Some(PeerKey::from_hex(&endpoint.public_key))
            }
            Request::ConnectViaAnyRelay(key) | Request::ConnectViaRelay { target: key, .. } => {
                Some(Some(*key))
            }
            _ => None,
        };
        if let Some(key) = preflight {
            let error = if key.is_none() {
                Some(ConnectError::InvalidPeerKey)
            } else if key.is_some_and(|k| {
                !self.settings.mode.allows_endpoint(k) && !self.configured_carrier(k)
            }) {
                Some(ConnectError::PeerOutsideMode)
            } else if !self.running {
                Some(ConnectError::NotRunning)
            } else if matches!(&request, Request::ConnectOver { observed_host, .. } | Request::ConnectOverWithLocal { observed_host, .. } if observed_host.as_ref().is_none_or(String::is_empty))
            {
                Some(ConnectError::StreamHasNoObservedHost)
            } else {
                None
            };
            if let Some(error) = error {
                if let Request::ConnectOver { connection, .. }
                | Request::ConnectOverWithLocal { connection, .. } = &request
                {
                    self.effects.push(Effect::Close(*connection));
                }
                self.complete(id, RequestResult::ConnectFailed(error));
                return;
            }
        }
        if !self.running {
            self.complete(id, RequestResult::Failed);
            return;
        }
        match request {
            Request::FindNode { target } => self.find_node(id, target),
            Request::DiscoverProviders { root_cid } => self.discover_providers(id, root_cid),
            Request::ProviderMemberships { root_cid } => {
                let memberships = self.provider_memberships(&root_cid);
                self.complete(id, RequestResult::ProviderMemberships(memberships));
            }
            Request::ConnectOver {
                endpoint,
                connection,
                observed_host,
            } => self.request(
                id,
                Request::ConnectOverWithLocal {
                    endpoint,
                    connection,
                    observed_host,
                    local_host: None,
                },
            ),
            Request::ConnectOverWithLocal {
                endpoint,
                connection,
                observed_host,
                local_host,
            } => {
                if self.links.contains_key(&connection) {
                    self.complete(id, RequestResult::ConnectionInProgress);
                    return;
                }
                let key = PeerKey::from_hex(&endpoint.public_key);
                if key.is_none()
                    || key == Some(self.config.peer_key())
                    || key.is_some_and(|k| {
                        !self.settings.mode.allows_endpoint(k) && !self.configured_carrier(k)
                    })
                    || observed_host.as_ref().is_none_or(|host| host.is_empty())
                {
                    self.effects.push(Effect::Close(connection));
                    self.complete(id, RequestResult::Failed);
                    return;
                }
                let peer = key.unwrap();
                self.resume_explicit_peer(peer);
                if let Some(existing) = self.connection(peer, None) {
                    if self.links[&existing].route.is_none() {
                        self.effects.push(Effect::Close(connection));
                        self.complete(id, RequestResult::Connected);
                        return;
                    }
                }
                if self.ongoing_connect(peer, id).is_some()
                    || self
                        .dials
                        .values()
                        .any(|d| PeerKey::from_hex(&d.endpoint.public_key) == Some(peer))
                {
                    self.effects.push(Effect::Close(connection));
                    self.complete(id, RequestResult::ConnectionInProgress);
                    return;
                }
                if self.links.len() + self.dials.len() >= self.settings.max_connections
                    || self.direct_netgroup_count(&net_group(&endpoint.host))
                        >= self.settings.max_connections_per_netgroup
                {
                    self.effects.push(Effect::Close(connection));
                    self.complete(id, RequestResult::Failed);
                    return;
                }
                self.track_direct_connect(id, key.unwrap());
                let dial = self.id();
                self.dials.insert(
                    dial,
                    Dial {
                        endpoint,
                        request: id,
                        cancelled: false,
                        abandoned: false,
                    },
                );
                self.opened_with_local(
                    connection,
                    ConnectionDirection::Outbound(dial),
                    observed_host,
                    local_host,
                );
                if let Some(link) = self.links.get_mut(&connection) {
                    if let Some(endpoint) = &mut link.endpoint {
                        endpoint.host = "unknown".into();
                        endpoint.port = 0;
                    }
                }
            }
            Request::ConnectViaAnyRelay(target) => {
                if target == self.config.peer_key()
                    || !self.settings.mode.allows_endpoint(target)
                    || self.configured_carrier(target)
                {
                    self.complete(id, RequestResult::Failed);
                } else if self.connection(target, None).is_some() {
                    self.complete(id, RequestResult::Connected);
                } else {
                    self.register_connect_fallback(id, target);
                    self.complete(id, RequestResult::Failed);
                }
            }
            Request::ConnectViaRelay { carrier, target } => {
                self.connect_via_relay(id, carrier, target)
            }
            Request::Connect(endpoint) => {
                let Some(key) = PeerKey::from_hex(&endpoint.public_key) else {
                    self.complete(id, RequestResult::Failed);
                    return;
                };
                if key == self.config.peer_key()
                    || endpoint.port == 0
                    || endpoint.host.is_empty()
                    || (!self.settings.mode.allows_endpoint(key) && !self.configured_carrier(key))
                {
                    self.complete(id, RequestResult::Failed);
                    return;
                }
                self.track_direct_connect(id, key);
                self.register_connect_fallback(id, key);
                if self.connection(key, None).is_some() {
                    self.complete(id, RequestResult::Connected);
                    return;
                }
                if let Some(leader) = self.ongoing_connect(key, id) {
                    if matches!(self.pending.get(&id), Some(Pending::VolumeConnect(_))) {
                        self.follow_connect(leader, id, endpoint);
                    } else {
                        // Only content connection groups follow an existing attempt.
                        // User, lookup and maintenance callers resolve immediately.
                        self.cancel_topology_request(id);
                        self.complete(id, RequestResult::ConnectionInProgress);
                    }
                    return;
                }
                if self
                    .dials
                    .values()
                    .any(|d| PeerKey::from_hex(&d.endpoint.public_key) == Some(key))
                {
                    self.cancel_topology_request(id);
                    self.complete(id, RequestResult::ConnectionInProgress);
                    return;
                }
                if self.links.len() + self.dials.len() >= self.settings.max_connections
                    || self.direct_netgroup_count(&net_group(&endpoint.host))
                        >= self.settings.max_connections_per_netgroup
                {
                    self.cancel_topology_request(id);
                    self.complete(id, RequestResult::Failed);
                    return;
                }
                let dial = self.id();
                self.dials.insert(
                    dial,
                    Dial {
                        endpoint: endpoint.clone(),
                        request: id,
                        cancelled: false,
                        abandoned: false,
                    },
                );
                self.effects.push(Effect::Dial(dial, endpoint));
            }
            Request::Send {
                peer,
                session_id,
                message,
            } => {
                let result = self
                    .connection(peer, session_id)
                    .map(|conn| self.send(conn, &message))
                    .unwrap_or(RequestResult::NotConnected);
                self.complete(id, result);
            }
            Request::WaitUntilWritable { peer, session_id } => {
                match self.connection(peer, session_id) {
                    Some(conn) if !self.transport_writable(conn, false) => {
                        self.pending.insert(id, Pending::Writable(conn));
                    }
                    Some(_) => self.complete(id, RequestResult::Writable(true)),
                    None => self.complete(id, RequestResult::Writable(false)),
                }
            }
            Request::RetrieveVolume {
                root_cid,
                maximum_archive_bytes,
                maximum_entries,
            } => self.retrieve_volume(id, root_cid, maximum_archive_bytes, maximum_entries),
            Request::FetchFromSessions {
                root_cid,
                bundle,
                peers,
                maximum_archive_bytes,
                maximum_entries,
            } => {
                self.fetch_sessions(
                    id,
                    root_cid,
                    bundle,
                    peers,
                    maximum_archive_bytes,
                    maximum_entries,
                );
            }
            Request::FetchVolume {
                peer,
                root_cid,
                bundle,
                maximum_archive_bytes,
                maximum_entries,
            } => self.fetch_volume(
                id,
                peer,
                root_cid,
                bundle,
                maximum_archive_bytes,
                maximum_entries,
            ),
            Request::Recycle(peer) => {
                let connection = self.connection(peer.key, Some(peer.session_id));
                if let Some(conn) = connection {
                    self.close(conn, true, true);
                }
                self.complete(id, RequestResult::Disconnected(connection.is_some()));
            }
            Request::Disconnect(peer) => {
                let connection = self.connection(peer.key, Some(peer.session_id));
                if let Some(conn) = connection {
                    self.suppress_configured(peer.key);
                    self.close(conn, true, true);
                }
                self.complete(id, RequestResult::Disconnected(connection.is_some()));
            }
        }
    }
    fn cancel(&mut self, id: RequestId) {
        self.cancel_topology_request(id);
        self.cancel_relay_open(id);
        self.cancel_retrieval(id);
        self.cancel_content(id);
        self.cancel_records(id);
        self.cancel_discovery(id);
        let dials: Vec<_> = self
            .dials
            .iter()
            .filter(|(_, d)| d.request == id)
            .map(|(&id, _)| id)
            .collect();
        for dial in dials {
            self.dials.get_mut(&dial).unwrap().cancelled = true;
        }
        let links: Vec<_> = self
            .links
            .iter()
            .filter(|(_, l)| l.connect_request == Some(id))
            .map(|(&id, _)| id)
            .collect();
        self.complete(id, RequestResult::Cancelled);
        for conn in links {
            self.close(conn, true, true);
        }
    }
    fn opened(
        &mut self,
        id: ConnectionId,
        direction: ConnectionDirection,
        observed: Option<String>,
    ) {
        self.opened_with_local(id, direction, observed, None);
    }
    fn opened_with_local(
        &mut self,
        id: ConnectionId,
        direction: ConnectionDirection,
        observed: Option<String>,
        local_host: Option<String>,
    ) {
        if self.links.contains_key(&id) {
            return;
        }
        let dial = match direction {
            ConnectionDirection::Outbound(dial) => match self.dials.remove(&dial) {
                Some(d) => Some(d),
                None => {
                    self.effects.push(Effect::Close(id));
                    return;
                }
            },
            ConnectionDirection::Inbound => None,
        };
        if let Some(d) = &dial {
            if d.cancelled || d.abandoned || !self.pending.contains_key(&d.request) {
                let key = PeerKey::from_hex(&d.endpoint.public_key).expect("validated dial");
                self.effects.push(Effect::Close(id));
                self.complete(d.request, RequestResult::Cancelled);
                self.dial_reservation_released(key);
                return;
            }
        }
        let group_count = observed
            .as_deref()
            .filter(|host| !host.is_empty())
            .or_else(|| dial.as_ref().map(|d| d.endpoint.host.as_str()))
            .map(|host| self.direct_netgroup_count(&net_group(host)))
            .unwrap_or(0);
        let inbound = dial.is_none();
        if !self.running
            || self.links.len() + self.dials.len() >= self.settings.max_connections
            || inbound
                && self.links.len().saturating_add(self.dials.len())
                    >= self
                        .settings
                        .max_connections
                        .saturating_sub(self.settings.reserved_outbound_connection_slots)
            || inbound
                && self.links.len() + self.dials.len() >= self.settings.max_inbound_connections
            || group_count >= self.settings.max_connections_per_netgroup
        {
            self.effects.push(Effect::Close(id));
            if let Some(d) = dial {
                self.refuse_direct_binding(
                    d.request,
                    PeerKey::from_hex(&d.endpoint.public_key).unwrap(),
                );
            }
            return;
        }
        let request = dial.as_ref().map(|d| d.request);
        let endpoint = dial.as_ref().map(|d| d.endpoint.clone());
        let (state, hello) = if let Some(d) = dial {
            let key = PeerKey::from_hex(&d.endpoint.public_key).expect("validated endpoint");
            let metadata = self.local_metadata(local_host.as_deref());
            match Initiator::start_with_metadata(
                self.config,
                key,
                [0; 32],
                self.rng.bytes32(),
                metadata,
            ) {
                Ok((s, bytes)) => (Handshake::Initiating(s), Some(bytes)),
                Err(_) => {
                    self.effects.push(Effect::Close(id));
                    self.complete(d.request, RequestResult::Failed);
                    return;
                }
            }
        } else {
            (Handshake::Incoming, None)
        };
        self.links.insert(
            id,
            Link {
                local_host: local_host.clone(),
                role: AuthenticatedPeerRole::Endpoint,
                route: None,
                state: Some(state),
                endpoint,
                inbound: VecDeque::new(),
                header: Vec::new(),
                expected_body: None,
                body: Vec::new(),
                charged: 0,
                stalled: false,
                observed,
                inbound_direction: inbound,
                deadline: Some(
                    self.now
                        .uptime
                        .saturating_add(self.settings.handshake_timeout),
                ),
                blocked: None,
                held_bytes: 0,
                reading: true,
                unflushed: 0,
                reserve_used: 0,
                connect_request: request,
                last_activity: self.now.uptime,
                pending_ping: None,
                missed_pongs: 0,
            },
        );
        // Swift binds and resumes a native link before emitting its hello.
        self.effects.push(Effect::ResumeReading(id));
        if let Some(hello) = hello {
            self.write(id, hello, true);
        }
    }
    fn close(&mut self, id: ConnectionId, notify: bool, disconnected: bool) {
        self.close_relay(id);
        self.close_content(id);
        self.close_discovery(id);
        let Some(link) = self.links.remove(&id) else {
            return;
        };
        let carrier = link.route.as_ref().map(|r| r.carrier_connection);
        if notify && link.route.is_none() {
            self.effects.push(Effect::Close(id));
        }
        if let Some(token) = link.blocked {
            self.deliveries.remove(&token);
        }
        if let Some(request) = link.connect_request {
            self.complete(request, RequestResult::Failed);
        }
        if let Some(peer) = link.peer() {
            self.router.remove_peer(peer.key);
            self.topology_disconnected(peer.key);
            if disconnected {
                self.disconnected_notification(peer.key);
            }
        }
        let waiting: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&r, p)| matches!(p,Pending::Writable(c) if *c==id).then_some(r))
            .collect();
        for r in waiting {
            self.complete(r, RequestResult::Writable(false));
        }
        if let Some(carrier) = carrier {
            self.sync_reading(carrier);
        }
    }
    fn write(&mut self, id: ConnectionId, record: Vec<u8>, reserve: bool) -> RequestResult {
        if let Some(route) = self.links.get(&id).and_then(|l| l.route.clone()) {
            return self.send_reserved(
                route.carrier_connection,
                &Message::RelayPacket {
                    route_id: route.route_id,
                    opaque_endpoint_record: record,
                },
                reserve,
            );
        }
        let Some(link) = self.links.get_mut(&id) else {
            return RequestResult::NotConnected;
        };
        if !link.writable() && (!reserve || link.reserve_used >= WRITE_HIGH_WATER_MARK) {
            return RequestResult::Backpressured;
        }
        let frame = frame(&record);
        if !link.writable() {
            link.reserve_used += frame.len();
        }
        link.unflushed += frame.len();
        self.effects.push(Effect::Write(id, frame));
        RequestResult::Enqueued
    }
    fn send(&mut self, id: ConnectionId, message: &Message) -> RequestResult {
        self.send_reserved(id, message, message.uses_write_reserve())
    }
    fn send_reserved(
        &mut self,
        id: ConnectionId,
        message: &Message,
        reserve: bool,
    ) -> RequestResult {
        if self
            .links
            .get(&id)
            .is_some_and(|l| l.role == AuthenticatedPeerRole::Carrier)
            && !Self::carrier_message(message)
        {
            return RequestResult::LocallyRejected;
        }
        let limit = self.outgoing_frame_limit(id);
        if !self.transport_writable(id, reserve) {
            return RequestResult::Backpressured;
        }
        let Some(link) = self.links.get_mut(&id) else {
            return RequestResult::NotConnected;
        };
        if !link.writable() && (!reserve || link.reserve_used >= WRITE_HIGH_WATER_MARK) {
            return RequestResult::Backpressured;
        }
        let Some(Handshake::Established(session)) = link.state.as_mut() else {
            return RequestResult::NotConnected;
        };
        let Ok(record) = session.seal_with_frame_limit(message, limit) else {
            return RequestResult::LocallyRejected;
        };
        let peer = session.peer();
        let payload_bytes = record.len() - crate::wire::DATA_RECORD_OVERHEAD;
        let result = self.write(id, record, reserve);
        if result == RequestResult::Enqueued {
            self.ledger.record_sent(peer, payload_bytes);
        }
        result
    }
    fn writable(&mut self, id: ConnectionId) {
        if let Some(link) = self.links.get_mut(&id) {
            link.unflushed = 0;
            link.reserve_used = 0;
            let waiting: Vec<_> = self
                .pending
                .iter()
                .filter_map(|(&r, p)| matches!(p,Pending::Writable(c) if *c==id).then_some(r))
                .collect();
            for r in waiting {
                self.complete(r, RequestResult::Writable(true));
            }
        }
        self.writable_relay(id);
        self.writable_relay_endpoints(id);
    }
    fn received(&mut self, id: ConnectionId, bytes: Vec<u8>) {
        let Some(link) = self.links.get_mut(&id) else {
            return;
        };
        // Shell reads at most 64 KiB per event. Bound undecoded carry even if a
        // caller ignores PauseReading, independently of charged frame memory.
        let carry_limit = 2 * self.config.metadata.max_frame_size as usize + 64 * 1024;
        if bytes.len() > carry_limit.saturating_sub(link.inbound.len()) {
            self.close(id, true, true);
            return;
        }
        link.inbound.extend(bytes);
        self.pump(id);
    }
    fn sync_reading(&mut self, id: ConnectionId) {
        let parent = self
            .links
            .get(&id)
            .and_then(|l| l.route.as_ref())
            .map(|r| r.carrier_connection);
        let blocked = self.carrier_has_blocked_endpoint(id);
        if let Some(link) = self.links.get_mut(&id) {
            let wanted = link.blocked.is_none() && !link.stalled && !blocked;
            if wanted != link.reading {
                link.reading = wanted;
                if parent.is_none() {
                    self.effects.push(if wanted {
                        Effect::ResumeReading(id)
                    } else {
                        Effect::PauseReading(id)
                    });
                }
            }
        }
        if let Some(parent) = parent {
            self.sync_reading(parent);
        }
    }
    fn pump(&mut self, id: ConnectionId) {
        loop {
            if self.carrier_has_blocked_endpoint(id) {
                self.sync_reading(id);
                return;
            }
            let used = self.inbound_bytes();
            let Some(link) = self.links.get_mut(&id) else {
                return;
            };
            if link.blocked.is_some() {
                self.sync_reading(id);
                return;
            }
            link.stalled = false;
            if link.inbound.is_empty() {
                self.sync_reading(id);
                return;
            }
            let per_link = 2 * self.config.metadata.max_frame_size as usize + 4;
            if link.expected_body.is_none() {
                if link.header.is_empty() {
                    if 4 > self.settings.max_inbound_bytes.saturating_sub(used)
                        || 4 > per_link.saturating_sub(link.charged)
                    {
                        link.stalled = true;
                        self.sync_reading(id);
                        return;
                    }
                    link.charged += 4;
                }
                let count = (4 - link.header.len()).min(link.inbound.len());
                link.header.extend(link.inbound.drain(..count));
                if link.header.len() < 4 {
                    self.sync_reading(id);
                    return;
                }
                let header: [u8; 4] = link.header.as_slice().try_into().unwrap();
                let Some(length) = frame_length(header, self.config.metadata.max_frame_size) else {
                    self.close(id, true, true);
                    return;
                };
                link.expected_body = Some(length);
                link.header.clear();
                link.charged -= 4;
                continue;
            }
            let length = link.expected_body.unwrap();
            let count = (length - link.body.len()).min(link.inbound.len());
            if count > self.settings.max_inbound_bytes.saturating_sub(used)
                || count > per_link.saturating_sub(link.charged)
            {
                link.stalled = true;
                self.sync_reading(id);
                return;
            }
            link.charged += count;
            link.body.extend(link.inbound.drain(..count));
            if link.body.len() < length {
                self.sync_reading(id);
                return;
            }
            let record = std::mem::take(&mut link.body);
            link.expected_body = None;
            self.record(id, &record);
            if let Some(link) = self.links.get_mut(&id) {
                if link.blocked.is_some() {
                    link.held_bytes = record.len();
                    self.sync_reading(id);
                    return;
                }
                link.charged -= record.len();
            }
        }
    }
    fn record(&mut self, id: ConnectionId, record: &[u8]) {
        let state = self.links.get_mut(&id).and_then(|l| l.state.take());
        let Some(state) = state else {
            return;
        };
        match state {
            Handshake::Incoming => {
                let route = self.links[&id].route.clone();
                let carriers = &self.settings.carriers;
                let mode = self.settings.mode;
                match Responder::on_route(
                    self.config,
                    route.as_ref().map(|r| r.route_id).unwrap_or([0; 32]),
                )
                .with_metadata(self.local_metadata(self.links[&id].local_host.as_deref()))
                .receive_with_nonce_source(
                    record,
                    |key| {
                        (mode.allows_endpoint(*key)
                            || (route.is_none()
                                && carriers
                                    .iter()
                                    .any(|e| PeerKey::from_hex(&e.public_key) == Some(*key))))
                            && route.as_ref().is_none_or(|r| r.remote == *key)
                    },
                    || self.rng.bytes32(),
                ) {
                    Ok((waiting, reply)) => {
                        self.links.get_mut(&id).unwrap().state =
                            Some(Handshake::Finishing(waiting));
                        if self.write(id, reply, true) != RequestResult::Enqueued {
                            self.close(id, true, true);
                        }
                    }
                    Err(_) => self.close(id, true, true),
                }
            }
            Handshake::Initiating(initiator) => match initiator.receive(record) {
                Ok((session, finish)) => {
                    if self.write(id, finish, true) == RequestResult::Enqueued {
                        self.established(id, session);
                    } else {
                        self.close(id, true, true);
                    }
                }
                Err(_) => self.close(id, true, true),
            },
            Handshake::Finishing(waiting) => match waiting.receive(record) {
                Ok(session) => self.established(id, session),
                Err(_) => self.close(id, true, true),
            },
            Handshake::Established(mut session) => {
                let previous = session.last_received_sequence();
                let opened = session.open(record);
                let authenticated = session.last_received_sequence() > previous;
                let peer = session.peer();
                if authenticated {
                    self.ledger
                        .record_received(peer, record.len() - crate::wire::DATA_RECORD_OVERHEAD);
                }
                if authenticated && opened.is_err() {
                    self.ledger.record_protocol_violation(peer);
                }
                self.links.get_mut(&id).unwrap().state = Some(Handshake::Established(session));
                match opened {
                    Ok(Some(message)) => self.message(id, message),
                    Ok(None) => {}
                    Err(_) => self.close(id, true, true),
                }
            }
        }
    }
    fn established(&mut self, id: ConnectionId, session: Session) {
        let existing_session = self.connection(session.peer(), None);
        if let Some(existing) = existing_session {
            let old = self.links[&existing].peer().unwrap();
            let old_direct = self.links[&existing].route.is_none();
            let new_direct = self.links[&id].route.is_none();
            if (old_direct && !new_direct)
                || (old_direct == new_direct && old.session_id <= session.id())
            {
                if let Some(request) = self
                    .links
                    .get_mut(&id)
                    .and_then(|l| l.connect_request.take())
                {
                    self.complete(request, RequestResult::Connected);
                }
                self.close(id, true, false);
                return;
            }
        }
        let link = &self.links[&id];
        let session_limit = if link.inbound_direction {
            self.inbound_limit()
        } else {
            self.settings.max_connections
        };
        let sessions = self.links.values().filter(|l| l.peer().is_some()).count();
        let group = link
            .observed
            .as_deref()
            .filter(|host| !host.is_empty())
            .map(net_group);
        let group_sessions = self
            .links
            .values()
            .filter(|l| {
                group.is_some()
                    && l.route.is_none()
                    && l.peer().is_some_and(|p| p.key != session.peer())
                    && l.observed
                        .as_deref()
                        .filter(|host| !host.is_empty())
                        .map(net_group)
                        == group
            })
            .count();
        if (existing_session.is_none() && sessions >= session_limit)
            || (link.route.is_none()
                && group_sessions >= self.settings.max_connections_per_netgroup)
        {
            self.close(id, true, true);
            return;
        }
        if let Some(existing) = existing_session {
            if let Some(request) = self
                .links
                .get_mut(&existing)
                .and_then(|l| l.connect_request.take())
            {
                self.complete(request, RequestResult::Connected);
            }
            self.close(existing, true, false);
        }
        let role = if self.links[&id].route.is_none() && self.configured_carrier(session.peer()) {
            AuthenticatedPeerRole::Carrier
        } else {
            AuthenticatedPeerRole::Endpoint
        };
        self.links.get_mut(&id).unwrap().role = role;
        let peer = AuthenticatedPeer {
            role,
            route: self.links[&id]
                .route
                .as_ref()
                .map(|r| AuthenticatedRoute::Relayed {
                    carrier: r.carrier_key,
                    route_id: r.route_id,
                })
                .unwrap_or(AuthenticatedRoute::Direct),
            key: session.peer(),
            session_id: session.id(),
            metadata: session.peer_metadata().clone(),
        };
        let token = self.id();
        let link = self.links.get_mut(&id).unwrap();
        link.state = Some(Handshake::Established(Box::new(session)));
        link.deadline = None;
        link.blocked = Some(token);
        self.deliveries.insert(token, id);
        if let Some(address) = peer.metadata.listen_addresses.iter().find(|a| {
            role == AuthenticatedPeerRole::Endpoint
                && a.port != 0
                && crate::allows_discovered_host(&a.host, true, link.observed.as_deref())
        }) {
            self.router.add_peer(
                peer.key,
                PeerEndpoint {
                    public_key: peer.key.hex(),
                    host: address.host.clone(),
                    port: address.port,
                },
            );
        }
        if role == AuthenticatedPeerRole::Endpoint
            && !self.router.all_peers().any(|e| e.key == peer.key)
        {
            if let Some(endpoint) = self.links[&id].endpoint.clone() {
                self.router.add_peer(peer.key, endpoint);
            }
        }
        self.effects.push(Effect::PeerConnected(token, peer));
    }
    fn delivered(&mut self, token: DeliveryToken) {
        let Some(id) = self.deliveries.remove(&token) else {
            return;
        };
        let Some(link) = self.links.get_mut(&id) else {
            return;
        };
        if link.blocked != Some(token) {
            return;
        }
        link.blocked = None;
        link.charged -= link.held_bytes;
        link.held_bytes = 0;
        let request = link.connect_request.take();
        let parent = link.route.as_ref().map(|r| r.carrier_connection);
        self.sync_reading(id);
        if let Some(r) = request {
            self.complete(r, RequestResult::Connected);
        }
        self.pump(id);
        if let Some(parent) = parent {
            self.pump(parent);
        }
    }
    fn carrier_message(message: &Message) -> bool {
        matches!(
            message,
            Message::Ping(_)
                | Message::Pong(_)
                | Message::RelayOpen { .. }
                | Message::RelayOffer { .. }
                | Message::RelayAccept { .. }
                | Message::RelayReady { .. }
                | Message::RelayPacket { .. }
                | Message::RelayClose { .. }
        )
    }
    fn message(&mut self, id: ConnectionId, message: Message) {
        let link = self.links.get_mut(&id).unwrap();
        let valid_activity = match &message {
            Message::Pong(nonce) => link.pending_ping == Some(*nonce),
            _ => true,
        };
        if valid_activity {
            link.last_activity = self.now.uptime;
            link.pending_ping = None;
            link.missed_pongs = 0;
        }
        if link.role == AuthenticatedPeerRole::Carrier && !Self::carrier_message(&message) {
            self.ledger
                .record_protocol_violation(link.peer().unwrap().key);
            return;
        }
        if !self.settings.mode.uses_overlay_services() {
            match &message {
                Message::Ping(_) | Message::Pong(_) | Message::PeerMessage { .. } => {}
                Message::VolumeRequest { .. }
                | Message::VolumeBundleRequest { .. }
                | Message::VolumeChunk { .. }
                | Message::VolumeBundleEnd { .. }
                | Message::ContentUnavailable { .. }
                    if self.settings.private_content_exchange_enabled => {}
                _ => return,
            }
        }
        if self.relay_message(id, &message) {
            return;
        }
        if self.records_message(id, &message) {
            return;
        }
        if self.discovery_message(id, &message) {
            return;
        }
        if self.content_message(id, &message) {
            return;
        }
        match message {
            Message::Ping(nonce) => {
                self.send(id, &Message::Pong(nonce));
            }
            Message::Pong(_) => {}
            Message::FindNode { target, nonce } => {
                let peers = self
                    .router
                    .closest_peers(&target, self.settings.bucket_size)
                    .into_iter()
                    .map(|e| e.endpoint.clone())
                    .collect();
                self.send(id, &Message::Neighbors { peers, nonce });
            }
            message => {
                let peer = self.links[&id].peer().unwrap();
                let token = self.id();
                self.links.get_mut(&id).unwrap().blocked = Some(token);
                self.deliveries.insert(token, id);
                self.effects.push(Effect::Deliver(token, peer, message));
            }
        }
    }
    fn tick(&mut self) {
        self.tick_content();
        self.tick_records();
        self.tick_relay();
        self.tick_topology();
        self.tick_discovery();
        let expired: Vec<_> = self
            .links
            .iter()
            .filter(|(_, l)| l.deadline.is_some_and(|d| d <= self.now.uptime))
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.close(id, true, true);
        }
        if self.health_at.is_some_and(|t| t <= self.now.uptime) {
            self.health_at = Some(
                self.now
                    .uptime
                    .saturating_add(self.settings.keepalive_interval),
            );
            let ids: Vec<_> = self
                .links
                .iter()
                .filter(|(_, l)| l.peer().is_some())
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                let link = self.links.get_mut(&id).unwrap();
                if self.now.uptime.saturating_sub(link.last_activity) >= self.settings.stale_timeout
                {
                    self.close(id, true, true);
                    continue;
                }
                if self.now.uptime.saturating_sub(link.last_activity)
                    < self.settings.keepalive_interval
                {
                    continue;
                }
                if link.pending_ping.is_some() {
                    link.missed_pongs += 1;
                    if link.missed_pongs >= self.settings.max_missed_pongs {
                        self.close(id, true, true);
                        continue;
                    }
                }
                let nonce = self.rng.next();
                link.pending_ping = Some(nonce);
                self.send(id, &Message::Ping(nonce));
            }
        }
    }
}
