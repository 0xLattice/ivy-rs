//! Deterministic virtual-clock Ivy network. No sockets or wall-clock reads.
//! Uses real deterministic Ed25519 signatures; trace digests are Rust-specific,
//! not byte-for-byte Swift simulated-signature trace digests.
use ivy_core::{
    core::*, Config, ContentEntry, Message, PeerEndpoint, PeerKey, PeerLedger, SimulationRandom,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
/// Forgeable digest-based scheme matching Swift IvySimulation exactly.
/// For isolated simulations only; default configurations use real Ed25519.
pub struct SimulatedSignatureScheme {
    key: PeerKey,
}
impl SimulatedSignatureScheme {
    pub fn new(key: PeerKey) -> Self {
        Self { key }
    }
    fn tag(key: PeerKey, message: &[u8]) -> [u8; 64] {
        let mut result = [0; 64];
        for (index, domain) in [b"ivy.sim.a", b"ivy.sim.b"].iter().enumerate() {
            let mut hash = Sha256::new();
            hash.update(domain);
            hash.update(key.as_bytes());
            hash.update(message);
            result[index * 32..(index + 1) * 32].copy_from_slice(&hash.finalize());
        }
        result
    }
}
impl ivy_core::SignatureScheme for SimulatedSignatureScheme {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        Self::tag(self.key, message)
    }
    fn verifies(&self, key: PeerKey, message: &[u8], signature: &[u8; 64]) -> bool {
        *signature == Self::tag(key, message)
    }
}
pub type NodeId = usize;
#[derive(Default)]
struct LedgerState {
    priority: BTreeMap<PeerKey, f64>,
    standing: BTreeMap<PeerKey, usize>,
    violations: BTreeMap<PeerKey, usize>,
}
#[derive(Clone, Default)]
pub struct SimulatedLedger(Arc<Mutex<LedgerState>>);
impl SimulatedLedger {
    pub fn set_priority(&self, peer: PeerKey, value: f64) {
        self.0.lock().unwrap().priority.insert(peer, value);
    }
    pub fn set_standing(&self, peer: PeerKey, bytes: usize) {
        self.0.lock().unwrap().standing.insert(peer, bytes);
    }
    pub fn standing(&self, peer: PeerKey) -> usize {
        self.0
            .lock()
            .unwrap()
            .standing
            .get(&peer)
            .copied()
            .unwrap_or(0)
    }
    pub fn violations(&self, peer: PeerKey) -> usize {
        self.0
            .lock()
            .unwrap()
            .violations
            .get(&peer)
            .copied()
            .unwrap_or(0)
    }
}
impl PeerLedger for SimulatedLedger {
    fn record_sent(&mut self, _: PeerKey, _: usize) {}
    fn record_received(&mut self, _: PeerKey, _: usize) {}
    fn record_protocol_violation(&mut self, peer: PeerKey) {
        *self.0.lock().unwrap().violations.entry(peer).or_default() += 1;
    }
    fn serving_priority(&self, peer: PeerKey) -> f64 {
        let state = self.0.lock().unwrap();
        state.priority.get(&peer).copied().unwrap_or(0.)
            + state.standing.get(&peer).copied().unwrap_or(0) as f64
    }
    fn record_served(&mut self, peer: PeerKey, bytes: usize) {
        if let Some(value) = self.0.lock().unwrap().standing.get_mut(&peer) {
            *value = value.saturating_sub(bytes);
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    pub time: Duration,
    pub node: NodeId,
    pub effect: Effect,
}
struct Endpoint {
    remote: Option<(NodeId, ConnectionId)>,
    reading: bool,
    inbox: VecDeque<Vec<u8>>,
    undelivered: usize,
    remote_closed: bool,
    extra_delay: Duration,
}
impl Endpoint {
    fn new(remote: Option<(NodeId, ConnectionId)>) -> Self {
        Self {
            remote,
            reading: false,
            inbox: VecDeque::new(),
            undelivered: 0,
            remote_closed: false,
            extra_delay: Duration::ZERO,
        }
    }
}
pub type Authorizer = Box<dyn Fn(&AuthenticatedPeer, &str) -> bool>;
pub struct Node<'a> {
    pub core: Core<'a, SimulationRandom>,
    pub host: String,
    pub endpoint: PeerEndpoint,
    pub ledger: SimulatedLedger,
    pub volumes: BTreeMap<String, Vec<ContentEntry>>,
    pub bundles: BTreeMap<String, Vec<String>>,
    pub authorize: Authorizer,
    pub storage_delay: Duration,
    pub stalls_storage: bool,
    pub delivery_delay: Duration,
    pub holds_deliveries: bool,
    pub observed_public_address: Option<ObservedAddress>,
    pub received: Vec<(AuthenticatedPeer, Message)>,
    pub connected: Vec<AuthenticatedPeer>,
    pub disconnected: Vec<PeerKey>,
    pub public_addresses: Vec<ObservedAddress>,
    pub started_jobs: Vec<(JobId, ContentJob)>,
    pub cancelled_jobs: Vec<JobId>,
    pub held_deliveries: Vec<DeliveryToken>,
    pub results: BTreeMap<RequestId, RequestResult>,
    stalled_jobs: Vec<(JobId, ContentJob)>,
    connections: BTreeMap<ConnectionId, Endpoint>,
    wake: Option<Duration>,
    running: bool,
}
enum Action {
    Event(Event),
    Arrive(ConnectionId, Vec<u8>),
    RemoteClosed(ConnectionId),
    Drained(ConnectionId),
}
pub struct Simulation<'a> {
    pub seed: u64,
    pub latency: Duration,
    pub segment_size: usize,
    pub nodes: Vec<Node<'a>>,
    pub trace: Vec<TraceEntry>,
    pub last_dialled_connections: Option<(ConnectionId, ConnectionId)>,
    now: Duration,
    queue: BTreeMap<(Duration, u64), (NodeId, Action)>,
    order: u64,
    next_connection: u64,
    next_request: u64,
    partitions: BTreeSet<(NodeId, NodeId)>,
    raw_output: BTreeMap<ConnectionId, Vec<u8>>,
    raw_stalled: BTreeSet<ConnectionId>,
    raw_closed: BTreeSet<ConnectionId>,
    digest: Sha256,
}
impl<'a> Simulation<'a> {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            latency: Duration::from_millis(10),
            segment_size: 65536,
            nodes: vec![],
            trace: vec![],
            last_dialled_connections: None,
            now: Duration::ZERO,
            queue: BTreeMap::new(),
            order: 0,
            next_connection: 0,
            next_request: 0,
            partitions: BTreeSet::new(),
            raw_output: BTreeMap::new(),
            raw_stalled: BTreeSet::new(),
            raw_closed: BTreeSet::new(),
            digest: Sha256::new(),
        }
    }
    /// Same key derivation as the pinned Swift simulation.
    pub fn signing_key(&self, index: usize) -> ed25519_dalek::SigningKey {
        let mut hash = Sha256::new();
        hash.update(b"ivy.sim.key");
        hash.update(self.seed.to_be_bytes());
        hash.update((index as u64).to_be_bytes());
        ed25519_dalek::SigningKey::from_bytes(&hash.finalize().into())
    }
    pub fn now(&self) -> Duration {
        self.now
    }
    pub fn unix_seconds(&self) -> u64 {
        1_800_000_000u64.saturating_add(self.now.as_secs())
    }
    pub fn add_node(
        &mut self,
        config: &'a Config,
        mut settings: CoreSettings,
        host: Option<String>,
    ) -> NodeId {
        assert!(
            settings.validate(config).is_ok(),
            "invalid simulation node settings"
        );
        let id = self.nodes.len();
        let host = host.unwrap_or_else(|| format!("8.{}.0.1", id + 1));
        let port = settings.listen_port.unwrap_or(4001);
        settings.listen_port = Some(port);
        let ledger = SimulatedLedger::default();
        let core = Core::new(
            config,
            settings,
            SimulationRandom::seeded(
                self.seed
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(id as u64),
            ),
        )
        .with_ledger(ledger.clone());
        self.nodes.push(Node {
            core,
            endpoint: PeerEndpoint {
                public_key: config.peer_key().hex(),
                host: host.clone(),
                port,
            },
            host,
            ledger,
            volumes: BTreeMap::new(),
            bundles: BTreeMap::new(),
            authorize: Box::new(|_, _| true),
            storage_delay: Duration::ZERO,
            stalls_storage: false,
            delivery_delay: Duration::ZERO,
            holds_deliveries: false,
            observed_public_address: None,
            received: vec![],
            connected: vec![],
            disconnected: vec![],
            public_addresses: vec![],
            started_jobs: vec![],
            cancelled_jobs: vec![],
            held_deliveries: vec![],
            results: BTreeMap::new(),
            stalled_jobs: vec![],
            connections: BTreeMap::new(),
            wake: None,
            running: false,
        });
        id
    }
    pub fn set_partitioned(&mut self, a: NodeId, b: NodeId, value: bool) {
        let pair = (a.min(b), a.max(b));
        if value {
            self.partitions.insert(pair);
        } else {
            self.partitions.remove(&pair);
        }
    }
    pub fn start(&mut self, node: NodeId) {
        self.send(node, Event::SetContentSource(true));
        self.send(node, Event::Start);
    }
    pub fn stop(&mut self, node: NodeId) {
        self.send(node, Event::Stop);
    }
    pub fn send(&mut self, node: NodeId, event: Event) {
        match event {
            Event::Start => self.nodes[node].running = true,
            Event::Stop => {
                self.nodes[node].running = false;
                self.nodes[node].wake = None;
            }
            _ => {}
        }
        let now = Timestamp {
            uptime: self.now,
            unix_seconds: self.unix_seconds(),
        };
        let effects = self.nodes[node].core.step(event, now);
        for effect in effects {
            self.digest
                .update(format!("{}:{}:{effect:?}", self.now.as_nanos(), node));
            self.trace.push(TraceEntry {
                time: self.now,
                node,
                effect: effect.clone(),
            });
            self.perform(node, effect);
        }
    }
    pub fn request(&mut self, node: NodeId, request: Request) -> RequestId {
        self.next_request += 1;
        let id = self.next_request;
        self.send(node, Event::Request(id, request));
        id
    }
    pub fn cancel(&mut self, node: NodeId, request: RequestId) {
        self.send(node, Event::Cancel(request));
    }
    pub fn await_request(
        &mut self,
        node: NodeId,
        request: Request,
        timeout: Duration,
    ) -> Option<RequestResult> {
        let id = self.request(node, request);
        self.run_until(timeout, |sim| sim.nodes[node].results.contains_key(&id));
        self.nodes[node].results.get(&id).cloned()
    }
    pub fn run_for(&mut self, duration: Duration) {
        self.run_until(duration, |_| false);
    }
    pub fn run_until(&mut self, timeout: Duration, condition: impl Fn(&Self) -> bool) -> bool {
        let end = self.now.saturating_add(timeout);
        while !condition(self) {
            let next = self
                .queue
                .first_key_value()
                .map(|(key, _)| key.0)
                .into_iter()
                .chain(self.nodes.iter().filter_map(|node| node.wake))
                .min();
            let Some(next) = next.filter(|next| *next <= end) else {
                self.now = end;
                return condition(self);
            };
            self.now = self.now.max(next);
            if self
                .queue
                .first_key_value()
                .is_some_and(|(key, _)| key.0 <= self.now)
            {
                let (_, (node, action)) = self.queue.pop_first().unwrap();
                self.act(node, action);
            } else if let Some(node) = self
                .nodes
                .iter()
                .position(|node| node.wake.is_some_and(|wake| wake <= self.now))
            {
                self.nodes[node].wake = None;
                self.send(node, Event::Tick);
            }
        }
        true
    }
    pub fn trace_digest(&self) -> String {
        self.digest
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    fn schedule(&mut self, node: NodeId, action: Action, delay: Duration) {
        self.order += 1;
        self.queue
            .insert((self.now.saturating_add(delay), self.order), (node, action));
    }
    fn connection_id(&mut self) -> ConnectionId {
        self.next_connection += 1;
        self.next_connection
    }
    fn pair(&mut self, a: NodeId, b: NodeId) -> (ConnectionId, ConnectionId) {
        let near = self.connection_id();
        let far = self.connection_id();
        self.nodes[a]
            .connections
            .insert(near, Endpoint::new(Some((b, far))));
        self.nodes[b]
            .connections
            .insert(far, Endpoint::new(Some((a, near))));
        (near, far)
    }
    pub fn connect_over(
        &mut self,
        a: NodeId,
        b: NodeId,
        expected: Option<PeerEndpoint>,
        observed: Option<String>,
    ) -> (RequestId, ConnectionId) {
        let (near, far) = self.pair(a, b);
        self.send(
            b,
            Event::ConnectionOpenedWithLocal {
                connection: far,
                direction: ConnectionDirection::Inbound,
                observed_host: Some(self.nodes[a].host.clone()),
                local_host: Some(self.nodes[b].host.clone()),
            },
        );
        let request = self.request(
            a,
            Request::ConnectOverWithLocal {
                endpoint: expected.unwrap_or_else(|| self.nodes[b].endpoint.clone()),
                connection: near,
                observed_host: observed,
                local_host: Some(self.nodes[a].host.clone()),
            },
        );
        (request, near)
    }
    pub fn delay_writes(&mut self, node: NodeId, connection: ConnectionId, delay: Duration) {
        if let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) {
            endpoint.extra_delay = delay;
        }
    }
    pub fn is_open(&self, node: NodeId, connection: ConnectionId) -> bool {
        self.nodes[node].connections.contains_key(&connection)
    }
    pub fn release_deliveries(&mut self, node: NodeId) {
        for token in std::mem::take(&mut self.nodes[node].held_deliveries) {
            self.send(node, Event::Delivered(token));
        }
    }
    pub fn release_storage(&mut self, node: NodeId) {
        self.nodes[node].stalls_storage = false;
        for (id, job) in std::mem::take(&mut self.nodes[node].stalled_jobs) {
            let result = self.answer(node, &job);
            self.schedule(
                node,
                Action::Event(Event::JobFinished(id, result)),
                Duration::ZERO,
            );
        }
    }
    fn answer(&self, node: NodeId, job: &ContentJob) -> ContentJobResult {
        let node = &self.nodes[node];
        match job {
            ContentJob::ReadVolume { root_cid, .. } => {
                ContentJobResult::Entries(node.volumes.get(root_cid).cloned().unwrap_or_default())
            }
            ContentJob::ReadBundle { root_cid } => {
                ContentJobResult::Roots(node.bundles.get(root_cid).cloned().unwrap_or_default())
            }
            ContentJob::AuthorizeVolume { peer, root_cid } => {
                ContentJobResult::Authorized((node.authorize)(peer, root_cid))
            }
        }
    }
    fn acknowledge(&mut self, node: NodeId, token: DeliveryToken) {
        if self.nodes[node].holds_deliveries {
            self.nodes[node].held_deliveries.push(token);
        } else {
            self.schedule(
                node,
                Action::Event(Event::Delivered(token)),
                self.nodes[node].delivery_delay,
            );
        }
    }
    fn perform(&mut self, node: NodeId, effect: Effect) {
        match effect {
            Effect::Dial(dial, endpoint) => {
                let target = self.nodes.iter().position(|n| {
                    n.host == endpoint.host && n.endpoint.port == endpoint.port && n.running
                });
                let target = target.filter(|target| {
                    !self
                        .partitions
                        .contains(&(node.min(*target), node.max(*target)))
                });
                if let Some(target) = target {
                    let (near, far) = self.pair(node, target);
                    self.last_dialled_connections = Some((near, far));
                    self.schedule(
                        target,
                        Action::Event(Event::ConnectionOpenedWithLocal {
                            connection: far,
                            direction: ConnectionDirection::Inbound,
                            observed_host: Some(self.nodes[node].host.clone()),
                            local_host: Some(self.nodes[target].host.clone()),
                        }),
                        self.latency,
                    );
                    self.schedule(
                        node,
                        Action::Event(Event::ConnectionOpenedWithLocal {
                            connection: near,
                            direction: ConnectionDirection::Outbound(dial),
                            observed_host: Some(self.nodes[target].host.clone()),
                            local_host: Some(self.nodes[node].host.clone()),
                        }),
                        self.latency,
                    );
                } else {
                    self.schedule(node, Action::Event(Event::DialFailed(dial)), self.latency);
                }
            }
            Effect::Write(connection, bytes) => {
                let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) else {
                    return;
                };
                if let Some((remote, far)) = endpoint.remote {
                    endpoint.undelivered += bytes.len();
                    let delay = self.latency.saturating_add(endpoint.extra_delay);
                    for chunk in bytes.chunks(self.segment_size.max(1)) {
                        self.schedule(remote, Action::Arrive(far, chunk.to_vec()), delay);
                    }
                } else {
                    self.raw_output.entry(connection).or_default().extend(bytes);
                    if !self.raw_stalled.contains(&connection) {
                        self.schedule(
                            node,
                            Action::Event(Event::Writable(connection)),
                            self.latency,
                        );
                    }
                }
            }
            Effect::Close(connection) => {
                if let Some(endpoint) = self.nodes[node].connections.remove(&connection) {
                    if let Some((remote, far)) = endpoint.remote {
                        self.schedule(remote, Action::RemoteClosed(far), self.latency);
                    } else {
                        self.raw_closed.insert(connection);
                    }
                }
            }
            Effect::PauseReading(connection) => {
                if let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) {
                    endpoint.reading = false;
                }
            }
            Effect::ResumeReading(connection) => {
                if let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) {
                    endpoint.reading = true;
                }
                self.drain(node, connection);
            }
            Effect::Deliver(token, peer, message) => {
                self.nodes[node].received.push((peer, message));
                self.acknowledge(node, token);
            }
            Effect::PeerConnected(token, peer) => {
                self.nodes[node].connected.push(peer);
                self.acknowledge(node, token);
            }
            Effect::PeerDisconnected(peer) => self.nodes[node].disconnected.push(peer),
            Effect::PublicAddressDiscovered(address) => {
                self.nodes[node].public_addresses.push(address)
            }
            Effect::Completed(id, result) => {
                self.nodes[node].results.insert(id, result);
            }
            Effect::StartJob(id, job) => {
                self.nodes[node].started_jobs.push((id, job.clone()));
                if self.nodes[node].stalls_storage {
                    self.nodes[node].stalled_jobs.push((id, job));
                } else {
                    let result = self.answer(node, &job);
                    self.schedule(
                        node,
                        Action::Event(Event::JobFinished(id, result)),
                        self.nodes[node].storage_delay,
                    );
                }
            }
            Effect::CancelJob(id) => self.nodes[node].cancelled_jobs.push(id),
            Effect::DiscoverPublicAddress => self.schedule(
                node,
                Action::Event(Event::PublicAddress(
                    self.nodes[node].observed_public_address.clone(),
                )),
                self.latency,
            ),
            Effect::WakeAt(deadline) => self.nodes[node].wake = Some(deadline),
        }
    }
    fn act(&mut self, node: NodeId, action: Action) {
        match action {
            Action::Event(event) => self.send(node, event),
            Action::Arrive(connection, bytes) => {
                if let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) {
                    endpoint.inbox.push_back(bytes);
                }
                self.drain(node, connection);
            }
            Action::RemoteClosed(connection) => {
                if let Some(endpoint) = self.nodes[node].connections.get_mut(&connection) {
                    endpoint.remote_closed = true;
                }
                self.drain(node, connection);
            }
            Action::Drained(connection) => {
                if self.nodes[node]
                    .connections
                    .get(&connection)
                    .is_some_and(|e| e.undelivered == 0)
                {
                    self.send(node, Event::Writable(connection));
                }
            }
        }
    }
    fn drain(&mut self, node: NodeId, connection: ConnectionId) {
        while let Some(endpoint) = self.nodes[node]
            .connections
            .get_mut(&connection)
            .filter(|e| e.reading)
        {
            let Some(bytes) = endpoint.inbox.pop_front() else {
                break;
            };
            let remote = endpoint.remote;
            if let Some((remote, far)) = remote {
                if let Some(writer) = self.nodes[remote].connections.get_mut(&far) {
                    writer.undelivered = writer.undelivered.saturating_sub(bytes.len());
                    if writer.undelivered == 0 {
                        self.schedule(remote, Action::Drained(far), self.latency);
                    }
                }
            }
            self.send(node, Event::Received(connection, bytes));
        }
        if self.nodes[node]
            .connections
            .get(&connection)
            .is_some_and(|e| e.remote_closed && e.inbox.is_empty())
        {
            self.nodes[node].connections.remove(&connection);
            self.send(node, Event::Closed(connection));
        }
    }
    pub fn open_raw(&mut self, node: NodeId, host: String) -> ConnectionId {
        let id = self.connection_id();
        self.nodes[node].connections.insert(id, Endpoint::new(None));
        self.send(
            node,
            Event::ConnectionOpenedWithLocal {
                connection: id,
                direction: ConnectionDirection::Inbound,
                observed_host: Some(host),
                local_host: Some(self.nodes[node].host.clone()),
            },
        );
        id
    }
    pub fn write_raw(&mut self, node: NodeId, connection: ConnectionId, bytes: Vec<u8>) {
        self.act(node, Action::Arrive(connection, bytes));
    }
    pub fn unread_bytes(&self, node: NodeId, connection: ConnectionId) -> usize {
        self.nodes[node]
            .connections
            .get(&connection)
            .map(|e| e.inbox.iter().map(Vec::len).sum())
            .unwrap_or(0)
    }
    pub fn is_reading(&self, node: NodeId, connection: ConnectionId) -> bool {
        self.nodes[node]
            .connections
            .get(&connection)
            .is_some_and(|e| e.reading)
    }
    pub fn take_raw_output(&mut self, connection: ConnectionId) -> Vec<u8> {
        self.raw_output.remove(&connection).unwrap_or_default()
    }
    pub fn set_raw_stalled(&mut self, node: NodeId, connection: ConnectionId, stalled: bool) {
        if stalled {
            self.raw_stalled.insert(connection);
        } else if self.raw_stalled.remove(&connection) {
            self.schedule(
                node,
                Action::Event(Event::Writable(connection)),
                Duration::ZERO,
            );
        }
    }
    pub fn close_raw(&mut self, node: NodeId, connection: ConnectionId) {
        if self.nodes[node].connections.remove(&connection).is_some() {
            self.send(node, Event::Closed(connection));
        }
    }
    pub fn node_closed_raw(&self, connection: ConnectionId) -> bool {
        self.raw_closed.contains(&connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configs() -> (Config, Config) {
        let sim = Simulation::new(77);
        (
            Config::new(sim.signing_key(0)),
            Config::new(sim.signing_key(1)),
        )
    }
    fn run_scenario() -> String {
        let (a_config, b_config) = configs();
        let mut sim = Simulation::new(77);
        sim.segment_size = 37;
        let a = sim.add_node(&a_config, CoreSettings::default(), None);
        let b = sim.add_node(&b_config, CoreSettings::default(), None);
        sim.start(a);
        sim.start(b);
        let connect = Request::Connect(sim.nodes[b].endpoint.clone());
        sim.set_partitioned(a, b, true);
        assert_eq!(
            sim.await_request(a, connect.clone(), Duration::from_secs(1)),
            Some(RequestResult::NoRelayAvailable)
        );
        sim.set_partitioned(a, b, false);
        assert_eq!(
            sim.await_request(a, connect, Duration::from_secs(1)),
            Some(RequestResult::Connected)
        );
        let peer = sim.nodes[a].core.authenticated_peers()[0].clone();
        let entries = vec![ContentEntry {
            cid: "root".into(),
            data: vec![23; 200_000],
        }];
        sim.nodes[b].volumes.insert("root".into(), entries.clone());
        sim.nodes[b]
            .bundles
            .insert("root".into(), vec!["root".into()]);
        sim.nodes[b].stalls_storage = true;
        sim.nodes[b]
            .ledger
            .set_standing(a_config.peer_key(), 300_000);
        let request = sim.request(
            a,
            Request::FetchVolume {
                peer: peer.clone(),
                root_cid: "root".into(),
                bundle: true,
                maximum_archive_bytes: 300_000,
                maximum_entries: 10,
            },
        );
        sim.run_for(Duration::from_secs(1));
        assert!(!sim.nodes[a].results.contains_key(&request));
        assert!(!sim.nodes[b].stalled_jobs.is_empty());
        sim.release_storage(b);
        assert!(sim.run_until(Duration::from_secs(3), |s| s.nodes[a]
            .results
            .contains_key(&request)));
        let RequestResult::Volume(volume) = &sim.nodes[a].results[&request] else {
            panic!("volume result")
        };
        assert!(volume.ended);
        assert_eq!(volume.served_by, Some(b_config.peer_key()));
        assert_eq!(volume.volumes[0].entries, entries);
        assert!(sim.nodes[b].ledger.standing(a_config.peer_key()) < 300_000);
        sim.stop(a);
        sim.stop(b);
        sim.run_for(Duration::from_secs(1));
        sim.trace_digest()
    }
    #[test]
    fn deterministic_partition_storage_and_complete_bundle_trace() {
        assert_eq!(run_scenario(), run_scenario());
    }
    #[test]
    fn held_deliveries_apply_transport_backpressure() {
        let (a_config, b_config) = configs();
        let mut sim = Simulation::new(77);
        sim.segment_size = 97;
        let a = sim.add_node(&a_config, CoreSettings::default(), None);
        let b = sim.add_node(&b_config, CoreSettings::default(), None);
        sim.start(a);
        sim.start(b);
        let endpoint = sim.nodes[b].endpoint.clone();
        assert_eq!(
            sim.await_request(a, Request::Connect(endpoint), Duration::from_secs(1)),
            Some(RequestResult::Connected)
        );
        let peer = sim.nodes[a].core.authenticated_peers()[0].clone();
        sim.run_for(Duration::from_millis(100));
        sim.nodes[b].holds_deliveries = true;
        let message = || Request::Send {
            peer: peer.key,
            session_id: Some(peer.session_id),
            message: Message::PeerMessage {
                topic: "test".into(),
                payload: vec![42; 100_000],
            },
        };
        assert_eq!(
            sim.await_request(a, message(), Duration::from_secs(1)),
            Some(RequestResult::Enqueued)
        );
        sim.run_for(Duration::from_millis(100));
        assert_eq!(sim.nodes[b].received.len(), 1);
        assert_eq!(
            sim.await_request(a, message(), Duration::from_secs(1)),
            Some(RequestResult::Enqueued)
        );
        sim.run_for(Duration::from_millis(100));
        assert_eq!(sim.nodes[b].received.len(), 1);
        let (near, far) = sim.last_dialled_connections.unwrap();
        assert!(sim.unread_bytes(b, far) > 0);
        assert!(!sim.is_reading(b, far));
        assert!(sim.is_open(a, near));
        sim.nodes[b].holds_deliveries = false;
        sim.release_deliveries(b);
        sim.run_for(Duration::from_millis(100));
        assert_eq!(sim.nodes[b].received.len(), 2);
    }
    #[test]
    fn raw_malformed_and_supplied_wrong_identity_are_closed() {
        let (a_config, b_config) = configs();
        let mut sim = Simulation::new(77);
        let a = sim.add_node(&a_config, CoreSettings::default(), None);
        let b = sim.add_node(&b_config, CoreSettings::default(), None);
        sim.start(a);
        sim.start(b);
        let raw = sim.open_raw(a, "9.9.0.1".into());
        sim.write_raw(a, raw, vec![255; 4]);
        assert!(sim.node_closed_raw(raw));
        let wrong = PeerEndpoint {
            public_key: Config::new(ed25519_dalek::SigningKey::from_bytes(&[99; 32]))
                .peer_key()
                .hex(),
            ..sim.nodes[b].endpoint.clone()
        };
        let host = sim.nodes[b].host.clone();
        let (id, conn) = sim.connect_over(a, b, Some(wrong), Some(host));
        sim.run_until(Duration::from_secs(1), |s| {
            s.nodes[a].results.contains_key(&id)
        });
        assert_eq!(sim.nodes[a].results.get(&id), Some(&RequestResult::Failed));
        assert!(!sim.is_open(a, conn));
    }
}
