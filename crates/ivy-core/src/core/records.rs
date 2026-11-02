//! Provider rounds shared by root; replies are bound to the queried session.
use super::*;
use crate::{ProviderCache, ProviderCacheConfig, ProviderHint, ProviderRecord};
use std::collections::BTreeSet;
struct Round {
    root: String,
    walk: RequestId,
    waiters: BTreeMap<RequestId, Vec<PeerEndpoint>>,
    expected: BTreeMap<PeerKey, [u8; 32]>,
    answers: BTreeMap<PeerKey, Vec<ProviderHint>>,
    walking: bool,
    deadline: Option<Duration>,
}
pub(super) struct RecordsState {
    cache: ProviderCache,
    rounds: BTreeMap<u64, Round>,
    announcements: BTreeMap<RequestId, (String, u64)>,
}
impl RecordsState {
    pub fn new(config: &Config, settings: &CoreSettings) -> Self {
        Self {
            cache: ProviderCache::new(
                &config.signing_key,
                ProviderCacheConfig {
                    providers_per_root: settings.bucket_size,
                    routes_per_identity: settings.max_routes_per_identity,
                    records_per_source: settings.max_provider_records_per_peer,
                    total_records: settings
                        .max_connections
                        .saturating_mul(settings.max_provider_records_per_peer),
                    max_ttl_seconds: settings.max_provider_ttl_seconds,
                },
            ),
            rounds: BTreeMap::new(),
            announcements: BTreeMap::new(),
        }
    }
}
impl<R: CoreEntropy> Core<'_, R> {
    pub fn provider_memberships(&mut self, root: &str) -> Vec<(PeerKey, u64)> {
        if !self.settings.mode.uses_overlay_services() {
            return vec![];
        }
        let mut expiries = BTreeMap::<PeerKey, u64>::new();
        for hint in self.records.cache.hints(root, self.now.unix_seconds) {
            expiries
                .entry(hint.peer)
                .and_modify(|expiry| *expiry = (*expiry).max(hint.expires_at))
                .or_insert(hint.expires_at);
        }
        expiries.into_iter().collect()
    }
    pub fn providers(&mut self, root: &str) -> Vec<PeerKey> {
        if !self.settings.mode.uses_overlay_services() {
            return vec![];
        }
        let mut seen = BTreeSet::new();
        self.records
            .cache
            .hints(root, self.now.unix_seconds)
            .iter()
            .filter_map(|h| seen.insert(h.peer).then_some(h.peer))
            .collect()
    }
    pub(super) fn records_deadline(&self) -> Option<Duration> {
        self.records
            .rounds
            .values()
            .filter_map(|r| r.deadline)
            .min()
    }
    pub(super) fn discover_providers(&mut self, request: RequestId, root: String) {
        if !self.settings.mode.uses_overlay_services() || !crate::wire::accepts_cid(&root) {
            self.complete(request, RequestResult::Endpoints(vec![]));
            return;
        }
        let local = self.config.peer_key();
        let cached: Vec<_> = self
            .records
            .cache
            .hints(&root, self.now.unix_seconds)
            .iter()
            .filter(|h| h.peer != local)
            .filter_map(|h| h.endpoint.clone())
            .collect();
        if cached.iter().any(|e| {
            PeerKey::from_hex(&e.public_key).is_some_and(|p| self.connection(p, None).is_none())
        }) {
            self.complete(request, RequestResult::Endpoints(cached));
            return;
        }
        if let Some(round) = self.records.rounds.values_mut().find(|r| r.root == root) {
            if round.waiters.len() < self.settings.max_pending_requests {
                round.waiters.insert(request, cached);
            } else {
                self.complete(request, RequestResult::Endpoints(cached));
            }
            return;
        }
        if self.records.rounds.len() >= self.settings.max_pending_requests {
            self.complete(request, RequestResult::Endpoints(cached));
            return;
        }
        let mut wire = self.rng.next();
        while wire == 0 || self.records.rounds.contains_key(&wire) {
            wire = self.rng.next();
        }
        let walk = self.internal_request_id();
        self.pending.insert(walk, Pending::ProviderWalk(wire));
        self.records.rounds.insert(
            wire,
            Round {
                root: root.clone(),
                walk,
                waiters: BTreeMap::from([(request, cached)]),
                expected: BTreeMap::new(),
                answers: BTreeMap::new(),
                walking: true,
                deadline: None,
            },
        );
        self.find_node(walk, root);
    }
    pub(super) fn ask_providers_for_walk(&mut self, walk: RequestId, conn: ConnectionId) {
        let Some(Pending::ProviderWalk(wire)) = self.pending.get(&walk).copied() else {
            return;
        };
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return;
        };
        let Some(round) = self.records.rounds.get(&wire) else {
            return;
        };
        if !round.walking
            || round.expected.contains_key(&peer.key)
            || round.answers.contains_key(&peer.key)
        {
            return;
        }
        let message = Message::FindProviders {
            root_cid: round.root.clone(),
            request_id: wire,
        };
        if self.send(conn, &message) == RequestResult::Enqueued {
            self.records
                .rounds
                .get_mut(&wire)
                .unwrap()
                .expected
                .insert(peer.key, peer.session_id);
        }
    }
    pub(super) fn provider_walk_finished(&mut self, wire: u64) {
        let Some(round) = self.records.rounds.get_mut(&wire) else {
            return;
        };
        round.walking = false;
        round.deadline = Some(
            self.now
                .uptime
                .saturating_add(self.settings.request_timeout),
        );
        if round.expected.is_empty() || !self.running {
            self.resolve_providers(wire);
        }
    }
    fn resolve_providers(&mut self, wire: u64) {
        let Some(mut round) = self.records.rounds.remove(&wire) else {
            return;
        };
        self.cancel(round.walk);
        // Round-robin independent authenticated sources before accepting their
        // second hint. Cache bounds preserve identity and source quotas.
        let mut sources: Vec<_> = round.answers.keys().copied().collect();
        self.rng.shuffle(&mut sources);
        let mut indices: BTreeMap<PeerKey, usize> = sources.iter().map(|&p| (p, 0)).collect();
        let mut seen_peers = BTreeSet::new();
        let mut peers = Vec::new();
        while seen_peers.len() < self.settings.bucket_size {
            let mut progress = false;
            for source in &sources {
                let hints = &round.answers[source];
                let index = indices.get_mut(source).unwrap();
                while *index < hints.len() {
                    let hint = &hints[*index];
                    *index += 1;
                    if seen_peers.insert(hint.peer) {
                        peers.push(hint.peer);
                        progress = true;
                        break;
                    }
                }
                if seen_peers.len() == self.settings.bucket_size {
                    break;
                }
            }
            if !progress {
                break;
            }
        }
        let mut selected: Vec<ProviderHint> = Vec::new();
        let mut seen = BTreeSet::new();
        for route_index in 0..self.settings.max_routes_per_identity {
            for peer in &peers {
                for source in &sources {
                    let routes: Vec<_> = round.answers[source]
                        .iter()
                        .filter(|h| h.peer == *peer)
                        .collect();
                    if selected.iter().filter(|h| h.peer == *peer).count()
                        >= self.settings.max_routes_per_identity
                    {
                        continue;
                    }
                    if let Some(h) = routes.get(route_index) {
                        if let Some(e) = &h.endpoint {
                            if seen.insert((h.peer, e.host.clone(), e.port)) {
                                selected.push((*h).clone());
                            }
                        }
                    }
                }
            }
        }
        for hint in &selected {
            self.records
                .cache
                .store(&round.root, hint.clone(), self.now.unix_seconds);
        }
        for (request, mut cached) in std::mem::take(&mut round.waiters) {
            cached.extend(
                selected
                    .iter()
                    .filter(|h| h.peer != self.config.peer_key())
                    .filter_map(|h| h.endpoint.clone()),
            );
            let mut seen = BTreeSet::new();
            cached.retain(|e| seen.insert((e.public_key.clone(), e.host.clone(), e.port)));
            self.complete(request, RequestResult::Endpoints(cached));
        }
    }
    pub(super) fn cancel_records(&mut self, request: RequestId) {
        let ids: Vec<_> = self
            .records
            .rounds
            .iter_mut()
            .filter_map(|(&id, r)| {
                r.waiters.remove(&request);
                r.waiters.is_empty().then_some(id)
            })
            .collect();
        for id in ids {
            if let Some(r) = self.records.rounds.remove(&id) {
                self.cancel(r.walk);
            }
        }
    }
    pub(super) fn tick_records(&mut self) {
        let ids: Vec<_> = self
            .records
            .rounds
            .iter()
            .filter(|(_, r)| r.deadline.is_some_and(|d| d <= self.now.uptime))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.resolve_providers(id);
        }
    }
    pub(super) fn records_message(&mut self, conn: ConnectionId, message: &Message) -> bool {
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return false;
        };
        match message {
            Message::FindProviders {
                root_cid,
                request_id,
            } => {
                if !self.settings.mode.uses_overlay_services() {
                    return true;
                }
                let mut grouped: BTreeMap<PeerKey, Vec<ProviderRecord>> = BTreeMap::new();
                for h in self.records.cache.hints(root_cid, self.now.unix_seconds) {
                    if let Some(endpoint) = h.endpoint.clone() {
                        grouped.entry(h.peer).or_default().push(ProviderRecord {
                            endpoint,
                            expires_at: h.expires_at,
                        });
                    }
                }
                for routes in grouped.values_mut() {
                    routes.sort_by(|a, b| {
                        (&a.endpoint.host, a.endpoint.port)
                            .cmp(&(&b.endpoint.host, b.endpoint.port))
                    });
                }
                let mut keys: Vec<_> = grouped.keys().copied().collect();
                self.rng.shuffle(&mut keys);
                let mut records = Vec::new();
                for index in 0..self.settings.max_routes_per_identity {
                    for key in &keys {
                        if records.len() < crate::wire::MAX_NEIGHBOR_COUNT {
                            if let Some(r) = grouped[key].get(index) {
                                records.push(r.clone());
                            }
                        }
                    }
                }
                self.send(
                    conn,
                    &Message::Providers {
                        root_cid: root_cid.clone(),
                        request_id: *request_id,
                        records,
                    },
                );
                true
            }
            Message::AnnounceProvider {
                root_cid,
                expires_at,
            } => {
                if self.settings.mode.uses_overlay_services()
                    && self
                        .records
                        .cache
                        .expiry_is_valid(*expires_at, self.now.unix_seconds)
                {
                    let endpoint = self
                        .router
                        .all_peers()
                        .find(|e| e.key == peer.key)
                        .map(|e| e.endpoint.clone());
                    self.records.cache.store(
                        root_cid,
                        ProviderHint {
                            peer: peer.key,
                            endpoint,
                            expires_at: *expires_at,
                            source: peer.key,
                        },
                        self.now.unix_seconds,
                    );
                }
                true
            }
            Message::Providers {
                root_cid,
                request_id,
                records,
            } => {
                let Some(round) = self.records.rounds.get(request_id) else {
                    return true;
                };
                if round.root != *root_cid
                    || round.expected.get(&peer.key) != Some(&peer.session_id)
                {
                    return true;
                }
                let mut hints = Vec::new();
                for record in records {
                    let e = &record.endpoint;
                    let Some(key) = PeerKey::from_hex(&e.public_key) else {
                        continue;
                    };
                    if !self
                        .records
                        .cache
                        .expiry_is_valid(record.expires_at, self.now.unix_seconds)
                        || e.port == 0
                        || key.work_bits() < self.config.min_peer_key_bits
                        || !self.settings.mode.allows_endpoint(key)
                        || !crate::allows_discovered_host(
                            &e.host,
                            key == peer.key,
                            self.links[&conn].observed.as_deref(),
                        )
                    {
                        continue;
                    }
                    hints.push(ProviderHint {
                        peer: key,
                        endpoint: Some(PeerEndpoint {
                            public_key: key.hex(),
                            host: e.host.trim().into(),
                            port: e.port,
                        }),
                        expires_at: record.expires_at,
                        source: peer.key,
                    });
                }
                let round = self.records.rounds.get_mut(request_id).unwrap();
                round.expected.remove(&peer.key);
                round
                    .answers
                    .insert(peer.key, self.records.cache.bounded(hints, root_cid));
                if !round.walking && round.expected.is_empty() {
                    self.resolve_providers(*request_id);
                }
                true
            }
            _ => false,
        }
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn announce_provider(&mut self, root: String, expiry: u64) {
        if !self.settings.mode.uses_overlay_services()
            || !crate::wire::accepts_cid(&root)
            || !self
                .records
                .cache
                .expiry_is_valid(expiry, self.now.unix_seconds)
        {
            return;
        }
        let key = self.config.peer_key();
        if let Some(address) = self
            .config
            .metadata
            .listen_addresses
            .iter()
            .find(|a| a.port != 0 && crate::is_globally_routable(&a.host))
        {
            self.records.cache.store(
                &root,
                ProviderHint {
                    peer: key,
                    endpoint: Some(PeerEndpoint {
                        public_key: key.hex(),
                        host: address.host.clone(),
                        port: address.port,
                    }),
                    expires_at: expiry,
                    source: key,
                },
                self.now.unix_seconds,
            );
        }
        if !self.running {
            return;
        }
        if let Some((_, expires)) = self
            .records
            .announcements
            .values_mut()
            .find(|(r, _)| *r == root)
        {
            *expires = expiry;
            return;
        }
        let request = self.internal_request_id();
        self.records
            .announcements
            .insert(request, (root.clone(), expiry));
        self.pending.insert(request, Pending::AnnounceWalk);
        self.find_node(request, root);
    }
    pub(super) fn announce_walk_finished(&mut self, request: RequestId, result: RequestResult) {
        let Some((root, expiry)) = self.records.announcements.remove(&request) else {
            return;
        };
        if !self.running || result == RequestResult::Cancelled {
            return;
        }
        let mut keys: Vec<_> = match result {
            RequestResult::Endpoints(es) => es
                .iter()
                .filter_map(|e| PeerKey::from_hex(&e.public_key))
                .filter(|&p| self.connection(p, None).is_some())
                .collect(),
            _ => vec![],
        };
        if keys.is_empty() {
            keys = self
                .router
                .closest_peers(&Router::hash(&root), self.settings.bucket_size)
                .iter()
                .map(|e| e.key)
                .filter(|&p| self.connection(p, None).is_some())
                .collect();
        }
        for key in keys {
            if let Some(conn) = self.connection(key, None) {
                self.send(
                    conn,
                    &Message::AnnounceProvider {
                        root_cid: root.clone(),
                        expires_at: expiry,
                    },
                );
            }
        }
    }
    pub(super) fn stop_providing(&mut self, root: &str) {
        self.records.cache.stop_providing(root);
        let walks: Vec<_> = self
            .records
            .announcements
            .iter()
            .filter(|(_, (r, _))| r == root)
            .map(|(&id, _)| id)
            .collect();
        for walk in walks {
            self.records.announcements.remove(&walk);
            self.cancel(walk);
        }
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn cached_provider_endpoints(&mut self, root: &str) -> Vec<PeerEndpoint> {
        self.records
            .cache
            .hints(root, self.now.unix_seconds)
            .iter()
            .filter_map(|h| h.endpoint.clone())
            .collect()
    }
    pub(super) fn forget_provider(&mut self, root: &str, peer: PeerKey) {
        self.records.cache.forget(root, peer);
    }
}

#[cfg(test)]
mod retrieval_order_tests {
    use super::*;
    use crate::SimulationRandom;
    fn config(seed: u8) -> Config {
        Config::new(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
    fn at(s: u64) -> Timestamp {
        Timestamp {
            uptime: Duration::from_secs(s),
            unix_seconds: 1000 + s,
        }
    }
    fn endpoint(key: PeerKey, host: &str) -> PeerEndpoint {
        PeerEndpoint {
            public_key: key.hex(),
            host: host.into(),
            port: 4001,
        }
    }
    #[test]
    fn cached_provider_group_and_alternate_routes_finish_before_connected_fallback() {
        let local = config(140);
        let remote = config(141);
        let first = config(142).peer_key();
        let second = config(143).peer_key();
        let mut a = Core::new(&local, CoreSettings::default(), SimulationRandom::seeded(1));
        let mut b = Core::new(
            &remote,
            CoreSettings::default(),
            SimulationRandom::seeded(2),
        );
        a.step(Event::Start, at(0));
        b.step(Event::Start, at(0));
        let effects = a.step(
            Event::Request(1, Request::Connect(endpoint(remote.peer_key(), "8.8.8.8"))),
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
        let mut queue = VecDeque::from([
            (
                false,
                Event::ConnectionOpened {
                    connection: 77,
                    direction: ConnectionDirection::Inbound,
                    observed_host: Some("8.8.8.8".into()),
                },
            ),
            (
                true,
                Event::ConnectionOpened {
                    connection: 77,
                    direction: ConnectionDirection::Outbound(dial),
                    observed_host: Some("8.8.8.8".into()),
                },
            ),
        ]);
        while let Some((side, event)) = queue.pop_front() {
            let effects = if side {
                a.step(event, at(0))
            } else {
                b.step(event, at(0))
            };
            for effect in effects {
                match effect {
                    Effect::Write(id, bytes) => {
                        queue.push_back((!side, Event::Received(id, bytes)));
                        queue.push_back((side, Event::Writable(id)));
                    }
                    Effect::PeerConnected(token, _) => {
                        queue.push_back((side, Event::Delivered(token)))
                    }
                    _ => {}
                }
            }
        }
        for (peer, host) in [(first, "1.1.1.1"), (first, "1.0.0.1"), (second, "8.8.4.4")] {
            assert!(a.records.cache.store(
                "root",
                ProviderHint {
                    peer,
                    endpoint: Some(endpoint(peer, host)),
                    source: peer,
                    expires_at: 2000
                },
                1000
            ));
        }
        let effects = a.step(
            Event::Request(
                2,
                Request::RetrieveVolume {
                    root_cid: "root".into(),
                    maximum_archive_bytes: 1_000_000,
                    maximum_entries: 10,
                },
            ),
            at(1),
        );
        assert!(!effects.iter().any(|e| matches!(e, Effect::Write(..))));
        let dials: BTreeMap<_, _> = effects
            .iter()
            .filter_map(|e| {
                if let Effect::Dial(id, endpoint) = e {
                    Some((endpoint.public_key.clone(), *id))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(dials.len(), 2);
        let failed = a.step(Event::DialFailed(dials[&first.hex()]), at(1));
        assert!(!failed.iter().any(|e| matches!(e, Effect::Write(..))));
        let retry = failed
            .iter()
            .find_map(|e| {
                if let Effect::Dial(id, endpoint) = e {
                    assert_eq!(endpoint.public_key, first.hex());
                    Some(*id)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(!a
            .step(Event::DialFailed(dials[&second.hex()]), at(1))
            .iter()
            .any(|e| matches!(e, Effect::Write(..))));
        let fallback = a.step(Event::DialFailed(retry), at(1));
        assert!(fallback.iter().any(|e| matches!(e, Effect::Write(77, _))));
        a.step(Event::Cancel(2), at(1));
        assert!(a.dials.is_empty());
    }
}
