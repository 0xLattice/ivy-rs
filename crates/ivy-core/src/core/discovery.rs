//! Iterative, correlated XOR-distance discovery over authenticated sessions.
use super::*;
use crate::wire::MAX_NEIGHBOR_COUNT;
use std::collections::BTreeSet;
const PARALLELISM: usize = 3;
#[derive(Clone, Debug, PartialEq, Eq)]
struct LookupRoute {
    endpoint: PeerEndpoint,
    source: String,
}
fn selected_routes(
    routes: Vec<LookupRoute>,
    preferred: Option<&PeerEndpoint>,
    limit: usize,
) -> Vec<LookupRoute> {
    let mut unique = vec![];
    for route in routes {
        if !unique
            .iter()
            .any(|r: &LookupRoute| r.endpoint == route.endpoint)
        {
            unique.push(route);
        }
    }
    let mut selected = vec![];
    if let Some(endpoint) = preferred {
        if let Some(index) = unique.iter().position(|r| &r.endpoint == endpoint) {
            selected.push(unique.remove(index));
        } else {
            selected.push(LookupRoute {
                endpoint: endpoint.clone(),
                source: "~authenticated".into(),
            });
        }
    }
    let mut sources: BTreeMap<String, Vec<LookupRoute>> = BTreeMap::new();
    for route in unique {
        sources.entry(route.source.clone()).or_default().push(route);
    }
    for alternatives in sources.values_mut() {
        alternatives.sort_by(|a, b| {
            (&a.endpoint.host, a.endpoint.port).cmp(&(&b.endpoint.host, b.endpoint.port))
        });
    }
    for index in 0..limit {
        for alternatives in sources.values() {
            if selected.len() < limit {
                if let Some(route) = alternatives.get(index) {
                    selected.push(route.clone());
                }
            }
        }
    }
    selected.truncate(limit);
    selected
}
struct Candidate {
    routes: Vec<LookupRoute>,
    timed_out: bool,
    readmitted: bool,
    endpoint: Option<PeerEndpoint>,
    responsive: bool,
    dialing: bool,
    failed: bool,
}
impl Candidate {
    fn new(endpoint: Option<PeerEndpoint>) -> Self {
        Self {
            routes: endpoint
                .iter()
                .map(|endpoint| LookupRoute {
                    endpoint: endpoint.clone(),
                    source: "~authenticated".into(),
                })
                .collect(),
            endpoint,
            responsive: false,
            dialing: false,
            failed: false,
            timed_out: false,
            readmitted: false,
        }
    }
}
struct Lookup {
    round: usize,
    batch: Vec<PeerKey>,
    querying: bool,
    queried: BTreeSet<PeerKey>,
    responses: BTreeMap<PeerKey, Vec<PeerEndpoint>>,
    request: RequestId,
    target: [u8; 32],
    candidates: BTreeMap<PeerKey, Candidate>,
}
struct Query {
    lookup: u64,
    peer: AuthenticatedPeer,
    deadline: Duration,
}
#[derive(Default)]
pub(super) struct DiscoveryState {
    lookups: BTreeMap<u64, Lookup>,
    queries: BTreeMap<u64, Query>,
    queue: BTreeSet<u64>,
    provider_sessions: BTreeSet<PeerKey>,
}
impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn discovery_deadline(&self) -> Option<Duration> {
        self.discovery.queries.values().map(|q| q.deadline).min()
    }
    pub(super) fn find_node(&mut self, request: RequestId, target: String) {
        if !self.settings.mode.uses_overlay_services()
            || self.discovery.lookups.len() >= self.settings.max_pending_requests
        {
            self.complete(request, RequestResult::Endpoints(Vec::new()));
            return;
        }
        let mut candidates = BTreeMap::new();
        for entry in self.router.all_peers() {
            candidates.insert(entry.key, Candidate::new(Some(entry.endpoint.clone())));
        }
        for peer in self.endpoint_peers() {
            candidates.entry(peer.key).or_insert(Candidate::new(None));
        }
        let id = self.id();
        self.discovery.lookups.insert(
            id,
            Lookup {
                round: 0,
                batch: vec![],
                querying: false,
                queried: BTreeSet::new(),
                responses: BTreeMap::new(),
                request,
                target: Router::hash(&target),
                candidates,
            },
        );
        self.discovery.queue.insert(id);
    }
    fn ordered_candidates(&self, id: u64) -> Vec<PeerKey> {
        let Some(lookup) = self.discovery.lookups.get(&id) else {
            return Vec::new();
        };
        let mut peers: Vec<_> = lookup
            .candidates
            .iter()
            .filter(|(_, c)| !c.failed)
            .map(|(&p, _)| p)
            .collect();
        peers.sort_by_key(|key| {
            let mut distance = Router::hash(&key.hex());
            for (a, b) in distance.iter_mut().zip(lookup.target) {
                *a ^= b;
            }
            distance
        });
        peers
    }
    pub(super) fn pump_discovery(&mut self) {
        while let Some(id) = self.discovery.queue.pop_first() {
            if !self.running {
                self.finish_lookup(id);
                continue;
            }
            let Some(lookup) = self.discovery.lookups.get(&id) else {
                continue;
            };
            if !lookup.batch.is_empty() && lookup.querying {
                if self.discovery.queries.values().any(|q| q.lookup == id) {
                    continue;
                }
                let responses =
                    std::mem::take(&mut self.discovery.lookups.get_mut(&id).unwrap().responses);
                for (source, endpoints) in responses {
                    for endpoint in endpoints {
                        let Some(key) = PeerKey::from_hex(&endpoint.public_key) else {
                            continue;
                        };
                        let connected = self.connection(key, None).is_some();
                        let preferred = if connected {
                            self.router
                                .all_peers()
                                .find(|e| e.key == key)
                                .map(|e| e.endpoint.clone())
                        } else {
                            None
                        };
                        let lookup = self.discovery.lookups.get_mut(&id).unwrap();
                        let candidate = lookup
                            .candidates
                            .entry(key)
                            .or_insert_with(|| Candidate::new(None));
                        if candidate.failed && candidate.timed_out {
                            if candidate.readmitted
                                || connected
                                || candidate.routes.iter().any(|r| r.endpoint == endpoint)
                            {
                                continue;
                            }
                            candidate.readmitted = true;
                            candidate.timed_out = false;
                        }
                        let old = candidate.routes.clone();
                        candidate.routes.push(LookupRoute {
                            endpoint: endpoint.clone(),
                            source: source.hex(),
                        });
                        candidate.routes = selected_routes(
                            std::mem::take(&mut candidate.routes),
                            preferred.as_ref(),
                            self.settings.max_routes_per_identity,
                        );
                        candidate.endpoint = candidate
                            .routes
                            .first()
                            .map(|r| r.endpoint.clone())
                            .or(Some(endpoint));
                        if !connected && (candidate.routes != old || candidate.failed) {
                            candidate.failed = false;
                            lookup.queried.remove(&key);
                        }
                    }
                }
                let retained: BTreeSet<_> = self
                    .ordered_candidates(id)
                    .into_iter()
                    .take(self.settings.bucket_size)
                    .collect();
                let lookup = self.discovery.lookups.get_mut(&id).unwrap();
                lookup
                    .candidates
                    .retain(|key, c| c.failed || retained.contains(key));
                lookup.batch.clear();
                lookup.querying = false;
            }
            if !self.discovery.lookups[&id].batch.is_empty() {
                if self.discovery.lookups[&id]
                    .candidates
                    .values()
                    .any(|c| c.dialing)
                {
                    continue;
                }
                let lookup = self.discovery.lookups.get_mut(&id).unwrap();
                lookup.querying = true;
                let (batch, target, walk_request) =
                    (lookup.batch.clone(), lookup.target, lookup.request);
                for peer in batch {
                    let Some(conn) = self.connection(peer, None) else {
                        continue;
                    };
                    if self.discovery.queries.len() >= self.settings.max_pending_requests {
                        continue;
                    }
                    let mut nonce = self.rng.next();
                    while nonce == 0 || self.discovery.queries.contains_key(&nonce) {
                        nonce = self.rng.next();
                    }
                    if self.send(conn, &Message::FindNode { target, nonce })
                        == RequestResult::Enqueued
                    {
                        let authenticated = self.links[&conn].peer().unwrap();
                        self.discovery.queries.insert(
                            nonce,
                            Query {
                                lookup: id,
                                peer: authenticated,
                                deadline: self
                                    .now
                                    .uptime
                                    .saturating_add(Duration::from_millis(500)),
                            },
                        );
                        self.ask_providers_for_walk(walk_request, conn);
                    }
                }
                if !self.discovery.queries.values().any(|q| q.lookup == id) {
                    self.discovery.queue.insert(id);
                }
                continue;
            }
            if self.discovery.lookups[&id].round >= self.settings.bucket_size.max(1) {
                self.finish_lookup(id);
                continue;
            }
            // Router changes are incorporated only at round boundaries.
            let routes: Vec<_> = self
                .router
                .all_peers()
                .map(|entry| (entry.key, entry.endpoint.clone()))
                .collect();
            for (key, endpoint) in routes {
                let connected = self.connection(key, None).is_some();
                let lookup = self.discovery.lookups.get_mut(&id).unwrap();
                let candidate = lookup
                    .candidates
                    .entry(key)
                    .or_insert_with(|| Candidate::new(Some(endpoint.clone())));
                if candidate.failed {
                    continue;
                }
                let mut routes = vec![LookupRoute {
                    endpoint: endpoint.clone(),
                    source: "~authenticated".into(),
                }];
                routes.append(&mut candidate.routes);
                candidate.routes = selected_routes(
                    routes,
                    connected.then_some(&endpoint),
                    self.settings.max_routes_per_identity,
                );
                candidate.endpoint = candidate.routes.first().map(|r| r.endpoint.clone());
            }
            let batch: Vec<_> = self
                .ordered_candidates(id)
                .into_iter()
                .take(self.settings.bucket_size)
                .filter(|p| !self.discovery.lookups[&id].queried.contains(p))
                .take(PARALLELISM)
                .collect();
            if batch.is_empty() {
                self.finish_lookup(id);
                continue;
            }
            let lookup = self.discovery.lookups.get_mut(&id).unwrap();
            lookup.round += 1;
            lookup.batch = batch.clone();
            let mut dials = vec![];
            let provider_walk = matches!(
                self.pending.get(&self.discovery.lookups[&id].request),
                Some(Pending::ProviderWalk(_) | Pending::AnnounceWalk)
            );
            let mut provider_used = self.discovery.provider_sessions.len()
                + self
                    .discovery
                    .lookups
                    .values()
                    .filter(|l| {
                        matches!(
                            self.pending.get(&l.request),
                            Some(Pending::ProviderWalk(_) | Pending::AnnounceWalk)
                        )
                    })
                    .map(|l| l.candidates.values().filter(|c| c.dialing).count())
                    .sum::<usize>();
            for peer in batch {
                let connected = self.connection(peer, None).is_some();
                let lookup = self.discovery.lookups.get_mut(&id).unwrap();
                lookup.queried.insert(peer);
                let candidate = lookup.candidates.get_mut(&peer).unwrap();
                if !connected {
                    if provider_walk
                        && (self.settings.provider_reach == ProviderReach::ConnectedPeers
                            || provider_used >= self.settings.max_provider_walk_sessions
                            || self.links.len() + self.dials.len() + dials.len()
                                >= self.settings.max_connections.saturating_sub(
                                    self.settings.reserved_outbound_connection_slots,
                                ))
                    {
                        continue;
                    }
                    if provider_walk {
                        provider_used += 1;
                    }
                    if !candidate.routes.is_empty() {
                        candidate.dialing = true;
                        dials.push((
                            peer,
                            candidate
                                .routes
                                .iter()
                                .map(|r| r.endpoint.clone())
                                .collect::<Vec<_>>(),
                        ));
                    } else {
                        candidate.failed = true;
                    }
                }
            }
            self.discovery.queue.insert(id);
            for (peer, routes) in dials {
                let request = self.internal_request_id();
                self.pending
                    .insert(request, Pending::LookupDial { lookup: id, peer });
                self.connect_routes(request, routes);
            }
        }
    }
    pub(super) fn lookup_dial_completed(
        &mut self,
        lookup: u64,
        peer: PeerKey,
        result: RequestResult,
    ) {
        if result == RequestResult::Connected
            && self.discovery.lookups.get(&lookup).is_some_and(|l| {
                matches!(
                    self.pending.get(&l.request),
                    Some(Pending::ProviderWalk(_) | Pending::AnnounceWalk)
                )
            })
        {
            self.discovery.provider_sessions.insert(peer);
        }
        if let Some(c) = self
            .discovery
            .lookups
            .get_mut(&lookup)
            .and_then(|l| l.candidates.get_mut(&peer))
        {
            c.dialing = false;
            c.failed = result != RequestResult::Connected;
            self.discovery.queue.insert(lookup);
        }
    }
    fn finish_lookup(&mut self, id: u64) {
        let peers = self.ordered_candidates(id);
        let Some(lookup) = self.discovery.lookups.remove(&id) else {
            return;
        };
        self.discovery.queries.retain(|_, q| q.lookup != id);
        self.discovery.queue.remove(&id);
        let answered_only = matches!(
            self.pending.get(&lookup.request),
            Some(Pending::AnnounceWalk)
        );
        let endpoints = peers
            .into_iter()
            .filter_map(|p| {
                lookup
                    .candidates
                    .get(&p)
                    .filter(|c| !answered_only || c.responsive)
                    .and_then(|c| {
                        if self.connection(p, None).is_some() {
                            self.router
                                .all_peers()
                                .find(|entry| entry.key == p)
                                .map(|entry| entry.endpoint.clone())
                                .or_else(|| c.endpoint.clone())
                        } else {
                            c.endpoint.clone()
                        }
                    })
            })
            .take(self.settings.bucket_size)
            .collect();
        self.complete(lookup.request, RequestResult::Endpoints(endpoints));
    }
    pub(super) fn discovery_message(&mut self, conn: ConnectionId, message: &Message) -> bool {
        let Message::Neighbors { peers, nonce } = message else {
            return false;
        };
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return true;
        };
        let Some(query) = self.discovery.queries.get(nonce) else {
            return true;
        };
        if query.peer.key != peer.key || query.peer.session_id != peer.session_id {
            return true;
        }
        let query = self.discovery.queries.remove(nonce).unwrap();
        let Some(lookup) = self.discovery.lookups.get_mut(&query.lookup) else {
            return true;
        };
        if let Some(c) = lookup.candidates.get_mut(&peer.key) {
            c.responsive = true;
        }
        if self.settings.mode.participates_in_public_discovery() {
            let accepted = peers
                .iter()
                .take(MAX_NEIGHBOR_COUNT)
                .filter_map(|endpoint| {
                    let key = PeerKey::from_hex(&endpoint.public_key)?;
                    if key == self.config.peer_key()
                        || !self.settings.mode.allows_endpoint(key)
                        || self
                            .settings
                            .carriers
                            .iter()
                            .any(|e| PeerKey::from_hex(&e.public_key) == Some(key))
                        || endpoint.port == 0
                        || !crate::is_globally_routable(&endpoint.host)
                        || key.work_bits() < self.config.min_peer_key_bits
                    {
                        return None;
                    }
                    Some(PeerEndpoint {
                        public_key: key.hex(),
                        host: endpoint.host.trim().into(),
                        port: endpoint.port,
                    })
                })
                .collect();
            lookup.responses.insert(peer.key, accepted);
        }
        self.discovery.queue.insert(query.lookup);
        true
    }
    pub(super) fn cancel_discovery(&mut self, request: RequestId) {
        let ids: Vec<_> = self
            .discovery
            .lookups
            .iter()
            .filter(|(_, l)| l.request == request)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.discovery.lookups.remove(&id);
            self.discovery.queries.retain(|_, q| q.lookup != id);
            self.discovery.queue.remove(&id);
            let requests: Vec<_> = self
                .pending
                .iter()
                .filter_map(|(&r, p)| {
                    matches!(p,Pending::LookupDial{lookup,..} if *lookup==id).then_some(r)
                })
                .collect();
            for r in requests {
                self.cancel(r);
            }
        }
    }
    pub(super) fn close_discovery(&mut self, conn: ConnectionId) {
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return;
        };
        self.discovery.provider_sessions.remove(&peer.key);
        let nonces: Vec<_> = self
            .discovery
            .queries
            .iter()
            .filter(|(_, q)| q.peer.key == peer.key && q.peer.session_id == peer.session_id)
            .map(|(&n, _)| n)
            .collect();
        for n in nonces {
            self.expire_query(n);
        }
    }
    fn expire_query(&mut self, nonce: u64) {
        if let Some(q) = self.discovery.queries.remove(&nonce) {
            if let Some(c) = self
                .discovery
                .lookups
                .get_mut(&q.lookup)
                .and_then(|l| l.candidates.get_mut(&q.peer.key))
            {
                c.failed = true;
                c.timed_out = true;
                c.responsive = false;
            }
            self.discovery.queue.insert(q.lookup);
        }
    }
    pub(super) fn tick_discovery(&mut self) {
        let nonces: Vec<_> = self
            .discovery
            .queries
            .iter()
            .filter(|(_, q)| q.deadline <= self.now.uptime)
            .map(|(&n, _)| n)
            .collect();
        for n in nonces {
            self.expire_query(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(seed: u8) -> Config {
        Config::new(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
    fn at(seconds: u64) -> Timestamp {
        Timestamp {
            uptime: Duration::from_secs(seconds),
            unix_seconds: 1000 + seconds,
        }
    }
    fn seed_routes(core: &mut Core<crate::SimulationRandom>) {
        for seed in 61..64 {
            let key = config(seed).peer_key();
            core.router.add_peer(
                key,
                PeerEndpoint {
                    public_key: key.hex(),
                    host: "8.8.8.8".into(),
                    port: 4001,
                },
            );
        }
    }
    #[test]
    fn provider_walk_respects_connected_only_and_dial_budget() {
        let config = config(60);
        for (reach, budget, expected) in [
            (ProviderReach::ConnectedPeers, 64, 0),
            (ProviderReach::Walk, 1, 1),
            (ProviderReach::Walk, 0, 0),
        ] {
            let mut core = Core::new(
                &config,
                CoreSettings {
                    provider_reach: reach,
                    max_provider_walk_sessions: budget,
                    ..CoreSettings::default()
                },
                crate::SimulationRandom::seeded(1),
            );
            core.step(Event::Start, at(0));
            seed_routes(&mut core);
            let effects = core.step(
                Event::Request(
                    1,
                    Request::DiscoverProviders {
                        root_cid: "root".into(),
                    },
                ),
                at(1),
            );
            assert_eq!(
                effects
                    .iter()
                    .filter(|e| matches!(e, Effect::Dial(..)))
                    .count(),
                expected
            );
            core.step(Event::Stop, at(2));
            assert!(core.discovery.lookups.is_empty());
        }
    }
    #[test]
    fn reserved_outbound_capacity_refuses_inbound_and_provider_walk() {
        let bootstrap = config(70).peer_key();
        let config = config(60);
        let mut core = Core::new(
            &config,
            CoreSettings {
                max_connections: 2,
                reserved_outbound_connection_slots: 2,
                bootstrap_peers: vec![PeerEndpoint {
                    public_key: bootstrap.hex(),
                    host: "8.8.4.4".into(),
                    port: 4001,
                }],
                ..CoreSettings::default()
            },
            crate::SimulationRandom::seeded(1),
        );
        assert!(core
            .step(Event::Start, at(0))
            .iter()
            .any(|e| matches!(e, Effect::Dial(..))));
        seed_routes(&mut core);
        let effects = core.step(
            Event::Request(
                1,
                Request::DiscoverProviders {
                    root_cid: "root".into(),
                },
            ),
            at(1),
        );
        assert!(!effects.iter().any(|e| matches!(e, Effect::Dial(..))));
        assert!(core
            .step(
                Event::ConnectionOpened {
                    connection: 99,
                    direction: ConnectionDirection::Inbound,
                    observed_host: Some("1.1.1.1".into())
                },
                at(1)
            )
            .contains(&Effect::Close(99)));
        assert!(core.links.is_empty());
    }
    #[test]
    fn overlay_routing_refresh_is_periodic_internal_and_stops_cleanly() {
        let config = config(60);
        let mut core = Core::new(
            &config,
            CoreSettings {
                health_enabled: false,
                ..CoreSettings::default()
            },
            crate::SimulationRandom::seeded(1),
        );
        assert!(core
            .step(Event::Start, at(0))
            .contains(&Effect::WakeAt(Duration::from_secs(30))));
        let effects = core.step(Event::Tick, at(30));
        assert!(effects.contains(&Effect::WakeAt(Duration::from_secs(150))));
        assert!(!effects.iter().any(|e| matches!(e, Effect::Completed(..))));
        core.step(Event::Stop, at(31));
        assert!(core.step(Event::Tick, at(200)).is_empty());
    }
    #[test]
    fn lookup_route_selection_balances_sources_and_preserves_authenticated_preference() {
        let key = config(90).peer_key();
        let route = |source: &str, host: &str| LookupRoute {
            source: source.into(),
            endpoint: PeerEndpoint {
                public_key: key.hex(),
                host: host.into(),
                port: 4001,
            },
        };
        let routes = vec![
            route("a", "9.9.9.9"),
            route("a", "1.1.1.1"),
            route("b", "8.8.8.8"),
            route("b", "8.8.8.8"),
        ];
        let selected = selected_routes(routes.clone(), None, 3);
        assert_eq!(
            selected
                .iter()
                .map(|r| r.endpoint.host.as_str())
                .collect::<Vec<_>>(),
            ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        );
        let preferred = route("~authenticated", "4.4.4.4").endpoint;
        let selected = selected_routes(routes, Some(&preferred), 3);
        assert_eq!(
            selected
                .iter()
                .map(|r| r.endpoint.host.as_str())
                .collect::<Vec<_>>(),
            ["4.4.4.4", "1.1.1.1", "8.8.8.8"]
        );
    }
    #[test]
    fn timed_out_lookup_peer_is_readmitted_once_on_a_new_route() {
        let identity = config(90);
        let key = config(91).peer_key();
        let source = config(92).peer_key();
        let endpoint = |host: &str| PeerEndpoint {
            public_key: key.hex(),
            host: host.into(),
            port: 4001,
        };
        let old = endpoint("8.8.8.8");
        let new = endpoint("1.1.1.1");
        let mut core = Core::new(
            &identity,
            CoreSettings::default(),
            crate::SimulationRandom::seeded(1),
        );
        core.step(Event::Start, at(0));
        let mut candidate = Candidate::new(Some(old.clone()));
        candidate.failed = true;
        candidate.timed_out = true;
        core.discovery.lookups.insert(
            100,
            Lookup {
                round: 0,
                batch: vec![source],
                querying: true,
                queried: BTreeSet::from([key]),
                responses: BTreeMap::from([(source, vec![new.clone()])]),
                request: 200,
                target: [0; 32],
                candidates: BTreeMap::from([(key, candidate)]),
            },
        );
        core.discovery.queue.insert(100);
        core.pump_discovery();
        assert!(core.discovery.lookups[&100].candidates[&key].readmitted);
        assert!(core
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Dial(_, e) if e == &new)));
        let dial = *core.dials.keys().next().unwrap();
        let retry = core.step(Event::DialFailed(dial), at(0));
        assert!(retry
            .iter()
            .any(|e| matches!(e, Effect::Dial(_, e) if e == &old)));
        // A second timeout cannot be resurrected by a third route.
        let lookup = core.discovery.lookups.get_mut(&100).unwrap();
        let candidate = lookup.candidates.get_mut(&key).unwrap();
        candidate.failed = true;
        candidate.timed_out = true;
        candidate.dialing = false;
        lookup.batch = vec![source];
        lookup.querying = true;
        lookup.responses.insert(source, vec![endpoint("9.9.9.9")]);
        core.discovery.queue.insert(100);
        core.effects.clear();
        core.pump_discovery();
        assert!(!core.effects.iter().any(|e| matches!(e, Effect::Dial(..))));
        assert!(!core.discovery.lookups.contains_key(&100));
    }
}
