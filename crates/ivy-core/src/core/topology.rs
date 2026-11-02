//! Configured-peer maintenance and bounded direct-to-relay connection fallback.
use super::*;
use std::collections::BTreeSet;
struct Fallback {
    target: PeerKey,
    attempted: BTreeSet<PeerKey>,
}
#[derive(Default)]
pub(super) struct TopologyState {
    active: BTreeMap<PeerKey, RequestId>,
    attempts: BTreeMap<PeerKey, u8>,
    scheduled: BTreeMap<PeerKey, Duration>,
    suppressed: BTreeSet<PeerKey>,
    fallback: BTreeMap<RequestId, Fallback>,
    direct_routes: BTreeMap<RequestId, VecDeque<PeerEndpoint>>,
    followers: BTreeMap<RequestId, BTreeMap<RequestId, PeerEndpoint>>,
    relaying: BTreeSet<PeerKey>,
    direct_targets: BTreeMap<RequestId, PeerKey>,
    responder_waiters: BTreeMap<RequestId, PeerKey>,
    refresh_at: Option<Duration>,
    held_disconnects: BTreeSet<PeerKey>,
}
impl<R: CoreEntropy> Core<'_, R> {
    fn configured_routes(&self, key: PeerKey) -> Vec<PeerEndpoint> {
        self.settings
            .carriers
            .iter()
            .chain(&self.settings.bootstrap_peers)
            .filter(|e| PeerKey::from_hex(&e.public_key) == Some(key))
            .cloned()
            .collect()
    }
    pub(super) fn start_topology(&mut self) {
        self.topology.suppressed.clear();
        if self.settings.mode.participates_in_public_discovery() {
            self.topology.refresh_at =
                Some(self.now.uptime.saturating_add(Duration::from_secs(30)));
        }
        let keys: BTreeSet<_> = self
            .settings
            .bootstrap_peers
            .iter()
            .chain(&self.settings.carriers)
            .filter_map(|e| PeerKey::from_hex(&e.public_key))
            .collect();
        for key in keys {
            self.maintain_peer(key);
        }
    }
    pub(super) fn stop_topology(&mut self) {
        self.topology = TopologyState::default();
    }
    pub(super) fn topology_deadline(&self) -> Option<Duration> {
        self.topology
            .scheduled
            .values()
            .copied()
            .chain(self.topology.refresh_at)
            .min()
    }
    fn maintain_peer(&mut self, key: PeerKey) {
        if !self.running
            || self.topology.suppressed.contains(&key)
            || self.topology.active.contains_key(&key)
            || self.connection(key, None).is_some()
        {
            return;
        }
        let routes = self.configured_routes(key);
        if routes.is_empty() {
            return;
        }
        self.topology.scheduled.remove(&key);

        let request = self.internal_request_id();
        self.topology.active.insert(key, request);
        self.pending.insert(request, Pending::Maintain(key));
        self.connect_routes(request, routes);
    }
    pub(super) fn maintained(&mut self, key: PeerKey, result: RequestResult) {
        self.topology.active.remove(&key);
        if result == RequestResult::Connected {
            self.topology.attempts.remove(&key);
            self.topology.scheduled.remove(&key);
        } else {
            self.schedule_reconnect(key);
        }
    }
    fn schedule_reconnect(&mut self, key: PeerKey) {
        if !self.running
            || self.topology.suppressed.contains(&key)
            || self.topology.active.contains_key(&key)
            || self.topology.scheduled.contains_key(&key)
            || self.connection(key, None).is_some()
            || self.configured_routes(key).is_empty()
        {
            return;
        }
        let attempt = self.topology.attempts.entry(key).or_default();
        *attempt = attempt.saturating_add(1).min(16);
        let exponential = 500u64 << (*attempt - 1).min(10);
        let delay = exponential.min(30_000) + self.rng.below(251).expect("nonzero jitter bound");
        self.topology.scheduled.insert(
            key,
            self.now.uptime.saturating_add(Duration::from_millis(delay)),
        );
    }
    pub(super) fn topology_disconnected(&mut self, key: PeerKey) {
        self.topology.relaying.remove(&key);
        self.schedule_reconnect(key);
    }
    pub(super) fn routing_refresh_finished(&mut self) {
        if self.running && self.settings.mode.participates_in_public_discovery() {
            self.topology.refresh_at = Some(
                self.now
                    .uptime
                    .saturating_add(self.settings.routing_refresh_interval),
            );
        }
    }
    pub(super) fn tick_topology(&mut self) {
        if self
            .topology
            .refresh_at
            .is_some_and(|at| at <= self.now.uptime)
        {
            self.topology.refresh_at = None;
            let target = self
                .rng
                .bytes32()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let request = self.internal_request_id();
            self.pending.insert(request, Pending::RoutingRefresh);
            self.find_node(request, target);
        }
        let keys: Vec<_> = self
            .topology
            .scheduled
            .iter()
            .filter(|(_, deadline)| **deadline <= self.now.uptime)
            .map(|(&key, _)| key)
            .collect();
        for key in keys {
            self.topology.scheduled.remove(&key);
            self.maintain_peer(key);
        }
    }
    pub(super) fn suppress_configured(&mut self, key: PeerKey) {
        self.topology.suppressed.insert(key);
        self.topology.scheduled.remove(&key);
        if let Some(&request) = self.topology.active.get(&key) {
            if let Some(dial) = self.dials.values_mut().find(|d| d.request == request) {
                dial.cancelled = true;
            } else {
                self.topology.active.remove(&key);
                self.cancel(request);
            }
        }
    }
    pub(super) fn restart_configured(&mut self, key: PeerKey) {
        if self.configured_routes(key).is_empty() {
            return;
        }
        // This command recycles an existing configured session. It does not
        // start disconnected peers or clear an explicit disconnect suppression.
        if let Some(conn) = self.connection(key, None) {
            self.close(conn, true, true);
        }
    }
    pub(super) fn register_connect_fallback(&mut self, request: RequestId, key: PeerKey) {
        self.topology.suppressed.remove(&key);
        self.topology.scheduled.remove(&key);
        if self.configured_carrier(key) {
            return;
        }
        self.topology.fallback.entry(request).or_insert(Fallback {
            target: key,
            attempted: BTreeSet::new(),
        });
    }
    pub(super) fn direct_netgroup_count(&self, group: &str) -> usize {
        let links = self
            .links
            .values()
            .filter(|link| {
                link.route.is_none()
                    && link
                        .observed
                        .as_deref()
                        .filter(|host| !host.is_empty())
                        .is_some_and(|host| net_group(host) == group)
            })
            .count();
        links
            + self
                .dials
                .values()
                .filter(|dial| net_group(&dial.endpoint.host) == group)
                .count()
    }
    pub(super) fn disconnected_notification(&mut self, key: PeerKey) {
        if self.verified_responder(key) {
            self.topology.held_disconnects.insert(key);
        } else {
            self.effects.push(Effect::PeerDisconnected(key));
        }
    }
    pub(super) fn resolve_held_disconnects(&mut self) {
        let ready: Vec<_> = self
            .topology
            .held_disconnects
            .iter()
            .copied()
            .filter(|&key| self.connection(key, None).is_some() || !self.verified_responder(key))
            .collect();
        for key in ready {
            self.topology.held_disconnects.remove(&key);
            if self.connection(key, None).is_none() {
                self.effects.push(Effect::PeerDisconnected(key));
            }
        }
    }
    pub(super) fn track_direct_connect(&mut self, request: RequestId, key: PeerKey) {
        self.topology.direct_targets.insert(request, key);
    }
    fn verified_responder(&self, key: PeerKey) -> bool {
        self.links.values().any(|link| {
            link.inbound_direction
                && matches!(
                    &link.state, Some(Handshake::Finishing(waiting)) if waiting.peer() == key
                )
        })
    }
    pub(super) fn await_responder(
        &mut self,
        request: RequestId,
        result: &mut RequestResult,
    ) -> bool {
        if *result != RequestResult::Failed || !self.running {
            return false;
        }
        let Some(&key) = self.topology.direct_targets.get(&request) else {
            return false;
        };
        if self.topology.suppressed.contains(&key) {
            *result = RequestResult::Cancelled;
        } else if self.connection(key, None).is_some() {
            *result = RequestResult::Connected;
        } else if self.verified_responder(key) {
            self.topology.responder_waiters.insert(request, key);
            return true;
        }
        false
    }
    pub(super) fn pump_responder_waiters(&mut self) {
        let ready: Vec<_> = self
            .topology
            .responder_waiters
            .iter()
            .filter_map(|(&id, &key)| {
                let connected = self.connection(key, None).is_some();
                (connected || !self.verified_responder(key)).then_some((id, connected))
            })
            .collect();
        for (request, connected) in ready {
            self.topology.responder_waiters.remove(&request);
            self.complete(
                request,
                if connected {
                    RequestResult::Connected
                } else {
                    RequestResult::Failed
                },
            );
        }
        let leaders: Vec<_> = self
            .topology
            .followers
            .keys()
            .copied()
            .filter(|id| !self.pending.contains_key(id))
            .collect();
        for leader in leaders {
            self.wake_connect_followers(leader);
        }
    }
    pub(super) fn finished_connect(&mut self, request: RequestId) {
        self.topology.direct_targets.remove(&request);
        self.topology.responder_waiters.remove(&request);
    }
    pub(super) fn ongoing_connect(&self, key: PeerKey, except: RequestId) -> Option<RequestId> {
        self.dials
            .values()
            .find_map(|d| {
                (!d.abandoned
                    && d.request != except
                    && PeerKey::from_hex(&d.endpoint.public_key) == Some(key))
                .then_some(d.request)
            })
            .or_else(|| {
                self.links
                    .values()
                    .filter_map(|link| {
                        let endpoint = link.endpoint.as_ref()?;
                        (PeerKey::from_hex(&endpoint.public_key) == Some(key))
                            .then_some(link.connect_request?)
                    })
                    .chain(
                        self.topology
                            .responder_waiters
                            .iter()
                            .filter_map(|(&id, &peer)| (peer == key).then_some(id)),
                    )
                    .find(|request| *request != except && self.pending.contains_key(request))
            })
    }
    pub(super) fn inbound_limit(&self) -> usize {
        self.settings.max_inbound_connections.min(
            self.settings
                .max_connections
                .saturating_sub(self.settings.reserved_outbound_connection_slots),
        )
    }
    pub(super) fn resume_explicit_peer(&mut self, key: PeerKey) {
        self.topology.suppressed.remove(&key);
    }
    pub(super) fn dial_reservation_released(&mut self, key: PeerKey) {
        self.schedule_reconnect(key);
    }
    pub(super) fn refuse_direct_binding(&mut self, request: RequestId, key: PeerKey) {
        if !self.configured_carrier(key) {
            self.topology.direct_routes.remove(&request);
            self.topology.fallback.remove(&request);
        }
        self.complete(request, RequestResult::Failed);
    }
    pub(super) fn follow_connect(
        &mut self,
        leader: RequestId,
        request: RequestId,
        endpoint: PeerEndpoint,
    ) {
        self.topology
            .followers
            .entry(leader)
            .or_default()
            .insert(request, endpoint);
    }
    pub(super) fn wake_connect_followers(&mut self, request: RequestId) {
        if let Some(followers) = self.topology.followers.remove(&request) {
            for (id, endpoint) in followers {
                if !self.pending.contains_key(&id) {
                    continue;
                }
                let key = PeerKey::from_hex(&endpoint.public_key).expect("validated follower");
                if self.connection(key, None).is_some() {
                    self.cancel_topology_request(id);
                    self.complete(id, RequestResult::Connected);
                } else if let Some(leader) = self.ongoing_connect(key, id) {
                    self.follow_connect(leader, id, endpoint);
                } else if self.verified_responder(key) {
                    self.follow_connect(request, id, endpoint);
                } else {
                    self.cancel_topology_request(id);
                    self.complete(id, RequestResult::Failed);
                }
            }
        }
    }
    pub(super) fn disconnect_peer(&mut self, key: PeerKey) {
        self.suppress_configured(key);
        self.topology.attempts.remove(&key);
        let requests: BTreeSet<_> = self
            .topology
            .direct_targets
            .iter()
            .filter_map(|(&id, &peer)| (peer == key).then_some(id))
            .chain(
                self.topology
                    .fallback
                    .iter()
                    .filter_map(|(&id, f)| (f.target == key).then_some(id)),
            )
            .collect();
        for request in requests {
            let mut awaiting_transport = false;
            for dial in self.dials.values_mut().filter(|d| d.request == request) {
                dial.cancelled = true;
                awaiting_transport = true;
            }
            if !awaiting_transport {
                self.cancel(request);
            }
        }
        self.disconnect_relay_peer(key);
        let links: Vec<_> = self.links.iter().filter_map(|(&id, link)| {
            let matching = link.peer().is_some_and(|p| p.key == key)
                || link.endpoint.as_ref().is_some_and(|e| PeerKey::from_hex(&e.public_key) == Some(key))
                || matches!(&link.state, Some(Handshake::Finishing(waiting)) if waiting.peer() == key);
            matching.then_some(id)
        }).collect();
        for link in links {
            self.close(link, true, true);
        }
    }
    /// A single connection operation exhausts its direct routes before relay.
    pub(super) fn connect_routes(&mut self, request: RequestId, routes: Vec<PeerEndpoint>) {
        let mut routes: VecDeque<_> = routes.into();
        let Some(endpoint) = routes.pop_front() else {
            self.complete(request, RequestResult::Failed);
            return;
        };
        // Every route must address the same identity; do not cross identities
        // after an authentication failure on the preceding transport.
        let key = PeerKey::from_hex(&endpoint.public_key);
        if key.is_none()
            || routes
                .iter()
                .any(|r| PeerKey::from_hex(&r.public_key) != key)
        {
            self.complete(request, RequestResult::Failed);
            return;
        }
        self.topology.direct_routes.insert(request, routes);
        self.request(request, Request::Connect(endpoint));
    }
    pub(super) fn connect_fallback(
        &mut self,
        request: RequestId,
        result: &mut RequestResult,
    ) -> bool {
        if *result != RequestResult::Failed || !self.running {
            self.topology.direct_routes.remove(&request);
            self.topology.fallback.remove(&request);
            return false;
        }
        if let Some(endpoint) = self
            .topology
            .direct_routes
            .get_mut(&request)
            .and_then(VecDeque::pop_front)
        {
            self.request(request, Request::Connect(endpoint));
            return true;
        }
        self.topology.direct_routes.remove(&request);
        self.topology.direct_targets.remove(&request);
        let Some(fallback) = self.topology.fallback.get(&request) else {
            return false;
        };
        let target = fallback.target;
        let mut carriers = self.carrier_peers();
        carriers.extend(
            self.endpoint_peers()
                .into_iter()
                .filter(|p| self.topology.relaying.contains(&p.key))
                .take(4),
        );
        let carrier = carriers.into_iter().find(|p| {
            p.key != target
                && p.route == AuthenticatedRoute::Direct
                && !fallback.attempted.contains(&p.key)
        });
        if let Some(carrier) = carrier {
            self.topology
                .fallback
                .get_mut(&request)
                .unwrap()
                .attempted
                .insert(carrier.key);
            self.connect_via_relay(request, carrier, target);
            true
        } else {
            self.topology.fallback.remove(&request);
            *result = RequestResult::NoRelayAvailable;
            false
        }
    }
    pub(super) fn cancel_topology_request(&mut self, request: RequestId) {
        self.finished_connect(request);
        self.topology.direct_routes.remove(&request);
        self.topology.fallback.remove(&request);
        for followers in self.topology.followers.values_mut() {
            followers.remove(&request);
        }
        self.topology
            .followers
            .retain(|_, followers| !followers.is_empty());
    }
    pub(super) fn set_relaying(&mut self, peer: PeerKey, relays: bool) {
        if relays && self.endpoint_peers().iter().any(|p| p.key == peer) {
            self.topology.relaying.insert(peer);
        } else {
            self.topology.relaying.remove(&peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimulationRandom;
    #[test]
    fn content_group_follows_cancelled_leader_until_transport_releases_reservation() {
        let local = Config::new(ed25519_dalek::SigningKey::from_bytes(&[94; 32]));
        let remote = Config::new(ed25519_dalek::SigningKey::from_bytes(&[95; 32]));
        let endpoint = PeerEndpoint {
            public_key: remote.peer_key().hex(),
            host: "8.8.8.8".into(),
            port: 4001,
        };
        let mut core = Core::new(&local, CoreSettings::default(), SimulationRandom::seeded(1));
        let now = Timestamp {
            uptime: Duration::ZERO,
            unix_seconds: 1000,
        };
        core.step(Event::Start, now);
        let first = core.step(Event::Request(7, Request::Connect(endpoint.clone())), now);
        assert_eq!(
            first
                .iter()
                .filter(|e| matches!(e, Effect::Dial(..)))
                .count(),
            1
        );
        let duplicate = core.step(Event::Request(8, Request::Connect(endpoint.clone())), now);
        assert!(duplicate.contains(&Effect::Completed(8, RequestResult::ConnectionInProgress)));
        assert!(!duplicate.iter().any(|e| matches!(e, Effect::Dial(..))));
        let follower = core.internal_request_id();
        core.pending.insert(follower, Pending::VolumeConnect(123));
        core.connect_routes(follower, vec![endpoint.clone()]);
        assert!(core.effects.is_empty());
        assert_eq!(core.dials.len(), 1);
        let cancelled = core.step(Event::Cancel(7), now);
        assert!(cancelled.contains(&Effect::Completed(7, RequestResult::Cancelled)));
        assert!(!cancelled.iter().any(|e| matches!(e, Effect::Dial(..))));
        assert_eq!(core.dials.len(), 1);
        assert!(core.pending.contains_key(&follower));
        let dial = *core.dials.keys().next().unwrap();
        core.step(Event::DialFailed(dial), now);
        assert!(core.dials.is_empty());
        assert!(!core.pending.contains_key(&follower));
        assert!(core.topology.followers.is_empty());
        assert!(core.topology.direct_routes.is_empty());
    }
    #[test]
    fn failed_outbound_waits_for_verified_inbound_handshake() {
        for succeeds in [true, false] {
            let local = Config::new(ed25519_dalek::SigningKey::from_bytes(&[96; 32]));
            let remote = Config::new(ed25519_dalek::SigningKey::from_bytes(&[97; 32]));
            let endpoint = PeerEndpoint {
                public_key: remote.peer_key().hex(),
                host: "8.8.8.8".into(),
                port: 4001,
            };
            let mut core = Core::new(&local, CoreSettings::default(), SimulationRandom::seeded(1));
            let now = Timestamp {
                uptime: Duration::ZERO,
                unix_seconds: 1000,
            };
            core.step(Event::Start, now);
            let effects = core.step(Event::Request(7, Request::Connect(endpoint)), now);
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
            core.step(
                Event::ConnectionOpened {
                    connection: 101,
                    direction: ConnectionDirection::Inbound,
                    observed_host: Some("8.8.8.8".into()),
                },
                now,
            );
            let (initiator, hello) =
                Initiator::start_with_nonce(&remote, local.peer_key(), [0; 32], [7; 32]).unwrap();
            let effects = core.step(Event::Received(101, frame(&hello)), now);
            let reply = effects
                .iter()
                .find_map(|e| {
                    if let Effect::Write(101, bytes) = e {
                        Some(bytes.clone())
                    } else {
                        None
                    }
                })
                .unwrap();
            let waiting = core.step(Event::DialFailed(dial), now);
            assert!(!waiting
                .iter()
                .any(|e| matches!(e, Effect::Completed(7, _) | Effect::Dial(..))));
            assert_eq!(core.topology.responder_waiters.len(), 1);
            let effects = if succeeds {
                let (_, finish) = initiator.receive(&reply[4..]).unwrap();
                core.step(Event::Received(101, frame(&finish)), now)
            } else {
                core.step(Event::Closed(101), now)
            };
            assert!(effects.contains(&Effect::Completed(
                7,
                if succeeds {
                    RequestResult::Connected
                } else {
                    RequestResult::NoRelayAvailable
                }
            )));
            assert!(core.topology.responder_waiters.is_empty());
            core.set_relaying(remote.peer_key(), true);
            assert_eq!(
                core.topology.relaying.contains(&remote.peer_key()),
                succeeds
            );
            if succeeds {
                core.step(Event::Closed(101), now);
                assert!(!core.topology.relaying.contains(&remote.peer_key()));
            }
        }
    }
}
