//! Bounded carrier-side relay routes. Endpoint records remain opaque to carriers.
use super::*;
const MAX_ROUTES: usize = 64;
const MAX_PER_SOURCE: usize = 8;
const IDLE: Duration = Duration::from_secs(300);
struct Route {
    source: AuthenticatedPeer,
    target: AuthenticatedPeer,
    ready: bool,
    deadline: Duration,
}
#[derive(Clone)]
pub(super) struct RelayLink {
    pub route_id: [u8; 32],
    pub carrier_connection: ConnectionId,
    pub carrier_key: PeerKey,
    pub remote: PeerKey,
}
struct Installed {
    carrier: AuthenticatedPeer,
    remote: PeerKey,
    link: Option<ConnectionId>,
    deadline: Duration,
}
struct Open {
    carrier: AuthenticatedPeer,
    target: PeerKey,
    request: RequestId,
    deadline: Duration,
}
struct Forward {
    route: [u8; 32],
    destination: ConnectionId,
    message: Message,
    token: DeliveryToken,
    deadline: Duration,
}
#[derive(Default)]
pub(super) struct RelayState {
    routes: BTreeMap<[u8; 32], Route>,
    installed: BTreeMap<[u8; 32], Installed>,
    opens: BTreeMap<[u8; 32], Open>,
    forwards: BTreeMap<ConnectionId, Forward>,
}
impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn disconnect_relay_peer(&mut self, key: PeerKey) {
        let requests: Vec<_> = self
            .relay
            .opens
            .values()
            .filter(|open| open.target == key || open.carrier.key == key)
            .map(|open| open.request)
            .collect();
        for request in requests {
            self.cancel(request);
        }
        let installed: Vec<_> = self
            .relay
            .installed
            .iter()
            .filter(|(_, route)| route.remote == key || route.carrier.key == key)
            .map(|(&id, _)| id)
            .collect();
        for id in installed {
            self.close_installed(id, true);
        }
        let routes: Vec<_> = self
            .relay
            .routes
            .iter()
            .filter(|(_, route)| route.source.key == key || route.target.key == key)
            .map(|(&id, _)| id)
            .collect();
        for id in routes {
            self.retire_route(id, None);
        }
    }
    pub(super) fn relay_deadline(&self) -> Option<Duration> {
        self.relay
            .routes
            .values()
            .map(|r| r.deadline)
            .chain(self.relay.forwards.values().map(|f| f.deadline))
            .chain(self.relay.opens.values().map(|o| o.deadline))
            .chain(
                self.relay
                    .installed
                    .values()
                    .filter(|r| r.link.is_none())
                    .map(|r| r.deadline),
            )
            .min()
    }
    fn relay_to(&mut self, peer: &AuthenticatedPeer, message: &Message) -> RequestResult {
        self.connection(peer.key, Some(peer.session_id))
            .map(|c| self.send(c, message))
            .unwrap_or(RequestResult::NotConnected)
    }
    fn retire_route(&mut self, id: [u8; 32], excluded: Option<PeerKey>) {
        let Some(route) = self.relay.routes.remove(&id) else {
            return;
        };
        for peer in [route.source, route.target] {
            if Some(peer.key) != excluded {
                self.relay_to(&peer, &Message::RelayClose { route_id: id });
            }
        }
        let sources: Vec<_> = self
            .relay
            .forwards
            .iter()
            .filter(|(_, f)| f.route == id)
            .map(|(&c, _)| c)
            .collect();
        for source in sources {
            self.end_forward(source);
        }
    }
    fn end_forward(&mut self, source: ConnectionId) {
        if let Some(f) = self.relay.forwards.remove(&source) {
            self.delivered(f.token);
        }
    }
    pub(super) fn close_relay(&mut self, conn: ConnectionId) {
        self.close_relay_endpoints(conn);
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return;
        };
        let ids: Vec<_> = self
            .relay
            .routes
            .iter()
            .filter(|(_, r)| r.source == peer || r.target == peer)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.retire_route(id, Some(peer.key));
        }
    }
    pub(super) fn tick_relay(&mut self) {
        self.tick_relay_endpoints();
        let ids: Vec<_> = self
            .relay
            .routes
            .iter()
            .filter(|(_, r)| r.deadline <= self.now.uptime)
            .map(|(&id, _)| id)
            .chain(
                self.relay
                    .forwards
                    .values()
                    .filter(|f| f.deadline <= self.now.uptime)
                    .map(|f| f.route),
            )
            .collect();
        for id in ids {
            self.retire_route(id, None);
        }
    }
    pub(super) fn writable_relay(&mut self, conn: ConnectionId) {
        let sources: Vec<_> = self
            .relay
            .forwards
            .iter()
            .filter(|(_, f)| f.destination == conn)
            .map(|(&s, _)| s)
            .collect();
        for source in sources {
            let Some(f) = self.relay.forwards.get(&source) else {
                continue;
            };
            let id = f.route;
            let message = f.message.clone();
            match self.send(conn, &message) {
                RequestResult::Enqueued => self.end_forward(source),
                RequestResult::Backpressured => {}
                _ => self.retire_route(id, None),
            }
        }
    }
    pub(super) fn relay_message(&mut self, conn: ConnectionId, message: &Message) -> bool {
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return false;
        };
        if self.links[&conn].route.is_some() {
            return matches!(
                message,
                Message::RelayOpen { .. }
                    | Message::RelayOffer { .. }
                    | Message::RelayAccept { .. }
                    | Message::RelayReady { .. }
                    | Message::RelayPacket { .. }
                    | Message::RelayClose { .. }
            );
        }
        if self.endpoint_relay_message(conn, message) {
            return true;
        }
        match message {
            Message::RelayOpen {
                route_id,
                target_key,
            } => {
                if !self.route_unknown(route_id) {
                    self.ledger.record_protocol_violation(peer.key);
                    return true;
                }
                let target = self
                    .connection(*target_key, None)
                    .filter(|c| self.links[c].route.is_none())
                    .and_then(|c| self.links[&c].peer());
                if !self.settings.relay_enabled
                    || !self.settings.mode.uses_overlay_services()
                    || self.relay.routes.len() >= MAX_ROUTES
                    || self
                        .relay
                        .routes
                        .values()
                        .filter(|r| r.source.key == peer.key)
                        .count()
                        >= MAX_PER_SOURCE
                    || *target_key == peer.key
                    || target.is_none()
                {
                    self.send(
                        conn,
                        &Message::RelayReady {
                            route_id: *route_id,
                            status: 1,
                        },
                    );
                    return true;
                }
                let target = target.unwrap();
                self.relay.routes.insert(
                    *route_id,
                    Route {
                        source: peer.clone(),
                        target: target.clone(),
                        ready: false,
                        deadline: self.now.uptime.saturating_add(self.settings.relay_timeout),
                    },
                );
                if self.relay_to(
                    &target,
                    &Message::RelayOffer {
                        route_id: *route_id,
                        source_key: peer.key,
                    },
                ) != RequestResult::Enqueued
                {
                    self.relay.routes.remove(route_id);
                    self.send(
                        conn,
                        &Message::RelayReady {
                            route_id: *route_id,
                            status: 1,
                        },
                    );
                }
                true
            }
            Message::RelayAccept { route_id, status } => {
                let Some(route) = self.relay.routes.get_mut(route_id) else {
                    return true;
                };
                if route.target != peer {
                    self.ledger.record_protocol_violation(peer.key);
                    return true;
                }
                let source = route.source.clone();
                if *status != 0 {
                    self.relay.routes.remove(route_id);
                    self.relay_to(
                        &source,
                        &Message::RelayReady {
                            route_id: *route_id,
                            status: *status,
                        },
                    );
                    return true;
                }
                route.ready = true;
                route.deadline = self.now.uptime.saturating_add(IDLE);
                if self.relay_to(
                    &source,
                    &Message::RelayReady {
                        route_id: *route_id,
                        status: 0,
                    },
                ) != RequestResult::Enqueued
                {
                    self.retire_route(*route_id, None);
                }
                true
            }
            Message::RelayClose { route_id } => {
                let Some(route) = self.relay.routes.get(route_id) else {
                    return true;
                };
                if route.source == peer || route.target == peer {
                    self.retire_route(*route_id, Some(peer.key));
                }
                true
            }
            Message::RelayPacket { route_id, .. } => {
                let Some(route) = self.relay.routes.get_mut(route_id) else {
                    return true;
                };
                let destination = if route.source == peer {
                    route.target.clone()
                } else if route.target == peer {
                    route.source.clone()
                } else {
                    self.ledger.record_protocol_violation(peer.key);
                    return true;
                };
                if !route.ready {
                    return true;
                }
                route.deadline = self.now.uptime.saturating_add(IDLE);
                let Some(dest) = self.connection(destination.key, Some(destination.session_id))
                else {
                    self.retire_route(*route_id, None);
                    return true;
                };
                match self.send(dest, message) {
                    RequestResult::Enqueued => {}
                    RequestResult::Backpressured => {
                        let token = self.id();
                        self.links.get_mut(&conn).unwrap().blocked = Some(token);
                        self.deliveries.insert(token, conn);
                        self.relay.forwards.insert(
                            conn,
                            Forward {
                                route: *route_id,
                                destination: dest,
                                message: message.clone(),
                                token,
                                deadline: self
                                    .now
                                    .uptime
                                    .saturating_add(self.settings.request_timeout),
                            },
                        );
                    }
                    _ => self.retire_route(*route_id, None),
                }
                true
            }
            _ => false,
        }
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    fn route_unknown(&self, id: &[u8; 32]) -> bool {
        *id != [0; 32]
            && !self.relay.routes.contains_key(id)
            && !self.relay.installed.contains_key(id)
            && !self.relay.opens.contains_key(id)
    }
    pub(super) fn outgoing_frame_limit(&self, conn: ConnectionId) -> u32 {
        let Some(link) = self.links.get(&conn) else {
            return 0;
        };
        let own = link
            .peer()
            .map(|p| p.metadata.max_frame_size)
            .unwrap_or(self.config.metadata.max_frame_size);
        if let Some(route) = &link.route {
            own.min(
                self.links
                    .get(&route.carrier_connection)
                    .and_then(Link::peer)
                    .map(|p| p.metadata.max_frame_size.saturating_sub(150))
                    .unwrap_or(0),
            )
        } else {
            own
        }
    }
    pub(super) fn transport_writable(&self, conn: ConnectionId, reserve: bool) -> bool {
        let Some(link) = self.links.get(&conn) else {
            return true;
        };
        if let Some(route) = &link.route {
            return self.transport_writable(route.carrier_connection, reserve);
        }
        link.writable() || (reserve && link.reserve_used < WRITE_HIGH_WATER_MARK)
    }
    pub(super) fn carrier_has_blocked_endpoint(&self, conn: ConnectionId) -> bool {
        self.links.values().any(|l| {
            l.route
                .as_ref()
                .is_some_and(|r| r.carrier_connection == conn)
                && (l.blocked.is_some() || l.stalled)
        })
    }
    pub(super) fn pump_relay_carriers(&mut self) {
        let carriers: std::collections::BTreeSet<_> = self
            .links
            .values()
            .filter_map(|l| l.route.as_ref().map(|r| r.carrier_connection))
            .collect();
        for carrier in carriers {
            self.pump(carrier);
        }
    }
    pub(super) fn writable_relay_endpoints(&mut self, carrier: ConnectionId) {
        let links: Vec<_> = self
            .links
            .iter()
            .filter(|(_, l)| {
                l.route
                    .as_ref()
                    .is_some_and(|r| r.carrier_connection == carrier)
            })
            .map(|(&id, _)| id)
            .collect();
        for link in links {
            self.writable(link);
        }
    }
    pub(super) fn connect_via_relay(
        &mut self,
        request: RequestId,
        carrier: AuthenticatedPeer,
        target: PeerKey,
    ) {
        if !self.settings.mode.uses_overlay_services()
            || target == self.config.peer_key()
            || target == carrier.key
            || !self.settings.mode.allows_endpoint(target)
            || self.relay.opens.len() + self.relay.installed.len() >= MAX_ROUTES
            || self
                .relay
                .opens
                .values()
                .filter(|r| r.carrier.key == carrier.key)
                .count()
                + self
                    .relay
                    .installed
                    .values()
                    .filter(|r| r.carrier.key == carrier.key)
                    .count()
                >= MAX_PER_SOURCE
        {
            self.complete(request, RequestResult::Failed);
            return;
        }
        let Some(conn) = self
            .connection(carrier.key, Some(carrier.session_id))
            .filter(|c| self.links[c].route.is_none())
        else {
            self.complete(request, RequestResult::Failed);
            return;
        };
        if self.connection(target, None).is_some() {
            self.complete(request, RequestResult::Connected);
            return;
        }
        let mut route = self.rng.bytes32();
        while !self.route_unknown(&route) {
            route = self.rng.bytes32();
        }
        self.relay.opens.insert(
            route,
            Open {
                carrier,
                target,
                request,
                deadline: self.now.uptime.saturating_add(self.settings.relay_timeout),
            },
        );
        if self.send(
            conn,
            &Message::RelayOpen {
                route_id: route,
                target_key: target,
            },
        ) != RequestResult::Enqueued
        {
            self.relay.opens.remove(&route);
            self.complete(request, RequestResult::Failed);
        }
    }
    pub(super) fn cancel_relay_open(&mut self, request: RequestId) {
        let ids: Vec<_> = self
            .relay
            .opens
            .iter()
            .filter(|(_, o)| o.request == request)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            if let Some(open) = self.relay.opens.remove(&id) {
                self.relay_to(&open.carrier, &Message::RelayClose { route_id: id });
            }
        }
    }
    fn close_installed(&mut self, id: [u8; 32], notify: bool) {
        let Some(route) = self.relay.installed.remove(&id) else {
            return;
        };
        if notify {
            self.relay_to(&route.carrier, &Message::RelayClose { route_id: id });
        }
        if let Some(link) = route.link {
            self.close(link, false, true);
        }
    }
    fn close_relay_endpoints(&mut self, conn: ConnectionId) {
        let own_route = self.links.get(&conn).and_then(|l| l.route.clone());
        if let Some(route) = own_route {
            if let Some(installed) = self.relay.installed.remove(&route.route_id) {
                self.relay_to(
                    &installed.carrier,
                    &Message::RelayClose {
                        route_id: route.route_id,
                    },
                );
            }
            return;
        }
        let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
            return;
        };
        let installed: Vec<_> = self
            .relay
            .installed
            .iter()
            .filter(|(_, r)| r.carrier == peer)
            .map(|(&id, _)| id)
            .collect();
        for id in installed {
            self.close_installed(id, false);
        }
        let opens: Vec<_> = self
            .relay
            .opens
            .iter()
            .filter(|(_, r)| r.carrier == peer)
            .map(|(&id, _)| id)
            .collect();
        for id in opens {
            if let Some(open) = self.relay.opens.remove(&id) {
                self.complete(open.request, RequestResult::Failed);
            }
        }
    }
    fn tick_relay_endpoints(&mut self) {
        let opens: Vec<_> = self
            .relay
            .opens
            .iter()
            .filter(|(_, o)| o.deadline <= self.now.uptime)
            .map(|(&id, _)| id)
            .collect();
        for id in opens {
            if let Some(open) = self.relay.opens.remove(&id) {
                self.relay_to(&open.carrier, &Message::RelayClose { route_id: id });
                self.complete(open.request, RequestResult::Failed);
            }
        }
        let idle: Vec<_> = self
            .relay
            .installed
            .iter()
            .filter(|(_, r)| r.link.is_none() && r.deadline <= self.now.uptime)
            .map(|(&id, _)| id)
            .collect();
        for id in idle {
            self.close_installed(id, true);
        }
    }
    fn install_relay_link(
        &mut self,
        id: [u8; 32],
        request: Option<RequestId>,
    ) -> Option<ConnectionId> {
        if self.links.len() + self.dials.len() >= self.settings.max_connections
            || (request.is_none() && self.links.len() + self.dials.len() >= self.inbound_limit())
        {
            return None;
        }
        let route = self.relay.installed.get(&id)?;
        let remote = route.remote;
        let carrier_key = route.carrier.key;
        let carrier = self.connection(route.carrier.key, Some(route.carrier.session_id))?;
        let mut link_id = self.id() | (1u64 << 63);
        while self.links.contains_key(&link_id) {
            link_id = self.id() | (1u64 << 63);
        }
        let (state, hello) = if request.is_some() {
            let (initiator, hello) = Initiator::start_with_metadata(
                self.config,
                remote,
                id,
                self.rng.bytes32(),
                self.local_metadata(None),
            )
            .ok()?;
            (Handshake::Initiating(initiator), Some(hello))
        } else {
            (Handshake::Incoming, None)
        };
        self.links.insert(
            link_id,
            Link {
                local_host: None,
                role: AuthenticatedPeerRole::Endpoint,
                route: Some(RelayLink {
                    route_id: id,
                    carrier_connection: carrier,
                    carrier_key,
                    remote,
                }),
                state: Some(state),
                endpoint: None,
                inbound: VecDeque::new(),
                header: vec![],
                expected_body: None,
                body: vec![],
                charged: 0,
                stalled: false,
                observed: None,
                inbound_direction: request.is_none(),
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
        self.relay.installed.get_mut(&id).unwrap().link = Some(link_id);
        if let Some(hello) = hello {
            if self.write(link_id, hello, true) != RequestResult::Enqueued {
                self.close_installed(id, true);
                return None;
            }
        }
        Some(link_id)
    }
    fn endpoint_relay_message(&mut self, conn: ConnectionId, message: &Message) -> bool {
        let peer = self.links[&conn].peer().unwrap();
        match message {
            Message::RelayOffer {
                route_id,
                source_key,
            } => {
                if !self.settings.mode.uses_overlay_services()
                    || *source_key == self.config.peer_key()
                    || *source_key == peer.key
                    || !self.settings.mode.allows_endpoint(*source_key)
                    || !self.route_unknown(route_id)
                    || self.relay.installed.len() + self.relay.opens.len() >= MAX_ROUTES
                    || self
                        .relay
                        .installed
                        .values()
                        .filter(|r| r.carrier.key == peer.key)
                        .count()
                        + self
                            .relay
                            .opens
                            .values()
                            .filter(|r| r.carrier.key == peer.key)
                            .count()
                        >= MAX_PER_SOURCE
                {
                    self.send(
                        conn,
                        &Message::RelayAccept {
                            route_id: *route_id,
                            status: 1,
                        },
                    );
                    return true;
                }
                self.relay.installed.insert(
                    *route_id,
                    Installed {
                        carrier: peer,
                        remote: *source_key,
                        link: None,
                        deadline: self.now.uptime.saturating_add(self.settings.relay_timeout),
                    },
                );
                if self.send(
                    conn,
                    &Message::RelayAccept {
                        route_id: *route_id,
                        status: 0,
                    },
                ) != RequestResult::Enqueued
                {
                    self.relay.installed.remove(route_id);
                }
                true
            }
            Message::RelayReady { route_id, status } => {
                let Some(open) = self.relay.opens.get(route_id) else {
                    return true;
                };
                if open.carrier != peer {
                    self.ledger.record_protocol_violation(peer.key);
                    return true;
                }
                let open = self.relay.opens.remove(route_id).unwrap();
                if *status != 0 {
                    self.complete(open.request, RequestResult::Failed);
                    return true;
                }
                self.relay.installed.insert(
                    *route_id,
                    Installed {
                        carrier: peer,
                        remote: open.target,
                        link: None,
                        deadline: self.now.uptime.saturating_add(self.settings.relay_timeout),
                    },
                );
                if self
                    .install_relay_link(*route_id, Some(open.request))
                    .is_none()
                {
                    self.close_installed(*route_id, true);
                    self.complete(open.request, RequestResult::Failed);
                }
                true
            }
            Message::RelayPacket {
                route_id,
                opaque_endpoint_record,
            } => {
                let Some(route) = self.relay.installed.get(route_id) else {
                    return false;
                };
                if route.carrier != peer {
                    return true;
                }
                let link = route
                    .link
                    .or_else(|| self.install_relay_link(*route_id, None));
                if let Some(link) = link {
                    self.received(link, frame(opaque_endpoint_record));
                } else {
                    self.close_installed(*route_id, true);
                }
                true
            }
            Message::RelayClose { route_id } => {
                if let Some(route) = self.relay.installed.get(route_id) {
                    if route.carrier == peer {
                        self.close_installed(*route_id, false);
                    }
                    return true;
                }
                if let Some(open) = self.relay.opens.get(route_id) {
                    if open.carrier == peer {
                        let open = self.relay.opens.remove(route_id).unwrap();
                        self.complete(open.request, RequestResult::Failed);
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }
}
