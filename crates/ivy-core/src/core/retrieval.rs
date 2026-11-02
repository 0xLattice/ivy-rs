//! Sequential exact-session candidate retrieval. Partial bundles retain attribution.
use super::*;
use crate::{VolumeReceiveError, VolumeResponse};
use std::collections::BTreeSet;
struct Retrieval {
    local_job: Option<JobId>,
    discover: bool,
    stage: u8,
    cached: Vec<PeerEndpoint>,
    fresh: Vec<PeerEndpoint>,
    connecting: BTreeMap<RequestId, (PeerKey, VecDeque<PeerEndpoint>)>,
    tried: BTreeSet<PeerKey>,
    request: RequestId,
    root: String,
    bundle: bool,
    max_archive: usize,
    max_entries: u16,
    peers: VecDeque<AuthenticatedPeer>,
    active: Option<RequestId>,
    wait_deadline: Option<Duration>,
    last: VolumeResponse,
}
#[derive(Default)]
pub(super) struct RetrievalState {
    operations: BTreeMap<u64, Retrieval>,
    queue: BTreeSet<u64>,
    deficient: BTreeMap<String, BTreeMap<PeerKey, Duration>>,
    rotation: usize,
}
impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn retrieval_deadline(&self) -> Option<Duration> {
        self.retrieval
            .operations
            .values()
            .filter_map(|r| r.wait_deadline)
            .min()
    }
    pub(super) fn fetch_sessions(
        &mut self,
        request: RequestId,
        root: String,
        bundle: bool,
        peers: Vec<AuthenticatedPeer>,
        max_archive: usize,
        max_entries: u16,
    ) -> u64 {
        // Last session supplied for a repeated identity wins, as in Swift.
        let mut sessions = BTreeMap::new();
        let mut order = Vec::new();
        for peer in peers {
            if !sessions.contains_key(&peer.key) {
                order.push(peer.key);
            }
            sessions.insert(peer.key, peer);
        }
        let peers: Vec<_> = order
            .into_iter()
            .filter_map(|key| sessions.remove(&key))
            .collect();

        let id = self.id();
        self.retrieval.operations.insert(
            id,
            Retrieval {
                local_job: None,
                discover: false,
                stage: 0,
                cached: vec![],
                fresh: vec![],
                connecting: BTreeMap::new(),
                tried: BTreeSet::new(),
                request,
                root,
                bundle,
                max_archive,
                max_entries,
                peers: peers.into(),
                active: None,
                wait_deadline: None,
                last: VolumeResponse {
                    served_by: None,
                    session_id: None,
                    volumes: vec![],
                    ended: false,
                    no_bundle: false,
                    failure: None,
                },
            },
        );
        self.retrieval.queue.insert(id);
        id
    }
    pub(super) fn retrieval_answer(&mut self, id: u64, result: RequestResult) {
        let Some(r) = self.retrieval.operations.get_mut(&id) else {
            return;
        };
        r.active = None;
        if let RequestResult::Volume(response) = result {
            let success = !response.volumes.is_empty();
            if success
                || (r.bundle && response.failure != Some(VolumeReceiveError::NotSent))
                || (!r.bundle && (response.failure.is_some() || r.last.failure.is_none()))
            {
                r.last = response;
            }
            if success {
                r.peers.clear();
                r.discover = false;
            }
        }
        self.retrieval.queue.insert(id);
    }
    pub(super) fn cancel_retrieval(&mut self, request: RequestId) {
        let ids: Vec<_> = self
            .retrieval
            .operations
            .iter()
            .filter(|(_, r)| r.request == request)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            if let Some(r) = self.retrieval.operations.remove(&id) {
                self.retrieval.queue.remove(&id);
                if let Some(job) = r.local_job {
                    self.cancel_local_retrieval(job);
                }
                if let Some(active) = r.active {
                    self.cancel(active);
                }
                for request in r.connecting.keys() {
                    self.cancel(*request);
                }
            }
        }
    }
    pub(super) fn pump_retrieval(&mut self) {
        // A writable notification can unlock any waiting candidate.
        self.retrieval.queue.extend(
            self.retrieval
                .operations
                .iter()
                .filter(|(_, r)| r.active.is_none() && r.local_job.is_none())
                .map(|(&id, _)| id),
        );
        while let Some(id) = self.retrieval.queue.pop_first() {
            let Some(r) = self.retrieval.operations.get(&id) else {
                continue;
            };
            if r.active.is_some() || r.local_job.is_some() || !r.connecting.is_empty() {
                continue;
            }
            if !r.peers.is_empty() {
                let mut open: Vec<_> = r
                    .peers
                    .iter()
                    .enumerate()
                    .filter_map(|(index, peer)| {
                        let rank = self.content_candidate_rank(peer.key);
                        (rank.1 < self.settings.max_outstanding_volume_requests_per_peer)
                            .then_some((index, rank))
                    })
                    .collect();
                self.rng.shuffle(&mut open);
                let Some((index, _)) = open.into_iter().min_by_key(|(_, rank)| *rank) else {
                    continue;
                };
                let peers = &mut self.retrieval.operations.get_mut(&id).unwrap().peers;
                let peer = peers.remove(index).unwrap();
                peers.push_front(peer);
            }
            let r = &self.retrieval.operations[&id];
            let Some(peer) = r.peers.front().cloned() else {
                if r.discover && r.stage < 6 {
                    self.advance_retrieval(id);
                    continue;
                }
                let r = self.retrieval.operations.remove(&id).unwrap();
                self.complete(r.request, RequestResult::Volume(r.last));
                continue;
            };
            let conn = self.connection(peer.key, Some(peer.session_id));
            if let Some(conn) = conn {
                if !self.transport_writable(conn, false) {
                    let r = self.retrieval.operations.get_mut(&id).unwrap();
                    if r.wait_deadline.is_some_and(|d| d <= self.now.uptime) {
                        r.peers.pop_front();
                        r.wait_deadline = None;
                        self.retrieval.queue.insert(id);
                    } else {
                        r.wait_deadline.get_or_insert(
                            self.now
                                .uptime
                                .saturating_add(self.settings.request_timeout),
                        );
                    }
                    continue;
                }
            }
            let request = self.internal_request_id();
            self.pending.insert(request, Pending::VolumeAttempt(id));
            let r = self.retrieval.operations.get_mut(&id).unwrap();
            r.peers.pop_front();
            r.tried.insert(peer.key);
            r.wait_deadline = None;
            r.active = Some(request);
            let (root, bundle, max_archive, max_entries) =
                (r.root.clone(), r.bundle, r.max_archive, r.max_entries);
            self.fetch_volume(request, peer, root, bundle, max_archive, max_entries);
        }
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn retrieve_volume(
        &mut self,
        request: RequestId,
        root: String,
        max_archive: usize,
        max_entries: u16,
    ) {
        let id = self.fetch_sessions(
            request,
            root.clone(),
            false,
            vec![],
            max_archive,
            max_entries,
        );
        self.retrieval.operations.get_mut(&id).unwrap().discover = true;
        let local = self.start_local_retrieval(id, root);
        self.retrieval.operations.get_mut(&id).unwrap().local_job = local;
    }
    pub(super) fn local_retrieval_finished(&mut self, id: u64, result: ContentJobResult) {
        let Some(r) = self.retrieval.operations.get_mut(&id) else {
            return;
        };
        r.local_job = None;
        if let ContentJobResult::Entries(entries) = result {
            let volume = crate::Volume {
                root_cid: r.root.clone(),
                entries,
            };
            // Swift's local read is already bounded by the serving reservation;
            // caller archive/entry boundaries apply to remote advertisements.
            if volume.encode().is_some() {
                r.last.volumes.push(volume);
                r.last.ended = true;
                r.peers.clear();
                r.discover = false;
            }
        }
        self.retrieval.queue.insert(id);
    }
    pub(super) fn retrieval_discovered(&mut self, id: u64, result: RequestResult) {
        let Some(r) = self.retrieval.operations.get_mut(&id) else {
            return;
        };
        r.active = None;
        r.stage = 4;
        if let RequestResult::Endpoints(endpoints) = result {
            r.fresh = endpoints;
        }
        self.retrieval.queue.insert(id);
    }
    pub(super) fn retrieval_connected(
        &mut self,
        id: u64,
        request: RequestId,
        _result: RequestResult,
    ) {
        let Some(r) = self.retrieval.operations.get_mut(&id) else {
            return;
        };
        r.connecting.remove(&request);
        self.retrieval.queue.insert(id);
    }
    fn connect_retrieval_group(&mut self, id: u64, endpoints: Vec<PeerEndpoint>) {
        let mut groups: BTreeMap<PeerKey, VecDeque<PeerEndpoint>> = BTreeMap::new();
        let mut order = vec![];
        for endpoint in endpoints {
            let Some(key) = PeerKey::from_hex(&endpoint.public_key) else {
                continue;
            };
            if key == self.config.peer_key()
                || self.configured_carrier(key)
                || self.is_deficient(&self.retrieval.operations[&id].root, key)
                || self.connection(key, None).is_some()
            {
                continue;
            }
            if !groups.contains_key(&key) {
                if groups.len() >= self.settings.max_content_candidates {
                    continue;
                }
                order.push(key);
            }
            let routes = groups.entry(key).or_default();
            if routes.len() < self.settings.max_routes_per_identity && !routes.contains(&endpoint) {
                routes.push_back(endpoint);
            }
        }
        // Register every member before launching: an immediate failure must not
        // let another member finish the group while it is still being built.
        let mut actions = vec![];
        for key in order {
            let routes = groups.remove(&key).unwrap();
            let request = self.internal_request_id();
            self.retrieval
                .operations
                .get_mut(&id)
                .unwrap()
                .connecting
                .insert(request, (key, VecDeque::new()));
            self.pending.insert(request, Pending::VolumeConnect(id));
            actions.push((request, routes));
        }
        for (request, routes) in actions {
            self.connect_routes(request, routes.into());
        }
    }
    fn advance_retrieval(&mut self, id: u64) {
        let root = self.retrieval.operations[&id].root.clone();
        let stage = self.retrieval.operations[&id].stage;
        match stage {
            0 => {
                let cached = self.cached_provider_endpoints(&root);
                let r = self.retrieval.operations.get_mut(&id).unwrap();
                r.cached = cached.clone();
                r.stage = 1;
                self.connect_retrieval_group(id, cached);
            }
            1 | 2 | 5 => {
                let providers: Vec<_> = self
                    .providers(&root)
                    .into_iter()
                    .chain(
                        self.retrieval.operations[&id]
                            .fresh
                            .iter()
                            .filter_map(|e| PeerKey::from_hex(&e.public_key)),
                    )
                    .collect();
                let mut peers = self.endpoint_peers();
                peers.sort_by_key(|p| p.key);
                peers.retain(|p| !self.is_deficient(&root, p.key));
                if stage == 2 && !peers.is_empty() {
                    let offset = self.retrieval.rotation % peers.len();
                    peers.rotate_left(offset);
                    let selected = peers.len().min(self.settings.max_content_candidates);
                    self.retrieval.rotation = (offset + selected) % peers.len();
                    peers.truncate(selected);
                }
                if stage != 2 {
                    peers.retain(|p| providers.contains(&p.key));
                    peers.sort_by_key(|p| providers.iter().position(|k| *k == p.key).unwrap());
                }
                peers.retain(|p| !self.retrieval.operations[&id].tried.contains(&p.key));
                peers.truncate(self.settings.max_content_candidates);
                let r = self.retrieval.operations.get_mut(&id).unwrap();
                r.peers = peers.into();
                r.stage = if stage == 1 {
                    2
                } else if stage == 2 {
                    3
                } else {
                    6
                };
            }
            3 => {
                let request = self.internal_request_id();
                let r = self.retrieval.operations.get_mut(&id).unwrap();
                r.active = Some(request);
                self.pending.insert(request, Pending::VolumeDiscovery(id));
                self.discover_providers(request, root);
            }
            4 => {
                let r = self.retrieval.operations.get_mut(&id).unwrap();
                r.stage = 5;
                let endpoints = r.fresh.iter().chain(&r.cached).cloned().collect();
                self.connect_retrieval_group(id, endpoints);
            }
            _ => {}
        }
        self.retrieval.queue.insert(id);
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    fn is_deficient(&self, root: &str, peer: PeerKey) -> bool {
        self.retrieval
            .deficient
            .get(root)
            .and_then(|peers| peers.get(&peer))
            .is_some_and(|until| *until > self.now.uptime)
    }
    pub(super) fn report_deficient(&mut self, root: String, peer: PeerKey) {
        if !crate::wire::accepts_cid(&root) {
            return;
        }
        self.forget_provider(&root, peer);
        if !self.retrieval.deficient.contains_key(&root) && self.retrieval.deficient.len() >= 10_000
        {
            let evicted = self
                .retrieval
                .deficient
                .iter()
                .min_by_key(|(root, peers)| (peers.values().max().copied(), *root))
                .map(|(root, _)| root.clone());
            if let Some(evicted) = evicted {
                self.retrieval.deficient.remove(&evicted);
            }
        }
        let peers = self.retrieval.deficient.entry(root).or_default();
        if !peers.contains_key(&peer) && peers.len() >= self.settings.bucket_size {
            let evicted = peers
                .iter()
                .min_by_key(|(key, expiry)| (**expiry, **key))
                .map(|(&key, _)| key);
            if let Some(evicted) = evicted {
                peers.remove(&evicted);
            }
        }
        peers.insert(
            peer,
            self.now.uptime.saturating_add(Duration::from_secs(30)),
        );
    }
}
