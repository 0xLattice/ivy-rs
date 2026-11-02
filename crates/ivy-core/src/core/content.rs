//! Session-bound volume operations and cancellable content-source jobs.
use super::*;
use crate::{
    ContentEntry, Volume, VolumeReceiveError, VolumeReceiver, VolumeResponse,
    MAX_VOLUME_ARCHIVE_BYTES,
};
use std::collections::BTreeSet;
pub type JobId = u64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentJob {
    ReadVolume {
        root_cid: String,
        max_data_bytes: usize,
    },
    ReadBundle {
        root_cid: String,
    },
    AuthorizeVolume {
        peer: AuthenticatedPeer,
        root_cid: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentJobResult {
    Entries(Vec<ContentEntry>),
    Roots(Vec<String>),
    Authorized(bool),
}
struct Fetch {
    request: RequestId,
    peer: AuthenticatedPeer,
    receiver: VolumeReceiver,
    deadline: Duration,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Waiting,
    List,
    Authorize,
    Read,
    Send,
    End,
}
struct Serving {
    peer: AuthenticatedPeer,
    root: String,
    roots: Vec<String>,
    bundle: bool,
    listed: bool,
    index: usize,
    phase: Phase,
    job: Option<JobId>,
    chunks: VecDeque<Message>,
    held: usize,
    deadline: Option<Duration>,
    arrival: u64,
}
struct Job {
    retrieval: Option<u64>,
    owner: Option<(ConnectionId, u64)>,
    reserved: usize,
}
#[derive(Default)]
pub(super) struct ContentState {
    enabled: bool,
    fetches: BTreeMap<u64, Fetch>,
    serving: BTreeMap<(ConnectionId, u64), Serving>,
    jobs: BTreeMap<JobId, Job>,
    passes: BTreeMap<PeerKey, f64>,
    virtual_time: f64,
    timeout_streaks: BTreeMap<PeerKey, u32>,
}
fn empty(failure: Option<VolumeReceiveError>) -> VolumeResponse {
    VolumeResponse {
        served_by: None,
        session_id: None,
        volumes: Vec::new(),
        ended: false,
        no_bundle: false,
        failure,
    }
}
impl<R: CoreEntropy> Core<'_, R> {
    /// Reserved incoming archives, reserved serving archives, and live source jobs.
    pub fn content_budget_usage(&self) -> (usize, usize, usize) {
        (
            self.content
                .fetches
                .values()
                .map(|f| f.receiver.reserved_bytes())
                .sum(),
            self.content_reserved(),
            self.content.jobs.len(),
        )
    }
    pub(super) fn content_deadline(&self) -> Option<Duration> {
        self.content
            .fetches
            .values()
            .map(|f| f.deadline)
            .chain(self.content.serving.values().filter_map(|s| s.deadline))
            .min()
    }
    pub(super) fn content_enabled(&mut self, enabled: bool) {
        self.content.enabled = enabled;
    }
    pub(super) fn fetch_volume(
        &mut self,
        request: RequestId,
        peer: AuthenticatedPeer,
        root: String,
        bundle: bool,
        max_archive: usize,
        max_entries: u16,
    ) {
        if !self.settings.mode.uses_overlay_services()
            && !self.settings.private_content_exchange_enabled
        {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::NotSent))),
            );
            return;
        }
        let Some(conn) = self.connection(peer.key, Some(peer.session_id)) else {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::NotSent))),
            );
            return;
        };
        if self.links[&conn].role != AuthenticatedPeerRole::Endpoint {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::NotSent))),
            );
            return;
        }
        if self.content.fetches.len() >= self.settings.max_pending_requests
            || self
                .content
                .fetches
                .values()
                .filter(|f| f.peer.key == peer.key)
                .count()
                >= self.settings.max_outstanding_volume_requests_per_peer
        {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::LocalCapacityUnavailable))),
            );
            return;
        }
        let wire = self.id();
        let Some(receiver) = VolumeReceiver::new(
            wire,
            root.clone(),
            bundle,
            max_archive,
            max_entries,
            self.settings.max_in_flight_volume_bytes,
            self.config.metadata.max_frame_size,
            self.links[&conn].route.is_some(),
        ) else {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::NotSent))),
            );
            return;
        };
        let message = if bundle {
            Message::VolumeBundleRequest {
                request_id: wire,
                root_cid: root,
            }
        } else {
            Message::VolumeRequest {
                request_id: wire,
                root_cid: root,
            }
        };
        if self.send(conn, &message) != RequestResult::Enqueued {
            self.complete(
                request,
                RequestResult::Volume(empty(Some(VolumeReceiveError::NotSent))),
            );
            return;
        }
        self.content.fetches.insert(
            wire,
            Fetch {
                request,
                peer,
                receiver,
                deadline: self
                    .now
                    .uptime
                    .saturating_add(self.settings.request_timeout),
            },
        );
    }
    fn finish_fetch(&mut self, wire: u64) {
        if let Some(fetch) = self.content.fetches.remove(&wire) {
            let mut response = fetch.receiver.finish();
            if !response.volumes.is_empty() {
                self.content.timeout_streaks.remove(&fetch.peer.key);
                response.served_by = Some(fetch.peer.key);
                response.session_id = Some(fetch.peer.session_id);
            }
            self.complete(fetch.request, RequestResult::Volume(response));
        }
    }
    pub(super) fn content_message(&mut self, conn: ConnectionId, message: &Message) -> bool {
        match message {
            Message::VolumeRequest {
                request_id,
                root_cid,
            }
            | Message::VolumeBundleRequest {
                request_id,
                root_cid,
            } => {
                let key = (conn, *request_id);
                let bundle = matches!(message, Message::VolumeBundleRequest { .. });
                let peer = self.links[&conn].peer().unwrap();
                if self.content.serving.contains_key(&key) {
                    self.ledger.record_protocol_violation(peer.key);
                    return true;
                }
                if !self.content.enabled {
                    self.send(
                        conn,
                        &if bundle {
                            Message::VolumeBundleEnd {
                                request_id: *request_id,
                            }
                        } else {
                            Message::ContentUnavailable {
                                request_id: *request_id,
                            }
                        },
                    );
                    return true;
                }
                if self.content.serving.len() >= self.settings.max_pending_requests
                    || self
                        .content
                        .serving
                        .values()
                        .filter(|s| s.peer.key == peer.key)
                        .count()
                        >= self.settings.max_outstanding_volume_requests_per_peer
                {
                    self.send(
                        conn,
                        &Message::ContentUnavailable {
                            request_id: *request_id,
                        },
                    );
                    return true;
                }
                let arrival = self.id();
                self.content.serving.insert(
                    key,
                    Serving {
                        peer,
                        root: root_cid.clone(),
                        roots: vec![root_cid.clone()],
                        bundle,
                        listed: false,
                        index: 0,
                        phase: Phase::Waiting,
                        job: None,
                        chunks: VecDeque::new(),
                        held: 0,
                        deadline: None,
                        arrival,
                    },
                );
                self.pump_content();
                true
            }
            Message::VolumeChunk { request_id, .. }
            | Message::VolumeBundleEnd { request_id }
            | Message::ContentUnavailable { request_id } => {
                let Some(peer) = self.links.get(&conn).and_then(Link::peer) else {
                    return true;
                };
                let Some(fetch) = self.content.fetches.get(request_id) else {
                    return true;
                };
                if fetch.peer.key != peer.key || fetch.peer.session_id != peer.session_id {
                    return true;
                }
                if matches!(message, Message::ContentUnavailable { .. }) {
                    self.finish_fetch(*request_id);
                    return true;
                }
                let others: usize = self
                    .content
                    .fetches
                    .iter()
                    .filter(|(id, _)| **id != *request_id)
                    .map(|(_, f)| f.receiver.reserved_bytes())
                    .sum();
                let fetch = self.content.fetches.get_mut(request_id).unwrap();
                fetch.receiver.set_global_capacity(
                    self.settings
                        .max_in_flight_volume_bytes
                        .saturating_sub(others),
                );
                if fetch.receiver.receive(message) == Err(VolumeReceiveError::ProtocolViolation) {
                    self.ledger.record_protocol_violation(peer.key);
                }
                if fetch.receiver.is_done() {
                    self.finish_fetch(*request_id);
                }
                true
            }
            _ => false,
        }
    }
    fn content_reserved(&self) -> usize {
        self.content
            .jobs
            .values()
            .map(|j| j.reserved)
            .sum::<usize>()
            + self.content.serving.values().map(|s| s.held).sum::<usize>()
    }
    fn start_content_job(
        &mut self,
        key: (ConnectionId, u64),
        phase: Phase,
        job: ContentJob,
        reserved: usize,
    ) {
        let id = self.id();
        self.content.jobs.insert(
            id,
            Job {
                retrieval: None,
                owner: Some(key),
                reserved,
            },
        );
        if let Some(s) = self.content.serving.get_mut(&key) {
            s.phase = phase;
            s.job = Some(id);
            if phase == Phase::Read {
                s.deadline = Some(
                    self.now
                        .uptime
                        .saturating_add(self.settings.request_timeout),
                );
            }
        }
        self.effects.push(Effect::StartJob(id, job));
    }
    fn end_serving(&mut self, key: (ConnectionId, u64)) {
        if let Some(s) = self.content.serving.remove(&key) {
            if let Some(job) = s.job {
                if let Some(j) = self.content.jobs.get_mut(&job) {
                    j.owner = None;
                }
                self.effects.push(Effect::CancelJob(job));
            }
        }
    }
    pub(super) fn job_finished(&mut self, id: JobId, result: ContentJobResult) {
        let Some(job) = self.content.jobs.remove(&id) else {
            return;
        };
        if let Some(retrieval) = job.retrieval {
            self.local_retrieval_finished(retrieval, result);
            return;
        }
        let Some(key) = job.owner else {
            self.pump_content();
            return;
        };
        let outgoing_limit = self.outgoing_frame_limit(key.0);
        let Some(s) = self.content.serving.get_mut(&key) else {
            self.pump_content();
            return;
        };
        if s.job != Some(id) {
            return;
        }
        s.job = None;
        if s.deadline.is_some_and(|d| d <= self.now.uptime) {
            self.end_serving(key);
            self.pump_content();
            return;
        }
        match (s.phase, result) {
            (Phase::List, ContentJobResult::Roots(roots)) => {
                let unique: BTreeSet<_> = roots.iter().collect();
                if roots.first() == Some(&s.root)
                    && unique.len() == roots.len()
                    && roots.iter().all(|r| crate::wire::accepts_cid(r))
                {
                    s.roots = roots;
                    s.listed = true;
                    s.phase = Phase::Authorize;
                } else {
                    s.phase = Phase::End;
                }
            }
            (Phase::Authorize, ContentJobResult::Authorized(true)) => s.phase = Phase::Read,
            (Phase::Read, ContentJobResult::Entries(entries)) => {
                let volume = Volume {
                    root_cid: s.roots[s.index].clone(),
                    entries,
                };
                if let Some(chunks) = volume.chunks(key.1, outgoing_limit, false) {
                    s.held = chunks
                        .iter()
                        .filter_map(|m| {
                            if let Message::VolumeChunk { payload, .. } = m {
                                Some(payload.len())
                            } else {
                                None
                            }
                        })
                        .sum();
                    s.chunks = chunks.into();
                    s.phase = Phase::Send;
                } else {
                    self.skip_serving_volume(key);
                }
            }
            _ => {
                self.skip_serving_volume(key);
            }
        }
        self.pump_content();
    }
    fn skip_serving_volume(&mut self, key: (ConnectionId, u64)) {
        let arrival = self.id();
        let Some(s) = self.content.serving.get_mut(&key) else {
            return;
        };
        if !s.bundle {
            s.phase = Phase::End;
            self.send(key.0, &Message::ContentUnavailable { request_id: key.1 });
            return;
        }
        if s.index == 0 {
            s.phase = Phase::End;
            return;
        }
        s.index += 1;
        s.arrival = arrival;
        s.phase = if s.index < s.roots.len() {
            Phase::Waiting
        } else {
            Phase::End
        };
    }
    fn serving_stride(&self, peer: PeerKey) -> f64 {
        let standing = self.ledger.serving_priority(peer).max(0.0);
        1.0 / (1.0 + (1.0 + standing / 1024.0).log2())
    }
    fn dispatch_content_slots(&mut self) {
        let waiting: BTreeSet<_> = self
            .content
            .serving
            .values()
            .filter(|s| s.phase == Phase::Waiting)
            .map(|s| s.peer.key)
            .collect();
        self.content.passes.retain(|peer, _| waiting.contains(peer));
        for peer in waiting {
            let pass = self.content.virtual_time + self.serving_stride(peer);
            self.content.passes.entry(peer).or_insert(pass);
        }
        loop {
            let active = self
                .content
                .serving
                .values()
                .filter(|s| s.phase != Phase::Waiting)
                .count()
                + self
                    .content
                    .jobs
                    .values()
                    .filter(|j| j.owner.is_none())
                    .count();
            if active >= self.settings.max_concurrent_content_requests {
                break;
            }
            let selected = self
                .content
                .serving
                .iter()
                .filter(|(_, s)| s.phase == Phase::Waiting)
                .min_by(|(_, a), (_, b)| {
                    self.content.passes[&a.peer.key]
                        .total_cmp(&self.content.passes[&b.peer.key])
                        .then_with(|| a.arrival.cmp(&b.arrival))
                })
                .map(|(&key, s)| (key, s.peer.key));
            let Some((key, peer)) = selected else {
                break;
            };
            let pass = self.content.passes[&peer];
            self.content.virtual_time = self.content.virtual_time.max(pass);
            self.content
                .passes
                .insert(peer, pass + self.serving_stride(peer));
            let s = self.content.serving.get_mut(&key).unwrap();
            s.phase = if s.bundle && !s.listed {
                Phase::List
            } else {
                Phase::Authorize
            };
            if !self
                .content
                .serving
                .values()
                .any(|s| s.phase == Phase::Waiting && s.peer.key == peer)
            {
                self.content.passes.remove(&peer);
            }
        }
    }
    pub(super) fn pump_content(&mut self) {
        // Job slots and read reservations include cancelled callbacks until the
        // shell actually reports JobFinished, so cancellation cannot evade caps.
        self.dispatch_content_slots();
        let keys: Vec<_> = self.content.serving.keys().copied().collect();
        for key in keys {
            while let Some(s) = self.content.serving.get(&key) {
                if self.connection(s.peer.key, Some(s.peer.session_id)) != Some(key.0) {
                    self.end_serving(key);
                    break;
                }
                if s.job.is_some() {
                    break;
                }
                match s.phase {
                    Phase::Waiting => break,
                    Phase::List => {
                        if self.content.jobs.len() >= self.settings.max_concurrent_content_requests
                        {
                            break;
                        }
                        let job = ContentJob::ReadBundle {
                            root_cid: s.root.clone(),
                        };
                        self.start_content_job(key, Phase::List, job, 0);
                        break;
                    }
                    Phase::Authorize => {
                        if self.content.jobs.len() >= self.settings.max_concurrent_content_requests
                        {
                            break;
                        }
                        let job = ContentJob::AuthorizeVolume {
                            peer: s.peer.clone(),
                            root_cid: s.roots[s.index].clone(),
                        };
                        self.start_content_job(key, Phase::Authorize, job, 0);
                        break;
                    }
                    Phase::Read => {
                        if self.content.jobs.len() >= self.settings.max_concurrent_content_requests
                            || MAX_VOLUME_ARCHIVE_BYTES
                                > self
                                    .settings
                                    .max_in_flight_volume_bytes
                                    .saturating_sub(self.content_reserved())
                        {
                            break;
                        }
                        let job = ContentJob::ReadVolume {
                            root_cid: s.roots[s.index].clone(),
                            max_data_bytes: MAX_VOLUME_ARCHIVE_BYTES,
                        };
                        self.start_content_job(key, Phase::Read, job, MAX_VOLUME_ARCHIVE_BYTES);
                        break;
                    }
                    Phase::Send => {
                        if let Some(message) = s.chunks.front().cloned() {
                            let peer = s.peer.key;
                            let bytes = if let Message::VolumeChunk { payload, .. } = &message {
                                payload.len()
                            } else {
                                0
                            };
                            match self.send(key.0, &message) {
                                RequestResult::Enqueued => {
                                    self.ledger.record_served(peer, bytes);
                                    self.content
                                        .serving
                                        .get_mut(&key)
                                        .unwrap()
                                        .chunks
                                        .pop_front();
                                }
                                RequestResult::Backpressured => break,
                                _ => {
                                    self.end_serving(key);
                                    break;
                                }
                            }
                        } else {
                            let arrival = self.id();
                            let s = self.content.serving.get_mut(&key).unwrap();
                            s.arrival = arrival;
                            s.held = 0;
                            s.deadline = None;
                            s.index += 1;
                            s.phase = if s.bundle && s.index < s.roots.len() {
                                Phase::Waiting
                            } else {
                                Phase::End
                            };
                        }
                    }
                    Phase::End => {
                        if s.bundle
                            && self.send(key.0, &Message::VolumeBundleEnd { request_id: key.1 })
                                == RequestResult::Backpressured
                        {
                            break;
                        }
                        self.end_serving(key);
                        break;
                    }
                }
            }
        }
    }
    pub(super) fn cancel_content(&mut self, request: RequestId) {
        self.content.fetches.retain(|_, f| f.request != request);
    }
    pub(super) fn close_content(&mut self, conn: ConnectionId) {
        let peer = self.links.get(&conn).and_then(Link::peer);
        if let Some(peer) = peer {
            self.content.timeout_streaks.remove(&peer.key);
            let fetches: Vec<_> = self
                .content
                .fetches
                .iter()
                .filter(|(_, f)| f.peer.key == peer.key && f.peer.session_id == peer.session_id)
                .map(|(&id, _)| id)
                .collect();
            for id in fetches {
                self.finish_fetch(id);
            }
        }
        let keys: Vec<_> = self
            .content
            .serving
            .keys()
            .filter(|(id, _)| *id == conn)
            .copied()
            .collect();
        for key in keys {
            self.end_serving(key);
        }
    }
    pub(super) fn tick_content(&mut self) {
        let fetches: Vec<_> = self
            .content
            .fetches
            .iter()
            .filter(|(_, f)| f.deadline <= self.now.uptime)
            .map(|(&id, _)| id)
            .collect();
        for id in fetches {
            let peer = self.content.fetches[&id].peer.key;
            let streak = self.content.timeout_streaks.entry(peer).or_default();
            *streak = streak.saturating_add(1);
            self.finish_fetch(id);
        }
        let serving: Vec<_> = self
            .content
            .serving
            .iter()
            .filter(|(_, s)| s.deadline.is_some_and(|d| d <= self.now.uptime))
            .map(|(&id, _)| id)
            .collect();
        for id in serving {
            self.end_serving(id);
        }
        self.pump_content();
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn start_local_retrieval(&mut self, retrieval: u64, root: String) -> Option<JobId> {
        if !self.content.enabled
            || self.content.jobs.len() >= self.settings.max_concurrent_content_requests
            || MAX_VOLUME_ARCHIVE_BYTES
                > self
                    .settings
                    .max_in_flight_volume_bytes
                    .saturating_sub(self.content_reserved())
        {
            return None;
        }
        let id = self.id();
        self.content.jobs.insert(
            id,
            Job {
                retrieval: Some(retrieval),
                owner: None,
                reserved: MAX_VOLUME_ARCHIVE_BYTES,
            },
        );
        self.effects.push(Effect::StartJob(
            id,
            ContentJob::ReadVolume {
                root_cid: root,
                max_data_bytes: MAX_VOLUME_ARCHIVE_BYTES,
            },
        ));
        Some(id)
    }
    pub(super) fn cancel_local_retrieval(&mut self, job: JobId) {
        if let Some(job_state) = self.content.jobs.get_mut(&job) {
            job_state.retrieval = None;
            self.effects.push(Effect::CancelJob(job));
        }
    }
}

impl<R: CoreEntropy> Core<'_, R> {
    pub(super) fn content_candidate_rank(&self, peer: PeerKey) -> (u32, usize) {
        (
            self.content
                .timeout_streaks
                .get(&peer)
                .copied()
                .unwrap_or(0),
            self.content
                .fetches
                .values()
                .filter(|f| f.peer.key == peer)
                .count(),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerLedger, SimulationRandom};
    struct Ledger {
        favored: PeerKey,
    }
    impl PeerLedger for Ledger {
        fn record_sent(&mut self, _: PeerKey, _: usize) {}
        fn record_received(&mut self, _: PeerKey, _: usize) {}
        fn record_protocol_violation(&mut self, _: PeerKey) {}
        fn serving_priority(&self, peer: PeerKey) -> f64 {
            if peer == self.favored {
                1024.
            } else {
                0.
            }
        }
    }
    #[test]
    fn contended_serving_slots_follow_tally_weight_without_starving_new_peers() {
        let config = Config::new(ed25519_dalek::SigningKey::from_bytes(&[0; 32]));
        let key = |n| {
            PeerKey::from_bytes(
                ed25519_dalek::SigningKey::from_bytes(&[n; 32])
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap()
        };
        let (a, b) = (key(1), key(2));
        let settings = CoreSettings {
            max_concurrent_content_requests: 1,
            ..CoreSettings::default()
        };
        let mut core = Core::new(&config, settings, SimulationRandom::seeded(0))
            .with_ledger(Ledger { favored: a });
        for i in 0..24u64 {
            let peer = if i % 2 == 0 { a } else { b };
            core.content.serving.insert(
                (i + 1, 1),
                Serving {
                    peer: AuthenticatedPeer {
                        role: AuthenticatedPeerRole::Endpoint,
                        route: AuthenticatedRoute::Direct,
                        key: peer,
                        session_id: [0; 32],
                        metadata: PeerMetadata::default(),
                    },
                    root: "root".into(),
                    roots: vec!["root".into()],
                    bundle: false,
                    listed: false,
                    index: 0,
                    phase: Phase::Waiting,
                    job: None,
                    chunks: VecDeque::new(),
                    held: 0,
                    deadline: None,
                    arrival: i,
                },
            );
        }
        let mut counts = [0, 0];
        for _ in 0..9 {
            core.dispatch_content_slots();
            let (id, peer) = core
                .content
                .serving
                .iter()
                .find(|(_, s)| s.phase == Phase::Authorize)
                .map(|(&id, s)| (id, s.peer.key))
                .unwrap();
            counts[usize::from(peer == b)] += 1;
            core.content.serving.remove(&id);
        }
        assert_eq!(counts, [6, 3]);
        assert!(
            core.content_deadline().is_none(),
            "queueing does not start request timeout"
        );
    }
}
