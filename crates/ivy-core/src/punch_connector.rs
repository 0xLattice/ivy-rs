//! Deterministic punch signalling coordinator. The shell prepares sockets,
//! sends signals through the exact authenticated session, and hands winners to
//! Core's supplied-stream path. No candidate has authority to identify a peer.
use crate::{
    core::{AuthenticatedPeer, AuthenticatedPeerRole, AuthenticatedRoute},
    punch::{Candidate, Signal},
    PeerKey,
};
use std::{collections::BTreeMap, time::Duration};
pub const MAX_ATTEMPTS: usize = 3;
pub const MAX_CONCURRENT_ATTEMPTS: usize = 8;
pub const MAX_SIGNALS: usize = 8;
#[derive(Clone, Debug)]
pub struct Options {
    pub auto_upgrade: bool,
    pub deadline: Duration,
    pub dial_window: Duration,
    pub allow_private_candidates: bool,
    pub transports: Vec<u8>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            auto_upgrade: true,
            deadline: Duration::from_secs(15),
            dial_window: Duration::from_secs(6),
            allow_private_candidates: false,
            transports: vec![Candidate::TCP],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Prepare {
        ticket: u64,
        peer: AuthenticatedPeer,
    },
    Send {
        ticket: u64,
        peer: AuthenticatedPeer,
        signal: Signal,
    },
    Dial {
        ticket: u64,
        peer: AuthenticatedPeer,
        candidates: Vec<Candidate>,
        initiator: bool,
        at: Duration,
        deadline: Duration,
    },
    /// Release losing/prepared sockets; a handed stream belongs to the node.
    Release {
        ticket: u64,
        peer: AuthenticatedPeer,
    },
    Finished {
        peer: AuthenticatedPeer,
        direct: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Requested,
    Preparing,
    AwaitingAnswer(Duration),
    AwaitingSync,
    Dialling,
    Handed,
}
struct Attempt {
    ticket: u64,
    peer: AuthenticatedPeer,
    id: u32,
    phase: Phase,
    remote: Vec<Candidate>,
    received: usize,
    deadline: Duration,
}
/// Method timestamps are monotonic elapsed durations. Tick at `next_deadline`;
/// execute Dial at its stated time rather than blocking the coordinator.
pub struct Connector {
    local: PeerKey,
    options: Options,
    sessions: BTreeMap<PeerKey, (AuthenticatedPeer, usize)>,
    attempts: BTreeMap<PeerKey, Attempt>,
    counter: u32,
    ticket: u64,
    now: Duration,
    closed: bool,
}
impl Connector {
    pub fn new(local: PeerKey, options: Options) -> Self {
        Self {
            local,
            options,
            sessions: BTreeMap::new(),
            attempts: BTreeMap::new(),
            counter: 0,
            ticket: 0,
            now: Duration::ZERO,
            closed: false,
        }
    }
    pub fn next_deadline(&self) -> Option<Duration> {
        self.attempts.values().map(|a| a.deadline).min()
    }
    fn time(&mut self, now: Duration) {
        self.now = self.now.max(now);
    }
    fn offers(&self, key: PeerKey) -> bool {
        self.local.hex() < key.hex()
    }
    fn is_relay(peer: &AuthenticatedPeer) -> bool {
        peer.role == AuthenticatedPeerRole::Endpoint
            && matches!(peer.route, AuthenticatedRoute::Relayed { .. })
    }
    fn end(&mut self, key: PeerKey, tell: bool, direct: bool) -> Vec<Action> {
        let Some(attempt) = self.attempts.remove(&key) else {
            return vec![];
        };
        let mut out = vec![Action::Release {
            ticket: attempt.ticket,
            peer: attempt.peer.clone(),
        }];
        if tell && attempt.id != 0 {
            out.push(Action::Send {
                ticket: attempt.ticket,
                peer: attempt.peer.clone(),
                signal: Signal::Abandon(attempt.id),
            });
        }
        out.push(Action::Finished {
            peer: attempt.peer,
            direct,
        });
        out
    }
    fn begin(&mut self, key: PeerKey, phase: Phase) -> bool {
        if self.closed || self.attempts.len() >= MAX_CONCURRENT_ATTEMPTS {
            return false;
        }
        let Some((peer, count)) = self.sessions.get_mut(&key) else {
            return false;
        };
        if !Self::is_relay(peer) || *count >= MAX_ATTEMPTS {
            return false;
        }
        *count += 1;
        self.ticket = self.ticket.checked_add(1).expect("punch ticket exhausted");
        self.attempts.insert(
            key,
            Attempt {
                ticket: self.ticket,
                peer: peer.clone(),
                id: 0,
                phase,
                remote: vec![],
                received: 0,
                deadline: self.now.saturating_add(self.options.deadline),
            },
        );
        true
    }
    pub fn connected(&mut self, peer: AuthenticatedPeer, now: Duration) -> Vec<Action> {
        self.time(now);
        if self.closed {
            return vec![];
        }
        let direct = peer.route == AuthenticatedRoute::Direct;
        let mut out = self.end(peer.key, false, direct);
        self.sessions.insert(peer.key, (peer.clone(), 0));
        if self.options.auto_upgrade && Self::is_relay(&peer) {
            out.extend(self.upgrade(&peer, now));
        }
        out
    }
    pub fn disconnected(&mut self, key: PeerKey) -> Vec<Action> {
        self.sessions.remove(&key);
        if self
            .attempts
            .get(&key)
            .is_some_and(|a| a.phase == Phase::Handed)
        {
            vec![]
        } else {
            self.end(key, false, false)
        }
    }
    /// Repeated callers join the active attempt; Finished is broadcast by the shell.
    pub fn upgrade(&mut self, peer: &AuthenticatedPeer, now: Duration) -> Vec<Action> {
        self.time(now);
        let Some((known, _)) = self.sessions.get(&peer.key) else {
            return vec![Action::Finished {
                peer: peer.clone(),
                direct: false,
            }];
        };
        if known.role != AuthenticatedPeerRole::Endpoint || self.closed {
            return vec![Action::Finished {
                peer: peer.clone(),
                direct: false,
            }];
        }
        if known.route == AuthenticatedRoute::Direct {
            return vec![Action::Finished {
                peer: known.clone(),
                direct: true,
            }];
        }
        if known.session_id != peer.session_id {
            return vec![Action::Finished {
                peer: peer.clone(),
                direct: false,
            }];
        }
        if self.attempts.contains_key(&peer.key) {
            return vec![];
        }
        let offer = self.offers(peer.key);
        if !self.begin(
            peer.key,
            if offer {
                Phase::Preparing
            } else {
                Phase::Requested
            },
        ) {
            return vec![Action::Finished {
                peer: peer.clone(),
                direct: false,
            }];
        }
        if offer {
            vec![Action::Prepare {
                ticket: self.attempts[&peer.key].ticket,
                peer: peer.clone(),
            }]
        } else {
            vec![Action::Send {
                ticket: self.attempts[&peer.key].ticket,
                peer: peer.clone(),
                signal: Signal::Request,
            }]
        }
    }
    /// Results of socket preparation must include the original session token.
    pub fn prepared(
        &mut self,
        ticket: u64,
        peer: &AuthenticatedPeer,
        candidates: Vec<Candidate>,
        now: Duration,
    ) -> Vec<Action> {
        self.time(now);
        let offer = self.offers(peer.key);
        let Some(a) = self.attempts.get_mut(&peer.key) else {
            return vec![];
        };
        if a.ticket != ticket || a.peer != *peer || a.phase != Phase::Preparing {
            return vec![];
        }
        let candidates: Vec<_> = candidates
            .into_iter()
            .take(crate::punch::MAX_CANDIDATES)
            .collect();
        if candidates.is_empty()
            || candidates.iter().any(|c| c.port == 0)
            || Signal::Offer(1, candidates.clone()).encode().is_none()
        {
            return self.end(peer.key, !offer, false);
        }
        let signal = if offer {
            self.counter = self.counter.wrapping_add(1).max(1);
            a.id = self.counter;
            a.phase = Phase::AwaitingAnswer(self.now);
            Signal::Offer(a.id, candidates)
        } else {
            a.phase = Phase::AwaitingSync;
            Signal::Answer(a.id, candidates)
        };
        vec![Action::Send {
            ticket: a.ticket,
            peer: peer.clone(),
            signal,
        }]
    }
    fn acceptable(&self, candidates: Vec<Candidate>) -> Vec<Candidate> {
        candidates
            .into_iter()
            .filter(|c| {
                c.port != 0
                    && self.options.transports.contains(&c.transport)
                    && (self.options.allow_private_candidates
                        || crate::is_globally_routable(&c.host))
            })
            .collect()
    }
    pub fn signalled(
        &mut self,
        peer: &AuthenticatedPeer,
        payload: &[u8],
        now: Duration,
    ) -> Vec<Action> {
        self.time(now);
        if self.closed
            || !Self::is_relay(peer)
            || self
                .sessions
                .get(&peer.key)
                .is_none_or(|(p, _)| p.session_id != peer.session_id)
        {
            return vec![];
        }
        let Some(signal) = Signal::decode(payload) else {
            return self.end(peer.key, true, false);
        };
        let offer = self.offers(peer.key);
        if signal == Signal::Request {
            return if offer && !self.attempts.contains_key(&peer.key) {
                self.upgrade(peer, now)
            } else {
                vec![]
            };
        }
        if let Signal::Offer(id, candidates) = signal {
            if offer {
                return vec![];
            }
            let remote = self.acceptable(candidates);
            if let Some(a) = self.attempts.get_mut(&peer.key) {
                if a.phase != Phase::Requested {
                    return vec![];
                }
                a.phase = Phase::Preparing;
            } else if !self.begin(peer.key, Phase::Preparing) {
                return vec![];
            }
            let a = self.attempts.get_mut(&peer.key).unwrap();
            a.id = id;
            a.remote = remote;
            if a.remote.is_empty() {
                return self.end(peer.key, true, false);
            }
            return vec![Action::Prepare {
                ticket: self.attempts[&peer.key].ticket,
                peer: peer.clone(),
            }];
        }
        let id = match &signal {
            Signal::Answer(id, _) | Signal::Sync(id) | Signal::Abandon(id) => *id,
            _ => return vec![],
        };
        let Some(a) = self.attempts.get_mut(&peer.key) else {
            return vec![];
        };
        if a.id != id {
            return vec![];
        }
        a.received += 1;
        if a.received > MAX_SIGNALS {
            return self.end(peer.key, true, false);
        }
        let phase = a.phase;
        match (signal, phase) {
            (Signal::Abandon(_), _) => self.end(peer.key, false, false),
            (Signal::Answer(_, candidates), Phase::AwaitingAnswer(sent)) if offer => {
                let remote = self.acceptable(candidates);
                if remote.is_empty() {
                    return self.end(peer.key, true, false);
                }
                let a = self.attempts.get_mut(&peer.key).unwrap();
                a.remote = remote.clone();
                a.phase = Phase::Dialling;
                let at = self.now.saturating_add(self.now.saturating_sub(sent) / 2);
                vec![
                    Action::Send {
                        ticket: a.ticket,
                        peer: peer.clone(),
                        signal: Signal::Sync(id),
                    },
                    Action::Dial {
                        ticket: a.ticket,
                        peer: peer.clone(),
                        candidates: remote,
                        initiator: true,
                        at,
                        deadline: at.saturating_add(self.options.dial_window).min(a.deadline),
                    },
                ]
            }
            (Signal::Sync(_), Phase::AwaitingSync) if !offer => {
                let a = self.attempts.get_mut(&peer.key).unwrap();
                a.phase = Phase::Dialling;
                vec![Action::Dial {
                    ticket: a.ticket,
                    peer: peer.clone(),
                    candidates: a.remote.clone(),
                    initiator: false,
                    at: self.now,
                    deadline: self
                        .now
                        .saturating_add(self.options.dial_window)
                        .min(a.deadline),
                }]
            }
            _ => self.end(peer.key, true, false),
        }
    }
    /// Call before handing a winning stream to Core. Failure preserves the relay.
    pub fn dial_finished(
        &mut self,
        ticket: u64,
        peer: &AuthenticatedPeer,
        success: bool,
    ) -> Vec<Action> {
        let Some(a) = self.attempts.get_mut(&peer.key) else {
            return vec![];
        };
        if a.ticket != ticket || a.peer != *peer || a.phase != Phase::Dialling {
            return vec![];
        }
        if success {
            a.phase = Phase::Handed;
            vec![Action::Release {
                ticket: a.ticket,
                peer: peer.clone(),
            }]
        } else {
            self.end(peer.key, true, false)
        }
    }
    /// A failed exact-session send or handshake ends only the matching attempt.
    pub fn failed(&mut self, ticket: u64, peer: &AuthenticatedPeer) -> Vec<Action> {
        if self
            .attempts
            .get(&peer.key)
            .is_some_and(|a| a.ticket == ticket && a.peer == *peer)
        {
            self.end(peer.key, false, false)
        } else {
            vec![]
        }
    }
    pub fn tick(&mut self, now: Duration) -> Vec<Action> {
        self.time(now);
        let expired: Vec<_> = self
            .attempts
            .iter()
            .filter(|(_, a)| a.deadline <= self.now)
            .map(|(k, _)| *k)
            .collect();
        expired
            .into_iter()
            .flat_map(|k| self.end(k, true, false))
            .collect()
    }
    pub fn close(&mut self) -> Vec<Action> {
        self.closed = true;
        self.sessions.clear();
        let keys: Vec<_> = self.attempts.keys().copied().collect();
        keys.into_iter()
            .flat_map(|k| self.end(k, false, false))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, PeerMetadata};
    fn peers() -> (AuthenticatedPeer, AuthenticatedPeer) {
        let mut keys: Vec<_> = (1..=3)
            .map(|n| Config::new(ed25519_dalek::SigningKey::from_bytes(&[n; 32])).peer_key())
            .collect();
        keys.sort_by_key(|k| k.hex());
        let peer = |key| AuthenticatedPeer {
            key,
            role: AuthenticatedPeerRole::Endpoint,
            route: AuthenticatedRoute::Relayed {
                carrier: keys[2],
                route_id: [1; 32],
            },
            session_id: [2; 32],
            metadata: PeerMetadata::default(),
        };
        (peer(keys[0]), peer(keys[1]))
    }
    fn candidates() -> Vec<Candidate> {
        vec![Candidate {
            transport: Candidate::TCP,
            host: "8.8.8.8".into(),
            port: 1234,
        }]
    }
    fn prepared_ticket(actions: &[Action]) -> u64 {
        match actions[0] {
            Action::Prepare { ticket, .. } => ticket,
            _ => panic!("expected preparation"),
        }
    }
    fn signal(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send { signal, .. } => signal.encode(),
                _ => None,
            })
            .unwrap()
    }
    #[test]
    fn synchronized_upgrade_correlates_session_and_transitions_after_handoff() {
        let (ap, bp) = peers();
        let mut a = Connector::new(ap.key, Options::default());
        let mut b = Connector::new(bp.key, Options::default());
        let now = Duration::ZERO;
        let actions = a.connected(bp.clone(), now);
        let at = prepared_ticket(&actions);
        let request = b.connected(ap.clone(), now);
        assert!(matches!(
            &request[0],
            Action::Send {
                signal: Signal::Request,
                ..
            }
        ));
        assert!(a.signalled(&bp, &signal(&request), now).is_empty());
        let offer = a.prepared(at, &bp, candidates(), now);
        let prepare = b.signalled(&ap, &signal(&offer), Duration::from_millis(20));
        let bt = prepared_ticket(&prepare);
        let answer = b.prepared(bt, &ap, candidates(), Duration::from_millis(20));
        let sync = a.signalled(&bp, &signal(&answer), Duration::from_millis(40));
        assert!(
            matches!(&sync[1],Action::Dial{initiator:true,at,..} if *at==Duration::from_millis(60))
        );
        let dial = b.signalled(&ap, &signal(&sync), Duration::from_millis(60));
        assert!(
            matches!(&dial[0],Action::Dial{initiator:false,at,..} if *at==Duration::from_millis(60))
        );
        a.dial_finished(at, &bp, true);
        b.dial_finished(bt, &ap, true);
        assert!(a.disconnected(bp.key).is_empty());
        let mut direct = bp.clone();
        direct.route = AuthenticatedRoute::Direct;
        direct.session_id = [3; 32];
        assert!(a
            .connected(direct, Duration::from_millis(70))
            .iter()
            .any(|a| matches!(a, Action::Finished { direct: true, .. })));
        assert!(a.next_deadline().is_none());
    }
    #[test]
    fn stale_results_attempt_limits_expiry_and_private_address_policy() {
        let (ap, bp) = peers();
        let mut a = Connector::new(
            ap.key,
            Options {
                auto_upgrade: false,
                ..Options::default()
            },
        );
        a.connected(bp.clone(), Duration::ZERO);
        let first = prepared_ticket(&a.upgrade(&bp, Duration::ZERO));
        assert!(a.upgrade(&bp, Duration::ZERO).is_empty());
        assert!(a
            .tick(Duration::from_secs(15))
            .iter()
            .any(|a| matches!(a, Action::Finished { direct: false, .. })));
        let second = prepared_ticket(&a.upgrade(&bp, Duration::from_secs(16)));
        assert_ne!(first, second);
        assert!(a
            .prepared(first, &bp, candidates(), Duration::from_secs(16))
            .is_empty());
        assert!(a.failed(first, &bp).is_empty());
        let offer = a.prepared(second, &bp, candidates(), Duration::from_secs(16));
        let id = match &offer[0] {
            Action::Send {
                signal: Signal::Offer(id, _),
                ..
            } => *id,
            _ => panic!(),
        };
        let private = Signal::Answer(
            id,
            vec![Candidate {
                transport: 1,
                host: "127.0.0.1".into(),
                port: 80,
            }],
        )
        .encode()
        .unwrap();
        let mut wrong = bp.clone();
        wrong.session_id = [8; 32];
        assert!(a
            .signalled(&wrong, &private, Duration::from_secs(16))
            .is_empty());
        assert!(a
            .signalled(&bp, &private, Duration::from_secs(16))
            .iter()
            .any(|a| matches!(a, Action::Finished { direct: false, .. })));
        let third = prepared_ticket(&a.upgrade(&bp, Duration::from_secs(17)));
        a.failed(third, &bp);
        assert!(matches!(
            a.upgrade(&bp, Duration::from_secs(18))[0],
            Action::Finished { direct: false, .. }
        ));
        a.close();
        assert!(a.connected(bp, Duration::from_secs(19)).is_empty());
    }
}
