//! Bounded authenticated provider-hint cache. Network admission/response correlation
//! happens before inserting hints; this component owns expiry and quota policy.
use crate::wire::accepts_cid;
use crate::{PeerEndpoint, PeerKey, Router};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderHint {
    pub peer: PeerKey,
    pub endpoint: Option<PeerEndpoint>,
    pub expires_at: u64,
    pub source: PeerKey,
}
#[derive(Clone, Debug)]
pub struct ProviderCacheConfig {
    pub providers_per_root: usize,
    pub routes_per_identity: usize,
    pub records_per_source: usize,
    pub total_records: usize,
    pub max_ttl_seconds: u64,
}
#[derive(Clone)]
pub struct ProviderCache {
    local: PeerKey,
    secret: String,
    config: ProviderCacheConfig,
    roots: BTreeMap<String, Vec<ProviderHint>>,
}
impl ProviderCache {
    pub fn new(signing_key: &ed25519_dalek::SigningKey, config: ProviderCacheConfig) -> Self {
        let local =
            PeerKey::from_bytes(signing_key.verifying_key().as_bytes()).expect("valid signing key");
        let key_hex: String = signing_key
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let secret = Router::hash(&format!("ivy.provider-shedding.v1:{key_hex}"))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            local,
            secret,
            config,
            roots: BTreeMap::new(),
        }
    }
    pub fn expiry_is_valid(&self, expires_at: u64, now: u64) -> bool {
        expires_at > now && expires_at <= now.saturating_add(self.config.max_ttl_seconds)
    }
    pub fn evict_expired(&mut self, root: &str, now: u64) {
        if let Some(hints) = self.roots.get_mut(root) {
            hints.retain(|h| h.expires_at > now);
            if hints.is_empty() {
                self.roots.remove(root);
            }
        }
    }
    pub fn hints(&mut self, root: &str, now: u64) -> &[ProviderHint] {
        self.evict_expired(root, now);
        self.roots.get(root).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn source_count(&self, source: PeerKey) -> usize {
        self.roots
            .values()
            .flatten()
            .filter(|h| h.source == source && h.source != self.local)
            .count()
    }
    pub fn total_count(&self) -> usize {
        self.roots
            .values()
            .flatten()
            .filter(|h| h.source != self.local)
            .count()
    }
    pub(crate) fn bounded(&self, input: Vec<ProviderHint>, root: &str) -> Vec<ProviderHint> {
        let mut order = Vec::new();
        let mut routes: BTreeMap<PeerKey, Vec<ProviderHint>> = BTreeMap::new();
        for h in input {
            order.retain(|p| *p != h.peer);
            order.push(h.peer);
            let list = routes.entry(h.peer).or_default();
            list.retain(|e| e.endpoint != h.endpoint);
            list.push(h);
            let excess = list.len().saturating_sub(self.config.routes_per_identity);
            list.drain(..excess);
        }
        if order.len() > self.config.providers_per_root {
            let mut ranked = order.clone();
            ranked.sort_by_key(|peer| {
                let list = &routes[peer];
                let tier = if list
                    .iter()
                    .any(|h| h.source == *peer && h.endpoint.is_some())
                {
                    0
                } else if list.iter().any(|h| h.source == *peer) {
                    1
                } else {
                    2
                };
                (
                    tier,
                    Router::hash(&format!("{}:{}:{}", self.secret, root, peer.hex())),
                )
            });
            let keep: BTreeSet<_> = ranked
                .into_iter()
                .take(self.config.providers_per_root)
                .collect();
            order.retain(|p| keep.contains(p));
        }
        order
            .into_iter()
            .flat_map(|p| routes.remove(&p).unwrap_or_default())
            .collect()
    }
    fn set(&mut self, root: &str, hints: Vec<ProviderHint>) {
        if hints.is_empty() {
            self.roots.remove(root);
        } else {
            self.roots.insert(root.into(), hints);
        }
    }
    fn evict_source_record(&mut self, source: PeerKey, incoming: &ProviderHint, now: u64) -> bool {
        let candidate = self
            .roots
            .iter()
            .flat_map(|(root, hints)| {
                hints
                    .iter()
                    .enumerate()
                    .filter(move |(_, h)| h.source == source)
                    .map(move |(index, h)| {
                        let tier = if h.expires_at <= now {
                            0
                        } else if h.source != h.peer {
                            1
                        } else {
                            2
                        };
                        ((tier, h.expires_at, root.clone()), index)
                    })
            })
            .min();
        let Some(((tier, _, root), index)) = candidate else {
            return false;
        };
        if tier == 2 && incoming.source != incoming.peer {
            return false;
        }
        let mut hints = self.roots.remove(&root).unwrap();
        hints.remove(index);
        self.set(&root, hints);
        true
    }
    /// Inserts a previously authenticated/admitted hint. A provider's own record
    /// takes precedence over referrals. Returns whether this exact hint survived.
    pub fn store(&mut self, root: &str, hint: ProviderHint, now: u64) -> bool {
        if !accepts_cid(root) || !self.expiry_is_valid(hint.expires_at, now) {
            return false;
        }
        self.evict_expired(root, now);
        let mut existing = self.roots.get(root).cloned().unwrap_or_default();
        if hint.source != hint.peer
            && existing
                .iter()
                .any(|h| h.peer == hint.peer && h.source == h.peer)
        {
            return false;
        }
        if hint.source == hint.peer {
            existing.retain(|h| h.peer != hint.peer || h.source == h.peer);
            self.set(root, existing.clone());
        }
        let mut proposed = existing.clone();
        proposed.push(hint.clone());
        let adds = self
            .bounded(proposed, root)
            .iter()
            .filter(|h| h.source == hint.source)
            .count()
            > existing.iter().filter(|h| h.source == hint.source).count();
        if hint.source != self.local && adds {
            if self.source_count(hint.source) >= self.config.records_per_source {
                if !self.evict_source_record(hint.source, &hint, now) {
                    return false;
                }
            } else if self.total_count() >= self.config.total_records {
                let sources: BTreeSet<_> = self
                    .roots
                    .values()
                    .flatten()
                    .filter(|h| h.source != self.local)
                    .map(|h| h.source)
                    .collect();
                let heaviest = sources
                    .into_iter()
                    .min_by_key(|source| (std::cmp::Reverse(self.source_count(*source)), *source));
                if !heaviest.is_some_and(|s| self.evict_source_record(s, &hint, now)) {
                    return false;
                }
            }
        }
        let mut hints = self.roots.get(root).cloned().unwrap_or_default();
        hints.push(hint.clone());
        let hints = self.bounded(hints, root);
        let retained = hints.contains(&hint);
        self.set(root, hints);
        retained
    }
    pub fn forget(&mut self, root: &str, peer: PeerKey) {
        let mut hints = self.roots.get(root).cloned().unwrap_or_default();
        hints.retain(|h| h.peer != peer);
        self.set(root, hints);
    }
    pub fn stop_providing(&mut self, root: &str) {
        let mut hints = self.roots.get(root).cloned().unwrap_or_default();
        hints.retain(|h| h.source != self.local);
        self.set(root, hints);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> PeerKey {
        PeerKey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[n; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap()
    }
    fn hint(peer: u8, source: u8, expires: u64) -> ProviderHint {
        ProviderHint {
            peer: key(peer),
            source: key(source),
            expires_at: expires,
            endpoint: Some(PeerEndpoint {
                public_key: key(peer).hex(),
                host: "8.8.8.8".into(),
                port: 42,
            }),
        }
    }
    fn cache() -> ProviderCache {
        ProviderCache::new(
            &ed25519_dalek::SigningKey::from_bytes(&[0; 32]),
            ProviderCacheConfig {
                providers_per_root: 2,
                routes_per_identity: 2,
                records_per_source: 2,
                total_records: 3,
                max_ttl_seconds: 100,
            },
        )
    }
    #[test]
    fn announcements_outrank_referrals_and_quotas_do_not_evict_them_for_referrals() {
        let mut c = cache();
        assert!(c.store("root", hint(1, 2, 50), 0));
        assert!(c.store("root", hint(1, 1, 60), 0));
        assert!(!c.store("root", hint(1, 2, 70), 0));
        assert_eq!(c.source_count(key(2)), 0);
        assert!(c.store("a", hint(2, 2, 50), 0));
        assert!(c.store("b", hint(2, 2, 60), 0));
        assert!(!c.store("c", hint(3, 2, 70), 0));
        assert_eq!(c.total_count(), 3);
        assert!(c.store("c", hint(2, 2, 70), 0));
        assert!(c.hints("a", 0).is_empty());
        assert_eq!(c.source_count(key(2)), 2);
    }
    #[test]
    fn expiry_local_exemption_and_secret_shedding() {
        let mut c = cache();
        assert!(!c.store("x", hint(1, 1, 101), 0));
        assert!(c.store("x", hint(0, 0, 100), 0));
        assert_eq!(c.total_count(), 0);
        c.stop_providing("x");
        assert!(c.hints("x", 0).is_empty());
        for n in 1..=20 {
            c.store("root", hint(n, n, 100), 0);
        }
        assert_eq!(c.hints("root", 0).len(), 2);
        assert_eq!(c.total_count(), 2);
        assert!(c.hints("root", 100).is_empty());
        assert_eq!(c.total_count(), 0);
        assert!(c.expiry_is_valid(u64::MAX, u64::MAX - 1));
    }
}
