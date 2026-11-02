//! Deterministic XOR-distance routing table, matching Ivy 3.1.1 Router.swift.
use crate::{PeerEndpoint, PeerKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketEntry {
    pub key: PeerKey,
    pub hash: [u8; 32],
    pub endpoint: PeerEndpoint,
}
#[derive(Clone, Debug)]
pub struct Router {
    pub local_hash: [u8; 32],
    k: usize,
    buckets: Vec<Vec<BucketEntry>>,
}
impl Router {
    pub fn new(local: PeerKey, k: usize) -> Self {
        Self {
            local_hash: Self::hash(&local.hex()),
            k,
            buckets: vec![Vec::new(); 256],
        }
    }
    pub fn hash(key: &str) -> [u8; 32] {
        Sha256::digest(key.as_bytes()).into()
    }
    pub fn common_prefix_length(a: &[u8; 32], b: &[u8; 32]) -> usize {
        let mut n = 0;
        for (&a, &b) in a.iter().zip(b) {
            let diff = a ^ b;
            n += diff.leading_zeros() as usize;
            if diff != 0 {
                break;
            }
        }
        n
    }
    pub fn add_peer(&mut self, key: PeerKey, endpoint: PeerEndpoint) {
        let hash = Self::hash(&key.hex());
        let index = Self::common_prefix_length(&self.local_hash, &hash).min(255);
        let bucket = &mut self.buckets[index];
        if let Some(entry) = bucket.iter_mut().find(|e| e.key == key) {
            entry.endpoint = endpoint;
        } else if bucket.len() < self.k {
            bucket.push(BucketEntry {
                key,
                hash,
                endpoint,
            });
        }
    }
    pub fn remove_peer(&mut self, key: PeerKey) {
        let index = Self::common_prefix_length(&self.local_hash, &Self::hash(&key.hex())).min(255);
        self.buckets[index].retain(|e| e.key != key);
    }
    pub fn all_peers(&self) -> impl Iterator<Item = &BucketEntry> {
        self.buckets.iter().flatten()
    }
    pub fn closest_peers(&self, target: &[u8; 32], count: usize) -> Vec<&BucketEntry> {
        let mut peers: Vec<_> = self.all_peers().collect();
        peers.sort_by_key(|e| {
            let mut distance = e.hash;
            for (a, b) in distance.iter_mut().zip(target) {
                *a ^= b;
            }
            distance
        });
        peers.truncate(count);
        peers
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
    fn endpoint(n: u8) -> PeerEndpoint {
        PeerEndpoint {
            public_key: key(n).hex(),
            host: "8.8.8.8".into(),
            port: n as u16,
        }
    }
    #[test]
    fn routing_order_update_remove_and_bucket_capacity() {
        let mut router = Router::new(key(0), 2);
        for n in 1..=100 {
            router.add_peer(key(n), endpoint(n));
        }
        assert!(router.buckets.iter().all(|b| b.len() <= 2));
        let target = router.all_peers().next().unwrap().key;
        let near = router.closest_peers(&Router::hash(&target.hex()), 5);
        assert_eq!(near[0].key, target);
        let mut changed = near[0].endpoint.clone();
        changed.port = 1234;
        router.add_peer(target, changed.clone());
        assert_eq!(
            router.closest_peers(&Router::hash(&target.hex()), 1)[0].endpoint,
            changed
        );
        router.remove_peer(target);
        assert!(!router.all_peers().any(|e| e.key == target));
        assert_eq!(Router::common_prefix_length(&[0; 32], &[0; 32]), 256);
    }
}
