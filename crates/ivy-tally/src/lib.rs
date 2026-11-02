//! Actual Tally ledger adapter for Ivy. Clone `Tally` before passing this adapter
//! into the core to retain application access to the same standing/evidence.
use ivy_core::{PeerKey, PeerLedger};
use lattice_tally::{PeerId, Tally};
#[derive(Clone)]
pub struct TallyLedger(pub Tally);
fn peer(key: PeerKey) -> PeerId {
    PeerId::new(key.hex())
}
fn bytes(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}
impl PeerLedger for TallyLedger {
    fn record_sent(&mut self, key: PeerKey, n: usize) {
        self.0.record_sent(&peer(key), bytes(n));
    }
    fn record_received(&mut self, key: PeerKey, n: usize) {
        self.0.record_received(&peer(key), bytes(n));
    }
    fn record_protocol_violation(&mut self, key: PeerKey) {
        self.0.record_protocol_violation(&peer(key));
    }
    fn serving_priority(&self, key: PeerKey) -> f64 {
        self.0.serving_priority(&peer(key))
    }
    fn record_served(&mut self, key: PeerKey, n: usize) {
        self.0.debit_standing(&peer(key), bytes(n));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn received_transport_bytes_do_not_earn_content_credit_and_served_bytes_debit_it() {
        let key = PeerKey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let tally = Tally::default();
        let mut ledger = TallyLedger(tally.clone());
        tally.credit_standing(&peer(key), 1000);
        ledger.record_received(key, 9999);
        assert_eq!(ledger.serving_priority(key), 1000.);
        ledger.record_served(key, 400);
        assert_eq!(tally.standing(&peer(key)), 600);
    }
}
