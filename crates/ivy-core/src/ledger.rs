//! Peer-global evidence boundary. Content merit is assigned by the application;
//! transport receipt alone never credits useful-content standing.
use crate::PeerKey;
pub trait PeerLedger: Send {
    fn record_sent(&mut self, peer: PeerKey, bytes: usize);
    fn record_received(&mut self, peer: PeerKey, bytes: usize);
    fn record_protocol_violation(&mut self, peer: PeerKey);
    fn serving_priority(&self, peer: PeerKey) -> f64;
    fn record_served(&mut self, _peer: PeerKey, _bytes: usize) {}
}
#[derive(Default)]
pub struct NullLedger;
impl PeerLedger for NullLedger {
    fn record_sent(&mut self, _peer: PeerKey, _bytes: usize) {}
    fn record_received(&mut self, _peer: PeerKey, _bytes: usize) {}
    fn record_protocol_violation(&mut self, _peer: PeerKey) {}
    fn serving_priority(&self, _peer: PeerKey) -> f64 {
        0.
    }
}
