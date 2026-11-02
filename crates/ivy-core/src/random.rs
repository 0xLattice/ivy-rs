//! Injected entropy. `SimulationRandom` exactly matches Swift CoreRandom's
//! SplitMix64 stream and bytes32/below/shuffle conventions. Never use it for a
//! live identity or session: its predictable output is for simulation only.
use rand_core::CryptoRngCore;
pub trait CoreEntropy {
    fn next(&mut self) -> u64;
    fn bytes32(&mut self) -> [u8; 32];
    fn below(&mut self, bound: u64) -> Option<u64> {
        if bound == 0 {
            return None;
        }
        let limit = u64::MAX - u64::MAX % bound;
        loop {
            let value = self.next();
            if value < limit {
                return Some(value % bound);
            }
        }
    }
    fn shuffle<T>(&mut self, values: &mut [T])
    where
        Self: Sized,
    {
        for i in (1..values.len()).rev() {
            let j = self.below(i as u64 + 1).unwrap() as usize;
            values.swap(i, j);
        }
    }
}
impl<R: CryptoRngCore> CoreEntropy for R {
    fn next(&mut self) -> u64 {
        self.next_u64()
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut bytes = [0; 32];
        self.fill_bytes(&mut bytes);
        bytes
    }
}
#[derive(Clone, Debug)]
pub struct SimulationRandom {
    state: u64,
}
impl SimulationRandom {
    pub fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }
}
impl CoreEntropy for SimulationRandom {
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }
    fn bytes32(&mut self) -> [u8; 32] {
        std::array::from_fn(|_| self.next() as u8)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn splitmix_vectors_and_byte_convention() {
        let mut r = SimulationRandom::seeded(0);
        assert_eq!(r.next(), 0xe220a8397b1dcdaf);
        assert_eq!(r.next(), 0x6e789e6aa1b965f4);
        let mut r = SimulationRandom::seeded(0);
        let b = r.bytes32();
        assert_eq!(&b[..2], &[0xaf, 0xf4]);
        assert_eq!(r.below(0), None);
    }
}
