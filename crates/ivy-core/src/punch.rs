//! Bounded signalling used on the authenticated `ivy.punch/1` topic.
pub const TOPIC: &str = "ivy.punch/1";
pub const MAX_SIGNAL_BYTES: usize = 1024;
pub const MAX_CANDIDATES: usize = 8;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub transport: u8,
    pub host: String,
    pub port: u16,
}
impl Candidate {
    pub const TCP: u8 = 1;
    pub const QUIC: u8 = 2;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    Request,
    Offer(u32, Vec<Candidate>),
    Answer(u32, Vec<Candidate>),
    Sync(u32),
    Abandon(u32),
}
impl Signal {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (kind, id, candidates) = match self {
            Self::Request => (0, 0, None),
            Self::Offer(id, c) => (1, *id, Some(c)),
            Self::Answer(id, c) => (2, *id, Some(c)),
            Self::Sync(id) => (3, *id, None),
            Self::Abandon(id) => (4, *id, None),
        };
        if kind != 0 && id == 0 {
            return None;
        }
        let mut out = vec![kind];
        out.extend(id.to_be_bytes());
        if let Some(candidates) = candidates {
            if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
                return None;
            }
            out.push(candidates.len() as u8);
            for candidate in candidates {
                if candidate.host.is_empty() || candidate.host.len() > 64 {
                    return None;
                }
                out.push(candidate.transport);
                out.extend(candidate.port.to_be_bytes());
                out.push(candidate.host.len() as u8);
                out.extend(candidate.host.as_bytes());
            }
        }
        (out.len() <= MAX_SIGNAL_BYTES).then_some(out)
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if !(5..=MAX_SIGNAL_BYTES).contains(&bytes.len()) {
            return None;
        }
        let kind = bytes[0];
        let id = u32::from_be_bytes(bytes[1..5].try_into().ok()?);
        let body = &bytes[5..];
        match kind {
            0 if id == 0 && body.is_empty() => Some(Self::Request),
            3 if id != 0 && body.is_empty() => Some(Self::Sync(id)),
            4 if id != 0 && body.is_empty() => Some(Self::Abandon(id)),
            1 | 2 if id != 0 => {
                let count = *body.first()? as usize;
                if !(1..=MAX_CANDIDATES).contains(&count) {
                    return None;
                }
                let mut cursor = 1;
                let mut candidates = Vec::with_capacity(count);
                for _ in 0..count {
                    let header = body.get(cursor..cursor + 4)?;
                    cursor += 4;
                    let len = header[3] as usize;
                    if !(1..=64).contains(&len) {
                        return None;
                    }
                    let host = std::str::from_utf8(body.get(cursor..cursor + len)?)
                        .ok()?
                        .to_owned();
                    cursor += len;
                    candidates.push(Candidate {
                        transport: header[0],
                        port: u16::from_be_bytes([header[1], header[2]]),
                        host,
                    });
                }
                if cursor != body.len() {
                    return None;
                }
                Some(if kind == 1 {
                    Self::Offer(id, candidates)
                } else {
                    Self::Answer(id, candidates)
                })
            }
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signal_layout_bounds_and_malformed_payloads() {
        let offer = Signal::Offer(
            0x01020304,
            vec![Candidate {
                transport: 1,
                port: 1234,
                host: "8.8.8.8".into(),
            }],
        );
        let bytes = offer.encode().unwrap();
        assert_eq!(
            bytes,
            vec![1, 1, 2, 3, 4, 1, 1, 4, 210, 7, b'8', b'.', b'8', b'.', b'8', b'.', b'8']
        );
        for signal in [
            offer,
            Signal::Request,
            Signal::Sync(1),
            Signal::Abandon(2),
            Signal::Answer(
                3,
                vec![Candidate {
                    transport: 2,
                    port: 0,
                    host: "::1".into(),
                }],
            ),
        ] {
            let bytes = signal.encode().unwrap();
            assert_eq!(Signal::decode(&bytes), Some(signal));
            for end in 0..bytes.len() {
                assert_eq!(Signal::decode(&bytes[..end]), None);
            }
            let mut extra = bytes;
            extra.push(0);
            assert_eq!(Signal::decode(&extra), None);
        }
        assert!(Signal::Sync(0).encode().is_none());
        assert!(Signal::Offer(1, vec![]).encode().is_none());
    }
}
