//! RFC 8489 binding codec and bounded reply policy, matching Ivy's STUN usage.
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAddress {
    pub host: String,
    pub port: u16,
}
pub fn binding_request(transaction: [u8; 12]) -> Vec<u8> {
    let mut bytes = vec![0, 1, 0, 0];
    bytes.extend_from_slice(&COOKIE);
    bytes.extend_from_slice(&transaction);
    bytes
}
pub fn binding_reply(request: &[u8], address: IpAddr, port: u16) -> Option<Vec<u8>> {
    if request.len() < 20
        || request.len() > 512
        || request[..2] != [0, 1]
        || request[4..8] != COOKIE
    {
        return None;
    }
    let length = u16::from_be_bytes(request[2..4].try_into().ok()?) as usize;
    if !length.is_multiple_of(4) || request.len() != 20 + length {
        return None;
    }
    let address: Vec<_> = match address {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| ip.octets().to_vec())
            .unwrap_or_else(|| ip.octets().to_vec()),
    };
    let mut reply = vec![1, 1, 0, (8 + address.len()) as u8];
    reply.extend_from_slice(&request[4..20]);
    reply.extend_from_slice(&[
        0,
        0x20,
        0,
        (4 + address.len()) as u8,
        0,
        if address.len() == 4 { 1 } else { 2 },
    ]);
    reply.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
    reply.extend(address.iter().zip(&request[4..20]).map(|(a, b)| a ^ b));
    Some(reply)
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb88320 } else { 0 };
        }
    }
    !crc
}
pub fn parse_binding_reply(bytes: &[u8], transaction: [u8; 12]) -> Option<ObservedAddress> {
    if bytes.len() < 20
        || bytes[..2] != [1, 1]
        || bytes[4..8] != COOKIE
        || bytes[8..20] != transaction
    {
        return None;
    }
    let length = u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize;
    if !length.is_multiple_of(4) || bytes.len() != 20 + length {
        return None;
    }
    let mut cursor = 20;
    let mut mapped = None;
    while cursor < bytes.len() {
        let start = cursor;
        let header = bytes.get(cursor..cursor + 4)?;
        cursor += 4;
        let kind = u16::from_be_bytes(header[..2].try_into().ok()?);
        let length = u16::from_be_bytes(header[2..].try_into().ok()?) as usize;
        let padded = (length + 3) & !3;
        let attr = bytes.get(cursor..cursor + padded)?;
        cursor += padded;
        match kind {
            0x20 => {
                if !matches!(length, 8 | 20) || attr[0] != 0 {
                    return None;
                }
                let port = u16::from_be_bytes(attr[2..4].try_into().ok()?) ^ 0x2112;
                let address: Vec<_> = attr[4..length]
                    .iter()
                    .zip(&bytes[4..20])
                    .map(|(a, b)| a ^ b)
                    .collect();
                let host = match (attr[1], length) {
                    (1, 8) => Ipv4Addr::from(<[u8; 4]>::try_from(address).ok()?).to_string(),
                    (2, 20) => Ipv6Addr::from(<[u8; 16]>::try_from(address).ok()?)
                        .segments()
                        .iter()
                        .map(|n| format!("{n:x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                    _ => return None,
                };
                mapped = Some(ObservedAddress { host, port });
            }
            0x8028 => {
                if length != 4
                    || cursor != bytes.len()
                    || u32::from_be_bytes(attr[..4].try_into().ok()?)
                        != (crc32(&bytes[..start]) ^ 0x5354554e)
                {
                    return None;
                }
            }
            0x1 | 0x8 | 0x1c => {}
            kind if kind >= 0x8000 => {}
            _ => return None,
        }
    }
    mapped
}
#[derive(Default)]
pub struct ReplyLimit {
    start: Option<Duration>,
    counts: BTreeMap<Vec<u8>, usize>,
}
impl ReplyLimit {
    pub fn allows(&mut self, address: IpAddr, now: Duration) -> bool {
        if self
            .start
            .is_none_or(|start| now.saturating_sub(start) >= Duration::from_secs(1))
        {
            self.start = Some(now);
            self.counts.clear();
        }
        let key = match address {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(|ip| ip.octets().to_vec())
                .unwrap_or_else(|| ip.octets()[..8].to_vec()),
        };
        let sent = self.counts.get(&key).copied().unwrap_or(0);
        if sent >= 20 || sent == 0 && self.counts.len() >= 4096 {
            return false;
        }
        self.counts.insert(key, sent + 1);
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binding_roundtrip_rejects_malformed_or_unrelated_datagrams() {
        let transaction = [7; 12];
        let request = binding_request(transaction);
        for ip in ["8.8.4.4", "2001:4860:4860::8888", "::ffff:8.8.4.4"] {
            let reply = binding_reply(&request, ip.parse().unwrap(), 4500).unwrap();
            let decoded = parse_binding_reply(&reply, transaction).unwrap();
            assert_eq!(decoded.port, 4500);
            assert_eq!(
                decoded.host.parse::<IpAddr>().unwrap(),
                if ip.starts_with("::ffff:") {
                    "8.8.4.4".parse::<IpAddr>().unwrap()
                } else {
                    ip.parse::<IpAddr>().unwrap()
                }
            );
            for len in 0..reply.len() {
                assert!(parse_binding_reply(&reply[..len], transaction).is_none());
            }
            assert!(parse_binding_reply(&reply, [8; 12]).is_none());
            let mut extra = reply.clone();
            extra.push(0);
            assert!(parse_binding_reply(&extra, transaction).is_none());
        }
        assert!(binding_reply(&vec![0; 513], "8.8.8.8".parse().unwrap(), 1).is_none());
    }
    #[test]
    fn fingerprint_and_unknown_required_attributes_are_checked() {
        let tx = [3; 12];
        let mut reply =
            binding_reply(&binding_request(tx), "8.8.8.8".parse().unwrap(), 80).unwrap();
        reply[3] += 8;
        let crc = crc32(&reply) ^ 0x5354554e;
        reply.extend_from_slice(&[0x80, 0x28, 0, 4]);
        reply.extend_from_slice(&crc.to_be_bytes());
        assert!(parse_binding_reply(&reply, tx).is_some());
        *reply.last_mut().unwrap() ^= 1;
        assert!(parse_binding_reply(&reply, tx).is_none());
        let mut required =
            binding_reply(&binding_request(tx), "8.8.8.8".parse().unwrap(), 80).unwrap();
        required[3] += 4;
        required.extend_from_slice(&[0, 0x17, 0, 0]);
        assert!(parse_binding_reply(&required, tx).is_none());
    }
    #[test]
    fn reply_limiter_groups_ipv6_64_and_resets_each_second() {
        let mut limiter = ReplyLimit::default();
        for _ in 0..20 {
            assert!(limiter.allows("2001:4860::1".parse().unwrap(), Duration::ZERO));
        }
        assert!(!limiter.allows("2001:4860::2".parse().unwrap(), Duration::ZERO));
        assert!(limiter.allows("2001:4860::2".parse().unwrap(), Duration::from_secs(1)));
    }
}
