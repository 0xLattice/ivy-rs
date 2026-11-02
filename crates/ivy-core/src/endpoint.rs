//! Discovery address filtering and network diversity groups from Ivy 3.1.1.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn ipv4(s: &str) -> Option<Ipv4Addr> {
    let fields: Vec<_> = s.split('.').collect();
    if fields.len() != 4 {
        return None;
    }
    let mut octets = [0; 4];
    for (n, s) in fields.iter().enumerate() {
        if s.is_empty() || s.len() > 3 {
            return None;
        }
        octets[n] = s.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}
fn host_literal(s: &str) -> &str {
    let s = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{200b}');
    let s = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s);
    s.split('%').next().unwrap_or(s)
}
fn embedded_v4(s: &str) -> Option<Ipv4Addr> {
    let s = host_literal(s);
    if s.starts_with("::") {
        if let Some(tail) = s.rsplit(':').next() {
            if tail.contains('.') {
                return ipv4(tail);
            }
        }
    }
    s.parse::<Ipv6Addr>().ok()?.to_ipv4_mapped()
}
fn parse(s: &str) -> Option<IpAddr> {
    let s = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{200b}');
    if let Some(ip) = ipv4(s) {
        return Some(IpAddr::V4(ip));
    }
    if !s.contains(':') {
        return None;
    }
    if let Some(ip) = embedded_v4(s) {
        return Some(IpAddr::V4(ip));
    }
    host_literal(s).parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}
pub fn net_group(host: &str) -> String {
    match parse(host) {
        Some(IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("v4:{}.{}", o[0], o[1])
        }
        Some(IpAddr::V6(ip)) => {
            let h = ip.segments();
            format!("v6:{:04x}.{:04x}", h[0], h[1])
        }
        None => format!(
            "raw:{}",
            host.trim_matches(|c: char| c.is_whitespace() || c == '\u{200b}')
        ),
    }
}
fn non_routable_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    match a {
        0 | 10 | 127 | 224..=255 => true,
        100 => (64..=127).contains(&b),
        169 => b == 254,
        172 => (16..=31).contains(&b),
        192 => {
            b == 168
                || b == 0 && c == 0 && d != 9 && d != 10
                || b == 0 && c == 2
                || b == 88 && c == 99
        }
        198 => b == 18 || b == 19 || b == 51 && c == 100,
        203 => b == 0 && c == 113,
        _ => false,
    }
}
fn non_routable_v6(ip: Ipv6Addr) -> bool {
    let h = ip.segments();
    if h[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return non_routable_v4(Ipv4Addr::new(
            (h[6] >> 8) as u8,
            h[6] as u8,
            (h[7] >> 8) as u8,
            h[7] as u8,
        ));
    }
    if !(0x2000..=0x3fff).contains(&h[0]) {
        return true;
    }
    if h[0] == 0x2001 && h[1] <= 0x1ff {
        let anycast = h[1] == 1 && h[2..7].iter().all(|n| *n == 0) && (1..=3).contains(&h[7]);
        if !(anycast || h[1] == 3 || h[1] == 4 && h[2] == 0x112 || (0x30..=0x3f).contains(&h[1])) {
            return true;
        }
    }
    h[0] == 0x2001 && h[1] == 0xdb8 || h[0] == 0x2002 || h[0] == 0x3fff && h[1] <= 0xfff
}
pub fn is_globally_routable(host: &str) -> bool {
    match parse(host) {
        Some(IpAddr::V4(ip)) => !non_routable_v4(ip),
        Some(IpAddr::V6(ip)) => !non_routable_v6(ip),
        None => false,
    }
}
/// Private/loopback addresses are accepted only when advertised by the session
/// whose observed IP is exactly that address. Referrals must be global literals.
pub fn allows_discovered_host(
    host: &str,
    self_advertisement: bool,
    observed_host: Option<&str>,
) -> bool {
    if is_globally_routable(host) {
        return true;
    }
    if !self_advertisement {
        return false;
    }
    let Some(ip) = parse(host) else {
        return false;
    };
    let private = match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback(),
        IpAddr::V6(v) => (0xfc00..=0xfdff).contains(&v.segments()[0]) || v.is_loopback(),
    };
    private && observed_host.and_then(parse) == Some(ip)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn special_use_ranges_and_adjacent_public_addresses() {
        for host in [
            "10.1.2.3",
            "192.0.2.1",
            "198.51.100.2",
            "203.0.113.9",
            "100.64.0.1",
            "192.0.0.8",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "64:ff9b::a00:1",
            "localhost",
        ] {
            assert!(!is_globally_routable(host), "{host}");
        }
        for host in [
            "8.8.8.8",
            "192.0.3.1",
            "192.0.0.9",
            "198.51.101.1",
            "100.128.0.1",
            "2001:4860::8888",
            "2001:1::1",
            "2001:3::1",
            "64:ff9b::808:808",
        ] {
            assert!(is_globally_routable(host), "{host}");
        }
    }
    #[test]
    fn mapped_addresses_share_groups_and_private_admission_uses_observed_ip() {
        assert_eq!(net_group("[::ffff:192.168.1.2]"), "v4:192.168");
        assert_eq!(net_group("::ffff:c0a8:102"), "v4:192.168");
        assert_eq!(net_group("2001:db8:1234::1"), "v6:2001.0db8");
        assert!(allows_discovered_host(
            "192.168.1.2",
            true,
            Some("::ffff:192.168.1.2")
        ));
        assert!(!allows_discovered_host(
            "192.168.1.2",
            false,
            Some("192.168.1.2")
        ));
        assert!(!allows_discovered_host(
            "192.168.1.3",
            true,
            Some("192.168.1.2")
        ));
        assert!(!allows_discovered_host(
            "169.254.1.2",
            true,
            Some("169.254.1.2")
        ));
    }
}
