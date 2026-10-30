//! Byte encodings Ivy's records and messages share: big-endian integers and
//! length-prefixed fields. Every decoder here is canonical: input that would
//! not re-encode to the same bytes is rejected, as Swift Ivy rejects it.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Longest string a message or session record may carry, in bytes.
pub const MAX_STRING_LENGTH: usize = 8192;
/// Largest frame a node accepts unless it advertises otherwise.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub(crate) fn is_at_end(&self) -> bool {
        self.offset == self.data.len()
    }

    pub(crate) fn bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let bytes = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(bytes)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N)?.try_into().ok()
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }

    /// Bytes behind a UInt32 length of at most `max`.
    pub(crate) fn data(&mut self, max: usize) -> Option<&'a [u8]> {
        let count = self.u32()? as usize;
        if count > max {
            return None;
        }
        self.bytes(count)
    }

    pub(crate) fn key(&mut self) -> Option<PeerKey> {
        PeerKey::from_bytes(self.bytes(32)?)
    }
}

pub(crate) fn put_data(bytes: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    bytes.extend_from_slice(&u32::try_from(value.len()).ok()?.to_be_bytes());
    bytes.extend_from_slice(value);
    Some(())
}

/// The string `bytes` spell, if they are UTF-8. Swift's decoder drops a
/// leading byte-order mark, so such a string would not re-encode to the
/// bytes that carried it: Swift Ivy rejects it, and so does this.
pub(crate) fn text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    (!text.starts_with('\u{feff}')).then_some(text)
}

/// Ivy's identity: an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()?;
        Some(Self(bytes))
    }

    /// Raw hex, or the `ed01`-prefixed Multikey hex form.
    pub fn from_hex(text: &str) -> Option<Self> {
        let raw = match text.get(..4) {
            Some(prefix) if text.len() == 68 && prefix.eq_ignore_ascii_case("ed01") => &text[4..],
            _ => text,
        };
        if raw.len() != 64 || !raw.is_ascii() {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..32)
            .map(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).ok())
            .collect();
        Self::from_bytes(&bytes?)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The key's proof of work: trailing zero bits of SHA-256 over its hex,
    /// counted from the hash's last byte. A node may refuse peers below its
    /// `min_peer_key_bits`.
    pub fn work_bits(&self) -> u32 {
        let hash = Sha256::digest(self.hex().as_bytes());
        let mut count = 0;
        for byte in hash.iter().rev() {
            count += byte.trailing_zeros();
            if *byte != 0 {
                break;
            }
        }
        count
    }

    pub(crate) fn verifies(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(&self.0)
            .map(|key| {
                key.verify_strict(message, &Signature::from_bytes(signature))
                    .is_ok()
            })
            .unwrap_or(false)
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({})", self.hex())
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// An address a peer says it listens on.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenAddress {
    pub host: String,
    pub port: u16,
}

/// What a peer tells the other during the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerMetadata {
    /// Sorted, without duplicates.
    pub listen_addresses: Vec<ListenAddress>,
    /// The largest frame this peer accepts; the other side sends no larger.
    pub max_frame_size: u32,
}

impl PeerMetadata {
    pub const MAX_ENCODED_SIZE: usize = 64 * 1024;
    const MAX_LISTEN_ADDRESSES: usize = 16;

    pub fn new(mut listen_addresses: Vec<ListenAddress>, max_frame_size: u32) -> Self {
        // Hosts order by bytes. Swift orders Strings by canonical
        // equivalence, which agrees for the ASCII hosts Ivy advertises.
        listen_addresses.sort();
        listen_addresses.dedup();
        Self {
            listen_addresses,
            max_frame_size,
        }
    }

    pub(crate) fn encode(&self) -> Option<Vec<u8>> {
        if self.listen_addresses.len() > Self::MAX_LISTEN_ADDRESSES {
            return None;
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.listen_addresses.len() as u16).to_be_bytes());
        for address in &self.listen_addresses {
            if address.host.len() > MAX_STRING_LENGTH {
                return None;
            }
            put_data(&mut bytes, address.host.as_bytes())?;
            bytes.extend_from_slice(&address.port.to_be_bytes());
        }
        // Present only when not the default, so a default peer's metadata
        // matches what a peer that predates the field sends.
        if self.max_frame_size != DEFAULT_MAX_FRAME_SIZE {
            bytes.extend_from_slice(&self.max_frame_size.to_be_bytes());
        }
        (bytes.len() <= Self::MAX_ENCODED_SIZE).then_some(bytes)
    }

    pub(crate) fn decode(data: &[u8]) -> Option<Self> {
        if data.len() > Self::MAX_ENCODED_SIZE {
            return None;
        }
        let mut reader = Reader::new(data);
        let count = reader.u16()? as usize;
        if count > Self::MAX_LISTEN_ADDRESSES {
            return None;
        }
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            let host = text(reader.data(MAX_STRING_LENGTH)?)?.to_owned();
            let port = reader.u16()?;
            addresses.push(ListenAddress { host, port });
        }
        let max_frame_size = if reader.is_at_end() {
            DEFAULT_MAX_FRAME_SIZE
        } else {
            reader.u32()?
        };
        if !reader.is_at_end() {
            return None;
        }
        let metadata = Self::new(addresses, max_frame_size);
        (metadata.encode()? == data).then_some(metadata)
    }
}

impl Default for PeerMetadata {
    fn default() -> Self {
        Self::new(Vec::new(), DEFAULT_MAX_FRAME_SIZE)
    }
}

/// The messages this port speaks. Ivy's discovery, content and relay
/// messages are not implemented yet; a peer that sends one is ignored, as
/// Swift Ivy ignores a message a later version added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping(u64),
    Pong(u64),
    /// An application message: Ivy carries it and does not read it.
    PeerMessage {
        topic: String,
        payload: Vec<u8>,
    },
}

const TAG_PING: u8 = 0;
const TAG_PONG: u8 = 1;
const TAG_PEER_MESSAGE: u8 = 49;

impl Message {
    /// `None` if the message cannot be sent in a frame of `max_frame_size`.
    pub fn encode(&self, max_frame_size: u32) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Ping(nonce) => {
                bytes.push(TAG_PING);
                bytes.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::Pong(nonce) => {
                bytes.push(TAG_PONG);
                bytes.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::PeerMessage { topic, payload } => {
                if topic.is_empty() || topic.len() > MAX_STRING_LENGTH {
                    return None;
                }
                bytes.push(TAG_PEER_MESSAGE);
                bytes.extend_from_slice(&(topic.len() as u16).to_be_bytes());
                bytes.extend_from_slice(topic.as_bytes());
                put_data(&mut bytes, payload)?;
            }
        }
        (bytes.len() <= max_frame_size as usize).then_some(bytes)
    }

    /// `Ok(None)` for a message this port does not handle.
    pub(crate) fn decode(data: &[u8], max_frame_size: u32) -> Result<Option<Self>, ()> {
        let mut reader = Reader::new(data);
        let message = match reader.u8().ok_or(())? {
            TAG_PING => Self::Ping(reader.u64().ok_or(())?),
            TAG_PONG => Self::Pong(reader.u64().ok_or(())?),
            TAG_PEER_MESSAGE => {
                let length = reader.u16().ok_or(())? as usize;
                if length > MAX_STRING_LENGTH {
                    return Err(());
                }
                let topic = text(reader.bytes(length).ok_or(())?).ok_or(())?;
                let payload = reader.data(max_frame_size as usize).ok_or(())?;
                Self::PeerMessage {
                    topic: topic.to_owned(),
                    payload: payload.to_vec(),
                }
            }
            _ => return Ok(None),
        };
        match message.encode(max_frame_size) {
            Some(encoded) if encoded == data => Ok(Some(message)),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PeerKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[byte; 32]);
        PeerKey::from_bytes(signing.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn messages_round_trip() {
        for message in [
            Message::Ping(7),
            Message::Pong(u64::MAX),
            Message::PeerMessage {
                topic: "swap".into(),
                payload: vec![1, 2, 3],
            },
        ] {
            let bytes = message.encode(DEFAULT_MAX_FRAME_SIZE).unwrap();
            assert_eq!(
                Message::decode(&bytes, DEFAULT_MAX_FRAME_SIZE),
                Ok(Some(message))
            );
        }
    }

    #[test]
    fn non_canonical_messages_are_malformed() {
        let mut ping = Message::Ping(1).encode(DEFAULT_MAX_FRAME_SIZE).unwrap();
        ping.push(0);
        assert_eq!(Message::decode(&ping, DEFAULT_MAX_FRAME_SIZE), Err(()));
        let empty_topic = [TAG_PEER_MESSAGE, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            Message::decode(&empty_topic, DEFAULT_MAX_FRAME_SIZE),
            Err(())
        );
        let bom_topic = [TAG_PEER_MESSAGE, 0, 4, 0xef, 0xbb, 0xbf, b'a', 0, 0, 0, 0];
        assert_eq!(Message::decode(&bom_topic, DEFAULT_MAX_FRAME_SIZE), Err(()));
        let big = Message::PeerMessage {
            topic: "t".into(),
            payload: vec![0; 100],
        };
        let bytes = big.encode(DEFAULT_MAX_FRAME_SIZE).unwrap();
        assert_eq!(Message::decode(&bytes, 50), Err(()));
        assert_eq!(big.encode(50), None);
    }

    #[test]
    fn other_ivy_messages_are_ignored() {
        // findNode, which this port does not handle yet.
        assert_eq!(
            Message::decode(&[5, 0, 0], DEFAULT_MAX_FRAME_SIZE),
            Ok(None)
        );
    }

    #[test]
    fn metadata_omits_the_default_frame_size_and_rejects_it_spelled_out() {
        assert_eq!(PeerMetadata::default().encode().unwrap(), [0, 0]);
        let spelled = [0, 0, 0, 0x40, 0, 0];
        assert_eq!(PeerMetadata::decode(&spelled), None);
        let custom = PeerMetadata::new(Vec::new(), 1 << 20);
        let bytes = custom.encode().unwrap();
        assert_eq!(PeerMetadata::decode(&bytes), Some(custom));
    }

    #[test]
    fn metadata_must_be_sorted_and_unique() {
        let a = ListenAddress {
            host: "10.0.0.1".into(),
            port: 1,
        };
        let b = ListenAddress {
            host: "10.0.0.2".into(),
            port: 1,
        };
        let sorted = PeerMetadata::new(
            vec![b.clone(), a.clone(), a.clone()],
            DEFAULT_MAX_FRAME_SIZE,
        );
        assert_eq!(sorted.listen_addresses, [a.clone(), b.clone()]);
        let bytes = sorted.encode().unwrap();
        assert_eq!(PeerMetadata::decode(&bytes), Some(sorted));

        let mut reversed = vec![0, 2];
        for address in [&b, &a] {
            put_data(&mut reversed, address.host.as_bytes()).unwrap();
            reversed.extend_from_slice(&address.port.to_be_bytes());
        }
        assert_eq!(PeerMetadata::decode(&reversed), None);
    }

    #[test]
    fn keys_parse_raw_and_multikey_hex() {
        let key = key(1);
        assert_eq!(PeerKey::from_hex(&key.hex()), Some(key));
        assert_eq!(PeerKey::from_hex(&format!("ED01{}", key.hex())), Some(key));
        assert_eq!(PeerKey::from_hex(&key.hex()[2..]), None);
    }

    #[test]
    fn work_bits_count_from_the_last_hash_byte() {
        let key = key(2);
        let hash = Sha256::digest(key.hex().as_bytes());
        let last_nonzero = hash.iter().rev().position(|b| *b != 0).unwrap();
        let expected = 8 * last_nonzero as u32 + hash[31 - last_nonzero].trailing_zeros();
        assert_eq!(key.work_bits(), expected);
    }
}
