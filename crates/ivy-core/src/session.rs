//! Ivy's session protocol: a signed three-record handshake, then signed,
//! sequenced data records that carry messages.
//!
//! The initiator sends a hello naming the responder it expects; the
//! responder answers with its own hello; the initiator closes with a signed
//! finish. Both derive the session ID from the two hellos, and every data
//! record after is signed over that ID, both keys and a sequence number, so
//! a record cannot be replayed, reordered or moved to another session.
//! Records are authenticated, not encrypted.

use crate::wire::{put_data, Message, PeerKey, PeerMetadata, Reader};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

const VERSION: u16 = 9;
const MAGIC: [u8; 4] = *b"IVY\x09";
/// Binds a hello to a direct connection; relayed routes use their route ID.
const DIRECT_ROUTE: [u8; 32] = [0; 32];
const HELLO_DOMAIN: &str = "ivy.session.hello.v1";
const TRANSCRIPT_DOMAIN: &str = "ivy.session.transcript.v1";
const FINISH_DOMAIN: &str = "ivy.session.finish.v1";
const DATA_DOMAIN: &str = "ivy.session.data.v1";
const INITIATOR_HELLO_OVERHEAD: usize = 2 + 4 * 32 + 4;
const RESPONDER_HELLO_OVERHEAD: usize = 2 + 5 * 32 + 4;

/// The smallest frame limit a node may set: room for the largest legal
/// handshake record, even relayed (inside a relay packet inside a data
/// record). Swift Ivy refuses a smaller `protocolMaxFrameSize` too.
pub const MIN_FRAME_SIZE: u32 = (PeerMetadata::MAX_ENCODED_SIZE
    + RESPONDER_HELLO_OVERHEAD
    + (4 + 1 + 4 + 64)
    + (1 + 32 + 4)
    + (4 + 1 + 32 + 8 + 4 + 64)) as u32;

/// Why a handshake or session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// A record did not decode, or was not the record expected next.
    Malformed,
    /// A record decoded but failed a signature, binding or sequence check.
    Rejected,
    /// The peer's key has less proof of work than this node requires.
    InsufficientKeyWork,
    /// The peer is not one this node accepts.
    PeerRefused,
    /// Nothing more can be sent: the message is too large for the peer, or
    /// the sequence numbers are spent.
    CannotSend,
    /// This node's own `Config` cannot work: its frame limit is below
    /// `MIN_FRAME_SIZE`, or its metadata does not encode.
    InvalidConfig,
}

/// This node's identity and what it tells peers.
pub struct Config {
    pub signing_key: SigningKey,
    pub metadata: PeerMetadata,
    /// Peers whose keys carry fewer work bits are refused. 0 accepts all.
    pub min_peer_key_bits: u32,
}

impl Config {
    pub fn new(signing_key: SigningKey) -> Self {
        Self {
            signing_key,
            metadata: PeerMetadata::default(),
            min_peer_key_bits: 0,
        }
    }

    pub fn peer_key(&self) -> PeerKey {
        PeerKey::from_bytes(self.signing_key.verifying_key().as_bytes())
            .expect("a signing key's public key is a valid point")
    }

    fn max_frame_size(&self) -> u32 {
        self.metadata.max_frame_size
    }

    fn accepts_work(&self, key: &PeerKey) -> Result<(), SessionError> {
        if self.min_peer_key_bits == 0 || key.work_bits() >= self.min_peer_key_bits {
            Ok(())
        } else {
            Err(SessionError::InsufficientKeyWork)
        }
    }

    fn sign(&self, domain: &str, body: &[u8]) -> [u8; 64] {
        self.signing_key
            .sign(&signed_bytes(domain, body))
            .to_bytes()
    }
}

fn length_prefixed(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + value.len());
    put_data(&mut bytes, value).expect("domain strings are short");
    bytes
}

fn signed_bytes(domain: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = length_prefixed(domain.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// An encoded hello and its signature: what the session ID is hashed over.
#[derive(Clone)]
struct SignedHello {
    encoded: Vec<u8>,
    signature: [u8; 64],
}

impl SignedHello {
    fn transcript(&self) -> Vec<u8> {
        [self.encoded.as_slice(), &self.signature].concat()
    }

    fn record(&self, tag: u8) -> Option<Vec<u8>> {
        let mut bytes = MAGIC.to_vec();
        bytes.push(tag);
        put_data(&mut bytes, &self.encoded)?;
        bytes.extend_from_slice(&self.signature);
        Some(bytes)
    }

    fn read(record: &[u8], tag: u8, overhead: usize) -> Result<Self, SessionError> {
        let mut reader = Reader::new(record);
        if reader.bytes(4) != Some(&MAGIC[..]) || reader.u8() != Some(tag) {
            return Err(SessionError::Malformed);
        }
        let encoded = reader
            .data(PeerMetadata::MAX_ENCODED_SIZE + overhead)
            .ok_or(SessionError::Malformed)?
            .to_vec();
        let signature = reader.array().ok_or(SessionError::Malformed)?;
        if !reader.is_at_end() {
            return Err(SessionError::Malformed);
        }
        Ok(Self { encoded, signature })
    }
}

fn session_id(initiator: &SignedHello, responder: &SignedHello) -> [u8; 32] {
    let mut transcript = length_prefixed(TRANSCRIPT_DOMAIN.as_bytes());
    put_data(&mut transcript, &initiator.transcript()).expect("hellos are bounded");
    put_data(&mut transcript, &responder.transcript()).expect("hellos are bounded");
    Sha256::digest(&transcript).into()
}

fn finish_body(session_id: &[u8; 32], sender: &PeerKey, receiver: &PeerKey) -> Vec<u8> {
    [
        session_id.as_slice(),
        sender.as_bytes(),
        receiver.as_bytes(),
    ]
    .concat()
}

/// This node's metadata, encoded; checked here because both sides of a
/// handshake send it first.
fn metadata_bytes(config: &Config) -> Result<Vec<u8>, SessionError> {
    if config.max_frame_size() < MIN_FRAME_SIZE {
        return Err(SessionError::InvalidConfig);
    }
    config.metadata.encode().ok_or(SessionError::InvalidConfig)
}

struct InitiatorHello {
    initiator: PeerKey,
    responder: PeerKey,
    nonce: [u8; 32],
    metadata: PeerMetadata,
}

impl InitiatorHello {
    fn encode(&self, metadata: &[u8]) -> Option<Vec<u8>> {
        let mut bytes = VERSION.to_be_bytes().to_vec();
        bytes.extend_from_slice(&DIRECT_ROUTE);
        bytes.extend_from_slice(self.initiator.as_bytes());
        bytes.extend_from_slice(self.responder.as_bytes());
        bytes.extend_from_slice(&self.nonce);
        put_data(&mut bytes, metadata)?;
        Some(bytes)
    }

    fn decode(encoded: &[u8]) -> Result<Self, SessionError> {
        let mut reader = Reader::new(encoded);
        if reader.u16() != Some(VERSION) || reader.array() != Some(DIRECT_ROUTE) {
            return Err(SessionError::Malformed);
        }
        let initiator = reader.key().ok_or(SessionError::Malformed)?;
        let responder = reader.key().ok_or(SessionError::Malformed)?;
        let nonce = reader.array().ok_or(SessionError::Malformed)?;
        let metadata = reader
            .data(PeerMetadata::MAX_ENCODED_SIZE)
            .and_then(PeerMetadata::decode)
            .ok_or(SessionError::Malformed)?;
        if !reader.is_at_end() {
            return Err(SessionError::Malformed);
        }
        Ok(Self {
            initiator,
            responder,
            nonce,
            metadata,
        })
    }
}

struct ResponderHello {
    responder: PeerKey,
    initiator: PeerKey,
    initiator_nonce: [u8; 32],
    metadata: PeerMetadata,
}

impl ResponderHello {
    fn encode(&self, responder_nonce: &[u8; 32], metadata: &[u8]) -> Option<Vec<u8>> {
        let mut bytes = VERSION.to_be_bytes().to_vec();
        bytes.extend_from_slice(&DIRECT_ROUTE);
        bytes.extend_from_slice(self.responder.as_bytes());
        bytes.extend_from_slice(self.initiator.as_bytes());
        bytes.extend_from_slice(&self.initiator_nonce);
        bytes.extend_from_slice(responder_nonce);
        put_data(&mut bytes, metadata)?;
        Some(bytes)
    }

    fn decode(encoded: &[u8]) -> Result<Self, SessionError> {
        let mut reader = Reader::new(encoded);
        if reader.u16() != Some(VERSION) || reader.array() != Some(DIRECT_ROUTE) {
            return Err(SessionError::Malformed);
        }
        let responder = reader.key().ok_or(SessionError::Malformed)?;
        let initiator = reader.key().ok_or(SessionError::Malformed)?;
        let initiator_nonce = reader.array().ok_or(SessionError::Malformed)?;
        reader.array::<32>().ok_or(SessionError::Malformed)?;
        let metadata = reader
            .data(PeerMetadata::MAX_ENCODED_SIZE)
            .and_then(PeerMetadata::decode)
            .ok_or(SessionError::Malformed)?;
        if !reader.is_at_end() {
            return Err(SessionError::Malformed);
        }
        Ok(Self {
            responder,
            initiator,
            initiator_nonce,
            metadata,
        })
    }
}

/// The dialing side of a handshake on a direct connection.
pub struct Initiator<'a> {
    config: &'a Config,
    expected: PeerKey,
    nonce: [u8; 32],
    hello: SignedHello,
}

impl<'a> Initiator<'a> {
    /// Starts a handshake with the peer that must hold `expected`. Send the
    /// returned record, then pass the reply to `receive`.
    pub fn start(
        config: &'a Config,
        expected: PeerKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let hello = InitiatorHello {
            initiator: config.peer_key(),
            responder: expected,
            nonce,
            metadata: config.metadata.clone(),
        };
        let encoded = hello
            .encode(&metadata_bytes(config)?)
            .ok_or(SessionError::CannotSend)?;
        let signature = config.sign(HELLO_DOMAIN, &encoded);
        let hello = SignedHello { encoded, signature };
        let record = hello.record(1).ok_or(SessionError::CannotSend)?;
        let initiator = Self {
            config,
            expected,
            nonce,
            hello,
        };
        Ok((initiator, record))
    }

    /// Takes the responder's hello. On success, send the returned finish
    /// record; the session is open from then on.
    pub fn receive(self, record: &[u8]) -> Result<(Session, Vec<u8>), SessionError> {
        let signed = SignedHello::read(record, 2, RESPONDER_HELLO_OVERHEAD)?;
        let hello = ResponderHello::decode(&signed.encoded)?;
        let local = self.config.peer_key();
        if hello.responder != self.expected
            || hello.initiator != local
            || hello.initiator_nonce != self.nonce
            || !self.expected.verifies(
                &signed_bytes(HELLO_DOMAIN, &signed.encoded),
                &signed.signature,
            )
        {
            return Err(SessionError::Rejected);
        }
        self.config.accepts_work(&self.expected)?;
        let id = session_id(&self.hello, &signed);
        let signature = self
            .config
            .sign(FINISH_DOMAIN, &finish_body(&id, &local, &self.expected));
        let mut finish = MAGIC.to_vec();
        finish.push(3);
        finish.extend_from_slice(&finish_body(&id, &local, &self.expected));
        finish.extend_from_slice(&signature);
        let session = Session::new(self.config, self.expected, id, hello.metadata);
        Ok((session, finish))
    }
}

/// The accepting side of a handshake on a direct connection.
pub struct Responder<'a> {
    config: &'a Config,
}

/// A responder that has answered and waits for the initiator's finish.
pub struct AwaitingFinish<'a> {
    config: &'a Config,
    remote: PeerKey,
    metadata: PeerMetadata,
    id: [u8; 32],
}

impl<'a> Responder<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    /// Takes the initiator's hello. `accepts` decides whether this node will
    /// talk to the key it names. On success, send the returned record.
    pub fn receive(
        self,
        record: &[u8],
        accepts: impl FnOnce(&PeerKey) -> bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(AwaitingFinish<'a>, Vec<u8>), SessionError> {
        let signed = SignedHello::read(record, 1, INITIATOR_HELLO_OVERHEAD)?;
        let hello = InitiatorHello::decode(&signed.encoded)?;
        let local = self.config.peer_key();
        if hello.responder != local
            || hello.initiator == local
            || !hello.initiator.verifies(
                &signed_bytes(HELLO_DOMAIN, &signed.encoded),
                &signed.signature,
            )
        {
            return Err(SessionError::Rejected);
        }
        if !accepts(&hello.initiator) {
            return Err(SessionError::PeerRefused);
        }
        self.config.accepts_work(&hello.initiator)?;

        let mut responder_nonce = [0; 32];
        rng.fill_bytes(&mut responder_nonce);
        let reply = ResponderHello {
            responder: local,
            initiator: hello.initiator,
            initiator_nonce: hello.nonce,
            metadata: self.config.metadata.clone(),
        };
        let encoded = reply
            .encode(&responder_nonce, &metadata_bytes(self.config)?)
            .ok_or(SessionError::CannotSend)?;
        let signature = self.config.sign(HELLO_DOMAIN, &encoded);
        let reply = SignedHello { encoded, signature };
        let record = reply.record(2).ok_or(SessionError::CannotSend)?;
        let waiting = AwaitingFinish {
            config: self.config,
            remote: hello.initiator,
            metadata: hello.metadata,
            id: session_id(&signed, &reply),
        };
        Ok((waiting, record))
    }
}

impl<'a> AwaitingFinish<'a> {
    /// The key the initiator proved it holds.
    pub fn peer(&self) -> PeerKey {
        self.remote
    }

    /// Takes the initiator's finish; the session is open after it.
    pub fn receive(self, record: &[u8]) -> Result<Session, SessionError> {
        let mut reader = Reader::new(record);
        if reader.bytes(4) != Some(&MAGIC[..]) || reader.u8() != Some(3) {
            return Err(SessionError::Malformed);
        }
        let id: [u8; 32] = reader.array().ok_or(SessionError::Malformed)?;
        let sender = reader.key().ok_or(SessionError::Malformed)?;
        let receiver = reader.key().ok_or(SessionError::Malformed)?;
        let signature = reader.array().ok_or(SessionError::Malformed)?;
        if !reader.is_at_end() {
            return Err(SessionError::Malformed);
        }
        let local = self.config.peer_key();
        if id != self.id
            || sender != self.remote
            || receiver != local
            || !sender.verifies(
                &signed_bytes(FINISH_DOMAIN, &finish_body(&id, &sender, &receiver)),
                &signature,
            )
        {
            return Err(SessionError::Rejected);
        }
        Ok(Session::new(self.config, self.remote, id, self.metadata))
    }
}

/// An authenticated session: seals outgoing messages into signed data
/// records and opens incoming ones.
pub struct Session {
    signing_key: SigningKey,
    local: PeerKey,
    remote: PeerKey,
    id: [u8; 32],
    remote_metadata: PeerMetadata,
    local_max_frame_size: u32,
    /// `None` once `u64::MAX` has been sent.
    next_to_send: Option<u64>,
    last_received: u64,
}

impl Session {
    fn new(config: &Config, remote: PeerKey, id: [u8; 32], remote_metadata: PeerMetadata) -> Self {
        Self {
            signing_key: config.signing_key.clone(),
            local: config.peer_key(),
            remote,
            id,
            remote_metadata,
            local_max_frame_size: config.max_frame_size(),
            next_to_send: Some(1),
            last_received: 0,
        }
    }

    pub fn peer(&self) -> PeerKey {
        self.remote
    }

    pub fn peer_metadata(&self) -> &PeerMetadata {
        &self.remote_metadata
    }

    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// The largest frame this node accepts on this session.
    pub fn max_inbound_frame_size(&self) -> u32 {
        self.local_max_frame_size
    }

    /// A signed data record carrying `message`, no larger than the peer
    /// said it accepts.
    pub fn seal(&mut self, message: &Message) -> Result<Vec<u8>, SessionError> {
        let limit = self.remote_metadata.max_frame_size;
        let payload = message.encode(limit).ok_or(SessionError::CannotSend)?;
        let sequence = self.next_to_send.ok_or(SessionError::CannotSend)?;
        let signature = self
            .signing_key
            .sign(&data_signed_bytes(
                &self.id,
                &self.local,
                &self.remote,
                sequence,
                &payload,
            ))
            .to_bytes();
        let mut record = MAGIC.to_vec();
        record.push(4);
        record.extend_from_slice(&self.id);
        record.extend_from_slice(&sequence.to_be_bytes());
        put_data(&mut record, &payload).ok_or(SessionError::CannotSend)?;
        record.extend_from_slice(&signature);
        if record.len() > limit as usize {
            return Err(SessionError::CannotSend);
        }
        self.next_to_send = sequence.checked_add(1);
        Ok(record)
    }

    /// Opens a data record from the peer. `Ok(None)` is a message this port
    /// does not handle. Any error ends the session.
    pub fn open(&mut self, record: &[u8]) -> Result<Option<Message>, SessionError> {
        let limit = self.local_max_frame_size;
        let mut reader = Reader::new(record);
        if reader.bytes(4) != Some(&MAGIC[..]) || reader.u8() != Some(4) {
            return Err(SessionError::Malformed);
        }
        let id: [u8; 32] = reader.array().ok_or(SessionError::Malformed)?;
        let sequence = reader.u64().ok_or(SessionError::Malformed)?;
        let payload = reader.data(limit as usize).ok_or(SessionError::Malformed)?;
        let signature = reader.array().ok_or(SessionError::Malformed)?;
        if !reader.is_at_end() || sequence == 0 {
            return Err(SessionError::Malformed);
        }
        if id != self.id
            || sequence <= self.last_received
            || !self.remote.verifies(
                &data_signed_bytes(&id, &self.remote, &self.local, sequence, payload),
                &signature,
            )
        {
            return Err(SessionError::Rejected);
        }
        self.last_received = sequence;
        Message::decode(payload, limit).map_err(|()| SessionError::Malformed)
    }
}

fn data_signed_bytes(
    id: &[u8; 32],
    sender: &PeerKey,
    receiver: &PeerKey,
    sequence: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = length_prefixed(DATA_DOMAIN.as_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(sender.as_bytes());
    bytes.extend_from_slice(receiver.as_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    put_data(&mut bytes, payload).expect("payloads fit a frame");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ListenAddress;
    use rand_core::OsRng;

    fn config(byte: u8) -> Config {
        Config::new(SigningKey::from_bytes(&[byte; 32]))
    }

    fn handshake(a: &Config, b: &Config) -> (Session, Session) {
        let (initiator, hello) = Initiator::start(a, b.peer_key(), &mut OsRng).unwrap();
        let (waiting, reply) = Responder::new(b)
            .receive(&hello, |_| true, &mut OsRng)
            .unwrap();
        assert_eq!(waiting.peer(), a.peer_key());
        let (dialer, finish) = initiator.receive(&reply).unwrap();
        let listener = waiting.receive(&finish).unwrap();
        (dialer, listener)
    }

    fn message(topic: &str) -> Message {
        Message::PeerMessage {
            topic: topic.into(),
            payload: topic.as_bytes().to_vec(),
        }
    }

    #[test]
    fn both_sides_agree_and_exchange_messages() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, mut listener) = handshake(&a, &b);
        assert_eq!(dialer.id(), listener.id());
        assert_eq!(dialer.peer(), b.peer_key());
        assert_eq!(listener.peer(), a.peer_key());

        let record = dialer.seal(&message("one")).unwrap();
        assert_eq!(listener.open(&record), Ok(Some(message("one"))));
        let record = listener.seal(&Message::Pong(9)).unwrap();
        assert_eq!(dialer.open(&record), Ok(Some(Message::Pong(9))));
    }

    #[test]
    fn metadata_reaches_the_other_side() {
        let mut a = config(1);
        a.metadata = PeerMetadata::new(
            vec![ListenAddress {
                host: "127.0.0.1".into(),
                port: 4001,
            }],
            1 << 20,
        );
        let b = config(2);
        let (dialer, listener) = handshake(&a, &b);
        assert_eq!(listener.peer_metadata(), &a.metadata);
        assert_eq!(dialer.peer_metadata(), &b.metadata);
    }

    #[test]
    fn a_responder_that_is_not_the_expected_key_is_rejected() {
        let (a, b, c) = (config(1), config(2), config(3));
        let (initiator, hello) = Initiator::start(&a, c.peer_key(), &mut OsRng).unwrap();
        // b is not the key a dialed for, so b refuses the hello outright.
        assert!(Responder::new(&b)
            .receive(&hello, |_| true, &mut OsRng)
            .is_err());
        // And a refuses an answer from b to a hello that named c.
        let (_, hello_to_b) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (_, reply) = Responder::new(&b)
            .receive(&hello_to_b, |_| true, &mut OsRng)
            .unwrap();
        assert_eq!(
            initiator.receive(&reply).err(),
            Some(SessionError::Rejected)
        );
    }

    /// A responder hello with any fields, signed by `signer`.
    fn forged_reply(
        signer: &Config,
        responder: PeerKey,
        initiator: PeerKey,
        initiator_nonce: [u8; 32],
    ) -> Vec<u8> {
        let hello = ResponderHello {
            responder,
            initiator,
            initiator_nonce,
            metadata: PeerMetadata::default(),
        };
        let encoded = hello.encode(&[7; 32], &[0, 0]).unwrap();
        let signature = signer.sign(HELLO_DOMAIN, &encoded);
        SignedHello { encoded, signature }.record(2).unwrap()
    }

    /// A finish with any fields, signed by `signer`.
    fn forged_finish(
        signer: &Config,
        id: &[u8; 32],
        sender: PeerKey,
        receiver: PeerKey,
    ) -> Vec<u8> {
        let body = finish_body(id, &sender, &receiver);
        let signature = signer.sign(FINISH_DOMAIN, &body);
        [MAGIC.as_slice(), &[3], &body, &signature].concat()
    }

    #[test]
    fn the_dialer_accepts_only_the_key_it_dialed() {
        let (a, b, m) = (config(1), config(2), config(3));
        let answer = |reply: &dyn Fn(&Initiator) -> Vec<u8>| {
            let (initiator, _) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
            let record = reply(&initiator);
            initiator.receive(&record).err()
        };
        // The honest answer, built the same way, is accepted.
        assert_eq!(
            answer(&|i| forged_reply(&b, b.peer_key(), a.peer_key(), i.nonce)),
            None
        );
        // m answers in its own name, correctly signed: still not b.
        assert_eq!(
            answer(&|i| forged_reply(&m, m.peer_key(), a.peer_key(), i.nonce)),
            Some(SessionError::Rejected)
        );
        // m answers in b's name: the signature is not b's.
        assert_eq!(
            answer(&|i| forged_reply(&m, b.peer_key(), a.peer_key(), i.nonce)),
            Some(SessionError::Rejected)
        );
        // b's answer, but to a hello from someone else.
        assert_eq!(
            answer(&|i| forged_reply(&b, b.peer_key(), m.peer_key(), i.nonce)),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn the_listener_accepts_only_a_finish_from_the_initiator_to_itself() {
        let (a, b, m) = (config(1), config(2), config(3));
        let waiting = || {
            let (_, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
            Responder::new(&b)
                .receive(&hello, |_| true, &mut OsRng)
                .unwrap()
                .0
        };
        let finish = |signer: &Config, sender: &Config, receiver: &Config| {
            let waiting = waiting();
            let record = forged_finish(signer, &waiting.id, sender.peer_key(), receiver.peer_key());
            waiting.receive(&record).err()
        };
        assert_eq!(finish(&a, &a, &b), None);
        // m replays a's hello and closes the handshake itself.
        assert_eq!(finish(&m, &m, &b), Some(SessionError::Rejected));
        // m claims to be a.
        assert_eq!(finish(&m, &a, &b), Some(SessionError::Rejected));
        // a's finish, but addressed to someone else.
        assert_eq!(finish(&a, &a, &m), Some(SessionError::Rejected));
    }

    #[test]
    fn hellos_for_another_version_or_a_relayed_route_are_malformed() {
        let (a, b) = (config(1), config(2));
        // Offsets in a hello record: magic, tag, length, then the version
        // and the route binding.
        let (version, route) = (4 + 1 + 4, 4 + 1 + 4 + 2);
        for offset in [version + 1, route] {
            let (_, mut hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
            hello[offset] ^= 1;
            assert_eq!(
                Responder::new(&b)
                    .receive(&hello, |_| true, &mut OsRng)
                    .err(),
                Some(SessionError::Malformed)
            );
            let (initiator, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
            let (_, mut reply) = Responder::new(&b)
                .receive(&hello, |_| true, &mut OsRng)
                .unwrap();
            reply[offset] ^= 1;
            assert_eq!(
                initiator.receive(&reply).err(),
                Some(SessionError::Malformed)
            );
        }
    }

    #[test]
    fn a_node_will_not_handshake_with_itself() {
        let b = config(2);
        let (_, hello) = Initiator::start(&b, b.peer_key(), &mut OsRng).unwrap();
        assert_eq!(
            Responder::new(&b)
                .receive(&hello, |_| true, &mut OsRng)
                .err(),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn the_dialer_refuses_a_responder_below_its_work_floor() {
        let mut a = config(1);
        let b = config(2);
        a.min_peer_key_bits = b.peer_key().work_bits() + 1;
        let (initiator, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (_, reply) = Responder::new(&b)
            .receive(&hello, |_| true, &mut OsRng)
            .unwrap();
        assert_eq!(
            initiator.receive(&reply).err(),
            Some(SessionError::InsufficientKeyWork)
        );
    }

    #[test]
    fn a_frame_limit_too_small_for_a_handshake_is_refused() {
        let mut a = config(1);
        let b = config(2);
        a.metadata = PeerMetadata::new(Vec::new(), MIN_FRAME_SIZE - 1);
        assert_eq!(
            Initiator::start(&a, b.peer_key(), &mut OsRng).err(),
            Some(SessionError::InvalidConfig)
        );
        a.metadata = PeerMetadata::new(Vec::new(), MIN_FRAME_SIZE);
        assert!(Initiator::start(&a, b.peer_key(), &mut OsRng).is_ok());
    }

    #[test]
    fn a_reply_to_another_hello_is_rejected() {
        let (a, b) = (config(1), config(2));
        let (first, _) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (_, second_hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (_, reply) = Responder::new(&b)
            .receive(&second_hello, |_| true, &mut OsRng)
            .unwrap();
        assert_eq!(first.receive(&reply).err(), Some(SessionError::Rejected));
    }

    #[test]
    fn a_tampered_hello_is_rejected() {
        let (a, b) = (config(1), config(2));
        let (_, mut hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        // A nonce byte: the hello still decodes, its signature does not hold.
        hello[5 + 4 + 2 + 32 * 3] ^= 1;
        assert_eq!(
            Responder::new(&b)
                .receive(&hello, |_| true, &mut OsRng)
                .err(),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn the_responder_may_refuse_a_peer() {
        let (a, b) = (config(1), config(2));
        let (_, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        assert_eq!(
            Responder::new(&b)
                .receive(&hello, |_| false, &mut OsRng)
                .err(),
            Some(SessionError::PeerRefused)
        );
    }

    #[test]
    fn keys_below_the_work_floor_are_refused() {
        let a = config(1);
        let mut b = config(2);
        b.min_peer_key_bits = a.peer_key().work_bits() + 1;
        let (_, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        assert_eq!(
            Responder::new(&b)
                .receive(&hello, |_| true, &mut OsRng)
                .err(),
            Some(SessionError::InsufficientKeyWork)
        );
    }

    #[test]
    fn a_finish_signed_for_another_session_is_rejected() {
        let (a, b) = (config(1), config(2));
        let (_, hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (waiting, _) = Responder::new(&b)
            .receive(&hello, |_| true, &mut OsRng)
            .unwrap();
        let (other, other_hello) = Initiator::start(&a, b.peer_key(), &mut OsRng).unwrap();
        let (_, other_reply) = Responder::new(&b)
            .receive(&other_hello, |_| true, &mut OsRng)
            .unwrap();
        let (_, other_finish) = other.receive(&other_reply).unwrap();
        assert_eq!(
            waiting.receive(&other_finish).err(),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn replayed_and_reordered_records_are_rejected() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, mut listener) = handshake(&a, &b);
        let first = dialer.seal(&message("first")).unwrap();
        let second = dialer.seal(&message("second")).unwrap();
        assert!(listener.open(&second).unwrap().is_some());
        assert_eq!(listener.open(&first), Err(SessionError::Rejected));
        assert_eq!(listener.open(&second), Err(SessionError::Rejected));
    }

    #[test]
    fn records_do_not_cross_sessions_or_directions() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, mut listener) = handshake(&a, &b);
        let (mut other_dialer, _) = handshake(&a, &b);
        let foreign = other_dialer.seal(&message("x")).unwrap();
        assert_eq!(listener.open(&foreign), Err(SessionError::Rejected));
        // A record the dialer sent, handed back to the dialer.
        let own = dialer.seal(&message("x")).unwrap();
        assert_eq!(dialer.open(&own), Err(SessionError::Rejected));
    }

    #[test]
    fn a_tampered_record_is_rejected() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, mut listener) = handshake(&a, &b);
        let mut record = dialer.seal(&message("payload")).unwrap();
        let last_payload_byte = record.len() - 65;
        record[last_payload_byte] ^= 1;
        assert_eq!(listener.open(&record), Err(SessionError::Rejected));
    }

    #[test]
    fn unknown_messages_are_ignored_but_still_sequenced() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, mut listener) = handshake(&a, &b);
        // A findNode record, signed as the dialer's session would sign it.
        let payload = [5u8, 0, 0, 0, 32];
        let sequence = 1;
        let signature = a
            .signing_key
            .sign(&data_signed_bytes(
                &dialer.id(),
                &a.peer_key(),
                &b.peer_key(),
                sequence,
                &payload,
            ))
            .to_bytes();
        let mut record = MAGIC.to_vec();
        record.push(4);
        record.extend_from_slice(&dialer.id());
        record.extend_from_slice(&sequence.to_be_bytes());
        put_data(&mut record, &payload).unwrap();
        record.extend_from_slice(&signature);
        assert_eq!(listener.open(&record), Ok(None));
        assert_eq!(listener.open(&record), Err(SessionError::Rejected));
        dialer.next_to_send = Some(2);
        let next = dialer.seal(&message("after")).unwrap();
        assert_eq!(listener.open(&next), Ok(Some(message("after"))));
    }

    #[test]
    fn messages_larger_than_the_peer_accepts_are_not_sealed() {
        let a = config(1);
        let mut b = config(2);
        b.metadata = PeerMetadata::new(Vec::new(), MIN_FRAME_SIZE);
        let (mut dialer, _) = handshake(&a, &b);
        let small = Message::PeerMessage {
            topic: "t".into(),
            payload: vec![0; MIN_FRAME_SIZE as usize - 200],
        };
        let large = Message::PeerMessage {
            topic: "t".into(),
            payload: vec![0; MIN_FRAME_SIZE as usize],
        };
        assert!(dialer.seal(&small).is_ok());
        assert_eq!(dialer.seal(&large), Err(SessionError::CannotSend));
    }

    #[test]
    fn sequence_numbers_run_out_rather_than_wrap() {
        let (a, b) = (config(1), config(2));
        let (mut dialer, _) = handshake(&a, &b);
        dialer.next_to_send = Some(u64::MAX);
        assert!(dialer.seal(&Message::Ping(1)).is_ok());
        assert_eq!(
            dialer.seal(&Message::Ping(2)),
            Err(SessionError::CannotSend)
        );
    }
}
