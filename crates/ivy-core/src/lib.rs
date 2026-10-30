//! Ivy, the Lattice peer-to-peer protocol, as plain data: no sockets, tasks
//! or clocks. It speaks the wire protocol of Swift Ivy (`0xLattice/Ivy2`)
//! 3.1.1 for direct, authenticated sessions and application messages.
//!
//! On a connection, every record travels as one frame: a big-endian UInt32
//! length, then the record.

mod session;
mod wire;

pub use session::{AwaitingFinish, Config, Initiator, Responder, Session, SessionError};
pub use wire::{
    ListenAddress, Message, PeerKey, PeerMetadata, DEFAULT_MAX_FRAME_SIZE, MAX_STRING_LENGTH,
};

/// `record` with its frame header.
pub fn frame(record: &[u8]) -> Vec<u8> {
    let length = u32::try_from(record.len()).expect("records are smaller than a frame limit");
    [length.to_be_bytes().as_slice(), record].concat()
}

/// The record length a frame header announces, if a frame of that length
/// is acceptable: not empty, and no larger than `max_frame_size`.
pub fn frame_length(header: [u8; 4], max_frame_size: u32) -> Option<usize> {
    let length = u32::from_be_bytes(header);
    (length > 0 && length <= max_frame_size).then_some(length as usize)
}
