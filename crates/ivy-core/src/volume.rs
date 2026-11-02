//! Canonical complete-Volume archives and bounded sequential bundle reception.
//! Content is unvalidated: the application must verify CIDs and semantic closure.
use crate::wire::{accepts_cid, put_data, put_string, Reader};
use crate::{Message, MAX_VOLUME_ARCHIVE_BYTES, MAX_VOLUME_CHUNK_COUNT};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEntry {
    pub cid: String,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Volume {
    pub root_cid: String,
    pub entries: Vec<ContentEntry>,
}

impl Volume {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.entries.is_empty() || self.entries.len() > u16::MAX as usize {
            return None;
        }
        let mut size = 2usize;
        for e in &self.entries {
            if !accepts_cid(&e.cid) {
                return None;
            }
            size = size
                .checked_add(6 + e.cid.len())?
                .checked_add(e.data.len())?;
            if size > MAX_VOLUME_ARCHIVE_BYTES {
                return None;
            }
        }
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.cid.cmp(&b.cid));
        if !entries.iter().any(|e| e.cid == self.root_cid)
            || entries.windows(2).any(|e| e[0].cid == e[1].cid)
        {
            return None;
        }
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for e in entries {
            put_string(&mut bytes, &e.cid)?;
            put_data(&mut bytes, &e.data)?;
        }
        Some(bytes)
    }
    pub fn decode(bytes: &[u8], root_cid: &str, expected_entries: u16) -> Option<Self> {
        if bytes.len() > MAX_VOLUME_ARCHIVE_BYTES {
            return None;
        }
        let mut reader = Reader::new(bytes);
        let count = reader.u16()?;
        if count == 0 || count != expected_entries {
            return None;
        }
        let mut entries: Vec<ContentEntry> = Vec::new();
        for _ in 0..count {
            let cid = reader.string()?;
            if !accepts_cid(&cid) || entries.last().is_some_and(|e| e.cid >= cid) {
                return None;
            }
            let data = reader.data(MAX_VOLUME_ARCHIVE_BYTES)?.to_vec();
            entries.push(ContentEntry { cid, data });
        }
        if !reader.is_at_end() || !entries.iter().any(|e| e.cid == root_cid) {
            return None;
        }
        Some(Self {
            root_cid: root_cid.into(),
            entries,
        })
    }
    pub fn chunks(
        &self,
        request_id: u64,
        max_frame_size: u32,
        relayed: bool,
    ) -> Option<Vec<Message>> {
        if request_id == 0 {
            return None;
        }
        let bytes = self.encode()?;
        let budget = Message::volume_chunk_data_budget(&self.root_cid, max_frame_size, relayed)?;
        if budget == 0 {
            return None;
        }
        let count = bytes.len().div_ceil(budget);
        if count > MAX_VOLUME_CHUNK_COUNT as usize {
            return None;
        }
        Some(
            bytes
                .chunks(budget)
                .enumerate()
                .map(|(index, payload)| Message::VolumeChunk {
                    request_id,
                    root_cid: self.root_cid.clone(),
                    index: index as u16,
                    count: count as u16,
                    total_entries: self.entries.len() as u16,
                    total_bytes: bytes.len() as u64,
                    payload: payload.to_vec(),
                })
                .collect(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeReceiveError {
    ProtocolViolation,
    CallerBoundaryExceeded,
    LocalCapacityUnavailable,
    AlreadyEnded,
    NotSent,
}
#[derive(Debug)]
struct Assembly {
    root: String,
    count: u16,
    entries: u16,
    bytes: usize,
    next: u16,
    data: Vec<u8>,
}
/// One request bound to one authenticated session by its caller. Callers must
/// check session identity before passing messages here. Budgets include completed
/// volumes until `finish` transfers ownership; terminal failures release assembly.
#[derive(Debug)]
pub struct VolumeReceiver {
    request_id: u64,
    root: String,
    bundle: bool,
    max_archive: usize,
    max_entries: u16,
    max_total: usize,
    used: usize,
    max_frame: u32,
    relayed: bool,
    assembly: Option<Assembly>,
    roots: BTreeSet<String>,
    volumes: Vec<Volume>,
    ended: bool,
    failure: Option<VolumeReceiveError>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeResponse {
    /// Set by a session-bound core fetch; standalone archive assembly has no peer identity.
    pub served_by: Option<crate::PeerKey>,
    pub session_id: Option<[u8; 32]>,
    pub volumes: Vec<Volume>,
    pub ended: bool,
    pub no_bundle: bool,
    pub failure: Option<VolumeReceiveError>,
}
impl VolumeReceiver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: u64,
        root: String,
        bundle: bool,
        max_archive: usize,
        max_entries: u16,
        max_total: usize,
        max_frame: u32,
        relayed: bool,
    ) -> Option<Self> {
        if request_id == 0 || !accepts_cid(&root) || max_archive == 0 || max_entries == 0 {
            return None;
        }
        Some(Self {
            request_id,
            root,
            bundle,
            max_archive: max_archive.min(MAX_VOLUME_ARCHIVE_BYTES),
            max_entries,
            max_total,
            used: 0,
            max_frame,
            relayed,
            assembly: None,
            roots: BTreeSet::new(),
            volumes: Vec::new(),
            ended: false,
            failure: None,
        })
    }
    pub fn reserved_bytes(&self) -> usize {
        self.used + self.assembly.as_ref().map(|a| a.bytes).unwrap_or(0)
    }
    pub fn set_global_capacity(&mut self, bytes: usize) {
        self.max_total = bytes;
    }
    pub fn is_done(&self) -> bool {
        self.ended || self.failure.is_some()
    }
    pub fn receive(&mut self, message: &Message) -> Result<(), VolumeReceiveError> {
        if self.ended || self.failure.is_some() {
            return Err(VolumeReceiveError::AlreadyEnded);
        }
        let result = self.receive_inner(message);
        if let Err(e) = result {
            self.assembly = None;
            self.failure = Some(e);
        }
        result
    }
    fn receive_inner(&mut self, message: &Message) -> Result<(), VolumeReceiveError> {
        use VolumeReceiveError::*;
        match message {
            Message::VolumeBundleEnd { request_id }
                if *request_id == self.request_id && self.bundle && self.assembly.is_none() =>
            {
                self.ended = true;
                Ok(())
            }
            Message::VolumeChunk {
                request_id,
                root_cid,
                index,
                count,
                total_entries,
                total_bytes,
                payload,
            } => {
                if *request_id != self.request_id
                    || message.encode(self.max_frame).is_none()
                    || self.volumes.is_empty() && *root_cid != self.root
                    || self.roots.contains(root_cid)
                    || payload.len()
                        > Message::volume_chunk_data_budget(root_cid, self.max_frame, self.relayed)
                            .ok_or(ProtocolViolation)?
                {
                    return Err(ProtocolViolation);
                }
                let bytes = usize::try_from(*total_bytes).map_err(|_| ProtocolViolation)?;
                if self.assembly.is_none() {
                    if *index != 0 {
                        return Err(ProtocolViolation);
                    }
                    if bytes > self.max_archive || *total_entries > self.max_entries {
                        return Err(CallerBoundaryExceeded);
                    }
                    if bytes > self.max_total.saturating_sub(self.used) {
                        return Err(LocalCapacityUnavailable);
                    }
                    self.assembly = Some(Assembly {
                        root: root_cid.clone(),
                        count: *count,
                        entries: *total_entries,
                        bytes,
                        next: 0,
                        data: Vec::new(),
                    });
                }
                let a = self.assembly.as_mut().unwrap();
                if a.root != *root_cid
                    || a.count != *count
                    || a.entries != *total_entries
                    || a.bytes != bytes
                    || a.next != *index
                    || payload.len() > a.bytes - a.data.len()
                {
                    return Err(ProtocolViolation);
                }
                a.data.extend_from_slice(payload);
                a.next += 1;
                if a.next < a.count {
                    return if a.data.len() < a.bytes {
                        Ok(())
                    } else {
                        Err(ProtocolViolation)
                    };
                }
                if a.data.len() != a.bytes {
                    return Err(ProtocolViolation);
                }
                let volume =
                    Volume::decode(&a.data, &a.root, a.entries).ok_or(ProtocolViolation)?;
                self.used += a.bytes;
                self.roots.insert(a.root.clone());
                self.volumes.push(volume);
                self.assembly = None;
                if !self.bundle {
                    self.ended = true;
                }
                Ok(())
            }
            _ => Err(ProtocolViolation),
        }
    }
    pub fn finish(self) -> VolumeResponse {
        VolumeResponse {
            served_by: None,
            session_id: None,
            no_bundle: self.bundle && self.ended && self.volumes.is_empty(),
            volumes: self.volumes,
            ended: self.ended,
            failure: self.failure,
        }
    }
}
