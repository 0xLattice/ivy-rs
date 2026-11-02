//! Swift-compatible WASM reactor ABI. The host supplies entropy through the
//! standard WASI random_get import and supplies both clocks on every step.
#![cfg(target_arch = "wasm32")]
use ivy_core::{core::Timestamp, Config, CoreEntropy};
use ivy_host::{configuration::Configuration, host::Host};
use std::{cell::RefCell, collections::BTreeMap, time::Duration};
#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    fn random_get(pointer: *mut u8, length: usize) -> u32;
}
struct Entropy;
impl CoreEntropy for Entropy {
    fn next(&mut self) -> u64 {
        let bytes = self.bytes32();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut bytes = [0; 32];
        // SAFETY: the host may write exactly the live array's 32 bytes.
        assert_eq!(
            unsafe { random_get(bytes.as_mut_ptr(), bytes.len()) },
            0,
            "host entropy failed"
        );
        bytes
    }
}
struct OwnedHost {
    // Fields drop in declaration order: all config references die before owner.
    host: Host<'static, Entropy>,
    config: Box<Config>,
}
impl OwnedHost {
    fn new(configuration: Configuration) -> Option<Self> {
        configuration.validate().ok()?;
        let config = Box::new(configuration.identity);
        // SAFETY: Box allocation remains stable when OwnedHost moves. No API
        // exposes this reference, and host is dropped before config. Config is
        // never mutated or removed while the borrowing host is alive.
        let reference = unsafe { &*(&*config as *const Config) };
        let host = Host::new(reference, configuration.settings, Entropy).ok()?;
        Some(Self { host, config })
    }
}
#[derive(Default)]
struct State {
    cores: BTreeMap<i32, OwnedHost>,
    last: i32,
    allocations: BTreeMap<usize, Box<[u8]>>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
fn allocate(bytes: Vec<u8>) -> usize {
    let mut bytes = bytes.into_boxed_slice();
    let pointer = bytes.as_mut_ptr() as usize;
    STATE.with(|s| s.borrow_mut().allocations.insert(pointer, bytes));
    pointer
}
fn block(bytes: Vec<u8>) -> usize {
    let Ok(size) = u32::try_from(bytes.len()) else {
        return 0;
    };
    let mut block = size.to_le_bytes().to_vec();
    block.extend(bytes);
    allocate(block)
}
/// Only live allocations from this reactor can be read. Unknown pointers and
/// lengths beyond their allocation are refused instead of dereferenced.
fn input(pointer: usize, length: i32) -> Option<Vec<u8>> {
    let length = usize::try_from(length).ok()?;
    if length == 0 {
        return Some(vec![]);
    }
    STATE.with(|s| {
        s.borrow()
            .allocations
            .get(&pointer)?
            .get(..length)
            .map(|b| b.to_vec())
    })
}
#[no_mangle]
pub extern "C" fn _initialize() {}
#[no_mangle]
pub extern "C" fn ivy_alloc(length: i32) -> usize {
    if length <= 0 {
        return 0;
    }
    allocate(vec![0; length as usize])
}
#[no_mangle]
pub extern "C" fn ivy_free(pointer: usize) {
    STATE.with(|s| s.borrow_mut().allocations.remove(&pointer));
}
#[no_mangle]
pub extern "C" fn ivy_write_high_water_mark() -> i32 {
    ivy_core::core::WRITE_HIGH_WATER_MARK as i32
}
#[no_mangle]
pub extern "C" fn ivy_core_create(pointer: usize, length: i32) -> i32 {
    let Some(bytes) = input(pointer, length) else {
        return 0;
    };
    let Some(config) = Configuration::decode(&bytes) else {
        return 0;
    };
    let Some(core) = OwnedHost::new(config) else {
        return 0;
    };
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        let Some(handle) = state.last.checked_add(1) else {
            return 0;
        };
        state.last = handle;
        state.cores.insert(handle, core);
        handle
    })
}
#[no_mangle]
pub extern "C" fn ivy_core_destroy(handle: i32) {
    STATE.with(|s| s.borrow_mut().cores.remove(&handle));
}
#[no_mangle]
pub extern "C" fn ivy_core_step(
    handle: i32,
    pointer: usize,
    length: i32,
    uptime_nanoseconds: u64,
    unix_seconds: u64,
) -> usize {
    let Some(bytes) = input(pointer, length) else {
        return 0;
    };
    let effects = STATE.with(|s| {
        s.borrow_mut().cores.get_mut(&handle)?.host.step(
            &bytes,
            Timestamp {
                uptime: Duration::from_nanos(uptime_nanoseconds),
                unix_seconds,
            },
        )
    });
    effects.map(block).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn ivy_core_public_key(handle: i32) -> usize {
    let bytes = STATE.with(|s| {
        s.borrow()
            .cores
            .get(&handle)
            .map(|h| h.config.peer_key().as_bytes().to_vec())
    });
    bytes.map(block).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn ivy_core_connected_peers(handle: i32) -> usize {
    let bytes = STATE.with(|s| {
        s.borrow()
            .cores
            .get(&handle)
            .map(|h| h.host.encoded_connected_peers())
    });
    bytes.map(block).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn ivy_core_connected_peer_endpoints(handle: i32) -> usize {
    let bytes = STATE.with(|s| {
        s.borrow()
            .cores
            .get(&handle)
            .map(|h| h.host.encoded_connected_endpoints())
    });
    bytes.map(block).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn ivy_core_known_peer_endpoints(handle: i32) -> usize {
    let bytes = STATE.with(|s| {
        s.borrow()
            .cores
            .get(&handle)
            .map(|h| h.host.encoded_known_endpoints())
    });
    bytes.map(block).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn ivy_core_providers(handle: i32, pointer: usize, length: i32) -> usize {
    let Some(bytes) = input(pointer, length) else {
        return 0;
    };
    let Ok(root) = std::str::from_utf8(&bytes) else {
        return 0;
    };
    let bytes = STATE.with(|s| {
        s.borrow_mut()
            .cores
            .get_mut(&handle)
            .map(|h| h.host.encoded_providers(root))
    });
    bytes.map(block).unwrap_or(0)
}
