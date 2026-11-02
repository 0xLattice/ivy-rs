# ivy-rs

Rust implementation of [Ivy](https://github.com/0xLattice/Ivy2), the Lattice
peer-to-peer protocol. It speaks the same wire protocol as Swift Ivy and is
checked against it by the interoperability suite.

See [PORTING.md](PORTING.md) for implemented coverage, validation commands, and remaining full-platform work.

Native entry points:

- `ivy::node::run` drives the core over TCP; `run_with_ledger` integrates Tally.
- `ivy::node::run_with_supplied` also accepts externally opened streams through
  a bounded channel, including `ivy_websocket::connect` / `accept` streams.
- `ivy::punch_node::run` wraps node notifications and commands with automatic
  relay-to-direct TCP upgrades. Configure explicit candidate hosts or STUN discovery.
- `ivy_core::core::Core::step` is the deterministic event/effect boundary for
  other runtimes. Acknowledge `PeerConnected` and `Deliver` tokens to release
  charged input and resume reads. Content jobs are completed by the host store.

`ivy-wasm` builds a `wasm32-unknown-unknown` reactor compatible with the original
Ivy Web host. `bash interop/browser.sh` exercises that host against the Rust
reactor and native WebSocket transport. See the coverage document for remaining
behavioral differences before treating this as a full replacement.

`ivy-simulation` runs many cores on one virtual clock, with deterministic key and
entropy derivation, real Ed25519 signatures, segmented transport, configurable
latency, dial partitions, delayed writes, delivery/storage holds, in-memory
Volumes and bundles, a controllable ledger, raw malformed-input connections,
and repeatable effect traces. Configurations are borrowed from the caller so
simulations do not leak signing keys or rely on self-referential allocation.
Its trace digest is stable for repeated Rust runs; it is not a Swift trace digest.

Custom punch transports implement `ivy::punch_transport::{PunchTransport,
PreparedPunch}` and return an ordered `PunchedStream`. Pass the factory to
`ivy::punch_node::run_with_transport`; preparation/connect cancellation and
expected-peer authentication remain under the wrapper and Core. TCP is bundled;
QUIC is not bundled. `Config::with_signature_scheme` supports an explicit
simulation/backend extension; the forgeable `SimulatedSignatureScheme` belongs
only in isolated simulations. Defaults continue to use strict real Ed25519.

Native consumers that can stop draining notifications should use
`ivy::node::run_with_shutdown`, passing a future that resolves on shutdown
(for example, an owned oneshot receiver). It can interrupt a full notification
queue and awaits transport cleanup. Final notifications are best effort;
applications cancel their own content-source jobs as part of stopping. See
[shutdown scope](PORTING.md#native-shutdown-under-backpressure).
