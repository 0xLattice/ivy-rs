# Ivy 3.1.1 Rust coverage

Reference: `0xLattice/Ivy2` revision `cc67fa9c4dd9f7566e13a70f9221af6313af88aa`.
This is an ongoing full platform port, not a completed Ivy replacement.

Implemented:

- Direct event/effect runtime: injected time/entropy, start/stop, connect/send,
  cancellation, handshake deadlines, fragmented framed input, delivery tokens,
  negotiated limits, session replacement by minimum session ID, write high-water
  and reserve accounting, writability waiters, and idle keepalive health.
  Caller request IDs are separate from internal operations. Configured endpoint
  and carrier maintenance uses capped exponential backoff with seeded jitter;
  configured carrier roles are separated from endpoint application authority.
  Inbound decoding charges partial frames and stalls/resumes competing links
  against global budgets. Pinned/private modes gate peers and content exchange.
- Tokio TCP node shell with bounded event channels, acknowledged reads, concurrent
  writes/reads, actual flush generation checks and a five-second native dial
  deadline. Canceled and stopped-run dials retain Core reservations until their
  transport callbacks release them; late sockets close without authentication.
  Supplied streams drive the same core with expected-key authentication; direct
  sessions replace relayed sessions on both ends. A bounded supplied-stream
  channel accepts WebSocket and punch streams.
- Native `ivy-websocket` binary byte-stream adapter: ws/wss, WebPKI TLS roots,
  path-checked upgrades, 10-second upgrade deadlines, 64 KiB outgoing messages,
  binary-only reads and ping/pong handling. Full node authentication and 200 KB
  application delivery are tested. Aggregate inbound WebSocket messages are
  limited to 1 MiB, stricter than Swift's per-frame fragmented-message policy.
- STUN binding request/response codecs, transaction correlation, XOR IPv4/IPv6
  mappings, fingerprint CRC validation, bounded per-source responder rate limits,
  UDP discovery retries and responder. Core public-address events are integrated;
  discovery servers are explicit configuration (empty by default). Handshakes
  advertise external overrides or the discovered public host at the listening
  port, plus the observed local address; this works through TCP, punch and the
  binary host ABI. Explicit legacy Config metadata remains supported.
- IPv4 TCP simultaneous-open sockets sharing their announced local port,
  candidate address filtering, deadline/cancellation and four eagerly accepted
  pre-candidate streams; overflow closes immediately.
  Punch signal codecs cover request/offer/answer/sync/abandon with strict bounds.
  The deterministic coordinator implements offer/answer/sync timing, per-session
  and global attempt limits, stale result tickets, deadlines and exact-session
  signalling authority. `ivy::punch_node` runs automatic upgrades, waits for
  signalling writability, cancels losing work and hands authenticated direct
  streams to Core. `run_with_transport` accepts custom async prepared transports,
  bounds connection futures by the coordinator deadline, and aborts preparation
  on cancellation. Public application request IDs remain separate from its work.
- Core-integrated session-bound complete-Volume/bundle fetches and serving jobs:
  authorization/list/read callbacks, reserved archive budgets across requests,
  source cancellation retaining resource holds until callbacks finish, chunk
  backpressure, and Tally-weighted stride scheduling of contended serving slots.
  Per-request budgets and serving limits are configurable; waiting for a slot
  does not start a content deadline. Exact-session multi-candidate requests
  try candidates sequentially, retain the last session named for duplicate keys,
  wait for transport writability and retain attributed partial bundle results.
  `RetrieveVolume` reads locally under the shared serving reservation, completes
  a concurrent cached-provider connection group, asks those providers, then
  connected fallback peers, then discovered providers. Group members retry bounded
  alternate endpoints; all members settle before content is asked. Candidate
  load/timeout ties are shuffled with the injected entropy. Cancelled local
  reads retain resources until completion. Deficient content reports evict cached
  hints and suppress that peer/root for 30 seconds in a bounded table.
- `ivy-host` implements the complete version-2 local event/effect/configuration
  codec, with signed 64-bit sizes, canonical attosecond durations, ordered peer
  metadata, Unicode-equivalent Volume key rejection, and strict framing. All
  92 pinned Swift vectors round-trip, including every truncation check. The
  stateful adapter drives Core, content callbacks, views and session operations.
- `ivy-wasm` exports the Swift reactor ABI, owns core/config lifetimes, validates
  memory allocations, imports live entropy through WASI `random_get`, and takes
  both clocks explicitly. The unmodified pinned TypeScript host loads it and
  completes authentication, 200 KB message/Volume transfers, bundles, session
  disconnect and a live WebSocket echo against native Rust.
- `ivy-simulation` virtual-clock networks include segmented transport, dial
  partitions, delayed writes, held deliveries, stalled storage jobs, Volumes and
  bundles, controlled ledgers, raw connections, and repeatable effect traces.
  Deterministic real Ed25519 signatures protect the same Core paths as native.
- Swift-compatible seeded SplitMix64 simulation entropy (explicitly non-crypto),
  and a real Swift IvyCore trace fixture for handshake/application record bodies.
- Actual `ivy-tally` adapter to sibling `tally-rs`: authenticated payload traffic
  evidence, signed-malformed-message attribution, served-byte standing debits.
  Transport receipt does not credit useful content.

- Authenticated direct sessions, canonical records, signatures, sequencing,
  negotiated frame limits, TCP stream handshake and cancel-safe framing.
- All 19 current wire message tags: keepalive, discovery, complete Volumes and
  bundles, providers, application messages, and relay envelopes. Retired tags 26
  and 50 remain unknown. General `Connection::send_message/recv_message` exposes
  these messages to an application; `send/recv` remains application-message only.
- Canonical sorted complete-Volume archives, bounded chunk production accounting
  for nested relay/session envelopes, sequential single-Volume/bundle reception.
  Root-first, unique roots, stable metadata, archive lengths, canonical entries,
  and local capacity boundaries are enforced. Content CID/closure validation
  remains the application/content store's responsibility, as in Swift Ivy.
- XOR routing buckets, stable distance ordering, endpoint replacement/removal.
  Iterative alpha=3 discovery waits for all connections and replies in each
  round, merges source-ordered answers, caps rounds at k and replies at 500 ms,
  and correlates exact authenticated sessions. Public routing refresh starts at
  30 seconds and repeats after each completed lookup. Provider walks have their
  own session ceiling and connected-only mode; inbound and provider dials honor
  reserved outbound capacity.
- Live provider announcements and shared per-root discovery walks, cached
  nonconnected-provider fast path, correlated replies, expiration, own-advertisement
  address admission and randomized source/identity/route diversification.
- Provider cache expiry, own-announcement precedence, per-source/global quotas,
  secret-ranked per-root shedding and bounded alternate routes.
- Relay-bound endpoint session handshakes and cross-route replay rejection.
- Carrier relay service: route open/offer/accept/ready, exact participant-session
  authority, opaque packet forwarding, global/per-source route limits, idle
  retirement and backpressure holding the source under charged frame budgets.
- Relay endpoint route opening/installation, exact carrier-session authority,
  virtual endpoint links and route-bound mutual handshakes. Endpoint application
  delivery pauses carrier reads; writability follows carrier flushes; outgoing
  records and complete-Volume chunks account for nested envelopes. Closing a
  carrier or route tears down dependent endpoint sessions.
- Discovered-host routability filtering and netgroups, including special-use
  IPv4/IPv6, mapped addresses, NAT64, and observed private-address admission.

Remaining validation and compatibility limits:

- Core now exposes typed connection refusals for invalid peer keys, pinned-mode
  exclusion, stopped operation and missing supplied-stream observed hosts, using
  Swift's refusal precedence and closing rejected supplied streams. The host
  codec preserves these types. Swift itself deliberately reports
  identityVerificationFailed for certain admission and exhausted supplied/carrier
  handshake failures; the Rust compatibility `Failed` variant retains that meaning. Duplicate
  outbound connections report connectionInProgress, and exhausted direct/relay
  attempts report noRelayAvailable. Duplicate request IDs preserve the original
  result shape; invalid peer commands are no-ops. Host duration
  bytes retain attoseconds, while Rust runtime timers truncate to nanoseconds.
- Competing admission now reserves canceled native dials until shell completion,
  including stop/restart and callbacks arriving after cancellation. Content groups
  continue following those attempts until their reservations release. Pending
  outgoing reservations count against inbound, global and direct-netgroup capacity;
  supplied and relay streams use those same admission budgets. Direct bind failure
  cannot bypass admission via endpoint relay fallback. Session promotion rechecks
  authenticated capacity and observed netgroups, preserving direct/session-ID tie
  breaks. A verified competing responder holds disconnect notification until it
  either establishes a replacement or fails. The pinned Swift admission oracle
  checks 37 event phases, including a reserved outbound session winning while an
  earlier inbound handshake is pending. Broader scheduling matrices remain useful.
  Failed outbound attempts wait for an already verified inbound handshake and
  resolve on its success/closure/timeout. Configured peers and provider groups
  exhaust their direct routes before relay fallback and reconnect backoff.
- Discovery now balances alternate routes across referral sources, prefers
  authenticated endpoints, retries direct alternatives before relay, and permits
  one readmission of a timed-out identity when a new route arrives. Broader Swift
  differential traces are still needed for discovery and admission policy edges.
- The complete local/cached-provider/connected-fallback/DHT Volume stage order,
  direct-route exhaustion before relay fallback and connection-group barrier
  are implemented. The standalone `VolumeReceiver` has no identity
  context; callers outside Core must supply their own session binding/budgets.
- Full serving admission parity: current server bounds queued requests using the
  configured global/per-peer limits; Swift queues serving tickets without these
  extra ceilings. Source job and archive limits match the implemented core path.
- Relay connection policy: direct-to-relay fallback uses configured carriers
  followed by explicitly marked relaying endpoint peers. Configured-carrier roles
  and pinned-mode admission and supplied-stream upgrades from relayed to direct
  are implemented. Configured restart recycles only an existing configured
  session and uses its normal reconnect schedule; unrelated peers are untouched.
- `ivy-simulation` provides virtual-clock networks, deterministic real signing,
  segmentation, dial partitions, delayed writes, delivery/storage holds, ledger
  controls, raw connections and repeatable traces. The explicit forgeable
  simulation scheme matches Swift; a generated Swift transcript compares all
  handshake/data bytes, signatures and session IDs without normalization.
  A real host-simulation differential now compares twelve ordered effects from
  startup through outbound connect completion: exact virtual times, transport IDs,
  peer/session identity, frame limits and hashes of every handshake frame. It caught
  and fixed resume-before-hello effect ordering. It omits the peerConnected delivery
  token because Swift allocates a separate internal LinkID, while Rust keys links
  by connection. Both original debug digests are retained and differ: Swift uses
  reflection strings and Rust uses Debug strings. They are not a portable protocol
  or interchangeable cross-runtime digest. Broader host-simulation scenarios and
  an agreed portable all-effect trace format remain unimplemented. Reproduce with
  `python3 interop/simulation-digest.py`; the comparator rejects unsupported effects.
  The same original TypeScript shell also passed in the actual desktop browser:
  WebAssembly/WebCrypto authentication, 200 KB message and Volume/bundle transfer,
  exact-session disconnect, and native browser WebSocket to Rust echo.
  Cross-browser engine coverage remains. The interoperability oracle
  uses the original TypeScript shell; it is not a newly ported Rust browser UI.
  Native PunchConnector supplies TCP by default and supports custom prepared
  stream transports through `PunchTransport`; no QUIC implementation is bundled.
  The pure `ivy-core` crate already compiles for `wasm32-unknown-unknown`.
  Deterministic two-node event tests already cover direct lifecycle and transport.
- Standalone CI/package publication needs a published, pinned sibling `tally-rs`
  dependency and matching checkout layout. The local workspace uses the actual
  sibling implementation.
- Broader Swift behavioral differential traces and relevant lattice-formal gates.
  The seeded direct trace compares bodies exactly, normalizing signature bytes
  and their derived session IDs because macOS CryptoKit randomizes Ed25519
  signatures. This does not weaken cryptographic verification in either runtime.

Verification:

The existing `lattice-formal` checkout was inspected for Ivy/session/provider
models. Its current chain/work/Merkle models do not validate Ivy networking; no
networking formal-proof claim is made. Dedicated event/budget invariants remain
part of the full-port validation work.

- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
- `python3 interop/generate-message-fixtures.py ../Ivy2` regenerates fixtures by
  executing the pinned Swift Message.swift and MessageLimits.swift directly.
  Minimal harness types supply config constants and raw key storage. This is a
  wire codec oracle, not evidence for crypto policy or core-state behavior.
- The fixture test covers every tag, all truncations, extra trailing data, and
  frame limits. Volume tests cover order, capacity attribution, inconsistent
  metadata, duplicate roots, and premature bundle endings.
- `bash interop/run.sh` checks real TCP Swift/Rust pairings, wrong-key refusal,
  and 256 key-work vectors.
- `bash interop/relay.sh` exercises real TCP triangles with mixed Swift/Rust
  carriers and endpoint initiator/responder implementations. The deterministic
  three-node test also sends complete bundles at minimum negotiated frame size,
  holds carrier backpressure, expires routes and upgrades relay sessions to direct.
- `IVY_PUNCH=1 bash interop/relay.sh` runs those four mixed-runtime triangles
  with automatic punch upgrades, requiring a direct session before the 200 KB
  echo. The native three-node regression covers this path and clean shutdown.
- `bash interop/browser.sh` builds the release Rust reactor and executes it with
  the unmodified Ivy2 Web host. It verifies complete content and a live native
  WebSocket connection using Node's standard WebSocket/WebCrypto APIs.

Known preexisting interoperability policies remain: metadata hosts are ASCII
only; Rust uses strict Ed25519 verification and refuses small-order keys accepted
by some Swift/Linux crypto backends.

Regenerate the direct core fixture with `swift run --package-path interop core-trace > crates/ivy-core/tests/fixtures/swift-3.1.1-core-trace.hex`.

Regenerate the exact simulated-signature core fixture with `swift run --package-path interop simulation-trace > crates/ivy-simulation/tests/fixtures/swift-3.1.1-simulation-trace.hex`. Its Rust regression compares the entire transcript, including signatures and derived session IDs; the forgeable scheme is only enabled explicitly for simulation.

Regenerate admission behavior evidence and its source/corpus hashes with `bash interop/admission.sh`. The regression compares dial/write/close/connection/result effects, ignoring timer and internal ID allocation differences; it uses the pinned real Swift core and cryptographic handshakes.

## Native shutdown under backpressure

`node::run_with_shutdown` adds an independent future that can resolve while the
bounded application notification channel is full. It then stops the core and
aborts and awaits all owned TCP/dial/STUN tasks. The existing `run` and
`run_with_supplied` entry points retain their signatures. During teardown,
notifications are best effort rather than a barrier to closing sockets. A normal
`Event::Stop` still requires the consumer to drain preceding notifications;
applications that may stop draining should use the independent shutdown future.
Content-source tasks belong to the application and must be cancelled by its
shutdown path, not depend on receiving a final `CancelJob` notification.

Two real TCP tests cover an active handshake with a full notification queue and
shutdown's own cancellation completions with an already full queue. The serving
reservation regression now covers disconnect, Stop and expired read deadline;
all retain the archive/job budget until the cancelled source callback returns,
and duplicate late callbacks cannot release it twice.

Source audit against pinned Swift `Ivy/Ivy.swift` (`stopNow`) confirms shutdown
cancels its timer, address discovery and owned content tasks independently of
notification consumption. `IvyCore/Core+Serving.swift` (`beginVolumeRead`) starts
the serving timer at the volume read; Rust preserves that behavior. Queued,
bundle-listing and authorization tasks do not gain an invented timeout. The
bounded Rust admission ceilings remain an explicit resource-policy difference
from Swift's unbounded ticket queue. This audit and finite tests do not establish
every scheduling interleaving; the new shutdown API is a Rust ownership seam,
not a Swift ABI equivalent.

### Provider membership snapshots for hosted platforms

The additive core `ProviderMemberships` request returns identities and maximum
live cache expiration per identity without a DHT walk. Lattice node uses this to
match Swift's live `providers(for:)` hosting membership while preserving expiry;
endpoint-only discovery results are not treated as perpetual host claims.
The actual provider round test checks both the live snapshot and removal exactly
at expiry. This is a local Rust API addition; Ivy wire messages are unchanged.
