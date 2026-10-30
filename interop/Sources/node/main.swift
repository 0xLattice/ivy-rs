import Crypto
import Foundation
import Ivy
import Tally

// The Swift side of run.sh. Keys are 32 copies of one byte, used as an
// Ed25519 seed, as in the Rust program.
// The dialer idles past the keepalive timeout, then sends again.
// usage: node listen <keyByte> <port>
//        node dial <keyByte> <port> <peerKeyByte>
//        node keybits
setvbuf(stdout, nil, _IONBF, 0)

func key(_ byte: String) -> Curve25519.Signing.PrivateKey {
    try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: UInt8(byte)!, count: 32))
}

actor Box {
    var echoes: [PeerMessage] = []
    func add(_ message: PeerMessage) { echoes.append(message) }
}

final class Echo: IvyDelegate, Sendable {
    let box = Box()
    func ivy(_ ivy: Ivy, didReceiveMessage message: PeerMessage, from peer: AuthenticatedPeer) async {
        if message.topic == "ping" {
            _ = await ivy.sendMessage(to: peer, topic: "echo", payload: message.payload)
        } else {
            await box.add(message)
        }
    }
}

extension Ivy {
    func use(_ delegate: IvyDelegate) { self.delegate = delegate }
}

func check(_ condition: Bool, _ what: String) {
    print(condition ? "ok   \(what)" : "FAIL \(what)")
    if !condition { exit(1) }
}

let args = CommandLine.arguments
if args[1] == "keybits" {
    // Tally's key work bits for each seed byte, one line each.
    for byte in 0...255 {
        print(KeyDifficulty.trailingZeroBits(of: IvyConfig(signingKey: key(String(byte))).publicKey))
    }
    exit(0)
}
let port = UInt16(args[3])!
// The dialer listens on a port of its own; run.sh never connects to it.
let ivy = Ivy(config: IvyConfig(
    signingKey: key(args[2]),
    listenPort: args[1] == "listen" ? port : port + 1000,
    stunServers: [],
    // Pings every second and drops a peer silent for 3: run.sh idles 5.
    healthConfig: PeerHealthConfig(keepaliveInterval: .seconds(1), staleTimeout: .seconds(3), maxMissedPongs: 2),
    maxConnectionsPerNetgroup: 8))
let echo = Echo()
await ivy.use(echo)
try await ivy.start()

if args[1] == "listen" {
    print("listening")
    try await Task.sleep(nanoseconds: 60_000_000_000)
    exit(0)
}

let peerKey = IvyConfig(signingKey: key(args[4])).publicKey
let peerID = PeerID(publicKey: peerKey)
do {
    try await ivy.connect(to: PeerEndpoint(publicKey: peerKey, host: "127.0.0.1", port: port))
} catch {
    check(false, "session: \(error)")
}
check(await ivy.connectedPeers == [peerID], "session authenticated")

let payload = Data((0..<200_000).map { UInt8($0 & 0xff) })
let sent = await ivy.sendMessage(to: peerID, topic: "ping", payload: payload)
check(sent == .enqueued(endpoint: peerID, route: .direct), "message enqueued")
for _ in 0..<500 where await echo.box.echoes.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
check(await echo.box.echoes.first?.payload == payload, "message echoed back intact")

// The peer answers pings while idle, or this side drops the session.
try await Task.sleep(nanoseconds: 5_000_000_000)
check(await ivy.connectedPeers == [peerID], "session still open after idling")
_ = await ivy.sendMessage(to: peerID, topic: "ping", payload: Data("again".utf8))
for _ in 0..<500 where await echo.box.echoes.count < 2 { try await Task.sleep(nanoseconds: 10_000_000) }
check(await echo.box.echoes.last?.payload == Data("again".utf8), "message echoed after idling")
await ivy.stop()
print("PASS")
exit(0)
