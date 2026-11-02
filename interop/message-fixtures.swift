import Foundation
struct PeerKey { let rawRepresentation: Data; init(rawRepresentation: Data) throws { self.rawRepresentation = rawRepresentation } }
struct SessionWireRecord { static let dataRecordOverhead = 113 }
struct IvyConfig { static let defaultProtocolMaxFrameSize: UInt32 = 4 * 1024 * 1024 }
func validUTF8String(_ data: Data) -> String? { String(data: data, encoding: .utf8) }
let key = try! PeerKey(rawRepresentation: Data(hexString: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")!)
let endpoint = PeerEndpoint(publicKey: "ed01abcd", host: "127.0.0.1", port: 9999)
let messages: [Message] = [
 .ping(nonce: 7), .pong(nonce: UInt64.max), .findNode(target: Data(repeating: 3, count: 32), nonce: 11), .neighbors([endpoint], nonce: 12),
 .volumeRequest(requestID: 1, rootCID: "root"), .volumeChunk(requestID: 2, rootCID: "root", index: 0, count: 1, totalEntries: 1, totalBytes: 3, payload: Data([1,2,3])),
 .volumeBundleRequest(requestID: 3, rootCID: "root"), .volumeBundleEnd(requestID: 3), .findProviders(rootCID: "root", requestID: 4),
 .providers(rootCID: "root", requestID: 5, records: [ProviderRecord(endpoint: endpoint, expiresAt: 999)]), .announceProvider(rootCID: "root", expiresAt: 1000),
 .peerMessage(topic: "héllo", payload: Data([0,255])), .contentUnavailable(requestID: 6),
 .relayOpen(routeID: Data(repeating: 4, count: 32), targetKey: key), .relayOffer(routeID: Data(repeating: 4, count: 32), sourceKey: key),
 .relayAccept(routeID: Data(repeating: 4, count: 32), status: 2), .relayReady(routeID: Data(repeating: 4, count: 32), status: 0),
 .relayPacket(routeID: Data(repeating: 4, count: 32), opaqueEndpointRecord: Data([1,2,3])), .relayClose(routeID: Data(repeating: 4, count: 32))]
for message in messages { let bytes = message.serialize(); precondition(!bytes.isEmpty); precondition(Message.deserialize(bytes) != nil); print(bytes.map { String(format:"%02x", $0) }.joined()) }
