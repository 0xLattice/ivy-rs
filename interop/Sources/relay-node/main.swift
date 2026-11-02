import Crypto
import Foundation
import Ivy
import Tally
setvbuf(stdout,nil,_IONBF,0)
func key(_ n:UInt8)->Curve25519.Signing.PrivateKey{try! .init(rawRepresentation:Data(repeating:n,count:32))}
actor Messages {var received:[PeerMessage]=[];var direct:Set<String>=[];func append(_ message:PeerMessage){received.append(message)};func connected(_ peer:AuthenticatedPeer){if peer.route == .direct {direct.insert(peer.key.hex)}}}
final class Echo:IvyDelegate,Sendable {
    let messages=Messages()
    func ivy(_ ivy:Ivy,didConnect peer:AuthenticatedPeer) async {await messages.connected(peer)}
    func ivy(_ ivy:Ivy,didReceiveMessage message:PeerMessage,from peer:AuthenticatedPeer) async {
        if message.topic=="ping"{_ = await ivy.sendMessage(to:peer,topic:"echo",payload:message.payload)}else{await messages.append(message)}
    }
}
extension Ivy {func use(_ delegate:IvyDelegate){self.delegate=delegate}}
let args=CommandLine.arguments
let role=args[1], seed=UInt8(args[2])!, port=UInt16(args[3])!
let carrier=PeerEndpoint(publicKey:IvyConfig(signingKey:key(1)).publicKey,host:"127.0.0.1",port:role=="carrier" ? port:UInt16(args[4])!)
let config=IvyConfig(signingKey:key(seed),listenPort:port,stunServers:[],maxConnectionsPerNetgroup:8,relayEnabled:role=="carrier",carriers:role=="dial" ? [carrier]:[])
let ivy=Ivy(config:config), echo=Echo()
let punching=ProcessInfo.processInfo.environment["IVY_PUNCH"] != nil && role != "carrier"
var punchOptions=PunchConnector.Options();punchOptions.hosts=["127.0.0.1"];punchOptions.allowPrivateCandidates=true
let punch=PunchConnector(ivy:ivy,localKey:config.publicKey,forwardingTo:echo,options:punchOptions)
if punching {await ivy.use(punch)}else{await ivy.use(echo)}
try await ivy.start()
if role=="serve" {try await ivy.connect(to:carrier)}
if role=="dial" {
    for _ in 0..<500 {
        let diagnostics=await ivy.diagnostics
        if diagnostics.outgoingDials==0 && diagnostics.pendingSessions==0 {break}
        try await Task.sleep(nanoseconds:10_000_000)
    }
}
if role != "dial" {print("READY");try await Task.sleep(nanoseconds:90_000_000_000);exit(0)}
let targetKey=IvyConfig(signingKey:key(2)).publicKey
try await ivy.connectViaRelay(to:PeerEndpoint(publicKey:targetKey,host:"relay",port:0))
if punching {
    for _ in 0..<2000 where !(await echo.messages.direct.contains(targetKey)) {try await Task.sleep(nanoseconds:10_000_000)}
    guard await echo.messages.direct.contains(targetKey) else {fatalError("upgrade did not become direct")}
}
let payload=Data(repeating:0x5a,count:200_000)
let sent=await ivy.sendMessage(to:PeerID(publicKey:targetKey),topic:"ping",payload:payload)
if punching {guard case .enqueued(_, .direct)=sent else{fatalError("not direct: \(sent)")}}
else {guard case .enqueued(_, .relayed)=sent else{fatalError("not relayed: \(sent)")}}
for _ in 0..<1000 where await echo.messages.received.isEmpty {try await Task.sleep(nanoseconds:10_000_000)}
guard await echo.messages.received.first?.payload==payload else{fatalError("missing relayed echo")}
await ivy.stop()
print("PASS")
