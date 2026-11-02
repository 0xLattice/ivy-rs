import Foundation
import Crypto
import IvyCore
import Tally
let keyA = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating:1,count:32))
let keyB = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating:2,count:32))
let configA = IvyConfig(signingKey:keyA,stunServers:[])
let configB = IvyConfig(signingKey:keyB,stunServers:[])
var a = IvyCore(config:configA,random:.seeded(1))
var b = IvyCore(config:configB,random:.seeded(2))
let now = Timestamp(uptime:.zero,unixSeconds:1000)
_ = a.step(.start,now:now); _ = b.step(.start,now:now)
let connect = a.step(.request(RequestID(1),.connect(PeerEndpoint(publicKey:configB.publicKey,host:"8.8.8.8",port:1234))),now:now)
let dial = connect.compactMap { effect -> DialID? in if case .dial(let id, _) = effect { return id };return nil }.first!
var queue:[(Bool,Event)] = [(false,.connectionOpened(ConnectionID(10),direction:.inbound,observedHost:"8.8.4.4",localHost:nil)),(true,.connectionOpened(ConnectionID(10),direction:.outbound(dial),observedHost:"8.8.8.8",localHost:nil))]
func pump() {
    while !queue.isEmpty {
        let (side,event) = queue.removeFirst()
        let effects = side ? a.step(event,now:now) : b.step(event,now:now)
        for effect in effects {
            switch effect {
            case .write(let id,let bytes):
                print(bytes.map {String(format:"%02x",$0)}.joined())
                queue.append((!side,.received(id,bytes)))
                queue.append((side,.writable(id)))
            case .peerConnected(let token,_),.deliver(let token,_,_): queue.append((side,.delivered(token)))
            case .close: fatalError("unexpected close")
            default: break
            }
        }
    }
}
pump()
queue.append((true,.request(RequestID(2),.send(to:PeerID(publicKey:configB.publicKey),topic:"trace",payload:Data([1,2,3])))))
pump()
