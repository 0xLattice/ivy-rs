import Foundation
import Crypto
import IvyCore
import Tally
let keys = try (1...3).map { try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: UInt8($0), count:32)) }
let publicKeys = keys.map { $0.publicKey.rawRepresentation.map {String(format:"%02x",$0)}.joined() }
func core(_ capacity:Int,_ reserve:Int = 0) -> IvyCore {
    IvyCore(config:IvyConfig(signingKey:keys[0],stunServers:[],maxConnections:capacity,reservedOutboundConnectionSlots:reserve,maxConnectionsPerNetgroup:1),random:.seeded(1))
}
func endpoint(_ index:Int,_ host:String="8.8.8.8") -> PeerEndpoint { PeerEndpoint(publicKey:publicKeys[index],host:host,port:1234) }
func at(_ seconds:Int64 = 0) -> Timestamp { Timestamp(uptime:.seconds(seconds),unixSeconds:UInt64(1000+seconds)) }
var rows:[String:[String]] = [:]
@discardableResult func apply(_ node:inout IvyCore,_ name:String,_ event:Event,_ time:Int64=0)->[Effect] {
    let effects=node.step(event,now:at(time)); rows[name]=effects.compactMap { effect in
        switch effect {
        case .dial: return "dial"
        case .write: return "write"
        case .peerConnected: return "connected"
        case .close(let id): return "close:\(id.rawValue)"
        case .completed(let id,.connect(let outcome)):
            switch outcome {
            case .connected:return "completed:\(id.rawValue):connected"
            case .cancelled:return "completed:\(id.rawValue):cancelled"
            case .failed(let error):return "completed:\(id.rawValue):\(error)"
            }
        default:return nil
        }
    }.sorted();return effects
}
func dial(_ effects:[Effect])->DialID { effects.compactMap{if case .dial(let id,_)=$0{return id};return nil}.first! }
var a=core(1)
_ = a.step(.start,now:at())
let first=dial(apply(&a,"cancel.reserve",.request(RequestID(1),.connect(endpoint(1)))))
apply(&a,"cancel.caller",.cancel(RequestID(1)))
apply(&a,"cancel.same-peer",.request(RequestID(2),.connect(endpoint(1))))
apply(&a,"cancel.other-peer",.request(RequestID(3),.connect(endpoint(2,"1.1.1.1"))))
apply(&a,"cancel.inbound-blocked",.connectionOpened(ConnectionID(10),direction:.inbound,observedHost:"9.9.9.9",localHost:nil))
apply(&a,"cancel.clock-does-not-release",.tick,100)
apply(&a,"cancel.transport-failed",.dialFailed(first),100)
let next=dial(apply(&a,"restart.reserve",.request(RequestID(4),.connect(endpoint(1))),100))
apply(&a,"restart.stop",.stop,100)
apply(&a,"restart.start",.start,100)
apply(&a,"restart.abandoned-blocks",.request(RequestID(5),.connect(endpoint(1))),100)
apply(&a,"restart.late-success",.connectionOpened(ConnectionID(11),direction:.outbound(next),observedHost:"8.8.8.8",localHost:nil),100)
let disconnected=dial(apply(&a,"disconnect.reserve",.request(RequestID(6),.connect(endpoint(1))),100))
apply(&a,"disconnect.command",.command(.disconnect(PeerID(publicKey:publicKeys[1]))),100)
apply(&a,"disconnect.late-success",.connectionOpened(ConnectionID(12),direction:.outbound(disconnected),observedHost:"8.8.8.8",localHost:nil),100)
var b=core(3);_ = b.step(.start,now:at())
let d1=dial(apply(&b,"observed.reserve-first",.request(RequestID(20),.connect(endpoint(1)))))
apply(&b,"observed.first",.connectionOpened(ConnectionID(20),direction:.outbound(d1),observedHost:"9.9.9.9",localHost:nil))
let d2=dial(apply(&b,"observed.reserve-second",.request(RequestID(21),.connect(endpoint(2,"1.1.1.1")))))
apply(&b,"observed.refuse-second",.connectionOpened(ConnectionID(21),direction:.outbound(d2),observedHost:"9.9.9.9",localHost:nil))
var c=core(3);_ = c.step(.start,now:at())
apply(&c,"supplied.inbound",.connectionOpened(ConnectionID(30),direction:.inbound,observedHost:nil,localHost:nil))
apply(&c,"supplied.duplicate-id",.request(RequestID(30),.connectOver(endpoint(1),ConnectionID(30),observedHost:"8.8.8.8",localHost:nil)))
_ = apply(&c,"supplied.native-reservation",.request(RequestID(31),.connect(endpoint(1))))
apply(&c,"supplied.duplicate-peer",.request(RequestID(32),.connectOver(endpoint(1),ConnectionID(31),observedHost:"8.8.8.8",localHost:nil)))
var d=core(1);_ = d.step(.start,now:at())
_ = apply(&d,"supplied.full-reservation",.request(RequestID(40),.connect(endpoint(1))))
apply(&d,"supplied.full",.request(RequestID(41),.connectOver(endpoint(2,"1.1.1.1"),ConnectionID(40),observedHost:"1.1.1.1",localHost:nil)))

func frame(_ effects:[Effect])->Data {effects.compactMap{if case .write(_,let bytes)=$0{return bytes};return nil}.first!}
var pa=core(2,1)
var pb=IvyCore(config:IvyConfig(signingKey:keys[1],stunServers:[]),random:.seeded(1))
var pc=IvyCore(config:IvyConfig(signingKey:keys[2],stunServers:[]),random:.seeded(1))
_ = pa.step(.start,now:at());_ = pb.step(.start,now:at());_ = pc.step(.start,now:at())
let bd=dial(pb.step(.request(RequestID(50),.connect(endpoint(0))),now:at()))
let bh=frame(pb.step(.connectionOpened(ConnectionID(50),direction:.outbound(bd),observedHost:"8.8.8.8",localHost:nil),now:at()))
apply(&pa,"promotion.inbound-reserved",.connectionOpened(ConnectionID(50),direction:.inbound,observedHost:"9.9.9.9",localHost:nil))
let br=frame(pa.step(.received(ConnectionID(50),bh),now:at()))
let bf=frame(pb.step(.received(ConnectionID(50),br),now:at()))
let ad=dial(pa.step(.request(RequestID(60),.connect(endpoint(2,"1.1.1.1"))),now:at()))
let ah=frame(pa.step(.connectionOpened(ConnectionID(60),direction:.outbound(ad),observedHost:"1.1.1.1",localHost:nil),now:at()))
_ = pc.step(.connectionOpened(ConnectionID(60),direction:.inbound,observedHost:"8.8.8.8",localHost:nil),now:at())
let cr=frame(pc.step(.received(ConnectionID(60),ah),now:at()))
let promoted=apply(&pa,"promotion.outbound-wins",.received(ConnectionID(60),cr))
let token=promoted.compactMap{if case .peerConnected(let token,_)=$0{return token};return nil}.first!
apply(&pa,"promotion.outbound-delivered",.delivered(token))
apply(&pa,"promotion.inbound-refused",.received(ConnectionID(50),bf))
var errors=core(3)
apply(&errors,"errors.stopped",.request(RequestID(80),.connect(endpoint(1))))
apply(&errors,"errors.invalid-before-stopped",.request(RequestID(81),.connect(PeerEndpoint(publicKey:"bad",host:"8.8.8.8",port:1234))))
apply(&errors,"errors.supplied-stopped",.request(RequestID(82),.connectOver(endpoint(1),ConnectionID(80),observedHost:nil,localHost:nil)))
_ = errors.step(.start,now:at())
apply(&errors,"errors.supplied-no-host",.request(RequestID(83),.connectOver(endpoint(1),ConnectionID(81),observedHost:nil,localHost:nil)))
apply(&errors,"errors.supplied-empty-host",.request(RequestID(84),.connectOver(endpoint(1),ConnectionID(82),observedHost:"",localHost:nil)))
apply(&errors,"errors.supplied-invalid-key",.request(RequestID(85),.connectOver(PeerEndpoint(publicKey:"bad",host:"8.8.8.8",port:1234),ConnectionID(83),observedHost:nil,localHost:nil)))
var pinned=IvyCore(config:IvyConfig(signingKey:keys[0],stunServers:[],mode:.pinned(peer:publicKeys[1])),random:.seeded(1))
apply(&pinned,"errors.mode-before-stopped",.request(RequestID(86),.connect(endpoint(2))))
_ = pinned.step(.start,now:at())
apply(&pinned,"errors.mode-before-host",.request(RequestID(87),.connectOver(endpoint(2),ConnectionID(84),observedHost:nil,localHost:nil)))
for name in rows.keys.sorted() { print(name + "\t" + rows[name]!.joined(separator:"|")) }
