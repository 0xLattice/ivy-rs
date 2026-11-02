import Foundation
import Crypto
import IvyCore
import IvySimulation
let sim = Simulation(seed: 1)
let a = sim.addNode { IvyConfig(signingKey:$0,stunServers:[]) }
let b = sim.addNode { IvyConfig(signingKey:$0,stunServers:[]) }
sim.start(a);sim.start(b)
_ = sim.await(.connect(b.endpoint),on:a)
func hex(_ data:Data)->String {data.map{String(format:"%02x",$0)}.joined()}
for row in sim.trace {
    var value="\(row.time.components.seconds * 1_000_000_000 + row.time.components.attoseconds / 1_000_000_000) \(row.node.index) "
    switch row.effect {
    case .wakeAt(let at):value += "wake \(at.components.seconds * 1_000_000_000 + at.components.attoseconds / 1_000_000_000)"
    case .dial(let id,let p):value += "dial \(id.rawValue) \(p.publicKey) \(p.host) \(p.port)"
    case .resumeReading(let id):value += "resume \(id.rawValue)"
    case .pauseReading(let id):value += "pause \(id.rawValue)"
    case .write(let id,let bytes):value += "write \(id.rawValue) \(hex(Data(SHA256.hash(data:bytes))))"
    case .peerConnected(_,let p):value += "connected \(p.key.hex) \(hex(p.sessionID)) \(p.metadata.maxFrameSize)"
    case .completed(let id,.connect(.connected)):value += "completed \(id.rawValue) connected"
    default:fatalError("unsupported fixture effect: \(row.effect)")
    }
    print(value)
}
print("legacy-digest \(sim.traceDigest)")
