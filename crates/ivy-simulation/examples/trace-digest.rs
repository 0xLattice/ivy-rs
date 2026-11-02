use ivy_core::{core::*, Config};
use ivy_simulation::{SimulatedSignatureScheme, Simulation};
use sha2::{Digest, Sha256};
use std::time::Duration;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let mut sim = Simulation::new(1);
    let configs: Vec<_> = (0..2)
        .map(|i| {
            let c = Config::new(sim.signing_key(i));
            let key = c.peer_key();
            c.with_signature_scheme(SimulatedSignatureScheme::new(key))
        })
        .collect();
    let a = sim.add_node(&configs[0], CoreSettings::default(), None);
    let b = sim.add_node(&configs[1], CoreSettings::default(), None);
    sim.start(a);
    sim.start(b);
    let endpoint = sim.nodes[b].endpoint.clone();
    let request = sim.request(a, Request::Connect(endpoint));
    sim.run_until(Duration::from_secs(120), |sim| {
        sim.nodes[a].results.contains_key(&request)
    });
    for e in &sim.trace {
        let value = match &e.effect {
            Effect::WakeAt(at) => format!("wake {}", at.as_nanos()),
            Effect::Dial(id, p) => format!("dial {id} {} {} {}", p.public_key, p.host, p.port),
            Effect::ResumeReading(id) => format!("resume {id}"),
            Effect::PauseReading(id) => format!("pause {id}"),
            Effect::Write(id, bytes) => format!("write {id} {}", hex(&Sha256::digest(bytes))),
            Effect::PeerConnected(_, p) => format!(
                "connected {} {} {}",
                p.key.hex(),
                hex(&p.session_id),
                p.metadata.max_frame_size
            ),
            Effect::Completed(id, RequestResult::Connected) => format!("completed {id} connected"),
            other => panic!("unsupported fixture effect: {other:?}"),
        };
        println!("{} {} {value}", e.time.as_nanos(), e.node);
    }
    println!("legacy-digest {}", sim.trace_digest());
}
