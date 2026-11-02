#!/usr/bin/env python3
"""Compare actual host simulation effects; preserve separate legacy debug hashes."""
import hashlib,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
swift=root/'interop/.build/checkouts/Ivy2'
pin=subprocess.check_output(['git','rev-parse','HEAD'],cwd=swift,text=True).strip()
assert pin=='cc67fa9c4dd9f7566e13a70f9221af6313af88aa'
assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=swift,text=True).strip()
def run(command):
    text=subprocess.check_output(command,cwd=root,text=True)
    rows=text.splitlines();assert rows[-1].startswith('legacy-digest ')
    return rows[:-1],rows[-1].split()[1]
a,ad=run(['swift','run','--package-path','interop','--force-resolved-versions','simulation-digest'])
b,bd=run(['cargo','run','--quiet','--locked','-p','ivy-simulation','--example','trace-digest'])
assert a==b, {'swift':a,'rust':b}
payload=('\n'.join(a)+'\n').encode()
paths=['interop/Sources/simulation-digest/main.swift','crates/ivy-simulation/examples/trace-digest.rs','interop/simulation-digest.py']
report={'passed':True,'ivyRevision':pin,'effects':len(a),'semanticSHA256':hashlib.sha256(payload).hexdigest(),'swiftLegacyDigest':ad,'rustLegacyDigest':bd,'normalization':'Exactly one case: peerConnected delivery token is omitted (Swift allocates an internal LinkID, Rust keys links by connection). Effect times, order, dial/connection/request IDs, peer key, session ID, frame limit and SHA256 of all wire bytes compared exactly. Only the fixture effect variants are supported; others fail.','harnessSHA256':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths},'swiftSourceSHA256':{p:hashlib.sha256((swift/p).read_bytes()).hexdigest() for p in ['Sources/IvySimulation/Simulation.swift','Sources/IvyCore/Core+Links.swift','Sources/IvyCore/Core+Sessions.swift']}}
out=root/'crates/ivy-simulation/tests/fixtures'
(out/'swift-3.1.1-host-simulation.tsv').write_bytes(payload)
(out/'swift-3.1.1-host-simulation-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
