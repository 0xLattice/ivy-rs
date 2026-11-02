#!/usr/bin/env python3
"""Execute pinned Swift wire sources (supply Ivy2 checkout as argument).
The small harness stubs configuration constants and raw key storage only;
cryptographic session interoperability is checked separately by run.sh.
"""
from pathlib import Path
import subprocess, sys, tempfile
root = Path(sys.argv[1])
revision = subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
if revision != 'cc67fa9c4dd9f7566e13a70f9221af6313af88aa':
    raise SystemExit('expected pinned Ivy 3.1.1 revision, got '+revision)
here = Path(__file__).resolve().parent
source = root / 'Sources/IvyCore'
text = '\n'.join((source / f).read_text() for f in ['MessageLimits.swift','Message.swift'])
text += '\n' + (here / 'message-fixtures.swift').read_text()
with tempfile.TemporaryDirectory() as directory:
    script = Path(directory) / 'main.swift'
    script.write_text(text)
    output = subprocess.check_output(['swift',str(script)])
(here.parent/'crates/ivy-core/tests/fixtures/swift-3.1.1-messages.hex').write_bytes(output)
