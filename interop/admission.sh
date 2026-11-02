#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
fixture=crates/ivy-core/tests/fixtures/swift-3.1.1-admission.tsv
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
swift run --package-path interop --force-resolved-versions admission-trace > "$temporary"
python3 - "$temporary" "$fixture" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path('interop/.build/checkouts/Ivy2')
revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
assert revision == 'cc67fa9c4dd9f7566e13a70f9221af6313af88aa', revision
source = pathlib.Path(sys.argv[1]).read_bytes()
fixture = pathlib.Path(sys.argv[2])
files = ['Sources/IvyCore/Core+Connect.swift', 'Sources/IvyCore/Core+Sessions.swift', 'Sources/IvyCore/IvyCore.swift']
fixture.write_bytes(source)
fixture.with_name('swift-3.1.1-admission-provenance.json').write_text(json.dumps({
    'ivy_revision': revision,
    'source_sha256': {p: hashlib.sha256((root/p).read_bytes()).hexdigest() for p in files},
    'harness_sha256': hashlib.sha256(pathlib.Path('interop/Sources/admission-trace/main.swift').read_bytes()).hexdigest(),
    'corpus_sha256': hashlib.sha256(source).hexdigest(),
    'cases': len(source.splitlines()),
    'method': 'Actual unmodified IvyCore with real cryptographic sessions; normalized dial/write/close/connection/request outcomes.'
}, indent=2)+'\n')
PY
cargo test -p ivy-core --test admission_trace --locked
