# Browser host oracle

`src`, package manifests and `tsconfig.json` are copied without modification from
0xLattice/Ivy2 revision cc67fa9c4dd9f7566e13a70f9221af6313af88aa (3.1.1).
They are an interoperability oracle for the Rust WASM reactor, not a Rust port.
The included MIT license applies to that reference source.

Run `bash interop/browser.sh` from the Rust repository to build the reactor and
execute it through this original host. Tests use Node's WebAssembly and WebCrypto
implementations and the original in-memory browser transport.

The second test uses the original WebSocketTransport over an actual local socket
to the Rust WebSocket peer, with mutual Ivy authentication and a 200 KB echo.
No external STUN server, chain RPC, or application chain is contacted.

For a real browser run, build with `../browser.sh`, serve the ivy-rs repository
root on localhost, and open `/interop/browser-oracle/browser.html`. The page
prints PASS only after authentication, 200 KB messaging, complete Volume and
bundle transfer, and session-specific disconnect all succeed. For live browser
WebSocket coverage, launch `target/debug/examples/browser_peer` and add its
printed `port` and `key` as query parameters to that page. Both paths passed in
the desktop app browser on 2026-11-01. The local server and test tab were closed
after verification. Browser fixture wrappers are authored here; the TypeScript
source in `src` remains the unmodified pinned upstream oracle.
