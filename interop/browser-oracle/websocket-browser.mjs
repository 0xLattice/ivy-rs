const assert = {
 equal(a,b){if(a!==b)throw new Error(`Expected ${a} to equal ${b}`)},
 deepEqual(a,b){const canonical=v=>v instanceof Uint8Array?Array.from(v):Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;if(JSON.stringify(canonical(a))!==JSON.stringify(canonical(b)))throw new Error('Deep equality failed')}
};
import {IvyModule} from './dist/src/core.js';
import {Ivy} from './dist/src/shell.js';
import {connectWebSocket} from './dist/src/websocket.js';
const parameters=new URLSearchParams(location.search);
const ready=['',parameters.get('port'),parameters.get('key')];
const timeout=setTimeout(()=>{document.querySelector('pre').textContent='FAIL: timeout';throw new Error('WebSocket interoperability timeout')},10000);
let client;
try {
  const module=await IvyModule.load(await (await fetch('../../target/wasm32-unknown-unknown/release/ivy_wasm.wasm')).arrayBuffer());
  let delivered;const received=new Promise(resolve=>delivered=resolve);
  client=new Ivy(module,{signingKey:new Uint8Array(32).fill(8),healthEnabled:false},{delegate:{deliver(message,peer){delivered({message,peer});}}});
  await client.start();
  await client.connect({publicKey:ready[2],host:'127.0.0.1',port:Number(ready[1])},await connectWebSocket(`ws://127.0.0.1:${ready[1]}/ivy`));
  assert.equal((await client.sendMessage(ready[2],'browser-websocket',new Uint8Array(200000).fill(6))).kind,'enqueued');
  const result=await received;assert.equal(result.message.topic,'echo');assert.deepEqual(result.message.payload,new Uint8Array(200000).fill(6));
  document.querySelector('pre').textContent='PASS: Browser native WebSocket + WebCrypto + Rust WASM + native Rust WebSocket: authenticated 200KB echo';
} finally {clearTimeout(timeout);if(client)await client.destroy();}
