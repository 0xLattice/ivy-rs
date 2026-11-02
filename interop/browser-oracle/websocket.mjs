import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {IvyModule} from './dist/src/core.js';
import {Ivy} from './dist/src/shell.js';
import {connectWebSocket} from './dist/src/websocket.js';
const peer=spawn(new URL('../../target/debug/examples/browser_peer',import.meta.url).pathname,[],{stdio:['ignore','pipe','inherit']});
const timeout=setTimeout(()=>{peer.kill();console.error('WebSocket interoperability timed out');process.exit(1)},10000);
let client;
try {
  const ready=await new Promise((resolve,reject)=>{let output='';peer.stdout.on('data',bytes=>{output+=bytes;const match=output.match(/READY (\d+) ([0-9a-f]{64})/);if(match)resolve(match);});peer.on('error',reject);peer.on('exit',code=>reject(new Error(`peer exited ${code}`)));});
  const module=await IvyModule.load(await readFile(new URL('../../target/wasm32-unknown-unknown/release/ivy_wasm.wasm',import.meta.url)));
  let delivered;const received=new Promise(resolve=>delivered=resolve);
  client=new Ivy(module,{signingKey:new Uint8Array(32).fill(8),healthEnabled:false},{delegate:{deliver(message,peer){delivered({message,peer});}}});
  await client.start();
  await client.connect({publicKey:ready[2],host:'127.0.0.1',port:Number(ready[1])},await connectWebSocket(`ws://127.0.0.1:${ready[1]}/ivy`));
  assert.equal((await client.sendMessage(ready[2],'browser-websocket',new Uint8Array(200000).fill(6))).kind,'enqueued');
  const result=await received;assert.equal(result.message.topic,'echo');assert.deepEqual(result.message.payload,new Uint8Array(200000).fill(6));
  console.log('PASS: original browser WebSocketTransport + Rust WASM + native Rust WebSocket, authenticated 200KB echo');
} finally {clearTimeout(timeout);if(client)await client.destroy();peer.kill();}
