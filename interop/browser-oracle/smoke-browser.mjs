const assert = {
 equal(a,b){if(a!==b)throw new Error(`Expected ${a} to equal ${b}`)},
 deepEqual(a,b){const canonical=v=>v instanceof Uint8Array?Array.from(v):Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;if(JSON.stringify(canonical(a))!==JSON.stringify(canonical(b)))throw new Error('Deep equality failed')}
};
import {IvyModule} from './dist/src/core.js';
import {Ivy} from './dist/src/shell.js';
import {memoryPair} from './dist/src/memory.js';
const bytes=await (await fetch('../../target/wasm32-unknown-unknown/release/ivy_wasm.wasm')).arrayBuffer();
const module=await IvyModule.load(bytes);
assert.equal(module.writeHighWaterMark,65536);
let delivered;
const received=new Promise(resolve=>delivered=resolve);
let serverSession;
const server=new Ivy(module,{signingKey:new Uint8Array(32).fill(9),healthEnabled:false},{
  delegate:{deliver(message,peer){delivered({message,peer});}},
  contentSource:{async volume(root){return [{cid:root,data:new Uint8Array(200000).fill(7)}];},async volumeBundle(root){return [root,'child'];}}
});
const client=new Ivy(module,{signingKey:new Uint8Array(32).fill(8),healthEnabled:false},{delegate:{peerConnected(peer){serverSession=peer;}}});
const timeout=setTimeout(()=>{document.querySelector('pre').textContent='FAIL: timeout';throw new Error('browser exchange timeout')},10000);
try {
  await server.start();await client.start();
  server.reportPublicAddress({host:"8.8.2.1",port:55000});
  const [left,right]=memoryPair({capacity:65536,readSize:37});server.accept(right);
  await client.connect({publicKey:server.localID,host:'8.8.2.1',port:4001},left);
  assert.equal(serverSession.key.length,32);
  assert.deepEqual(serverSession.metadata.listenAddresses,[{host:"8.8.2.1",port:4001}]);
  assert.deepEqual(client.connectedPeers,[server.localID]);
  assert.equal(client.connectedPeerEndpoints[0].publicKey,server.localID);
  assert.deepEqual(client.providers('root'),[]);
  const payload=new Uint8Array(200000).fill(5);
  const sent=await client.sendMessage(serverSession,'browser-payload',payload);
  assert.equal(sent.kind,'enqueued');assert.equal(sent.route.kind,'direct');
  const result=await received;assert.equal(result.message.topic,'browser-payload');assert.deepEqual(result.message.payload,payload);
  const volume=await client.fetchVolume('root',{from:serverSession,maximumArchiveBytes:1000000,maximumEntries:10});
  assert.equal(volume.servedBy,server.localID);assert.deepEqual(volume.entries.get('root'),new Uint8Array(200000).fill(7));
  const bundle=await client.fetchVolumeBundle('root',[serverSession]);
  assert.equal(bundle.ended,true);assert.equal(bundle.volumes.length,2);assert.equal(bundle.volumes[1].rootCID,'child');
  assert.equal(await client.disconnectSession(serverSession),true);
  assert.equal(await client.disconnectSession(serverSession),false);
  document.querySelector('pre').textContent='PASS: Browser WebAssembly + WebCrypto + original Ivy shell: authenticated 200KB message, complete Volume/bundle, session disconnect';
} finally {clearTimeout(timeout);await client.destroy();await server.destroy();}
