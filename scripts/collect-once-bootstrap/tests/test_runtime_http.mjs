// Integration test against an already extracted candidate; loopback only, no module mocks.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {syncBuiltinESMExports} from 'node:module';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
assert.equal(process.env.NODE_ENV,'test');
assert.equal(process.env.ALLOW_PRIVATE_NETWORK_FETCH,'true');
let requests=0;
const server=http.createServer((req,res)=>{requests++;res.setHeader('content-type','application/rss+xml');res.end('<rss version="2.0"><channel><title>Fixture</title><item><title>Local</title><link>https://example.invalid/item</link><description>Local fixture</description></item></channel></rss>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const port=server.address().port;
const connect=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...args){
 const options=Array.isArray(args[0])?args[0][0]:args[0];
 assert.equal(typeof options,'object');
 assert.equal(options.host,'127.0.0.1');assert.equal(Number(options.port),port);
 return connect.apply(this,args);
};
syncBuiltinESMExports();
try {
 const {guardedFetch}=await import(pathToFileURL(path.resolve(process.argv[2],'packages/backend/src/lib/http-fetch.ts')));
 const result=await guardedFetch(`http://127.0.0.1:${port}/fixture`,{timeoutMs:5000,maxBytes:4096});
 assert.equal(result.status,200);assert.match(result.text(),/Local fixture/);assert.equal(requests,1);
 await assert.rejects(guardedFetch(`http://127.0.0.1:${port}/fixture`,{timeoutMs:5000,maxBytes:8}),/too large/);
 assert.equal(requests,2);
 console.log(JSON.stringify({real_guarded_fetch:true,real_undici:true,module_mocks:false,external_connections:0,local_requests:requests,size_limit_enforced:true}));
} finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
