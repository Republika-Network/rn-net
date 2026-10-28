// Preloaded into every test process (`node --import ./tools/offline.mjs --test ...`). It makes
// the common ways a test could reach the network, or start code outside this preload, fail
// loudly.
//
// This is defense in depth, not a sandbox: code inside the process can still find routes this
// file does not patch. Real isolation comes from running the tests in a network namespace
// with no interfaces (tools/ci/offline-checks.sh, used by CI and runnable locally).
import childProcess from 'node:child_process';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import tls from 'node:tls';
import workerThreads from 'node:worker_threads';

export const OFFLINE_MESSAGE = 'offline: network access is not allowed in RN-NET tests';

const deny = (what) =>
  function denied() {
    throw new Error(`${OFFLINE_MESSAGE} (${what})`);
  };

// Sockets, TLS, HTTP and HTTP/2 (which connects through net and tls).
net.Socket.prototype.connect = deny('net.Socket.connect');
net.connect = net.createConnection = deny('net.connect');
tls.connect = deny('tls.connect');
for (const [name, mod] of [['http', http], ['https', https]]) {
  mod.request = deny(`${name}.request`);
  mod.get = deny(`${name}.get`);
}
dgram.createSocket = deny('dgram.createSocket');

// DNS: the module functions and every resolver method, including new Resolver instances.
const isResolverMethod = (name) =>
  name === 'lookup' || name === 'lookupService' || name === 'reverse' || name.startsWith('resolve');
for (const target of [dns, dns.promises, dns.Resolver.prototype, dns.promises.Resolver.prototype]) {
  for (const name of Object.getOwnPropertyNames(target)) {
    if (isResolverMethod(name) && typeof target[name] === 'function') target[name] = deny(`dns ${name}`);
  }
}

// Native bindings reach sockets directly, bypassing every patch above.
process.binding = deny('process.binding');
process._linkedBinding = deny('process._linkedBinding');

// Workers and subprocesses would start without this preload, so they are refused too. The test
// runner itself is unaffected: only the per-file test processes load this preload.
workerThreads.Worker = deny('worker_threads.Worker');
for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  childProcess[name] = deny(`child_process.${name}`);
}

globalThis.fetch = deny('fetch');
if (globalThis.WebSocket) globalThis.WebSocket = deny('WebSocket');

// Patching a built-in's default export does not change its named ES-module exports
// (`import { connect } from 'node:net'`) until they are synchronized.
syncBuiltinESMExports();
globalThis.__RNNET_OFFLINE__ = true;
