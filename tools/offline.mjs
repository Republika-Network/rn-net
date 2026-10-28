// Preloaded into every test process (`node --import ./tools/offline.mjs --test ...`) so that
// any attempt to reach the network fails loudly instead of silently depending on it.
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

export const OFFLINE_MESSAGE = 'offline: network access is not allowed in RN-NET tests';

const deny = (what) =>
  function denied() {
    throw new Error(`${OFFLINE_MESSAGE} (${what})`);
  };

net.Socket.prototype.connect = deny('net.Socket.connect');
net.connect = net.createConnection = deny('net.connect');
tls.connect = deny('tls.connect');
for (const [name, mod] of [['http', http], ['https', https]]) {
  mod.request = deny(`${name}.request`);
  mod.get = deny(`${name}.get`);
}
dgram.createSocket = deny('dgram.createSocket');
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveTxt', 'reverse']) {
  dns[fn] = deny(`dns.${fn}`);
  dns.promises[fn] = deny(`dns.promises.${fn}`);
}
globalThis.fetch = deny('fetch');
if (globalThis.WebSocket) globalThis.WebSocket = deny('WebSocket');
globalThis.__RNNET_OFFLINE__ = true;
