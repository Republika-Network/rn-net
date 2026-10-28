// Proves that the test run is offline. Run with `node --import ./tools/offline.mjs --test`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

const offline = { message: /offline: network access is not allowed/ };

test('the offline preload is active', () => {
  assert.equal(globalThis.__RNNET_OFFLINE__, true, 'run tests with --import ./tools/offline.mjs');
});

test('every network entry point is blocked', async () => {
  assert.throws(() => net.connect(443, '192.0.2.1'), offline);
  assert.throws(() => new net.Socket().connect(443, '192.0.2.1'), offline);
  assert.throws(() => tls.connect(443, '192.0.2.1'), offline);
  assert.throws(() => http.get('http://192.0.2.1/'), offline);
  assert.throws(() => https.request('https://192.0.2.1/'), offline);
  assert.throws(() => dns.lookup('example.org', () => {}), offline);
  assert.throws(() => dns.promises.resolve4('example.org'), offline);
  assert.throws(() => fetch('https://192.0.2.1/'), offline);
});
