// Checks the offline preload. Run with `node --import ./tools/offline.mjs --test`.
// The preload is defense in depth; network isolation is enforced by tools/ci/offline-checks.sh.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import workerThreads from 'node:worker_threads';
import { spawn } from 'node:child_process';
import { connect } from 'node:net';
import { Worker } from 'node:worker_threads';
import { Resolver } from 'node:dns';

const offline = { message: /offline: network access is not allowed/ };

test('the offline preload is active', () => {
  assert.equal(globalThis.__RNNET_OFFLINE__, true, 'run tests with --import ./tools/offline.mjs');
});

test('the patched Node network APIs are blocked', () => {
  assert.throws(() => net.connect(443, '192.0.2.1'), offline);
  assert.throws(() => new net.Socket().connect(443, '192.0.2.1'), offline);
  assert.throws(() => tls.connect(443, '192.0.2.1'), offline);
  assert.throws(() => http.get('http://192.0.2.1/'), offline);
  assert.throws(() => https.request('https://192.0.2.1/'), offline);
  assert.throws(() => http2.connect('https://192.0.2.1/'), offline);
  assert.throws(() => dgram.createSocket('udp4'), offline);
  assert.throws(() => fetch('https://192.0.2.1/'), offline);
});

test('DNS module functions and Resolver instances are blocked (RN-NET-01H, F7)', () => {
  assert.throws(() => dns.lookup('example.org', () => {}), offline);
  assert.throws(() => dns.promises.resolve4('example.org'), offline);
  assert.throws(() => new dns.Resolver().resolve4('example.org', () => {}), offline);
  assert.throws(() => new dns.promises.Resolver().resolve4('example.org'), offline);
  assert.throws(() => new dns.Resolver().reverse('192.0.2.1', () => {}), offline);
});

test('native bindings, workers and subprocesses are blocked (RN-NET-01H, F7)', () => {
  assert.throws(() => process.binding('tcp_wrap'), offline);
  assert.throws(() => new workerThreads.Worker('process.exit()', { eval: true }), offline);
  assert.throws(() => childProcess.spawn(process.execPath, ['-e', '0']), offline);
  assert.throws(() => childProcess.execFileSync(process.execPath, ['-e', '0']), offline);
  assert.throws(() => childProcess.fork('./x.mjs'), offline);
});

test('named ES-module imports are blocked too, not only default exports (RN-NET-01H, F7)', () => {
  assert.throws(() => connect(443, '192.0.2.1'), offline);
  assert.throws(() => spawn(process.execPath, ['-e', '0']), offline);
  assert.throws(() => new Worker('process.exit()', { eval: true }), offline);
  assert.throws(() => new Resolver().resolve4('example.org', () => {}), offline);
});
