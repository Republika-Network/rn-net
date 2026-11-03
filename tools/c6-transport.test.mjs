// RN-NET-03B2-C6-LIVE-ENABLE: the narrow C6 transport (tools/compat-live/c6-transport.mjs), over a
// fake base transport. Nothing here reaches the network: the base is injected, and the offline
// preload refuses node:https. This file imports nothing of tools/compat/ (it would join the C6 run
// to the transport); it compares the transport's own provider copy with the reviewed files as data.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  C6_TRANSPORT_ENVIRONMENT,
  C6_TRANSPORT_LIMITS,
  C6_TRANSPORT_PROVIDERS,
  C6_TRANSPORT_REFUSED_ENVIRONMENT,
  C6_TRANSPORT_REFUSED_METHODS,
  checkTransportEnvironment,
  createC6Transport,
} from './compat-live/c6-transport.mjs';

const json = (path) => JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'));
const CLEAN = Object.freeze({ PATH: '/usr/bin', HOME: '/home/founder', LANG: 'C.UTF-8' });
const body = (method, params = []) => Buffer.from(JSON.stringify({ id: 1, jsonrpc: '2.0', method, params }));
const req = (id, extra = {}) => ({ providerId: id, url: C6_TRANSPORT_PROVIDERS.find((p) => p.id === id)?.url, body: body('eth_chainId'), timeoutMs: 10_000, maxResponseBytes: 262_144, ...extra });
const fakeBase = (answer = async () => ({ status: 200, body: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x1"}') })) => {
  const calls = [];
  const base = async (r) => {
    calls.push(r);
    return answer(r);
  };
  return { base, calls };
};

test('the transport copy of the providers is exactly the reviewed manifest and endpoint file', () => {
  const manifest = json('fixtures/compat-c6/manifest.json');
  assert.deepEqual(C6_TRANSPORT_PROVIDERS.map((p) => ({ id: p.id, url: p.url, requests: p.requests })), manifest.providers.map((p) => ({ id: p.id, url: p.url, requests: manifest.budget[p.id] })));
  const config = json('config/rpc-endpoints.json');
  assert.deepEqual(C6_TRANSPORT_PROVIDERS.map((p) => [p.id, p.url]).sort(), config.providers.map((p) => [p.id, p.url]).sort());
  assert.equal(C6_TRANSPORT_LIMITS.totalRequests, manifest.totalRequests);
  assert.equal(C6_TRANSPORT_LIMITS.timeoutMs, manifest.limits.timeoutMs);
  assert.equal(C6_TRANSPORT_LIMITS.maxResponseBytes, manifest.limits.maxResponseBytes);
  assert.equal(C6_TRANSPORT_PROVIDERS.reduce((n, p) => n + p.requests, 0), 22);
  for (const m of ['eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'submit', 'sign', 'wallet_propose']) assert.ok(C6_TRANSPORT_REFUSED_METHODS.includes(m), m);
  assert.ok(!manifest.requests.some((r) => C6_TRANSPORT_REFUSED_METHODS.includes(r.method)));
});

test('no proxy, TLS override, extra CA, preload or Node.js option: the transport is not even built', () => {
  for (const name of C6_TRANSPORT_REFUSED_ENVIRONMENT) {
    for (const spelled of [name, name.toLowerCase()]) {
      for (const value of ['http://127.0.0.1:3128', '0', '']) {
        assert.throws(() => createC6Transport({ env: { ...CLEAN, [spelled]: value }, execArgv: [], base: async () => assert.fail('built') }), { code: C6_TRANSPORT_ENVIRONMENT }, `${spelled}=${value}`);
      }
    }
  }
  for (const option of ['--use-openssl-ca', '--tls-min-v1.0', '--import=./x.mjs', '--inspect', '--require', '--experimental-network-inspection']) {
    assert.throws(() => createC6Transport({ env: CLEAN, execArgv: [option], base: async () => {} }), { code: C6_TRANSPORT_ENVIRONMENT }, option);
  }
  assert.throws(() => checkTransportEnvironment(undefined, []), { code: C6_TRANSPORT_ENVIRONMENT });
  assert.throws(() => checkTransportEnvironment(CLEAN, undefined), { code: C6_TRANSPORT_ENVIRONMENT });
  assert.doesNotThrow(() => checkTransportEnvironment(CLEAN, []));
});

test('only the four reviewed providers at their reviewed URLs, with the manifest limits', async () => {
  const cases = [
    ['unknown provider', { ...req('sepolia-1rpc'), providerId: 'sepolia-other' }],
    ['substituted url', req('sepolia-1rpc', { url: 'https://ethereum-sepolia-rpc.publicnode.com/' })],
    ['trailing slash', req('sepolia-1rpc', { url: 'https://public.1rpc.io/sepolia/' })],
    ['other port', req('xrpl-testnet-ripple', { url: 'https://s.altnet.rippletest.net:51235/' })],
    ['http', req('xrpl-testnet-xrpl-labs', { url: 'http://testnet.xrpl-labs.com/' })],
    ['credentials', req('xrpl-testnet-xrpl-labs', { url: 'https://u:p@testnet.xrpl-labs.com/' })],
    ['an address literal', req('sepolia-1rpc', { url: 'https://127.0.0.1/sepolia' })],
    ['longer deadline', req('sepolia-1rpc', { timeoutMs: 10_001 })],
    ['shorter deadline', req('sepolia-1rpc', { timeoutMs: 1 })],
    ['larger limit', req('sepolia-1rpc', { maxResponseBytes: 262_145 })],
    ['oversized body', req('sepolia-1rpc', { body: Buffer.alloc(4097, 0x20) })],
    ['empty body', req('sepolia-1rpc', { body: Buffer.alloc(0) })],
    ['not bytes', req('sepolia-1rpc', { body: '{}' })],
    ['not JSON', req('sepolia-1rpc', { body: Buffer.from('nope') })],
    ['a batch', req('sepolia-1rpc', { body: Buffer.from('[{"method":"eth_chainId"}]') })],
    ['inherited providerId', Object.create({ providerId: 'sepolia-1rpc' })],
    ['__proto__ provider', { ...req('sepolia-1rpc'), providerId: '__proto__' }],
    ...C6_TRANSPORT_REFUSED_METHODS.map((m) => [`write method ${m}`, req('sepolia-1rpc', { body: body(m, ['0x00']) })]),
  ];
  for (const [label, request] of cases) {
    const { base, calls } = fakeBase();
    const t = createC6Transport({ env: CLEAN, execArgv: [], base });
    await assert.rejects(t(request), { code: 'RNLO_BLOCKED_ADDRESS' }, label);
    assert.equal(calls.length, 0, label);
  }
  // What the base transport sees: the reviewed URL and limits, and a copy of the body.
  const { base, calls } = fakeBase();
  const t = createC6Transport({ env: CLEAN, execArgv: [], base });
  const r = req('xrpl-testnet-ripple', { body: Buffer.from('{"method":"server_info","params":[{"api_version":2}]}') });
  await t(r);
  assert.deepEqual(Object.keys(calls[0]).sort(), ['body', 'maxResponseBytes', 'timeoutMs', 'url']);
  assert.equal(calls[0].url, 'https://s.altnet.rippletest.net:51234/');
  assert.ok(calls[0].body !== r.body && Buffer.from(calls[0].body).equals(r.body));
});

test('at most 22 requests and each provider its own count, failures included: no retry', async () => {
  let fail = true;
  const { base, calls } = fakeBase(async () => {
    if (fail) throw Object.assign(new Error('x'), { code: 'RNLO_TIMEOUT' });
    return { status: 200, body: Buffer.from('{}') };
  });
  const t = createC6Transport({ env: CLEAN, execArgv: [], base });
  // XRPL Labs: 2, the first one failing; a third is refused.
  await assert.rejects(t(req('xrpl-testnet-xrpl-labs')), { code: 'RNLO_TIMEOUT' });
  fail = false;
  await t(req('xrpl-testnet-xrpl-labs'));
  await assert.rejects(t(req('xrpl-testnet-xrpl-labs')), { code: 'RNLO_BLOCKED_ADDRESS' });
  assert.equal(calls.length, 2);
  // Fill every other provider's count: 2 + 9 + 9, then nothing more for anyone.
  for (const [id, n] of [['xrpl-testnet-ripple', 2], ['sepolia-publicnode', 9], ['sepolia-1rpc', 9]]) for (let i = 0; i < n; i += 1) await t(req(id));
  assert.equal(calls.length, 22);
  for (const p of C6_TRANSPORT_PROVIDERS) await assert.rejects(t(req(p.id)), { code: 'RNLO_BLOCKED_ADDRESS' });
  assert.equal(calls.length, 22);
});

test('one request at a time, and the response is bounded and copied', async () => {
  let release;
  const { base, calls } = fakeBase(() => new Promise((ok) => { release = () => ok({ status: 200, body: Buffer.from('{}') }); }));
  const t = createC6Transport({ env: CLEAN, execArgv: [], base });
  const first = t(req('sepolia-1rpc'));
  await assert.rejects(t(req('sepolia-publicnode')), { code: 'RNLO_BLOCKED_ADDRESS' });
  release();
  await first;
  assert.equal(calls.length, 1);
  for (const [label, answer, code] of [
    ['too large', { status: 200, body: Buffer.alloc(262_145) }, 'RNLO_RESPONSE_TOO_LARGE'],
    ['not bytes', { status: 200, body: 'x' }, 'RNLO_CONNECTION'],
    ['no status', { body: Buffer.from('{}') }, 'RNLO_CONNECTION'],
    ['nothing', null, 'RNLO_CONNECTION'],
  ]) {
    const u = createC6Transport({ env: CLEAN, execArgv: [], base: async () => answer });
    await assert.rejects(u(req('sepolia-1rpc')), { code }, label);
  }
  const shared = Buffer.from('{}');
  const v = createC6Transport({ env: CLEAN, execArgv: [], base: async () => ({ status: 200, body: shared }) });
  const out = await v(req('sepolia-1rpc'));
  assert.ok(out.body !== shared && Object.getPrototypeOf(out.body) === Uint8Array.prototype);
});
