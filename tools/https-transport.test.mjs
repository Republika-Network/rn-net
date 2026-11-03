// The live HTTPS transport's offline-testable parts: address refusal and the guarded lookup.
// (Its network path is exercised only by the optional live smoke test, never in CI.) Since
// C6-LIVE-ENABLE its response handling is tested over a fake node:https request: redirects, size
// limits on the declared length and on the stream, encodings, the deadline and the peer address.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Buffer } from 'node:buffer';
import { createHttpsTransport, guardedLookup, httpsTransport, isBlockedAddress, makeGuardedLookup, TLS_OPTIONS } from './live/https-transport.mjs';

test('non-public addresses are refused', () => {
  const blocked = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '192.0.2.10', '198.18.0.1', '203.0.113.5', '::1', '::', 'fe80::1', 'fc00::1', 'fd12::3', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2001:db8::1', '64:ff9b::a00:1', 'not-an-ip', '',
    '2002:7f00:1::1', '2001:0:7f00:1::1', '2001:2::1', '2001:10::1', '2001:20::1', '192.88.99.1'];
  for (const address of blocked) assert.equal(isBlockedAddress(address), true, address);
  for (const address of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:1.1.1.1']) {
    assert.equal(isBlockedAddress(address), false, address);
  }
});

test('the guarded lookup refuses a name if any of its addresses is not public (DNS rebinding)', async () => {
  const lookupWith = (addresses) => makeGuardedLookup((host, options, cb) => cb(null, addresses));
  const resolve = (lookup, all) => new Promise((ok) => lookup('rpc.example.org', { all }, (error, address, family) => ok({ error, address, family })));
  const mixed = await resolve(lookupWith([{ address: '1.1.1.1', family: 4 }, { address: '169.254.169.254', family: 4 }]), false);
  assert.equal(mixed.error?.code, 'RNLO_BLOCKED_ADDRESS');
  const empty = await resolve(lookupWith([]), false);
  assert.equal(empty.error?.code, 'RNLO_BLOCKED_ADDRESS');
  const ok = await resolve(lookupWith([{ address: '1.1.1.1', family: 4 }]), false);
  assert.deepEqual([ok.error, ok.address, ok.family], [null, '1.1.1.1', 4]);
  const all = await resolve(lookupWith([{ address: '1.1.1.1', family: 4 }]), true);
  assert.deepEqual(all.address, [{ address: '1.1.1.1', family: 4 }]);
});

test('non-https or credentialed URLs are refused before any connection', async () => {
  for (const url of ['http://example.org/', 'https://u:p@example.org/', 'https://127.0.0.1:8443/', 'https://[::1]/', 'https://8.8.8.8/']) {
    await assert.rejects(() => httpsTransport({ url, body: new Uint8Array(), timeoutMs: 10, maxResponseBytes: 10 }), { code: 'RNLO_BLOCKED_ADDRESS' });
  }
});

/**
 * A fake node:https request: records its options and body; `script(res, req)` drives the response.
 * `peer` is the remote address the socket reports.
 */
function fakeRequest(script, { peer = '93.184.216.34' } = {}) {
  const seen = { options: null, body: null, destroyed: 0, resDestroyed: 0, target: null };
  const request = (target, options, onResponse) => {
    seen.target = target;
    seen.options = options;
    const req = new EventEmitter();
    req.destroy = () => { seen.destroyed += 1; };
    req.end = (body) => {
      seen.body = body;
      const socket = new EventEmitter();
      socket.remoteAddress = peer;
      req.emit('socket', socket);
      setImmediate(() => {
        if (seen.destroyed > 0) return;
        const res = new EventEmitter();
        res.statusCode = 200;
        res.headers = {};
        res.destroy = () => { seen.resDestroyed += 1; };
        script(res, req, onResponse);
      });
    };
    return req;
  };
  return { request, seen };
}
const call = (request, extra = {}) => createHttpsTransport({ request })({ url: 'https://rpc.example.org/x', body: Buffer.from('{}'), timeoutMs: 1000, maxResponseBytes: 16, ...extra });
const respond = (status, headers, chunks) => (res, req, onResponse) => {
  res.statusCode = status;
  res.headers = headers;
  onResponse(res);
  for (const c of chunks) res.emit('data', Buffer.from(c));
  res.emit('end');
};

test('C6-LIVE-ENABLE: every request states TLS verification, the guarded lookup, no agent reuse and identity encoding', async () => {
  const { request, seen } = fakeRequest(respond(200, {}, ['{"a":1}']));
  const out = await call(request);
  assert.deepEqual([out.status, Buffer.from(out.body).toString()], [200, '{"a":1}']);
  assert.ok(out.body instanceof Uint8Array);
  const o = seen.options;
  assert.equal(o.rejectUnauthorized, true);
  assert.equal(o.minVersion, 'TLSv1.2');
  assert.deepEqual(TLS_OPTIONS, { rejectUnauthorized: true, minVersion: 'TLSv1.2' });
  assert.equal(o.servername, 'rpc.example.org');
  assert.equal(o.agent, false);
  assert.equal(o.lookup, guardedLookup);
  assert.equal(o.method, 'POST');
  assert.equal(o.insecureHTTPParser, false);
  assert.equal(o.headers['accept-encoding'], 'identity');
  assert.equal(seen.target.href, 'https://rpc.example.org/x');
});

test('C6-LIVE-ENABLE F4: the declared length and the stream are both bounded; nothing past the limit is kept', async () => {
  // Declared too large: refused before any byte is read.
  const declared = fakeRequest(respond(200, { 'content-length': '17' }, ['x']));
  await assert.rejects(call(declared.request), { code: 'RNLO_RESPONSE_TOO_LARGE' });
  assert.equal(declared.seen.resDestroyed, 1);
  // No length, a stream past the limit: refused at the chunk that crosses it, the stream destroyed.
  let after = 0;
  const streaming = fakeRequest((res, req, onResponse) => {
    onResponse(res);
    res.emit('data', Buffer.alloc(10, 0x61));
    res.emit('data', Buffer.alloc(10, 0x61));
    for (let i = 0; i < 1000; i += 1) { after += 1; res.emit('data', Buffer.alloc(1 << 16, 0x61)); }
    res.emit('end');
  });
  await assert.rejects(call(streaming.request), { code: 'RNLO_RESPONSE_TOO_LARGE' });
  assert.equal(streaming.seen.resDestroyed, 1);
  assert.equal(after, 1000);
  // A lying declared length (smaller than the stream): still bounded by the stream count.
  const lying = fakeRequest(respond(200, { 'content-length': '4' }, ['0123456789', '0123456789']));
  await assert.rejects(call(lying.request), { code: 'RNLO_RESPONSE_TOO_LARGE' });
  // Exactly the limit is accepted.
  const exact = fakeRequest(respond(200, {}, ['0123456789', '012345']));
  assert.equal((await call(exact.request)).body.length, 16);
});

test('C6-LIVE-ENABLE: redirects, compressed bodies, the deadline, a private peer and a refused request all fail closed', async () => {
  for (const status of [301, 302, 307, 308]) {
    const r = fakeRequest(respond(status, { location: 'https://evil.example/' }, []));
    await assert.rejects(call(r.request), { code: 'RNLO_REDIRECT' });
  }
  for (const encoding of ['gzip', 'br', 'deflate', 'GZIP']) {
    const r = fakeRequest(respond(200, { 'content-encoding': encoding }, ['x']));
    await assert.rejects(call(r.request), { code: 'RNLO_CONNECTION' }, encoding);
  }
  const identity = fakeRequest(respond(200, { 'content-encoding': 'identity' }, ['x']));
  assert.equal((await call(identity.request)).body.length, 1);
  const hang = fakeRequest(() => {});
  await assert.rejects(call(hang.request, { timeoutMs: 20 }), { code: 'RNLO_TIMEOUT' });
  assert.ok(hang.seen.destroyed >= 1);
  for (const peer of ['127.0.0.1', '10.0.0.7', '169.254.169.254', '::1', 'fe80::1', '::ffff:192.168.1.1']) {
    const r = fakeRequest(respond(200, {}, ['x']), { peer });
    await assert.rejects(call(r.request), { code: 'RNLO_BLOCKED_ADDRESS' }, peer);
  }
  const thrower = () => { throw new Error('offline'); };
  await assert.rejects(call(thrower), { code: 'RNLO_CONNECTION' });
  const errored = fakeRequest((res, req) => req.emit('error', new Error('ECONNRESET')));
  await assert.rejects(call(errored.request), { code: 'RNLO_CONNECTION' });
  await assert.rejects(call(fakeRequest(() => {}).request, { url: 'not a url' }), { code: 'RNLO_BLOCKED_ADDRESS' });
});
