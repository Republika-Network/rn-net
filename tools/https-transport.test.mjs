// The live HTTPS transport's offline-testable parts: address refusal and the guarded lookup.
// (Its network path is exercised only by the optional live smoke test, never in CI.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { httpsTransport, isBlockedAddress, makeGuardedLookup } from './live/https-transport.mjs';

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
