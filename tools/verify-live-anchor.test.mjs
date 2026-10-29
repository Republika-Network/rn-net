// The read-only live CLI, driven offline with simulated servers: provider ids only, captures that
// replay to identical reports, replay that never asks for a network transport.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CONFIG_PATH, EXIT, main } from './verify-live-anchor.mjs';
import { COMMITMENT, fakeEvm, fakeXrpl } from '../packages/chain-readonly/test/fake-chains.mjs';

function io(fake, files = {}) {
  const out = { stdout: '', stderr: '', written: new Map(), transportsRequested: 0 };
  out.io = {
    readFile: (path) => {
      if (path === CONFIG_PATH) return new Uint8Array(readFileSync(path));
      if (!Object.hasOwn(files, path) && !out.written.has(path)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return new TextEncoder().encode(files[path] ?? out.written.get(path));
    },
    writeFile: (path, data) => {
      if (out.written.has(path)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      out.written.set(path, new TextDecoder().decode(data));
    },
    stdout: (text) => (out.stdout += text),
    stderr: (text) => (out.stderr += text),
    liveTransport: async () => {
      out.transportsRequested += 1;
      if (!fake) throw new Error('no network in this test');
      return fake.transport;
    },
    now: () => '2026-10-29T00:00:00.000Z',
  };
  return out;
}

test('live XRPL with one configured provider; the capture replays to the same report without a transport', async () => {
  const fake = fakeXrpl();
  const live = io(fake);
  const code = await main(['--network', 'xrpl-testnet', '--tx', fake.hash.toLowerCase(), '--commitment', COMMITMENT, '--rpc', 'xrpl-testnet-ripple', '--capture', 'cap.json'], live.io);
  assert.equal(code, EXIT.PASS);
  const report = JSON.parse(live.stdout);
  assert.equal(report.providers[0].id, 'xrpl-testnet-ripple');
  const capture = JSON.parse(live.written.get('cap.json'));
  assert.equal(capture.providers[0].origin, 'https://s.altnet.rippletest.net:51234');
  assert.equal(capture.retrieval.startedAt, '2026-10-29T00:00:00.000Z');
  assert.ok(!live.stdout.includes('2026-10-29T00:00:00.000Z'), 'the report holds no retrieval time');

  const replay = io(null, { 'cap.json': live.written.get('cap.json') });
  assert.equal(await main(['--offline-replay', 'cap.json', '--commitment', COMMITMENT], replay.io), EXIT.PASS);
  assert.equal(replay.stdout, live.stdout);
  assert.equal(replay.transportsRequested, 0);
});

test('compare-providers uses every configured provider for the network', async () => {
  const fake = fakeEvm();
  const run = io(fake);
  assert.equal(await main(['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--compare-providers'], run.io), EXIT.PASS);
  const report = JSON.parse(run.stdout);
  assert.deepEqual(report.providers.map((p) => p.id), ['sepolia-publicnode', 'sepolia-drpc']);
  assert.equal(report.agreement, 'AGREEMENT');
});

test('exit codes: FAIL, INDETERMINATE, usage and existing files', async () => {
  const notFound = fakeEvm({ notFound: true });
  assert.equal(await main(['--network', 'sepolia', '--tx', notFound.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'], io(notFound).io), EXIT.FAIL);
  const down = fakeEvm({ fail: { eth_chainId: () => { throw Object.assign(new Error('t'), { code: 'RNLO_TIMEOUT' }); } } });
  assert.equal(await main(['--network', 'sepolia', '--tx', down.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'], io(down).io), EXIT.INDETERMINATE);
  const fake = fakeEvm();
  const usage = [
    ['--network', 'mainnet', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'],
    ['--network', 'ethereum', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc', '--compare-providers'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'https://evil.example.org/'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'xrpl-testnet-ripple'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc', '--rpc', 'sepolia-drpc'],
    ['--network', 'sepolia', '--tx', '0x12', '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', 'sha256:x', '--rpc', 'sepolia-drpc'],
    ['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc', '--url', 'https://x.org'],
    ['--offline-replay', 'cap.json', '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc'],
    ['--offline-replay', 'cap.json', '--commitment', COMMITMENT, '--network', 'sepolia'],
  ];
  for (const argv of usage) {
    const run = io(fake);
    assert.equal(await main(argv, run.io), EXIT.USAGE, JSON.stringify(argv));
    assert.equal(run.transportsRequested, 0, JSON.stringify(argv));
  }
  const exists = io(fake);
  exists.written.set('out.json', 'old');
  assert.equal(await main(['--network', 'sepolia', '--tx', fake.hash, '--commitment', COMMITMENT, '--rpc', 'sepolia-drpc', '--output', 'out.json'], exists.io), EXIT.CANNOT_CREATE);
  assert.equal(exists.written.get('out.json'), 'old');
  assert.equal(await main(['--offline-replay', 'missing.json', '--commitment', COMMITMENT], io(null).io), EXIT.NO_INPUT);
});
