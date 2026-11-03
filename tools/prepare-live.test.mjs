// RN-NET-03B2-C3: the controlled live preparation entry point (tools/prepare/), against simulated
// providers only. Every transport here is injected and synthetic: nothing reaches a network, and the
// command line itself refuses (RNPL_LIVE_DISABLED) before reading anything.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { chmodSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { PREPARATION_REQUESTS, requestBytes } from '../packages/chain-readonly/src/index.mjs';
import { intentDigest, makeIntent, XRPL } from '../packages/tx-intent/src/index.mjs';
import { prepareSepoliaIntent, prepareXrplIntent } from '../packages/tx-prepare/src/index.mjs';
import {
  COMMITMENT,
  fakeTransport,
  NOW,
  SEPOLIA_FROM,
  sepoliaProviders,
  sepoliaServer,
  XRPL_ACCOUNT,
  XRPL_SIGNING_PUB_KEY,
  xrplProviders,
  xrplServer,
} from '../packages/tx-prepare/test/fake-providers.mjs';
import { readPreparationAuthorization } from './prepare/authorization.mjs';
import { AGREED_EVIDENCE_DIR, GENESIS_COMMITMENT, PrepareEntryCode, REVIEWED_PREPARATION_PROVIDERS, SEPOLIA_COMPATIBILITY } from './prepare/entry.mjs';
import { PREPARATION_EVIDENCE_FORMAT } from './prepare/evidence.mjs';
import { createPreparationPolicy, PREPARATION_RUN_REQUESTS } from './prepare/policy.mjs';
import { LIVE_NETWORK_ACCESS, main, PREPARE_EXIT, PREPARE_FLAGS, prepareLive, xrplWindow } from './prepare/prepare-live.mjs';
import { REVIEWED_PROVIDERS } from './submit/entry.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const X = 'xrpl:testnet';
const S = 'evm:11155111';
const [XA, XB] = xrplProviders();
const [SA, SB] = sepoliaProviders();
const REVIEWED = [XA, XB, SA, SB];
const ENDPOINTS = { format: 'rnnet.rpc-endpoints.v1', providers: REVIEWED.map(({ id, network, url, operator }) => ({ id, network, url, operator })) };
const RECORDED = { [SA.id]: { eip1898AccountReads: true, estimateGasBlockHash: true }, [SB.id]: { eip1898AccountReads: true, estimateGasBlockHash: true } };
const iso = (seconds) => `${new Date(seconds * 1000).toISOString().slice(0, 19)}Z`;

function authorization(network, overrides = {}) {
  const base = network === X
    ? { network: X, providerIds: [XA.id, XB.id], sender: XRPL_ACCOUNT, signingPubKey: XRPL_SIGNING_PUB_KEY, requestBudget: 4 }
    : { network: S, providerIds: [SA.id, SB.id], sender: SEPOLIA_FROM, signingPubKey: null, requestBudget: 16 };
  return {
    format: 'rnnet.preparation-authorization.v1',
    authorizationId: 'prep-1',
    purpose: 'genesis-proof-01',
    commitment: COMMITMENT,
    notAfter: iso(NOW + 1800),
    scope: 'Synthetic test: one read-only preparation run against simulated providers.',
    ...base,
    ...overrides,
  };
}

function privateDir() {
  const dir = mkdtempSync(join(tmpdir(), 'rnnet-prepare-'));
  chmodSync(dir, 0o700);
  return dir;
}

/** One run's argv and deps. `servers` are simulated providers; `approve` answers correctly unless replaced. */
function run(network, { auth = authorization(network), servers, evidenceDir = privateDir(), deps = {}, argv } = {}) {
  const text = typeof auth === 'string' ? auth : `${canonicalize(auth)}\n`;
  const files = { '/f/authorization.json': text, '/f/endpoints.json': JSON.stringify(ENDPOINTS) };
  const transport = fakeTransport(servers ?? (network === X
    ? { [XA.id]: xrplServer(), [XB.id]: xrplServer({ seq: 5_000_001 }) }
    : { [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_185 }) }));
  const prompts = [];
  let digest = null;
  try {
    digest = readPreparationAuthorization(text).digest;
  } catch {
    // a malformed authorization: the run refuses before any approval
  }
  const full = {
    readText: (path) => {
      if (!Object.hasOwn(files, path)) throw new Error(`no file ${path}`);
      return files[path];
    },
    transport,
    now: () => NOW,
    approve: async (prompt) => {
      prompts.push(prompt);
      return `${network} ${digest.slice(-16)}`;
    },
    agreed: evidenceDir,
    reviewed: REVIEWED,
    compatibility: RECORDED,
    ...deps,
  };
  const args = argv ?? ['--network', network, '--authorization', '/f/authorization.json', '--endpoints', '/f/endpoints.json', '--evidence-dir', evidenceDir];
  return { promise: prepareLive({ argv: args, deps: full }), transport, prompts, evidenceDir };
}

const refusedWith = async (r, code) => {
  const out = await r.promise;
  assert.equal(out.outcome, 'REFUSED', out.message);
  assert.equal(out.code, code, out.message);
  assert.equal(out.exitCode, PREPARE_EXIT.REFUSED);
  return out;
};

test('live network access is disabled: the command line refuses before reading anything', () => {
  assert.equal(LIVE_NETWORK_ACCESS, false);
  assert.equal(AGREED_EVIDENCE_DIR, null);
  for (const record of Object.values(SEPOLIA_COMPATIBILITY)) assert.deepEqual({ ...record }, { eip1898AccountReads: null, estimateGasBlockHash: null });
  assert.deepEqual(PREPARE_FLAGS, ['network', 'authorization', 'endpoints', 'evidence-dir']);
  const writes = [];
  const original = process.stderr.write;
  process.stderr.write = (text) => writes.push(text);
  try {
    assert.equal(main(), PREPARE_EXIT.LIVE_DISABLED);
  } finally {
    process.stderr.write = original;
  }
  assert.match(writes.join(''), /RNPL_LIVE_DISABLED/);
  // As a command (a subprocess) it is checked by tools/broadcast/live-disabled.check.mjs, run by
  // tools/ci/offline-checks.sh: the test preload refuses subprocesses.
});

test('the reviewed providers and the Genesis commitment are pinned to the repository', () => {
  const config = JSON.parse(readFileSync(join(ROOT, 'config/rpc-endpoints.json'), 'utf8'));
  assert.deepEqual(REVIEWED_PREPARATION_PROVIDERS.map((p) => ({ ...p })), config.providers.map(({ id, network, url, operator }) => ({ id, network, url, operator })));
  assert.deepEqual(REVIEWED_PREPARATION_PROVIDERS.map(({ id, network, url }) => ({ id, network, url })), REVIEWED_PROVIDERS.map((p) => ({ ...p })));
  const golden = JSON.parse(readFileSync(join(ROOT, 'fixtures/genesis-proof-01/golden.json'), 'utf8'));
  assert.equal(GENESIS_COMMITMENT, golden.envelope.commitment);
  assert.equal(GENESIS_COMMITMENT, COMMITMENT);
  assert.deepEqual(PREPARATION_RUN_REQUESTS, { [X]: 4, [S]: 16 });
  assert.deepEqual(Object.keys(SEPOLIA_COMPATIBILITY).sort(), ['sepolia-1rpc', 'sepolia-publicnode']);
});

test('XRPL: one approved run reads exactly 4 times and writes the intent, bound to + 80, privately', async () => {
  const r = run(X);
  const out = await r.promise;
  assert.equal(out.outcome, 'PREPARED', out.message);
  assert.equal(out.exitCode, 0);
  assert.equal(r.prompts.length, 1);
  assert.match(r.prompts[0], /exactly 4 requests/);
  assert.equal(r.transport.exchanges.length, 4);
  assert.equal(out.intent.transaction.LastLedgerSequence, 5_000_000 + 80);
  assert.equal(XRPL.lastLedgerOffset, 80);
  // The same intent and digest as the library gives on the same answers.
  const direct = await prepareXrplIntent({ commitment: COMMITMENT, account: XRPL_ACCOUNT, signingPubKey: XRPL_SIGNING_PUB_KEY, providers: [XA, XB], now: NOW, transport: fakeTransport({ [XA.id]: xrplServer(), [XB.id]: xrplServer({ seq: 5_000_001 }) }) });
  assert.equal(out.intentDigest, direct.digest);
  assert.deepEqual(xrplWindow(out.intent), { lastLedgerSequence: 5_000_080, voidAtLedger: 5_000_076, fromLedger: 5_000_000, usableLedgers: 76, usableSeconds: [228, 380] });
  // Evidence: one private run directory, private files, the intent as canonical JSON.
  const dir = join(r.evidenceDir, 'prep-1');
  assert.equal(lstatSync(dir).mode & 0o777, 0o700);
  const names = readdirSync(dir).sort();
  assert.deepEqual(names, ['evidence.json', 'intent.json', 'response-01.bin', 'response-02.bin', 'response-03.bin', 'response-04.bin']);
  for (const name of names) assert.equal(lstatSync(join(dir, name)).mode & 0o777, 0o600, name);
  const intentText = readFileSync(join(dir, 'intent.json'), 'utf8');
  assert.equal(intentText, `${canonicalize(out.intent)}\n`);
  assert.equal(intentDigest(makeIntent(JSON.parse(intentText))), out.intentDigest);
  const evidence = JSON.parse(readFileSync(join(dir, 'evidence.json'), 'utf8'));
  assert.equal(evidence.format, PREPARATION_EVIDENCE_FORMAT);
  assert.equal(evidence.outcome, 'PREPARED');
  assert.equal(evidence.requestCount, 4);
  assert.equal(evidence.intentDigest, out.intentDigest);
  assert.equal(evidence.authorizationDigest, readPreparationAuthorization(`${canonicalize(authorization(X))}\n`).digest);
  for (const [i, e] of evidence.exchanges.entries()) {
    assert.equal(e.request, r.transport.exchanges[i].request);
    assert.equal(readFileSync(join(dir, e.responseFile), 'utf8'), r.transport.exchanges[i].response.body);
  }
  rmSync(r.evidenceDir, { recursive: true });
});

test('Sepolia: with compatibility recorded, exactly 16 reads, all account reads pinned to one hash', async () => {
  const r = run(S);
  const out = await r.promise;
  assert.equal(out.outcome, 'PREPARED', out.message);
  assert.equal(r.transport.exchanges.length, 16);
  const pinned = r.transport.exchanges.map((e) => JSON.parse(e.request)).filter((b) => ['eth_getBalance', 'eth_getCode', 'eth_estimateGas'].includes(b.method) || (b.method === 'eth_getTransactionCount' && b.params[1] !== 'pending'));
  assert.equal(pinned.length, 8);
  assert.equal(new Set(pinned.map((b) => JSON.stringify(b.params[1]))).size, 1);
  assert.deepEqual(Object.keys(pinned[0].params[1]).sort(), ['blockHash', 'requireCanonical']);
  const direct = await prepareSepoliaIntent({ commitment: COMMITMENT, from: SEPOLIA_FROM, providers: [SA, SB], now: NOW, transport: fakeTransport({ [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_185 }) }) });
  assert.equal(out.intentDigest, direct.digest);
  rmSync(r.evidenceDir, { recursive: true });
});

test('Sepolia: BLOCKED before any read until C6 records block-hash support on both providers', async () => {
  for (const [compatibility, blocked, providerId] of [
    [SEPOLIA_COMPATIBILITY, 'BLOCK_HASH_READ_REFUSED', 'sepolia-publicnode'],
    [{ ...RECORDED, [SB.id]: { eip1898AccountReads: true, estimateGasBlockHash: null } }, 'GAS_ESTIMATION_UNAVAILABLE', SB.id],
    [{ ...RECORDED, [SA.id]: { eip1898AccountReads: true, estimateGasBlockHash: false } }, 'GAS_ESTIMATION_UNAVAILABLE', SA.id],
    [{ ...RECORDED, [SB.id]: { eip1898AccountReads: false, estimateGasBlockHash: true } }, 'BLOCK_HASH_READ_REFUSED', SB.id],
  ]) {
    // The reviewed table names the real providers; the synthetic run names fixture ones.
    const auth = compatibility === SEPOLIA_COMPATIBILITY ? authorization(S, { providerIds: ['sepolia-publicnode', 'sepolia-1rpc'] }) : authorization(S);
    const deps = compatibility === SEPOLIA_COMPATIBILITY ? { compatibility, reviewed: REVIEWED_PREPARATION_PROVIDERS } : { compatibility };
    const r = run(S, { auth, deps });
    if (compatibility === SEPOLIA_COMPATIBILITY) {
      r.promise = prepareLive({ argv: ['--network', S, '--authorization', '/f/a', '--endpoints', '/f/e', '--evidence-dir', r.evidenceDir], deps: {
        readText: (p) => (p === '/f/a' ? `${canonicalize(auth)}\n` : readFileSync(join(ROOT, 'config/rpc-endpoints.json'), 'utf8')),
        transport: r.transport, now: () => NOW, approve: async () => assert.fail('no approval is asked'), agreed: r.evidenceDir, ...deps,
      } });
    }
    const out = await r.promise;
    assert.equal(out.outcome, 'BLOCKED', out.message);
    assert.equal(out.exitCode, PREPARE_EXIT.BLOCKED);
    assert.equal(out.code, PrepareEntryCode.COMPATIBILITY_UNRECORDED);
    assert.equal(out.blocked, blocked);
    assert.equal(out.providerId, providerId);
    assert.equal(r.transport.exchanges.length, 0);
    assert.equal(r.prompts.length, 0);
    assert.deepEqual(readdirSync(r.evidenceDir), []);
    assert.match(out.message, /Do not retry another way/);
    rmSync(r.evidenceDir, { recursive: true });
  }
});

test('Sepolia: a provider that refuses a pinned read BLOCKS the run, with evidence and no fallback', async () => {
  for (const [servers, blocked, providerId, sent] of [
    [{ [SA.id]: sepoliaServer({ eip1898: false }), [SB.id]: sepoliaServer({ number: 9_437_185 }) }, 'BLOCK_HASH_READ_REFUSED', SA.id, 7],
    [{ [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_185, estimateGasBlockHash: false }) }, 'GAS_ESTIMATION_UNAVAILABLE', SB.id, 16],
  ]) {
    const r = run(S, { servers });
    const out = await r.promise;
    assert.equal(out.outcome, 'BLOCKED', out.message);
    assert.equal(out.code, 'RNTP_PROVIDER_ERROR');
    assert.equal(out.blocked, blocked);
    assert.equal(out.providerId, providerId);
    assert.equal(out.exitCode, PREPARE_EXIT.BLOCKED);
    assert.equal(r.transport.exchanges.length, sent);
    // No unpinned account read was ever sent, by number, tag or omission.
    for (const e of r.transport.exchanges) {
      const { method, params } = JSON.parse(e.request);
      if (['eth_getBalance', 'eth_getCode', 'eth_estimateGas'].includes(method)) assert.equal(typeof params[1], 'object');
    }
    const evidence = JSON.parse(readFileSync(join(r.evidenceDir, 'prep-1', 'evidence.json'), 'utf8'));
    assert.equal(evidence.outcome, 'BLOCKED');
    assert.equal(evidence.blocked, blocked);
    assert.equal(evidence.intentDigest, null);
    assert.ok(!readdirSync(join(r.evidenceDir, 'prep-1')).includes('intent.json'));
    rmSync(r.evidenceDir, { recursive: true });
  }
});

test('refusals before any read: flags, network, directory, authorization, commitment, budget, time, providers', async () => {
  const none = async (r, code) => {
    await refusedWith(r, code);
    assert.equal(r.transport.exchanges.length, 0);
    assert.deepEqual(readdirSync(r.evidenceDir), []);
  };
  const dir = privateDir();
  const argv = (extra = []) => ['--network', X, '--authorization', '/f/authorization.json', '--endpoints', '/f/endpoints.json', '--evidence-dir', dir, ...extra];
  await none(run(X, { evidenceDir: dir, argv: argv(['--retry', '1']) }), PrepareEntryCode.USAGE);
  await none(run(X, { evidenceDir: dir, argv: argv().slice(0, 6) }), PrepareEntryCode.USAGE);
  await none(run(X, { evidenceDir: dir, argv: [...argv().slice(0, 6), '--network', X] }), PrepareEntryCode.USAGE);
  await none(run(X, { evidenceDir: dir, argv: ['--network', 'xrpl:mainnet', ...argv().slice(2)] }), PrepareEntryCode.NETWORK_NOT_ALLOWED);
  await none(run(X, { evidenceDir: dir, argv: ['--network', 'evm:1', ...argv().slice(2)] }), PrepareEntryCode.NETWORK_NOT_ALLOWED);
  await none(run(X, { evidenceDir: dir, deps: { agreed: null } }), PrepareEntryCode.DIRECTORY_NOT_AGREED);
  await none(run(X, { evidenceDir: dir, deps: { agreed: '/elsewhere' } }), PrepareEntryCode.DIRECTORY_NOT_AGREED);
  await none(run(X, { evidenceDir: dir, auth: authorization(S) }), PrepareEntryCode.NETWORK_MISMATCH);
  await none(run(X, { evidenceDir: dir, auth: `${JSON.stringify(authorization(X), null, 1)}\n` }), PrepareEntryCode.AUTHORIZATION);
  await none(run(X, { evidenceDir: dir, auth: { ...authorization(X), extra: 1 } }), PrepareEntryCode.AUTHORIZATION);
  // A modified commitment (and so a modified 42-byte payload) never reaches a provider.
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { commitment: `sha256:${'0'.repeat(64)}` }) }), PrepareEntryCode.NOT_GENESIS);
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { requestBudget: 5 }) }), PrepareEntryCode.AUTHORIZATION);
  await none(run(S, { evidenceDir: dir, auth: authorization(S, { requestBudget: 14 }) }), PrepareEntryCode.AUTHORIZATION);
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { notAfter: iso(NOW - 1) }) }), PrepareEntryCode.AUTHORIZATION_EXPIRED);
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { notAfter: iso(NOW + 3601) }) }), PrepareEntryCode.AUTHORIZATION);
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { sender: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' }) }), PrepareEntryCode.AUTHORIZATION);
  await none(run(X, { evidenceDir: dir, auth: authorization(X, { providerIds: [XA.id, SA.id] }) }), PrepareEntryCode.AUTHORIZATION);
  await none(run(X, { evidenceDir: dir, deps: { reviewed: REVIEWED_PREPARATION_PROVIDERS } }), PrepareEntryCode.ENDPOINTS_NOT_REVIEWED);
  await none(run(X, { evidenceDir: dir, deps: { reviewed: REVIEWED.map((p) => (p.id === XB.id ? { ...p, operator: 'Someone else' } : p)) } }), PrepareEntryCode.ENDPOINTS_NOT_REVIEWED);
  // The approval: anything but "<network> <last 16 of the digest>" refuses before any read.
  for (const answer of ['yes', `${S} 0000000000000000`, '']) {
    const r = run(X, { evidenceDir: dir, deps: { approve: async () => answer } });
    await none(r, PrepareEntryCode.APPROVAL_REFUSED);
  }
  rmSync(dir, { recursive: true });
});

test('one run per authorization: a second run of the same authorization is refused and reads nothing', async () => {
  const dir = privateDir();
  assert.equal((await run(X, { evidenceDir: dir }).promise).outcome, 'PREPARED');
  const again = run(X, { evidenceDir: dir });
  await refusedWith(again, PrepareEntryCode.AUTHORIZATION_USED);
  assert.equal(again.transport.exchanges.length, 0);
  // A refused run consumes its authorization too.
  const refused = run(X, { evidenceDir: dir, auth: authorization(X, { authorizationId: 'prep-2' }), servers: { [XA.id]: xrplServer({ info: (i) => { i.network_id = 0; } }), [XB.id]: xrplServer() } });
  assert.equal((await refused.promise).code, 'RNTP_WRONG_NETWORK');
  await refusedWith(run(X, { evidenceDir: dir, auth: authorization(X, { authorizationId: 'prep-2' }) }), PrepareEntryCode.AUTHORIZATION_USED);
  // The evidence directory must be private.
  chmodSync(dir, 0o755);
  await refusedWith(run(X, { evidenceDir: dir, auth: authorization(X, { authorizationId: 'prep-3' }) }), PrepareEntryCode.EVIDENCE);
  rmSync(dir, { recursive: true });
});

test('negative state cases through the entry point give their preparation codes', async () => {
  const cases = [
    [X, { [XA.id]: xrplServer(), [XB.id]: xrplServer({ seq: 5_000_005 }) }, 'RNTP_INCONSISTENT', null], // ledger disagreement
    [X, { [XA.id]: xrplServer(), [XB.id]: xrplServer({ seq: 5_000_001, account: (r) => { r.account_data.Sequence = 7; } }) }, 'RNTP_INCONSISTENT', null], // wrong Sequence
    [X, { [XA.id]: xrplServer({ info: (i) => { i.load_factor = 2; } }), [XB.id]: xrplServer() }, 'RNTP_FEE_TOO_HIGH', XA.id], // fee above the fixed 12 drops
    [X, { [XA.id]: xrplServer({ info: (i) => { i.validated_ledger.age = 31; } }), [XB.id]: xrplServer() }, 'RNTP_STALE', XA.id],
    [S, { [SA.id]: sepoliaServer({ chainId: '0x1' }), [SB.id]: sepoliaServer() }, 'RNTP_WRONG_NETWORK', SA.id], // wrong chain ID
    [S, { [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_185, pin: (b) => { b.hash = `0x${'cd'.repeat(32)}`; } }) }, 'RNTP_INCONSISTENT', null], // pin hash disagreement
    [S, { [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_179, timestamp: NOW - 1 }) }, 'RNTP_INCONSISTENT', null], // provider lag of 5
    [S, { [SA.id]: sepoliaServer({ shift: 48 }), [SB.id]: sepoliaServer({ shift: 48 }) }, 'RNTP_STALE', SA.id], // stale data
    [S, { [SA.id]: sepoliaServer(), [SB.id]: sepoliaServer({ number: 9_437_185, nonce: '0x1' }) }, 'RNTP_INCONSISTENT', null], // nonce mismatch
    [S, { [SA.id]: sepoliaServer({ pending: '0x1' }), [SB.id]: sepoliaServer() }, 'RNTP_NONCE_PENDING', SA.id],
    [S, { [SA.id]: sepoliaServer({ pinBaseFee: `0x${(19_000_000_001).toString(16)}` }), [SB.id]: sepoliaServer({ pinBaseFee: `0x${(19_000_000_001).toString(16)}` }) }, 'RNTP_FEE_TOO_HIGH', SA.id], // fee cap
    [S, { [SA.id]: sepoliaServer({ estimate: '0x7531' }), [SB.id]: sepoliaServer() }, 'RNTP_GAS_TOO_HIGH', SA.id],
  ];
  for (const [network, servers, code, providerId] of cases) {
    const r = run(network, { servers });
    const out = await r.promise;
    assert.equal(out.code, code, `${code}: ${out.message}`);
    assert.equal(out.providerId, providerId, out.message);
    assert.equal(out.outcome, 'REFUSED');
    assert.ok(r.transport.exchanges.length <= PREPARATION_RUN_REQUESTS[network]);
    rmSync(r.evidenceDir, { recursive: true });
  }
});

test('the request policy admits exactly the plan, in its forms, and nothing else', async () => {
  const sent = [];
  const transport = async (request) => {
    sent.push(request);
    return { status: 200, body: new Uint8Array() };
  };
  const body = (method, params) => {
    try {
      return requestBytes(S, method, params);
    } catch {
      return new Uint8Array(Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })));
    }
  };
  const ask = (policy, provider, method, params) => policy.wrap(transport)({ providerId: provider.id, url: provider.url, body: body(method, params) });
  const pin = { blockHash: `0x${'ab'.repeat(32)}`, requireCanonical: true };
  const data = '0x00';
  const call = { data, from: SEPOLIA_FROM, to: SEPOLIA_FROM, value: '0x0' };
  const fresh = () => createPreparationPolicy({ network: S, providers: [SA, SB], sender: SEPOLIA_FROM, data });
  const headPass = async (policy) => {
    for (const p of [SA, SB]) {
      await ask(policy, p, 'eth_chainId', []);
      await ask(policy, p, 'eth_getBlockByNumber', ['latest', false]);
    }
  };
  const fullPlan = async (policy) => {
    await headPass(policy);
    for (const p of [SA, SB]) await ask(policy, p, 'eth_getBlockByNumber', ['0x8ffffe', false]);
    for (const p of [SA, SB]) {
      await ask(policy, p, 'eth_getTransactionCount', [SEPOLIA_FROM, pin]);
      await ask(policy, p, 'eth_getTransactionCount', [SEPOLIA_FROM, 'pending']);
      await ask(policy, p, 'eth_getBalance', [SEPOLIA_FROM, pin]);
      await ask(policy, p, 'eth_getCode', [SEPOLIA_FROM, pin]);
      await ask(policy, p, 'eth_estimateGas', [call, pin]);
    }
  };
  const ok = fresh();
  await fullPlan(ok);
  assert.ok(ok.complete());
  assert.equal(sent.length, 16);
  await assert.rejects(ask(ok, SA, 'eth_chainId', []), /budget used/);
  // Each refusal is recorded and nothing more is sent.
  const refusedAt = async (prefix, method, params, reason) => {
    const policy = fresh();
    const before = sent.length;
    await prefix(policy);
    const admitted = sent.length;
    await assert.rejects(ask(policy, SA, method, params), reason);
    assert.equal(sent.length, admitted);
    assert.ok(policy.violation);
    await assert.rejects(ask(policy, SA, 'eth_chainId', []));
    assert.ok(sent.length >= before);
  };
  const toPinned = async (policy) => {
    await headPass(policy);
    for (const p of [SA, SB]) await ask(policy, p, 'eth_getBlockByNumber', ['0x8ffffe', false]);
  };
  for (const tag of ['latest', 'pending', 'safe', 'finalized', '0x8ffffe', undefined]) {
    await refusedAt(toPinned, 'eth_getTransactionCount', tag === undefined ? [SEPOLIA_FROM] : [SEPOLIA_FROM, tag], /pinned|sender|params/);
  }
  await refusedAt(toPinned, 'eth_getTransactionCount', [SEPOLIA_FROM, { blockHash: pin.blockHash }], /pinned/);
  await refusedAt(toPinned, 'eth_getTransactionCount', [SEPOLIA_FROM, { blockHash: pin.blockHash, requireCanonical: false }], /pinned/);
  await refusedAt(toPinned, 'eth_getTransactionCount', [SEPOLIA_FROM, { blockNumber: '0x8ffffe' }], /pinned/);
  await refusedAt(toPinned, 'eth_getTransactionCount', ['0x0000000000000000000000000000000000000001', pin], /sender/);
  await refusedAt(toPinned, 'eth_sendRawTransaction', ['0x02'], /not eth_sendRawTransaction/);
  // eth_estimateGas: always the block-hash object, never another form (ADR-RN-018 Amendment C1, P4).
  const toEstimate = async (policy) => {
    await toPinned(policy);
    await ask(policy, SA, 'eth_getTransactionCount', [SEPOLIA_FROM, pin]);
    await ask(policy, SA, 'eth_getTransactionCount', [SEPOLIA_FROM, 'pending']);
    await ask(policy, SA, 'eth_getBalance', [SEPOLIA_FROM, pin]);
    await ask(policy, SA, 'eth_getCode', [SEPOLIA_FROM, pin]);
  };
  for (const at of ['latest', 'pending', '0x8ffffe']) await refusedAt(toEstimate, 'eth_estimateGas', [call, at], /pinned/);
  await refusedAt(toEstimate, 'eth_estimateGas', [call], /eth_estimateGas call object|pinned/);
  await refusedAt(toEstimate, 'eth_estimateGas', [{ ...call, data: '0x01' }, pin], /call object/);
  await refusedAt(toEstimate, 'eth_estimateGas', [call, { ...pin, blockHash: `0x${'cd'.repeat(32)}` }], /two pinned hashes/);
  // Order: no pin before every head pass; no pinned read before every pin; one pin number.
  await refusedAt(async (p) => { await ask(p, SA, 'eth_chainId', []); await ask(p, SA, 'eth_getBlockByNumber', ['latest', false]); }, 'eth_getBlockByNumber', ['0x8ffffe', false], /before every head pass/);
  await refusedAt(async (p) => { await headPass(p); await ask(p, SA, 'eth_getBlockByNumber', ['0x8ffffe', false]); }, 'eth_getTransactionCount', [SEPOLIA_FROM, pin], /before every pin/);
  await refusedAt(async (p) => { await headPass(p); await ask(p, SB, 'eth_getBlockByNumber', ['0x8ffffe', false]); }, 'eth_getBlockByNumber', ['0x8ffffd', false], /two pin numbers/);
  await refusedAt(headPass, 'eth_getBlockByNumber', ['latest', false], /by number/);
  // Providers and URLs: only the run's two, at their configured URLs.
  const p = fresh();
  await assert.rejects(p.wrap(transport)({ providerId: 'other', url: SA.url, body: body('eth_chainId', []) }), /not one of this run/);
  const q = fresh();
  await assert.rejects(q.wrap(transport)({ providerId: SA.id, url: 'https://elsewhere.fixture.invalid/', body: body('eth_chainId', []) }), /url of/);
  // XRPL: server_info then account_info at "validated" for the authorized account only; no submit.
  const xrpl = () => createPreparationPolicy({ network: X, providers: [XA, XB], sender: XRPL_ACCOUNT });
  const xbody = (method, params) => {
    try {
      return requestBytes(X, method, params);
    } catch {
      return new Uint8Array(Buffer.from(JSON.stringify({ method, params: [params] })));
    }
  };
  const xask = (policy, method, params) => policy.wrap(transport)({ providerId: XA.id, url: XA.url, body: xbody(method, params) });
  const x1 = xrpl();
  await xask(x1, 'server_info', { api_version: 2 });
  await assert.rejects(xask(x1, 'account_info', { account: XRPL_ACCOUNT, api_version: 2, ledger_index: 'current', signer_lists: true }), /account_info params/);
  const x2 = xrpl();
  await assert.rejects(xask(x2, 'submit', { tx_blob: '00' }), /not submit/);
  assert.deepEqual(PREPARATION_REQUESTS[X], ['server_info', 'account_info']);
});

test('the freshness time is read after the founder approves, and the authorization is checked again then', async () => {
  // Blocks made while the founder reads the prompt are fresh, not "in the future" (found by the C3
  // rehearsal): the approval takes 30 s and the providers' heads are from that later time.
  let t = NOW;
  const servers = { [SA.id]: sepoliaServer({ number: 9_437_187, timestamp: NOW + 29 }), [SB.id]: sepoliaServer({ number: 9_437_187, timestamp: NOW + 29 }) };
  const slow = run(S, { servers, deps: { now: () => t, approve: async (prompt) => { t += 30; return `${S} ${readPreparationAuthorization(`${canonicalize(authorization(S))}\n`).digest.slice(-16)}`; } } });
  const out = await slow.promise;
  assert.equal(out.outcome, 'PREPARED', out.message);
  assert.equal(out.intent.preparation.observedAt, NOW + 30);
  rmSync(slow.evidenceDir, { recursive: true });
  // An authorization that expires while the founder reads is refused before any read or run directory.
  t = NOW;
  const expiring = run(X, { auth: authorization(X, { notAfter: iso(NOW + 10) }), deps: { now: () => t, approve: async () => { t += 11; return `${X} ${readPreparationAuthorization(`${canonicalize(authorization(X, { notAfter: iso(NOW + 10) }))}\n`).digest.slice(-16)}`; } } });
  await refusedWith(expiring, PrepareEntryCode.AUTHORIZATION_EXPIRED);
  assert.equal(expiring.transport.exchanges.length, 0);
  assert.deepEqual(readdirSync(expiring.evidenceDir), []);
  rmSync(expiring.evidenceDir, { recursive: true });
});

test('C3 review: the policy admits only the canonical planned bytes', async () => {
  const transport = async () => ({ status: 200, body: new Uint8Array() });
  const raw = (text) => new Uint8Array(Buffer.from(text));
  for (const text of [
    '{"id":1,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xdead"],"method":"eth_chainId","params":[]}', // duplicate keys
    '{"id":1,"jsonrpc":"2.0","method":"eth_chainId","params":[],"x":1}', // an extra member
    '{"id":2,"jsonrpc":"2.0","method":"eth_chainId","params":[]}', // another id
    '{"id":1,"method":"eth_chainId","params":[]}', // no jsonrpc
    '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}', // not canonical key order
  ]) {
    const policy = createPreparationPolicy({ network: S, providers: [SA, SB], sender: SEPOLIA_FROM, data: '0x00' });
    await assert.rejects(policy.wrap(transport)({ providerId: SA.id, url: SA.url, body: raw(text) }), /preparation policy/, text);
  }
  const ok = createPreparationPolicy({ network: S, providers: [SA, SB], sender: SEPOLIA_FROM, data: '0x00' });
  await ok.wrap(transport)({ providerId: SA.id, url: SA.url, body: requestBytes(S, 'eth_chainId', []) });
});

test('C3 review: an error on the pending nonce (no block hash) is not blocked; the hashed reads are', async () => {
  const error = () => Buffer.from('{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"rate limited"}}');
  const pending = (params) => (params[1] === 'pending' ? { status: 200, body: new Uint8Array(error()) } : undefined);
  const r = run(S, { servers: { [SA.id]: sepoliaServer({ raw: { eth_getTransactionCount: pending } }), [SB.id]: sepoliaServer({ number: 9_437_185 }) } });
  const out = await r.promise;
  assert.equal(out.outcome, 'REFUSED', out.message);
  assert.equal(out.code, 'RNTP_PROVIDER_ERROR');
  assert.equal(out.blocked, null);
  rmSync(r.evidenceDir, { recursive: true });
});

test('C3 review: an unexpected error still leaves the evidence of what was sent', async () => {
  let n = 0;
  const inner = fakeTransport({ [XA.id]: xrplServer(), [XB.id]: xrplServer({ seq: 5_000_001 }) });
  const r = run(X, { deps: { transport: async (request) => {
    n += 1;
    if (n === 3) throw Object.assign(new Error('synthetic capture mismatch'), { name: 'ReplayMismatch' });
    return inner(request);
  } } });
  await assert.rejects(r.promise, /synthetic capture mismatch/);
  const evidence = JSON.parse(readFileSync(join(r.evidenceDir, 'prep-1', 'evidence.json'), 'utf8'));
  assert.equal(evidence.requestCount, 3);
  assert.equal(evidence.code, PrepareEntryCode.EVIDENCE);
  rmSync(r.evidenceDir, { recursive: true });
});
