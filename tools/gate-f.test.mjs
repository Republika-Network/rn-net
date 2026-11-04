// RN-NET-03B2-WP4-B1: the offline durable gate-F core (ADR-RN-020; spec
// rnnet.gate-f-sepolia-verification.v1). Synthetic, offline: every capture comes from a simulated
// chain read by the existing reader, and no request reaches a network.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { canonicalBytes } from '../packages/canonical/src/index.mjs';
import { statusRecordDigest, submissionRecordDigest } from '../packages/chain-submit/src/index.mjs';
import { baseInputs, build, CASES, PATH, runCase, SUBMISSION, T0 } from './gate-f/build-gate-f-fixtures.mjs';
import { verifyGateFHypotheticalStageB } from './gate-f/test-seam.mjs';
import { checkGateFChain, checkGateFRecord, FINDING_GROUPS, GATE_F_DIGEST_DOMAIN, gateFRecordDigest, verifyGateF } from './gate-f/verify.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const doc = JSON.parse(readFileSync(PATH, 'utf8'));
const byId = Object.fromEntries(doc.cases.map((c) => [c.id, c.expected]));
const clone = (v) => JSON.parse(JSON.stringify(v));
const refusedAs = (code) => (e) => e.name === 'GateFError' && e.code === code;
const SKIP = new Set(['.git', 'node_modules', 'fixtures']);
const walk = (dir) =>
  readdirSync(new URL(dir, ROOT), { withFileTypes: true }).flatMap((e) => {
    const path = dir === './' ? e.name : `${dir}${e.name}`;
    if (e.isDirectory()) return SKIP.has(e.name) ? [] : walk(`${path}/`);
    return path.endsWith('.mjs') ? [path] : [];
  });
const escapeRegExp = (s) => s.replace(/[\\^$.*+?()[\]{}|/-]/g, '\\$&');
const importers = (target) => walk('./').filter((f) => new RegExp(`^(?:import|export) [^;]* from '[^']*${escapeRegExp(target)}';$`, 'm').test(read(f)));

test('the committed gate-F B1 fixtures are exactly what the builder produces', async () => {
  assert.equal(readFileSync(PATH, 'utf8'), await build());
  assert.equal(doc.cases.length, CASES.length);
  assert.match(doc.status, /^SYNTHETIC/);
});

test('every case replays to its recorded record and digest (byte-identical, deterministic)', async () => {
  for (const c of CASES) {
    const { record, digest } = await runCase(c);
    assert.deepEqual(clone(record), byId[c.id].record, c.id);
    assert.equal(digest, byId[c.id].digest, c.id);
    const again = await runCase(c);
    assert.equal(again.digest, digest, `${c.id}: identical inputs give identical records`);
  }
});

test('B1 is partial: no gas state is evaluated, no gas value is invented, nothing is ever eligible or proven', () => {
  for (const { record } of Object.values(byId)) {
    assert.deepEqual([record.gas.record, record.gas.rules, record.gas.accounting], ['NOT_EVALUATED', 'NOT_EVALUATED', 'NOT_EVALUATED']);
    assert.deepEqual([record.gas.recorded, record.gas.atInclusion, record.gas.expected, record.gas.gasUsed], [null, null, null, null]);
    assert.ok(['FAIL', 'UNRESOLVED'].includes(record.disposition));
    assert.equal(record.finality.chainInclusionProof, 'UNRESOLVED');
  }
  const text = readFileSync(PATH, 'utf8');
  for (const word of ['ELIGIBLE_FOR_FOUNDER_REVIEW', 'CHAIN_PROVEN', '"VERIFIED"', '"published"']) assert.ok(!text.includes(word), word);
});

test('positive structure: both providers finalized, inclusion linked, t_i from the captured block, evidence bound by digest', () => {
  const r = byId['both-finalized'].record;
  assert.equal(r.inclusion.status, 'ESTABLISHED');
  assert.equal(r.inclusion.timestamp, T0);
  assert.equal(r.finality.disposition, 'PROVIDER_REPORTED_FINALIZED');
  assert.deepEqual(r.finality.perProvider.map((p) => p.result), ['IN_ANCESTRY', 'IN_ANCESTRY']);
  assert.equal(r.finality.classification, 'CLAIMED');
  assert.equal(r.subject.transactionHash, SUBMISSION.expectedTransactionHash);
  assert.equal(r.subject.submissionRecordDigest, submissionRecordDigest(SUBMISSION));
  assert.equal(r.disposition, 'UNRESOLVED');
  // 256 steps is the limit and passes; 257 is refused as UNRESOLVED, never inferred.
  assert.equal(byId['walk-256-steps'].record.finality.disposition, 'PROVIDER_REPORTED_FINALIZED');
  assert.equal(byId['walk-beyond-depth'].record.finality.disposition, 'NOT_ESTABLISHED');
});

test('CONFLICT on either provider is preserved, is FAIL, and is never hidden by the other provider (PR #42)', () => {
  for (const [id, results] of [['publicnode-conflict', ['CONFLICT', 'IN_ANCESTRY']], ['1rpc-conflict-publicnode-finalized', ['IN_ANCESTRY', 'CONFLICT']]]) {
    const r = byId[id].record;
    assert.deepEqual(r.finality.perProvider.map((p) => p.result), results, id);
    assert.equal(r.finality.disposition, 'CONFLICT', id);
    assert.equal(r.disposition, 'FAIL', id);
    assert.equal(r.gas.record, 'NOT_EVALUATED', id);
    assert.equal(r.inclusion.status, 'ESTABLISHED', id);
    assert.equal(r.inclusion.timestamp, null, id);
  }
  const single = byId['1rpc-not-reached'].record;
  assert.deepEqual([single.finality.disposition, single.disposition], ['PROVIDER_REPORTED_FINALIZED_SINGLE', 'UNRESOLVED']);
});

test('NOT_EVALUATED is distinct from NOT_ESTABLISHED; a candidate subject gives a FAIL record with nothing invented', () => {
  const failed = byId['candidate-as-intent'].record;
  assert.deepEqual([failed.inclusion.status, failed.finality.disposition, failed.finality.perProvider, failed.disposition], ['NOT_EVALUATED', 'NOT_EVALUATED', [], 'FAIL']);
  assert.deepEqual([failed.subject.commitment, failed.subject.transactionHash, failed.subject.blobSha256], [null, null, null]);
  const pending = byId.pending.record;
  assert.deepEqual([pending.inclusion.status, pending.finality.disposition, pending.disposition], ['NOT_ESTABLISHED', 'NOT_ESTABLISHED', 'UNRESOLVED']);
  assert.deepEqual([pending.inclusion.blockHash, pending.inclusion.timestamp], [null, null]);
  const op = byId['operational-refuses-every-subject'].record;
  assert.deepEqual(op.findings.map((f) => f.code), ['RNGF_SUBJECT_NOT_ELIGIBLE']);
  assert.notEqual(op.subject.commitment, null); // a valid intent, not eligible: its commitment is known
});

test('preliminary status is referenced only; INCLUDED never changes a finding', () => {
  const withStatus = byId['preliminary-status-included'].record;
  const without = byId['both-finalized'].record;
  assert.equal(withStatus.preliminaryStatus.finding, 'INCLUDED');
  assert.deepEqual({ ...withStatus, preliminaryStatus: null }, without);
});

test('the strict schema refuses tampered and state-inconsistent records', () => {
  const good = byId['both-finalized'].record;
  checkGateFRecord(good);
  const conflict = byId['publicnode-conflict'].record;
  const variants = [
    (r) => { r.format = 'rnnet.gate-f-sepolia-verification.v2'; },
    (r) => { r.extra = 1; },
    (r) => { delete r.supersedes; },
    (r) => { r.findings.push({ code: 'X', group: 'other', subject: null }); },
    (r) => { r.finality.disposition = 'CONFLICT'; },
    (r) => { r.finality.perProvider[0].result = 'CONFLICT'; },
    (r) => { r.finality.perProvider.reverse(); },
    (r) => { r.disposition = 'ELIGIBLE_FOR_FOUNDER_REVIEW'; },
    (r) => { r.finality.classification = 'UNRESOLVED'; },
    (r) => { r.finality.chainInclusionProof = 'CHAIN_PROVEN'; },
    (r) => { r.inclusion.status = 'NOT_EVALUATED'; },
    (r) => { r.inclusion.timestamp = 1.5; },
    (r) => { r.gas.expected = 14688; },
    (r) => { r.gas.record = 'VALID'; },
    (r) => { r.evidence.providers = ['sepolia-1rpc', 'sepolia-publicnode']; },
    (r) => { r.subject.intentDigest = null; },
  ];
  for (const edit of variants) {
    const r = clone(good);
    edit(r);
    assert.throws(() => checkGateFRecord(r), refusedAs('RNGF_EVIDENCE_INVALID'), edit.toString());
  }
  for (const edit of [(r) => { r.disposition = 'UNRESOLVED'; }, (r) => { r.finality.perProvider[0].result = 'IN_ANCESTRY'; }, (r) => { r.finality.disposition = 'NOT_ESTABLISHED'; }]) {
    const r = clone(conflict);
    edit(r);
    assert.throws(() => checkGateFRecord(r), refusedAs('RNGF_EVIDENCE_INVALID'), edit.toString());
  }
  assert.deepEqual([...FINDING_GROUPS], ['subject', 'binding', 'evidence', 'inclusion', 'finality', 'gasRecord', 'gasRules', 'gasAccounting', 'review', 'chain']);
});

test('the record digest is domain-separated and differs from every other domain', () => {
  const r = byId['both-finalized'].record;
  const bytes = Buffer.from(canonicalBytes(r));
  assert.equal(GATE_F_DIGEST_DOMAIN, 'rnnet:gate-f-sepolia-verification:v1\0');
  assert.equal(gateFRecordDigest(r), `sha256:${createHash('sha256').update(GATE_F_DIGEST_DOMAIN).update(bytes).digest('hex')}`);
  for (const other of ['rnnet:unsigned-tx-intent:v1\0', 'rnnet:tx-preparation-v2-candidate:v1\0', 'rnnet:submission-record:v1\0', 'rnnet:submission-status:v1\0', '']) {
    assert.notEqual(gateFRecordDigest(r), `sha256:${createHash('sha256').update(other).update(bytes).digest('hex')}`);
  }
});

test('the submission and status digests equal chain-submit’s (gate F may not import it)', async () => {
  const b3 = JSON.parse(read('fixtures/broadcast-b3/cases.json'));
  const status = b3.statusChecks.find((c) => c.inputs.intent.includes('"network":"evm:11155111"')).expected.record;
  assert.equal(byId['preliminary-status-included'].record.preliminaryStatus.statusRecordDigest, statusRecordDigest(status));
  assert.equal(byId['both-finalized'].record.subject.submissionRecordDigest, submissionRecordDigest(SUBMISSION));
});

test('append-only: a valid successor; a wrong reason, another subject or an invalid predecessor is refused', async () => {
  const pred = byId['1rpc-not-reached'].record;
  const inputs = await baseInputs();
  const { record } = await verifyGateFHypotheticalStageB({ ...inputs, supersedes: { record: pred, reason: 'NEW_EVIDENCE' } });
  assert.deepEqual(record.supersedes, { recordDigest: gateFRecordDigest(pred), reason: 'NEW_EVIDENCE' });
  assert.equal(checkGateFChain([record, pred]).length, 2);
  await assert.rejects(verifyGateFHypotheticalStageB({ ...inputs, supersedes: { record: pred, reason: 'OVERWRITE' } }), refusedAs('RNGF_CHAIN_INVALID'));
  await assert.rejects(verifyGateFHypotheticalStageB({ ...inputs, supersedes: { record: byId['candidate-as-intent'].record, reason: 'CORRECTION' } }), refusedAs('RNGF_CHAIN_INVALID'));
  await assert.rejects(verifyGateFHypotheticalStageB({ ...inputs, supersedes: { record: { ...pred, extra: 1 }, reason: 'CORRECTION' } }), refusedAs('RNGF_CHAIN_INVALID'));
  // The chain over a supplied set: dangling, branching, duplicate.
  assert.throws(() => checkGateFChain([record]), refusedAs('RNGF_CHAIN_INVALID'));
  const { record: second } = await verifyGateFHypotheticalStageB({ ...inputs, preliminaryStatus: null, reviewHistory: [{ synthetic: 'TEST' }], supersedes: { record: pred, reason: 'CORRECTION' } });
  assert.throws(() => checkGateFChain([record, second, pred]), refusedAs('RNGF_CHAIN_INVALID'));
  assert.throws(() => checkGateFChain([pred, pred]), refusedAs('RNGF_CHAIN_INVALID'));
  // An incorrect predecessor digest names no supplied record (dangling), and a tampered successor is refused by the schema.
  const wrong = clone(record);
  wrong.supersedes.recordDigest = `sha256:${'a'.repeat(64)}`;
  assert.throws(() => checkGateFChain([wrong, pred]), refusedAs('RNGF_CHAIN_INVALID'));
  // A cycle needs a SHA-256 preimage (a record naming a digest computed over itself); the checker refuses one
  // anyway, and a self-reference is not constructible, so it is not exercised here.
  // The earlier record is unchanged by its successor.
  assert.deepEqual(pred, byId['1rpc-not-reached'].record);
});

test('the input set is strict, read once and frozen: unknown members, getters, proxies and later mutation have no effect', async () => {
  const inputs = await baseInputs();
  await assert.rejects(verifyGateFHypotheticalStageB({ ...inputs, extra: 1 }), refusedAs('RNGF_EVIDENCE_INVALID'));
  const { preliminaryStatus, ...missing } = inputs;
  assert.equal(preliminaryStatus, null);
  await assert.rejects(verifyGateFHypotheticalStageB(missing), refusedAs('RNGF_EVIDENCE_INVALID'));
  await assert.rejects(verifyGateFHypotheticalStageB(new Proxy(inputs, {})), refusedAs('RNGF_EVIDENCE_INVALID'));
  const getter = { ...inputs };
  Object.defineProperty(getter, 'signedTransaction', { enumerable: true, get: () => inputs.signedTransaction });
  await assert.rejects(verifyGateFHypotheticalStageB(getter), refusedAs('RNGF_EVIDENCE_INVALID'));
  await assert.rejects(verifyGateFHypotheticalStageB({ ...inputs, txverifyRecord: Object.create(inputs.txverifyRecord) }), refusedAs('RNGF_EVIDENCE_INVALID'));
  // Mutating the caller's objects after the call starts does not change the record.
  const mutable = clone(inputs);
  const pending = verifyGateFHypotheticalStageB(mutable);
  mutable.submissionRecord.intentDigest = `sha256:${'9'.repeat(64)}`;
  mutable.capture.exchanges.length = 0;
  const { digest } = await pending;
  assert.equal(digest, byId['both-finalized'].digest);
});

test('the operational entry refuses every subject; only tests and the builder reach the hypothetical Stage B seam', async () => {
  const inputs = await baseInputs();
  const { record } = await verifyGateF(inputs);
  assert.deepEqual([record.disposition, record.findings[0].code], ['FAIL', 'RNGF_SUBJECT_NOT_ELIGIBLE']);
  assert.deepEqual(importers('test-seam.mjs').sort(), ['tools/gate-f.test.mjs', 'tools/gate-f/build-gate-f-fixtures.mjs']);
  assert.deepEqual(importers('gate-f/core.mjs'), []);
  assert.deepEqual(walk('./').filter((f) => /from '\.\/core\.mjs';$/m.test(read(f))).sort(), ['tools/gate-f/test-seam.mjs', 'tools/gate-f/verify.mjs']);
  assert.doesNotMatch(read('tools/gate-f/verify.mjs'), /test-seam/);
  // Nothing operational uses gate F yet.
  for (const f of walk('./').filter((p) => /^(tools\/(prepare|submit|rehearsal|keytool|compat-live)\/|signer\/|txverify\/src\/)/.test(p))) assert.doesNotMatch(read(f), /gate-f/, f);
});

test('the gate-F files are pure: fixed imports, no network, clock, environment, subprocess, key or write path', () => {
  const allowed = {
    'tools/gate-f/record.mjs': ['node:buffer', 'node:crypto', '../../packages/canonical/src/index.mjs', '../../packages/tx-intent/src/index.mjs'],
    'tools/gate-f/core.mjs': ['node:buffer', 'node:crypto', '../../packages/canonical/src/index.mjs', '../../packages/chain-readonly/src/index.mjs', '../../packages/tx-intent/src/index.mjs', '../../txverify/src/index.mjs', './record.mjs'],
    'tools/gate-f/verify.mjs': ['./core.mjs'],
    'tools/gate-f/test-seam.mjs': ['./core.mjs'],
  };
  for (const [file, imports] of Object.entries(allowed)) {
    const text = read(file);
    assert.deepEqual([...text.matchAll(/^import [^;]* from '([^']+)';$/gm)].map((m) => m[1]), imports, file);
    const code = text.replace(/\/\/.*$/gm, '');
    for (const name of ['fetch', 'Date', 'process', 'globalThis', 'require', 'child_process', 'node:http', 'node:https', 'node:net', 'node:fs', 'WebSocket', 'signer/', 'chain-submit', 'setTimeout']) {
      assert.doesNotMatch(code, new RegExp(`\\b${escapeRegExp(name)}${/\w$/.test(name) ? '(?!\\w)' : ''}`), `${file}: ${name}`);
    }
  }
});

test('the live switches are unchanged (B1 is offline only)', () => {
  for (const f of ['tools/compat-live/compat-live.mjs', 'tools/prepare/prepare-live.mjs', 'tools/submit/submit-anchor.mjs', 'tools/submit/status-check.mjs']) assert.match(read(f), /^export const LIVE_NETWORK_ACCESS = false;$/m, f);
  for (const f of ['tools/compat-live/entry.mjs', 'tools/prepare/entry.mjs']) assert.match(read(f), /^export const AGREED_EVIDENCE_DIR = null;$/m, f);
  assert.match(read('tools/guards/dependency-boundaries.mjs'), /^export const (PREPARE|WRITE)_TRANSPORT_JOINERS = \[\];$/m);
});
