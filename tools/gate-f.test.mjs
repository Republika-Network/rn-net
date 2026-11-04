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
import { baseInputs, build, CASES, PATH, PATH_SEC01, runCase, SEC01_CASES, SETS, SUBMISSION, T0 } from './gate-f/build-gate-f-fixtures.mjs';
import { verifyGateFHypotheticalStageB } from './gate-f/test-seam.mjs';
import { checkGateFChain, checkGateFRecord, FINDING_GROUPS, GATE_F_DIGEST_DOMAIN, gateFRecordDigest, verifyGateF } from './gate-f/verify.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const doc = JSON.parse(readFileSync(PATH, 'utf8'));
const docSec01 = JSON.parse(readFileSync(PATH_SEC01, 'utf8'));
const byId = Object.fromEntries([...doc.cases, ...docSec01.cases].map((c) => [c.id, c.expected]));
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

test('the committed gate-F fixtures are exactly what the builder produces; the merged B1 file is unchanged', async () => {
  for (const { path, cases } of SETS) assert.equal(readFileSync(path, 'utf8'), await build(cases), path);
  assert.equal(doc.cases.length, CASES.length);
  assert.equal(docSec01.cases.length, SEC01_CASES.length);
  for (const d of [doc, docSec01]) assert.match(d.status, /^SYNTHETIC/);
  // WP4-B1-SEC-01 changed no B1 record: the file merged in #43 (aa44d19), byte for byte.
  assert.equal(createHash('sha256').update(readFileSync(PATH)).digest('hex'), '3cb728e827788b7d1d9303d1548a5ef1045050f8c63b25e579649c19c8572dad');
  assert.equal(new Set([...CASES, ...SEC01_CASES].map((c) => c.id)).size, CASES.length + SEC01_CASES.length);
});

test('every case replays to its recorded record and digest (byte-identical, deterministic)', async () => {
  for (const c of [...CASES, ...SEC01_CASES]) {
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

test('R2: the operational entry refuses every subject, and no caller can supply an eligibility rule', async () => {
  const inputs = await baseInputs();
  const { record, digest } = await verifyGateF(inputs);
  assert.deepEqual([record.disposition, record.findings.map((f) => f.code)], ['FAIL', ['RNGF_SUBJECT_NOT_ELIGIBLE']]);
  // Extra arguments (a callback, a policy object, a mode name) are ignored: the rule is fixed.
  for (const extra of [() => true, { eligible: () => true }, 'TEST', { id: 'test-hypothetical-stage-b', eligible: () => true }]) {
    assert.equal((await verifyGateF(inputs, extra)).digest, digest);
  }
  // The same synthetic subject the seam accepts is refused operationally, and so are v1 rpc-read and synthetic-with-note intents.
  for (const id of ['operational-refuses-every-subject', 'r2-operational-refuses-v1-rpc-read', 'r2-operational-refuses-synthetic-with-note']) {
    assert.deepEqual(byId[id].record.findings.map((f) => f.code), ['RNGF_SUBJECT_NOT_ELIGIBLE'], id);
  }
  // The seam's fixed rule accepts the synthetic preparation only: a v1 rpc-read intent is refused there too.
  assert.deepEqual(byId['r2-seam-refuses-v1-rpc-read'].record.findings.map((f) => f.code), ['RNGF_SUBJECT_NOT_ELIGIBLE']);
  assert.notEqual(byId['r2-seam-refuses-v1-rpc-read'].record.subject.commitment, null); // a valid approved intent, not eligible
});

test('R2: core.mjs exports no evaluator that takes a rule; the seam and builder are pinned by the guard and here', () => {
  const core = read('tools/gate-f/core.mjs');
  const exported = [...core.matchAll(/^export (?:async )?(?:function|const|class|let) (\w+)(\([^)]*\))?/gm)].map((m) => [m[1], m[2] ?? null]);
  assert.deepEqual(exported, [['GATE_F_INPUTS', null], ['evaluateGateFOperational', '(inputs)'], ['evaluateGateFTestStandIn', '(inputs)']]);
  assert.doesNotMatch(core, /^export (?:default|\{|\*)/m);
  for (const gone of ['OPERATIONAL_SUBJECT_POLICY', 'evaluateGateF(', 'policy.eligible']) assert.ok(!core.includes(gone), gone);
  assert.match(read('tools/gate-f/verify.mjs'), /^import \{ evaluateGateFOperational \} from '\.\/core\.mjs';$/m);
  assert.doesNotMatch(read('tools/gate-f/verify.mjs'), /TestStandIn|test-seam/);
  assert.match(read('tools/gate-f/test-seam.mjs'), /^import \{ evaluateGateFTestStandIn \} from '\.\/core\.mjs';$/m);
  // Importers in the tree: exactly the allowed ones.
  assert.deepEqual(importers('test-seam.mjs').sort(), ['tools/gate-f.test.mjs', 'tools/gate-f/build-gate-f-fixtures.mjs']);
  assert.deepEqual(importers('build-gate-f-fixtures.mjs'), ['tools/gate-f.test.mjs']);
  assert.deepEqual(importers('gate-f/core.mjs'), []);
  assert.deepEqual(walk('./').filter((f) => /from '\.\/core\.mjs';$/m.test(read(f))).sort(), ['tools/gate-f/test-seam.mjs', 'tools/gate-f/verify.mjs']);
  // The repository guard enforces the same pins (dependency-boundaries GATE_F_RESTRICTED).
  const guard = read('tools/guards/dependency-boundaries.mjs');
  for (const rule of ['gate-f-${id}-importer-not-allowed', 'gate-f-computed-import']) assert.ok(guard.includes(rule), rule);
  // Nothing operational uses gate F yet.
  for (const f of walk('./').filter((p) => /^(tools\/(prepare|submit|rehearsal|keytool|compat-live|broadcast|signing)\/|signer\/|txverify\/src\/|packages\/)/.test(p))) assert.doesNotMatch(read(f), /gate-f/, f);
});

test('R1: the provider comparison table (spec §3.3.1)', () => {
  const look = (id) => {
    const r = byId[id].record;
    return [r.disposition, r.finality.disposition, r.findings.map((f) => f.code)];
  };
  // D2 contradicted missing observation (both directions) and D3 material difference: FAIL.
  for (const id of ['one-provider-not-found', 'r1-publicnode-not-found-1rpc-observed', 'providers-disagree-on-block', 'r1-pending-against-included']) {
    assert.deepEqual(look(id), ['FAIL', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT']], id);
  }
  // D4 no observation and D5 uncontradicted missing observation: never a disagreement.
  assert.deepEqual(look('r1-both-unavailable'), ['UNRESOLVED', 'NOT_ESTABLISHED', []]);
  assert.deepEqual(look('r1-not-found-and-unavailable'), ['UNRESOLVED', 'NOT_ESTABLISHED', []]);
  assert.deepEqual(byId['r1-publicnode-unavailable-1rpc-finalized'].record.finality.perProvider.map((p) => p.result), ['NOT_OBSERVED', 'IN_ANCESTRY']);
  assert.deepEqual(look('r1-publicnode-unavailable-1rpc-finalized'), ['UNRESOLVED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  assert.deepEqual(look('1rpc-unavailable'), ['UNRESOLVED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  // D8 finality-only differences and D9 unresolved walks: decided by §3.4, never an evidence FAIL.
  assert.deepEqual(look('r1-safe-walk-differs-only'), ['UNRESOLVED', 'PROVIDER_REPORTED_FINALIZED', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  assert.deepEqual(look('1rpc-not-reached'), ['UNRESOLVED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  assert.deepEqual(look('r1-1rpc-walk-unresolved'), ['UNRESOLVED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  assert.deepEqual(look('publicnode-not-reached-1rpc-finalized'), ['UNRESOLVED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  assert.deepEqual(look('r1-publicnode-walk-unresolved-1rpc-finalized'), ['UNRESOLVED', 'NOT_ESTABLISHED', ['RNGF_RULES_AUTHORITY_ABSENT']]);
  // D6 / D7: every CONFLICT is FAIL and recorded, on either tag, either provider, or behind an evidence failure.
  assert.deepEqual(look('r1-both-providers-conflict'), ['FAIL', 'CONFLICT', ['RNLO_FINALITY_CONFLICT', 'RNLO_FINALITY_CONFLICT']]);
  assert.deepEqual(look('r1-safe-conflict-publicnode-finalized-not-reached'), ['FAIL', 'NOT_ESTABLISHED', ['RNLO_FINALITY_CONFLICT']]);
  assert.deepEqual(look('r1-safe-conflict-1rpc-finalized-not-reached'), ['FAIL', 'PROVIDER_REPORTED_FINALIZED_SINGLE', ['RNLO_FINALITY_CONFLICT']]);
  assert.deepEqual(look('r1-conflict-behind-material-disagreement'), ['FAIL', 'NOT_EVALUATED', ['RNLO_PROVIDER_DISAGREEMENT', 'RNLO_FINALITY_CONFLICT']]);
  assert.deepEqual(byId['r1-safe-conflict-1rpc-finalized-not-reached'].record.findings[0], { code: 'RNLO_FINALITY_CONFLICT', group: 'finality', subject: 'sepolia-1rpc' });
  // Across every recorded case: a CONFLICT anywhere is FAIL; two-provider finality needs both IN_ANCESTRY;
  // SINGLE needs PublicNode IN_ANCESTRY and is never two-provider.
  for (const [id, { record: r }] of Object.entries(byId)) {
    const results = r.finality.perProvider.map((p) => p.result);
    if (r.findings.some((f) => f.code === 'RNLO_FINALITY_CONFLICT') || r.finality.disposition === 'CONFLICT') assert.equal(r.disposition, 'FAIL', id);
    if (r.finality.disposition === 'PROVIDER_REPORTED_FINALIZED') assert.deepEqual(results, ['IN_ANCESTRY', 'IN_ANCESTRY'], id);
    if (r.finality.disposition === 'PROVIDER_REPORTED_FINALIZED_SINGLE') assert.ok(results[0] === 'IN_ANCESTRY' && results[1] !== 'IN_ANCESTRY' && results[1] !== 'CONFLICT', id);
  }
});

test('R1: a second replay attributed to another provider, or not matching the report, is refused', async () => {
  // The providers' readings differ (1RPC's finalized head is below the block), so moving each
  // provider's exchanges to the other provider moves evidence between them.
  const inputs = await baseInputs([{}, { finalized: 1005 }]);
  assert.equal((await verifyGateFHypotheticalStageB(inputs)).record.finality.disposition, 'PROVIDER_REPORTED_FINALIZED_SINGLE');
  const swapped = clone(inputs);
  swapped.capture.exchanges = swapped.capture.exchanges.map((e) => ({ ...e, providerId: e.providerId === 'sepolia-1rpc' ? 'sepolia-publicnode' : 'sepolia-1rpc' }));
  const { record } = await verifyGateFHypotheticalStageB(swapped);
  assert.equal(record.disposition, 'FAIL');
  assert.equal(record.findings[0].group, 'evidence');
  assert.ok(['RNLO_REPLAY_MISMATCH', 'RNGF_EVIDENCE_INVALID'].includes(record.findings[0].code), record.findings[0].code);
  assert.equal(record.finality.disposition, 'NOT_EVALUATED');
});

test('R3: exactly the ten finding groups of spec §5; any other group is refused', () => {
  const spec = read('spec/rnnet.gate-f-sepolia-verification.v1.md');
  const section = spec.slice(spec.indexOf('The finding groups are recorded separately'), spec.indexOf('`findings[].group` is exactly one of these'));
  const listed = [...section.matchAll(/^- `(\w+)`/gm)].map((m) => m[1]);
  assert.deepEqual(listed, [...FINDING_GROUPS]);
  assert.equal(FINDING_GROUPS.length, 10);
  assert.match(spec, /`findings\[\]\.group` is exactly one of these ten names\./);
  assert.ok(!/eleven/.test(spec) && !/eleven/.test(read('tools/gate-f/record.mjs')));
  const good = byId['both-finalized'].record;
  for (const group of ['other', 'gas', 'Gas', 'GASRECORD', 'gasrecord', 'stageB', 'provider', 'status', 'preliminary', '', ' chain', 'chain ', 'finality\u0000', null, 1, ['chain'], { group: 'chain' }]) {
    const r = clone(good);
    r.findings[0].group = group;
    assert.throws(() => checkGateFRecord(r), refusedAs('RNGF_EVIDENCE_INVALID'), JSON.stringify(group));
  }
  for (const group of FINDING_GROUPS) {
    const r = clone(good);
    r.findings[0].group = group;
    checkGateFRecord(r);
  }
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
