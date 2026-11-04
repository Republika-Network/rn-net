// RN-NET S1: the strict preparation-format allowlist, at the shared intent boundary and at every
// downstream consumer. A correctly recomputed approved digest never overrides it. Offline only:
// synthetic fixture keys, temporary directories and recorded exchanges.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { canonicalBytes, canonicalize } from '../packages/canonical/src/index.mjs';
import { checkHandoff } from '../packages/broadcast-handoff/src/index.mjs';
import { entryDigest } from '../packages/chain-submit/src/index.mjs';
import { approvedIntent, INTENT_DIGEST_DOMAIN, intentDigest, makeIntent } from '../packages/tx-intent/src/index.mjs';
import { preparationProblem } from '../packages/tx-intent/src/intent.mjs';
import { verifySignedTransaction } from '../txverify/src/index.mjs';
import { FILE as B3_FILE, withLog } from './broadcast/build-b3-fixtures.mjs';
import { replayTextTransport } from './broadcast/simulated.mjs';
import { build, cases, PATH } from './s1/build-s1-cases.mjs';
import { runBroadcast } from './submit/broadcaster.mjs';
import { runStatusCheck } from './submit/status.mjs';

const ROOT = new URL('../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');
const SEP = 'evm:11155111';
const golden = JSON.parse(read('fixtures/signing-b1/golden.json'));
const SEP_INTENT = JSON.parse(read('fixtures/signing-b1/sepolia-intent.json'));
const SEP_SIGNED = golden.signed.sepolia;
const S1 = Object.fromEntries(cases().map((c) => [c.id, c]));
const V2 = S1['v2-record'].preparation;
const V9 = S1['v9-record'].preparation;

/** The digest an attacker could recompute for any intent: the same domain and canonical bytes, no checks. */
const rawDigest = (intent) => `sha256:${createHash('sha256').update(INTENT_DIGEST_DOMAIN).update(canonicalBytes(intent)).digest('hex')}`;
const withPrep = (preparation, base = SEP_INTENT) => ({ ...base, preparation });
const invalid = (fn) => assert.throws(fn, (e) => e.code === 'RNTX_INTENT_INVALID', 'RNTX_INTENT_INVALID');

test('the committed S1 cases are current, and makeIntent reaches every hand-stated decision', () => {
  assert.equal(read('fixtures/s1-preparation/cases.json'), build());
  const doc = JSON.parse(readFileSync(PATH, 'utf8'));
  assert.ok(doc.cases.length >= 25 && doc.cases.some((c) => c.accept) && doc.cases.some((c) => !c.accept));
  const base = { 'xrpl:testnet': JSON.parse(read('fixtures/signing-b1/xrpl-intent.json')), [SEP]: SEP_INTENT };
  for (const c of doc.cases) {
    const intent = { ...base[c.network], preparation: c.preparation };
    if (c.accept) assert.doesNotThrow(() => makeIntent(intent), c.id);
    else invalid(() => makeIntent(intent));
    assert.equal(preparationProblem(c.preparation) === null, c.accept, c.id);
  }
});

test('getters, proxies, inherited members and a missing preparation are refused', () => {
  const getter = {};
  Object.defineProperty(getter, 'source', { enumerable: true, get: () => 'synthetic' });
  const inherited = Object.create({ source: 'synthetic' });
  const proxied = new Proxy({ source: 'synthetic' }, {});
  for (const p of [getter, inherited, proxied]) invalid(() => makeIntent(withPrep(p)));
  const { preparation, ...missing } = SEP_INTENT;
  assert.ok(preparation);
  invalid(() => makeIntent(missing));
});

test('a correctly recomputed approved digest never overrides the allowlist (approvedIntent, intentDigest)', () => {
  for (const p of [V2, V9, S1['v1-with-gas'].preparation, S1['synthetic-with-format'].preparation]) {
    const intent = withPrep(p);
    const digest = rawDigest(intent);
    invalid(() => approvedIntent(intent, digest)); // INVALID, not DIGEST_MISMATCH: the format is checked first
    invalid(() => intentDigest(intent));
  }
  // The accepted historical shapes keep their digests exactly.
  assert.equal(intentDigest(SEP_INTENT), SEP_SIGNED.intentDigest);
  assert.equal(rawDigest(SEP_INTENT), SEP_SIGNED.intentDigest);
});

// The signer and the keytool sign entry are tested in tools/signing.test.mjs and
// tools/keytool.test.mjs, the files the guard allows to import them.

test('txverify and the broadcast hand-off refuse an unsupported preparation with a correct digest', () => {
  for (const p of [V2, V9]) {
    const intent = withPrep(p);
    const digest = rawDigest(intent);
    const record = verifySignedTransaction({ intent, approvedDigest: digest, signedTransaction: SEP_SIGNED.signedTransaction });
    assert.equal(record.outcome, 'FAIL');
    assert.equal(record.code, 'RNTX_INTENT_INVALID');
    const passing = verifySignedTransaction({ intent: SEP_INTENT, approvedDigest: SEP_SIGNED.intentDigest, signedTransaction: SEP_SIGNED.signedTransaction });
    assert.equal(passing.outcome, 'PASS');
    invalid(() => checkHandoff({ intent, approvedDigest: digest, signedTransaction: SEP_SIGNED.signedTransaction, verifications: [passing, passing] }));
  }
});

// --- the broadcaster and status ------------------------------------------------------------------

const b3 = JSON.parse(readFileSync(B3_FILE, 'utf8'));

test('broadcaster: an unsupported preparation is NOT_SENT before any request or write', async () => {
  const c = b3.submit.find((x) => x.inputs.intent.includes('"network":"evm:11155111"') && x.expected.writes === 1);
  assert.ok(c, 'a Sepolia case that writes');
  for (const p of [V2, V9]) {
    const original = JSON.parse(c.inputs.intent);
    const intent = { ...original, preparation: p };
    const inputs = { ...c.inputs, intent: canonicalize(intent), approvedDigest: rawDigest(intent) };
    let sent = 0;
    const transport = async () => {
      sent += 1;
      throw new Error('no request may be sent');
    };
    transport.remaining = () => 0;
    // The Python verifier refuses the same way (rnnet_tx_reference.intent_ok, S1): it returns the same record.
    const referenceVerifier = () => verifySignedTransaction({ intent, approvedDigest: inputs.approvedDigest, signedTransaction: inputs.signedTransaction });
    const { result } = await withLog(c.logBefore, (dirs) => runBroadcast({
      inputs,
      environment: { endpoints: b3.endpoints, now: () => c.now, referenceVerifier, transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir, ...c.environmentExtra },
    }));
    assert.equal(result.outcome, 'NOT_SENT');
    assert.equal(result.code, 'RNTX_INTENT_INVALID');
    assert.equal(result.requests, 0);
    assert.equal(result.writes, 0);
    assert.equal(sent, 0);
  }
});

test('status: an unsupported preparation is refused at makeIntent, before any request, even when the log names its digest', async () => {
  const c = b3.statusChecks.find((x) => x.inputs.intent.includes('"network":"evm:11155111"'));
  assert.ok(c, 'a Sepolia status case');
  for (const p of [V2, V9]) {
    const intent = { ...JSON.parse(c.inputs.intent), preparation: p };
    // The logged attempt and the authorization name this intent's own digest, so the digest
    // comparison would pass: only the allowlist in makeIntent can refuse it.
    const oldAttempt = entryDigest(c.logBefore.find((e) => e.kind === 'ATTEMPTING'));
    const relabelled = c.logBefore.map((e) => (e.kind === 'ATTEMPTING' ? { ...e, intentDigest: rawDigest(intent) } : e));
    const attempt = relabelled.find((e) => e.kind === 'ATTEMPTING');
    const logBefore = relabelled.map((e) => (e.attemptEntry === oldAttempt ? { ...e, attemptEntry: entryDigest(attempt) } : e));
    const authorization = canonicalize({ ...JSON.parse(c.inputs.authorization), attemptEntry: entryDigest(attempt) });
    let sent = 0;
    const transport = async () => {
      sent += 1;
      throw new Error('no request may be sent');
    };
    const { result } = await withLog(logBefore, (dirs) => runStatusCheck({
      inputs: { ...c.inputs, authorization, intent: canonicalize(intent) },
      environment: { endpoints: b3.endpoints, now: () => c.now, transport, logDir: dirs.logDir, evidenceDir: dirs.evidenceDir },
    }));
    assert.equal(result.code, 'RNBC_STATUS_MISMATCH');
    assert.equal(sent, 0);
  }
  assert.equal(typeof replayTextTransport, 'function');
});
