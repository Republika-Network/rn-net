// RN-NET-03B2-C3: the offline end-to-end rehearsal (tools/rehearsal/). Every scenario of
// fixtures/rehearsal-c3/rehearsal.json is run again here, through the real entry points with
// injected, simulated dependencies, and must give the recorded report exactly. The fixture was built
// with the Python reference verifier as a subprocess (offline-checks.sh); here the reference
// verifier is the JavaScript one, so equal reports also show that both verifiers agree.
// tools/reference/rnnet_rehearsal_reference.py reproduces the expiry decisions independently.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { approvedIntent, XRPL } from '../packages/tx-intent/src/index.mjs';
import { verifySignedTransaction } from '../txverify/src/index.mjs';
import { CLOSE_SECONDS, FIXED_SCENARIOS, PATH } from './rehearsal/build-c3-rehearsal.mjs';
import { PROFILE, REHEARSAL_FORMAT, rehearse } from './rehearsal/rehearse.mjs';

const corpus = JSON.parse(readFileSync(PATH, 'utf8'));
const jsVerifier = (intentText, approvedDigest, signedTransaction) => verifySignedTransaction({ intent: JSON.parse(intentText), approvedDigest, signedTransaction });
const report = (id) => corpus.reports.find((r) => r.id === id);
const STAGES = ['evidence', 'payload', 'preparation', 'intent', 'signing', 'verification', 'authorization', 'submission', 'duplicate'];

test('the corpus is canonical and names every scenario once', () => {
  assert.equal(readFileSync(PATH, 'utf8'), `${canonicalize(corpus)}\n`);
  assert.equal(corpus.format, REHEARSAL_FORMAT);
  assert.match(corpus.status, /^SYNTHETIC/);
  assert.equal(new Set(corpus.scenarios.map((s) => s.id)).size, corpus.scenarios.length);
  assert.deepEqual(corpus.scenarios.map((s) => s.id), corpus.reports.map((r) => r.id));
  for (const [id] of FIXED_SCENARIOS) assert.ok(report(id), id);
  assert.deepEqual(corpus.windows.map((w) => w.closeSeconds), CLOSE_SECONDS);
});

test('every scenario reproduces exactly, with the JavaScript verifier in place of the Python one', async () => {
  for (const { id, network, closeSeconds, profile } of corpus.scenarios) {
    const got = await rehearse({ id, network, closeSeconds, profile, referenceVerifier: jsVerifier });
    assert.equal(canonicalize(got), canonicalize(report(id)), id);
  }
});

test('nominal runs: every stage in order, accepted, the duplicate refused, the status INCLUDED', () => {
  for (const id of ['xrpl-3s-nominal', 'xrpl-4s-nominal', 'xrpl-5s-nominal', 'sepolia-nominal']) {
    const r = report(id);
    assert.deepEqual(r.stages.map((s) => s.stage), [...STAGES, 'status', 'assembly'], id);
    assert.equal(r.submission.outcome, 'ACCEPTED_PROVISIONAL', id);
    assert.equal(r.submission.writes, 1, id);
    assert.equal(r.submission.requests, r.network === 'xrpl:testnet' ? 7 : 13, id);
    assert.equal(r.preparation.requests, r.network === 'xrpl:testnet' ? 4 : 16, id);
    assert.deepEqual({ code: r.duplicate.code, requests: r.duplicate.requests, writes: r.duplicate.writes }, { code: 'RNBC_AUTHORIZATION_USED', requests: 0, writes: 0 }, id);
    assert.equal(r.status.finding, 'INCLUDED', id);
    assert.equal(r.verification.outcome, 'PASS', id);
    // Elapsed time per stage is measured on the simulated clock, and the stages tile the run.
    for (let i = 1; i < r.stages.length; i++) assert.ok(r.stages[i].startMs >= r.stages[i - 1].endMs, `${id} ${r.stages[i].stage}`);
    const assembly = r.assembly;
    assert.equal(assembly.payloadHex.length, 84);
    // The submission run, then the status run; the refused duplicate appended nothing.
    assert.deepEqual(assembly.submissionLog.map((e) => e.kind), ['RUN_STARTED', 'ATTEMPTING', 'RESULT', 'RUN_STARTED', 'RESOLVED']);
  }
});

test('XRPL: LastLedgerSequence is the lower provider ledger + 80, and at least 5 ledgers must remain', () => {
  assert.equal(XRPL.lastLedgerOffset, 80);
  for (const r of corpus.reports.filter((x) => x.network === 'xrpl:testnet')) {
    const prepared = r.preparation.observed.filter((e) => e.method === 'server_info').map((e) => JSON.parse(e.response).result.info.validated_ledger.seq);
    assert.equal(r.preparation.lastLedgerSequence, Math.min(...prepared) + 80, r.id);
    const sent = r.submission.outcome === 'ACCEPTED_PROVISIONAL';
    assert.equal(sent, r.submission.ledgersLeftAtPresubmit >= 5, r.id);
    if (!sent) {
      assert.equal(r.submission.code, 'RNBC_AUTHORIZATION_EXPIRED', r.id);
      assert.equal(r.submission.writes, 0, r.id);
      assert.equal(r.status, null, r.id);
    }
  }
});

test('XRPL window: the latest gate-D review that still submits, and one second more that does not', () => {
  for (const w of corpus.windows) {
    const ok = report(`xrpl-${w.closeSeconds}s-latest-intent-review`);
    const late = report(`xrpl-${w.closeSeconds}s-intent-review-one-second-too-long`);
    assert.equal(ok.profile.intentReview, w.latestIntentReviewSeconds);
    assert.equal(late.profile.intentReview, w.latestIntentReviewSeconds + 1);
    assert.equal(ok.submission.outcome, 'ACCEPTED_PROVISIONAL');
    assert.equal(ok.submission.ledgersLeftAtPresubmit, 5);
    assert.equal(late.submission.outcome, 'NOT_SENT');
    assert.equal(late.submission.ledgersLeftAtPresubmit, 4);
    // The nominal review leaves room: more than twice the nominal review at every interval.
    assert.ok(w.latestIntentReviewSeconds > 2 * PROFILE.intentReview, `${w.closeSeconds}s`);
  }
  // A slower ledger gives a longer window.
  const reviews = corpus.windows.map((w) => w.latestIntentReviewSeconds);
  assert.deepEqual([...reviews].sort((a, b) => a - b), reviews);
});

test('expiry during human approval refuses before any write, on both networks', () => {
  for (const id of ['xrpl-4s-expires-during-intent-review', 'xrpl-4s-expires-during-submit-approval', 'sepolia-not-after-passes-during-submit-approval']) {
    const r = report(id);
    assert.equal(r.submission.outcome, 'NOT_SENT', id);
    assert.equal(r.submission.code, 'RNBC_AUTHORIZATION_EXPIRED', id);
    assert.equal(r.submission.writes, 0, id);
    assert.equal(r.duplicate.code, 'RNBC_AUTHORIZATION_USED', id);
  }
});

test('Sepolia: the preparation reads are pinned to one block hash, and the fee stays capped', () => {
  const r = report('sepolia-nominal');
  const bodies = r.preparation.observed.map((e) => JSON.parse(e.request));
  const pinned = bodies.filter((b) => ['eth_getBalance', 'eth_getCode', 'eth_estimateGas'].includes(b.method) || (b.method === 'eth_getTransactionCount' && b.params[1] !== 'pending'));
  assert.equal(pinned.length, 8);
  assert.equal(new Set(pinned.map((b) => JSON.stringify(b.params[1]))).size, 1);
  const intent = JSON.parse(r.intentText);
  assert.ok(BigInt(intent.transaction.maxFeePerGas) <= 20_000_000_000n);
  assert.equal(intent.preparation.providers[0].block.hash, pinned[0].params[1].blockHash);
});

test('a modified intent or payload is refused at approval and at verification', () => {
  const r = report('xrpl-4s-nominal');
  const intent = JSON.parse(r.intentText);
  // The approved digest binds every field: a changed LastLedgerSequence or memo is another intent.
  const later = structuredClone(intent);
  later.transaction.LastLedgerSequence += 1;
  assert.throws(() => approvedIntent(later, r.approvedDigest), /digest/i);
  const memo = structuredClone(intent);
  const data = memo.transaction.Memos[0].Memo.MemoData;
  memo.transaction.Memos[0].Memo.MemoData = `${data.slice(0, -2)}${data.endsWith('00') ? '01' : '00'}`;
  assert.throws(() => approvedIntent(memo, r.approvedDigest));
  // The signed bytes verify only against the approved intent.
  assert.equal(verifySignedTransaction({ intent, approvedDigest: r.approvedDigest, signedTransaction: r.signedTransaction }).outcome, 'PASS');
  assert.notEqual(verifySignedTransaction({ intent: later, approvedDigest: r.approvedDigest, signedTransaction: r.signedTransaction }).outcome, 'PASS');
});
