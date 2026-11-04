// RN-NET-03B2-WP3-R1: the Stage A v2 preparation candidate envelope (never an intent).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { canonicalBytes } from '../../canonical/src/index.mjs';
import {
  approvedIntent,
  CANDIDATE_DIGEST_DOMAIN,
  CANDIDATE_FORMAT,
  candidateDigest,
  INTENT_DIGEST_DOMAIN,
  makeIntent,
  makePreparationCandidate,
  sepoliaAnchorTemplate,
  verifiedPreparationCandidate,
} from '../src/index.mjs';

const C = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
const T = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86';
const record = { format: 'rnnet.tx-preparation.v2', source: 'rpc-read', rules: 'ADR-RN-018-C2', observedAt: 1, gas: {}, providers: [] };
const candidate = (o = {}) => ({
  format: CANDIDATE_FORMAT,
  network: 'evm:11155111',
  purpose: 'genesis-proof-01',
  commitment: C,
  transaction: sepoliaAnchorTemplate(C, { nonce: '0x0', from: T, maxFeePerGas: '0x77359401' }),
  preparation: record,
  ...o,
});
const invalid = (fn) => assert.throws(fn, (e) => e.code === 'RNTX_INTENT_INVALID');
const raw = (domain, v) => `sha256:${createHash('sha256').update(domain).update(canonicalBytes(v)).digest('hex')}`;

test('the candidate digest uses its own domain, never the intent domain', () => {
  assert.equal(CANDIDATE_DIGEST_DOMAIN, 'rnnet:tx-preparation-v2-candidate:v1\0');
  const d = candidateDigest(candidate());
  assert.equal(d, raw(CANDIDATE_DIGEST_DOMAIN, candidate()));
  assert.notEqual(d, raw(INTENT_DIGEST_DOMAIN, candidate()));
  assert.deepEqual(verifiedPreparationCandidate(candidate(), d), makePreparationCandidate(candidate()));
  assert.ok(Object.isFrozen(makePreparationCandidate(candidate())));
  assert.throws(() => verifiedPreparationCandidate(candidate(), raw(INTENT_DIGEST_DOMAIN, candidate())), (e) => e.code === 'RNTX_INTENT_DIGEST_MISMATCH');
});

test('a candidate is not an intent, and an intent is not a candidate', () => {
  invalid(() => makeIntent(candidate()));
  invalid(() => approvedIntent(candidate(), candidateDigest(candidate())));
  invalid(() => makeIntent({ ...candidate(), format: 'rnnet.unsigned-tx-intent.v1' })); // S1 refuses the v2 preparation
  invalid(() => makePreparationCandidate({ ...candidate(), format: 'rnnet.unsigned-tx-intent.v1' }));
});

test('the envelope is strict: members, network, purpose, v2 top level, the anchor transaction', () => {
  const v1 = { format: 'rnnet.tx-preparation.v1', source: 'rpc-read', rules: 'ADR-RN-018', observedAt: 1, providers: [] };
  for (const bad of [
    { network: 'xrpl:testnet' }, { purpose: 'other' }, { commitment: 'sha256:x' }, { preparation: v1 },
    { preparation: { ...record, extra: 1 } }, { preparation: { source: 'synthetic' } }, { preparation: { ...record, format: 'rnnet.tx-preparation.v9' } },
    { transaction: { ...candidate().transaction, gas: '0x7531' } }, { transaction: { ...candidate().transaction, to: '0x1111111111111111111111111111111111111111' } },
    { extra: true },
  ]) invalid(() => makePreparationCandidate(candidate(bad)));
  const { preparation, ...missing } = candidate();
  assert.ok(preparation);
  invalid(() => makePreparationCandidate(missing));
  invalid(() => makePreparationCandidate(new Proxy(candidate(), {})));
});
