// Dual-chain comparison (spec/rnnet.anchor-record.v1.md §6): one XRPL Testnet observation and one
// Ethereum Sepolia observation, each checked by its own adapter, then compared. RN-NET-03A has no
// authenticated inclusion proof, so CHAIN_PROVEN is never produced.
import { checkCommitment, freeze, statement } from './common.mjs';
import { verifyEvmObservation } from './evm.mjs';
import { verifyXrplObservation } from './xrpl.mjs';

export const REPORT_FORMAT = 'rnnet.anchor-verification-report.v1';
export const Conclusion = Object.freeze({
  PAYLOAD_MATCH: 'PAYLOAD_MATCH',
  RECORDS_CONSISTENT: 'RECORDS_CONSISTENT',
  CHAIN_INCLUSION_UNVERIFIED: 'CHAIN_INCLUSION_UNVERIFIED',
  /** Reserved: requires authenticated inclusion proofs, which RN-NET-03A does not verify. */
  CHAIN_PROVEN: 'CHAIN_PROVEN',
});

const BASIS = Object.freeze({
  inclusion: 'No authenticated proof of inclusion was verified on either network.',
  evidence: 'An anchor binds a commitment; it says nothing about whether the evidence is true or the event happened.',
});

/**
 * @param {{ xrpl?: Uint8Array | null, evm?: Uint8Array | null }} observations the bytes of each
 *   network's rnnet.anchor-observation.v1, each checked only as that network
 * @param {string} expectedCommitment sha256:<64 lowercase hex>
 * @returns {Readonly<object>} an rnnet.anchor-verification-report.v1 report
 */
export function verifyDualAnchor(observations, expectedCommitment) {
  const expected = checkCommitment(expectedCommitment);
  if (observations === null || typeof observations !== 'object') throw new TypeError('observations must be an object.');
  const { xrpl, evm } = observations; // read once
  const records = {};
  if (xrpl !== undefined && xrpl !== null) records.xrpl = verifyXrplObservation(xrpl, expected);
  if (evm !== undefined && evm !== null) records.evm = verifyEvmObservation(evm, expected);

  const findings = [];
  for (const slot of ['xrpl', 'evm']) if (!records[slot]) findings.push({ code: 'RNAD_MISSING_RECORD', severity: 'error', subject: slot });
  for (const slot of ['xrpl', 'evm']) {
    if (records[slot] && records[slot].outcome !== 'PASS') findings.push({ code: 'RNAD_RECORD_NOT_PASSED', severity: 'error', subject: slot });
  }
  const payloads = [records.xrpl?.payload, records.evm?.payload];
  if (payloads.every(Boolean) && payloads[0].hex !== payloads[1].hex) findings.push({ code: 'RNAD_PAYLOAD_DIFFERS', severity: 'error', subject: 'pair' });

  const conclusions = [];
  if (payloads.every((p) => p?.matchesExpected) && payloads[0].hex === payloads[1].hex) conclusions.push(Conclusion.PAYLOAD_MATCH);
  if (records.xrpl?.outcome === 'PASS' && records.evm?.outcome === 'PASS') conclusions.push(Conclusion.RECORDS_CONSISTENT);
  conclusions.push(Conclusion.CHAIN_INCLUSION_UNVERIFIED);

  const outcomes = Object.values(records).map((r) => r.outcome);
  let outcome = 'FAIL';
  if (conclusions.includes(Conclusion.PAYLOAD_MATCH) && conclusions.includes(Conclusion.RECORDS_CONSISTENT)) outcome = 'PASS';
  else if (outcomes.length === 2 && outcomes.includes('UNSUPPORTED') && !outcomes.includes('FAIL')) outcome = 'UNSUPPORTED';

  return freeze({
    format: REPORT_FORMAT,
    expectedCommitment: expected,
    outcome,
    conclusions,
    records,
    findings,
    statements: [statement('chainInclusion', 'UNRESOLVED', BASIS.inclusion), statement('anchoredEvidence', 'UNRESOLVED', BASIS.evidence)],
  });
}
