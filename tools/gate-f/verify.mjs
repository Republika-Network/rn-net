// The operational durable gate-F verifier (ADR-RN-020; spec rnnet.gate-f-sepolia-verification.v1).
// RN-NET-03B2-WP4-B1: offline and partial (no gas; see core.mjs).
//
// The subject policy is fixed. No Stage B acceptance policy exists (ADR-RN-020 D1), so every
// subject is refused at §3.1: a candidate, a candidate digest presented as an approval, a v1 or
// synthetic preparation, an unsupported preparation (S1). The record is a FAIL.
//
// No command line, no I/O, no network, no clock, no key. It reports evidence and findings only:
// it approves, signs, submits and publishes nothing.
import { evaluateGateFOperational } from './core.mjs';

export { GATE_F_INPUTS } from './core.mjs';
export { checkGateFChain, checkGateFRecord, FINDING_GROUPS, GATE_F_DIGEST_DOMAIN, GATE_F_PROVIDERS, GATE_F_RECORD_FORMAT, GATE_F_RULES, gateFRecordDigest, GateFError, SUPERSESSION_REASONS } from './record.mjs';

/** Verifies one gate-F input set (spec §2) and returns { record, digest }. Throws GateFError for an unusable set. */
export function verifyGateF(inputs) {
  return evaluateGateFOperational(inputs);
}
