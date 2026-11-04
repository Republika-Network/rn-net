// TEST ONLY: the gate-F core with its fixed test stand-in subject rule (RN-NET-03B2-WP4-B1;
// WP4-B1-SEC-01 R2).
//
// Stage B does not exist. To exercise binding, replay, inclusion, finality and the timestamp
// offline, core.mjs's evaluateGateFTestStandIn accepts an approved intent with a SYNTHETIC
// preparation (the B1 signing fixtures) as a stand-in for a future Stage B subject, and nothing
// else: not a v1 rpc-read intent, not a candidate. The rule is fixed in core.mjs; no caller can
// supply one. B1 evaluates no gas, so the v2 gas member is not needed.
//
// It is not an operational interface:
//   - verify.mjs never imports it;
//   - the dependency guard refuses every importer of this file except the gate-F test and its
//     fixture builder (GATE_F_RESTRICTED; gate-f-test-seam-importer-not-allowed), and every
//     importer of core.mjs except verify.mjs and this file (gate-f-core-importer-not-allowed);
//   - it creates no intent, changes no allowlist (S1), signs, submits and writes nothing.
import { evaluateGateFTestStandIn } from './core.mjs';

/** TEST ONLY. As verifyGateF, with a synthetic-preparation intent standing in for a Stage B subject. */
export function verifyGateFHypotheticalStageB(inputs) {
  return evaluateGateFTestStandIn(inputs);
}
