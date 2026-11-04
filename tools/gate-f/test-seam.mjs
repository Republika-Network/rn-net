// TEST ONLY: the gate-F core with a hypothetical Stage B subject policy (RN-NET-03B2-WP4-B1).
//
// Stage B does not exist. To exercise binding, replay, inclusion, finality and the timestamp
// offline, this policy accepts an approved intent with a SYNTHETIC preparation (the B1 signing
// fixtures) as a stand-in for a future Stage B subject. B1 evaluates no gas, so the v2 gas member
// is not needed.
//
// It is not an operational interface:
//   - verify.mjs never imports it;
//   - tools/gate-f.test.mjs pins every importer of this file to the gate-F tests and the fixture
//     builder;
//   - it creates no intent, changes no allowlist (S1), signs, submits and writes nothing.
import { evaluateGateF } from './core.mjs';

const HYPOTHETICAL_STAGE_B_POLICY = Object.freeze({ id: 'test-hypothetical-stage-b', eligible: (intent) => intent.preparation?.source === 'synthetic' });

/** TEST ONLY. As verifyGateF, with a synthetic-preparation intent standing in for a Stage B subject. */
export function verifyGateFHypotheticalStageB(inputs) {
  return evaluateGateF(inputs, HYPOTHETICAL_STAGE_B_POLICY);
}
