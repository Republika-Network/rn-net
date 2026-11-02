// The broadcaster's second verifier (ADR-RN-019 §3 step 5): the independent Python reference,
// tools/reference/rnnet_tx_reference.py, spawned as `python3 -I -B` with the intent, the
// approved digest and the signed bytes as arguments. It prints one canonical
// rnnet.signed-tx-verification.v1 record.
//
// The offline test preload refuses subprocesses, so the tests inject records that the Python
// reference reproduces independently (tools/reference/rnnet_broadcast_reference.py). This
// function itself is exercised by tools/broadcast/python-verifier.check.mjs, which offline-checks.sh
// runs inside the network namespace without the preload.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse } from '../../packages/canonical/src/index.mjs';

export const REFERENCE_SCRIPT = fileURLToPath(new URL('../reference/rnnet_tx_reference.py', import.meta.url));

/**
 * A reference verifier: (intentText, approvedDigest, signedTransaction) => record. The child gets
 * an empty environment, no stdin, a 30 s deadline and a 64 KiB output limit.
 * @param {{ python?: string }} options an absolute path to the Python interpreter
 */
export function pythonReferenceVerifier({ python = '/usr/bin/python3' } = {}) {
  return (intentText, approvedDigest, signedTransaction) => {
    for (const arg of [intentText, approvedDigest, signedTransaction]) if (typeof arg !== 'string' || arg.length > 65_536) throw new TypeError('reference verifier arguments');
    const out = execFileSync(python, ['-I', '-B', REFERENCE_SCRIPT, 'verify', intentText, approvedDigest, signedTransaction], {
      env: {}, stdio: ['ignore', 'pipe', 'pipe'], timeout: 30_000, maxBuffer: 65_536, encoding: 'utf8',
    });
    if (!out.endsWith('\n')) throw new Error('reference verifier output');
    return parse(out.slice(0, -1));
  };
}
