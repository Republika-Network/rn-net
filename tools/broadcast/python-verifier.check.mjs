// Checks the broadcaster's Python verifier as the broadcaster calls it: a real `python3 -I -B`
// subprocess. Run by tools/ci/offline-checks.sh inside the network namespace, without the test
// preload (which refuses subprocesses). Offline; it reads only committed fixtures.
//   node tools/broadcast/python-verifier.check.mjs [/absolute/path/to/python3]
import { readFileSync } from 'node:fs';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import { pythonReferenceVerifier } from '../submit/python-verifier.mjs';

const dir = new URL('../../fixtures/signing-b1/', import.meta.url);
const golden = JSON.parse(readFileSync(new URL('golden.json', dir), 'utf8'));
const verify = pythonReferenceVerifier(process.argv[2] ? { python: process.argv[2] } : {});
const cases = [];
for (const signed of Object.values(golden.signed)) {
  const intentText = readFileSync(new URL(signed.intentFile, dir), 'utf8').replace(/\n$/, '');
  cases.push([intentText, signed.intentDigest, signed.signedTransaction]);
  // A flipped final hex digit, and a non-canonical intent text.
  const last = signed.signedTransaction.at(-1);
  cases.push([intentText, signed.intentDigest, signed.signedTransaction.slice(0, -1) + (last === '0' ? '1' : '0')]);
  cases.push([` ${intentText}`, signed.intentDigest, signed.signedTransaction]);
}
let failed = 0;
for (const [intentText, digest, blob] of cases) {
  const python = verify(intentText, digest, blob);
  let intent;
  try {
    intent = JSON.parse(intentText);
  } catch {
    intent = null;
  }
  const expected = intentText.startsWith(' ')
    ? { format: 'rnnet.signed-tx-verification.v1', network: null, intentDigest: null, blobSha256: null, transactionHash: null, outcome: 'FAIL', code: 'RNTX_INTENT_INVALID' }
    : verifySignedTransaction({ intent, approvedDigest: digest, signedTransaction: blob });
  if (canonicalize(python) !== canonicalize(expected)) {
    failed += 1;
    console.error(`python verifier differs: ${blob.slice(0, 16)}...`);
  }
}
console.log(`python verifier: ${cases.length - failed}/${cases.length} subprocess records agree`);
process.exit(failed ? 1 : 0);
