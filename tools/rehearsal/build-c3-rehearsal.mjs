// Builds fixtures/rehearsal-c3/rehearsal.json: the offline end-to-end rehearsal of Genesis Proof 01
// (RN-NET-03B2-C3), with the elapsed time of every stage on a simulated clock and the XRPL expiry
// window measured at 3, 4 and 5 seconds per ledger.
//
//   node tools/rehearsal/build-c3-rehearsal.mjs <python3>           # check the committed file
//   node tools/rehearsal/build-c3-rehearsal.mjs <python3> --write   # write it (refuses to overwrite)
//
// The reference verifier is the independent Python reference, run as a real subprocess
// (tools/submit/python-verifier.mjs), so this runs without the test preload: offline-checks.sh runs
// it inside the network namespace. tools/rehearsal.test.mjs replays every scenario with the
// JavaScript verifier and must get the same report; tools/reference/rnnet_rehearsal_reference.py
// reproduces the expiry and window decisions and re-verifies every signed transaction.
//
// For each XRPL ledger interval, the latest founder review time at gate D that still lets the
// submission go out is found by search (monotone: a longer review only moves the pre-submit read
// later), and recorded with the run one second longer, which must be refused before any write.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { pythonReferenceVerifier } from '../submit/python-verifier.mjs';
import { PROFILE, REHEARSAL_FORMAT, rehearse, S, X } from './rehearse.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/rehearsal-c3/rehearsal.json', import.meta.url));
export const CLOSE_SECONDS = Object.freeze([3, 4, 5]);
const SEARCH_LIMIT_SECONDS = 600;

/** The fixed scenarios: [id, network, closeSeconds, profile overrides]. */
export const FIXED_SCENARIOS = Object.freeze([
  ...CLOSE_SECONDS.map((close) => [`xrpl-${close}s-nominal`, X, close, {}]),
  // The founder takes 5 minutes at gate D: the window is gone before the pre-submit reads.
  ['xrpl-4s-expires-during-intent-review', X, 4, { intentReview: 300 }],
  // The window passes while the founder approves the submission itself.
  ['xrpl-4s-expires-during-submit-approval', X, 4, { submitApproval: 200 }],
  ['sepolia-nominal', S, 4, {}],
  // Sepolia validity is the authorization's notAfter (written 3000 s ahead): it passes during approval.
  ['sepolia-not-after-passes-during-submit-approval', S, 4, { submitApproval: 3001 }],
]);

/** The latest gate-D review (whole seconds) that still submits at `close` seconds per ledger. */
export async function latestReview(close, referenceVerifier) {
  const sends = async (review) => (await rehearse({ id: `search-${close}s`, network: X, closeSeconds: close, profile: { intentReview: review }, referenceVerifier, duplicate: false })).submission.outcome === 'ACCEPTED_PROVISIONAL';
  let low = 0;
  let high = SEARCH_LIMIT_SECONDS;
  if (!(await sends(low)) || (await sends(high))) throw new Error(`search bounds at ${close}s`);
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (await sends(mid)) low = mid;
    else high = mid;
  }
  return low;
}

export async function build(referenceVerifier) {
  const windows = [];
  const scenarios = [];
  for (const close of CLOSE_SECONDS) {
    const review = await latestReview(close, referenceVerifier);
    windows.push({ closeSeconds: close, latestIntentReviewSeconds: review, nominalIntentReviewSeconds: PROFILE.intentReview });
    scenarios.push([`xrpl-${close}s-latest-intent-review`, X, close, { intentReview: review }]);
    scenarios.push([`xrpl-${close}s-intent-review-one-second-too-long`, X, close, { intentReview: review + 1 }]);
  }
  const all = [...FIXED_SCENARIOS, ...scenarios];
  const reports = [];
  for (const [id, network, closeSeconds, profile] of all) reports.push(await rehearse({ id, network, closeSeconds, profile, referenceVerifier }));
  const document = {
    format: REHEARSAL_FORMAT,
    status: 'SYNTHETIC: simulated providers, a simulated clock and public test keys; nothing was read from or sent to a network',
    scenarios: all.map(([id, network, closeSeconds, profile]) => ({ id, network, closeSeconds, profile })),
    windows,
    reports,
  };
  return `${canonicalize(document)}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [python, flag] = process.argv.slice(2);
  if (typeof python !== 'string' || !python.startsWith('/')) throw new Error('usage: build-c3-rehearsal.mjs <absolute path to python3> [--write]');
  const text = await build(pythonReferenceVerifier({ python }));
  if (flag === '--write') {
    if (existsSync(PATH)) throw new Error(`${PATH} exists; remove it first to rebuild`);
    writeFileSync(PATH, text, { flag: 'wx' });
    console.log(`wrote ${PATH}`);
  } else if (!existsSync(PATH) || readFileSync(PATH, 'utf8') !== text) {
    console.error('fixtures/rehearsal-c3/rehearsal.json is not current: rebuild with --write');
    process.exitCode = 1;
  } else {
    console.log('fixtures/rehearsal-c3/rehearsal.json is current (Python reference verifier as a subprocess)');
  }
}
