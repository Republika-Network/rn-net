#!/usr/bin/env node
// tools/compat-live/compat-live.mjs: the controlled, READ-ONLY, keyless C6 provider compatibility
// entry point (RN-NET-03B2-C6-LIVE; docs/genesis/rn-net-03b2c6-provider-compatibility.md §8,
// spec/rnnet.compat-authorization.v1.md). DISABLED FOR LIVE NETWORK ACCESS IN THIS MILESTONE.
//
// What it is: the one command that may, after the founder's H3 authorization, send the 22 reviewed
// read-only requests of the C6 manifest once and record what the four providers answered. Here it
// is the interface and its checks, exercised only against injected, simulated transports:
//   - `compatLive({ argv, deps })` runs the whole flow with an injected transport (tests only);
//   - run as a command, it refuses at once (RNCL_LIVE_DISABLED, exit 3): it reads no file, builds
//     no transport and contacts nothing. It imports no transport, and the guard keeps it so
//     (compat-live-reaches-network; COMPAT_TRANSPORT_JOINERS empty).
//
// The flow, in order; any failure refuses the run, and nothing is sent before step 9:
//   1. exactly --authorization --endpoints --evidence-dir, each once. There is no provider, URL,
//      budget, retry, timeout or force option: all of them are fixed by the manifest;
//   2. --evidence-dir is the agreed directory (AGREED_EVIDENCE_DIR, not yet agreed);
//   3. the authorization (rnnet.compat-authorization.v1, a private 0600 file of this user) binds the
//      manifest digest the code computes, which must also be the reviewed C6_MANIFEST_SHA256; the
//      four reviewed providers at their reviewed URLs with their per-provider budget, in manifest
//      order; exactly 22 requests; this evidence directory; publication "none";
//   4. its notAfter has not passed and is at most 60 minutes ahead;
//   5. the endpoint file is exactly the reviewed config/rpc-endpoints.json (by canonical digest);
//   6. the founder approves this one run by typing `c6` and the digest's last 16 hex digits, after
//      seeing every value it is bound to;
//   7. `now` is read after the approval; the authorization is checked again at that time;
//   8. the run directory <evidence-dir>/<authorizationId>/ is created (0700): one run per
//      authorization, whatever its outcome; the authorization text is stored first;
//   9. tools/compat/run.mjs sends the manifest requests through the request policy
//      (tools/compat-live/policy.mjs), which checks every request, the expiry before each one, and
//      stores each response body as it arrives; no retry, no fallback;
//  10. transcript.json, evidence.json and report.json are written (0600, exclusive, fsync);
//  11. the run is replayed from the stored files alone and must reproduce evidence.json and
//      report.json byte for byte; the independent Python reference is the next, separate command.
// It holds no key, imports nothing of the signer, txverify, the key tool, tools/signing/,
// transaction preparation or the write path (chain-submit, tools/submit/), and sends no write
// method: none is in the manifest, and the policy refuses one (guard: compat-live-reaches-write-or-key).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCompatibility } from '../compat/run.mjs';
import { CompatAuthorizationError, readCompatAuthorization, utcSeconds } from './authorization.mjs';
import {
  AGREED_EVIDENCE_DIR,
  checkAgreedEvidenceDir,
  checkBinding,
  checkEvidenceDirectory,
  COMPAT_FLAGS,
  CompatEntryCode,
  CompatEntryError,
  createRunDirectory,
  MAX_AUTHORIZATION_AHEAD_SECONDS,
  parseArguments,
  readFileText,
  requireApproval,
  reviewedEndpoints,
  storedText,
  writeNewFile,
} from './entry.mjs';
import { createCompatPolicy } from './policy.mjs';
import { buildReport, reproduceRun, RUN_FILES } from './report.mjs';

/** False in RN-NET-03B2-C6-LIVE. A test pins it, and the command line refuses while it is false. */
export const LIVE_NETWORK_ACCESS = false;
/** Exit codes, by outcome. */
export const COMPAT_EXIT = Object.freeze({ PASS: 0, REFUSED: 2, LIVE_DISABLED: 3, BLOCKED: 4, UNRESOLVED: 5 });

const refuse = (code, detail) => {
  throw new CompatEntryError(code, detail);
};

const NEXT_STEP = Object.freeze({
  RUN: 'Next, offline and separately: python3 -I -B tools/reference/rnnet_compat_reference.py --run <run directory> --record. Then the founder reviews the sanitized evidence. Nothing is published, and a repeat is a new authorization, never a retry.',
  REFUSED: 'No C6 run was completed. A new run needs a new authorization (a new authorizationId).',
});

/**
 * The whole flow with injected dependencies (tests only; the command line refuses). Returns
 * { exitCode, outcome, code, runDirectory, reportSha256, report, message }.
 * @param {{ argv: string[], deps: { transport, now, approve, readText?, getuid?, agreed?, sleep? } }} options
 */
export async function compatLive({ argv, deps }) {
  try {
    const args = parseArguments(argv, COMPAT_FLAGS);
    checkAgreedEvidenceDir(args['evidence-dir'], Object.hasOwn(deps, 'agreed') ? deps.agreed : AGREED_EVIDENCE_DIR);
    const uid = typeof deps.getuid === 'function' ? deps.getuid() : null;
    const readText = deps.readText ?? ((path, options) => readFileText(path, options));
    const authorizationText = readText(args.authorization, { privateTo: uid });
    let parsed;
    try {
      parsed = readCompatAuthorization(authorizationText);
    } catch (error) {
      if (error instanceof CompatAuthorizationError) refuse(CompatEntryCode.AUTHORIZATION, error.detail);
      throw error;
    }
    const { authorization: a, digest } = parsed;
    checkBinding(a);
    if (a.evidenceDir !== args['evidence-dir']) refuse(CompatEntryCode.AUTHORIZATION, 'the authorization names another evidence directory');
    const clock = () => {
      const seconds = deps.now();
      if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new TypeError('now() must return Unix seconds');
      return seconds;
    };
    const notAfter = utcSeconds(a.notAfter);
    const checkedAt = clock();
    if (checkedAt > notAfter) refuse(CompatEntryCode.AUTHORIZATION_EXPIRED, `void since ${a.notAfter}`);
    if (notAfter - checkedAt > MAX_AUTHORIZATION_AHEAD_SECONDS) refuse(CompatEntryCode.AUTHORIZATION, 'notAfter is more than 60 minutes ahead');
    const endpoints = reviewedEndpoints(readText(args.endpoints, {}));

    await requireApproval(deps.approve, {
      digest,
      lines: [
        'C6 PROVIDER COMPATIBILITY (read-only, no key, no write method, no retry, no fallback, no publication)',
        `manifest ${a.manifestSha256}: exactly ${a.requestBudget} requests, one attempt each, 10 s deadline, 256 KiB limit`,
        ...a.providers.map((p) => `  ${p.id} at ${p.url}: ${p.requests} requests`),
        `authorization ${a.authorizationId}, valid until ${a.notAfter}`,
        `scope: ${a.scope}`,
        `evidence (private): ${args['evidence-dir']}/${a.authorizationId}/`,
      ],
    });

    // `now` is read AFTER the approval, immediately before the first request (as in C3).
    const now = clock();
    if (now > notAfter) refuse(CompatEntryCode.AUTHORIZATION_EXPIRED, `void since ${a.notAfter} (expired during the approval)`);
    checkEvidenceDirectory(args['evidence-dir'], uid);
    const runDirectory = createRunDirectory(args['evidence-dir'], a.authorizationId);
    writeNewFile(runDirectory, RUN_FILES.authorization, authorizationText);
    const outcome = await executeRun({ authorizationText, authorization: a, digest, endpoints, transport: deps.transport, now, clock, notAfter, runDirectory, sleep: deps.sleep });
    return result({ ...outcome, runDirectory });
  } catch (error) {
    if (error instanceof CompatEntryError) return result({ outcome: 'REFUSED', code: error.code, detail: error.message });
    throw error;
  }
}

/**
 * Steps 9 to 11 into an existing, empty-but-for-the-authorization run directory. Exported for the
 * fixture builder, which runs it over simulated providers with a fixed authorization.
 */
export async function executeRun({ authorizationText, authorization: a, digest, endpoints, transport, now, clock, notAfter, runDirectory, sleep, store = writeNewFile }) {
  if (typeof transport !== 'function') throw new TypeError('transport');
  // `store` is writeNewFile; the fixture builder replaces it to model a failing disk (review F1).
  const policy = createCompatPolicy({ providers: a.providers, notAfter, clock, keep: (name, body) => store(runDirectory, name, body), sleep });
  let run;
  let unexpected = null;
  try {
    run = await runCompatibility({ endpoints, transport: policy.wrap(transport), now });
  } catch (error) {
    unexpected = error;
  }
  // The transcript is stored whatever happened: the requests already sent stay on record.
  const transcript = policy.transcript();
  const transcriptText = storedText(transcript);
  writeNewFile(runDirectory, RUN_FILES.transcript, transcriptText);
  if (unexpected !== null) throw unexpected;
  const evidence = { ...run.evidence, authorizationId: a.authorizationId, authorizationDigest: digest, manifestSha256: a.manifestSha256 };
  const evidenceText = storedText(evidence);
  writeNewFile(runDirectory, RUN_FILES.evidence, evidenceText);
  const report = buildReport({ authorization: a, digest, authorizationText, transcript, transcriptText, evidence, evidenceText });
  const reportText = storedText(report);
  writeNewFile(runDirectory, RUN_FILES.report, reportText);

  const files = new Map(readdirSync(runDirectory).map((name) => [name, readFileSync(join(runDirectory, name))]));
  const check = await reproduceRun({ files, endpoints, readAuthorization: readCompatAuthorization });
  if (!check.reproduced) return { outcome: 'REFUSED', code: CompatEntryCode.NOT_REPRODUCED, detail: check.problems.join('; '), report };
  return { outcome: report.overall, code: null, report, reportSha256: check.reportSha256 };
}

function result({ outcome, code, detail, runDirectory = null, report = null, reportSha256 = null }) {
  const lines = [`${outcome}${code ? ` ${code}` : ''}${detail ? ` (${detail})` : ''}`];
  if (report !== null) {
    lines.push(
      `report ${reportSha256 ?? '(not reproduced)'}: XRPL ${report.verdict.xrpl}, Sepolia ${report.verdict.sepolia} (${report.sepoliaBranches.join('+')}), ${report.forwardedRequests} of ${report.requestBudget} requests sent`,
      ...report.checks.filter((c) => c.status !== 'PASS').map((c) => `  ${c.status} ${c.id}`),
    );
    if (report.policyViolation !== null) lines.push(`request policy stopped the run: ${report.policyViolation}`);
  }
  if (runDirectory !== null) lines.push(`evidence: ${runDirectory}`);
  lines.push(outcome === 'REFUSED' ? NEXT_STEP.REFUSED : NEXT_STEP.RUN);
  return Object.freeze({ exitCode: COMPAT_EXIT[outcome], outcome, code, runDirectory, reportSha256, report, message: lines.join('\n') });
}

/** The command line: refuses while LIVE_NETWORK_ACCESS is false, before reading anything. */
export function main() {
  process.stderr.write(`${CompatEntryCode.LIVE_DISABLED}: live network access is disabled in RN-NET-03B2-C6-LIVE. A separately reviewed enabling change and the founder's H3 authorization are required.\n`);
  return COMPAT_EXIT.LIVE_DISABLED;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main();

