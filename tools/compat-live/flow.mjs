// The C6 run flow (RN-NET-03B2-C6-LIVE; moved out of compat-live.mjs in C6-LIVE-ENABLE so that the
// command is the only file that joins it to a transport). It holds no transport and reaches no
// network file: every dependency that touches the outside (transport, clock, approval, file
// system) is injected. tools/compat-live/compat-live.mjs wires the real ones, and only while
// LIVE_NETWORK_ACCESS is true; the tests wire simulated ones.
//
// The flow, in order; any failure refuses the run, and nothing is sent before step 10:
//   1. exactly --authorization --endpoints --evidence-dir, each once. There is no provider, URL,
//      budget, retry, timeout, approval or force option: all of them are fixed;
//   2. --evidence-dir is the agreed directory (AGREED_EVIDENCE_DIR);
//   3. the authorization (rnnet.compat-authorization.v1, a private 0600 file of this user) binds the
//      manifest digest the code computes, which must also be the reviewed C6_MANIFEST_SHA256; the
//      four reviewed providers at their reviewed URLs with their per-provider budget, in manifest
//      order; exactly 22 requests; this evidence directory; publication "none";
//   4. its notAfter has not passed and is at most 60 minutes ahead;
//   5. the endpoint file is exactly the reviewed config/rpc-endpoints.json (by canonical digest);
//   6. the founder approves this one run by typing `c6` and the digest's last 16 hex digits, after
//      seeing every value it is bound to;
//   7. `now` is read after the approval; the authorization is checked again at that time;
//   8. the evidence directory is private, its run lock is free and taken (one run at a time), and
//      it has room for the whole run and passes a durable write probe;
//   9. the run directory <evidence-dir>/<authorizationId>/ is created (0700): one run per
//      authorization, whatever its outcome; the authorization text is stored, then the journal;
//  10. tools/compat/run.mjs sends the manifest requests through the request policy
//      (tools/compat-live/policy.mjs), which checks every request byte for byte, the expiry before
//      each one, journals it before it is sent, and stores each response body as it arrives;
//  11. transcript.json is written; if any evidence write failed, the run is refused here
//      (RNCL_EVIDENCE) with what was sent and recorded, sent but not recorded, and never sent;
//  12. evidence.json is written; the run is replayed from the stored files alone and must
//      reproduce it and the report byte for byte; only then is report.json written (review F5).
import { Buffer } from 'node:buffer';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runCompatibility } from '../compat/run.mjs';
import { CompatAuthorizationError, readCompatAuthorization, utcSeconds } from './authorization.mjs';
import {
  acquireRunLock,
  AGREED_EVIDENCE_DIR,
  checkAgreedEvidenceDir,
  checkBinding,
  checkDurability,
  checkEvidenceDirectory,
  COMPAT_FLAGS,
  CompatEntryCode,
  CompatEntryError,
  createRunDirectory,
  MAX_AUTHORIZATION_AHEAD_SECONDS,
  NODE_IO,
  openJournal,
  parseArguments,
  readFileText,
  requireApproval,
  reviewedEndpoints,
  storedText,
  writeNewFile,
} from './entry.mjs';
import { createCompatPolicy, errorCode } from './policy.mjs';
import { buildReport, reproduceRun, RUN_FILES } from './report.mjs';

/** Exit codes, by outcome. */
export const COMPAT_EXIT = Object.freeze({ PASS: 0, REFUSED: 2, LIVE_DISABLED: 3, BLOCKED: 4, UNRESOLVED: 5 });

const refuse = (code, detail) => {
  throw new CompatEntryError(code, detail);
};
const evidenceRefusal = (detail) => new CompatEntryError(CompatEntryCode.EVIDENCE, detail);

const NEXT_STEP = Object.freeze({
  RUN: 'Next, offline and separately: python3 -I -B tools/reference/rnnet_compat_reference.py --run <run directory> --record. Then the founder reviews the sanitized evidence. Nothing is published, and a repeat is a new authorization, never a retry.',
  REFUSED: 'No C6 run was completed. A new run needs a new authorization (a new authorizationId).',
});

/** "1-5, 7" from [1, 2, 3, 4, 5, 7]. */
const ranges = (calls) => {
  const out = [];
  for (const c of calls) {
    const last = out[out.length - 1];
    if (last && c === last[1] + 1) last[1] = c;
    else out.push([c, c]);
  }
  return out.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(', ') || 'none';
};

/** The record of what was sent, in words (N1). */
export function describeSummary(s) {
  return [
    `calls sent and durably recorded: ${ranges(s.recorded)}`,
    `calls SENT BUT NOT DURABLY RECORDED: ${ranges(s.sentUnrecorded)}`,
    `calls refused before sending (never sent): ${ranges(s.notSent)}`,
    `manifest requests never reached (never sent): ${s.notReached}`,
  ].join('; ');
}

/**
 * The whole flow with injected dependencies. Returns
 * { exitCode, outcome, code, runDirectory, reportSha256, report, summary, message }.
 * @param {{ argv: string[], deps: { transport, now, approve, readText?, getuid?, agreed?, sleep?, io?, minFreeBytes? } }} options
 */
export async function compatLive({ argv, deps }) {
  try {
    const args = parseArguments(argv, COMPAT_FLAGS);
    checkAgreedEvidenceDir(args['evidence-dir'], Object.hasOwn(deps, 'agreed') ? deps.agreed : AGREED_EVIDENCE_DIR);
    const uid = typeof deps.getuid === 'function' ? deps.getuid() : null;
    const io = deps.io ?? NODE_IO;
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
    checkEvidenceDirectory(args['evidence-dir'], uid, io);
    // The lock first, so no two runs probe or write at once (C6-LIVE-ENABLE review: probe race).
    const release = acquireRunLock(args['evidence-dir'], a.authorizationId, io);
    let outcome;
    let runDirectory = null;
    try {
      checkDurability(args['evidence-dir'], { io, minFreeBytes: deps.minFreeBytes });
      runDirectory = createRunDirectory(args['evidence-dir'], a.authorizationId, io);
      try {
        writeNewFile(runDirectory, RUN_FILES.authorization, authorizationText, io);
      } catch (error) {
        throw evidenceRefusal(`the authorization could not be stored${errorCode(error) ? ` (${errorCode(error)})` : ''}; nothing was sent`);
      }
      outcome = await executeRun({ authorizationText, authorization: a, digest, endpoints, transport: deps.transport, now, clock, notAfter, runDirectory, sleep: deps.sleep, io });
    } catch (error) {
      if (error instanceof CompatEntryError) return result({ outcome: 'REFUSED', code: error.code, detail: error.message, runDirectory });
      throw error;
    } finally {
      try {
        release();
      } catch {
        // The lock stays: the next run is refused until the founder removes it (fail closed).
      }
    }
    return result({ ...outcome, runDirectory });
  } catch (error) {
    if (error instanceof CompatEntryError) return result({ outcome: 'REFUSED', code: error.code, detail: error.message });
    throw error;
  }
}

/**
 * Steps 10 to 12 into an existing, empty-but-for-the-authorization run directory. Exported for the
 * fixture builder, which runs it over simulated providers with a fixed authorization; `store`
 * (writeNewFile) and `io` are replaced there and in the tests to model a failing disk.
 */
export async function executeRun({ authorizationText, authorization: a, digest, endpoints, transport, now, clock, notAfter, runDirectory, sleep, io = NODE_IO, store = writeNewFile }) {
  if (typeof transport !== 'function') throw new TypeError('transport');
  let journal;
  try {
    journal = openJournal(runDirectory, { authorizationDigest: digest, authorizationId: a.authorizationId }, io);
  } catch (error) {
    throw evidenceRefusal(`the journal could not be started${errorCode(error) ? ` (${errorCode(error)})` : ''}; nothing was sent`);
  }
  const policy = createCompatPolicy({ providers: a.providers, notAfter, clock, sleep, evidence: { journal: journal.append, keep: (name, body) => store(runDirectory, name, body, io) } });
  let run;
  let unexpected = null;
  try {
    run = await runCompatibility({ endpoints, transport: policy.wrap(transport), now });
  } catch (error) {
    unexpected = error;
  }
  try {
    journal.close();
  } catch {
    // every record was fsynced as it was written
  }
  // The transcript is stored whatever happened: the requests already sent stay on record.
  const transcript = policy.transcript();
  const transcriptText = storedText(transcript);
  let storageFailure = policy.storageFailure;
  try {
    store(runDirectory, RUN_FILES.transcript, transcriptText, io);
  } catch (error) {
    storageFailure ??= `transcript.json could not be stored${errorCode(error) ? ` (${errorCode(error)})` : ''}`;
  }
  const summary = policy.summary();
  if (unexpected !== null) throw unexpected;
  // N1: an incomplete record is never completed into a report.
  if (storageFailure !== null) return { outcome: 'REFUSED', code: CompatEntryCode.EVIDENCE, detail: `${storageFailure}. ${describeSummary(summary)}. No evidence.json or report.json was written`, summary };
  const evidence = { ...run.evidence, authorizationId: a.authorizationId, authorizationDigest: digest, manifestSha256: a.manifestSha256 };
  const evidenceText = storedText(evidence);
  try {
    store(runDirectory, RUN_FILES.evidence, evidenceText, io);
  } catch (error) {
    return { outcome: 'REFUSED', code: CompatEntryCode.EVIDENCE, detail: `evidence.json could not be stored${errorCode(error) ? ` (${errorCode(error)})` : ''}. ${describeSummary(summary)}. No report.json was written`, summary };
  }
  const report = buildReport({ authorization: a, digest, authorizationText, transcript, transcriptText, evidence, evidenceText });
  const reportText = storedText(report);
  // Review F5: the report is written only once the stored files, with it, reproduce.
  const files = new Map(readdirSync(runDirectory).map((name) => [name, readFileSync(join(runDirectory, name))]));
  files.set(RUN_FILES.report, Buffer.from(reportText, 'utf8'));
  const check = await reproduceRun({ files, endpoints, readAuthorization: readCompatAuthorization });
  if (!check.reproduced) return { outcome: 'REFUSED', code: CompatEntryCode.NOT_REPRODUCED, detail: `${check.problems.join('; ')}. No report.json was written`, report, summary };
  try {
    store(runDirectory, RUN_FILES.report, reportText, io);
  } catch (error) {
    return { outcome: 'REFUSED', code: CompatEntryCode.EVIDENCE, detail: `report.json could not be stored${errorCode(error) ? ` (${errorCode(error)})` : ''}. ${describeSummary(summary)}`, summary };
  }
  return { outcome: report.overall, code: null, report, reportSha256: check.reportSha256, summary };
}

function result({ outcome, code, detail, runDirectory = null, report = null, reportSha256 = null, summary = null }) {
  const lines = [`${outcome}${code ? ` ${code}` : ''}${detail ? ` (${detail})` : ''}`];
  if (report !== null) {
    lines.push(
      `report ${reportSha256 ?? '(not reproduced)'}: XRPL ${report.verdict.xrpl}, Sepolia ${report.verdict.sepolia} (${report.sepoliaBranches.join('+')}), ${report.forwardedRequests} of ${report.requestBudget} requests sent`,
      ...report.checks.filter((c) => c.status !== 'PASS').map((c) => `  ${c.status} ${c.id}`),
    );
    if (report.policyViolation !== null) lines.push(`request policy stopped the run: ${report.policyViolation}`);
  }
  if (summary !== null) lines.push(describeSummary(summary));
  if (runDirectory !== null) lines.push(`evidence: ${runDirectory}`);
  lines.push(outcome === 'REFUSED' ? NEXT_STEP.REFUSED : NEXT_STEP.RUN);
  return Object.freeze({ exitCode: COMPAT_EXIT[outcome], outcome, code, runDirectory, reportSha256, report, summary, message: lines.join('\n') });
}
