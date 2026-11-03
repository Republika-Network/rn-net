// The C6 report and its reproduction (RN-NET-03B2-C6-LIVE).
//
// rnnet.provider-compat-report.v1 is the reproducible summary of one run: what was authorized, the
// digests of every stored file, every check's status (not its free-text detail), both verdicts, the
// Sepolia branches, the compatibility candidate, the finality numbers and one overall status:
//   BLOCKED     if either network's verdict is BLOCKED;
//   PASS        if both verdicts are PASS and the request policy was never violated;
//   UNRESOLVED  otherwise.
// It is a pure function of the authorization, the transcript and the stored response bodies, so the
// JavaScript replay below and the independent Python reference (rnnet_compat_reference.py --run)
// rebuild it byte for byte from the run directory alone.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { runCompatibility } from '../compat/run.mjs';
import { JOURNAL_FILE, JOURNAL_FORMAT, journalRecords, storedText } from './entry.mjs';
import { responseFileName, STORAGE_ERROR, TRANSPORT_REFUSED } from './policy.mjs';

export const COMPAT_REPORT_FORMAT = 'rnnet.provider-compat-report.v1';
/** The files of a run directory, besides the response bodies. */
/** Written by the Python reference with --record; the only other file a run directory may hold. */
export const PYTHON_RECORD = 'python-reference.txt';
export const RUN_FILES = Object.freeze({ authorization: 'authorization.json', journal: JOURNAL_FILE, transcript: 'transcript.json', evidence: 'evidence.json', report: 'report.json' });

/** The journal a complete run leaves: its header, then the records its transcript implies (N1). */
export const expectedJournalText = (authorization, digest, transcript) =>
  [{ authorizationDigest: digest, authorizationId: authorization.authorizationId, format: JOURNAL_FORMAT }, ...journalRecords(transcript)].map((r) => `${canonicalize(r)}\n`).join('');

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const textSha = (text) => sha256(Buffer.from(text, 'utf8'));

/** The run's first policy violation, or a storage failure (which stops the run), or null. */
export function runViolation(transcript) {
  const policy = transcript.calls.find((c) => c.policy !== null)?.policy;
  if (policy !== undefined) return policy;
  const stored = transcript.calls.find((c) => c.error === STORAGE_ERROR);
  if (stored !== undefined) return `response storage failed at call ${stored.call}`;
  const refused = transcript.calls.find((c) => c.error === TRANSPORT_REFUSED);
  return refused === undefined ? null : `the C6 transport refused call ${refused.call}`;
}

/** The overall status of a run. */
export function overallStatus(verdict, policyViolation) {
  if (verdict.xrpl === 'BLOCKED' || verdict.sepolia === 'BLOCKED') return 'BLOCKED';
  if (verdict.xrpl === 'PASS' && verdict.sepolia === 'PASS' && policyViolation === null) return 'PASS';
  return 'UNRESOLVED';
}

/**
 * The report of a run, from the stored texts: `authorizationText` (exact bytes as given),
 * `authorization` and `digest` (parsed), `transcriptText`, `evidenceText`, and the evidence itself.
 */
export function buildReport({ authorization: a, digest, authorizationText, transcript, transcriptText, evidence, evidenceText }) {
  const policyViolation = runViolation(transcript);
  return {
    format: COMPAT_REPORT_FORMAT,
    authorizationId: a.authorizationId,
    authorizationDigest: digest,
    authorizationFileSha256: textSha(authorizationText),
    manifestSha256: a.manifestSha256,
    providers: a.providers.map((p) => ({ id: p.id, requests: p.requests, url: p.url })),
    requestBudget: a.requestBudget,
    publication: a.publication,
    observedAt: evidence.observedAt,
    requestCount: evidence.requestCount,
    sentPerProvider: { ...evidence.sentPerProvider },
    // What actually reached the transport: requestCount less the calls the policy refused.
    // A call the C6 transport refused never reached the network (review B1).
    forwardedRequests: transcript.calls.filter((c) => c.policy === null && c.error !== TRANSPORT_REFUSED).length,
    policyViolation,
    transcriptSha256: textSha(transcriptText),
    evidenceSha256: textSha(evidenceText),
    responses: transcript.calls.filter((c) => c.responseFile !== null).map((c) => ({ call: c.call, file: c.responseFile, bytes: c.responseBytes, sha256: c.responseSha256 })),
    checks: evidence.checks.map((c) => ({ id: c.id, status: c.status })),
    verdict: { ...evidence.verdict },
    sepoliaBranches: [...evidence.sepoliaBranches],
    compatibilityCandidate: evidence.compatibilityCandidate,
    finality: evidence.finality,
    overall: overallStatus(evidence.verdict, policyViolation),
  };
}

/**
 * A transport that answers each call from the transcript and the stored bodies, in order. Every
 * mismatch is collected in `mismatches` (the run would otherwise read a replay error as a transport
 * error and reproduce wrong evidence: C6-LIVE review F1); `used()` is the number of calls answered.
 */
export function transcriptTransport(transcript, bodies) {
  let i = 0;
  const mismatches = [];
  const mismatch = (text) => {
    mismatches.push(text);
    return Object.assign(new Error(text), { code: 'RNCL_REPLAY' });
  };
  const transport = async (request) => {
    const c = transcript.calls[i];
    i += 1;
    if (c === undefined || c.providerId !== request.providerId) throw mismatch(`replay: call ${i} is not in the transcript, or is for another provider`);
    if (c.call !== i) throw mismatch(`replay: call ${i} is numbered ${c.call}`);
    if (c.requestSha256 !== sha256(request.body)) throw mismatch(`replay: call ${i} request bytes differ`);
    if (c.policy !== null || c.error !== null) {
      if (c.status !== null || c.responseFile !== null || c.responseSha256 !== null || c.responseBytes !== null) throw mismatch(`replay: call ${i} failed but records a response`);
      if (c.policy !== null) throw Object.assign(new Error('policy'), { code: 'RNCL_REQUEST_POLICY' });
      throw Object.assign(new Error(c.error), { code: c.error });
    }
    const body = bodies.get(c.responseFile);
    if (c.responseFile !== responseFileName(i) || !(body instanceof Uint8Array) || sha256(body) !== c.responseSha256 || body.length !== c.responseBytes) throw mismatch(`replay: ${c.responseFile} differs`);
    return { status: c.status, body };
  };
  return { transport, mismatches, used: () => i };
}

/**
 * Rebuilds the evidence and the report from a run's stored files (`files`: Map name -> bytes) and
 * returns { reproduced, problems, reportSha256 }. The JavaScript classifier runs again here, over
 * the replayed responses; nothing reaches a provider.
 */
export async function reproduceRun({ files, endpoints, readAuthorization }) {
  const problems = [];
  const text = (name) => (files.has(name) ? Buffer.from(files.get(name)).toString('utf8') : null);
  const authorizationText = text(RUN_FILES.authorization);
  const transcriptText = text(RUN_FILES.transcript);
  const evidenceText = text(RUN_FILES.evidence);
  const reportText = text(RUN_FILES.report);
  const journalText = text(RUN_FILES.journal);
  if ([authorizationText, journalText, transcriptText, evidenceText, reportText].includes(null)) return { reproduced: false, problems: ['a run file is missing'], reportSha256: null };
  const { authorization, digest } = readAuthorization(authorizationText);
  const transcript = JSON.parse(transcriptText);
  if (storedText(transcript) !== transcriptText) problems.push('transcript.json is not canonical');
  if (journalText !== expectedJournalText(authorization, digest, transcript)) problems.push('journal.ndjson is not the record the transcript implies');
  const bodies = new Map([...files].filter(([name]) => name.endsWith('.bin')));
  const expectedFiles = new Set([...Object.values(RUN_FILES), ...transcript.calls.filter((c) => c.responseFile !== null).map((c) => c.responseFile)]);
  // The Python reference's own record (--record) may be present beside the run's files (review F8).
  const known = (name) => expectedFiles.has(name) || name === PYTHON_RECORD;
  if ([...files.keys()].some((name) => !known(name)) || [...expectedFiles].some((name) => !files.has(name))) problems.push('the run directory does not hold exactly the expected files');
  const stored = JSON.parse(evidenceText);
  let replayed;
  const replay = transcriptTransport(transcript, bodies);
  try {
    replayed = await runCompatibility({ endpoints, transport: replay.transport, now: stored.observedAt });
  } catch (error) {
    return { reproduced: false, problems: [...problems, `replay failed: ${error.message}`], reportSha256: null };
  }
  problems.push(...replay.mismatches);
  if (replay.used() !== transcript.calls.length) problems.push(`the replay used ${replay.used()} of ${transcript.calls.length} transcript calls`);
  const evidence = { ...replayed.evidence, authorizationId: authorization.authorizationId, authorizationDigest: digest, manifestSha256: authorization.manifestSha256 };
  if (storedText(evidence) !== evidenceText) problems.push('evidence.json is not what the replay produces');
  const report = buildReport({ authorization, digest, authorizationText, transcript, transcriptText, evidence, evidenceText });
  if (storedText(report) !== reportText) problems.push('report.json is not what the replay produces');
  return { reproduced: problems.length === 0, problems, reportSha256: textSha(reportText) };
}
