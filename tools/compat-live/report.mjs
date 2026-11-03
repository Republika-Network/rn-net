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
import { storedText } from './entry.mjs';

export const COMPAT_REPORT_FORMAT = 'rnnet.provider-compat-report.v1';
/** The files of a run directory, besides the response bodies. */
export const RUN_FILES = Object.freeze({ authorization: 'authorization.json', transcript: 'transcript.json', evidence: 'evidence.json', report: 'report.json' });

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const textSha = (text) => sha256(Buffer.from(text, 'utf8'));

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
  const policyViolation = transcript.calls.find((c) => c.policy !== null)?.policy ?? null;
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
    forwardedRequests: transcript.calls.filter((c) => c.policy === null).length,
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

/** A transport that answers each call from the transcript and the stored bodies, in order. */
export function transcriptTransport(transcript, bodies) {
  let i = 0;
  return async (request) => {
    const c = transcript.calls[i];
    i += 1;
    if (c === undefined || c.providerId !== request.providerId) throw Object.assign(new Error('replay: transcript out of order'), { code: 'RNCL_REPLAY' });
    if (c.requestSha256 !== sha256(request.body)) throw Object.assign(new Error(`replay: call ${c.call} request bytes differ`), { code: 'RNCL_REPLAY' });
    if (c.policy !== null) throw Object.assign(new Error('policy'), { code: 'RNCL_REQUEST_POLICY' });
    if (c.error !== null) throw Object.assign(new Error(c.error), { code: c.error });
    const body = bodies.get(c.responseFile);
    if (!(body instanceof Uint8Array) || sha256(body) !== c.responseSha256 || body.length !== c.responseBytes) throw Object.assign(new Error(`replay: ${c.responseFile} differs`), { code: 'RNCL_REPLAY' });
    return { status: c.status, body };
  };
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
  if ([authorizationText, transcriptText, evidenceText, reportText].includes(null)) return { reproduced: false, problems: ['a run file is missing'], reportSha256: null };
  const { authorization, digest } = readAuthorization(authorizationText);
  const transcript = JSON.parse(transcriptText);
  if (storedText(transcript) !== transcriptText) problems.push('transcript.json is not canonical');
  const bodies = new Map([...files].filter(([name]) => name.endsWith('.bin')));
  const expectedFiles = new Set([...Object.values(RUN_FILES), ...transcript.calls.filter((c) => c.responseFile !== null).map((c) => c.responseFile)]);
  if ([...files.keys()].some((name) => !expectedFiles.has(name)) || [...expectedFiles].some((name) => !files.has(name))) problems.push('the run directory does not hold exactly the expected files');
  const stored = JSON.parse(evidenceText);
  let replayed;
  try {
    replayed = await runCompatibility({ endpoints, transport: transcriptTransport(transcript, bodies), now: stored.observedAt });
  } catch (error) {
    return { reproduced: false, problems: [...problems, `replay failed: ${error.message}`], reportSha256: null };
  }
  const evidence = { ...replayed.evidence, authorizationId: authorization.authorizationId, authorizationDigest: digest, manifestSha256: authorization.manifestSha256 };
  if (storedText(evidence) !== evidenceText) problems.push('evidence.json is not what the replay produces');
  const report = buildReport({ authorization, digest, authorizationText, transcript, transcriptText, evidence, evidenceText });
  if (storedText(report) !== reportText) problems.push('report.json is not what the replay produces');
  return { reproduced: problems.length === 0, problems, reportSha256: textSha(reportText) };
}
