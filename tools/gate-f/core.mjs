// The durable gate-F verification core (ADR-RN-020; spec rnnet.gate-f-sepolia-verification.v1
// §2–§3, §5, §6). RN-NET-03B2-WP4-B1: a PARTIAL gate F.
//
// What B1 covers:
//   - subject, binding and evidence (offline replay of the capture through the existing reader);
//   - inclusion and provider-reported finality (ADR-RN-015, unchanged);
//   - the inclusion timestamp from the linked block;
//   - the canonical record.
//
// What B1 does not cover: gas. Every gas state is NOT_EVALUATED, so no B1 record is ever
// ELIGIBLE_FOR_FOUNDER_REVIEW. Gas-record integrity, inclusion rules and accounting are WP4-B2.
//
// Pure and offline:
//   - the capture is replayed with replayTransport, which never opens a connection;
//   - no clock, environment, key, signer, write path or transport is used;
//   - classifications stay CLAIMED / UNRESOLVED, and nothing is CHAIN_PROVEN.
//
// The subject policy is a parameter of this file only. verify.mjs passes the operational policy,
// which accepts no subject until a Stage B policy is reviewed. test-seam.mjs passes the test
// policy, and only tests import it.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { checkCapture, LIMITS, Network, parseRpcJson, readEvm, ReadError, replayTransport, verifyLiveAnchor } from '../../packages/chain-readonly/src/index.mjs';
import { approvedIntent, decodeEip1559Signed, isPlainData } from '../../packages/tx-intent/src/index.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import { checkGateFRecord, GATE_F_PROVIDERS, GATE_F_RECORD_FORMAT, GATE_F_RULES, gateFRecordDigest, GateFError, SUPERSESSION_REASONS } from './record.mjs';

/** The exact members of the input set (spec §2, I1–I10). */
export const GATE_F_INPUTS = Object.freeze(['intent', 'approvedDigest', 'signedTransaction', 'txverifyRecord', 'submissionRecord', 'capture', 'liveReport', 'reviewHistory', 'preliminaryStatus', 'supersedes']);
const SUBMISSION_RECORD_DOMAIN = 'rnnet:submission-record:v1\0'; // spec rnnet.broadcast.v1 §7 (chain-submit)
const STATUS_RECORD_DOMAIN = 'rnnet:submission-status:v1\0'; // spec rnnet.broadcast.v1 §10 (chain-submit)
const SUBMISSION_FIELDS = ['authorizationDigest', 'blobSha256', 'code', 'dryRun', 'expectedTransactionHash', 'format', 'httpStatus', 'intentDigest', 'network', 'outcome', 'providerId',
  'recordedAt', 'requestSha256', 'responseSha256', 'returnedTransactionHash', 'sepolia', 'transportError', 'xrpl'];
const STATUS_FIELDS = ['attemptEntry', 'authorizationDigest', 'code', 'finding', 'format', 'live', 'liveReportSha256', 'network', 'providers', 'recordedAt', 'transactionHash'];
/** Outcomes after which the write may have reached the chain (spec rnnet.broadcast.v1 §6). NOT_SENT and REJECTED did not. */
const SUBMITTED_OUTCOMES = ['ACCEPTED_PROVISIONAL', 'UNCERTAIN'];
const TX_FIELDS = ['type', 'chainId', 'nonce', 'from', 'to', 'value', 'input', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList'];
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const MAX_TIMESTAMP = 2 ** 40 - 1;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const domainDigest = (domain, value) => `sha256:${createHash('sha256').update(domain).update(Buffer.from(canonicalBytes(value))).digest('hex')}`;
const keysAre = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const same = (a, b) => Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const copy = (v) => JSON.parse(Buffer.from(canonicalBytes(v)).toString('utf8'));
const deepFreeze = (v) => {
  if (v !== null && typeof v === 'object') {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
};

/**
 * Reads and freezes the input set. A structurally unusable set (a missing member, a wrong type, a
 * getter, a proxy, an inherited member, non-canonical data) is refused with no record
 * (RNGF_EVIDENCE_INVALID): the record could not name its inputs. Each member is read once, and
 * every later step uses the frozen copies only.
 */
function readInputs(inputs) {
  const bad = (detail) => {
    throw new GateFError('RNGF_EVIDENCE_INVALID', `inputs: ${detail}`);
  };
  if (!isPlainData(inputs) || !keysAre(inputs, GATE_F_INPUTS)) bad(`exactly ${GATE_F_INPUTS.join(', ')}`);
  const v = Object.fromEntries(GATE_F_INPUTS.map((k) => [k, inputs[k]]));
  for (const k of ['intent', 'signedTransaction', 'liveReport']) if (typeof v[k] !== 'string') bad(`${k} must be text`);
  if (typeof v.approvedDigest !== 'string' || !DIGEST.test(v.approvedDigest)) bad('approvedDigest must be sha256:<64 lowercase hex>');
  for (const k of ['txverifyRecord', 'submissionRecord', 'capture']) if (v[k] === null || typeof v[k] !== 'object' || Array.isArray(v[k])) bad(`${k} must be an object`);
  if (!Array.isArray(v.reviewHistory) || !v.reviewHistory.every((r) => r !== null && typeof r === 'object' && !Array.isArray(r))) bad('reviewHistory must be a list of review records');
  if (v.preliminaryStatus !== null && (typeof v.preliminaryStatus !== 'object' || Array.isArray(v.preliminaryStatus))) bad('preliminaryStatus must be an object or null');
  if (v.supersedes !== null && !keysAre(v.supersedes, ['record', 'reason'])) bad('supersedes must be null or {record, reason}');
  let frozen;
  try {
    frozen = deepFreeze(copy(v));
  } catch (error) {
    bad(`not canonical JSON data (${error.code ?? error.message})`);
  }
  return frozen;
}

/** The operational subject policy: no Stage B acceptance policy exists, so no subject is eligible (ADR-RN-020 V4, D1). */
export const OPERATIONAL_SUBJECT_POLICY = Object.freeze({ id: 'operational', eligible: () => false });

/**
 * Evaluates one gate-F verification. Returns { record, digest }, or throws GateFError for an unusable
 * input set or an invalid predecessor.
 */
export async function evaluateGateF(inputs, policy) {
  if (policy === null || typeof policy !== 'object' || typeof policy.eligible !== 'function') throw new TypeError('a subject policy is required');
  const v = readInputs(inputs);
  const findings = [];
  const note = (code, group, subject = null) => findings.push({ code, group, subject });

  // The record's references to its inputs (spec §6.1). They are digests, never contents.
  const subject = {
    intentDigest: v.approvedDigest,
    commitment: null,
    transactionHash: null,
    blobSha256: null,
    txverifyRecordSha256: sha256(Buffer.from(canonicalBytes(v.txverifyRecord))),
    submissionRecordDigest: domainDigest(SUBMISSION_RECORD_DOMAIN, v.submissionRecord),
  };
  const evidence = { captureSha256: sha256(Buffer.from(canonicalBytes(v.capture))), liveReportSha256: sha256(Buffer.from(v.liveReport, 'utf8')), providers: [...GATE_F_PROVIDERS] };
  let inclusion = { status: 'NOT_EVALUATED', blockHash: null, blockNumber: null, transactionIndex: null, timestamp: null };
  let finality = { disposition: 'NOT_EVALUATED', perProvider: [], classification: 'UNRESOLVED', chainInclusionProof: 'UNRESOLVED' };
  const gas = { record: 'NOT_EVALUATED', recorded: null, rules: 'NOT_EVALUATED', atInclusion: null, expected: null, gasUsed: null, accounting: 'NOT_EVALUATED', codeStateAtInclusion: 'NOT_ESTABLISHED', codeStateBasis: 'G4.3' };
  let failed = false;

  const preliminaryStatus = readPreliminaryStatus(v.preliminaryStatus);
  const supersedes = readSupersedes(v.supersedes);

  run: {
    // §3.1 Subject.
    let intent;
    try {
      const parsed = parse(v.intent);
      if (canonicalize(parsed) !== v.intent) throw Object.assign(new Error('not canonical'), { code: 'RNTX_INTENT_INVALID' });
      intent = approvedIntent(parsed, v.approvedDigest);
    } catch (error) {
      note(typeof error?.code === 'string' && error.code.startsWith('RNTX_') ? error.code : 'RNTX_INTENT_INVALID', 'subject', 'intent');
      failed = true;
      break run;
    }
    subject.commitment = intent.commitment;
    if (intent.network !== Network.SEPOLIA || intent.purpose !== 'genesis-proof-01' || !policy.eligible(intent)) {
      note('RNGF_SUBJECT_NOT_ELIGIBLE', 'subject', 'intent');
      failed = true;
      break run;
    }

    // §3.2 steps 1–3: the signed bytes, txverify recomputed (a supplied PASS is never trusted), the submission record.
    const recomputed = verifySignedTransaction({ intent, approvedDigest: v.approvedDigest, signedTransaction: v.signedTransaction });
    if (recomputed.outcome !== 'PASS') {
      note(recomputed.code ?? 'RNGF_BINDING_MISMATCH', 'binding', 'signedTransaction');
      failed = true;
      break run;
    }
    if (!same(recomputed, v.txverifyRecord)) {
      note('RNGF_BINDING_MISMATCH', 'binding', 'txverifyRecord');
      failed = true;
      break run;
    }
    subject.transactionHash = recomputed.transactionHash;
    subject.blobSha256 = recomputed.blobSha256;
    const s = v.submissionRecord;
    if (!keysAre(s, SUBMISSION_FIELDS) || s.format !== 'rnnet.submission-record.v1' || s.network !== Network.SEPOLIA || s.dryRun !== false || !SUBMITTED_OUTCOMES.includes(s.outcome)
      || s.intentDigest !== v.approvedDigest || s.blobSha256 !== recomputed.blobSha256 || s.expectedTransactionHash !== recomputed.transactionHash) {
      note('RNGF_BINDING_MISMATCH', 'binding', 'submissionRecord');
      failed = true;
      break run;
    }
    const signed = decodeEip1559Signed(Buffer.from(v.signedTransaction.slice(2), 'hex')).transaction;

    // §3.3 Evidence: the capture, its replay, and the replayed report equal to the supplied one.
    const c = v.capture;
    try {
      checkCapture(c);
    } catch {
      note('RNGF_EVIDENCE_INVALID', 'evidence', 'capture');
      failed = true;
      break run;
    }
    if (c.network !== Network.SEPOLIA || c.transactionHash !== recomputed.transactionHash || c.providers.map((p) => p.id).join(',') !== GATE_F_PROVIDERS.join(',')) {
      note('RNGF_EVIDENCE_INVALID', 'evidence', 'capture');
      failed = true;
      break run;
    }
    const providers = c.providers.map((p) => ({ id: p.id, network: c.network, url: `${p.origin}/`, operator: p.operator }));
    let report;
    let observed;
    try {
      const transport = replayTransport(c);
      report = await verifyLiveAnchor({ network: c.network, transactionHash: c.transactionHash, expectedCommitment: intent.commitment, providers, transport });
      transport.assertConsumed();
      observed = await observe(c, providers, report);
    } catch (error) {
      note(error?.code === 'RNLO_REPLAY_MISMATCH' ? 'RNLO_REPLAY_MISMATCH' : 'RNGF_EVIDENCE_INVALID', 'evidence', 'capture');
      failed = true;
      break run;
    }
    if (Buffer.from(canonicalBytes(report)).toString('utf8') !== v.liveReport) {
      note('RNGF_EVIDENCE_INVALID', 'evidence', 'liveReport');
      failed = true;
      break run;
    }
    // Evidence failures in the replayed report. A finality CONFLICT is not cut off here (§3.4
    // records it). Pending and not found are inclusion questions (§3.4), not evidence failures.
    const evidenceFailure = evidenceFailureOf(report, observed);
    if (evidenceFailure) {
      note(evidenceFailure.code, 'evidence', evidenceFailure.subject);
      failed = true;
      break run;
    }

    // §3.2 step 4: every observed provider's transaction and receipt against the signed bytes.
    for (const o of observed) {
      const t = o.transaction;
      if (!TX_FIELDS.every((k) => Object.hasOwn(t, k))) {
        note('RNGF_EVIDENCE_INVALID', 'evidence', o.id);
        failed = true;
        break run;
      }
      const fieldsMatch = TX_FIELDS.every((k) => (k === 'from' ? t.from === intent.transaction.from : same(t[k], signed[k])));
      if (t.hash !== recomputed.transactionHash || !fieldsMatch) {
        note('RNGF_BINDING_MISMATCH', 'binding', o.id);
        failed = true;
        break run;
      }
      if (o.receipt !== null && (o.receipt.transactionHash !== recomputed.transactionHash || o.receipt.contractAddress !== null || !Array.isArray(o.receipt.logs))) {
        note('RNGF_BINDING_MISMATCH', 'binding', o.id);
        failed = true;
        break run;
      }
    }
    for (const o of observed) if (o.receipt !== null && o.receipt.logs.length > 0) note('RNGF_EXECUTION_OBSERVED', 'binding', o.id);

    // §3.4 Inclusion and provider-reported finality.
    const included = observed.filter((o) => o.receipt !== null && o.transaction.blockHash !== null && o.transaction.blockHash !== undefined);
    if (included.length > 0) {
      const t = included[0].transaction;
      inclusion = { status: 'ESTABLISHED', blockHash: t.blockHash, blockNumber: t.blockNumber, transactionIndex: t.transactionIndex, timestamp: null };
    } else {
      inclusion = { status: 'NOT_ESTABLISHED', blockHash: null, blockNumber: null, transactionIndex: null, timestamp: null };
    }
    const perProvider = GATE_F_PROVIDERS.map((id) => {
      const entry = report.providers.find((p) => p.id === id);
      return { id, result: entry && entry.outcome === 'OBSERVED' ? entry.finality.finalized : 'NOT_OBSERVED' };
    });
    const [pn, other] = perProvider.map((p) => p.result);
    let disposition;
    if (pn === 'CONFLICT' || other === 'CONFLICT') disposition = 'CONFLICT';
    else if (pn === 'IN_ANCESTRY' && other === 'IN_ANCESTRY') disposition = 'PROVIDER_REPORTED_FINALIZED';
    else if (pn === 'IN_ANCESTRY') disposition = 'PROVIDER_REPORTED_FINALIZED_SINGLE';
    else disposition = 'NOT_ESTABLISHED';
    finality = { disposition, perProvider, classification: perProvider.some((p) => p.result !== 'NOT_OBSERVED') ? 'CLAIMED' : 'UNRESOLVED', chainInclusionProof: 'UNRESOLVED' };
    if (disposition === 'CONFLICT') {
      for (const p of perProvider) if (p.result === 'CONFLICT') note('RNLO_FINALITY_CONFLICT', 'finality', p.id);
      failed = true;
      break run;
    }

    // §3.5 The inclusion timestamp: only from the captured block of the receipt, linked to the
    // PublicNode walk. Without a PublicNode IN_ANCESTRY there is no linkage, so no timestamp is
    // derived (finality NOT_ESTABLISHED governs), and none is invented.
    if (inclusion.status === 'ESTABLISHED' && pn === 'IN_ANCESTRY') {
      const times = [];
      for (const o of included) {
        const t = timestampOf(o, inclusion);
        if (t === null) {
          note('RNGF_INCLUSION_TIMESTAMP_INVALID', 'inclusion', o.id);
          failed = true;
          break run;
        }
        times.push(t);
      }
      if (new Set(times).size !== 1) {
        note('RNGF_EVIDENCE_CONTRADICTORY', 'evidence', 'inclusion.timestamp');
        failed = true;
        break run;
      }
      inclusion = { ...inclusion, timestamp: times[0] };
    }

    // §4 Gas: WP4-B2. B1 evaluates no gas state; an empty review history is still reported (§4.1).
    if (inclusion.status === 'ESTABLISHED' && v.reviewHistory.length === 0) note('RNGF_RULES_AUTHORITY_ABSENT', 'gasRecord', null);
  }

  // §5. B1 never reaches rule 3 (no gas is evaluated), so the disposition is FAIL or UNRESOLVED.
  const record = {
    format: GATE_F_RECORD_FORMAT,
    rules: GATE_F_RULES,
    network: Network.SEPOLIA,
    subject,
    evidence,
    inclusion,
    finality,
    gas,
    findings,
    disposition: failed ? 'FAIL' : 'UNRESOLVED',
    preliminaryStatus,
    supersedes: null,
  };
  if (supersedes !== null) {
    if (supersedes.subject.intentDigest !== subject.intentDigest || supersedes.subject.transactionHash !== subject.transactionHash) {
      throw new GateFError('RNGF_CHAIN_INVALID', 'a successor must keep the subject of the record it supersedes');
    }
    record.supersedes = { recordDigest: supersedes.digest, reason: supersedes.reason };
  }
  const checked = deepFreeze(copy(checkGateFRecord(record)));
  if (checked.disposition === 'ELIGIBLE_FOR_FOUNDER_REVIEW') throw new Error('B1 must never produce ELIGIBLE_FOR_FOUNDER_REVIEW');
  return Object.freeze({ record: checked, digest: gateFRecordDigest(checked) });
}

/**
 * Replays the capture again, provider by provider, through readEvm (the same reader and context as
 * verifyLiveAnchor). It keeps each OBSERVED provider's transaction, receipt and the exact response
 * bytes of its eth_getBlockByHash requests. It is read-only: it reads the capture's bytes and never
 * opens a connection.
 */
async function observe(capture, providers, report) {
  const replay = replayTransport(capture);
  const out = [];
  for (const provider of providers) {
    const blocks = [];
    const tap = async (request) => {
      const response = await replay(request);
      const body = JSON.parse(Buffer.from(request.body).toString('utf8'));
      if (body.method === 'eth_getBlockByHash') blocks.push({ params: body.params, body: response.body });
      return response;
    };
    const context = { provider, transport: tap, budget: { remaining: LIMITS.maxRequestsPerProvider } };
    const entry = report.providers.find((p) => p.id === provider.id);
    try {
      const read = await readEvm(context, capture.transactionHash);
      if (entry?.outcome === 'OBSERVED') {
        const o = JSON.parse(Buffer.from(read.observation).toString('utf8'));
        out.push({ id: provider.id, transaction: o.transaction, receipt: o.receipt, blocks });
      }
    } catch (error) {
      if (!(error instanceof ReadError)) throw error;
      if (entry?.outcome === 'OBSERVED') throw new GateFError('RNGF_EVIDENCE_INVALID', 'the second replay disagrees with the report');
    }
  }
  replay.assertConsumed();
  return out;
}

// The live report's compared material (live-observation-report §7.2) without its finality member.
const MATERIAL = (o) => ({
  hash: o.transaction.hash, blockHash: o.transaction.blockHash ?? null, blockNumber: o.transaction.blockNumber ?? null, transactionIndex: o.transaction.transactionIndex ?? null,
  input: o.transaction.input ?? null, from: o.transaction.from ?? null, to: o.transaction.to ?? null, status: o.receipt === null ? null : (o.receipt.status ?? null),
});

/**
 * The first evidence failure in the replayed report, or null (spec §3.3 step 3; §3.4 for pending
 * and not found).
 *
 * The report's material includes the finality result, so a provider whose walk differs, such as the
 * unresolved 1RPC lag, makes the report DISAGREEMENT. Spec §3.4 decides finality differences:
 * PROVIDER_REPORTED_FINALIZED_SINGLE, or a recorded per-provider CONFLICT, then FAIL. So
 * RNLO_PROVIDER_DISAGREEMENT is an evidence FAIL here only when the providers disagree on the
 * rest of the material, or one finds the transaction and another does not (ADR-RN-019 §8: a
 * finality difference is reported, not averaged). Clarification proposed for the spec.
 */
function evidenceFailureOf(report, observed) {
  if (report.findings.some((f) => f.code === 'RNLO_PROVIDER_DISAGREEMENT')) {
    const notFound = report.providers.some((p) => p.outcome === 'NOT_FOUND');
    const materials = new Set(observed.map((o) => Buffer.from(canonicalBytes(MATERIAL(o))).toString('hex')));
    if (notFound || materials.size > 1) return { code: 'RNLO_PROVIDER_DISAGREEMENT', subject: 'providers' };
  }
  for (const p of report.providers) {
    if (['INCONSISTENT', 'WRONG_NETWORK', 'INVALID_RESPONSE'].includes(p.outcome)) return { code: p.error, subject: p.id };
    if (p.outcome === 'OBSERVED' && p.record.outcome !== 'PASS') {
      const codes = p.record.findings.map((x) => x.code);
      if (!(codes.length === 1 && codes[0] === 'RNAE_PENDING')) return { code: codes[0] ?? 'RNGF_EVIDENCE_INVALID', subject: p.id };
    }
  }
  return null;
}

/**
 * t_i from one provider's captured eth_getBlockByHash response for the receipt's block (§3.5).
 * Returns null unless the block is linked (hash, number, the transaction at its index) and its
 * timestamp is a canonical quantity in [0, 2^40).
 */
function timestampOf(o, inclusion) {
  const hit = o.blocks.find((b) => Array.isArray(b.params) && b.params.length === 2 && b.params[0] === inclusion.blockHash && b.params[1] === false);
  if (!hit) return null;
  let block;
  try {
    block = parseRpcJson(hit.body, LIMITS.maxResponseBytes)?.result;
  } catch {
    return null;
  }
  if (block === null || typeof block !== 'object' || block.hash !== inclusion.blockHash || block.number !== inclusion.blockNumber) return null;
  const index = Number.parseInt(inclusion.transactionIndex, 16);
  if (!Array.isArray(block.transactions) || block.transactions[index] !== o.transaction.hash) return null;
  if (typeof block.timestamp !== 'string' || !QUANTITY.test(block.timestamp)) return null;
  const t = BigInt(block.timestamp);
  return t <= BigInt(MAX_TIMESTAMP) ? Number(t) : null;
}

/** I9: referenced as preliminary only (Q5). It never changes a finding. */
function readPreliminaryStatus(status) {
  if (status === null) return null;
  if (!keysAre(status, STATUS_FIELDS) || status.format !== 'rnnet.submission-status.v1' || status.network !== Network.SEPOLIA || !(status.finding === null || typeof status.finding === 'string')) {
    throw new GateFError('RNGF_EVIDENCE_INVALID', 'preliminaryStatus is not an rnnet.submission-status.v1 record for Sepolia');
  }
  return { statusRecordDigest: domainDigest(STATUS_RECORD_DOMAIN, status), finding: status.finding };
}

/** I10: the record this one supersedes. It must itself be a valid record (spec §6.3). */
function readSupersedes(sup) {
  if (sup === null) return null;
  if (!SUPERSESSION_REASONS.includes(sup.reason)) throw new GateFError('RNGF_CHAIN_INVALID', 'supersedes.reason is not NEW_EVIDENCE, NEW_RULES_REVIEW or CORRECTION');
  let digest;
  try {
    digest = gateFRecordDigest(sup.record);
  } catch (error) {
    throw new GateFError('RNGF_CHAIN_INVALID', `the superseded record is invalid (${error.detail ?? error.message})`);
  }
  return { digest, reason: sup.reason, subject: sup.record.subject };
}
