// The durable gate-F verification core (ADR-RN-020; spec rnnet.gate-f-sepolia-verification.v1
// §2–§3, §5, §6). RN-NET-03B2-WP4-B1: a PARTIAL gate F.
//
// What B1 covers:
//   - subject, binding and evidence (offline replay of the capture through the existing reader);
//   - inclusion and provider-reported finality (ADR-RN-015, unchanged);
//   - the inclusion timestamp from the linked block;
//   - the canonical record.
//
// WP4-B2 adds the receipt gas evidence (§3.6) and gas (§4, in gas.mjs): the integrity of the
// recorded gas member, the inclusion rule set from the linked t_i, and the accounting. Gas runs
// only when inclusion is established with a linked t_i (PublicNode IN_ANCESTRY, §3.5); otherwise
// it is NOT_EVALUATED (spec §4, as clarified in WP4-B2).
//
// Pure and offline:
//   - the capture is replayed with replayTransport, which never opens a connection;
//   - no clock, environment, key, signer, write path or transport is used;
//   - classifications stay CLAIMED / UNRESOLVED, and nothing is CHAIN_PROVEN.
//
// Subject acceptance is fixed here, never supplied by a caller (WP4-B1-SEC-01 R2). No exported
// function takes an eligibility callback, a policy object or a mode argument. This file exports
// exactly two evaluators:
//   - evaluateGateFOperational: accepts no subject, because no Stage B acceptance policy exists
//     (ADR-RN-020 D1). verify.mjs is its only caller;
//   - evaluateGateFTestStandIn: TEST ONLY. It accepts an approved intent with a SYNTHETIC
//     preparation as a stand-in for a hypothetical Stage B subject, and nothing else (not v1
//     rpc-read, not a candidate). The test seam beside verify.mjs is its only caller. It is the B1
//     stand-in, unchanged: it carries no gas member, so gas is not evaluated, and the B1
//     conformance records stay byte-identical;
//   - evaluateGateFTestStandInStageB (WP4-B2): TEST ONLY. The same fixed subject rule, plus the
//     v2 preparation that hypothetical Stage B intent would carry (S1 refuses every real v2
//     intent, so none can be built), and a TEST ONLY review history whose every reviewer says so.
//     It may produce ELIGIBLE_FOR_FOUNDER_REVIEW for a synthetic vector; the operational evaluator
//     never can.
// Authority (WP4-B2 R-G7): the operational evaluator takes the review history ONLY from the
// reviewed constant SEPOLIA_GAS_RULES_REVIEW (gas.mjs verifierReviewHistory, empty today), and
// refuses an input whose reviewHistory is anything else. No input, argument, clock or provider
// answer becomes authority.
// JavaScript cannot hide an export from a file that imports this one, so the boundary is enforced
// by the repository guard (dependency-boundaries GATE_F_RESTRICTED: the core, seam and builder
// importer rules), which CI runs on every change, and pinned by tests.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { checkCapture, LIMITS, Network, parseRpcJson, readEvm, ReadError, replayTransport, verifyLiveAnchor } from '../../packages/chain-readonly/src/index.mjs';
import { approvedIntent, decodeEip1559Signed, isPlainData } from '../../packages/tx-intent/src/index.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import { checkReviewHistory, evaluateRecordedGas, isPreparationV2, verifierReviewHistory } from './gas.mjs';
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

const syntheticSubject = (intent) => intent.preparation !== null && typeof intent.preparation === 'object' && intent.preparation.source === 'synthetic' && !Object.hasOwn(intent.preparation, 'format');
const refuseInputs = (detail) => {
  throw new GateFError('RNGF_EVIDENCE_INVALID', `inputs: ${detail}`);
};

/**
 * Operational: no subject is eligible until a Stage B acceptance policy is separately authorized
 * (ADR-RN-020 V4, D1). The review history is the verifier's own (I8); a supplied reviewHistory
 * must be exactly that history, and is never used as authority.
 */
export function evaluateGateFOperational(inputs) {
  return evaluate(inputs, (v) => {
    const history = verifierReviewHistory();
    if (!same(v.reviewHistory, history)) refuseInputs("reviewHistory must be the verifier's reviewed history (SEPOLIA_GAS_RULES_REVIEW); it is never supplied authority");
    return { eligible: () => false, gasMember: (intent) => intent.preparation, history, mayBeEligible: false };
  });
}

/** TEST ONLY, B1 (see the header): a synthetic-preparation intent stands in for a Stage B subject; no gas member. */
export function evaluateGateFTestStandIn(inputs) {
  return evaluate(inputs, (v) => ({ eligible: syntheticSubject, gasMember: null, history: v.reviewHistory, mayBeEligible: false }));
}

/** TEST ONLY, B2 (see the header): the B1 stand-in subject with the v2 preparation a Stage B intent would carry. */
export async function evaluateGateFTestStandInStageB(inputs, stageBPreparation) {
  let preparation;
  try {
    preparation = deepFreeze(copy(stageBPreparation));
  } catch (error) {
    refuseInputs(`the stand-in preparation is not canonical JSON data (${error.code ?? error.message})`);
  }
  return evaluate(inputs, (v) => {
    try {
      checkReviewHistory(v.reviewHistory, { testOnly: true });
    } catch (error) {
      refuseInputs(error.message);
    }
    return { eligible: syntheticSubject, gasMember: () => preparation, history: v.reviewHistory, mayBeEligible: true };
  });
}

/**
 * Evaluates one gate-F verification with a fixed profile (not exported): the subject rule, where
 * the gas member comes from, the review history, and whether rule 3 of §5 may be reached. Returns
 * { record, digest }, or throws GateFError for an unusable input set or an invalid predecessor.
 */
async function evaluate(inputs, profileOf) {
  const v = readInputs(inputs);
  const { eligible, gasMember, history, mayBeEligible } = profileOf(v);
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
    if (intent.network !== Network.SEPOLIA || intent.purpose !== 'genesis-proof-01' || !eligible(intent)) {
      note('RNGF_SUBJECT_NOT_ELIGIBLE', 'subject', 'intent');
      failed = true;
      break run;
    }
    // §3.1 step 3: the preparation is a v2 record (format, source, rules, exact members). A v1,
    // synthetic, candidate or unknown-version preparation is not eligible; nothing falls back.
    const preparation = gasMember === null ? null : gasMember(intent);
    if (gasMember !== null && !isPreparationV2(preparation)) {
      note('RNGF_SUBJECT_NOT_ELIGIBLE', 'subject', 'preparation');
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
      // A CONFLICT the report shows is never hidden behind the evidence failure: finality is not
      // evaluated (§3.3 ends verification), but each conflicting provider is still recorded.
      for (const id of GATE_F_PROVIDERS) {
        const p = report.providers.find((e) => e.id === id && e.outcome === 'OBSERVED');
        if (p && (p.finality.finalized === 'CONFLICT' || p.finality.safe === 'CONFLICT')) note('RNLO_FINALITY_CONFLICT', 'finality', id);
      }
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
    // Any CONFLICT is FAIL, then verification ends (§3.4). perProvider holds the finalized walk; a
    // CONFLICT of a provider's safe walk is recorded as a finding on that provider (the disposition
    // stays the finalized table's), never dropped and never mapped to UNRESOLVED.
    const safeConflict = (id) => report.providers.some((p) => p.id === id && p.outcome === 'OBSERVED' && p.finality.safe === 'CONFLICT');
    const conflicted = perProvider.filter((p) => p.result === 'CONFLICT' || safeConflict(p.id));
    if (conflicted.length > 0) {
      for (const p of conflicted) note('RNLO_FINALITY_CONFLICT', 'finality', p.id);
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

    // §3.6 The receipt for gas: every included provider's receipt names the inclusion block and
    // index, and its gasUsed is a canonical quantity in the safe range, the same on every provider.
    // It is evidence (FAIL), never a rule problem. The status (0x1) is the anchor record's check (§3.3).
    let gasUsed = null;
    if (inclusion.status === 'ESTABLISHED') {
      const used = [];
      for (const o of included) {
        const r = o.receipt;
        if (r.blockHash !== inclusion.blockHash || r.blockNumber !== inclusion.blockNumber || r.transactionIndex !== inclusion.transactionIndex) {
          note('RNGF_BINDING_MISMATCH', 'binding', o.id);
          failed = true;
          break run;
        }
        if (typeof r.gasUsed !== 'string' || !QUANTITY.test(r.gasUsed) || BigInt(r.gasUsed) > BigInt(Number.MAX_SAFE_INTEGER)) {
          note('RNGF_EVIDENCE_INVALID', 'evidence', o.id);
          failed = true;
          break run;
        }
        used.push(Number(BigInt(r.gasUsed)));
      }
      if (new Set(used).size !== 1) {
        note('RNGF_EVIDENCE_CONTRADICTORY', 'evidence', 'receipt.gasUsed');
        failed = true;
        break run;
      }
      gasUsed = used[0];
    }

    // §4 Gas. An empty review history refuses every gas step (RNGF_RULES_AUTHORITY_ABSENT; the
    // record is not blamed). Otherwise gas runs only with a linked t_i: without PublicNode
    // IN_ANCESTRY there is none (§3.5), so gas stays NOT_EVALUATED and finality governs.
    if (inclusion.status === 'ESTABLISHED') {
      if (history.length === 0) note('RNGF_RULES_AUTHORITY_ABSENT', 'gasRecord', null);
      else if (preparation !== null && inclusion.timestamp !== null) {
        const result = evaluateRecordedGas({ transaction: intent.transaction, commitment: intent.commitment, preparation, history, inclusionTimestamp: inclusion.timestamp, gasUsed });
        Object.assign(gas, result.gas);
        for (const f of result.findings) note(f.code, f.group, f.subject);
        if (gas.record === 'GAS_RECORD_INVALID') failed = true;
      }
    }
  }

  // §5 precedence. Rule 3 needs every condition, and no finding that rule 2 names (only
  // GAS_RULES_CROSSED may coexist with it).
  const rule3 = !failed && inclusion.status === 'ESTABLISHED' && finality.disposition === 'PROVIDER_REPORTED_FINALIZED' && gas.record === 'VALID' && gas.accounting === 'GAS_ACCOUNTED'
    && findings.every((f) => f.code === 'GAS_RULES_CROSSED');
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
    disposition: failed ? 'FAIL' : rule3 ? 'ELIGIBLE_FOR_FOUNDER_REVIEW' : 'UNRESOLVED',
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
  // Only the TEST ONLY Stage B stand-in may reach rule 3. The operational evaluator and the B1
  // stand-in never return ELIGIBLE_FOR_FOUNDER_REVIEW (Stage B is not authorized).
  if (checked.disposition === 'ELIGIBLE_FOR_FOUNDER_REVIEW' && !mayBeEligible) throw new Error('ELIGIBLE_FOR_FOUNDER_REVIEW outside the test stand-in');
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
        // The second replay must be the reading the report digested, provider by provider (no
        // reattribution between providers).
        if (sha256(read.observation) !== entry.observationSha256 || sha256(read.material) !== entry.materialSha256) {
          throw new GateFError('RNGF_EVIDENCE_INVALID', 'the second replay disagrees with the report');
        }
        const o = JSON.parse(Buffer.from(read.observation).toString('utf8'));
        // The reader's own compared material (readers.mjs readEvm), with its finality member removed.
        const { finality: _finality, ...material } = JSON.parse(Buffer.from(read.material).toString('utf8'));
        out.push({ id: provider.id, transaction: o.transaction, receipt: o.receipt, material, blocks });
      }
    } catch (error) {
      if (!(error instanceof ReadError)) throw error;
      if (entry?.outcome === 'OBSERVED' || entry?.error !== error.code) throw new GateFError('RNGF_EVIDENCE_INVALID', 'the second replay disagrees with the report');
    }
    if (entry?.outcome === 'OBSERVED' && !out.some((o) => o.id === provider.id)) throw new GateFError('RNGF_EVIDENCE_INVALID', 'the second replay disagrees with the report');
  }
  replay.assertConsumed();
  return out;
}

/** Every per-provider outcome the live report can give (live.mjs). Anything else is refused. */
const PROVIDER_OUTCOMES = ['OBSERVED', 'NOT_FOUND', 'UNAVAILABLE', 'INCONSISTENT', 'WRONG_NETWORK', 'INVALID_RESPONSE'];

/**
 * The first evidence failure in the replayed report, or null. Spec §3.3 step 3 and the provider
 * comparison table (§3.3.1, WP4-B1-SEC-01 R1):
 *   - an outcome the report cannot give: RNGF_EVIDENCE_INVALID;
 *   - one provider OBSERVED and another NOT_FOUND (a missing observation contradicted by another
 *     provider): RNLO_PROVIDER_DISAGREEMENT, FAIL;
 *   - two OBSERVED providers whose material differs once the finality member is removed (hash,
 *     block hash, number, index, input, from, to, receipt status; the reader's own definition,
 *     readers.mjs readEvm): RNLO_PROVIDER_DISAGREEMENT, FAIL;
 *   - an INCONSISTENT, WRONG_NETWORK or INVALID_RESPONSE provider: its error, FAIL;
 *   - an observed anchor record that did not PASS, except RNAE_PENDING (§3.4): FAIL.
 * A report DISAGREEMENT that is none of these differs only in finality, and §3.4 decides it; it is
 * never averaged away (ADR-RN-019 §8). UNAVAILABLE is not a disagreement: that provider is
 * NOT_OBSERVED.
 */
function evidenceFailureOf(report, observed) {
  for (const p of report.providers) if (!PROVIDER_OUTCOMES.includes(p.outcome)) return { code: 'RNGF_EVIDENCE_INVALID', subject: p.id };
  const missing = observed.length > 0 && report.providers.some((p) => p.outcome === 'NOT_FOUND');
  const materials = new Set(observed.map((o) => Buffer.from(canonicalBytes(o.material)).toString('hex')));
  if (missing || materials.size > 1) return { code: 'RNLO_PROVIDER_DISAGREEMENT', subject: 'providers' };
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
