// rnnet.gate-f-sepolia-verification.v1: the durable gate-F record (spec §6; ADR-RN-020 V9).
// RN-NET-03B2-WP4-B1. Pure: a strict schema check, the domain-separated digest, and the
// append-only chain check over a supplied set of records. No clock, no I/O, no network.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { isPlainData } from '../../packages/tx-intent/src/index.mjs';

export const GATE_F_RECORD_FORMAT = 'rnnet.gate-f-sepolia-verification.v1';
export const GATE_F_RULES = 'ADR-RN-020';
export const GATE_F_DIGEST_DOMAIN = 'rnnet:gate-f-sepolia-verification:v1\0';
export const GATE_F_PROVIDERS = Object.freeze(['sepolia-publicnode', 'sepolia-1rpc']);
export const SUPERSESSION_REASONS = Object.freeze(['NEW_EVIDENCE', 'NEW_RULES_REVIEW', 'CORRECTION']);
/** The eleven finding groups of spec §5. */
export const FINDING_GROUPS = Object.freeze(['subject', 'binding', 'evidence', 'inclusion', 'finality', 'gasRecord', 'gasRules', 'gasAccounting', 'review', 'chain']);
const ENUM = Object.freeze({
  inclusion: ['ESTABLISHED', 'NOT_ESTABLISHED', 'NOT_EVALUATED'],
  finality: ['PROVIDER_REPORTED_FINALIZED', 'PROVIDER_REPORTED_FINALIZED_SINGLE', 'CONFLICT', 'NOT_ESTABLISHED', 'NOT_EVALUATED'],
  walk: ['IN_ANCESTRY', 'CONFLICT', 'NOT_REACHED', 'UNRESOLVED', 'NOT_OBSERVED'],
  classification: ['CLAIMED', 'UNRESOLVED'],
  gasRecord: ['VALID', 'GAS_RECORD_INVALID', 'NOT_EVALUATED'],
  gasRules: ['SAME', 'GAS_RULES_CROSSED', 'GAS_RULES_UNRESOLVED', 'NOT_EVALUATED'],
  gasAccounting: ['GAS_ACCOUNTED', 'GAS_ACCOUNTING_MISMATCH', 'UNRESOLVED', 'NOT_EVALUATED'],
  disposition: ['FAIL', 'UNRESOLVED', 'ELIGIBLE_FOR_FOUNDER_REVIEW'],
});

/** A gate-F refusal with one RN-NET code (spec §8). */
export class GateFError extends Error {
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'GateFError';
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const CODE = /^[A-Z][A-Z0-9_]*$/;
const MAX_TIMESTAMP = 2 ** 40 - 1;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const keysAre = (v, keys) => isObject(v) && Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const orNull = (test) => (v) => v === null || test(v);
const isDigest = (v) => typeof v === 'string' && DIGEST.test(v);
const isHash = (v) => typeof v === 'string' && HASH.test(v);
const isQuantity = (v) => typeof v === 'string' && QUANTITY.test(v);
const isGas = (v) => Number.isSafeInteger(v) && v >= 0;
const isTime = (v) => Number.isSafeInteger(v) && v >= 0 && v <= MAX_TIMESTAMP;

/**
 * Checks a record against spec §6.1: exact members, types, enums, and the state rules (including
 * PR #42: CONFLICT, NOT_EVALUATED, subject nullability, the group enum). Throws
 * GateFError(RNGF_EVIDENCE_INVALID). Returns the record unchanged.
 */
export function checkGateFRecord(record) {
  const bad = (detail) => {
    throw new GateFError('RNGF_EVIDENCE_INVALID', `record: ${detail}`);
  };
  if (!isPlainData(record) || !keysAre(record, ['format', 'rules', 'network', 'subject', 'evidence', 'inclusion', 'finality', 'gas', 'findings', 'disposition', 'preliminaryStatus', 'supersedes'])) bad('members');
  if (record.format !== GATE_F_RECORD_FORMAT || record.rules !== GATE_F_RULES || record.network !== 'evm:11155111') bad('format, rules or network');

  const s = record.subject;
  if (!keysAre(s, ['intentDigest', 'commitment', 'transactionHash', 'blobSha256', 'txverifyRecordSha256', 'submissionRecordDigest'])) bad('subject members');
  if (!isDigest(s.intentDigest) || !isDigest(s.txverifyRecordSha256) || !isDigest(s.submissionRecordDigest)) bad('subject digests');
  if (!orNull(isDigest)(s.commitment) || !orNull(isHash)(s.transactionHash) || !orNull(isDigest)(s.blobSha256)) bad('subject values');

  const e = record.evidence;
  if (!keysAre(e, ['captureSha256', 'liveReportSha256', 'providers']) || !isDigest(e.captureSha256) || !isDigest(e.liveReportSha256)) bad('evidence');
  if (!Array.isArray(e.providers) || e.providers.join(',') !== GATE_F_PROVIDERS.join(',')) bad('evidence providers');

  const inc = record.inclusion;
  if (!keysAre(inc, ['status', 'blockHash', 'blockNumber', 'transactionIndex', 'timestamp']) || !ENUM.inclusion.includes(inc.status)) bad('inclusion');
  if (!orNull(isHash)(inc.blockHash) || !orNull(isQuantity)(inc.blockNumber) || !orNull(isQuantity)(inc.transactionIndex) || !orNull(isTime)(inc.timestamp)) bad('inclusion values');
  const blockKnown = inc.blockHash !== null && inc.blockNumber !== null && inc.transactionIndex !== null;
  if (inc.status === 'ESTABLISHED' && !blockKnown) bad('an established inclusion names its block');
  if (inc.status !== 'ESTABLISHED' && (inc.blockHash !== null || inc.blockNumber !== null || inc.transactionIndex !== null || inc.timestamp !== null)) bad('block values only for an established inclusion');

  const f = record.finality;
  if (!keysAre(f, ['disposition', 'perProvider', 'classification', 'chainInclusionProof']) || !ENUM.finality.includes(f.disposition)) bad('finality');
  if (f.chainInclusionProof !== 'UNRESOLVED' || !ENUM.classification.includes(f.classification)) bad('finality classification');
  if (!Array.isArray(f.perProvider)) bad('perProvider');
  if (f.disposition === 'NOT_EVALUATED') {
    if (f.perProvider.length !== 0) bad('perProvider is [] when finality is NOT_EVALUATED');
  } else {
    if (f.perProvider.length !== GATE_F_PROVIDERS.length) bad('perProvider names both providers');
    f.perProvider.forEach((p, i) => {
      if (!keysAre(p, ['id', 'result']) || p.id !== GATE_F_PROVIDERS[i] || !ENUM.walk.includes(p.result)) bad(`perProvider ${i}`);
    });
  }
  const results = f.perProvider.map((p) => p.result);
  const conflict = results.includes('CONFLICT');
  if ((f.disposition === 'CONFLICT') !== conflict) bad('finality CONFLICT if and only if a provider reports CONFLICT');
  if (f.disposition === 'PROVIDER_REPORTED_FINALIZED' && !results.every((r) => r === 'IN_ANCESTRY')) bad('finalized needs both providers IN_ANCESTRY');
  if (f.disposition === 'PROVIDER_REPORTED_FINALIZED_SINGLE' && !(results[0] === 'IN_ANCESTRY' && !['IN_ANCESTRY', 'CONFLICT'].includes(results[1]))) bad('a single-provider claim needs PublicNode IN_ANCESTRY');
  if (f.disposition === 'NOT_ESTABLISHED' && (results[0] === 'IN_ANCESTRY' || conflict)) bad('NOT_ESTABLISHED excludes PublicNode IN_ANCESTRY and CONFLICT');
  const observedWalk = results.some((r) => r !== 'NOT_OBSERVED');
  if ((f.classification === 'CLAIMED') !== observedWalk) bad('finality is CLAIMED if and only if a walk result was observed');

  const g = record.gas;
  if (!keysAre(g, ['record', 'recorded', 'rules', 'atInclusion', 'expected', 'gasUsed', 'accounting', 'codeStateAtInclusion', 'codeStateBasis'])) bad('gas members');
  if (!ENUM.gasRecord.includes(g.record) || !ENUM.gasRules.includes(g.rules) || !ENUM.gasAccounting.includes(g.accounting)) bad('gas states');
  if (g.codeStateAtInclusion !== 'NOT_ESTABLISHED' || g.codeStateBasis !== 'G4.3') bad('code state');
  if (g.recorded !== null && !(keysAre(g.recorded, ['ruleSetId', 'fork', 'reviewDigest', 'standard', 'floor', 'need', 'gasLimit']) && typeof g.recorded.ruleSetId === 'string'
    && typeof g.recorded.fork === 'string' && isDigest(g.recorded.reviewDigest) && ['standard', 'floor', 'need'].every((k) => isGas(g.recorded[k])) && g.recorded.gasLimit === 30000)) bad('gas.recorded');
  if (g.atInclusion !== null && !(keysAre(g.atInclusion, ['ruleSetId', 'standard', 'floor', 'need']) && typeof g.atInclusion.ruleSetId === 'string' && ['standard', 'floor', 'need'].every((k) => isGas(g.atInclusion[k])))) bad('gas.atInclusion');
  if (!orNull(isGas)(g.expected) || !orNull(isGas)(g.gasUsed)) bad('gas values');
  if ((g.atInclusion !== null) !== (g.rules === 'GAS_RULES_CROSSED')) bad('atInclusion only when GAS_RULES_CROSSED');
  const expected = g.rules === 'SAME' ? g.recorded?.need ?? null : g.rules === 'GAS_RULES_CROSSED' ? g.atInclusion.need : null;
  if (g.expected !== expected) bad('gas.expected');
  if (g.record !== 'VALID' && (g.rules !== 'NOT_EVALUATED' || g.accounting !== 'NOT_EVALUATED')) bad('no gas rules or accounting without a valid gas record');
  // §4.1 checks the recorded gas member, so VALID names one (implied by §4.1; clarification proposed for §6.1).
  if (g.record === 'VALID' && g.recorded === null) bad('a VALID gas record names the recorded gas member');
  if (inc.status !== 'ESTABLISHED' && (g.record !== 'NOT_EVALUATED' || g.recorded !== null || g.gasUsed !== null)) bad('gas is NOT_EVALUATED without an established inclusion');
  if (f.disposition === 'CONFLICT' && g.record !== 'NOT_EVALUATED') bad('gas is NOT_EVALUATED after a CONFLICT');

  if (!Array.isArray(record.findings)) bad('findings');
  for (const x of record.findings) {
    if (!keysAre(x, ['code', 'group', 'subject']) || typeof x.code !== 'string' || !CODE.test(x.code) || !FINDING_GROUPS.includes(x.group) || !(x.subject === null || typeof x.subject === 'string')) bad('a finding');
  }
  if (!ENUM.disposition.includes(record.disposition)) bad('disposition');
  if ((f.disposition === 'CONFLICT' || g.record === 'GAS_RECORD_INVALID') && record.disposition !== 'FAIL') bad('CONFLICT and GAS_RECORD_INVALID are FAIL');
  if (record.disposition === 'ELIGIBLE_FOR_FOUNDER_REVIEW' && !(inc.status === 'ESTABLISHED' && f.disposition === 'PROVIDER_REPORTED_FINALIZED' && g.record === 'VALID' && g.accounting === 'GAS_ACCOUNTED')) bad('eligibility needs every condition of spec §5 rule 3');

  const p = record.preliminaryStatus;
  if (p !== null && !(keysAre(p, ['statusRecordDigest', 'finding']) && isDigest(p.statusRecordDigest) && (p.finding === null || typeof p.finding === 'string'))) bad('preliminaryStatus');
  const sup = record.supersedes;
  if (sup !== null && !(keysAre(sup, ['recordDigest', 'reason']) && isDigest(sup.recordDigest) && SUPERSESSION_REASONS.includes(sup.reason))) bad('supersedes');
  return record;
}

/** "sha256:<hex>" over the gate-F domain and the record's canonical JSON (spec §6.2), after checkGateFRecord. */
export function gateFRecordDigest(record) {
  checkGateFRecord(record);
  return `sha256:${createHash('sha256').update(GATE_F_DIGEST_DOMAIN).update(Buffer.from(canonicalBytes(record))).digest('hex')}`;
}

/**
 * The append-only chain over a supplied set of records (spec §6.3). Every record must be valid. A
 * `supersedes` must name a record in the set (no dangling reference), with the same intentDigest
 * and transactionHash. At most one successor per record (no fork), no duplicate, no cycle.
 * Throws GateFError(RNGF_CHAIN_INVALID). Returns the records ordered from each root to its last
 * successor.
 */
export function checkGateFChain(records) {
  const bad = (detail) => {
    throw new GateFError('RNGF_CHAIN_INVALID', detail);
  };
  if (!Array.isArray(records) || records.length === 0) bad('a non-empty list of records is required');
  const byDigest = new Map();
  for (const r of records) {
    let d;
    try {
      d = gateFRecordDigest(r);
    } catch (error) {
      bad(`an invalid record (${error.detail ?? error.message})`);
    }
    if (byDigest.has(d)) bad('the same record twice');
    byDigest.set(d, r);
  }
  const successor = new Map();
  for (const [d, r] of byDigest) {
    if (r.supersedes === null) continue;
    const prev = byDigest.get(r.supersedes.recordDigest);
    if (!prev) bad('a supersedes names a record not in the set');
    if (prev.subject.intentDigest !== r.subject.intentDigest || prev.subject.transactionHash !== r.subject.transactionHash) bad('a successor changes the subject');
    if (successor.has(r.supersedes.recordDigest)) bad('two records supersede the same record');
    successor.set(r.supersedes.recordDigest, d);
  }
  const ordered = [];
  const seen = new Set();
  for (const [d, r] of byDigest) {
    if (r.supersedes !== null) continue;
    for (let cur = d; cur !== undefined; cur = successor.get(cur)) {
      if (seen.has(cur)) bad('a cycle');
      seen.add(cur);
      ordered.push(byDigest.get(cur));
    }
  }
  if (seen.size !== byDigest.size) bad('a cycle (records unreachable from a root)');
  return ordered;
}
