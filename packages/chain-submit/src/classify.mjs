// Classification of the one write (ADR-RN-019 §6; spec/rnnet.broadcast.v1.md §6).
//
// The input describes what happened to the write request, as the harness saw it:
//   { harnessRefused: code }       the harness refused before calling the transport
//   { transportError: code }       the transport threw (an RNLO_* code)
//   { status, envelope }           an HTTP response whose body parsed as strict JSON
//   { status, invalidJson: true }  an HTTP response whose body did not parse
// Only a harness refusal and RNLO_BLOCKED_ADDRESS (refused before a connection was opened) are
// NOT_SENT. Every other failure is UNCERTAIN: a connection error can come after the bytes left.
// Error text is recorded by digest, never interpreted.
//
// fail_hard (ADR-RN-019 Amendment C1, E6), checked against the rippled source at tag 3.4.1 (the
// build_version both Testnet providers reported; spec/rnnet.broadcast.v1.md §6.1):
//   - tec* is discarded under fail_hard (Transactor: "a tec result must not do anything") and is
//     neither relayed nor kept; but a tes that then fails an invariant becomes tecINVARIANT_FAILED
//     and IS applied, and the same signed blob stays valid until LastLedgerSequence. So tec* stays
//     UNCERTAIN: the response alone never proves that no copy of the blob can be included.
//   - terQUEUED cannot be returned under fail_hard (TxQ::canBeHeld refuses: telCAN_NOT_QUEUE). An
//     answer that says it anyway is inconsistent, and stays UNCERTAIN.
//   - tesSUCCESS means applied to that server's open ledger only, never inclusion or finality.
import { createHash } from 'node:crypto';
import { BroadcastCode as C, Outcome } from './codes.mjs';
import { SubmitNetwork } from './requests.mjs';

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const sha256Text = (text) => `sha256:${createHash('sha256').update(text, 'utf8').digest('hex')}`;
const ENGINE_RESULT = /^(tes|tec|tel|tem|tef|ter)[A-Z][A-Za-z0-9_]{0,63}$/;
const XRPL_HASH = /^[0-9A-F]{64}$/;
const XRPL_FLAGS = Object.freeze(['accepted', 'applied', 'broadcast', 'kept', 'queued']);
// Numeric ranges of each result class (rippled TER.h).
const CLASS_RANGE = Object.freeze({ tes: [0, 0], tec: [100, 255], tel: [-399, -300], tem: [-299, -200], tef: [-199, -100], ter: [-99, -1] });
// tefNO_TICKET (RN-NET-03B2-C2, rippled 3.4.1 source): what an already-applied Ticket-based
// transaction gets back. The Genesis intents use a Sequence, never a Ticket; it stays UNCERTAIN.
const UNCERTAIN_TEF = new Set(['tefALREADY', 'tefPAST_SEQ', 'tefNO_TICKET']);

const empty = () => ({ outcome: null, code: null, httpStatus: null, transportError: null, returnedTransactionHash: null, xrpl: null, sepolia: null });
const done = (base, outcome, code) => Object.freeze({ ...base, outcome, code });

/**
 * @param {string} network
 * @param {object} response as described above
 * @param {{ signedTransaction: string, transactionHash: string }} expected the sent blob and its recomputed hash
 * @returns {Readonly<{ outcome, code, httpStatus, transportError, returnedTransactionHash, xrpl, sepolia }>}
 */
export function classifySubmitResponse(network, response, expected) {
  const base = empty();
  if (response === null || typeof response !== 'object') return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  if (Object.hasOwn(response, 'harnessRefused')) return done(base, Outcome.NOT_SENT, C.NOT_SENT_HARNESS);
  if (Object.hasOwn(response, 'transportError')) {
    base.transportError = typeof response.transportError === 'string' ? response.transportError : 'RNLO_CONNECTION';
    return base.transportError === 'RNLO_BLOCKED_ADDRESS' ? done(base, Outcome.NOT_SENT, C.NOT_SENT_BLOCKED_ADDRESS) : done(base, Outcome.UNCERTAIN, C.UNCERTAIN_TRANSPORT);
  }
  if (!Number.isInteger(response.status)) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  base.httpStatus = response.status;
  if (response.status !== 200) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_HTTP_STATUS);
  if (response.invalidJson === true || !Object.hasOwn(response, 'envelope')) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  return network === SubmitNetwork.XRPL_TESTNET ? classifyXrpl(base, response.envelope, expected) : classifySepolia(base, response.envelope, expected);
}

function classifyXrpl(base, envelope, expected) {
  if (kind(envelope) !== 'object' || kind(envelope.result) !== 'object') return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  const r = envelope.result;
  // An RPC-level error (invalidTransaction, highFee, ...) is not interpreted: it may or may not
  // have been relayed.
  if (r.status === 'error') return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RPC_ERROR);
  if (r.status !== 'success') return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  const engine = r.engine_result;
  const code = r.engine_result_code;
  if (typeof engine !== 'string' || !ENGINE_RESULT.test(engine) || !Number.isSafeInteger(code)) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  const [low, high] = CLASS_RANGE[engine.slice(0, 3)];
  if (code < low || code > high || (engine === 'tesSUCCESS') !== (code === 0)) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  const flags = {};
  for (const flag of XRPL_FLAGS) flags[flag] = typeof r[flag] === 'boolean' ? r[flag] : null;
  base.xrpl = { engineResult: engine, engineResultCode: code, ...flags };
  if (typeof r.tx_blob !== 'string' || kind(r.tx_json) !== 'object' || typeof r.tx_json.hash !== 'string' || !XRPL_HASH.test(r.tx_json.hash)) {
    return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  }
  base.returnedTransactionHash = r.tx_json.hash;
  if (r.tx_blob !== expected.signedTransaction) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_BLOB_MISMATCH);
  if (r.tx_json.hash !== expected.transactionHash) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_HASH_MISMATCH);
  if (XRPL_FLAGS.some((flag) => flags[flag] === null)) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_FLAGS);
  const cls = engine.slice(0, 3);
  if (engine === 'tesSUCCESS') {
    const consistent = flags.accepted && flags.broadcast && !flags.queued;
    return consistent ? done(base, Outcome.ACCEPTED_PROVISIONAL, C.ACCEPTED) : done(base, Outcome.UNCERTAIN, C.UNCERTAIN_FLAGS);
  }
  // tec* may be applied and claim the fee; tefALREADY and tefPAST_SEQ mean this transaction, or
  // another with this Sequence, may already be in a ledger; terQUEUED is not confirmed under
  // fail_hard (see the header).
  if (cls === 'tes' || cls === 'tec' || UNCERTAIN_TEF.has(engine) || engine === 'terQUEUED') return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_ENGINE_RESULT);
  // tem*, tel*, other ter* and tef*: refused locally. With fail_hard nothing may be kept, queued,
  // applied or relayed; any flag saying otherwise makes the answer inconsistent.
  const silent = !flags.accepted && !flags.applied && !flags.broadcast && !flags.kept && !flags.queued;
  return silent ? done(base, Outcome.REJECTED, C.REJECTED) : done(base, Outcome.UNCERTAIN, C.UNCERTAIN_FLAGS);
}

function classifySepolia(base, envelope, expected) {
  if (kind(envelope) !== 'object' || envelope.jsonrpc !== '2.0' || envelope.id !== 1) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  const hasError = Object.hasOwn(envelope, 'error');
  const hasResult = Object.hasOwn(envelope, 'result');
  if (hasError === hasResult) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  if (hasError) {
    // Error texts are not standardized: "already known" or "nonce too low" can mean the bytes are
    // already on the network. Recorded verbatim (code) and by digest (message); never parsed.
    const e = envelope.error;
    const errorCode = kind(e) === 'object' && Number.isSafeInteger(e.code) ? e.code : null;
    const messageSha256 = kind(e) === 'object' && typeof e.message === 'string' ? sha256Text(e.message) : null;
    base.sepolia = { errorCode, errorMessageSha256: messageSha256 };
    return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RPC_ERROR);
  }
  if (typeof envelope.result !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(envelope.result)) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_RESPONSE);
  base.returnedTransactionHash = envelope.result;
  if (envelope.result !== expected.transactionHash) return done(base, Outcome.UNCERTAIN, C.UNCERTAIN_HASH_MISMATCH);
  return done(base, Outcome.ACCEPTED_PROVISIONAL, C.ACCEPTED);
}
