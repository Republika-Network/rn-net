// The C6 request policy (RN-NET-03B2-C6-LIVE; hardened in C6-LIVE-ENABLE): what the transport is
// allowed to see, enforced around it independently of the run (tools/compat/run.mjs), which already
// plans one attempt per manifest request. Before a request reaches the transport, the policy checks:
//   - the provider is one of the four authorized, at its authorized URL (no substitution);
//   - the deadline and response limit are the manifest's (10 s, 256 KiB);
//   - the body is a single JSON-RPC request whose method is read-only on that network, never a
//     write method, and is the provider's next planned manifest method, in manifest order;
//   - the body is BYTE FOR BYTE the manifest request of that entry, with only the values the run
//     observes filled in, each of its own form (review F3): a validated ledger index, the pinned
//     block number (the same on both providers) or a block hash. No other key, value or order;
//   - the provider's authorized count and the 22-request total are not exceeded;
//   - the authorization has not expired (checked before EVERY request);
//   - the evidence journal has durably recorded that the request is about to be sent (N1). If it
//     cannot, the request is NOT sent: a request missing from the journal was never sent.
// It then calls the transport exactly once (no retry, no other provider), with its own deadline
// (a transport that has not answered after timeoutMs is a TIMEOUT). The response is read once
// (review F4): its status and body are each read a single time, the body must be a plain
// Uint8Array or Buffer of at most 256 KiB, and it is copied only after its size is checked, so an
// oversized or hostile body is never stored or parsed. After the first violation, or the first
// evidence write that fails, nothing more reaches the transport.
//
// Each call is recorded in the transcript (the raw transport facts the Python reference replays)
// and in the journal, and each response body is handed to the evidence store as soon as it
// arrives, so what was sent stays on record even if the run ends early.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { READ_ONLY_METHODS, TRANSPORT_CODES } from '../../packages/chain-readonly/src/index.mjs';
import { buildParams, C6_LIMITS, C6_PROVIDERS, C6_REQUESTS, C6_TOTAL_REQUESTS, C6_XRPL_RANGE, entryBytes, WRITE_METHODS } from '../compat/manifest.mjs';

export const COMPAT_TRANSCRIPT_FORMAT = 'rnnet.provider-compat-transcript.v1';
/** The transcript `error` of a call whose response could not be stored; the run stops there. */
export const STORAGE_ERROR = 'RNCL_STORAGE';
/** A request body is a few hundred bytes; anything larger is not a manifest request. */
export const MAX_REQUEST_BYTES = 4096;
/**
 * The policy's own deadline is the request's plus this grace (C6-LIVE-ENABLE review B1): the
 * transport's own timer (exactly timeoutMs) settles first, so the transport is idle before the next
 * request. The policy deadline only bounds a transport that never settles; then the C6 transport is
 * still busy and refuses the next request, which stops the run.
 */
export const POLICY_DEADLINE_GRACE_MS = 2000;
/** The code with which the C6 transport refuses a request it did not send (review B1). */
export const TRANSPORT_REFUSED = 'RNCL_TRANSPORT_REFUSED';

/**
 * The request's members, each read once, the body copied once (review N1 of C6-LIVE-ENABLE): every
 * check, the transcript and the transport see the same bytes.
 */
function snapshot(request) {
  if (request === null || typeof request !== 'object') return { providerId: null, url: null, body: null, timeoutMs: null, maxResponseBytes: null };
  const providerId = request.providerId;
  const url = request.url;
  const raw = request.body;
  const timeoutMs = request.timeoutMs;
  const maxResponseBytes = request.maxResponseBytes;
  const genuine = raw instanceof Uint8Array && ArrayBuffer.isView(raw) && raw.length <= MAX_REQUEST_BYTES;
  return Object.freeze({ providerId: typeof providerId === 'string' ? providerId : null, url: typeof url === 'string' ? url : null, body: genuine ? new Uint8Array(raw) : null, timeoutMs, maxResponseBytes });
}

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const coded = (code, message) => Object.assign(new Error(message), { code });
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameBytes = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
/** An fs error code worth keeping in the record (a fixed shape: ENOSPC, EIO, ...). */
export const errorCode = (error) => (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(error.code) ? error.code : null);

/** The file name of the n-th response (1-based call number). */
export const responseFileName = (call) => `response-${String(call).padStart(2, '0')}.bin`;

/**
 * The observed values a manifest request carries, read from its own params, or null if they are
 * not of their form. Only these vary between runs; every other byte is the manifest's.
 */
function observedState(entry, params, pinned) {
  const id = entry.providerId;
  switch (entry.form) {
    case 'tx_absent_range': {
      const max = Array.isArray(params) && isObject(params[0]) ? params[0].max_ledger : undefined;
      return Number.isSafeInteger(max) && max >= C6_XRPL_RANGE && max <= 0xffff_ffff ? { validatedSeq: { [id]: max } } : null;
    }
    case 'pin': {
      const n = Array.isArray(params) ? params[0] : undefined;
      if (typeof n !== 'string' || !QUANTITY.test(n) || (pinned.number !== null && n !== pinned.number)) return null;
      return { pinNumber: n };
    }
    case 'nonce_at_hash':
    case 'balance_at_hash':
    case 'code_at_hash':
    case 'estimate_at_hash': {
      const hash = Array.isArray(params) && isObject(params[1]) ? params[1].blockHash : undefined;
      return typeof hash === 'string' && EVM_HASH.test(hash) ? { pinHash: { [id]: hash } } : null;
    }
    default:
      return {};
  }
}

/**
 * @param {{ providers: {id, url, requests}[], notAfter: number, clock: () => number,
 *           evidence: { journal: (record: object) => void, keep: (name: string, body: Uint8Array) => void },
 *           sleep?: (ms: number) => Promise<void> }} options
 * `providers` are the authorization's; `notAfter` is in Unix seconds; `clock` returns Unix seconds.
 * `evidence.journal` appends one record durably and `evidence.keep` stores one response body
 * durably; either throws if it cannot.
 */
export function createCompatPolicy({ providers, notAfter, clock, evidence, sleep = defaultSleep }) {
  if (typeof evidence?.journal !== 'function' || typeof evidence?.keep !== 'function') throw new TypeError('evidence store');
  const authorized = new Map(providers.map((p) => [p.id, p]));
  const sent = Object.fromEntries(providers.map((p) => [p.id, 0]));
  const cursor = Object.fromEntries(providers.map((p) => [p.id, 0]));
  const pinned = { number: null };
  const transcript = [];
  /** Per call: whether the journal holds its "send" line and its outcome line. */
  const journaled = [];
  let total = 0;
  let violation = null;
  let storageFailure = null;

  const failStorage = (call, stage, error) => {
    const code = errorCode(error);
    const detail = `evidence could not be stored ${stage} call ${call}${code ? ` (${code})` : ''}`;
    if (storageFailure === null) storageFailure = detail;
    if (violation === null) violation = detail;
    return detail;
  };
  const journal = (call, record, stage) => {
    try {
      evidence.journal(record);
      return true;
    } catch (error) {
      failStorage(call, stage, error);
      return false;
    }
  };

  const check = (request) => {
    const p = authorized.get(request?.providerId);
    if (!p) return 'provider not authorized';
    const network = C6_PROVIDERS.find((x) => x.id === p.id)?.network;
    if (network === undefined) return 'provider not in the manifest';
    if (request.url !== p.url) return `${p.id}: url is not the authorized url`;
    if (request.timeoutMs !== C6_LIMITS.timeoutMs || request.maxResponseBytes !== C6_LIMITS.maxResponseBytes) return `${p.id}: limits are not the manifest's`;
    if (!(request.body instanceof Uint8Array) || request.body.length > MAX_REQUEST_BYTES) return `${p.id}: body`;
    let message;
    try {
      message = JSON.parse(Buffer.from(request.body).toString('utf8'));
    } catch {
      return `${p.id}: body is not JSON`;
    }
    const method = isObject(message) ? message.method : undefined;
    if (typeof method !== 'string' || WRITE_METHODS.includes(method) || !READ_ONLY_METHODS[network]?.includes(method)) return `${p.id}: method is not read-only`;
    const planned = C6_REQUESTS.filter((e) => e.providerId === p.id);
    if (!planned.some((e, i) => i >= cursor[p.id] && e.method === method)) return `${p.id}: ${method} is not its next planned request`;
    // Review F3: the first planned entry from the cursor on (a skipped entry was NOT_SENT) whose
    // exact bytes, given only its observed values, are the request's.
    let next = -1;
    let state = null;
    for (let i = cursor[p.id]; i < planned.length && next < 0; i += 1) {
      if (planned[i].method !== method) continue;
      const observed = observedState(planned[i], message.params, pinned);
      const expectedParams = observed === null ? null : buildParams(planned[i], observed);
      if (expectedParams !== null && sameBytes(request.body, entryBytes(planned[i], expectedParams))) {
        next = i;
        state = observed;
      }
    }
    if (next < 0) return `${p.id}: ${method} is not a planned manifest request, byte for byte`;
    const entry = planned[next];
    if (sent[p.id] >= p.requests) return `${p.id}: authorized request count exhausted`;
    if (total >= C6_TOTAL_REQUESTS) return 'authorized request total exhausted';
    const now = clock();
    if (!Number.isSafeInteger(now) || now > notAfter) return 'authorization expired before this request';
    cursor[p.id] = next + 1;
    if (entry.form === 'pin') pinned.number = state.pinNumber;
    return null;
  };

  const wrap = (inner) => async (given) => {
    const request = snapshot(given);
    const call = transcript.length + 1;
    const entry = { call, providerId: request.providerId, requestSha256: request.body !== null ? sha256(request.body) : null, status: null, responseFile: null, responseSha256: null, responseBytes: null, error: null, policy: null };
    transcript.push(entry);
    const marks = { send: false, outcome: false, refusedByTransport: false };
    journaled.push(marks);
    if (violation === null) violation = check(request);
    if (violation !== null) {
      entry.policy = violation;
      marks.outcome = journal(call, { call, event: 'refused', policy: violation }, 'for');
      throw coded('RNCL_REQUEST_POLICY', violation);
    }
    // N1: the journal records the request before it is sent. If it cannot, it is not sent.
    if (!journal(call, { call, event: 'send', providerId: entry.providerId, requestSha256: entry.requestSha256 }, 'before')) {
      entry.policy = violation;
      throw coded('RNCL_REQUEST_POLICY', violation);
    }
    marks.send = true;
    sent[request.providerId] += 1;
    total += 1;
    const outcome = () => {
      marks.outcome = journal(call, { call, event: 'outcome', error: entry.error, responseBytes: entry.responseBytes, responseFile: entry.responseFile, responseSha256: entry.responseSha256, status: entry.status }, 'after');
    };
    const timer = sleep(request.timeoutMs + POLICY_DEADLINE_GRACE_MS);
    const deadline = new Promise((_, reject) => {
      timer.then(() => reject(coded('RNLO_TIMEOUT', 'deadline')));
    });
    let response;
    try {
      // A fresh request object: the transport sees only the checked values.
      const forwarded = Object.freeze({ providerId: request.providerId, url: request.url, body: Uint8Array.from(request.body), timeoutMs: request.timeoutMs, maxResponseBytes: request.maxResponseBytes });
      response = await Promise.race([Promise.resolve().then(() => inner(forwarded)), deadline]);
    } catch (error) {
      // The C6 transport refused it without sending it: recorded as such, never as a transport
      // error, and nothing more is sent (policy and transport disagree; review B1).
      if (error?.code === TRANSPORT_REFUSED) {
        entry.error = TRANSPORT_REFUSED;
        marks.refusedByTransport = true;
        if (violation === null) violation = `the C6 transport refused call ${call}`;
        outcome();
        throw coded('RNCL_REQUEST_POLICY', violation);
      }
      // Only the transport's own fixed codes are kept; anything else is a bare TRANSPORT_ERROR.
      entry.error = TRANSPORT_CODES.includes(error?.code) ? error.code : 'TRANSPORT_ERROR';
      outcome();
      throw entry.error === 'TRANSPORT_ERROR' ? coded('RNCL_TRANSPORT', 'transport error') : coded(entry.error, entry.error);
    } finally {
      if (typeof timer.cancel === 'function') timer.cancel();
    }
    // Review F4: each member is read once, the body's size is checked before it is copied, and
    // only the copy is used from here on.
    const read = readResponse(response);
    response = null;
    if (read.error !== null) {
      entry.error = read.error;
      outcome();
      throw read.error === 'RNLO_RESPONSE_TOO_LARGE' ? coded('RNLO_RESPONSE_TOO_LARGE', 'response too large') : coded('RNCL_TRANSPORT', 'not a transport response');
    }
    const { status, body } = read;
    try {
      evidence.keep(responseFileName(call), body);
    } catch (error) {
      // A response that cannot be stored stops the run (C6-LIVE review F1): it is recorded as a
      // storage failure, never as a transport error, and nothing more reaches the transport.
      entry.error = STORAGE_ERROR;
      const detail = failStorage(call, 'at', error);
      outcome();
      throw coded('RNCL_REQUEST_POLICY', detail);
    }
    entry.status = status;
    entry.responseFile = responseFileName(call);
    entry.responseSha256 = sha256(body);
    entry.responseBytes = body.length;
    // If the outcome cannot be journaled the response is kept, but nothing more is sent.
    outcome();
    return { status, body };
  };

  /**
   * What happened to each call, from the policy's own record (N1): `recorded` (sent; its outcome
   * and body are durably stored), `sentUnrecorded` (it reached the transport, but its outcome or
   * body is not durably stored), `notSent` (refused before the transport: never sent) and
   * `notReached` (manifest requests the run never asked for: never sent).
   */
  const summary = () => {
    const recorded = [];
    const sentUnrecorded = [];
    const notSent = [];
    transcript.forEach((e, i) => {
      const m = journaled[i];
      if (!m.send || m.refusedByTransport) notSent.push(e.call);
      else if (m.outcome && e.error !== STORAGE_ERROR) recorded.push(e.call);
      else sentUnrecorded.push(e.call);
    });
    return { recorded, sentUnrecorded, notSent, notReached: Math.max(0, C6_TOTAL_REQUESTS - transcript.length), forwarded: total - journaled.filter((m) => m.refusedByTransport).length };
  };

  return Object.freeze({
    wrap,
    get violation() {
      return violation;
    },
    get storageFailure() {
      return storageFailure;
    },
    sent: () => ({ ...sent }),
    summary,
    transcript: () => ({ format: COMPAT_TRANSCRIPT_FORMAT, calls: transcript.map((e) => ({ ...e })) }),
  });
}

/**
 * Reads a transport response once: { status, body, error }. The status is an HTTP status
 * (100 to 599; review F6); the body is a plain Uint8Array or Buffer with no own length, at most
 * 256 KiB, copied only after its size is known.
 */
export function readResponse(response) {
  const bad = { status: null, body: null, error: 'TRANSPORT_ERROR' };
  if (response === null || typeof response !== 'object') return bad;
  const status = response.status;
  const raw = response.body;
  if (!Number.isSafeInteger(status) || status < 100 || status > 599) return bad;
  // A Proxy passes instanceof and the prototype check but is no typed array: copying it would read
  // its (hostile) length and elements again. ArrayBuffer.isView reads internal slots only.
  if (!(raw instanceof Uint8Array) || !ArrayBuffer.isView(raw)) return bad;
  const proto = Object.getPrototypeOf(raw);
  if ((proto !== Uint8Array.prototype && proto !== Buffer.prototype) || Object.hasOwn(raw, 'length') || Object.hasOwn(raw, 'byteLength')) return bad;
  if (raw.length > C6_LIMITS.maxResponseBytes) return { status: null, body: null, error: 'RNLO_RESPONSE_TOO_LARGE' };
  const body = new Uint8Array(raw);
  if (body.length > C6_LIMITS.maxResponseBytes) return { status: null, body: null, error: 'RNLO_RESPONSE_TOO_LARGE' };
  return { status, body, error: null };
}

/** A cancellable sleep: resolves after `ms` unless cancelled (then never). */
function defaultSleep(ms) {
  let handle;
  let cancelled = false;
  const promise = new Promise((resolve) => {
    handle = setTimeout(() => {
      if (!cancelled) resolve();
    }, ms);
  });
  promise.cancel = () => {
    cancelled = true;
    clearTimeout(handle);
  };
  return promise;
}
