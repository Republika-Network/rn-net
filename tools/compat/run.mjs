// The C6 compatibility run over an INJECTED transport (RN-NET-03B2-C6-PREP). OFFLINE ONLY in this
// milestone: there is no command line, no file access and no transport here, and the guard keeps
// tools/compat/ from reaching one (compat-reaches-network). Tests drive it with simulated
// providers (tools/compat/simulated.mjs) and recorded transcripts (fixtures/compat-c6).
//
// What it does, in manifest order:
//   - each of the 22 requests is sent at most once (no retry) to its own provider only (no
//     fallback), with the manifest's exact bytes, the 10 s deadline and the 256 KiB limit;
//   - a request whose dependency was not observed is NOT_SENT, never sent in another form;
//   - once a provider reports the wrong network, nothing more is sent to it;
//   - every response is reduced to a sanitized observation (no headers, no addresses of the
//     machine, error messages truncated to printable ASCII with URLs and IPv4 addresses masked);
//   - the raw bodies are returned separately, for private storage only.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { parseRpcJson, TRANSPORT_CODES } from '../../packages/chain-readonly/src/index.mjs';
import { classify } from './classify.mjs';
import { buildParams, C6_BUDGET, C6_LIMITS, C6_PIN_DEPTH, C6_REQUESTS, C6_TOTAL_REQUESTS, checkManifest, entryBytes, providerOf } from './manifest.mjs';

export const C6_EVIDENCE_FORMAT = 'rnnet.provider-compat-evidence.v1';
/** Outcomes of one planned request. */
export const Outcome = Object.freeze({
  OK: 'OK',
  RPC_ERROR: 'RPC_ERROR',
  HTTP_STATUS: 'HTTP_STATUS',
  RATE_LIMITED: 'RATE_LIMITED',
  TIMEOUT: 'TIMEOUT',
  TRANSPORT_ERROR: 'TRANSPORT_ERROR',
  TOO_LARGE: 'TOO_LARGE',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  NOT_SENT: 'NOT_SENT',
});

const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const DATA = /^0x(?:[0-9a-f]{2}){0,64}$/;
const XRPL_HASH = /^[0-9A-F]{64}$/;
const BUILD = /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[a-z0-9]{1,16}(?:\.\d{1,4})?)?$/;
const LEDGERS = /^(?:empty|[0-9,-]{1,256})$/;
const STATE = /^[a-z_]{1,32}$/;
const RPC_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const safeInt = (v) => (Number.isSafeInteger(v) ? v : null);
const match = (re, v) => (typeof v === 'string' && re.test(v) ? v : null);
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/**
 * An error message as evidence: printable ASCII; URLs, host:port, IPv6 and IPv4 addresses and
 * long opaque tokens masked (a 0x-prefixed hex value is kept: it is chain data); at most 160
 * characters. The order is fixed; tools/reference/rnnet_compat_reference.py applies the same.
 */
export function sanitizeMessage(value) {
  if (typeof value !== 'string') return null;
  // Cut before masking, so the masks run on at most 512 characters (C6 re-check N2), and drop a
  // trailing run cut in the middle, so no partial address survives the cut.
  let ascii = Array.from(value.length > 2048 ? value.slice(0, 2048) : value, (ch) => (ch >= ' ' && ch <= '~' ? ch : '?')).join('');
  if (ascii.length > 512) ascii = ascii.slice(0, 512).replace(/\S*$/, '');
  // IPv4 before IPv6, so an IPv4-mapped address (::ffff:a.b.c.d) is masked whole (C6 re-check N1).
  return ascii
    .replace(/[A-Za-z][A-Za-z0-9+.-]*:\/\/\S*/g, '<url>')
    .replace(/\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:\d{1,5}\b/g, '<host>')
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '<ip>')
    .replace(/[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}/g, (m) => (/[0-9A-Fa-f]/.test(m) ? '<ip>' : m))
    .replace(/[A-Za-z0-9_+\/=-]{32,}/g, (m) => (/^0x[0-9a-fA-F]+$/.test(m) ? m : '<token>'))
    .slice(0, 160);
}

/** The block members the run keeps, or null. */
function blockOf(result) {
  if (!isObject(result)) return null;
  return { number: match(QUANTITY, result.number), hash: match(EVM_HASH, result.hash), timestamp: match(QUANTITY, result.timestamp), baseFeePerGas: match(QUANTITY, result.baseFeePerGas) };
}

/** The sanitized observation of an OK result, by form. */
function observe(entry, result) {
  switch (entry.form) {
    case 'server_info': {
      const info = isObject(result.info) ? result.info : {};
      const v = isObject(info.validated_ledger) ? info.validated_ledger : {};
      return {
        networkId: safeInt(info.network_id),
        buildVersion: match(BUILD, info.build_version),
        serverState: match(STATE, info.server_state),
        completeLedgers: match(LEDGERS, info.complete_ledgers),
        validatedSeq: safeInt(v.seq),
        validatedHash: match(XRPL_HASH, v.hash),
        validatedAge: safeInt(v.age),
      };
    }
    case 'tx_absent_range':
      return { found: true };
    case 'chain_id':
      return { chainId: match(QUANTITY, result) };
    case 'head':
    case 'pin':
    case 'finalized':
      return { block: blockOf(result) };
    case 'code_at_hash':
      return { value: match(DATA, result) };
    default:
      return { value: match(QUANTITY, result) };
  }
}

/** The outcome, rpc error and observation of one response (status, body). */
export function interpretResponse(entry, response) {
  const network = providerOf(entry).network;
  const out = { outcome: null, httpStatus: response.status, rpcError: null, observed: null };
  if (response.body.length > C6_LIMITS.maxResponseBytes) return { ...out, outcome: Outcome.TOO_LARGE };
  if (response.status === 429) return { ...out, outcome: Outcome.RATE_LIMITED };
  let envelope;
  try {
    envelope = parseRpcJson(response.body, C6_LIMITS.maxResponseBytes);
  } catch {
    return { ...out, outcome: response.status === 200 ? Outcome.INVALID_RESPONSE : Outcome.HTTP_STATUS };
  }
  if (network === 'xrpl:testnet') {
    const result = isObject(envelope) ? envelope.result : undefined;
    if (isObject(result) && result.status === 'error') {
      return { ...out, outcome: Outcome.RPC_ERROR, rpcError: { error: match(RPC_NAME, result.error), code: safeInt(result.error_code), searchedAll: typeof result.searched_all === 'boolean' ? result.searched_all : null, message: sanitizeMessage(result.error_message) } };
    }
    if (response.status !== 200) return { ...out, outcome: Outcome.HTTP_STATUS };
    if (!isObject(result) || result.status !== 'success') return { ...out, outcome: Outcome.INVALID_RESPONSE };
    return { ...out, outcome: Outcome.OK, observed: observe(entry, result) };
  }
  const wellFormed = isObject(envelope) && envelope.jsonrpc === '2.0' && envelope.id === 1;
  if (wellFormed && Object.hasOwn(envelope, 'error')) {
    const e = isObject(envelope.error) ? envelope.error : {};
    return { ...out, outcome: Outcome.RPC_ERROR, rpcError: { error: null, code: safeInt(e.code), searchedAll: null, message: sanitizeMessage(e.message) } };
  }
  if (response.status !== 200) return { ...out, outcome: Outcome.HTTP_STATUS };
  if (!wellFormed || !Object.hasOwn(envelope, 'result')) return { ...out, outcome: Outcome.INVALID_RESPONSE };
  return { ...out, outcome: Outcome.OK, observed: observe(entry, envelope.result) };
}

const SEPOLIA_CHAIN = '0xaa36a7';

/**
 * One C6 run. `endpoints` is the parsed config/rpc-endpoints.json; `transport(request)` returns
 * { status, body: Uint8Array } or throws (error.code RNLO_TIMEOUT for a timeout); `now` is the
 * Unix time in seconds the freshness checks use, read once before the first request.
 * Returns { evidence, responses: [{ seq, body }] }; the bodies are for private storage only.
 */
export async function runCompatibility({ endpoints, transport, now }) {
  checkManifest(endpoints);
  if (!Number.isSafeInteger(now) || now <= 0) throw new TypeError('now must be Unix seconds');
  if (typeof transport !== 'function') throw new TypeError('transport');
  const sent = Object.fromEntries(Object.keys(C6_BUDGET).map((id) => [id, 0]));
  const state = { validatedSeq: {}, pinNumber: null, pinHash: {}, identity: {}, heads: {}, pins: {} };
  const exchanges = [];
  const responses = [];
  let total = 0;

  for (const entry of C6_REQUESTS) {
    const id = entry.providerId;
    const provider = providerOf(entry);
    const record = { seq: entry.seq, id: entry.id, providerId: id, method: entry.method, request: null, requestSha256: null, outcome: Outcome.NOT_SENT, transportCode: null, httpStatus: null, responseSha256: null, responseBytes: null, rpcError: null, observed: null, notSentReason: null };
    exchanges.push(record);
    const missing = unmet(entry, state);
    if (missing !== null) {
      record.notSentReason = missing;
      continue;
    }
    const params = buildParams(entry, state);
    if (params === null) {
      record.notSentReason = 'dependency';
      continue;
    }
    if (sent[id] >= C6_BUDGET[id] || total >= C6_TOTAL_REQUESTS) throw new Error(`C6 budget exceeded at ${entry.id}`); // unreachable: one pass over the manifest
    const body = entryBytes(entry, params);
    record.request = Buffer.from(body).toString('utf8');
    record.requestSha256 = sha256(body);
    sent[id] += 1;
    total += 1;
    let response;
    try {
      response = await transport({ providerId: id, url: provider.url, body, timeoutMs: C6_LIMITS.timeoutMs, maxResponseBytes: C6_LIMITS.maxResponseBytes });
    } catch (error) {
      // The transport's own codes are a fixed set, so they need no sanitizing (C6 review 7).
      const code = TRANSPORT_CODES.includes(error?.code) ? error.code : null;
      record.transportCode = code;
      record.outcome = code === 'RNLO_TIMEOUT' ? Outcome.TIMEOUT : code === 'RNLO_RESPONSE_TOO_LARGE' ? Outcome.TOO_LARGE : Outcome.TRANSPORT_ERROR;
      continue;
    }
    if (!isObject(response) || !Number.isInteger(response.status) || !(response.body instanceof Uint8Array)) {
      record.outcome = Outcome.TRANSPORT_ERROR;
      continue;
    }
    record.responseSha256 = sha256(response.body);
    record.responseBytes = response.body.length;
    responses.push({ seq: entry.seq, body: response.body });
    Object.assign(record, interpretResponse(entry, response));
    learn(entry, record, state);
  }

  const evidence = { format: C6_EVIDENCE_FORMAT, observedAt: now, requestCount: total, sentPerProvider: sent, exchanges };
  return { evidence: { ...evidence, ...classify(evidence) }, responses };
}

/** The first unmet dependency of `entry`, or null. */
function unmet(entry, state) {
  for (const need of entry.needs) {
    if (need === 'identity' && state.identity[entry.providerId] !== true) return 'identity not confirmed';
    if (need === 'validated' && !Number.isSafeInteger(state.validatedSeq[entry.providerId])) return 'no validated ledger';
    if (need === 'both_heads' && state.pinNumber === null) return 'no head on both providers';
    if (need === 'own_pin' && typeof state.pinHash[entry.providerId] !== 'string') return 'no pinned block on this provider';
  }
  return null;
}

/** Updates what later requests depend on. */
function learn(entry, record, state) {
  const id = entry.providerId;
  if (record.outcome !== Outcome.OK) return;
  const o = record.observed;
  if (entry.form === 'server_info') {
    state.identity[id] = o.networkId === 1;
    if (state.identity[id] && o.validatedSeq !== null) state.validatedSeq[id] = o.validatedSeq;
  } else if (entry.form === 'chain_id') {
    state.identity[id] = o.chainId === SEPOLIA_CHAIN;
  } else if (entry.form === 'head' && o.block !== null && o.block.number !== null && o.block.hash !== null) {
    state.heads[id] = BigInt(o.block.number);
    const heads = C6_REQUESTS.filter((e) => e.form === 'head').map((e) => state.heads[e.providerId]);
    if (heads.every((h) => typeof h === 'bigint')) {
      const lowest = heads.reduce((a, b) => (b < a ? b : a));
      if (lowest >= BigInt(C6_PIN_DEPTH)) state.pinNumber = `0x${(lowest - BigInt(C6_PIN_DEPTH)).toString(16)}`;
    }
  } else if (entry.form === 'pin' && o.block !== null && o.block.number === state.pinNumber && o.block.hash !== null) {
    state.pinHash[id] = o.block.hash;
  }
}
