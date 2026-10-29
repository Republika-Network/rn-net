// Read-only RPC calls through an injected transport (spec/rnnet.live-observation-report.v1.md §3).
// This package never opens a connection: the transport is supplied by the caller (tools/live/ in
// production, a mock or a capture replay in tests). Every request is built here, from an exact
// allowlist of read-only methods; nothing in this package can construct a write or signing call.
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { OPERATOR } from './capture.mjs';
import { JsonError, parseRpcJson } from './json.mjs';

export const Network = Object.freeze({ XRPL_TESTNET: 'xrpl:testnet', SEPOLIA: 'evm:11155111' });

/** The only methods that may be called, per network. Exact names; there is no pattern matching. */
export const READ_ONLY_METHODS = Object.freeze({
  [Network.XRPL_TESTNET]: Object.freeze(['server_info', 'tx', 'ledger']),
  [Network.SEPOLIA]: Object.freeze(['eth_chainId', 'eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getBlockByHash', 'eth_getBlockByNumber']),
});

export const LIMITS = Object.freeze({
  /** Largest response body accepted, in bytes. */
  maxResponseBytes: 262_144,
  /** Attempts per request; retries only for timeouts, connection failures, 429 and 502-504. */
  maxAttempts: 2,
  /** Requests per provider per verification, including the Sepolia ancestry walk. */
  maxRequestsPerProvider: 300,
  /** Per-request timeout the transport must enforce, in milliseconds. */
  timeoutMs: 10_000,
});

/** A failed read: a stable code, never response text. */
export class ReadError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'ReadError';
    this.code = code;
  }
}

/** Transport failure codes a transport may throw (as `{ code }`); anything else is RNLO_CONNECTION. */
export const TRANSPORT_CODES = Object.freeze([
  'RNLO_TIMEOUT', 'RNLO_CONNECTION', 'RNLO_RESPONSE_TOO_LARGE', 'RNLO_REDIRECT', 'RNLO_BLOCKED_ADDRESS',
]);
const RETRYABLE = new Set(['RNLO_TIMEOUT', 'RNLO_CONNECTION', 'RNLO_RATE_LIMITED', 'RNLO_HTTP_STATUS_RETRYABLE']);

// --- endpoint configuration -------------------------------------------------------------------

export const ENDPOINTS_FORMAT = 'rnnet.rpc-endpoints.v1';
const PROVIDER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const PATH = /^\/[A-Za-z0-9._~\/-]{0,128}$/;

/** Checks an rnnet.rpc-endpoints.v1 configuration; returns frozen providers or throws TypeError. */
export function loadEndpointConfig(config) {
  const fail = (why) => {
    throw new TypeError(`endpoint configuration: ${why}`);
  };
  if (config === null || typeof config !== 'object' || config.format !== ENDPOINTS_FORMAT || !Array.isArray(config.providers)) fail('not rnnet.rpc-endpoints.v1');
  const ids = new Set();
  const urls = new Set();
  return Object.freeze(config.providers.map((entry) => {
    const { id, network, url, operator } = entry ?? {};
    if (typeof id !== 'string' || !PROVIDER_ID.test(id) || ids.has(id)) fail(`bad or duplicate provider id ${JSON.stringify(id)}`);
    if (!Object.hasOwn(READ_ONLY_METHODS, network)) fail(`${id}: network not allowed`);
    if (typeof operator !== 'string' || !OPERATOR.test(operator)) fail(`${id}: operator must be 1 to 64 letters, digits, spaces or ().&,'-`);
    const parsed = checkEndpointUrl(url, fail, id);
    if (urls.has(parsed.href)) fail(`${id}: duplicate url`);
    ids.add(id);
    urls.add(parsed.href);
    return Object.freeze({ id, network, url: parsed.href, origin: parsed.origin, operator });
  }));
}

function checkEndpointUrl(url, fail, id) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    fail(`${id}: not a URL`);
  }
  if (typeof url !== 'string' || parsed.href !== url) fail(`${id}: url must be in normalized form`);
  if (parsed.protocol !== 'https:') fail(`${id}: https only`);
  if (parsed.username || parsed.password) fail(`${id}: credentials are not allowed in urls`);
  if (parsed.search || parsed.hash) fail(`${id}: query and fragment are not allowed`);
  if (!HOSTNAME.test(parsed.hostname)) fail(`${id}: host must be a DNS name, not an address`);
  if (!PATH.test(parsed.pathname)) fail(`${id}: path not allowed`);
  return parsed;
}

// --- calls -------------------------------------------------------------------------------------

/** The exact request bytes for one call (canonical JSON). */
export function requestBytes(network, method, params) {
  if (!READ_ONLY_METHODS[network]?.includes(method)) throw new TypeError(`method ${method} is not an allowed read-only method for ${network}`);
  const body = network === Network.XRPL_TESTNET ? { method, params: [params] } : { jsonrpc: '2.0', id: 1, method, params };
  return canonicalBytes(body);
}

/**
 * Calls one read-only method on one provider and returns the parsed `result`.
 * @param {{ provider, transport, budget: { remaining: number } }} context
 */
export async function call(context, method, params) {
  const { provider, transport, budget } = context;
  let body;
  try {
    body = requestBytes(provider.network, method, params);
  } catch (error) {
    if (error instanceof TypeError && /allowed read-only method/.test(error.message)) throw error;
    throw new ReadError('RNLO_INVALID_RESPONSE', 'a provider value cannot be sent back in a request');
  }
  let lastError;
  for (let attempt = 1; attempt <= LIMITS.maxAttempts; attempt++) {
    if (budget.remaining <= 0) throw new ReadError('RNLO_REQUEST_BUDGET');
    budget.remaining -= 1;
    try {
      return interpret(provider.network, await send(transport, provider, body));
    } catch (error) {
      if (error?.name === 'ReplayMismatch') throw error; // a capture that does not fit is never "unavailable"
      lastError = error instanceof ReadError ? error : new ReadError('RNLO_CONNECTION');
      if (!RETRYABLE.has(lastError.code)) throw lastError;
    }
  }
  throw lastError.code === 'RNLO_HTTP_STATUS_RETRYABLE' ? new ReadError('RNLO_HTTP_STATUS') : lastError;
}

async function send(transport, provider, body) {
  let response;
  try {
    response = await transport({ providerId: provider.id, url: provider.url, body, timeoutMs: LIMITS.timeoutMs, maxResponseBytes: LIMITS.maxResponseBytes });
  } catch (error) {
    if (error?.name === 'ReplayMismatch') throw error;
    throw new ReadError(TRANSPORT_CODES.includes(error?.code) ? error.code : 'RNLO_CONNECTION');
  }
  if (response === null || typeof response !== 'object' || !Number.isInteger(response.status) || !(response.body instanceof Uint8Array)) {
    throw new ReadError('RNLO_CONNECTION');
  }
  if (response.body.length > LIMITS.maxResponseBytes) throw new ReadError('RNLO_RESPONSE_TOO_LARGE');
  if (response.status === 429) throw new ReadError('RNLO_RATE_LIMITED');
  if ([502, 503, 504].includes(response.status)) throw new ReadError('RNLO_HTTP_STATUS_RETRYABLE');
  if (response.status !== 200) throw new ReadError('RNLO_HTTP_STATUS');
  try {
    return parseRpcJson(response.body, LIMITS.maxResponseBytes);
  } catch (error) {
    if (error instanceof JsonError) throw new ReadError('RNLO_INVALID_JSON');
    throw error;
  }
}

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const RPC_ERROR_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/** The `result` of a well-formed response envelope, or a ReadError. */
function interpret(network, envelope) {
  if (kind(envelope) !== 'object') throw new ReadError('RNLO_INVALID_RESPONSE', 'envelope');
  if (network === Network.XRPL_TESTNET) {
    const { result } = envelope;
    if (kind(result) !== 'object') throw new ReadError('RNLO_INVALID_RESPONSE', 'result');
    if (result.status === 'error') {
      if (result.error === 'txnNotFound') throw new ReadError('RNLO_NOT_FOUND');
      throw new ReadError('RNLO_RPC_ERROR', typeof result.error === 'string' && RPC_ERROR_NAME.test(result.error) ? result.error : '');
    }
    if (result.status !== 'success') throw new ReadError('RNLO_INVALID_RESPONSE', 'status');
    return result;
  }
  if (envelope.jsonrpc !== '2.0' || envelope.id !== 1) throw new ReadError('RNLO_INVALID_RESPONSE', 'envelope');
  if (Object.hasOwn(envelope, 'error')) throw new ReadError('RNLO_RPC_ERROR');
  if (!Object.hasOwn(envelope, 'result')) throw new ReadError('RNLO_INVALID_RESPONSE', 'result');
  return envelope.result;
}
