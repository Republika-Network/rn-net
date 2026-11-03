// The C6 request policy (RN-NET-03B2-C6-LIVE): what the transport is allowed to see, enforced
// around it independently of the run (tools/compat/run.mjs), which already plans one attempt per
// manifest request. Before a request reaches the transport, the policy checks:
//   - the provider is one of the four authorized, at its authorized URL (no substitution);
//   - the deadline and response limit are the manifest's (10 s, 256 KiB);
//   - the body is a single JSON-RPC request whose method is read-only on that network, never a
//     write method, and is the provider's next planned manifest method, in manifest order;
//   - the provider's authorized count and the 22-request total are not exceeded;
//   - the authorization has not expired (checked before EVERY request).
// It then calls the transport exactly once (no retry, no other provider), with its own deadline
// (a transport that has not answered after timeoutMs is a TIMEOUT), and refuses a body over the
// limit without keeping it. After the first violation nothing more reaches the transport.
//
// Each call is recorded in the transcript (the raw transport facts the Python reference replays),
// and each response body is handed to `keep` as soon as it arrives, so it is stored durably even if
// the run ends early.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { READ_ONLY_METHODS, TRANSPORT_CODES } from '../../packages/chain-readonly/src/index.mjs';
import { C6_LIMITS, C6_PROVIDERS, C6_REQUESTS, C6_TOTAL_REQUESTS, WRITE_METHODS } from '../compat/manifest.mjs';

export const COMPAT_TRANSCRIPT_FORMAT = 'rnnet.provider-compat-transcript.v1';
/** A request body is a few hundred bytes; anything larger is not a manifest request. */
export const MAX_REQUEST_BYTES = 4096;

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const coded = (code, message) => Object.assign(new Error(message), { code });

/** The file name of the n-th response (1-based call number). */
export const responseFileName = (call) => `response-${String(call).padStart(2, '0')}.bin`;

/**
 * @param {{ providers: {id, url, requests}[], notAfter: number, clock: () => number,
 *           keep: (name: string, body: Uint8Array) => void, sleep?: (ms: number) => Promise<void> }} options
 * `providers` are the authorization's; `notAfter` is in Unix seconds; `clock` returns Unix seconds.
 */
export function createCompatPolicy({ providers, notAfter, clock, keep, sleep = defaultSleep }) {
  const authorized = new Map(providers.map((p) => [p.id, p]));
  const sent = Object.fromEntries(providers.map((p) => [p.id, 0]));
  const cursor = Object.fromEntries(providers.map((p) => [p.id, 0]));
  const transcript = [];
  let total = 0;
  let violation = null;

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
    const method = message !== null && typeof message === 'object' && !Array.isArray(message) ? message.method : undefined;
    if (typeof method !== 'string' || WRITE_METHODS.includes(method) || !READ_ONLY_METHODS[network]?.includes(method)) return `${p.id}: method is not read-only`;
    const planned = C6_REQUESTS.filter((e) => e.providerId === p.id);
    const next = planned.findIndex((e, i) => i >= cursor[p.id] && e.method === method);
    if (next < 0) return `${p.id}: ${method} is not its next planned request`;
    if (sent[p.id] >= p.requests) return `${p.id}: authorized request count exhausted`;
    if (total >= C6_TOTAL_REQUESTS) return 'authorized request total exhausted';
    const now = clock();
    if (!Number.isSafeInteger(now) || now > notAfter) return 'authorization expired before this request';
    cursor[p.id] = next + 1;
    return null;
  };

  const wrap = (inner) => async (request) => {
    const call = transcript.length + 1;
    const entry = { call, providerId: typeof request?.providerId === 'string' ? request.providerId : null, requestSha256: request?.body instanceof Uint8Array ? sha256(request.body) : null, status: null, responseFile: null, responseSha256: null, responseBytes: null, error: null, policy: null };
    transcript.push(entry);
    if (violation === null) violation = check(request);
    if (violation !== null) {
      entry.policy = violation;
      throw coded('RNCL_REQUEST_POLICY', violation);
    }
    sent[request.providerId] += 1;
    total += 1;
    const timer = sleep(request.timeoutMs);
    const deadline = new Promise((_, reject) => {
      timer.then(() => reject(coded('RNLO_TIMEOUT', 'deadline')));
    });
    let response;
    try {
      response = await Promise.race([Promise.resolve().then(() => inner(request)), deadline]);
    } catch (error) {
      // Only the transport's own fixed codes are kept; anything else is a bare TRANSPORT_ERROR.
      if (TRANSPORT_CODES.includes(error?.code)) {
        entry.error = error.code;
        throw coded(error.code, error.code);
      }
      entry.error = 'TRANSPORT_ERROR';
      throw coded('RNCL_TRANSPORT', 'transport error');
    } finally {
      if (typeof timer.cancel === 'function') timer.cancel();
    }
    if (response === null || typeof response !== 'object' || !Number.isInteger(response.status) || !(response.body instanceof Uint8Array)) {
      entry.error = 'TRANSPORT_ERROR';
      throw coded('RNCL_TRANSPORT', 'not a transport response');
    }
    if (response.body.length > C6_LIMITS.maxResponseBytes) {
      entry.error = 'RNLO_RESPONSE_TOO_LARGE';
      throw coded('RNLO_RESPONSE_TOO_LARGE', 'response too large');
    }
    const body = Uint8Array.from(response.body);
    entry.status = response.status;
    entry.responseFile = responseFileName(call);
    entry.responseSha256 = sha256(body);
    entry.responseBytes = body.length;
    keep(entry.responseFile, body);
    return { status: response.status, body };
  };

  return Object.freeze({
    wrap,
    get violation() {
      return violation;
    },
    sent: () => ({ ...sent }),
    transcript: () => ({ format: COMPAT_TRANSCRIPT_FORMAT, calls: transcript.map((e) => ({ ...e })) }),
  });
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
