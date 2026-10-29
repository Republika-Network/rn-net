// rnnet.rpc-capture.v1 (spec/rnnet.live-observation-report.v1.md §8): the exact bytes exchanged
// with each provider, so a verification can be replayed offline with the same result. A capture
// shows which bytes were received; it does not show that a provider told the truth.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

export const CAPTURE_FORMAT = 'rnnet.rpc-capture.v1';
/** Equal to LIMITS.maxRequestsPerProvider: a capture holds at most what one verification can send. */
export const MAX_EXCHANGES_PER_PROVIDER = 600;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** Thrown when a replayed verification asks for something the capture does not contain. */
export class ReplayMismatch extends Error {
  constructor(detail) {
    super(`capture does not match this verification: ${detail}`);
    this.name = 'ReplayMismatch';
    this.code = 'RNLO_REPLAY_MISMATCH';
  }
}

/** Wraps a transport so every exchange is appended to `exchanges`. */
export function recordingTransport(inner, exchanges) {
  return async (request) => {
    const entry = { providerId: request.providerId, request: Buffer.from(request.body).toString('base64') };
    exchanges.push(entry);
    try {
      const response = await inner(request);
      entry.response = { status: response.status, body: Buffer.from(response.body).toString('base64'), sha256: sha256(response.body) };
      return response;
    } catch (error) {
      entry.error = typeof error?.code === 'string' ? error.code : 'RNLO_CONNECTION';
      throw error;
    }
  };
}

/** A transport that answers only from a capture, in order, per provider. It never opens a connection. */
export function replayTransport(capture) {
  const queues = new Map();
  for (const exchange of capture.exchanges) {
    if (!queues.has(exchange.providerId)) queues.set(exchange.providerId, []);
    queues.get(exchange.providerId).push(exchange);
  }
  const transport = async (request) => {
    const next = queues.get(request.providerId)?.shift();
    if (!next) throw new ReplayMismatch(`no recorded exchange for ${request.providerId}`);
    if (next.request !== Buffer.from(request.body).toString('base64')) throw new ReplayMismatch(`request differs for ${request.providerId}`);
    if (next.error) throw Object.assign(new Error(next.error), { code: next.error });
    const body = new Uint8Array(Buffer.from(next.response.body, 'base64'));
    if (sha256(body) !== next.response.sha256) throw new ReplayMismatch('response digest differs');
    return { status: next.response.status, body };
  };
  /** Throws unless every recorded exchange was used: a capture must fit its verification exactly. */
  transport.assertConsumed = () => {
    for (const [id, queue] of queues) if (queue.length > 0) throw new ReplayMismatch(`${queue.length} unused exchanges for ${id}`);
  };
  return transport;
}

const PROVIDER_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
export const OPERATOR = /^[A-Za-z0-9][A-Za-z0-9 ().&,'-]{0,63}$/;
const ORIGIN = /^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[1-9][0-9]{0,4})?$/;

/** Checks a parsed capture; returns it or throws TypeError. */
export function checkCapture(capture) {
  const fail = (why) => {
    throw new TypeError(`capture: ${why}`);
  };
  if (capture === null || typeof capture !== 'object' || capture.format !== CAPTURE_FORMAT) fail('not rnnet.rpc-capture.v1');
  for (const field of ['network', 'transactionHash']) if (typeof capture[field] !== 'string') fail(`${field} missing`);
  if (!Array.isArray(capture.providers) || capture.providers.length === 0) fail('providers missing');
  for (const p of capture.providers) {
    if (typeof p?.id !== 'string' || !PROVIDER_ID.test(p.id) || typeof p.operator !== 'string' || !OPERATOR.test(p.operator) || typeof p.origin !== 'string' || !ORIGIN.test(p.origin) || !URL.canParse(p.origin)) fail('bad provider');
  }
  if (!Array.isArray(capture.exchanges) || capture.exchanges.length > capture.providers.length * MAX_EXCHANGES_PER_PROVIDER) fail('exchanges missing or too many');
  for (const e of capture.exchanges) {
    if (!capture.providers.some((p) => p.id === e?.providerId) || typeof e.request !== 'string' || !BASE64.test(e.request)) fail('bad exchange');
    const hasResponse = e.response !== undefined;
    if (hasResponse === (e.error !== undefined)) fail('an exchange has exactly one of response and error');
    if (hasResponse && (!Number.isInteger(e.response.status) || typeof e.response.body !== 'string' || !BASE64.test(e.response.body) || typeof e.response.sha256 !== 'string')) fail('bad response');
    if (!hasResponse && typeof e.error !== 'string') fail('bad error');
  }
  for (const p of capture.providers) {
    if (capture.exchanges.filter((e) => e.providerId === p.id).length > MAX_EXCHANGES_PER_PROVIDER) fail(`too many exchanges for ${p.id}`);
  }
  return capture;
}
