// The only network transport in this repository (RN-NET-03B1, ADR-RN-013). It is used only by
// tools/verify-live-anchor.mjs in live mode; packages/ never imports it, and the offline test
// suite never loads it.
//
// One HTTPS POST to a configured endpoint:
// - no redirects are followed (a 3xx response is an error);
// - TLS certificates are verified;
// - the destination address comes from a DNS lookup made here, and private, loopback,
//   link-local, multicast and other non-public addresses are refused, at connection time;
// - the request has a deadline, and the response is read up to a size limit.
import { lookup as dnsLookup } from 'node:dns';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

const fail = (code) => Object.assign(new Error(code), { code });

/** Whether an IP address must never be contacted: anything that is not public unicast. */
export function isBlockedAddress(address) {
  const version = isIP(address);
  if (version === 4) return blockedV4(address);
  if (version === 6) {
    const lower = address.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return blockedV4(mapped[1]);
    if (lower === '::' || lower === '::1') return true;
    const first = Number.parseInt(lower.split(':')[0] || '0', 16);
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((first & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    if (lower.startsWith('64:ff9b:') || lower.startsWith('2001:db8:') || lower.startsWith('100::')) return true;
    return (first & 0xe000) !== 0x2000; // only 2000::/3 is global unicast
  }
  return true;
}

function blockedV4(address) {
  const [a, b] = address.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 shared address space
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) || // 192.0.0.0/24 and 192.0.2.0/24
    (a === 198 && (b === 18 || b === 19 || b === 51)) ||
    (a === 203 && b === 0)
  );
}

/** A DNS lookup for https.request that refuses non-public addresses (all results must be public). */
export const makeGuardedLookup = (resolve = dnsLookup) => (hostname, options, callback) => {
  resolve(hostname, { all: true, verbatim: true }, (error, addresses) => {
    if (error) return callback(error);
    if (addresses.length === 0 || addresses.some((a) => isBlockedAddress(a.address))) return callback(fail('RNLO_BLOCKED_ADDRESS'));
    if (options?.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
};
export const guardedLookup = makeGuardedLookup();

/**
 * The transport: (request) => Promise<{ status, body }>, throwing { code } on failure.
 * @param {{ url: string, body: Uint8Array, timeoutMs: number, maxResponseBytes: number }} request
 */
export function httpsTransport({ url, body, timeoutMs, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== 'https:' || target.username || target.password) return reject(fail('RNLO_BLOCKED_ADDRESS'));
    let settled = false;
    const finish = (fn, value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        fn(value);
      }
    };
    const req = httpsRequest(target, {
      method: 'POST',
      lookup: guardedLookup,
      agent: false,
      headers: { 'content-type': 'application/json', accept: 'application/json', 'content-length': body.length },
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.destroy();
        return finish(reject, fail('RNLO_REDIRECT'));
      }
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxResponseBytes) {
        res.destroy();
        return finish(reject, fail('RNLO_RESPONSE_TOO_LARGE'));
      }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxResponseBytes) {
          res.destroy();
          finish(reject, fail('RNLO_RESPONSE_TOO_LARGE'));
        } else chunks.push(chunk);
      });
      res.on('end', () => finish(resolve, { status: res.statusCode, body: new Uint8Array(Buffer.concat(chunks)) }));
      res.on('error', () => finish(reject, fail('RNLO_CONNECTION')));
    });
    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, fail('RNLO_TIMEOUT'));
    }, timeoutMs);
    req.on('error', (error) => finish(reject, fail(error?.code === 'RNLO_BLOCKED_ADDRESS' ? 'RNLO_BLOCKED_ADDRESS' : 'RNLO_CONNECTION')));
    req.end(Buffer.from(body));
  });
}
