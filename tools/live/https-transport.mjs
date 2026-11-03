// The only network transport in this repository (RN-NET-03B1, ADR-RN-013). It is used only by
// tools/verify-live-anchor.mjs in live mode, and packages/ never imports it. The offline tests
// import it only to test its pure parts; the offline preload refuses its connections and lookups.
//
// One HTTPS POST to a configured endpoint:
// - no redirects are followed (a 3xx response is an error);
// - TLS certificates are verified;
// - the destination address comes from a DNS lookup made here, and private, loopback,
//   link-local, multicast and other non-public addresses are refused, at connection time;
// - the request has a deadline, and the response is read up to a size limit;
// - TLS verification is stated in every request (never inherited from the environment), only
//   identity-encoded bodies are read, and the connected peer address is checked again.
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
    if (first === 0x2002) return true; // 6to4: embeds an IPv4 address
    if ((first & 0xfff0) === 0x3ff0) return true; // 3fff::/20 documentation
    const second = Number.parseInt(lower.split(':')[1] || '0', 16);
    if (first === 0x2001 && second === 0) return true; // Teredo 2001::/32
    if (first === 0x2001 && second === 0x2) return true; // 2001:2::/48 benchmarking
    if (first === 0x2001 && (second & 0xfff0) === 0x10) return true; // ORCHID 2001:10::/28
    if (first === 0x2001 && (second & 0xfff0) === 0x20) return true; // ORCHIDv2 2001:20::/28
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
    (a === 192 && b === 88 && Number(address.split('.')[2]) === 99) || // 192.88.99.0/24 6to4 relay
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

/** TLS settings every request states explicitly, whatever the environment says (C6-LIVE-ENABLE). */
export const TLS_OPTIONS = Object.freeze({ rejectUnauthorized: true, minVersion: 'TLSv1.2' });

/**
 * A transport over `request` (node:https request; tests inject a fake one, since the offline
 * preload refuses the real one) and `lookup` (the guarded lookup).
 * The transport: (request) => Promise<{ status, body }>, throwing { code } on failure.
 */
export function createHttpsTransport({ request = httpsRequest, lookup = guardedLookup } = {}) {
  return ({ url, body, timeoutMs, maxResponseBytes }) => new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch {
      return reject(fail('RNLO_BLOCKED_ADDRESS'));
    }
    // An address literal would skip the guarded lookup, so only DNS names are accepted.
    const host = target.hostname.replace(/^\[|\]$/g, '');
    if (target.protocol !== 'https:' || target.username || target.password || isIP(host) !== 0) return reject(fail('RNLO_BLOCKED_ADDRESS'));
    let settled = false;
    let chunks = [];
    let req;
    const finish = (fn, value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        if (fn === reject) chunks = [];
        fn(value);
      }
    };
    // Settled first, then destroyed: an error the destruction raises cannot replace the cause.
    const abort = (code) => {
      finish(reject, fail(code));
      req?.destroy();
    };
    const timer = setTimeout(() => abort('RNLO_TIMEOUT'), timeoutMs);
    try {
      req = request(target, {
        method: 'POST',
        lookup,
        agent: false,
        // Stated, not inherited: certificates and the host name are verified, TLS 1.2 at least.
        ...TLS_OPTIONS,
        servername: host,
        insecureHTTPParser: false,
        maxHeaderSize: 16_384,
        headers: { 'content-type': 'application/json', accept: 'application/json', 'accept-encoding': 'identity', 'content-length': body.length },
      }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          finish(reject, fail('RNLO_REDIRECT'));
          res.destroy();
          return;
        }
        // Only identity bodies: a compressed body would expand past the limit after it is read.
        const encoding = res.headers['content-encoding'];
        if (encoding !== undefined && String(encoding).toLowerCase() !== 'identity') {
          finish(reject, fail('RNLO_CONNECTION'));
          res.destroy();
          return;
        }
        const declared = Number(res.headers['content-length']);
        if (Number.isFinite(declared) && declared > maxResponseBytes) {
          finish(reject, fail('RNLO_RESPONSE_TOO_LARGE'));
          res.destroy();
          return;
        }
        let size = 0;
        res.on('data', (chunk) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxResponseBytes) {
            finish(reject, fail('RNLO_RESPONSE_TOO_LARGE'));
            res.destroy();
          } else chunks.push(chunk);
        });
        res.on('end', () => finish(resolve, { status: res.statusCode, body: new Uint8Array(Buffer.concat(chunks)) }));
        res.on('error', () => finish(reject, fail('RNLO_CONNECTION')));
      });
    } catch {
      return abort('RNLO_CONNECTION');
    }
    // Defense in depth: the address actually connected must be public too.
    req.on('socket', (socket) => {
      const checkPeer = () => {
        if (typeof socket.remoteAddress !== 'string' || isBlockedAddress(socket.remoteAddress)) abort('RNLO_BLOCKED_ADDRESS');
      };
      if (typeof socket.remoteAddress === 'string') checkPeer();
      else socket.once('connect', checkPeer);
    });
    req.on('error', (error) => finish(reject, fail(error?.code === 'RNLO_BLOCKED_ADDRESS' ? 'RNLO_BLOCKED_ADDRESS' : 'RNLO_CONNECTION')));
    req.end(Buffer.from(body));
  });
}

/** The transport over node:https and the guarded lookup. */
export const httpsTransport = createHttpsTransport();
