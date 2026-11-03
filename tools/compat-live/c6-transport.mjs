// The C6 transport (RN-NET-03B2-C6-LIVE-ENABLE): the only file in tools/compat-live/ that imports
// the reviewed HTTPS transport (tools/live/https-transport.mjs), and nothing else that can reach
// the network (guard: compat-live-reaches-network). It is narrower than the request policy in front
// of it, and independent of it: it holds its own copy of the four reviewed providers, budget and
// limits, and imports nothing of tools/compat/ (a test checks the copies agree), so a fault in the
// run, the manifest or the policy still cannot widen what reaches the network.
//
// What it allows, whatever its caller asks:
//   - exactly the four reviewed provider ids, each only at its reviewed URL (no substitution, no
//     fallback, no other host, port, path, scheme or credential);
//   - at most 22 requests in all, and each provider's own count (2, 2, 9, 9), counted when a request
//     is handed to the HTTPS transport; no retry: a request that failed there still counts;
//   - a 10 s deadline and a 256 KiB response limit, exactly; a request body of at most 4096 bytes
//     that is one canonical JSON-RPC request object of the manifest's shape (no other key, no
//     duplicate key), whose method is one the manifest uses for that provider's network (an
//     allowlist: every other method, a write or signing method above all, is refused);
//   - anything it refuses is refused WITHOUT being sent, with RNCL_TRANSPORT_REFUSED, which the
//     policy records as never sent and which stops the run (C6-LIVE-ENABLE review B1);
//   - one request at a time;
//   - none of the environment that could reroute or weaken it: a proxy variable, a TLS override,
//     an extra CA, NODE_OPTIONS or a key log file, and no Node.js option (--use-openssl-ca, --tls-*,
//     --import, --inspect, ...). It refuses to be built at all if any is present.
// Underneath, tools/live/https-transport.mjs adds: HTTPS only, certificate and host verification
// stated explicitly, no redirect, DNS names only, every resolved and connected address public
// (no private, loopback, link-local, multicast or reserved address), identity bodies only, a
// streaming size limit, and no connection reuse.
import { Buffer } from 'node:buffer';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { createHttpsTransport } from '../live/https-transport.mjs';

/** The four reviewed providers (config/rpc-endpoints.json, the C6 manifest), in manifest order. */
export const C6_TRANSPORT_PROVIDERS = Object.freeze([
  Object.freeze({ id: 'xrpl-testnet-ripple', url: 'https://s.altnet.rippletest.net:51234/', requests: 2 }),
  Object.freeze({ id: 'xrpl-testnet-xrpl-labs', url: 'https://testnet.xrpl-labs.com/', requests: 2 }),
  Object.freeze({ id: 'sepolia-publicnode', url: 'https://ethereum-sepolia-rpc.publicnode.com/', requests: 9 }),
  Object.freeze({ id: 'sepolia-1rpc', url: 'https://public.1rpc.io/sepolia', requests: 9 }),
]);
/** The methods the manifest uses, per network of the provider: the only ones sent. */
export const C6_TRANSPORT_METHODS = Object.freeze({
  'xrpl-testnet-ripple': Object.freeze(['server_info', 'tx']),
  'xrpl-testnet-xrpl-labs': Object.freeze(['server_info', 'tx']),
  'sepolia-publicnode': Object.freeze(['eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionCount', 'eth_getBalance', 'eth_getCode', 'eth_estimateGas']),
  'sepolia-1rpc': Object.freeze(['eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionCount', 'eth_getBalance', 'eth_getCode', 'eth_estimateGas']),
});
export const C6_TRANSPORT_LIMITS = Object.freeze({ totalRequests: 22, timeoutMs: 10_000, maxResponseBytes: 262_144, maxRequestBytes: 4096 });
/** Methods that write, sign or hold keys: never sent, whatever the policy says. */
export const C6_TRANSPORT_REFUSED_METHODS = Object.freeze([
  'submit', 'submit_multisigned', 'sign', 'sign_for', 'wallet_propose', 'channel_authorize', 'validation_create', 'wallet_seed',
  'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction', 'eth_signTypedData', 'eth_signTypedData_v4', 'personal_sign', 'personal_unlockAccount', 'personal_sendTransaction',
]);
/**
 * Environment variables that could reroute or weaken an HTTPS request, or load code into the
 * process: refused when present at all (even empty), in any letter case.
 */
export const C6_TRANSPORT_REFUSED_ENVIRONMENT = Object.freeze([
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_USE_ENV_PROXY', 'GLOBAL_AGENT_HTTP_PROXY', 'GLOBAL_AGENT_HTTPS_PROXY',
  'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS', 'NODE_USE_SYSTEM_CA', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES',
  'SSLKEYLOGFILE', 'NODE_OPTIONS', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_V8_COVERAGE', 'NODE_PATH', 'NODE_REPL_EXTERNAL_MODULE', 'NODE_ICU_DATA', 'UV_USE_IO_URING',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'RES_OPTIONS', 'HOSTALIASES', 'LOCALDOMAIN',
]);

export const C6_TRANSPORT_ENVIRONMENT = 'RNCL_TRANSPORT_ENVIRONMENT';
export class C6TransportEnvironmentError extends Error {
  constructor(detail) {
    super(`${C6_TRANSPORT_ENVIRONMENT}: ${detail}`);
    this.name = 'C6TransportEnvironmentError';
    this.code = C6_TRANSPORT_ENVIRONMENT;
  }
}

export const C6_TRANSPORT_REFUSED = 'RNCL_TRANSPORT_REFUSED';
const refused = () => Object.assign(new Error(C6_TRANSPORT_REFUSED), { code: C6_TRANSPORT_REFUSED });
const sameBytes = (a, b) => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
const connection = () => Object.assign(new Error('RNLO_CONNECTION'), { code: 'RNLO_CONNECTION' });

/** Refuses an environment or Node.js options that could reroute or weaken the transport. */
export function checkTransportEnvironment(env, execArgv) {
  if (env === null || typeof env !== 'object') throw new C6TransportEnvironmentError('the environment is required');
  if (!Array.isArray(execArgv)) throw new C6TransportEnvironmentError('the Node.js options are required');
  const refused = new Set(C6_TRANSPORT_REFUSED_ENVIRONMENT);
  const present = Object.keys(env).filter((name) => refused.has(name.toUpperCase())).sort();
  if (present.length > 0) throw new C6TransportEnvironmentError(`unset ${present.join(', ')} before a C6 run`);
  if (execArgv.length > 0) throw new C6TransportEnvironmentError('run node with no options: node tools/compat-live/compat-live.mjs ...');
}

/**
 * The C6 transport. `env` and `execArgv` are the process's; `base` is the HTTPS transport (tests
 * inject a fake one). Throws C6TransportEnvironmentError if the environment is refused.
 */
export function createC6Transport({ env, execArgv, base = createHttpsTransport() }) {
  checkTransportEnvironment(env, execArgv);
  if (typeof base !== 'function') throw new TypeError('base transport');
  const providers = new Map(C6_TRANSPORT_PROVIDERS.map((p) => [p.id, p]));
  const sent = new Map(C6_TRANSPORT_PROVIDERS.map((p) => [p.id, 0]));
  let total = 0;
  let busy = false;
  const L = C6_TRANSPORT_LIMITS;

  return async (request) => {
    const id = request?.providerId;
    const provider = typeof id === 'string' ? providers.get(id) : undefined;
    if (provider === undefined || request.url !== provider.url) throw refused();
    if (request.timeoutMs !== L.timeoutMs || request.maxResponseBytes !== L.maxResponseBytes) throw refused();
    if (!(request.body instanceof Uint8Array) || request.body.length === 0 || request.body.length > L.maxRequestBytes) throw refused();
    const body = Uint8Array.from(request.body);
    let message;
    try {
      message = JSON.parse(Buffer.from(body).toString('utf8'));
    } catch {
      throw refused();
    }
    if (message === null || typeof message !== 'object' || Array.isArray(message) || typeof message.method !== 'string' || C6_TRANSPORT_REFUSED_METHODS.includes(message.method)) throw refused();
    if (!C6_TRANSPORT_METHODS[id].includes(message.method)) throw refused();
    // The manifest's shape, in canonical form: XRPL { method, params: [ {...} ] }, Sepolia
    // { id: 1, jsonrpc: "2.0", method, params: [...] }. A duplicate key cannot survive the
    // canonical comparison (JSON.parse keeps one; the bytes held two).
    const keys = Object.keys(message).sort().join(',');
    const xrpl = id.startsWith('xrpl-');
    if (xrpl ? keys !== 'method,params' || !Array.isArray(message.params) || message.params.length !== 1 : keys !== 'id,jsonrpc,method,params' || message.id !== 1 || message.jsonrpc !== '2.0' || !Array.isArray(message.params)) throw refused();
    let canonical;
    try {
      canonical = canonicalBytes(message);
    } catch {
      throw refused();
    }
    if (!sameBytes(canonical, body)) throw refused();
    if (busy || total >= L.totalRequests || sent.get(id) >= provider.requests) throw refused();
    // Counted before it is sent: a request that fails is never sent again by this transport.
    total += 1;
    sent.set(id, sent.get(id) + 1);
    busy = true;
    let response;
    try {
      response = await base({ url: provider.url, body, timeoutMs: L.timeoutMs, maxResponseBytes: L.maxResponseBytes });
    } finally {
      busy = false;
    }
    const status = response?.status;
    const raw = response?.body;
    if (!Number.isSafeInteger(status) || !(raw instanceof Uint8Array)) throw connection();
    if (raw.length > L.maxResponseBytes) throw Object.assign(new Error('RNLO_RESPONSE_TOO_LARGE'), { code: 'RNLO_RESPONSE_TOO_LARGE' });
    return { status, body: new Uint8Array(raw) };
  };
}
