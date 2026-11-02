// The request policy of the broadcaster's runs (RN-NET-03B2-C2; ADR-RN-019 Amendment C1, E2).
//
// Every request a run makes goes through this policy before the transport sees it. It admits a
// request only if all of these hold, and otherwise refuses it without calling the transport:
//   - the request names one of the run's configured providers, by id, at that provider's URL;
//   - its body is one JSON-RPC request whose method is on the run's exact method list;
//   - that method's per-provider count is not yet used up, so the budget is fixed in code;
//   - a write is the network's one write method (WRITE_METHODS), to the authorized provider only,
//     once, and only after every planned pre-submit read was made (an exact, not maximal, plan).
// A refusal is recorded once, as the run's `violation`, and the run ends with RNBC_REQUEST_POLICY.
// The policy is defense in depth: the run's own code already makes exactly these requests.
//
// The read-only policy of the status check admits only read methods (READ_ONLY_METHODS), never a
// write method, within a per-provider ceiling.
import { Buffer } from 'node:buffer';
import { READ_ONLY_METHODS } from '../../packages/chain-readonly/src/index.mjs';
import { SubmitNetwork, WRITE_METHODS } from '../../packages/chain-submit/src/index.mjs';

/** The pre-submit reads per provider, by method (ADR-RN-019 §6): XRPL 3, Sepolia 6. */
export const SUBMIT_READ_PLAN = Object.freeze({
  [SubmitNetwork.XRPL_TESTNET]: Object.freeze({ server_info: 1, account_info: 1, tx: 1 }),
  [SubmitNetwork.SEPOLIA]: Object.freeze({ eth_chainId: 1, eth_getBlockByNumber: 1, eth_getTransactionCount: 2, eth_getTransactionByHash: 1, eth_getBalance: 1 }),
});
/** Requests per submit run (two providers): XRPL 6 reads + 1 write = 7; Sepolia 12 + 1 = 13. */
export const SUBMIT_RUN_REQUESTS = Object.freeze({ [SubmitNetwork.XRPL_TESTNET]: 7, [SubmitNetwork.SEPOLIA]: 13 });
/**
 * The status check's ceiling per provider: the live verifier's reads (XRPL 3 calls, Sepolia at most
 * 262 calls, each of at most 2 attempts) plus at most 3 absence reads.
 */
export const STATUS_REQUESTS_PER_PROVIDER = Object.freeze({ [SubmitNetwork.XRPL_TESTNET]: 3 * 2 + 3, [SubmitNetwork.SEPOLIA]: 262 * 2 + 3 });

/** The JSON-RPC method of a request body, or null if the body is not exactly one request object. */
export function requestMethod(body) {
  if (!(body instanceof Uint8Array) || body.length > 65_536) return null;
  let value;
  try {
    value = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return null;
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) || typeof value.method !== 'string') return null;
  return value.method;
}

function admitter(providers) {
  const byId = new Map(providers.map((p) => [p.id, p]));
  return (request) => {
    if (request === null || typeof request !== 'object') return 'request';
    const provider = byId.get(request.providerId);
    if (!provider) return `provider ${JSON.stringify(request.providerId)} is not one of this run's`;
    if (request.url !== provider.url) return `url of ${provider.id}`;
    const method = requestMethod(request.body);
    if (method === null) return 'body is not one JSON-RPC request';
    return { provider, method };
  };
}

/**
 * The policy of one submit run on `network`, with its two configured providers and the authorized
 * write provider. Returns { reads(transport), admitWrite(request), violation, counts }.
 */
export function createRequestPolicy(network, providers, writeProviderId) {
  const plan = SUBMIT_READ_PLAN[network];
  if (!plan || !Array.isArray(providers) || providers.length !== 2 || providers.some((p) => p.network !== network)) throw new TypeError('request policy');
  const admit = admitter(providers);
  const counts = new Map(providers.map((p) => [p.id, Object.fromEntries(Object.keys(plan).map((m) => [m, 0]))]));
  let writes = 0;
  const state = { violation: null };
  const refuse = (why) => {
    if (state.violation === null) state.violation = why;
    return why;
  };
  const planned = () => providers.every((p) => Object.entries(plan).every(([m, n]) => counts.get(p.id)[m] === n));
  return Object.freeze({
    get violation() {
      return state.violation;
    },
    counts: () => structuredClone(Object.fromEntries(counts)),
    /** Wraps `transport` for the pre-submit reads; a refused read throws without being sent. */
    reads(transport) {
      return async (request) => {
        const admitted = admit(request);
        let why = typeof admitted === 'string' ? admitted : null;
        if (why === null) {
          const { provider, method } = admitted;
          const used = counts.get(provider.id);
          if (WRITE_METHODS[network].includes(method)) why = `${method} is a write`;
          else if (!Object.hasOwn(plan, method)) why = `${method} is not a pre-submit read`;
          else if (used[method] >= plan[method]) why = `${method} on ${provider.id}: budget used`;
          else used[method] += 1;
        }
        if (why !== null) throw Object.assign(new Error(`request policy: ${refuse(why)}`), { code: 'RNBC_REQUEST_POLICY' });
        return transport(request);
      };
    },
    /** null if the one write may be sent now; otherwise the reason, recorded as the violation. */
    admitWrite(request) {
      if (state.violation !== null) return state.violation;
      const admitted = admit(request);
      if (typeof admitted === 'string') return refuse(admitted);
      if (admitted.provider.id !== writeProviderId) return refuse(`the write goes to ${writeProviderId} only`);
      if (!WRITE_METHODS[network].includes(admitted.method)) return refuse(`${admitted.method} is not the write method`);
      if (writes >= 1) return refuse('a second write');
      if (!planned()) return refuse('the write comes only after every planned pre-submit read');
      writes += 1;
      return null;
    },
  });
}

/**
 * The read-only policy of one status check: only READ_ONLY_METHODS of `network`, never a write
 * method, to the two named providers, within STATUS_REQUESTS_PER_PROVIDER each. Returns
 * { wrap(transport), violation }.
 */
export function createReadOnlyPolicy(network, providers) {
  if (!Object.hasOwn(READ_ONLY_METHODS, network) || !Array.isArray(providers) || providers.length !== 2 || providers.some((p) => p.network !== network)) throw new TypeError('read-only policy');
  const admit = admitter(providers);
  const used = new Map(providers.map((p) => [p.id, 0]));
  const state = { violation: null };
  return Object.freeze({
    get violation() {
      return state.violation;
    },
    wrap(transport) {
      return async (request) => {
        const admitted = admit(request);
        let why = typeof admitted === 'string' ? admitted : null;
        if (why === null) {
          const { provider, method } = admitted;
          if (WRITE_METHODS[network].includes(method) || !READ_ONLY_METHODS[network].includes(method)) why = `${method} is not a read-only method`;
          else if (used.get(provider.id) >= STATUS_REQUESTS_PER_PROVIDER[network]) why = `${provider.id}: budget used`;
          else used.set(provider.id, used.get(provider.id) + 1);
        }
        if (why !== null) {
          if (state.violation === null) state.violation = why;
          throw Object.assign(new Error(`read-only policy: ${why}`), { code: 'RNBC_REQUEST_POLICY' });
        }
        return transport(request);
      };
    },
  });
}
