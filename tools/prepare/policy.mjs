// The request policy of one live preparation run (RN-NET-03B2-C3; ADR-RN-018 Amendment C1, P2 and
// P3; ADR-RN-019 Amendment C1, E2). It wraps the transport and admits, per provider and in order,
// exactly the planned requests, each in exactly its planned form. It is checked BEFORE the
// transport sees a request, so a refused request is never sent:
//   - only the two named providers, each at its configured URL;
//   - per provider, exactly PREPARATION_REQUESTS[network], in order, one attempt each (no retry),
//     each body byte-identical to the canonical request rnnet.tx-preparation.v1 §3 builds;
//   - XRPL: server_info {api_version: 2}; account_info of the authorized account at "validated";
//   - Sepolia: the head pass on every provider before any pin, every pin before any pinned read;
//     the latest block by tag, the pin by number (the same number on both), and the nonce, balance,
//     code and gas estimate at {blockHash, requireCanonical: true}, the same hash everywhere. Only
//     the pending nonce uses a tag. Never "latest", "pending", a number or no block parameter on a
//     pinned read: there is no fallback to admit.
// No write method is in any plan, so none can pass.
import { Buffer } from 'node:buffer';
import { PREPARATION_REQUESTS, requestBytes } from '../../packages/chain-readonly/src/index.mjs';
import { IntentNetwork } from '../../packages/tx-intent/src/index.mjs';

/** Requests per run (two providers): XRPL 4, Sepolia 16 (ADR-RN-019 Amendment C1, E2). */
export const PREPARATION_RUN_REQUESTS = Object.freeze({
  [IntentNetwork.XRPL_TESTNET]: 2 * PREPARATION_REQUESTS[IntentNetwork.XRPL_TESTNET].length,
  [IntentNetwork.SEPOLIA]: 2 * PREPARATION_REQUESTS[IntentNetwork.SEPOLIA].length,
});

const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const keys = (v) => (isObject(v) ? Object.keys(v).sort().join(',') : null);

/** One JSON-RPC request object from the body, or null. */
function requestOf(body) {
  if (!(body instanceof Uint8Array) || body.length > 65_536) return null;
  let value;
  try {
    value = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return null;
  }
  return isObject(value) && typeof value.method === 'string' ? value : null;
}

/** The block-hash object of a pinned read, or null if `at` is any other form. */
const pinnedHash = (at) => (keys(at) === 'blockHash,requireCanonical' && at.requireCanonical === true && typeof at.blockHash === 'string' && EVM_HASH.test(at.blockHash) ? at.blockHash : null);

/**
 * The policy of one preparation run on `network`, for `providers` (in reading order) and the
 * authorized `sender` (and the exact calldata on Sepolia). Returns { wrap(transport), violation,
 * counts(), complete() }.
 * @param {{ network: string, providers: ReadonlyArray<{ id, url }>, sender: string, data?: string }} options
 */
export function createPreparationPolicy({ network, providers, sender, data }) {
  const plan = PREPARATION_REQUESTS[network];
  if (!plan || !Array.isArray(providers) || providers.length !== 2 || typeof sender !== 'string') throw new TypeError('preparation policy');
  const byId = new Map(providers.map((p) => [p.id, p]));
  const step = new Map(providers.map((p) => [p.id, 0]));
  const shared = { pinNumber: null, pinHash: null };
  const state = { violation: null };
  const doneAll = (n) => providers.every((p) => step.get(p.id) >= n);

  // Whether request `index` of the plan, with these params, is the planned form. A string is the reason it is not.
  function formOf(index, params, providerId) {
    if (network === IntentNetwork.XRPL_TESTNET) {
      if (index === 0) return sameJson(params, [{ api_version: 2 }]) || 'server_info params';
      return sameJson(params, [{ account: sender, api_version: 2, ledger_index: 'validated', signer_lists: true }]) || 'account_info params';
    }
    if (!Array.isArray(params)) return 'params';
    switch (index) {
      case 0:
        return params.length === 0 || 'eth_chainId params';
      case 1:
        return sameJson(params, ['latest', false]) || 'the head is read as ["latest", false]';
      case 2: {
        // The pin: only after every provider's head pass; the same number on every provider.
        if (!doneAll(2)) return `${providerId}: the pin before every head pass`;
        if (params.length !== 2 || typeof params[0] !== 'string' || !QUANTITY.test(params[0]) || params[1] !== false) return 'the pin is read by number';
        if (shared.pinNumber !== null && shared.pinNumber !== params[0]) return 'two pin numbers';
        shared.pinNumber = params[0];
        return true;
      }
      default: {
        if (!doneAll(3)) return `${providerId}: a pinned read before every pin`;
        const method = plan[index];
        const expected = index === 4 ? 'pending' : null;
        const at = params[1];
        if (index === 7) {
          if (params.length !== 2 || !sameJson(params[0], { data, from: sender, to: sender, value: '0x0' })) return 'eth_estimateGas call object';
        } else if (params.length !== 2 || params[0] !== sender) {
          return `${method} sender`;
        }
        if (expected !== null) return at === 'pending' || 'the pending nonce is read with "pending"';
        const hash = pinnedHash(at);
        if (hash === null) return `${method} must be pinned to {blockHash, requireCanonical: true}`;
        if (shared.pinHash !== null && shared.pinHash !== hash) return 'two pinned hashes';
        shared.pinHash = hash;
        return true;
      }
    }
  }

  const refuse = (why) => {
    if (state.violation === null) state.violation = why;
    throw Object.assign(new Error(`preparation policy: ${why}`), { code: 'RNPL_REQUEST_POLICY' });
  };
  return Object.freeze({
    get violation() {
      return state.violation;
    },
    counts: () => Object.fromEntries(step),
    /** True once every provider made every planned request. */
    complete: () => doneAll(plan.length),
    wrap(transport) {
      return async (request) => {
        if (state.violation !== null) refuse(state.violation);
        if (!isObject(request)) refuse('request');
        const provider = byId.get(request.providerId);
        if (!provider) refuse(`provider ${JSON.stringify(request.providerId)} is not one of this run's`);
        if (request.url !== provider.url) refuse(`url of ${provider.id}`);
        const body = requestOf(request.body);
        if (body === null) refuse('body is not one JSON-RPC request');
        const index = step.get(provider.id);
        if (index >= plan.length) refuse(`${provider.id}: budget used`);
        if (body.method !== plan[index]) refuse(`${provider.id}: request ${index + 1} is ${plan[index]}, not ${body.method}`);
        const form = formOf(index, body.params, provider.id);
        if (form !== true) refuse(form);
        // Byte for byte the request this plan builds (canonical JSON, one envelope): no duplicate or
        // extra member, no other id, nothing a provider could parse differently (C3 review 2).
        let canonical = null;
        try {
          canonical = Buffer.from(requestBytes(network, body.method, network === IntentNetwork.XRPL_TESTNET ? body.params[0] : body.params));
        } catch {
          // not expressible as a planned request
        }
        if (canonical === null || !canonical.equals(Buffer.from(request.body))) refuse(`${provider.id}: request ${index + 1} is not the planned bytes`);
        step.set(provider.id, index + 1);
        return transport(request);
      };
    },
  });
}
