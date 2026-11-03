// The RN-NET-03B2-C6 provider compatibility manifest (ADR-RN-018 Amendment C1, P5; readiness
// analysis §4, "C6"). OFFLINE ONLY: this file is data and pure request building. It holds no
// transport, and nothing in tools/compat/ may reach one (guard: compat-reaches-network).
//
// Exactly 22 read-only requests, one attempt each, in a fixed order, to the four reviewed
// providers at their reviewed URLs. No write method, no retry, no fallback: a request planned
// for one provider is never sent to another, and a request that cannot be built (its dependency
// was not observed) is NOT_SENT, never replaced by another form.
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { loadEndpointConfig, Network, READ_ONLY_METHODS, requestBytes } from '../../packages/chain-readonly/src/index.mjs';
import { payloadHex } from '../../packages/tx-intent/src/index.mjs';

export const C6_MANIFEST_FORMAT = 'rnnet.provider-compat-manifest.v1';

/** The reviewed providers, in the order the run reads them, with their reviewed URLs (config/rpc-endpoints.json). */
export const C6_PROVIDERS = Object.freeze([
  Object.freeze({ id: 'xrpl-testnet-ripple', network: Network.XRPL_TESTNET, url: 'https://s.altnet.rippletest.net:51234/', operator: 'Ripple' }),
  Object.freeze({ id: 'xrpl-testnet-xrpl-labs', network: Network.XRPL_TESTNET, url: 'https://testnet.xrpl-labs.com/', operator: 'XRPL Labs' }),
  Object.freeze({ id: 'sepolia-publicnode', network: Network.SEPOLIA, url: 'https://ethereum-sepolia-rpc.publicnode.com/', operator: 'PublicNode' }),
  Object.freeze({ id: 'sepolia-1rpc', network: Network.SEPOLIA, url: 'https://public.1rpc.io/sepolia', operator: 'Automata 1RPC' }),
]);
const [RIPPLE, LABS, PUBLICNODE, ONERPC] = C6_PROVIDERS.map((p) => p.id);

/** Limits of every request: one attempt, the ADR-RN-013 deadline and response limit. */
export const C6_LIMITS = Object.freeze({ attempts: 1, timeoutMs: 10_000, maxResponseBytes: 262_144 });
/** Requests per provider; the run never exceeds them. */
export const C6_BUDGET = Object.freeze({ [RIPPLE]: 2, [LABS]: 2, [PUBLICNODE]: 9, [ONERPC]: 9 });
export const C6_TOTAL_REQUESTS = 22;

/** Methods that write or sign; none may appear in the manifest (and none is in READ_ONLY_METHODS). */
export const WRITE_METHODS = Object.freeze(['submit', 'submit_multisigned', 'sign', 'sign_for', 'wallet_propose', 'eth_sendRawTransaction', 'eth_sendTransaction', 'eth_sign', 'eth_signTransaction', 'personal_sign']);

const sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

/** The public, label-derived B1 test address (fixtures/signing-b1, label rn-net-03b2b1-sepolia-1). Never funded. */
export const C6_TEST_ADDRESS = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86';
/** The Genesis Proof 01 commitment; the estimate uses its 42-byte payload, as preparation does. */
export const C6_COMMITMENT = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
export const C6_CALLDATA = `0x${payloadHex(C6_COMMITMENT)}`;
/** A transaction hash that does not exist (SHA-256 of a public label), for the ranged lookup. */
export const C6_ABSENT_XRPL_TX = sha256Hex('rnnet:c6:absent-xrpl-transaction:v1').toUpperCase();
/** A block hash no provider knows (SHA-256 of a public label), for the error shape of an unservable hash. */
export const C6_UNKNOWN_BLOCK_HASH = `0x${sha256Hex('rnnet:c6:unknown-sepolia-block:v1')}`;
/** The ranged lookup covers 1,000 ledgers ending at the provider's own validated ledger (MAX_LEDGER_RANGE). */
export const C6_XRPL_RANGE = 999;
/** The pin is the lowest head minus this depth (ADR-RN-018 Amendment C1, P1). */
export const C6_PIN_DEPTH = 2;

const pinned = (hash) => ({ blockHash: hash, requireCanonical: true });

/**
 * The 22 requests. `form` names how params are built; `needs` names what must have been observed
 * first (otherwise NOT_SENT). `expect` is the response shape the classifier checks.
 */
export const C6_REQUESTS = Object.freeze([
  { id: 'X01', providerId: RIPPLE, method: 'server_info', form: 'server_info', needs: [], expect: 'xrpl server_info: network_id 1, build_version, complete_ledgers, validated_ledger {seq, hash, age}' },
  { id: 'X02', providerId: LABS, method: 'server_info', form: 'server_info', needs: [], expect: 'as X01' },
  { id: 'X03', providerId: RIPPLE, method: 'tx', form: 'tx_absent_range', needs: ['identity', 'validated'], expect: 'error txnNotFound with searched_all: true' },
  { id: 'X04', providerId: LABS, method: 'tx', form: 'tx_absent_range', needs: ['identity', 'validated'], expect: 'as X03' },
  { id: 'S01', providerId: PUBLICNODE, method: 'eth_chainId', form: 'chain_id', needs: [], expect: 'result "0xaa36a7"' },
  { id: 'S02', providerId: ONERPC, method: 'eth_chainId', form: 'chain_id', needs: [], expect: 'as S01' },
  { id: 'S03', providerId: PUBLICNODE, method: 'eth_getBlockByNumber', form: 'head', needs: ['identity'], expect: 'block {number, hash, timestamp, baseFeePerGas}' },
  { id: 'S04', providerId: ONERPC, method: 'eth_getBlockByNumber', form: 'head', needs: ['identity'], expect: 'as S03' },
  { id: 'S05', providerId: PUBLICNODE, method: 'eth_getBlockByNumber', form: 'pin', needs: ['identity', 'both_heads'], expect: 'block at P = lowest head - 2; the same hash on both providers' },
  { id: 'S06', providerId: ONERPC, method: 'eth_getBlockByNumber', form: 'pin', needs: ['identity', 'both_heads'], expect: 'as S05' },
  { id: 'S07', providerId: PUBLICNODE, method: 'eth_getTransactionCount', form: 'nonce_at_hash', needs: ['identity', 'own_pin'], expect: 'QUANTITY' },
  { id: 'S08', providerId: PUBLICNODE, method: 'eth_getBalance', form: 'balance_at_hash', needs: ['identity', 'own_pin'], expect: 'QUANTITY' },
  { id: 'S09', providerId: PUBLICNODE, method: 'eth_getCode', form: 'code_at_hash', needs: ['identity', 'own_pin'], expect: 'DATA ("0x" for the unfunded test address)' },
  { id: 'S10', providerId: PUBLICNODE, method: 'eth_estimateGas', form: 'estimate_at_hash', needs: ['identity', 'own_pin'], expect: 'QUANTITY from the intrinsic gas to 30,000' },
  { id: 'S11', providerId: ONERPC, method: 'eth_getTransactionCount', form: 'nonce_at_hash', needs: ['identity', 'own_pin'], expect: 'as S07' },
  { id: 'S12', providerId: ONERPC, method: 'eth_getBalance', form: 'balance_at_hash', needs: ['identity', 'own_pin'], expect: 'as S08' },
  { id: 'S13', providerId: ONERPC, method: 'eth_getCode', form: 'code_at_hash', needs: ['identity', 'own_pin'], expect: 'as S09' },
  { id: 'S14', providerId: ONERPC, method: 'eth_estimateGas', form: 'estimate_at_hash', needs: ['identity', 'own_pin'], expect: 'as S10' },
  { id: 'S15', providerId: PUBLICNODE, method: 'eth_getBalance', form: 'balance_unknown_hash', needs: ['identity'], expect: 'a JSON-RPC error (an unknown hash is never served)' },
  { id: 'S16', providerId: ONERPC, method: 'eth_getBalance', form: 'balance_unknown_hash', needs: ['identity'], expect: 'as S15' },
  { id: 'S17', providerId: PUBLICNODE, method: 'eth_getBlockByNumber', form: 'finalized', needs: ['identity'], expect: 'block {number, hash}; compared with the other provider' },
  { id: 'S18', providerId: ONERPC, method: 'eth_getBlockByNumber', form: 'finalized', needs: ['identity'], expect: 'as S17' },
].map((r, i) => Object.freeze({ seq: i + 1, ...r, needs: Object.freeze(r.needs) })));

/** The provider record of a manifest entry. */
export const providerOf = (entry) => C6_PROVIDERS.find((p) => p.id === entry.providerId);

/**
 * The params of `entry`, given what has been observed (`state`), or null if a dependency is
 * missing. `state`: { validatedSeq: {id: n}, pinNumber: '0x..' | null, pinHash: {id: '0x..'} }.
 */
export function buildParams(entry, state) {
  const id = entry.providerId;
  switch (entry.form) {
    case 'server_info':
      return { api_version: 2 };
    case 'tx_absent_range': {
      const max = state.validatedSeq?.[id];
      if (!Number.isSafeInteger(max) || max < C6_XRPL_RANGE) return null;
      return { api_version: 2, binary: false, max_ledger: max, min_ledger: max - C6_XRPL_RANGE, transaction: C6_ABSENT_XRPL_TX };
    }
    case 'chain_id':
      return [];
    case 'head':
      return ['latest', false];
    case 'pin':
      return typeof state.pinNumber === 'string' ? [state.pinNumber, false] : null;
    case 'nonce_at_hash':
    case 'balance_at_hash':
    case 'code_at_hash': {
      const hash = state.pinHash?.[id];
      return typeof hash === 'string' ? [C6_TEST_ADDRESS, pinned(hash)] : null;
    }
    case 'estimate_at_hash': {
      const hash = state.pinHash?.[id];
      return typeof hash === 'string' ? [{ data: C6_CALLDATA, from: C6_TEST_ADDRESS, to: C6_TEST_ADDRESS, value: '0x0' }, pinned(hash)] : null;
    }
    case 'balance_unknown_hash':
      return [C6_TEST_ADDRESS, pinned(C6_UNKNOWN_BLOCK_HASH)];
    case 'finalized':
      return ['finalized', false];
    default:
      throw new TypeError(`unknown form ${entry.form}`);
  }
}

/** The exact request bytes of `entry` with `params` (canonical JSON, as packages/chain-readonly builds them). */
export function entryBytes(entry, params) {
  return requestBytes(providerOf(entry).network, entry.method, params);
}

/** The params template shown in the manifest (placeholders for values only the run observes). */
function template(entry) {
  return buildParams(entry, {
    validatedSeq: { [entry.providerId]: 1_000_000 },
    pinNumber: '<P>',
    pinHash: { [entry.providerId]: `<H:${entry.providerId}>` },
  });
}

/** The manifest as data. fixtures/compat-c6/manifest.json is this, indented for reading; the digest a read authorization binds is of manifestBytes(). */
export function describeManifest() {
  const requests = C6_REQUESTS.map((e) => {
    let params = template(e);
    if (e.form === 'tx_absent_range') params = { ...params, max_ledger: '<validated seq of this provider>', min_ledger: `<validated seq - ${C6_XRPL_RANGE}>` };
    return { seq: e.seq, id: e.id, providerId: e.providerId, url: providerOf(e).url, method: e.method, form: e.form, params, needs: [...e.needs], expect: e.expect };
  });
  return {
    format: C6_MANIFEST_FORMAT,
    totalRequests: C6_TOTAL_REQUESTS,
    budget: { ...C6_BUDGET },
    limits: { ...C6_LIMITS },
    retry: false,
    fallback: false,
    testAddress: C6_TEST_ADDRESS,
    calldata: C6_CALLDATA,
    absentXrplTransaction: C6_ABSENT_XRPL_TX,
    unknownBlockHash: C6_UNKNOWN_BLOCK_HASH,
    pinDepth: C6_PIN_DEPTH,
    providers: C6_PROVIDERS.map((p) => ({ ...p })),
    requests,
  };
}

/** The manifest's canonical bytes: the C6 manifest digest is their SHA-256 (docs §0, §8). */
export const manifestBytes = () => canonicalBytes(describeManifest());

/**
 * Checks the manifest against itself and against the endpoint file (`endpoints`, parsed JSON):
 * exactly the reviewed providers at the reviewed URLs, the budget, read-only methods only.
 * Returns the providers loaded through loadEndpointConfig, in C6 order; throws on any mismatch.
 */
export function checkManifest(endpoints) {
  const problems = [];
  if (C6_REQUESTS.length !== C6_TOTAL_REQUESTS) problems.push('request count');
  const total = Object.values(C6_BUDGET).reduce((a, b) => a + b, 0);
  if (total !== C6_TOTAL_REQUESTS) problems.push('budget total');
  for (const p of C6_PROVIDERS) {
    const n = C6_REQUESTS.filter((e) => e.providerId === p.id).length;
    if (n !== C6_BUDGET[p.id]) problems.push(`budget of ${p.id}`);
  }
  const ids = new Set();
  for (const e of C6_REQUESTS) {
    const provider = providerOf(e);
    if (!provider) problems.push(`${e.id}: provider`);
    else if (!READ_ONLY_METHODS[provider.network]?.includes(e.method)) problems.push(`${e.id}: ${e.method} is not read-only`);
    if (WRITE_METHODS.includes(e.method)) problems.push(`${e.id}: write method`);
    if (ids.has(e.id)) problems.push(`${e.id}: duplicate`);
    ids.add(e.id);
  }
  const loaded = loadEndpointConfig(endpoints);
  if (loaded.length !== C6_PROVIDERS.length) problems.push('the endpoint file is not exactly the four reviewed providers');
  const providers = C6_PROVIDERS.map((p) => {
    const found = loaded.find((l) => l.id === p.id);
    if (!found) problems.push(`${p.id}: not in the endpoint file`);
    else if (found.url !== p.url || found.network !== p.network) problems.push(`${p.id}: not at its reviewed url and network`);
    return found ?? p;
  });
  if (problems.length > 0) throw new TypeError(`C6 manifest: ${problems.join('; ')}`);
  return providers;
}
