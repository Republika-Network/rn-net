// Simulated providers for the C6 run (RN-NET-03B2-C6-PREP). OFFLINE: a pure function from a
// request to a response; nothing here is real provider behaviour. Each scenario is a healthy
// world plus overrides that model one finding (a refused block-hash form, a disagreement, a lag).
// The error texts are illustrative only: no provider's real error shape is known before C6.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { C6_PROVIDERS, C6_REQUESTS, C6_UNKNOWN_BLOCK_HASH } from './manifest.mjs';
import { intrinsicGas } from './classify.mjs';

export const SIM_NOW = 1_793_000_000;
const hex = (label) => createHash('sha256').update(label, 'utf8').digest('hex');
const q = (n) => `0x${BigInt(n).toString(16)}`;
const blockHash = (n, fork = '') => `0x${hex(`sim-sepolia${fork}:${n}`)}`;
const ledgerHash = (n, fork = '') => hex(`sim-xrpl${fork}:${n}`).toUpperCase();
const json = (value) => Buffer.from(JSON.stringify(value), 'utf8');

/** The default (healthy) world; `s` overrides parts of it. */
function world(s) {
  const now = s.now ?? SIM_NOW;
  return {
    now,
    xrpl: {
      'xrpl-testnet-ripple': { networkId: 1, build: '3.4.1', seq: 21_950_000, age: 2, complete: '21900000-21950000', fork: '', state: 'full', ...(s.xrpl?.['xrpl-testnet-ripple'] ?? {}) },
      'xrpl-testnet-xrpl-labs': { networkId: 1, build: '3.4.1', seq: 21_950_001, age: 1, complete: '21000000-21950001', fork: '', state: 'full', ...(s.xrpl?.['xrpl-testnet-xrpl-labs'] ?? {}) },
    },
    searchedAll: s.searchedAll ?? {},
    sepolia: {
      'sepolia-publicnode': { chainId: '0xaa36a7', head: 9_500_000, headAge: 6, fork: '', pinFork: '', finalizedLag: 70, ...(s.sepolia?.['sepolia-publicnode'] ?? {}) },
      'sepolia-1rpc': { chainId: '0xaa36a7', head: 9_500_001, headAge: 1, fork: '', pinFork: '', finalizedLag: 71, ...(s.sepolia?.['sepolia-1rpc'] ?? {}) },
    },
    override: s.override ?? {},
  };
}

/**
 * A simulated transport for scenario `s`. Overrides by manifest id:
 *   { rpcError: { code, message }, httpStatus? } | { timeout: true } | { connection: true }
 *   | { http: status, text } | { result } | { text, status?, pad? }.
 */
export function simulatedTransport(s = {}) {
  const w = world(s);
  return async (request) => {
    const provider = C6_PROVIDERS.find((p) => p.id === request.providerId);
    if (!provider || provider.url !== request.url) throw new Error('simulated: unknown provider or url');
    const body = JSON.parse(Buffer.from(request.body).toString('utf8'));
    const entry = resolveEntry(provider.id, body);
    if (!entry) throw new Error(`simulated: unplanned request ${body.method}`);
    const o = w.override[entry.id];
    if (o?.timeout) throw Object.assign(new Error('timeout'), { code: 'RNLO_TIMEOUT' });
    if (o?.connection) throw Object.assign(new Error('connection'), { code: 'RNLO_CONNECTION' });
    if (o?.text !== undefined) return { status: o.status ?? 200, body: Buffer.concat([Buffer.from(o.text, 'utf8'), Buffer.alloc(o.pad ?? 0, 0x20)]) };
    if (o?.http !== undefined) return { status: o.http, body: Buffer.from(o.httpText ?? '', 'utf8') };
    if (provider.network === 'xrpl:testnet') return { status: 200, body: json({ result: xrplResult(w, provider.id, entry, body.params[0], o) }) };
    if (o?.rpcError) return { status: o.httpStatus ?? 200, body: json({ jsonrpc: '2.0', id: 1, error: o.rpcError }) };
    // A healthy provider refuses a block hash it does not know (geth: -32000 "header for hash not found").
    if (entry.form === 'balance_unknown_hash' && !(o && Object.hasOwn(o, 'result'))) return { status: 200, body: json({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'header for hash not found' } }) };
    return { status: 200, body: json({ jsonrpc: '2.0', id: 1, result: o && Object.hasOwn(o, 'result') ? o.result : sepoliaResult(w, provider.id, entry, body.params) }) };
  };
}

function resolveEntry(providerId, body) {
  const forms = C6_REQUESTS.filter((e) => e.providerId === providerId && e.method === body.method);
  if (forms.length === 1) return forms[0];
  const p = body.params;
  if (body.method === 'eth_getBlockByNumber') return forms.find((e) => e.form === (p[0] === 'latest' ? 'head' : p[0] === 'finalized' ? 'finalized' : 'pin'));
  if (body.method === 'eth_getBalance') return forms.find((e) => e.form === (p[1]?.blockHash === C6_UNKNOWN_BLOCK_HASH ? 'balance_unknown_hash' : 'balance_at_hash'));
  return undefined;
}
function xrplResult(w, id, entry, params, o) {
  const x = w.xrpl[id];
  if (o?.rpcError) return { status: 'error', error: o.rpcError.error, error_code: o.rpcError.code, error_message: o.rpcError.message, request: params };
  if (entry.method === 'server_info') {
    return { status: 'success', info: { build_version: x.build, complete_ledgers: x.complete, network_id: x.networkId, server_state: x.state, load_factor: 1, validated_ledger: { age: x.age, base_fee_xrp: 0.00001, hash: ledgerHash(x.seq, x.fork), reserve_base_xrp: 1, reserve_inc_xrp: 0.2, seq: x.seq } } };
  }
  const searched = Object.hasOwn(w.searchedAll, id) ? w.searchedAll[id] : true;
  const r = { status: 'error', error: 'txnNotFound', error_code: 29, error_message: 'Transaction not found.', request: params };
  if (searched !== undefined) r.searched_all = searched;
  return r;
}

function sepoliaResult(w, id, entry, params) {
  const e = w.sepolia[id];
  const block = (n, fork) => ({ number: q(n), hash: blockHash(n, fork), parentHash: blockHash(n - 1, fork), timestamp: q(w.now - e.headAge - (e.head - n) * 12), baseFeePerGas: q(1_000_000_000), transactions: [] });
  switch (entry.form) {
    case 'chain_id':
      return e.chainId;
    case 'head':
      return block(e.head, e.fork);
    case 'pin':
      return block(Number(BigInt(params[0])), e.pinFork);
    case 'nonce_at_hash':
    case 'balance_at_hash':
      return '0x0';
    case 'code_at_hash':
      return '0x';
    case 'estimate_at_hash':
      return q(intrinsicGas());
    case 'finalized':
      return block(e.head - e.finalizedLag, e.fork);
    default:
      throw new Error('simulated: form');
  }
}

/** The C6 scenarios: name, the decision they model and their overrides. */
export const SCENARIOS = Object.freeze([
  { name: 'all-compatible', models: 'A' },
  { name: 'estimate-gas-refused-publicnode', models: 'B', override: { S10: { rpcError: { code: -32602, message: 'invalid argument 1: hex string without 0x prefix' } } } },
  { name: 'estimate-gas-refused-both', models: 'B', override: { S10: { rpcError: { code: -32602, message: 'invalid block parameter' } }, S14: { rpcError: { code: -32602, message: 'invalid block parameter' } } } },
  { name: 'estimate-gas-refused-http-400', models: 'B', override: { S14: { rpcError: { code: -32600, message: 'unsupported block parameter' }, httpStatus: 400 } } },
  { name: 'estimate-gas-above-limit', models: 'B', override: { S10: { result: '0x7531' } } },
  { name: 'pin-hash-disagreement', models: 'C', sepolia: { 'sepolia-1rpc': { pinFork: '-fork' } } },
  { name: 'head-same-number-two-hashes', models: 'C', sepolia: { 'sepolia-1rpc': { head: 9_500_000, fork: '-fork' } } },
  { name: 'finality-lag-blocks-window', models: 'D', sepolia: { 'sepolia-1rpc': { finalizedLag: 335 } } },
  { name: 'finality-lag-unresolved', models: 'UNRESOLVED', sepolia: { 'sepolia-1rpc': { finalizedLag: 170 } } },
  { name: 'estimate-refused-and-finality-lag', models: 'B+D', override: { S14: { rpcError: { code: -32602, message: 'invalid block parameter' } } }, sepolia: { 'sepolia-1rpc': { finalizedLag: 335 } } },
  { name: 'account-read-refused-1rpc', models: 'E', override: { S12: { rpcError: { code: -32602, message: 'invalid argument 1: json: cannot unmarshal object' } } } },
  { name: 'unknown-hash-served', models: 'E', override: { S16: { result: '0x0' } } },
  { name: 'sepolia-wrong-chain-1rpc', models: 'E', sepolia: { 'sepolia-1rpc': { chainId: '0x1' } } },
  { name: 'head-timeout-1rpc', models: 'UNRESOLVED', override: { S04: { timeout: true } } },
  { name: 'head-stale', models: 'UNRESOLVED', sepolia: { 'sepolia-publicnode': { headAge: 75 } } },
  { name: 'head-skew-5', models: 'UNRESOLVED', sepolia: { 'sepolia-1rpc': { head: 9_500_005 } } },
  { name: 'estimate-rate-limited', models: 'UNRESOLVED', override: { S10: { http: 429 } } },
  { name: 'code-invalid-json', models: 'UNRESOLVED', override: { S09: { text: '{"jsonrpc":"2.0","id":1,"result":' } } },
  { name: 'response-too-large', models: 'UNRESOLVED', override: { S07: { text: '{"jsonrpc":"2.0","id":1,"result":"0x0"}', pad: 262_145 } } },
  { name: 'error-message-sanitized', models: 'B', override: { S10: { rpcError: { code: -32000, message: 'upstream https://10.0.0.7:8545/x?key=abc failed at 192.168.1.20 \u00e9\u{1F600}\n' + 'x'.repeat(200) } } } },
  { name: 'xrpl-wrong-network-labs', models: 'XRPL BLOCKED', xrpl: { 'xrpl-testnet-xrpl-labs': { networkId: 0 } } },
  { name: 'xrpl-build-version-differs', models: 'XRPL UNRESOLVED', xrpl: { 'xrpl-testnet-ripple': { build: '3.5.0' } } },
  { name: 'xrpl-searched-all-false', models: 'XRPL BLOCKED', searchedAll: { 'xrpl-testnet-ripple': false } },
  { name: 'xrpl-searched-all-absent', models: 'XRPL BLOCKED', searchedAll: { 'xrpl-testnet-xrpl-labs': undefined } },
  { name: 'xrpl-history-short', models: 'XRPL BLOCKED', xrpl: { 'xrpl-testnet-ripple': { complete: '21949500-21950000' } } },
  { name: 'xrpl-stale', models: 'XRPL UNRESOLVED', xrpl: { 'xrpl-testnet-xrpl-labs': { age: 45 } } },
  { name: 'xrpl-ledger-conflict', models: 'XRPL BLOCKED', xrpl: { 'xrpl-testnet-xrpl-labs': { seq: 21_950_000, fork: '-fork', complete: '21000000-21950000' } } },
  { name: 'xrpl-server-info-connection-error', models: 'XRPL UNRESOLVED', override: { X01: { connection: true } } },
].map((s) => Object.freeze(s)));
