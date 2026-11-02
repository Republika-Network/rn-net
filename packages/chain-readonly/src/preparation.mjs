// Transaction-preparation readers (RN-NET-03B2-B2, ADR-RN-018, spec/rnnet.tx-preparation.v1.md §3).
// Each one reads, from one provider and through the injected transport, the account and fee state
// that an unsigned Genesis transaction is bound from. It checks the shape of every value it keeps
// and refuses anything malformed; it decides nothing about freshness, fees or agreement, which
// packages/tx-prepare checks across providers.
//
// Read-only: the requests are built by rpc.mjs from the allowlist, so no write, signing or wallet
// method can be expressed. Nothing here holds or derives a key.
import { RawNumber } from './json.mjs';
import { call, Network, ReadError } from './rpc.mjs';

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : v instanceof RawNumber ? 'raw-number' : typeof v);
const bad = (what) => new ReadError('RNLO_INVALID_RESPONSE', what);

const XRPL_TESTNET_NETWORK_ID = 1;
const SEPOLIA_CHAIN_ID = '0xaa36a7';
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const LEDGER_HASH = /^[0-9A-F]{64}$/;
const DROPS = /^(?:0|[1-9][0-9]{0,17})$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;
const isUint32 = (v) => Number.isInteger(v) && v >= 0 && v <= 0xffff_ffff;
const isSafeNonNegative = (v) => Number.isSafeInteger(v) && v >= 0;

/**
 * The exact request list of one preparation reading, per provider, in order. Sepolia follows
 * ADR-RN-018 Amendment C1 (P1, P3; RN-NET-03B2-C3): the head pass (2), the pin block (1), then five
 * reads pinned to the agreed block hash, the pending nonce excepted (5). 8 in all.
 */
export const PREPARATION_REQUESTS = Object.freeze({
  [Network.XRPL_TESTNET]: Object.freeze(['server_info', 'account_info']),
  [Network.SEPOLIA]: Object.freeze([
    'eth_chainId', 'eth_getBlockByNumber', 'eth_getBlockByNumber',
    'eth_getTransactionCount', 'eth_getTransactionCount', 'eth_getBalance', 'eth_getCode', 'eth_estimateGas',
  ]),
});

const DECIMAL = /^(0|[1-9][0-9]{0,29})(?:\.([0-9]{1,30}))?(?:[eE]([+-]?[0-9]{1,2}))?$/;

/**
 * A non-negative JSON number (a safe integer, or a RawNumber's exact text such as `1e-05` or
 * `0.2`) as an exact fraction { num, den } of BigInts, den a power of ten. Never a float.
 * Returns null for anything else.
 */
export function xrpDecimal(value) {
  let text;
  if (Number.isSafeInteger(value) && value >= 0) text = String(value);
  else if (value instanceof RawNumber) text = value.text;
  else return null;
  const match = DECIMAL.exec(text);
  if (!match) return null;
  const [, whole, fraction = '', exponentText = '0'] = match;
  const exponent = Number(exponentText) - fraction.length;
  const digits = BigInt(whole + fraction);
  return exponent >= 0 ? { num: digits * 10n ** BigInt(exponent), den: 1n } : { num: digits, den: 10n ** BigInt(-exponent) };
}

/** An XRP amount given as a decimal number of XRP, in whole drops; null if not whole drops. */
function xrpToDrops(value) {
  const fraction = xrpDecimal(value);
  if (fraction === null) return null;
  const scaled = fraction.num * 1_000_000n;
  if (scaled % fraction.den !== 0n) return null;
  const drops = scaled / fraction.den;
  return drops <= 100_000_000_000_000_000n ? drops : null;
}

// --- XRPL Testnet --------------------------------------------------------------------------------

/**
 * Reads server_info, then account_info on the validated ledger, for one account.
 * Returns plain values (BigInts for amounts and the load factor's fraction). Throws ReadError:
 * RNLO_NETWORK_UNKNOWN or RNLO_WRONG_NETWORK before account_info is sent; RNLO_RPC_ERROR (detail
 * `actNotFound` for an unfunded account); RNLO_INVALID_RESPONSE for any malformed value.
 */
export async function readXrplAccount(context, account) {
  if (typeof account !== 'string' || !XRPL_ACCOUNT.test(account)) throw new TypeError('account must be an XRPL classic address');
  const server = await call(context, 'server_info', { api_version: 2 });
  const info = kind(server.info) === 'object' ? server.info : null;
  if (info === null) throw bad('info');
  if (info.network_id === undefined) throw new ReadError('RNLO_NETWORK_UNKNOWN');
  if (!Number.isSafeInteger(info.network_id)) throw bad('network_id');
  if (info.network_id !== XRPL_TESTNET_NETWORK_ID) throw new ReadError('RNLO_WRONG_NETWORK');
  if (typeof info.server_state !== 'string') throw bad('server_state');
  const ledger = kind(info.validated_ledger) === 'object' ? info.validated_ledger : null;
  if (ledger === null) throw bad('validated_ledger');
  if (!isUint32(ledger.seq) || ledger.seq === 0) throw bad('validated_ledger.seq');
  if (typeof ledger.hash !== 'string' || !LEDGER_HASH.test(ledger.hash)) throw bad('validated_ledger.hash');
  if (!isSafeNonNegative(ledger.age)) throw bad('validated_ledger.age');
  const baseFeeDrops = xrpToDrops(ledger.base_fee_xrp);
  const reserveBaseDrops = xrpToDrops(ledger.reserve_base_xrp);
  const reserveIncDrops = xrpToDrops(ledger.reserve_inc_xrp);
  if (baseFeeDrops === null || baseFeeDrops === 0n) throw bad('validated_ledger.base_fee_xrp');
  if (reserveBaseDrops === null) throw bad('validated_ledger.reserve_base_xrp');
  if (reserveIncDrops === null) throw bad('validated_ledger.reserve_inc_xrp');
  const loadFactor = xrpDecimal(info.load_factor);
  if (loadFactor === null || loadFactor.num < loadFactor.den) throw bad('load_factor');

  const result = await call(context, 'account_info', { account, ledger_index: 'validated', signer_lists: true, api_version: 2 });
  if (typeof result.validated !== 'boolean') throw bad('validated');
  if (!isUint32(result.ledger_index) || result.ledger_index === 0) throw bad('ledger_index');
  if (typeof result.ledger_hash !== 'string' || !LEDGER_HASH.test(result.ledger_hash)) throw bad('ledger_hash');
  const data = kind(result.account_data) === 'object' ? result.account_data : null;
  if (data === null) throw bad('account_data');
  if (typeof data.Account !== 'string' || !XRPL_ACCOUNT.test(data.Account)) throw bad('account_data.Account');
  if (typeof data.Balance !== 'string' || !DROPS.test(data.Balance)) throw bad('account_data.Balance');
  if (!isUint32(data.Sequence) || data.Sequence === 0) throw bad('account_data.Sequence');
  if (!isUint32(data.OwnerCount)) throw bad('account_data.OwnerCount');
  if (!isUint32(data.Flags)) throw bad('account_data.Flags');
  if (Object.hasOwn(data, 'RegularKey') && (typeof data.RegularKey !== 'string' || !XRPL_ACCOUNT.test(data.RegularKey))) throw bad('account_data.RegularKey');
  // API v2 returns signer_lists at the top level of the result.
  if (!Array.isArray(result.signer_lists)) throw bad('signer_lists');

  return {
    serverState: info.server_state,
    validatedLedger: { index: ledger.seq, hash: ledger.hash, age: ledger.age },
    baseFeeDrops,
    reserveBaseDrops,
    reserveIncDrops,
    loadFactor,
    accountLedger: { index: result.ledger_index, hash: result.ledger_hash, validated: result.validated },
    account: data.Account,
    balanceDrops: BigInt(data.Balance),
    sequence: data.Sequence,
    ownerCount: data.OwnerCount,
    flags: data.Flags,
    hasRegularKey: Object.hasOwn(data, 'RegularKey'),
    signerListCount: result.signer_lists.length,
  };
}

// --- Ethereum Sepolia ---------------------------------------------------------------------------

const quantity = (value, what) => {
  if (typeof value !== 'string' || !QUANTITY.test(value)) throw bad(what);
  return value;
};

/** A block object's four kept members, each checked; anything else is RNLO_INVALID_RESPONSE. */
function blockOf(block) {
  if (kind(block) !== 'object') throw bad('block');
  const number = quantity(block.number, 'block.number');
  if (typeof block.hash !== 'string' || !EVM_HASH.test(block.hash)) throw bad('block.hash');
  const timestamp = quantity(block.timestamp, 'block.timestamp');
  const baseFeePerGas = quantity(block.baseFeePerGas, 'block.baseFeePerGas');
  return { number, hash: block.hash, timestamp, baseFeePerGas };
}

/**
 * Sepolia preparation, pass 1 (ADR-RN-018 Amendment C1, P1.1): eth_chainId, then the latest block.
 * Throws ReadError: RNLO_WRONG_NETWORK before the block is read; RNLO_RPC_ERROR; RNLO_INVALID_RESPONSE.
 */
export async function readSepoliaHead(context) {
  const chainId = quantity(await call(context, 'eth_chainId', []), 'chainId');
  if (chainId !== SEPOLIA_CHAIN_ID) throw new ReadError('RNLO_WRONG_NETWORK');
  return { chainId, block: blockOf(await call(context, 'eth_getBlockByNumber', ['latest', false])) };
}

/**
 * Sepolia preparation, the pin (P1.3): the block at `number` (a quantity), by number. The caller
 * checks that the block returned is that number and that every provider returned the same hash.
 */
export async function readSepoliaPin(context, number) {
  if (typeof number !== 'string' || !QUANTITY.test(number)) throw new TypeError('number must be a quantity');
  return blockOf(await call(context, 'eth_getBlockByNumber', [number, false]));
}

/**
 * Sepolia preparation, pass 2 (P1.4): the sender's nonce, balance and code and the gas estimate of
 * the exact unsigned call, each at `{blockHash, requireCanonical: true}` (EIP-1898); the pending
 * nonce with the `pending` tag, which has no hash. There is no other form: a provider that refuses
 * the block-hash object refuses preparation (P2), and nothing here retries by number or by tag.
 * eth_estimateGas is not in EIP-1898; it is sent in the same form, never another (P4).
 * Returns hex quantities as received. Throws ReadError: RNLO_RPC_ERROR; RNLO_INVALID_RESPONSE.
 * @param {{ from: string, input: string, blockHash: string }} request
 */
export async function readSepoliaPinned(context, { from, input, blockHash }) {
  if (typeof from !== 'string' || !EVM_ADDRESS.test(from)) throw new TypeError('from must be a lowercase address');
  if (typeof input !== 'string' || !HEX_DATA.test(input)) throw new TypeError('input must be 0x-prefixed lowercase hex data');
  if (typeof blockHash !== 'string' || !EVM_HASH.test(blockHash)) throw new TypeError('blockHash must be 0x + 64 lowercase hex');
  const at = { blockHash, requireCanonical: true };
  const nonceLatest = quantity(await call(context, 'eth_getTransactionCount', [from, at]), 'nonce');
  const noncePending = quantity(await call(context, 'eth_getTransactionCount', [from, 'pending']), 'pending nonce');
  // EIP-2681: a nonce is below 2^64.
  if (BigInt(nonceLatest) >= 2n ** 64n || BigInt(noncePending) >= 2n ** 64n) throw bad('nonce');
  const balance = quantity(await call(context, 'eth_getBalance', [from, at]), 'balance');
  const code = await call(context, 'eth_getCode', [from, at]);
  if (typeof code !== 'string' || !HEX_DATA.test(code)) throw bad('code');
  const estimate = quantity(await call(context, 'eth_estimateGas', [{ from, to: from, value: '0x0', data: input }, at]), 'estimateGas');
  return { nonceLatest, noncePending, balance, code, estimateGas: estimate };
}
