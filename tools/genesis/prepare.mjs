// Offline preparation of the Genesis Proof 01 anchoring transactions (RN-NET-03B2-A).
//
// Everything here is pure: it builds and checks *unsigned* transaction descriptions from a
// commitment, and builds synthetic "rehearsal" observations that show the existing
// rnnet.anchor-record.v1 checks would accept the intended transactions. It holds no key, signs
// nothing, serializes nothing for submission and never opens a connection. Signing and
// broadcasting are later milestones, each behind its own founder decision
// (docs/genesis/genesis-proof-01-authorization.md).
//
// Formats are unchanged: the payload is rnnet.anchor-payload.v1 and the transports are those of
// rnnet.anchor-record.v1 §3.1 (XRPL) and §4.1 (Sepolia).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { ANCHOR_MEMO_TYPE, encodeAnchorPayload, SEPOLIA_CHAIN_ID } from '../../packages/anchor/src/index.mjs';

const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const checkCommitment = (c) => {
  if (typeof c !== 'string' || !COMMITMENT.test(c)) throw new TypeError('commitment must be sha256:<64 lowercase hex>');
  return c;
};
const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const isUint32 = (v) => Number.isInteger(v) && v >= 1 && v <= 0xffff_ffff;

/**
 * Whether a value is plain JSON data: strings, numbers, booleans, null, and arrays and objects
 * whose prototype is the default one (or null for objects), with only own, enumerable data
 * properties, all plain, and no Proxy anywhere. The checks below refuse anything else, so an
 * inherited field, a getter or a Proxy cannot show the checks one value and a signer another.
 * What is signed must be exactly the canonical JSON of the object that was checked.
 */
export function isPlainData(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object' || types.isProxy(value)) return false;
  const array = Array.isArray(value);
  const proto = Object.getPrototypeOf(value);
  if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) return false;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') return false;
    if (array && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!Object.hasOwn(descriptor, 'value') || !descriptor.enumerable || !isPlainData(descriptor.value)) return false;
  }
  return true;
}
const NOT_PLAIN = 'transaction must be plain JSON data (no inherited fields, accessors or proxies)';

/** The 42 payload bytes as lowercase hex. */
export const payloadHex = (commitment) => Buffer.from(encodeAnchorPayload(checkCommitment(commitment))).toString('hex');

// --- XRPL Testnet ------------------------------------------------------------------------------

export const XRPL = Object.freeze({
  network: 'xrpl:testnet',
  /** Testnet's network ID. Networks with ID 1024 or less must omit the NetworkID field. */
  networkId: 1,
  /** Proposed fee in drops: the 10-drop reference cost plus a small margin. */
  feeDrops: '12',
  /** Hard cap: a description with a higher fee is refused (0.001 XRP). */
  maxFeeDrops: 1000n,
  /** Proposed validity window: LastLedgerSequence = latest validated ledger + this. */
  lastLedgerOffset: 20,
  /** The serialized Memos field may be at most 1 KB (XRPL common fields). */
  maxMemosBytes: 1024,
});

/** Fields an unsigned Genesis AccountSet may have. Anything else, NetworkID included, is refused. */
const XRPL_FIELDS = ['TransactionType', 'Account', 'Fee', 'Sequence', 'LastLedgerSequence', 'Flags', 'Memos', 'SigningPubKey'];
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const XRPL_SIGNING_KEY = /^ED[0-9A-F]{64}$/; // an Ed25519 key, as XRPL writes it
const DROPS = /^[1-9][0-9]{0,18}$/;

/**
 * Length of the serialized Memos field for memos of the given blob lengths (bytes): field header
 * 0xF9 (STArray Memos), then per memo 0xEA (STObject Memo), each blob's one-byte field header
 * (0x7C MemoType, 0x7D MemoData) and length prefix, 0xE1 (end of object), and finally 0xF1 (end
 * of array). One-byte length prefixes hold up to 192 bytes, which is all this needs.
 */
export function memosSerializedLength(memos) {
  let total = 2;
  for (const blobs of memos) {
    total += 2;
    for (const length of blobs) {
      if (!Number.isInteger(length) || length < 0 || length > 192) throw new RangeError('blob length outside one-byte prefix range');
      total += 2 + length;
    }
  }
  return total;
}

/** The intended anchor memo for a commitment (rnnet.anchor-record.v1 §3.1). */
export const xrplAnchorMemo = (commitment) => ({ Memo: { MemoType: ANCHOR_MEMO_TYPE, MemoData: payloadHex(commitment).toUpperCase() } });

/**
 * The unsigned Genesis AccountSet. Fields that can only be known when an account exists and the
 * ledger is read (Account, Sequence, LastLedgerSequence, SigningPubKey) are `null` here and are
 * bound at signing time (gate D).
 */
export function xrplAnchorTemplate(commitment, bound = {}) {
  return {
    TransactionType: 'AccountSet',
    Account: bound.Account ?? null,
    Fee: bound.Fee ?? XRPL.feeDrops,
    Sequence: bound.Sequence ?? null,
    LastLedgerSequence: bound.LastLedgerSequence ?? null,
    Memos: [xrplAnchorMemo(commitment)],
    ...(bound.SigningPubKey === undefined ? {} : { SigningPubKey: bound.SigningPubKey }),
  };
}

/**
 * Checks a completed, unsigned Genesis AccountSet against the intended construction. Returns the
 * list of problems (empty when it is acceptable to sign). Stricter than the anchor-record checks
 * on purpose: those accept any valid anchor, this accepts only the one Genesis transaction.
 */
export function checkXrplAnchorTx(tx, commitment) {
  checkCommitment(commitment);
  const problems = [];
  if (kind(tx) !== 'object') return ['transaction is not an object'];
  if (!isPlainData(tx)) return [NOT_PLAIN];
  for (const key of Object.keys(tx)) if (!XRPL_FIELDS.includes(key)) problems.push(key === 'NetworkID' ? 'NetworkID must be omitted on XRPL Testnet (network ID 1)' : `unexpected field ${key}`);
  if (tx.TransactionType !== 'AccountSet') problems.push('TransactionType must be AccountSet');
  if (typeof tx.Account !== 'string' || !XRPL_ACCOUNT.test(tx.Account)) problems.push('Account must be a classic address');
  if (typeof tx.Fee !== 'string' || !DROPS.test(tx.Fee)) problems.push('Fee must be a decimal string of drops');
  else if (BigInt(tx.Fee) > XRPL.maxFeeDrops) problems.push(`Fee exceeds the ${XRPL.maxFeeDrops}-drop cap`);
  if (!isUint32(tx.Sequence)) problems.push('Sequence must be an integer from 1 to 4294967295');
  if (!isUint32(tx.LastLedgerSequence)) problems.push('LastLedgerSequence is required (expiry) and must be an integer from 1 to 4294967295');
  if (Object.hasOwn(tx, 'Flags') && tx.Flags !== 0) problems.push('Flags must be absent or 0');
  if (Object.hasOwn(tx, 'SigningPubKey') && (typeof tx.SigningPubKey !== 'string' || !XRPL_SIGNING_KEY.test(tx.SigningPubKey))) problems.push('SigningPubKey must be an Ed25519 key (ED + 64 uppercase hex)');
  const expected = xrplAnchorMemo(commitment).Memo;
  const memos = tx.Memos;
  if (!Array.isArray(memos) || memos.length !== 1) problems.push('Memos must hold exactly one memo');
  else {
    const entry = memos[0];
    const memo = kind(entry) === 'object' && Object.keys(entry).length === 1 ? entry.Memo : undefined;
    if (kind(memo) !== 'object') problems.push('the memo must be exactly {"Memo": {...}}');
    else {
      if (Object.keys(memo).sort().join(',') !== 'MemoData,MemoType') problems.push('the memo must have exactly MemoType and MemoData (no MemoFormat)');
      if (memo.MemoType !== expected.MemoType) problems.push('MemoType must be hex("rnnet.anchor-payload.v1") in upper case');
      if (memo.MemoData !== expected.MemoData) problems.push('MemoData must be the 42-byte payload of the commitment in upper case');
      // The only accepted memo is the expected one, whose Memos field is 73 bytes (golden.json), far under 1 KB.
    }
  }
  return problems;
}

// --- Ethereum Sepolia --------------------------------------------------------------------------

const GWEI = 1_000_000_000n;
export const SEPOLIA = Object.freeze({
  network: 'evm:11155111',
  chainId: SEPOLIA_CHAIN_ID,
  /** EIP-1559 transaction. */
  type: '0x2',
  /** Gas limit: above the intrinsic cost under Prague rules, with margin for calldata repricing. */
  gasLimit: 30_000n,
  /** Hard cap on maxFeePerGas: 20 gwei. */
  maxFeePerGasCapWei: 20n * GWEI,
  /** Proposed priority fee: 1 gwei. */
  maxPriorityFeePerGasWei: 1n * GWEI,
});

const ADDRESS = /^0x[0-9a-f]{40}$/;
const QUANTITY = /^0x(0|[1-9a-f][0-9a-f]*)$/;
const quantity = (n) => `0x${BigInt(n).toString(16)}`;
const SEPOLIA_FIELDS = ['type', 'chainId', 'nonce', 'from', 'to', 'value', 'input', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList'];

/**
 * Intrinsic gas of a transaction with this calldata to an account without code, under the Prague
 * rules (EIP-2028 calldata cost and the EIP-7623 floor). With no execution, gas used is the larger
 * of the two. A later fork may reprice calldata; gas used must be confirmed before signing.
 */
export function intrinsicGas(data) {
  const zero = data.filter((b) => b === 0).length;
  const nonzero = data.length - zero;
  const tokens = zero + 4 * nonzero;
  const standard = 21_000 + 4 * tokens;
  const floor = 21_000 + 10 * tokens;
  return { zeroBytes: zero, nonzeroBytes: nonzero, tokens, standard, floor, gasUsed: Math.max(standard, floor) };
}

/**
 * The unsigned Genesis transaction: a zero-value EIP-1559 self-send whose input is exactly the
 * payload. `from`/`to`, `nonce` and `maxFeePerGas` are `null` here and bound at signing time.
 */
export function sepoliaAnchorTemplate(commitment, bound = {}) {
  return {
    type: SEPOLIA.type,
    chainId: SEPOLIA.chainId,
    nonce: bound.nonce ?? null,
    from: bound.from ?? null,
    to: bound.from ?? null,
    value: '0x0',
    input: `0x${payloadHex(commitment)}`,
    gas: quantity(SEPOLIA.gasLimit),
    maxFeePerGas: bound.maxFeePerGas ?? null,
    maxPriorityFeePerGas: quantity(SEPOLIA.maxPriorityFeePerGasWei),
    accessList: [],
  };
}

/**
 * maxFeePerGas from an observed base fee: twice the base fee plus the priority fee (headroom for
 * five consecutive full blocks of 12.5% base-fee growth), never above the cap.
 */
export function sepoliaMaxFee(baseFeePerGasHex) {
  if (typeof baseFeePerGasHex !== 'string' || !QUANTITY.test(baseFeePerGasHex)) throw new TypeError('baseFeePerGas must be a quantity');
  const wanted = 2n * BigInt(baseFeePerGasHex) + SEPOLIA.maxPriorityFeePerGasWei;
  return quantity(wanted < SEPOLIA.maxFeePerGasCapWei ? wanted : SEPOLIA.maxFeePerGasCapWei);
}

/** Checks a completed, unsigned Genesis Sepolia transaction. Returns the problems (empty if acceptable). */
export function checkSepoliaAnchorTx(tx, commitment) {
  checkCommitment(commitment);
  const problems = [];
  if (kind(tx) !== 'object') return ['transaction is not an object'];
  if (!isPlainData(tx)) return [NOT_PLAIN];
  for (const key of Object.keys(tx)) if (!SEPOLIA_FIELDS.includes(key)) problems.push(`unexpected field ${key}`);
  for (const key of SEPOLIA_FIELDS) if (!Object.hasOwn(tx, key)) problems.push(`missing field ${key}`);
  if (tx.type !== SEPOLIA.type) problems.push('type must be 0x2 (EIP-1559)');
  if (tx.chainId !== SEPOLIA.chainId) problems.push('chainId must be 0xaa36a7 (11155111)');
  const q = (name) => typeof tx[name] === 'string' && QUANTITY.test(tx[name]);
  for (const name of ['nonce', 'value', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas']) if (Object.hasOwn(tx, name) && !q(name)) problems.push(`${name} must be a quantity`);
  if (typeof tx.from !== 'string' || !ADDRESS.test(tx.from)) problems.push('from must be a lowercase address');
  if (tx.to === null || tx.to === undefined) problems.push('to must be set: no contract creation');
  else if (tx.to !== tx.from) problems.push('to must equal from (self-send)');
  if (q('value') && tx.value !== '0x0') problems.push('value must be 0x0');
  const expectedInput = `0x${payloadHex(commitment)}`;
  if (tx.input !== expectedInput) problems.push('input must be exactly the 42-byte payload');
  if (!Array.isArray(tx.accessList) || tx.accessList.length !== 0) problems.push('accessList must be empty');
  if (q('gas')) {
    const gas = BigInt(tx.gas);
    const needed = BigInt(intrinsicGas(Buffer.from(expectedInput.slice(2), 'hex')).gasUsed);
    if (gas < needed) problems.push(`gas is below the intrinsic ${needed}`);
    if (gas > SEPOLIA.gasLimit) problems.push(`gas exceeds the ${SEPOLIA.gasLimit} limit`);
  }
  if (q('maxFeePerGas') && BigInt(tx.maxFeePerGas) > SEPOLIA.maxFeePerGasCapWei) problems.push('maxFeePerGas exceeds the 20 gwei cap');
  if (q('maxFeePerGas') && q('maxPriorityFeePerGas') && BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas)) problems.push('maxPriorityFeePerGas exceeds maxFeePerGas');
  return problems;
}

/** Most wei the transaction can cost: gas limit × maxFeePerGas. */
export const sepoliaMaxCostWei = (tx) => BigInt(tx.gas) * BigInt(tx.maxFeePerGas);

// --- rehearsal ---------------------------------------------------------------------------------
// Synthetic observations of the intended transactions as a node would report them once included.
// Every hash, ledger, block and account below is derived from a label and exists on no network.

const label = (text) => createHash('sha256').update(`rnnet:synthetic-genesis-rehearsal:${text}`).digest('hex');
export const REHEARSAL = Object.freeze({
  xrplAccount: 'rGenesisRehearsaSyntheticAccount',
  xrplSigningPubKey: `ED${label('xrpl-key').toUpperCase()}`,
  xrplSequence: 1_000_001,
  xrplLedger: 1_000_020,
  xrplTransactionIndex: 0,
  evmFrom: `0x${label('evm-account').slice(0, 40)}`,
  evmBlock: 12_000_000,
  evmTransactionIndex: 0,
  evmBaseFeePerGas: '0x11',
});
const ctid = (ledger, index, network) => `C${((BigInt(ledger) << 32n) | (BigInt(index) << 16n) | BigInt(network)).toString(16).toUpperCase().padStart(15, '0')}`;

/** The completed, unsigned XRPL and Sepolia transactions the rehearsal uses. */
export function rehearsalTransactions(commitment) {
  const xrpl = xrplAnchorTemplate(commitment, {
    Account: REHEARSAL.xrplAccount,
    Sequence: REHEARSAL.xrplSequence,
    LastLedgerSequence: REHEARSAL.xrplLedger - 2 + XRPL.lastLedgerOffset,
    SigningPubKey: REHEARSAL.xrplSigningPubKey,
  });
  const evm = sepoliaAnchorTemplate(commitment, { from: REHEARSAL.evmFrom, nonce: '0x0', maxFeePerGas: sepoliaMaxFee(REHEARSAL.evmBaseFeePerGas) });
  return { xrpl, evm };
}

/** rnnet.anchor-observation.v1 text for each network, as the included transactions would read. */
export function rehearsalObservations(commitment) {
  const { xrpl, evm } = rehearsalTransactions(commitment);
  const xrplHash = label('xrpl-tx').toUpperCase();
  const tx = {
    hash: xrplHash,
    ledger_index: REHEARSAL.xrplLedger,
    ledger_hash: label(`xrpl-ledger-${REHEARSAL.xrplLedger}`).toUpperCase(),
    validated: true,
    ctid: ctid(REHEARSAL.xrplLedger, REHEARSAL.xrplTransactionIndex, XRPL.networkId),
    meta: { TransactionIndex: REHEARSAL.xrplTransactionIndex, TransactionResult: 'tesSUCCESS' },
    tx_json: { ...xrpl, hash: xrplHash, ledger_index: REHEARSAL.xrplLedger },
  };
  const evmHash = `0x${label('evm-tx')}`;
  const blockHash = `0x${label(`evm-block-${REHEARSAL.evmBlock}`)}`;
  const blockNumber = quantity(REHEARSAL.evmBlock);
  const transactionIndex = quantity(REHEARSAL.evmTransactionIndex);
  const transaction = { hash: evmHash, ...evm, blockHash, blockNumber, transactionIndex };
  const receipt = {
    transactionHash: evmHash,
    blockHash,
    blockNumber,
    transactionIndex,
    from: evm.from,
    to: evm.to,
    contractAddress: null,
    status: '0x1',
    gasUsed: quantity(intrinsicGas(Buffer.from(evm.input.slice(2), 'hex')).gasUsed),
    logs: [],
  };
  return {
    xrpl: JSON.stringify({ format: 'rnnet.anchor-observation.v1', network: XRPL.network, tx }),
    evm: JSON.stringify({ format: 'rnnet.anchor-observation.v1', network: SEPOLIA.network, transaction, receipt }),
  };
}
