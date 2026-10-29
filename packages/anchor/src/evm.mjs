// Ethereum Sepolia anchor adapter (spec/rnnet.anchor-record.v1.md §4). Offline: it checks a
// supplied transaction and receipt (JSON-RPC results) and never contacts a node. Supplied data is
// unauthenticated; the record says so.
import { bytesOfHex, checkCommitment, fail, finish, hexOf, kind, Network, newRecord, parseObservation, phase, snapshotBytes } from './common.mjs';
import { decodeAnchorPayload } from './payload.mjs';

export const SEPOLIA_CHAIN_ID = '0xaa36a7'; // 11155111
const HASH = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const DATA = /^0x(?:[0-9a-f]{2})*$/;
const TYPES = ['0x0', '0x1', '0x2'];
const BLOCK_FIELDS = ['blockHash', 'blockNumber', 'transactionIndex'];

function requireFields(object, fields, path) {
  for (const [field, types] of Object.entries(fields)) {
    if (!Object.hasOwn(object, field)) fail('RNAE_MISSING_FIELD', `${path}.${field}`);
    if (!types.includes(kind(object[field]))) fail('RNAE_FIELD_TYPE', `${path}.${field}`);
  }
}

/** Phase A (§4.2): structure, network and consistency; throws on the first failure. */
function checkStructure(transaction, receipt) {
  if (kind(transaction) !== 'object') fail('RNAE_FIELD_TYPE', 'transaction');
  if (!['object', 'null'].includes(kind(receipt))) fail('RNAE_FIELD_TYPE', 'receipt');
  const nullable = ['string', 'null'];
  requireFields(transaction, {
    hash: ['string'], chainId: ['string'], type: ['string'], from: ['string'], input: ['string'],
    to: nullable, blockHash: nullable, blockNumber: nullable, transactionIndex: nullable,
  }, 'transaction');
  if (!HASH.test(transaction.hash)) fail('RNAE_INVALID_HASH', 'transaction.hash');
  if (!QUANTITY.test(transaction.chainId)) fail('RNAE_FIELD_TYPE', 'transaction.chainId');
  if (transaction.chainId !== SEPOLIA_CHAIN_ID) fail('RNAE_WRONG_NETWORK', 'transaction.chainId');
  if (!TYPES.includes(transaction.type)) fail('RNAE_UNSUPPORTED_TRANSACTION_TYPE', 'transaction.type');
  if (transaction.to === null) fail('RNAE_CONTRACT_CREATION', 'transaction.to');
  for (const field of ['from', 'to']) if (!ADDRESS.test(transaction[field])) fail('RNAE_INVALID_ADDRESS', `transaction.${field}`);
  if (!DATA.test(transaction.input)) fail('RNAE_INVALID_INPUT', 'transaction.input');
  const included = BLOCK_FIELDS.filter((field) => transaction[field] !== null).length;
  if (included !== 0 && included !== BLOCK_FIELDS.length) fail('RNAE_INVALID_BLOCK_REFERENCE', 'transaction');
  if (included !== 0) {
    if (!HASH.test(transaction.blockHash)) fail('RNAE_INVALID_BLOCK_REFERENCE', 'transaction.blockHash');
    for (const field of ['blockNumber', 'transactionIndex']) {
      if (!QUANTITY.test(transaction[field])) fail('RNAE_INVALID_BLOCK_REFERENCE', `transaction.${field}`);
    }
  }
  if (receipt === null) return;
  requireFields(receipt, {
    transactionHash: ['string'], blockHash: ['string'], blockNumber: ['string'], transactionIndex: ['string'],
    from: ['string'], status: ['string'], to: nullable, contractAddress: nullable,
  }, 'receipt');
  for (const [field, own] of [['transactionHash', 'hash'], ['from', 'from'], ['to', 'to']]) {
    if (receipt[field] !== transaction[own]) fail('RNAE_RECEIPT_MISMATCH', `receipt.${field}`);
  }
  for (const field of BLOCK_FIELDS) {
    if (transaction[field] === null || receipt[field] !== transaction[field]) fail('RNAE_CONFLICTING_BLOCK_REFERENCE', `receipt.${field}`);
  }
}

/** Phase B: the whole input is the expected payload. */
function checkAnchor(transaction, expected, record) {
  if (transaction.input === '0x') fail('RNAE_MISSING_ANCHOR', 'transaction.input');
  const bytes = bytesOfHex(transaction.input.slice(2));
  const commitment = decodeAnchorPayload(bytes, 'transaction.input');
  record.payload = { hex: hexOf(bytes), commitment, matchesExpected: commitment === expected };
  if (commitment !== expected) fail('RNAP_COMMITMENT_MISMATCH', 'transaction.input');
}

/** Phase C: included, not a contract creation, and claimed successful. */
function checkStatus(transaction, receipt) {
  if (receipt === null || transaction.blockHash === null) fail('RNAE_PENDING', receipt === null ? 'receipt' : 'transaction.blockHash');
  if (receipt.contractAddress !== null) fail('RNAE_CONTRACT_CREATION', 'receipt.contractAddress');
  if (receipt.status === '0x0') fail('RNAE_TRANSACTION_REVERTED', 'receipt.status');
  if (receipt.status !== '0x1') fail('RNAE_INVALID_STATUS', 'receipt.status');
}

export const EVM_BASIS = Object.freeze({
  finality: 'The supplied data shows inclusion in a block, not finality.',
});

/**
 * Checks a supplied Ethereum Sepolia observation against an expected commitment.
 * @param {Uint8Array} observationBytes rnnet.anchor-observation.v1 JSON bytes
 * @param {string} expectedCommitment sha256:<64 lowercase hex>
 * @returns {Readonly<object>} an rnnet.anchor-record.v1 record
 */
export function verifyEvmObservation(observationBytes, expectedCommitment) {
  const expected = checkCommitment(expectedCommitment);
  const bytes = snapshotBytes(observationBytes, 'observationBytes');
  const record = newRecord(Network.SEPOLIA, expected, bytes);
  let transaction;
  let receipt;
  const structured = phase(record.findings, () => {
    ({ transaction, receipt } = parseObservation(bytes, Network.SEPOLIA));
    checkStructure(transaction, receipt);
  });
  if (structured) {
    record.transaction = {
      hash: transaction.hash,
      blockHash: transaction.blockHash,
      blockNumber: transaction.blockNumber,
      transactionIndex: transaction.transactionIndex,
      from: transaction.from,
      to: transaction.to,
    };
    phase(record.findings, () => checkAnchor(transaction, expected, record));
    phase(record.findings, () => checkStatus(transaction, receipt));
  }
  return finish(record, EVM_BASIS.finality, 'UNRESOLVED');
}
