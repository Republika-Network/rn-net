// XRPL Testnet and Ethereum Sepolia readers (spec/rnnet.live-observation-report.v1.md §5, §6).
// Each reads one transaction from one provider, cross-checks what the provider says, and
// normalizes the result into an RN-NET-03A observation without adding or inventing any field.
import { canonicalBytes } from '../../canonical/src/index.mjs';
import { call, Network, ReadError } from './rpc.mjs';

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const OBSERVATION_FORMAT = 'rnnet.anchor-observation.v1';
const XRPL_TESTNET_NETWORK_ID = 1;
const SEPOLIA_CHAIN_ID = '0xaa36a7';
export const XRPL_HASH = /^[0-9A-F]{64}$/;
export const EVM_HASH = /^0x[0-9a-f]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;

/** Observation bytes; a value with no canonical form (a fraction, say) is an invalid response. */
function observationBytes(observation) {
  try {
    return canonicalBytes(observation);
  } catch {
    throw new ReadError('RNLO_INVALID_RESPONSE', 'not representable as an observation');
  }
}

/** Copies a provider object without the envelope members that are not part of the record. */
function withoutEnvelope(result, members) {
  const copy = Object.create(null);
  for (const [key, value] of Object.entries(result)) if (!members.includes(key)) copy[key] = value;
  return copy;
}

// --- XRPL Testnet --------------------------------------------------------------------------------

/**
 * Reads an XRPL Testnet transaction. Returns { observation, material, validated }.
 * Network identity comes from the server (server_info network_id), never from its URL or name.
 */
export async function readXrpl(context, hash) {
  if (!XRPL_HASH.test(hash)) throw new TypeError('XRPL transaction hash must be 64 uppercase hex digits.');
  const info = await call(context, 'server_info', { api_version: 2 });
  const networkId = info?.info?.network_id;
  if (networkId === undefined) throw new ReadError('RNLO_NETWORK_UNKNOWN');
  if (networkId !== XRPL_TESTNET_NETWORK_ID) throw new ReadError('RNLO_WRONG_NETWORK');

  const tx = await call(context, 'tx', { transaction: hash, binary: false, api_version: 2 });
  if (kind(tx.tx_json) !== 'object') throw new ReadError('RNLO_UNSUPPORTED_API_VERSION');
  if (tx.hash !== hash) throw new ReadError('RNLO_HASH_MISMATCH');
  if (kind(tx.meta) !== 'object') throw new ReadError('RNLO_INVALID_RESPONSE', 'meta');

  // A validated transaction's ledger is read separately and must agree on index and hash.
  let ledgerConfirmed = false;
  if (tx.validated === true) {
    if (!Number.isInteger(tx.ledger_index)) throw new ReadError('RNLO_INVALID_RESPONSE', 'ledger_index');
    const ledger = await call(context, 'ledger', { ledger_index: tx.ledger_index, transactions: false, expand: false, api_version: 2 });
    const header = kind(ledger.ledger) === 'object' ? ledger.ledger : null;
    if (ledger.validated !== true) throw new ReadError('RNLO_LEDGER_MISMATCH', 'ledger not validated');
    if (ledger.ledger_index !== tx.ledger_index || ledger.ledger_hash !== tx.ledger_hash) throw new ReadError('RNLO_LEDGER_MISMATCH');
    if (header && ((Object.hasOwn(header, 'ledger_hash') && header.ledger_hash !== tx.ledger_hash) || (Object.hasOwn(header, 'ledger_index') && header.ledger_index !== tx.ledger_index))) {
      throw new ReadError('RNLO_LEDGER_MISMATCH');
    }
    ledgerConfirmed = true;
  }

  const record = withoutEnvelope(tx, ['status', 'warnings']);
  const observation = { format: OBSERVATION_FORMAT, network: Network.XRPL_TESTNET, tx: record };
  const material = {
    hash: tx.hash,
    ledger_index: tx.ledger_index ?? null,
    ledger_hash: tx.ledger_hash ?? null,
    validated: tx.validated === true,
    result: typeof tx.meta.TransactionResult === 'string' ? tx.meta.TransactionResult : null,
    tx_json: tx.tx_json,
  };
  return { observation: observationBytes(observation), material: observationBytes(material), validated: ledgerConfirmed };
}

// --- Ethereum Sepolia ---------------------------------------------------------------------------

export const ANCESTRY_LIMIT = 256;

/**
 * Reads a Sepolia transaction. Returns { observation, material, finality }.
 * Network identity comes from eth_chainId. Finality is assessed only by walking parent hashes from
 * the provider's finalized (then safe) block down to the transaction's block, at most ANCESTRY_LIMIT steps.
 */
export async function readEvm(context, hash) {
  if (!EVM_HASH.test(hash)) throw new TypeError('Ethereum transaction hash must be 0x and 64 lowercase hex digits.');
  const chainId = await call(context, 'eth_chainId', []);
  if (typeof chainId !== 'string' || !QUANTITY.test(chainId)) throw new ReadError('RNLO_INVALID_RESPONSE', 'chainId');
  if (chainId !== SEPOLIA_CHAIN_ID) throw new ReadError('RNLO_WRONG_NETWORK');

  const transaction = await call(context, 'eth_getTransactionByHash', [hash]);
  if (transaction === null) throw new ReadError('RNLO_NOT_FOUND');
  if (kind(transaction) !== 'object') throw new ReadError('RNLO_INVALID_RESPONSE', 'transaction');
  if (transaction.hash !== hash) throw new ReadError('RNLO_HASH_MISMATCH');
  const receipt = await call(context, 'eth_getTransactionReceipt', [hash]);
  if (receipt !== null && kind(receipt) !== 'object') throw new ReadError('RNLO_INVALID_RESPONSE', 'receipt');

  let finality = { finalized: 'UNRESOLVED', safe: 'UNRESOLVED' };
  if (transaction.blockHash !== null && transaction.blockHash !== undefined) {
    const block = await call(context, 'eth_getBlockByHash', [transaction.blockHash, false]);
    if (kind(block) !== 'object' || block.hash !== transaction.blockHash || block.number !== transaction.blockNumber) throw new ReadError('RNLO_BLOCK_MISMATCH');
    const index = typeof transaction.transactionIndex === 'string' && QUANTITY.test(transaction.transactionIndex) ? Number.parseInt(transaction.transactionIndex, 16) : -1;
    if (!Array.isArray(block.transactions) || block.transactions[index] !== hash) throw new ReadError('RNLO_BLOCK_MISMATCH', 'membership');
    finality = await assessFinality(context, block);
  }

  const observation = {
    format: OBSERVATION_FORMAT,
    network: Network.SEPOLIA,
    transaction: withoutEnvelope(transaction, []),
    receipt: receipt === null ? null : withoutEnvelope(receipt, []),
  };
  const material = {
    hash: transaction.hash,
    blockHash: transaction.blockHash ?? null,
    blockNumber: transaction.blockNumber ?? null,
    transactionIndex: transaction.transactionIndex ?? null,
    input: transaction.input ?? null,
    from: transaction.from ?? null,
    to: transaction.to ?? null,
    status: receipt === null ? null : (receipt.status ?? null),
    finality,
  };
  return { observation: observationBytes(observation), material: observationBytes(material), finality };
}

/** For each tag: IN_ANCESTRY, NOT_REACHED, CONFLICT or UNRESOLVED (spec §6.2). */
async function assessFinality(context, block) {
  const height = Number.parseInt(block.number, 16);
  const result = {};
  for (const tag of ['finalized', 'safe']) {
    // A transaction in the finalized ancestry is also in the safe one; no second walk is needed.
    if (tag === 'safe' && result.finalized === 'IN_ANCESTRY') {
      result.safe = 'IN_ANCESTRY';
      continue;
    }
    result[tag] = await walk(context, tag, block.hash, height);
  }
  return result;
}

async function walk(context, tag, targetHash, targetHeight) {
  let head;
  try {
    head = await call(context, 'eth_getBlockByNumber', [tag, false]);
  } catch (error) {
    if (error instanceof ReadError && error.code === 'RNLO_RPC_ERROR') return 'UNRESOLVED'; // tag not supported
    throw error;
  }
  if (kind(head) !== 'object' || typeof head.number !== 'string' || !QUANTITY.test(head.number)) return 'UNRESOLVED';
  let current = head;
  let height = Number.parseInt(head.number, 16);
  if (height < targetHeight) return 'NOT_REACHED';
  for (let steps = 0; height > targetHeight; steps++) {
    if (steps >= ANCESTRY_LIMIT) return 'UNRESOLVED';
    if (typeof current.parentHash !== 'string' || !EVM_HASH.test(current.parentHash)) throw new ReadError('RNLO_BLOCK_MISMATCH', 'parentHash');
    const parent = await call(context, 'eth_getBlockByHash', [current.parentHash, false]);
    if (kind(parent) !== 'object' || parent.hash !== current.parentHash || parent.number !== `0x${(height - 1).toString(16)}`) {
      throw new ReadError('RNLO_BLOCK_MISMATCH', 'ancestry');
    }
    current = parent;
    height -= 1;
  }
  return current.hash === targetHash ? 'IN_ANCESTRY' : 'CONFLICT';
}
