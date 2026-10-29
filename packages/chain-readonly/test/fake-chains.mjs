// Simulated XRPL and Sepolia servers for offline tests. Synthetic data only; injected as the
// transport, so nothing here can reach a network.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { ANCHOR_MEMO_TYPE, encodeAnchorPayload } from '../../anchor/src/index.mjs';

export const COMMITMENT = `sha256:${'ab'.repeat(32)}`;
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const h = (label) => createHash('sha256').update(`rnnet:synthetic-live-${label}`).digest('hex');
export const PAYLOAD = hex(encodeAnchorPayload(COMMITMENT));

export const provider = (id, network) => ({ id, network, url: `https://${id}.example.org/`, operator: `operator of ${id}` });
const json = (status, value) => ({ status, body: new Uint8Array(Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))) });

/** A transport answering like rippled (API v2). `opts` alters the answers. */
export function fakeXrpl(opts = {}) {
  const hash = h('xrpl-tx').toUpperCase();
  const ledgerHash = h('xrpl-ledger').toUpperCase();
  const tx = {
    hash, ledger_index: 5000, ledger_hash: ledgerHash, validated: true, ctid: 'C000138800020001', close_time_iso: '2026-10-29T00:00:00Z',
    meta: { TransactionIndex: 2, TransactionResult: 'tesSUCCESS', AffectedNodes: [] },
    tx_json: { TransactionType: 'AccountSet', Account: 'rSyntheticAnchorTestAccount1111', Fee: '12', Flags: 0, Sequence: 9, ledger_index: 5000, ctid: 'C000138800020001',
      Memos: [{ Memo: { MemoType: ANCHOR_MEMO_TYPE, MemoData: PAYLOAD.toUpperCase() } }] },
    status: 'success',
    ...opts.tx,
  };
  const calls = [];
  const transport = async (request) => {
    const { method, params } = JSON.parse(Buffer.from(request.body).toString());
    calls.push(method);
    if (opts.fail?.[method]) return opts.fail[method](calls);
    if (method === 'server_info') return json(200, { result: { status: 'success', info: { build_version: '2.4.0', network_id: opts.networkId ?? 1, load_factor: 1.5 } } });
    if (method === 'tx') {
      if (opts.notFound) return json(200, { result: { status: 'error', error: 'txnNotFound' } });
      return json(200, { result: { ...tx, hash: opts.returnedHash ?? tx.hash } });
    }
    if (method === 'ledger') {
      return json(200, { result: { status: 'success', validated: opts.ledgerValidated ?? true, ledger_index: params[0].ledger_index, ledger_hash: opts.ledgerHash ?? ledgerHash, ledger: { ledger_hash: opts.ledgerHash ?? ledgerHash, ledger_index: params[0].ledger_index, closed: true } } });
    }
    throw new Error(`unexpected method ${method}`);
  };
  return { transport, hash, calls };
}

/** A Sepolia chain of blocks 100..140 (and an optional fork), with the anchor tx in block 110. */
export function fakeEvm(opts = {}) {
  const txHash = `0x${h('evm-tx')}`;
  const blocks = new Map();
  const byNumber = new Map();
  let parent = `0x${h('evm-genesis')}`;
  for (let n = 100; n <= 140; n++) {
    const block = { hash: `0x${h(`evm-block-${n}`)}`, number: `0x${n.toString(16)}`, parentHash: parent, transactions: n === 110 ? [`0x${h('other')}`, txHash] : [] };
    blocks.set(block.hash, block);
    byNumber.set(n, block);
    parent = block.hash;
  }
  // A competing chain from block 110 (without the tx) to 135.
  let forkParent = byNumber.get(109).hash;
  const fork = new Map();
  for (let n = 110; n <= 135; n++) {
    const block = { hash: `0x${h(`evm-fork-${n}`)}`, number: `0x${n.toString(16)}`, parentHash: forkParent, transactions: [] };
    blocks.set(block.hash, block);
    fork.set(n, block);
    forkParent = block.hash;
  }
  const included = byNumber.get(110);
  const sender = `0x${h('evm-from').slice(0, 40)}`;
  const transaction = {
    hash: txHash, chainId: '0xaa36a7', type: '0x2', nonce: '0x3', from: sender, to: sender, value: '0x0', input: `0x${PAYLOAD}`,
    blockHash: included.hash, blockNumber: included.number, transactionIndex: '0x1', v: '0x0', r: '0x1', s: '0x2', accessList: [], ...opts.transaction,
  };
  const receipt = opts.receipt === null ? null : {
    transactionHash: txHash, blockHash: included.hash, blockNumber: included.number, transactionIndex: '0x1', from: sender, to: sender,
    status: '0x1', contractAddress: null, logs: [], gasUsed: '0x5208', ...opts.receipt,
  };
  const tags = { finalized: opts.finalized === undefined ? byNumber.get(130) : opts.finalized, safe: opts.safe === undefined ? byNumber.get(135) : opts.safe };
  const calls = [];
  const transport = async (request) => {
    const { method, params } = JSON.parse(Buffer.from(request.body).toString());
    calls.push(method);
    const answer = (result) => json(200, { jsonrpc: '2.0', id: 1, result });
    if (opts.fail?.[method]) return opts.fail[method](calls);
    if (method === 'eth_chainId') return answer(opts.chainId ?? '0xaa36a7');
    if (method === 'eth_getTransactionByHash') return answer(opts.notFound ? null : transaction);
    if (method === 'eth_getTransactionReceipt') return answer(receipt);
    if (method === 'eth_getBlockByHash') return answer(opts.blockOverride?.(params[0]) ?? blocks.get(params[0]) ?? null);
    if (method === 'eth_getBlockByNumber') {
      if (opts.unsupportedTags) return json(200, { jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'unknown block tag' } });
      return answer(tags[params[0]] ?? null);
    }
    throw new Error(`unexpected method ${method}`);
  };
  return { transport, hash: txHash, calls, byNumber, fork };
}
