// Simulated XRPL Testnet and Sepolia providers for the RN-NET-03B2-B3 broadcaster fixtures and
// tests. Synthetic data only, injected as the transport: nothing here can reach a network. The
// hosts are `*.fixture.invalid`, which cannot resolve. The senders are the public test-key
// addresses of fixtures/signing-b1 (derived from public labels; never identities, never funded).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

// Self-contained: these providers share no code with the B2 preparation package, whose test
// helpers only the B2 fixture builder may reach.
/** A JSON number written exactly as given (`1e-05`, `0.2`). */
const raw = (text) => `@@raw:${text}@@`;
const jsonText = (value) => JSON.stringify(value).replace(/"@@raw:([^@]+)@@"/g, '$1');
const reply = (body, status = 200) => ({ status, body: new Uint8Array(Buffer.from(body, 'utf8')) });

/** server_info and account_info (validated) of a rippled API v2 server. */
function xrplServer(opts) {
  const seq = opts.seq;
  return (method, params) => {
    if (method === 'server_info') {
      const info = {
        build_version: '2.6.1', network_id: 1, server_state: 'full', load_factor: 1, complete_ledgers: `990000-${seq}`,
        validated_ledger: { seq, hash: xrplLedgerHash(seq), age: 2, base_fee_xrp: raw('1e-05'), reserve_base_xrp: 1, reserve_inc_xrp: raw('0.2') },
      };
      if (opts.info) opts.info(info);
      return reply(jsonText({ result: { info, status: 'success' } }));
    }
    const result = {
      account_data: { Account: params.account, Balance: '25000000', Flags: 0, LedgerEntryType: 'AccountRoot', OwnerCount: 0, Sequence: 1, index: h('xrpl-account-root').toUpperCase() },
      signer_lists: [], ledger_hash: xrplLedgerHash(seq), ledger_index: seq, validated: true, status: 'success',
    };
    if (opts.account) opts.account(result);
    return reply(jsonText({ result }));
  };
}

/** The read methods of a Sepolia provider used before a submission. */
function sepoliaServer(opts) {
  const number = opts.number;
  const q = (n) => `0x${BigInt(n).toString(16)}`;
  return (method, params) => {
    switch (method) {
      case 'eth_chainId':
        return ok(opts.chainId ?? '0xaa36a7');
      case 'eth_getBlockByNumber':
        return ok({ number: q(number), hash: evmBlockHash(number), parentHash: evmBlockHash(number - 1), timestamp: q(NOW - 6), baseFeePerGas: opts.baseFee, gasLimit: '0x2255100', gasUsed: '0x1c9c380', transactions: [] });
      case 'eth_getTransactionCount':
        return ok(params[1] === 'pending' ? (opts.pending ?? opts.nonce ?? '0x0') : (opts.nonce ?? '0x0'));
      case 'eth_getBalance':
        return ok(opts.balance ?? '0x2386f26fc10000');
      default:
        throw new Error(`unexpected Sepolia method ${method}`);
    }
  };
}

export const NOW = 1_793_491_200; // 2026-11-01T00:00:00Z
export const ENDPOINTS = Object.freeze({
  format: 'rnnet.rpc-endpoints.v1',
  note: 'Synthetic providers of the RN-NET-03B2-B3 fixtures. The hosts cannot resolve.',
  providers: [
    { id: 'fixture-xrpl-a', network: 'xrpl:testnet', url: 'https://fixture-xrpl-a.fixture.invalid/', operator: 'Synthetic operator A' },
    { id: 'fixture-xrpl-b', network: 'xrpl:testnet', url: 'https://fixture-xrpl-b.fixture.invalid/', operator: 'Synthetic operator B' },
    { id: 'fixture-sepolia-a', network: 'evm:11155111', url: 'https://fixture-sepolia-a.fixture.invalid/', operator: 'Synthetic operator A' },
    { id: 'fixture-sepolia-b', network: 'evm:11155111', url: 'https://fixture-sepolia-b.fixture.invalid/', operator: 'Synthetic operator B' },
  ],
});
const h = (label) => createHash('sha256').update(`rnnet:synthetic-broadcast-${label}`).digest('hex');
export const xrplLedgerHash = (index) => h(`xrpl-ledger-${index}`).toUpperCase();
export const evmBlockHash = (n) => `0x${h(`evm-block-${n}`)}`;
const ok = (result) => reply(jsonText({ jsonrpc: '2.0', id: 1, result }));
export const transportError = (code) => () => {
  throw Object.assign(new Error(code), { code });
};

/** A rippled `submit` answer for the sent blob. `edit` changes a fresh copy of the result. */
export function xrplSubmitReply(blob, hash, edit) {
  const result = {
    accepted: true, applied: true, broadcast: true, kept: true, queued: false,
    engine_result: 'tesSUCCESS', engine_result_code: 0, engine_result_message: 'The transaction was applied. Only final in a validated ledger.',
    status: 'success', tx_blob: blob, tx_json: { hash },
  };
  if (edit) edit(result);
  return reply(jsonText({ result }));
}

/** A rejected or uncertain engine result with the given flags (all false unless set). */
export const xrplEngine = (engine, code, flags = {}) => (r) => {
  Object.assign(r, { engine_result: engine, engine_result_code: code, accepted: false, applied: false, broadcast: false, kept: false, queued: false }, flags);
};

const NOT_FOUND = (searchedAll) => reply(jsonText({ result: { error: 'txnNotFound', error_code: 29, error_message: 'Transaction not found.', ...(searchedAll === undefined ? {} : { searched_all: searchedAll }), status: 'error' } }));

/**
 * One simulated rippled provider for the broadcaster: server_info and account_info as in the B2
 * fixtures (validated ledger `seq`, account Sequence `sequence`), `tx` answering txnNotFound, and
 * `submit` answering `submit(params)`. `opts.raw[method]` replaces any answer.
 */
export function xrplBroadcastServer(opts = {}) {
  const seq = opts.seq ?? 1_000_010;
  const base = xrplServer({
    seq,
    info: opts.info,
    account: (r) => {
      r.account_data.Sequence = opts.sequence ?? 1_000_001;
      if (opts.account) opts.account(r);
    },
  });
  return (method, params) => {
    if (opts.raw?.[method]) return opts.raw[method](params);
    if (method === 'server_info') return base(method, params);
    if (method === 'account_info') {
      if (typeof params.ledger_index === 'number') {
        const index = params.ledger_index;
        return reply(jsonText({ result: { account_data: { Account: params.account, Balance: '24999988', Flags: 0, OwnerCount: 0, Sequence: opts.sequenceAt ?? 1_000_001 }, ledger_hash: xrplLedgerHash(index), ledger_index: index, validated: true, status: 'success' } }));
      }
      return base(method, params);
    }
    if (method === 'tx') {
      if (Object.hasOwn(params, 'min_ledger')) return NOT_FOUND(opts.searchedAll ?? true);
      if (opts.included) return reply(jsonText({ result: opts.included }));
      return NOT_FOUND();
    }
    if (method === 'ledger') {
      const index = params.ledger_index;
      return reply(jsonText({ result: { ledger: { ledger_hash: xrplLedgerHash(index), ledger_index: index, closed: true }, ledger_hash: xrplLedgerHash(index), ledger_index: index, validated: true, status: 'success' } }));
    }
    if (method === 'submit') return opts.submit(params);
    throw new Error(`unexpected XRPL method ${method}`);
  };
}

/** The `tx` result of an included AccountSet anchor (API v2), as rippled would report it. */
export function xrplIncludedTx(intent, hash, ledgerIndex) {
  const t = intent.transaction;
  return {
    hash, ledger_index: ledgerIndex, ledger_hash: xrplLedgerHash(ledgerIndex), validated: true, close_time_iso: '2026-11-01T00:00:30Z',
    meta: { TransactionIndex: 0, TransactionResult: 'tesSUCCESS', AffectedNodes: [] },
    tx_json: { Account: t.Account, Fee: t.Fee, Flags: 0, LastLedgerSequence: t.LastLedgerSequence, Memos: t.Memos, Sequence: t.Sequence, SigningPubKey: t.SigningPubKey, TransactionType: 'AccountSet', ledger_index: ledgerIndex },
    status: 'success',
  };
}

/**
 * One simulated Sepolia provider for the broadcaster. `opts`: chainId, baseFee, nonce, pending,
 * balance, known (an eth_getTransactionByHash answer), send(params) for eth_sendRawTransaction,
 * chain ({ txHash, from, input, block, finalized }) for an included transaction, raw[method].
 */
export function sepoliaBroadcastServer(opts = {}) {
  const base = sepoliaServer({ number: 9_437_184, baseFee: opts.baseFee ?? '0x7', nonce: opts.nonce, pending: opts.pending, balance: opts.balance, chainId: opts.chainId });
  return (method, params) => {
    const answer = opts.raw?.[method]?.(params);
    if (answer !== undefined) return answer;
    if (method === 'eth_sendRawTransaction') return opts.send(params);
    const chain = opts.chain;
    if (method === 'eth_getTransactionByHash') {
      if (!chain) return ok(opts.known ?? null);
      return ok({ hash: chain.txHash, type: '0x2', chainId: '0xaa36a7', nonce: '0x0', from: chain.from, to: chain.from, value: '0x0', input: chain.input, blockHash: evmBlockHash(chain.block), blockNumber: `0x${chain.block.toString(16)}`, transactionIndex: '0x0', accessList: [], v: '0x0', r: '0x1', s: '0x2' });
    }
    if (method === 'eth_getTransactionReceipt' && chain) {
      return ok({ transactionHash: chain.txHash, blockHash: evmBlockHash(chain.block), blockNumber: `0x${chain.block.toString(16)}`, transactionIndex: '0x0', from: chain.from, to: chain.from, status: '0x1', contractAddress: null, logs: [], gasUsed: '0x5898' });
    }
    if (method === 'eth_getTransactionReceipt') return ok(null);
    const blockOf = (n) => ({ hash: evmBlockHash(n), number: `0x${n.toString(16)}`, parentHash: evmBlockHash(n - 1), transactions: chain && n === chain.block ? [chain.txHash] : [] });
    if (method === 'eth_getBlockByHash' && chain) {
      for (let n = chain.block; n <= chain.finalized + 2; n++) if (evmBlockHash(n) === params[0]) return ok(blockOf(n));
      return ok(null);
    }
    if (method === 'eth_getBlockByNumber' && chain && (params[0] === 'finalized' || params[0] === 'safe')) {
      return ok(blockOf(params[0] === 'finalized' ? chain.finalized : chain.finalized + 1));
    }
    return base(method, params);
  };
}

/** An eth_sendRawTransaction answer: the hash, or a JSON-RPC error. */
export const sepoliaSendReply = (result) => ok(result);
export const sepoliaErrorReply = (code, message) => reply(jsonText({ jsonrpc: '2.0', id: 1, error: { code, message } }));

/**
 * A transport over simulated servers keyed by provider id, recording each exchange as text:
 * { providerId, request, response: { status, body } } or { providerId, request, error }.
 */
export function simulatedTransport(servers, exchanges) {
  return async (request) => {
    const text = Buffer.from(request.body).toString('utf8');
    const { method, params } = JSON.parse(text);
    const server = servers[request.providerId];
    if (!server) throw new Error(`no simulated server ${request.providerId}`);
    const entry = { providerId: request.providerId, request: text };
    exchanges.push(entry);
    let response;
    try {
      response = server(method, method.startsWith('eth_') ? params : params[0]);
    } catch (error) {
      if (typeof error?.code === 'string') entry.error = error.code;
      throw error;
    }
    entry.response = { status: response.status, body: Buffer.from(response.body).toString('utf8') };
    return response;
  };
}

/** A transport that answers only from recorded text exchanges, in order; it never connects. */
export function replayTextTransport(exchanges) {
  const queue = [...exchanges];
  const transport = async (request) => {
    const next = queue.shift();
    const text = Buffer.from(request.body).toString('utf8');
    if (!next || next.providerId !== request.providerId || next.request !== text) throw Object.assign(new Error(`replay mismatch at ${text.slice(0, 80)}`), { name: 'ReplayMismatch' });
    if (next.error) throw Object.assign(new Error(next.error), { code: next.error });
    return { status: next.response.status, body: new Uint8Array(Buffer.from(next.response.body, 'utf8')) };
  };
  transport.remaining = () => queue.length;
  return transport;
}
