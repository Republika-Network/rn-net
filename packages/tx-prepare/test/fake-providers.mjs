// Simulated XRPL Testnet and Sepolia providers for offline preparation tests and the B2 fixtures.
// Synthetic data only, injected as the transport: nothing here can reach a network. The sender
// values are the public test-key addresses of fixtures/signing-b1 (derived from public labels;
// never identities and never funded).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

export const COMMITMENT = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';
export const XRPL_ACCOUNT = 'rPMhDyWFH1uu1kMwheshzpaMouWr75XRa2';
export const XRPL_SIGNING_PUB_KEY = 'ED0C325AFF74C97AEA604FCC239998CA6EC98741D97991842E1F649325C57DEE66';
export const SEPOLIA_FROM = '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86';
/** 2026-11-01T00:00:00Z: the fixed `now` of every fixture. */
export const NOW = 1_793_491_200;

const h = (label) => createHash('sha256').update(`rnnet:synthetic-preparation-${label}`).digest('hex');
export const xrplLedgerHash = (index) => h(`xrpl-ledger-${index}`).toUpperCase();
export const evmBlockHash = (number) => `0x${h(`evm-block-${number}`)}`;

export const provider = (id, network) => ({ id, network, url: `https://${id}.fixture.invalid/`, operator: `Synthetic operator ${id.slice(-1).toUpperCase()}` });
export const xrplProviders = () => [provider('fixture-xrpl-a', 'xrpl:testnet'), provider('fixture-xrpl-b', 'xrpl:testnet')];
export const sepoliaProviders = () => [provider('fixture-sepolia-a', 'evm:11155111'), provider('fixture-sepolia-b', 'evm:11155111')];

/** A JSON number written exactly as given (`1e-05`, `0.2`): not representable as a JS number. */
export const raw = (text) => `@@raw:${text}@@`;
/** JSON text with raw numbers substituted. */
export const jsonText = (value) => JSON.stringify(value).replace(/"@@raw:([^@]+)@@"/g, '$1');
const reply = (body, status = 200) => ({ status, body: new Uint8Array(Buffer.from(body, 'utf8')) });

/** Applies `edit` (a function changing a fresh copy) to a default object. */
const apply = (base, edit) => {
  if (edit) edit(base);
  return base;
};

/**
 * One simulated rippled (API v2) provider. `opts`:
 *   seq (validated ledger index), accountLead (account_info ledger - seq), info / account
 *   (functions editing the server_info `info` and the account_info result), raw[method]
 *   (a function returning a whole reply, or throwing a transport error).
 */
export function xrplServer(opts = {}) {
  const seq = opts.seq ?? 5_000_000;
  return (method, params) => {
    if (opts.raw?.[method]) return opts.raw[method](params);
    if (method === 'server_info') {
      const info = apply({
        build_version: '2.6.1',
        network_id: 1,
        server_state: 'full',
        load_factor: 1,
        complete_ledgers: `4000000-${seq}`,
        validated_ledger: { seq, hash: xrplLedgerHash(seq), age: 2, base_fee_xrp: raw('1e-05'), reserve_base_xrp: 1, reserve_inc_xrp: raw('0.2') },
      }, opts.info);
      return reply(jsonText({ result: { info, status: 'success' } }));
    }
    if (method === 'account_info') {
      const index = seq + (opts.accountLead ?? 0);
      const result = apply({
        account_data: {
          Account: params.account,
          Balance: '25000000',
          Flags: 0,
          LedgerEntryType: 'AccountRoot',
          OwnerCount: 0,
          PreviousTxnID: h('xrpl-prev-tx').toUpperCase(),
          PreviousTxnLgrSeq: 4_999_000,
          Sequence: 4_999_001,
          index: h('xrpl-account-root').toUpperCase(),
        },
        account_flags: { disableMasterKey: false, requireDestinationTag: false },
        signer_lists: [],
        ledger_hash: xrplLedgerHash(index),
        ledger_index: index,
        validated: true,
        status: 'success',
      }, opts.account);
      return reply(jsonText({ result }));
    }
    throw new Error(`unexpected XRPL method ${method}`);
  };
}

/** The synthetic chain's block timestamps: 12 s apart, block 9,437,185 at NOW - 1 - shift. */
export const evmBlockTimestamp = (number, shift = 0) => NOW - 1 - shift - 12 * (9_437_185 - number);

/**
 * One simulated Sepolia provider (EIP-1898 aware, ADR-RN-018 Amendment C1). `opts`:
 *   number (latest block), timestamp (of the latest block only), shift (seconds every block of
 *   the chain is older by), baseFee, block (edits the latest block); pin (edits a block read by
 *   number), pinBaseFee; nonce, pending, balance, code,
 *   estimate; eip1898 false (refuses every block-hash object), estimateGasBlockHash false (refuses
 *   it for eth_estimateGas only); raw[method].
 * A block-hash object must be {blockHash, requireCanonical: true} naming a block at or below the
 * latest; anything else is the JSON-RPC error a node gives for an unknown block.
 */
export function sepoliaServer(opts = {}) {
  const number = opts.number ?? 9_437_184;
  const q = (n) => `0x${BigInt(n).toString(16)}`;
  const ok = (result) => reply(jsonText({ jsonrpc: '2.0', id: 1, result }));
  const rpcError = (code, message) => reply(jsonText({ jsonrpc: '2.0', id: 1, error: { code, message } }));
  const blockAt = (n, edit, timestamp) => apply({
    number: q(n),
    hash: evmBlockHash(n),
    parentHash: evmBlockHash(n - 1),
    timestamp: q(timestamp ?? evmBlockTimestamp(n, opts.shift)),
    baseFeePerGas: (n === number ? opts.baseFee : opts.pinBaseFee ?? opts.baseFee) ?? '0x47868c00',
    gasLimit: '0x2255100',
    gasUsed: '0x1c9c380',
    transactions: [],
  }, edit);
  // undefined: the object is accepted; otherwise the error reply.
  const pinnedError = (method, at) => {
    if (at === null || typeof at !== 'object' || Array.isArray(at)) return rpcError(-32602, 'invalid argument 1: block parameter');
    if (opts.eip1898 === false || (method === 'eth_estimateGas' && opts.estimateGasBlockHash === false)) return rpcError(-32602, 'invalid argument 1: hex string without 0x prefix');
    const keys = Object.keys(at).sort().join(',');
    if (keys !== 'blockHash,requireCanonical' || at.requireCanonical !== true) return rpcError(-32602, 'invalid argument 1: block parameter');
    for (let n = number; n >= number - 64; n--) if (evmBlockHash(n) === at.blockHash) return undefined;
    return rpcError(-32000, `header for hash not found`);
  };
  return (method, params) => {
    // A raw hook returns a whole reply, throws a transport error, or returns undefined to answer normally.
    const answer = opts.raw?.[method]?.(params);
    if (answer !== undefined) return answer;
    switch (method) {
      case 'eth_chainId':
        return ok(opts.chainId ?? '0xaa36a7');
      case 'eth_getBlockByNumber':
        if (params[0] === 'latest') return ok(blockAt(number, opts.block, opts.timestamp));
        return ok(blockAt(Number(BigInt(params[0])), opts.pin));
      case 'eth_getTransactionCount':
        if (params[1] === 'pending') return ok(opts.pending ?? opts.nonce ?? '0x0');
        return pinnedError(method, params[1]) ?? ok(opts.nonce ?? '0x0');
      case 'eth_getBalance':
        return pinnedError(method, params[1]) ?? ok(opts.balance ?? '0x2386f26fc10000');
      case 'eth_getCode':
        return pinnedError(method, params[1]) ?? ok(opts.code ?? '0x');
      case 'eth_estimateGas':
        return pinnedError(method, params[1]) ?? ok(opts.estimate ?? '0x5898');
      default:
        throw new Error(`unexpected Sepolia method ${method}`);
    }
  };
}

/**
 * A transport over simulated servers keyed by provider id. Records every exchange (request
 * text, and the reply or the transport error code) in `exchanges` for the fixtures.
 */
export function fakeTransport(servers, exchanges = []) {
  const transport = async (request) => {
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
  transport.exchanges = exchanges;
  return transport;
}

/** A transport error a simulated server can throw (timeouts, connection failures). */
export const transportError = (code) => () => {
  throw Object.assign(new Error(code), { code });
};
export { reply };
