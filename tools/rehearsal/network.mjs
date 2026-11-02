// A simulated clock and simulated XRPL Testnet and Sepolia providers whose state follows it
// (RN-NET-03B2-C3 offline rehearsal). Synthetic data only, injected as the transport: nothing here
// can reach a network. The hosts are `*.fixture.invalid`, which cannot resolve, and the senders are
// the public fixtures/signing-b1 test-key addresses (never identities, never funded).
//
// The clock moves only when told to: each request costs `requestSeconds`, and each human step its
// scripted duration. XRPL closes a ledger every `closeSeconds`; provider b reports one ledger less
// than provider a (a realistic lag). Sepolia makes a block every 12 s. Each answer is built from the
// clock at the moment the request arrives.
import { Buffer } from 'node:buffer';
import { evmBlockTimestamp, NOW, sepoliaServer, xrplServer } from '../../packages/tx-prepare/test/fake-providers.mjs';
import { sepoliaBroadcastServer, sepoliaSendReply, xrplBroadcastServer, xrplIncludedTx, xrplSubmitReply } from '../broadcast/simulated.mjs';

export { NOW };
export const XRPL_START_LEDGER = 5_000_000;
export const SEPOLIA_START_BLOCK = 9_437_185;
export const SEPOLIA_SLOT_SECONDS = 12;
/** Synthetic providers: the preparation, submission and status runs all use these. */
export const PROVIDERS = Object.freeze({
  xrpl: Object.freeze(['fixture-xrpl-a', 'fixture-xrpl-b']),
  sepolia: Object.freeze(['fixture-sepolia-a', 'fixture-sepolia-b']),
});
export const ENDPOINTS = Object.freeze({
  format: 'rnnet.rpc-endpoints.v1',
  note: 'Synthetic providers of the RN-NET-03B2-C3 rehearsal. The hosts cannot resolve.',
  providers: [...PROVIDERS.xrpl, ...PROVIDERS.sepolia].map((id) => ({
    id, network: id.includes('xrpl') ? 'xrpl:testnet' : 'evm:11155111', url: `https://${id}.fixture.invalid/`, operator: `Synthetic operator ${id.slice(-1).toUpperCase()}`,
  })),
});

/** A clock in milliseconds that only moves forward when told to. */
export function createClock(startSeconds = NOW) {
  const start = startSeconds * 1000;
  let ms = start;
  return Object.freeze({
    ms: () => ms,
    elapsed: () => (ms - start) / 1000,
    /** Unix seconds, as every RN-NET tool reads the time. */
    now: () => Math.floor(ms / 1000),
    date: () => new Date(ms),
    advance(seconds) {
      if (!(seconds >= 0)) throw new RangeError('the clock only moves forward');
      ms += Math.round(seconds * 1000);
    },
  });
}

/**
 * The simulated networks for one rehearsal run.
 * @param {{ clock, closeSeconds: number, requestSeconds: number }} options
 */
export function createNetworks({ clock, closeSeconds, requestSeconds }) {
  const startMs = clock.ms();
  /** The validated ledger a provider reports at `atMs` (default: now): provider b is one behind. */
  const xrplLedger = (providerId, atMs = clock.ms()) => XRPL_START_LEDGER + Math.floor((atMs - startMs) / (closeSeconds * 1000)) - (providerId.endsWith('-b') ? 1 : 0);
  // Sepolia: the head at the clock (block 9,437,185 at NOW - 1, as in the B2 fixtures).
  const sepoliaHead = () => SEPOLIA_START_BLOCK + Math.floor((clock.now() - (NOW - 1)) / SEPOLIA_SLOT_SECONDS);
  const state = { xrplSubmitted: null, sepoliaSubmitted: null, writes: [] };

  const preparation = {
    'fixture-xrpl-a': (method, params) => xrplServer({ seq: xrplLedger('fixture-xrpl-a') })(method, params),
    'fixture-xrpl-b': (method, params) => xrplServer({ seq: xrplLedger('fixture-xrpl-b') })(method, params),
    'fixture-sepolia-a': (method, params) => sepoliaServer({ number: sepoliaHead(), timestamp: evmBlockTimestamp(sepoliaHead()) })(method, params),
    'fixture-sepolia-b': (method, params) => sepoliaServer({ number: sepoliaHead(), timestamp: evmBlockTimestamp(sepoliaHead()) })(method, params),
  };

  // Submission and status: the B3 broadcaster providers, at the clock's ledger, with the one write
  // recorded and the transaction included in the next ledger (block) after it.
  const xrplSubmission = (providerId, { sequence, intent, transactionHash }) => (method, params) => {
    const seq = xrplLedger(providerId);
    const included = state.xrplSubmitted !== null && seq >= state.xrplSubmitted.ledger ? xrplIncludedTx(intent, transactionHash, state.xrplSubmitted.ledger) : undefined;
    return xrplBroadcastServer({
      seq,
      sequence: included ? sequence + 1 : sequence,
      included,
      submit: (p) => {
        state.writes.push({ providerId, method, at: clock.elapsed(), ledger: seq });
        state.xrplSubmitted = { ledger: seq + 1 };
        return xrplSubmitReply(p.tx_blob, transactionHash);
      },
    })(method, params);
  };
  const sepoliaSubmission = (providerId, { transactionHash, intent }) => (method, params) => {
    const head = sepoliaHead();
    const sent = state.sepoliaSubmitted;
    const chain = sent !== null && head > sent.block ? { txHash: transactionHash, from: intent.transaction.from, input: intent.transaction.input, block: sent.block, finalized: Math.min(head - 2, sent.block + 64) } : undefined;
    return sepoliaBroadcastServer({
      baseFee: '0x47868c00',
      nonce: chain ? '0x1' : '0x0',
      chain: chain && chain.finalized >= chain.block ? chain : undefined,
      send: () => {
        state.writes.push({ providerId, method, at: clock.elapsed(), block: head });
        state.sepoliaSubmitted = { block: head + 1 };
        return sepoliaSendReply(transactionHash);
      },
    })(method, params);
  };

  /** A transport over `servers` that charges `requestSeconds` per request and records every exchange. */
  const transport = (servers, exchanges = []) => {
    const send = async (request) => {
      clock.advance(requestSeconds);
      const text = Buffer.from(request.body).toString('utf8');
      const { method, params } = JSON.parse(text);
      const server = servers[request.providerId];
      if (!server) throw new Error(`no simulated server ${request.providerId}`);
      const response = server(method, method.startsWith('eth_') ? params : params[0]);
      exchanges.push({ providerId: request.providerId, method, at: clock.elapsed(), request: text, response: { status: response.status, body: Buffer.from(response.body).toString('utf8') } });
      return response;
    };
    send.exchanges = exchanges;
    return send;
  };

  return Object.freeze({
    state,
    xrplLedger,
    sepoliaHead,
    preparationTransport: () => transport(preparation),
    submissionTransport(network, bound) {
      const ids = network === 'xrpl:testnet' ? PROVIDERS.xrpl : PROVIDERS.sepolia;
      return transport(Object.fromEntries(ids.map((id) => [id, network === 'xrpl:testnet' ? xrplSubmission(id, bound) : sepoliaSubmission(id, bound)])));
    },
  });
}
