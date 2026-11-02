// Read-only transaction preparation (RN-NET-03B2-B2, ADR-RN-018, spec/rnnet.tx-preparation.v1.md).
// Reads account and fee state from every given provider through an injected transport, refuses
// stale, inconsistent or malformed data, binds the template's `null` fields (ADR-RN-016) and
// returns an rnnet.unsigned-tx-intent.v1 intent with its digest, for the founder to approve.
//
// No key, no signing, no write method, no network code: the transport is the caller's, and in
// RN-NET-03B2-B2 it is only ever an offline fixture.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { Network, PREPARATION_REQUESTS, readSepoliaAccount, ReadError, readXrplAccount } from '../../chain-readonly/src/index.mjs';
import {
  addressFromPublicKey,
  INTENT_FORMAT,
  intentDigest,
  intrinsicGas,
  makeIntent,
  payloadHex,
  SEPOLIA,
  sepoliaAnchorTemplate,
  sepoliaMaxFee,
  XRPL,
  xrplAnchorTemplate,
} from '../../tx-intent/src/index.mjs';
import { PrepError, PrepErrorCode as C } from './errors.mjs';

export const PREPARATION_FORMAT = 'rnnet.tx-preparation.v1';
const GWEI = 1_000_000_000n;

/** Every bound used below (ADR-RN-018 §3). Changing one is a reviewed change to that ADR. */
export const PREPARATION_RULES = Object.freeze({
  id: 'ADR-RN-018',
  minProviders: 2,
  maxProviders: 4,
  /** One attempt per request: no retry, so the request list is exact. */
  maxAttempts: 1,
  xrpl: Object.freeze({
    /** server_state values of a server that is in sync with the network. */
    syncedStates: Object.freeze(['full', 'proposing', 'validating']),
    /** Oldest acceptable validated ledger, in seconds (server_info validated_ledger.age). */
    maxLedgerAgeSeconds: 30,
    /** Largest gap between providers' validated ledgers. */
    maxValidatedSkew: 4,
    /** account_info's validated ledger may be this many ledgers past server_info's, never before it. */
    maxAccountLedgerLead: 2,
    /** lsfDisableMaster: the master key cannot sign. */
    disableMasterFlag: 0x0010_0000,
  }),
  sepolia: Object.freeze({
    /** Oldest acceptable latest block, in seconds before `now`. */
    maxBlockAgeSeconds: 60,
    /** A latest block this many seconds after `now` or more is refused. */
    maxClockAheadSeconds: 15,
    /** Largest gap between providers' latest blocks. */
    maxBlockSkew: 4,
    /** Largest acceptable base fee: 19 gwei (ADR-RN-016 / design §8). */
    maxBaseFeeWei: 19n * GWEI,
  }),
});

const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const XRPL_SIGNING_KEY = /^ED[0-9A-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

// --- inputs --------------------------------------------------------------------------------------

function checkCommon({ commitment, providers, transport, now }, network) {
  const fail = (why) => {
    throw new PrepError(C.INPUT_INVALID, null, why);
  };
  if (typeof commitment !== 'string' || !COMMITMENT.test(commitment)) fail('commitment must be sha256:<64 lowercase hex>');
  if (!Number.isSafeInteger(now) || now <= 0) fail('now must be a positive integer of Unix seconds');
  if (typeof transport !== 'function') fail('transport must be a function');
  const { minProviders, maxProviders } = PREPARATION_RULES;
  if (!Array.isArray(providers) || providers.length < minProviders || providers.length > maxProviders) fail(`${minProviders} to ${maxProviders} providers are required`);
  const ids = new Set();
  const urls = new Set();
  const operators = new Set();
  for (const p of providers) {
    if (p === null || typeof p !== 'object' || typeof p.id !== 'string' || typeof p.url !== 'string' || typeof p.operator !== 'string') fail('provider must have id, url and operator');
    if (p.network !== network) fail(`provider ${p.id} is not configured for ${network}`);
    if (ids.has(p.id) || urls.has(p.url)) fail(`provider ${p.id} is given twice`);
    // Agreement is only meaningful between different operators (ADR-RN-014).
    if (operators.has(p.operator)) fail(`provider ${p.id} has the same operator as another provider`);
    operators.add(p.operator);
    ids.add(p.id);
    urls.add(p.url);
  }
}

// --- reading -------------------------------------------------------------------------------------

/** A ReadError from one provider as a preparation refusal. */
function refusal(error, providerId) {
  if (!(error instanceof ReadError)) throw error; // a bug, or a capture that does not fit: never a refusal
  switch (error.code) {
    case 'RNLO_WRONG_NETWORK':
    case 'RNLO_NETWORK_UNKNOWN':
      return new PrepError(C.WRONG_NETWORK, providerId);
    case 'RNLO_INVALID_JSON':
    case 'RNLO_INVALID_RESPONSE':
      return new PrepError(C.MALFORMED, providerId, error.detail || undefined);
    case 'RNLO_RPC_ERROR':
      return new PrepError(error.detail === 'actNotFound' ? C.ACCOUNT_NOT_FOUND : C.PROVIDER_ERROR, providerId, error.detail || undefined);
    case 'RNLO_NOT_FOUND': // txnNotFound: an RPC error like any other here
      return new PrepError(C.PROVIDER_ERROR, providerId, 'txnNotFound');
    default:
      return new PrepError(C.PROVIDER_UNAVAILABLE, providerId, error.code);
  }
}

/** Reads one provider with its exact request budget, recording the digest of every exchange. */
async function readProvider(provider, transport, network, read) {
  const exchanges = [];
  const recording = async (request) => {
    const entry = { method: JSON.parse(new TextDecoder().decode(request.body)).method, requestSha256: sha256(request.body) };
    exchanges.push(entry);
    const response = await transport(request);
    if (response !== null && typeof response === 'object' && response.body instanceof Uint8Array) entry.responseSha256 = sha256(response.body);
    return response;
  };
  const budget = { remaining: PREPARATION_REQUESTS[network].length };
  const context = { provider, transport: recording, budget, maxAttempts: PREPARATION_RULES.maxAttempts };
  let observed;
  try {
    observed = await read(context);
  } catch (error) {
    throw refusal(error, provider.id);
  }
  return { observed, exchanges };
}

const intentFrom = (fields) => {
  try {
    const intent = makeIntent({ format: INTENT_FORMAT, purpose: 'genesis-proof-01', ...fields });
    return Object.freeze({ intent, digest: intentDigest(intent) });
  } catch (error) {
    if (error?.name === 'TxError') throw new PrepError(C.INTENT_INVALID, null, error.detail);
    throw error;
  }
};

const minOf = (values) => values.reduce((a, b) => (b < a ? b : a));
const maxOf = (values) => values.reduce((a, b) => (b > a ? b : a));

// --- XRPL Testnet --------------------------------------------------------------------------------

/**
 * Prepares the Genesis AccountSet for `account`, whose public key is `signingPubKey`.
 * @param {{ commitment: string, account: string, signingPubKey: string, now: number,
 *   providers: ReadonlyArray<{ id, network, url, operator }>, transport: (request: object) => Promise<object> }} input
 * @returns {Promise<Readonly<{ intent: object, digest: string }>>}  Throws PrepError.
 */
export async function prepareXrplIntent(input) {
  checkCommon(input, Network.XRPL_TESTNET);
  const { commitment, account, signingPubKey, providers, transport, now } = input;
  if (typeof signingPubKey !== 'string' || !XRPL_SIGNING_KEY.test(signingPubKey)) throw new PrepError(C.INPUT_INVALID, null, 'signingPubKey must be ED + 64 uppercase hex');
  if (typeof account !== 'string' || !XRPL_ACCOUNT.test(account) || addressFromPublicKey(Buffer.from(signingPubKey, 'hex')) !== account) {
    throw new PrepError(C.INPUT_INVALID, null, 'account must be the classic address of signingPubKey');
  }
  const rules = PREPARATION_RULES.xrpl;
  const feeDrops = BigInt(XRPL.feeDrops);

  const readings = [];
  for (const provider of providers) {
    const { observed: o, exchanges } = await readProvider(provider, transport, Network.XRPL_TESTNET, (context) => readXrplAccount(context, account));
    const fail = (code, detail) => {
      throw new PrepError(code, provider.id, detail);
    };
    if (!rules.syncedStates.includes(o.serverState)) fail(C.NOT_SYNCED, 'server_state');
    if (o.validatedLedger.age > rules.maxLedgerAgeSeconds) fail(C.STALE, 'validated ledger too old');
    if (o.accountLedger.validated !== true) fail(C.INCONSISTENT, 'account_info not from a validated ledger');
    const lead = o.accountLedger.index - o.validatedLedger.index;
    if (lead < 0 || lead > rules.maxAccountLedgerLead) fail(C.INCONSISTENT, 'account_info ledger does not follow server_info');
    if (lead === 0 && o.accountLedger.hash !== o.validatedLedger.hash) fail(C.INCONSISTENT, 'same ledger index, different hash');
    if (o.account !== account) fail(C.INCONSISTENT, 'account_info answered for another account');
    if (o.hasRegularKey) fail(C.ACCOUNT_UNSUITABLE, 'RegularKey is set');
    if ((o.flags & rules.disableMasterFlag) !== 0) fail(C.ACCOUNT_UNSUITABLE, 'master key disabled');
    if (o.signerListCount !== 0) fail(C.ACCOUNT_UNSUITABLE, 'signer list present');
    // The load-scaled fee must not exceed the fixed fee: the run stops, it never raises the fee.
    if (o.baseFeeDrops * o.loadFactor.num > feeDrops * o.loadFactor.den) fail(C.FEE_TOO_HIGH, 'load-scaled fee above the fixed fee');
    const needed = o.reserveBaseDrops + BigInt(o.ownerCount) * o.reserveIncDrops + feeDrops;
    if (o.balanceDrops < needed) fail(C.INSUFFICIENT_BALANCE, 'balance below reserve plus fee');
    readings.push({ provider, o, exchanges });
  }

  const validated = readings.map((r) => r.o.validatedLedger.index);
  if (maxOf(validated) - minOf(validated) > rules.maxValidatedSkew) throw new PrepError(C.INCONSISTENT, null, 'providers are too far apart');
  const ledgers = readings.flatMap((r) => [r.o.validatedLedger, r.o.accountLedger]);
  if (ledgers.some((a) => ledgers.some((b) => a.index === b.index && a.hash !== b.hash))) throw new PrepError(C.INCONSISTENT, null, 'one ledger index with two hashes');
  if (new Set(readings.map((r) => r.o.sequence)).size !== 1) throw new PrepError(C.INCONSISTENT, null, 'providers disagree on Sequence');

  // The expiry counts from the lowest validated ledger every provider reported.
  const transaction = xrplAnchorTemplate(commitment, {
    Account: account,
    Sequence: readings[0].o.sequence,
    LastLedgerSequence: minOf(validated) + XRPL.lastLedgerOffset,
    SigningPubKey: signingPubKey,
  });
  const preparation = record(now, readings.map(({ provider, o, exchanges }) => ({
    id: provider.id,
    operator: provider.operator,
    validatedLedger: { index: o.validatedLedger.index, hash: o.validatedLedger.hash },
    accountLedger: { index: o.accountLedger.index, hash: o.accountLedger.hash },
    exchanges,
  })));
  return intentFrom({ network: Network.XRPL_TESTNET, commitment, transaction, preparation });
}

// --- Ethereum Sepolia ---------------------------------------------------------------------------

/**
 * Prepares the Genesis EIP-1559 self-send from `from`.
 * @param {{ commitment: string, from: string, now: number,
 *   providers: ReadonlyArray<{ id, network, url, operator }>, transport: (request: object) => Promise<object> }} input
 * @returns {Promise<Readonly<{ intent: object, digest: string }>>}  Throws PrepError.
 */
export async function prepareSepoliaIntent(input) {
  checkCommon(input, Network.SEPOLIA);
  const { commitment, from, providers, transport, now } = input;
  if (typeof from !== 'string' || !EVM_ADDRESS.test(from)) throw new PrepError(C.INPUT_INVALID, null, 'from must be a lowercase address');
  const rules = PREPARATION_RULES.sepolia;
  const call = { from, input: `0x${payloadHex(commitment)}` };
  const intrinsic = BigInt(intrinsicGas(Buffer.from(payloadHex(commitment), 'hex')).gasUsed);

  const readings = [];
  for (const provider of providers) {
    const { observed: o, exchanges } = await readProvider(provider, transport, Network.SEPOLIA, (context) => readSepoliaAccount(context, call));
    const fail = (code, detail) => {
      throw new PrepError(code, provider.id, detail);
    };
    const timestamp = BigInt(o.block.timestamp);
    if (BigInt(now) - timestamp > BigInt(rules.maxBlockAgeSeconds)) fail(C.STALE, 'latest block too old');
    if (timestamp - BigInt(now) >= BigInt(rules.maxClockAheadSeconds)) fail(C.STALE, 'latest block is in the future');
    if (BigInt(o.block.baseFeePerGas) > rules.maxBaseFeeWei) fail(C.FEE_TOO_HIGH, 'base fee above 19 gwei');
    if (o.noncePending !== o.nonceLatest) fail(C.NONCE_PENDING, 'a transaction from the sender is pending');
    if (o.code !== '0x') fail(C.ACCOUNT_UNSUITABLE, 'the sender has code or an EIP-7702 delegation');
    const estimate = BigInt(o.estimateGas);
    if (estimate > SEPOLIA.gasLimit) fail(C.GAS_TOO_HIGH, 'estimate above the gas limit');
    if (estimate < intrinsic) fail(C.INCONSISTENT, 'estimate below the intrinsic gas');
    readings.push({ provider, o, exchanges });
  }

  const heights = readings.map((r) => BigInt(r.o.block.number));
  if (maxOf(heights) - minOf(heights) > BigInt(rules.maxBlockSkew)) throw new PrepError(C.INCONSISTENT, null, 'providers are too far apart');
  const blocks = readings.map((r) => r.o.block);
  if (blocks.some((a) => blocks.some((b) => a.number === b.number && a.hash !== b.hash))) throw new PrepError(C.INCONSISTENT, null, 'one block number with two hashes');
  if (new Set(readings.map((r) => r.o.nonceLatest)).size !== 1) throw new PrepError(C.INCONSISTENT, null, 'providers disagree on the nonce');
  // The fee is set from the highest base fee any provider reported, then capped (ADR-RN-016).
  const maxFeePerGas = sepoliaMaxFee(`0x${maxOf(readings.map((r) => BigInt(r.o.block.baseFeePerGas))).toString(16)}`);
  const worstCase = SEPOLIA.gasLimit * BigInt(maxFeePerGas);
  for (const { provider, o } of readings) {
    if (BigInt(o.balance) < worstCase) throw new PrepError(C.INSUFFICIENT_BALANCE, provider.id, 'balance below gas limit times maxFeePerGas');
  }

  const transaction = sepoliaAnchorTemplate(commitment, { nonce: readings[0].o.nonceLatest, from, maxFeePerGas });
  const preparation = record(now, readings.map(({ provider, o, exchanges }) => ({
    id: provider.id,
    operator: provider.operator,
    block: { ...o.block },
    estimateGas: o.estimateGas,
    exchanges,
  })));
  return intentFrom({ network: Network.SEPOLIA, commitment, transaction, preparation });
}

/** The intent's `preparation` member (spec §5). Covered by the intent digest. */
function record(now, providers) {
  return { format: PREPARATION_FORMAT, source: 'rpc-read', rules: PREPARATION_RULES.id, observedAt: now, providers };
}
