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
import { intrinsicGas, quantity, SEPOLIA, sepoliaAnchorTemplate, sepoliaMaxFee, XRPL, xrplAnchorTemplate } from '../../packages/tx-intent/src/index.mjs';

// The construction and checks live in packages/tx-intent (RN-NET-03B2-B1), so the signer and the
// verifiers apply the same copy; they are re-exported here unchanged.
export {
  checkSepoliaAnchorTx,
  checkXrplAnchorTx,
  intrinsicGas,
  isPlainData,
  memosSerializedLength,
  payloadHex,
  SEPOLIA,
  sepoliaAnchorTemplate,
  sepoliaMaxCostWei,
  sepoliaMaxFee,
  XRPL,
  xrplAnchorMemo,
  xrplAnchorTemplate,
} from '../../packages/tx-intent/src/index.mjs';

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
/**
 * The offset the RN-NET-03B2-A preflight rehearsal was built with. fixtures/genesis-proof-01 is
 * immutable, so its rehearsal keeps this recorded value; preparation binds XRPL.lastLedgerOffset
 * (80 since RN-NET-03B2-C3, ADR-RN-016 Amendment C1). A test pins both.
 */
export const PREFLIGHT_LAST_LEDGER_OFFSET = 20;
const ctid = (ledger, index, network) => `C${((BigInt(ledger) << 32n) | (BigInt(index) << 16n) | BigInt(network)).toString(16).toUpperCase().padStart(15, '0')}`;

/** The completed, unsigned XRPL and Sepolia transactions the rehearsal uses. */
export function rehearsalTransactions(commitment) {
  const xrpl = xrplAnchorTemplate(commitment, {
    Account: REHEARSAL.xrplAccount,
    Sequence: REHEARSAL.xrplSequence,
    LastLedgerSequence: REHEARSAL.xrplLedger - 2 + PREFLIGHT_LAST_LEDGER_OFFSET,
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
