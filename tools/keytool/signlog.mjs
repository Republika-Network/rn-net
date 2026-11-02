// rnnet.sign-log-entry.v1 (spec/rnnet.sign-log-entry.v1.md; ADR-RN-017 Amendment C1, K4): the
// founder's persistent, append-only sign log. Pure functions only; the files are in
// signlog-store.mjs. Reproduced independently by tools/reference/rnnet_keys_reference.py.
//
// The log holds public data only: key identities, intent digests, sequence numbers, blob and
// transaction hashes, status-record digests and times. Never a secret, seed or passphrase.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { addressFromPublicKey, decodeAddress, IntentNetwork, PURPOSES } from '../../packages/tx-intent/src/index.mjs';
import { evmAddress } from '../../txverify/src/index.mjs';
import { KeyToolCode, KeyToolError } from './errors.mjs';

export const SIGN_LOG_FORMAT = 'rnnet.sign-log-entry.v1';
export const SIGN_LOG_DOMAIN = 'rnnet:sign-log-entry:v1\0';
export const STATUS_RECORD_FORMAT = 'rnnet.submission-status.v1';
export const STATUS_RECORD_DOMAIN = 'rnnet:submission-status:v1\0';
export const EntryType = Object.freeze({ KEY_CREATED: 'KEY_CREATED', RESIGN_BASIS: 'RESIGN_BASIS', SIGNING: 'SIGNING', SIGNED: 'SIGNED' });
export const MAX_ENTRY_BYTES = 4096;

const COMMON = ['address', 'format', 'index', 'network', 'previous', 'purpose', 'recordedAt', 'type'];
export const ENTRY_FIELDS = Object.freeze({
  KEY_CREATED: [...COMMON, 'keyFileSha256', 'publicKey'].sort(),
  SIGNING: [...COMMON, 'intentDigest', 'sequence'].sort(),
  SIGNED: [...COMMON, 'blobSha256', 'intentDigest', 'sequence', 'transactionHash'].sort(),
  RESIGN_BASIS: [...COMMON, 'expiredIntentDigest', 'expiredTransactionHash', 'intentDigest', 'sequence', 'statusRecordDigest'].sort(),
});

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SEQUENCE = /^(?:0|[1-9][0-9]{0,19})$/;
const XRPL_ACCOUNT = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
const XRPL_PUBLIC_KEY = /^ED[0-9A-F]{64}$/;
const XRPL_HASH = /^[0-9A-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const EVM_PUBLIC_KEY = /^04[0-9a-f]{128}$/;
const EVM_HASH = /^0x[0-9a-f]{64}$/;
const SECP256K1_P = 2n ** 256n - 2n ** 32n - 977n;
const SEQUENCE_LIMIT = { [IntentNetwork.XRPL_TESTNET]: 2n ** 32n, [IntentNetwork.SEPOLIA]: 2n ** 64n };

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
/** "sha256:" + SHA-256(domain || canonical JSON) of an entry. */
export const entryDigest = (entry) => sha256(Buffer.concat([Buffer.from(SIGN_LOG_DOMAIN, 'utf8'), Buffer.from(canonicalBytes(entry))]));
/** "sha256:" + SHA-256(domain || canonical JSON) of an rnnet.submission-status.v1 record. */
export const statusRecordDigest = (record) => sha256(Buffer.concat([Buffer.from(STATUS_RECORD_DOMAIN, 'utf8'), Buffer.from(canonicalBytes(record))]));

// A real UTC time: it survives a round trip through Date (so no 30 February, no hour 24).
const realTime = (text) => {
  const ms = Date.parse(text);
  return !Number.isNaN(ms) && `${new Date(ms).toISOString().slice(0, 19)}Z` === text;
};
const invalid = (index, why) => new KeyToolError(KeyToolCode.SIGNLOG_INVALID, `entry ${index}: ${why}`);

function addressMatches(network, address, publicKey) {
  try {
    if (network === IntentNetwork.XRPL_TESTNET) {
      decodeAddress(address);
      return addressFromPublicKey(Buffer.from(publicKey, 'hex')) === address;
    }
    // An uncompressed secp256k1 point must be on the curve: y^2 = x^3 + 7 (mod p).
    const x = BigInt(`0x${publicKey.slice(2, 66)}`);
    const y = BigInt(`0x${publicKey.slice(66)}`);
    if (x >= SECP256K1_P || y >= SECP256K1_P || (y * y - x * x * x - 7n) % SECP256K1_P !== 0n) return false;
    return evmAddress(Buffer.from(publicKey, 'hex')) === address;
  } catch {
    return false;
  }
}

// The shape and value checks of one entry, independent of the others.
function checkEntryShape(entry, index) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw invalid(index, 'not an object');
  const fields = ENTRY_FIELDS[entry.type];
  if (!fields) throw invalid(index, 'unknown type');
  if (Object.keys(entry).sort().join(',') !== fields.join(',')) throw invalid(index, `fields must be exactly ${fields.join(', ')}`);
  if (entry.format !== SIGN_LOG_FORMAT) throw invalid(index, 'wrong format');
  if (entry.index !== index) throw invalid(index, 'index is not its position');
  if (!Object.values(IntentNetwork).includes(entry.network)) throw invalid(index, 'unknown network');
  if (!PURPOSES.includes(entry.purpose)) throw invalid(index, 'unknown purpose');
  if (typeof entry.recordedAt !== 'string' || !TIME.test(entry.recordedAt) || !realTime(entry.recordedAt)) throw invalid(index, 'bad recordedAt');
  const xrpl = entry.network === IntentNetwork.XRPL_TESTNET;
  if (typeof entry.address !== 'string' || !(xrpl ? XRPL_ACCOUNT : EVM_ADDRESS).test(entry.address)) throw invalid(index, 'bad address');
  for (const field of ['intentDigest', 'blobSha256', 'keyFileSha256', 'expiredIntentDigest', 'statusRecordDigest']) {
    if (Object.hasOwn(entry, field) && (typeof entry[field] !== 'string' || !DIGEST.test(entry[field]))) throw invalid(index, `bad ${field}`);
  }
  for (const field of ['transactionHash', 'expiredTransactionHash']) {
    if (Object.hasOwn(entry, field) && (typeof entry[field] !== 'string' || !(xrpl ? XRPL_HASH : EVM_HASH).test(entry[field]))) throw invalid(index, `bad ${field}`);
  }
  if (Object.hasOwn(entry, 'sequence') && (typeof entry.sequence !== 'string' || !SEQUENCE.test(entry.sequence) || BigInt(entry.sequence) >= SEQUENCE_LIMIT[entry.network])) throw invalid(index, 'bad sequence');
  if (entry.type === EntryType.KEY_CREATED) {
    if (typeof entry.publicKey !== 'string' || !(xrpl ? XRPL_PUBLIC_KEY : EVM_PUBLIC_KEY).test(entry.publicKey)) throw invalid(index, 'bad publicKey');
    if (!addressMatches(entry.network, entry.address, entry.publicKey)) throw invalid(index, 'address is not the address of publicKey');
  }
  if (entry.type === EntryType.RESIGN_BASIS && !xrpl) throw invalid(index, 'RESIGN_BASIS is XRPL only');
}

const freshState = (key) => ({ key, sequence: null, pending: null, latest: null, basis: null, signed: new Map(), digests: new Set(), basisFor: new Map() });

/**
 * Replays a whole log and returns its state, or throws RNKEY_SIGNLOG_INVALID naming the first
 * entry that breaks a rule. Rules: contiguous indexes from 0; each `previous` is the digest of the
 * entry before it (null for entry 0); times never decrease; one KEY_CREATED per address and per
 * (network, purpose), before any other entry for that address; then, per address:
 *   SIGNING      no SIGNING pending; the first one fixes the sequence; a later one needs the same
 *                sequence and an unused RESIGN_BASIS naming its digest; a digest is signed once.
 *   SIGNED       completes the pending SIGNING with the same digest and sequence.
 *   RESIGN_BASIS XRPL only; nothing pending and no unused basis; names the latest SIGNED digest
 *                and transaction hash of that sequence; a status-record digest is used once; the
 *                new digest has never been signed with this key.
 */
export function replaySignLog(entries) {
  if (!Array.isArray(entries)) throw invalid(0, 'the log is a list');
  const byAddress = new Map();
  const byKeySlot = new Set();
  const usedStatus = new Set();
  let previous = null;
  let lastTime = '';
  entries.forEach((entry, index) => {
    checkEntryShape(entry, index);
    if (entry.previous !== previous) throw invalid(index, 'previous is not the digest of the entry before');
    if (entry.recordedAt < lastTime) throw invalid(index, 'recordedAt is earlier than the entry before');
    lastTime = entry.recordedAt;
    previous = entryDigest(entry);
    if (entry.type === EntryType.KEY_CREATED) {
      const slot = `${entry.network}|${entry.purpose}`;
      if (byAddress.has(entry.address)) throw invalid(index, 'a second KEY_CREATED for this address');
      if (byKeySlot.has(slot)) throw invalid(index, 'a second key for this network and purpose');
      byKeySlot.add(slot);
      byAddress.set(entry.address, freshState({ network: entry.network, purpose: entry.purpose, address: entry.address, publicKey: entry.publicKey, keyFileSha256: entry.keyFileSha256 }));
      return;
    }
    const state = byAddress.get(entry.address);
    if (!state) throw invalid(index, 'no KEY_CREATED for this address before it');
    if (state.key.network !== entry.network || state.key.purpose !== entry.purpose) throw invalid(index, 'network or purpose differs from the KEY_CREATED entry');
    const sequence = BigInt(entry.sequence);
    if (entry.type === EntryType.SIGNING) {
      if (state.pending !== null) throw invalid(index, 'a SIGNING entry is already pending for this key');
      if (state.digests.has(entry.intentDigest)) throw invalid(index, 'this digest was already signed with this key');
      if (state.sequence !== null) {
        if (sequence !== state.sequence) throw invalid(index, 'a different sequence while an earlier one is unresolved');
        if (state.basis === null || state.basis.intentDigest !== entry.intentDigest) throw invalid(index, 'a second intent for this sequence without a RESIGN_BASIS for it');
        state.basisFor.set(entry.intentDigest, state.basis);
        state.basis = null;
      }
      state.sequence = sequence;
      state.pending = entry.intentDigest;
      state.digests.add(entry.intentDigest);
      return;
    }
    if (entry.type === EntryType.SIGNED) {
      if (state.pending !== entry.intentDigest || state.sequence !== sequence) throw invalid(index, 'SIGNED without the matching pending SIGNING');
      state.signed.set(entry.intentDigest, { blobSha256: entry.blobSha256, transactionHash: entry.transactionHash, index });
      state.latest = { intentDigest: entry.intentDigest, transactionHash: entry.transactionHash };
      state.pending = null;
      return;
    }
    // RESIGN_BASIS
    if (state.pending !== null) throw invalid(index, 'RESIGN_BASIS while a SIGNING entry is pending');
    if (state.basis !== null) throw invalid(index, 'RESIGN_BASIS while another basis is unused');
    if (state.latest === null || state.sequence !== sequence) throw invalid(index, 'RESIGN_BASIS for a sequence that was not signed');
    if (state.latest.intentDigest !== entry.expiredIntentDigest || state.latest.transactionHash !== entry.expiredTransactionHash) throw invalid(index, 'RESIGN_BASIS does not name the latest signed transaction');
    if (usedStatus.has(entry.statusRecordDigest)) throw invalid(index, 'this status record was already used');
    if (state.digests.has(entry.intentDigest)) throw invalid(index, 'RESIGN_BASIS names a digest already signed with this key');
    usedStatus.add(entry.statusRecordDigest);
    state.basis = { intentDigest: entry.intentDigest, statusRecordDigest: entry.statusRecordDigest, expiredTransactionHash: entry.expiredTransactionHash };
  });
  return { byAddress, usedStatus, head: previous, lastTime, length: entries.length };
}

export const SignAction = Object.freeze({ SIGN: 'SIGN', COMPLETE: 'COMPLETE', RESIGN: 'RESIGN' });

/**
 * Decides what a signing request may do, against a log that replays cleanly. `request` is
 * { network, purpose, address, publicKey, keyFileSha256, sequence (decimal string), intentDigest,
 * resign (null, or { statusRecordDigest, expiredTransactionHash }) }. Returns
 * { action, append: [entry types] } or throws:
 *   RNKEY_KEY_NOT_REGISTERED   no KEY_CREATED for exactly this key file;
 *   RNTX_ALREADY_SIGNED        this digest was signed with this key (the blob already written is
 *                              the output);
 *   RNTX_SEQUENCE_UNRESOLVED   another intent is pending, or this key already signed another
 *                              intent (any sequence) without a RESIGN_BASIS for this one;
 *   RNKEY_RESIGN_BASIS_INVALID a basis that names nothing signed, another transaction, a used
 *                              status record, or a Sepolia replacement (not supported).
 */
export function decideSigning(entries, request) {
  const { byAddress, usedStatus } = replaySignLog(entries);
  const state = byAddress.get(request.address);
  const key = state?.key;
  if (!key || key.network !== request.network || key.purpose !== request.purpose || key.publicKey !== request.publicKey || key.keyFileSha256 !== request.keyFileSha256) {
    throw new KeyToolError(KeyToolCode.KEY_NOT_REGISTERED, 'the sign log has no KEY_CREATED entry for exactly this key file');
  }
  const { intentDigest: digest, resign } = request;
  const sequence = BigInt(request.sequence);
  const sameBasis = (basis) => resign === null || (basis !== undefined && basis !== null && basis.statusRecordDigest === resign.statusRecordDigest && basis.expiredTransactionHash === resign.expiredTransactionHash);
  if (state.signed.has(digest)) throw new KeyToolError(KeyToolCode.ALREADY_SIGNED, `entry ${state.signed.get(digest).index}: this intent is already signed with this key`);
  if (state.pending === digest) {
    if (!sameBasis(state.basisFor.get(digest))) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'the pending signature was started with another basis');
    return { action: SignAction.COMPLETE, append: [EntryType.SIGNED] };
  }
  if (state.pending !== null) throw new KeyToolError(KeyToolCode.SEQUENCE_UNRESOLVED, 'another intent is pending for this key');
  if (state.sequence === null) {
    if (resign !== null) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'nothing was signed with this key, so there is nothing to re-sign');
    return { action: SignAction.SIGN, append: [EntryType.SIGNING, EntryType.SIGNED] };
  }
  if (sequence !== state.sequence) throw new KeyToolError(KeyToolCode.SEQUENCE_UNRESOLVED, `sequence ${state.sequence} was signed with this key and is unresolved`);
  if (state.basis !== null) {
    if (state.basis.intentDigest !== digest) throw new KeyToolError(KeyToolCode.SEQUENCE_UNRESOLVED, 'the unused RESIGN_BASIS names another intent');
    if (!sameBasis(state.basis)) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'the recorded RESIGN_BASIS is for another status record');
    return { action: SignAction.SIGN, append: [EntryType.SIGNING, EntryType.SIGNED] };
  }
  if (resign === null) throw new KeyToolError(KeyToolCode.SEQUENCE_UNRESOLVED, `sequence ${state.sequence} is already signed with this key for another intent`);
  if (request.network !== IntentNetwork.XRPL_TESTNET) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'Sepolia same-nonce replacement is not supported');
  if (resign.expiredTransactionHash !== state.latest.transactionHash) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'the status record is not for the latest transaction signed for this sequence');
  if (usedStatus.has(resign.statusRecordDigest)) throw new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, 'this status record was already used');
  return { action: SignAction.RESIGN, append: [EntryType.RESIGN_BASIS, EntryType.SIGNING, EntryType.SIGNED] };
}

/** The next entry of a log: its index and `previous` follow from the entries before it. */
export function nextEntry(entries, type, fields, recordedAt) {
  const index = entries.length;
  const entry = { format: SIGN_LOG_FORMAT, index, previous: index === 0 ? null : entryDigest(entries[index - 1]), recordedAt, type, ...fields };
  replaySignLog([...entries, entry]);
  return entry;
}

/**
 * Checks a status record offered as the basis for an XRPL re-sign: an
 * rnnet.submission-status.v1 for xrpl:testnet whose finding is EXPIRED. Returns
 * { statusRecordDigest, expiredTransactionHash }. The record is a file anyone could write: it is
 * evidence the founder vouches for at gate D, not a proof, and the broadcaster's own status check
 * is what produced it.
 */
export function readResignBasis(record) {
  const bad = (why) => new KeyToolError(KeyToolCode.RESIGN_BASIS_INVALID, why);
  if (record === null || typeof record !== 'object' || Array.isArray(record)) throw bad('not an object');
  if (record.format !== STATUS_RECORD_FORMAT) throw bad(`format must be ${STATUS_RECORD_FORMAT}`);
  if (record.network !== IntentNetwork.XRPL_TESTNET) throw bad('only an xrpl:testnet status record can be a basis');
  if (record.finding !== 'EXPIRED') throw bad('the finding must be EXPIRED');
  if (typeof record.transactionHash !== 'string' || !XRPL_HASH.test(record.transactionHash)) throw bad('bad transactionHash');
  return { statusRecordDigest: statusRecordDigest(record), expiredTransactionHash: record.transactionHash };
}
