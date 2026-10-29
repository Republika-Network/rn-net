// rnnet.anchor-payload.v1 (spec/rnnet.anchor-payload.v1.md): the 42 bytes anchored on every
// network. Magic "RNNETANC", version 01, commitment format 01, then the 32 digest bytes.
import { Buffer } from 'node:buffer';
import { checkCommitment, fail } from './common.mjs';

export const PAYLOAD_FORMAT = 'rnnet.anchor-payload.v1';
export const MAGIC = Uint8Array.from(Buffer.from('RNNETANC', 'ascii'));
export const PAYLOAD_VERSION = 0x01;
/** Commitment format codes: 01 = rnnet.evidence-commitment.v1. */
export const COMMITMENT_FORMAT_V1 = 0x01;
export const PAYLOAD_LENGTH = 42;

/** The payload bytes for a commitment `sha256:<64 lowercase hex>` (§5). */
export function encodeAnchorPayload(commitment) {
  checkCommitment(commitment);
  return Uint8Array.from([...MAGIC, PAYLOAD_VERSION, COMMITMENT_FORMAT_V1, ...Buffer.from(commitment.slice(7), 'hex')]);
}

/**
 * Decodes payload bytes in the order of §3. Returns the commitment; throws an AnchorError
 * (RNAP_*) with the given subject on the first failure.
 * @param {Uint8Array} bytes
 */
export function decodeAnchorPayload(bytes, subject = 'payload') {
  if (bytes.length < MAGIC.length || !MAGIC.every((b, i) => bytes[i] === b)) fail('RNAP_NOT_ANCHOR_PAYLOAD', subject);
  if (bytes.length < MAGIC.length + 1) fail('RNAP_INVALID_LENGTH', subject);
  if (bytes[8] !== PAYLOAD_VERSION) fail('RNAP_UNSUPPORTED_VERSION', subject);
  if (bytes.length !== PAYLOAD_LENGTH) fail('RNAP_INVALID_LENGTH', subject);
  if (bytes[9] !== COMMITMENT_FORMAT_V1) fail('RNAP_UNSUPPORTED_COMMITMENT_FORMAT', subject);
  return `sha256:${Buffer.from(bytes.subarray(10)).toString('hex')}`;
}
