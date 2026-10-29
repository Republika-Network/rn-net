// Public API of the RN-NET anchor package (RN-NET-03A): offline anchor payloads, per-network
// checks of supplied transaction data, and the dual-chain comparison. No signing, no network.
import { canonicalBytes } from '../../canonical/src/index.mjs';

export { AnchorError, MAX_OBSERVATION_BYTES, Network, OBSERVATION_FORMAT, RECORD_FORMAT } from './common.mjs';
export { COMMITMENT_FORMAT_V1, decodeAnchorPayload, encodeAnchorPayload, MAGIC, PAYLOAD_FORMAT, PAYLOAD_LENGTH, PAYLOAD_VERSION } from './payload.mjs';
export { ANCHOR_MEMO_TYPE, verifyXrplObservation } from './xrpl.mjs';
export { SEPOLIA_CHAIN_ID, verifyEvmObservation } from './evm.mjs';
export { Conclusion, REPORT_FORMAT, verifyDualAnchor } from './dual.mjs';

/** The exact bytes of a record or report under rnnet.canonical-json.v1. */
export const encodeAnchorReport = (report) => canonicalBytes(report);
