// Public API of packages/tx-prepare (RN-NET-03B2-B2, ADR-RN-018): read-only preparation of the
// unsigned Genesis transactions from provider observations given through an injected transport.
// No dependencies, no keys, no signing, no write method, no network code.
export { BlockedReason, PrepError, PrepErrorCode } from './errors.mjs';
export { PREPARATION_FORMAT, PREPARATION_RULES, prepareSepoliaIntent, prepareXrplIntent } from './prepare.mjs';
// RN-NET-03B2-WP3 (ADR-RN-018 Amendment C2, Proposed; offline): the fork-aware Sepolia path and its
// rnnet.tx-preparation.v2 record. The gas-rule authority is the reviewed constant only (null).
export { PREPARATION_FORMAT_V2, PREPARATION_RULES_V2_ID, prepareSepoliaIntentV2, verifySepoliaPreparationV2 } from './prepare-v2.mjs';
