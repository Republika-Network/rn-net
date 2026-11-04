// Public API of packages/tx-intent (RN-NET-03B2-B1, ADR-RN-017): the approved unsigned
// transaction intent, its digest, and offline XRPL and EIP-1559 encoding and decoding.
// No dependencies, no keys, no signing, no network.
export { ensure, TxError, TxErrorCode } from './errors.mjs';
export {
  checkSepoliaAnchorTx,
  checkXrplAnchorTx,
  intrinsicGas,
  isPlainData,
  memosSerializedLength,
  payloadHex,
  quantity,
  SEPOLIA,
  sepoliaAnchorTemplate,
  sepoliaMaxCostWei,
  sepoliaMaxFee,
  XRPL,
  xrplAnchorMemo,
  xrplAnchorTemplate,
} from './genesis.mjs';
export { approvedIntent, INTENT_DIGEST_DOMAIN, INTENT_FORMAT, intentDigest, IntentNetwork, intentSender, intentSequence, makeIntent, PURPOSES } from './intent.mjs';
// RN-NET-03B2-WP3-R1: the Stage A v2 preparation candidate. It is not an intent: makeIntent and every
// consumer refuse it, and its digest uses its own domain (ADR-RN-018 C2 Q4, Proposed).
export { CANDIDATE_DIGEST_DOMAIN, CANDIDATE_FORMAT, candidateDigest, makePreparationCandidate, verifiedPreparationCandidate } from './candidate.mjs';
export {
  addressFromPublicKey,
  decodeAddress,
  decodeXrplTx,
  encodeAddress,
  encodeNativeAmount,
  encodeVL,
  encodeXrplTx,
  fieldHeader,
  SIGNING_PREFIX,
  TX_ID_PREFIX,
  XRPL_FIELD_CODES,
  xrplSigningPreimage,
  xrplTxHash,
} from './xrpl.mjs';
export { decodeUint, encodeUint, rlpDecode, rlpEncode } from './rlp.mjs';
export { decodeEip1559Signed, EIP1559_TYPE, encodeEip1559Signed, encodeEip1559Unsigned, SECP256K1_N } from './evm.mjs';
export { compareSepolia, compareXrpl, SEPOLIA_COMPARE_ORDER, XRPL_COMPARE_ORDER } from './compare.mjs';
// Fork-aware gas rules (ADR-RN-018 Amendment C2; WP2, offline). Not used by preparation yet;
// the production intrinsicGas above is unchanged.
export {
  BOUNDARY_AFTER_SECONDS,
  BOUNDARY_BEFORE_SECONDS,
  calldataGas,
  calldataGasForInput,
  checkForkBoundary,
  checkGasWithinLimit,
  checkRuleSetForTimestamp,
  evaluateGenesisGas,
  GAS_RULE_SETS,
  GAS_RULES_LIMIT,
  MAX_REVIEW_AGE_SECONDS,
  MAX_TIMESTAMP,
  REVIEWED_GAS_RULE_SOURCES,
  selectSepoliaGasRules,
  SEPOLIA_ACTIVATIONS,
  SEPOLIA_GAS_RULES_REVIEW,
  validateActivationTable,
  validateGenesisGasPreconditions,
  validateReviewedRulesHorizon,
} from './gas-rules.mjs';
