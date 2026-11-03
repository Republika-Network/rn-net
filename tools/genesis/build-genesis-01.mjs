// Builds fixtures/genesis-proof-01/: the synthetic evidence anchored by Genesis Proof 01, its
// rnnet.evidence-commitment.v1 envelope, and the immutable offline golden values.
//
//   node tools/genesis/build-genesis-01.mjs           # check the committed files are current
//   node tools/genesis/build-genesis-01.mjs --write   # write them (refuses to overwrite)
//
// The evidence is original and synthetic: it describes no real operation, person or
// organization. Its one signature uses a test key derived from a public label (as in
// tools/vectors/evidence-vectors.mjs), so anyone can rebuild the key: it is a fixture key that can
// never stand for an identity, not an operational key. No key is stored. Nothing here touches a
// network, and no transaction is signed (the transactions are described unsigned).
//
// The build stops unless the RN-NET-02 verifier PASSes the evidence with its commitment, the
// payload decodes back to the commitment, both intended transactions pass the preparation checks,
// and the rehearsal observations PASS the dual-chain check. tools/reference/
// rnnet_genesis_reference.py checks the committed values independently.
import { Buffer } from 'node:buffer';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { computeCommitment } from '../../packages/commitment/src/index.mjs';
import { computeEvidenceDigest, encodeReport, evidenceDigestBytes, signingMessage, verifyEvidence } from '../../packages/verifier/src/index.mjs';
import { ANCHOR_MEMO_TYPE, decodeAnchorPayload, encodeAnchorReport, PAYLOAD_LENGTH, verifyDualAnchor } from '../../packages/anchor/src/index.mjs';
import {
  checkSepoliaAnchorTx,
  checkXrplAnchorTx,
  intrinsicGas,
  memosSerializedLength,
  payloadHex,
  PREFLIGHT_LAST_LEDGER_OFFSET,
  REHEARSAL,
  rehearsalObservations,
  rehearsalTransactions,
  SEPOLIA,
  sepoliaAnchorTemplate,
  sepoliaMaxCostWei,
  XRPL,
  xrplAnchorTemplate,
} from './prepare.mjs';

export const DIR = fileURLToPath(new URL('../../fixtures/genesis-proof-01/', import.meta.url));
export const FILES = ['evidence.json', 'envelope.json', 'golden.json'];
export const KEY_LABEL = 'genesis-proof-01';
export const SOURCE_REF = 'synthetic:fixtures/genesis-proof-01/evidence.json';

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const text = (bytes) => new TextDecoder().decode(bytes);

/** The fixture test key: Ed25519 from SHA-256("rnnet:synthetic-test-key:v1:<label>"), as in RN-NET-02. */
function testKey(label) {
  const seed = createHash('sha256').update(`rnnet:synthetic-test-key:v1:${label}`).digest();
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url').toString('hex');
  return { privateKey, publicKey };
}

export const BODY = Object.freeze({
  evidenceId: 'genesis-proof-01',
  issuer: 'synthetic-issuer.rnnet.example',
  subject: 'demonstration:genesis-proof-01',
  action: 'synthetic.anchoring.demonstration',
  outcome: 'succeeded',
  payload: {
    note: 'Synthetic RN-NET demonstration evidence for Genesis Proof 01. It describes no real operation, person or organization.',
    purpose: 'dual-chain-anchoring-demonstration',
    sequence: 1,
    targetNetworks: ['xrpl:testnet', 'evm:11155111'],
  },
});

const fail = (why) => {
  throw new Error(`genesis build: ${why}`);
};

export function build() {
  const body = structuredClone(BODY);
  const key = testKey(KEY_LABEL);
  const signature = sign(null, signingMessage(evidenceDigestBytes(body)), key.privateKey).toString('hex');
  const evidenceDoc = {
    format: 'rnnet.synthetic-evidence.v1',
    canonicalization: 'rnnet.canonical-json.v1',
    body,
    digest: computeEvidenceDigest(body),
    signatures: [{ keyId: 'genesis-fixture-key-1', algorithm: 'ed25519', publicKey: key.publicKey, signature }],
  };
  const evidence = canonicalBytes(evidenceDoc);
  const envelopeValue = {
    format: 'rnnet.evidence-commitment.v1',
    sourceFormat: 'rnnet.synthetic-evidence.v1',
    sourceCanonicalization: 'rnnet.canonical-json.v1',
    sourceEvidenceDigest: evidenceDoc.digest,
    sourceFileSha256: sha256(evidence),
    sourceRef: SOURCE_REF,
  };
  const envelope = canonicalBytes(envelopeValue);
  const { digest: commitment } = computeCommitment(envelopeValue);

  // RN-NET-02: the evidence and its commitment verify.
  const report = verifyEvidence(evidence, { commitment: { envelope, digest: commitment } });
  if (report.outcome !== 'PASS' || report.findings.length !== 0) fail(`verifier outcome ${report.outcome}`);

  // RN-NET-03A: the payload.
  const payload = payloadHex(commitment);
  if (payload.length !== PAYLOAD_LENGTH * 2 || decodeAnchorPayload(Buffer.from(payload, 'hex')) !== commitment) fail('payload does not round-trip');

  // Intended transactions, completed with rehearsal values, pass the preparation checks.
  const completed = rehearsalTransactions(commitment);
  const xrplProblems = checkXrplAnchorTx(completed.xrpl, commitment);
  const evmProblems = checkSepoliaAnchorTx(completed.evm, commitment);
  if (xrplProblems.length || evmProblems.length) fail(`preparation checks: ${[...xrplProblems, ...evmProblems].join('; ')}`);

  // Rehearsal: the existing dual-chain checks accept what the transactions would look like.
  const observations = rehearsalObservations(commitment);
  const dual = verifyDualAnchor({ xrpl: Buffer.from(observations.xrpl), evm: Buffer.from(observations.evm) }, commitment);
  if (dual.outcome !== 'PASS' || dual.conclusions.includes('CHAIN_PROVEN')) fail(`rehearsal outcome ${dual.outcome}`);

  const gas = intrinsicGas(Buffer.from(payload, 'hex'));
  const golden = {
    format: 'rnnet.genesis-preflight.v1',
    id: 'genesis-proof-01',
    status: 'PREFLIGHT: not signed, not submitted, not anchored',
    synthetic: 'The evidence is synthetic. The rehearsal observations are synthetic and exist on no network.',
    evidence: {
      file: 'evidence.json',
      fileSha256: sha256(evidence),
      evidenceDigest: evidenceDoc.digest,
      fixtureKey: { keyId: 'genesis-fixture-key-1', publicKey: key.publicKey, derivation: `Ed25519 seed = SHA-256("rnnet:synthetic-test-key:v1:${KEY_LABEL}"); public, test-only, not an identity` },
      verification: { outcome: report.outcome, reportSha256: sha256(encodeReport(report)), report: text(encodeReport(report)) },
    },
    envelope: { file: 'envelope.json', fileSha256: sha256(envelope), commitment },
    anchorPayload: { length: PAYLOAD_LENGTH, hex: payload },
    xrpl: {
      network: XRPL.network,
      transactionType: 'AccountSet',
      memoType: ANCHOR_MEMO_TYPE,
      memoData: payload.toUpperCase(),
      memosSerializedBytes: memosSerializedLength([[ANCHOR_MEMO_TYPE.length / 2, PAYLOAD_LENGTH]]),
      feeDrops: XRPL.feeDrops,
      maxFeeDrops: String(XRPL.maxFeeDrops),
      // The value recorded at the RN-NET-03B2-A preflight; the golden file is immutable (prepare.mjs).
      lastLedgerOffset: PREFLIGHT_LAST_LEDGER_OFFSET,
      unsignedTemplate: xrplAnchorTemplate(commitment),
      boundAtSigning: ['Account', 'Sequence', 'LastLedgerSequence', 'SigningPubKey'],
    },
    sepolia: {
      network: SEPOLIA.network,
      chainId: SEPOLIA.chainId,
      input: `0x${payload}`,
      gas: { rules: 'Prague: EIP-2028 calldata cost with the EIP-7623 floor', ...gas, gasLimit: Number(SEPOLIA.gasLimit) },
      maxFeePerGasCapWei: String(SEPOLIA.maxFeePerGasCapWei),
      maxPriorityFeePerGasWei: String(SEPOLIA.maxPriorityFeePerGasWei),
      maxCostAtCapWei: String(sepoliaMaxCostWei({ gas: `0x${SEPOLIA.gasLimit.toString(16)}`, maxFeePerGas: `0x${SEPOLIA.maxFeePerGasCapWei.toString(16)}` })),
      unsignedTemplate: sepoliaAnchorTemplate(commitment),
      boundAtSigning: ['from', 'to', 'nonce', 'maxFeePerGas'],
    },
    rehearsal: {
      values: { ...REHEARSAL },
      xrplObservation: observations.xrpl,
      evmObservation: observations.evm,
      expectedOutcome: dual.outcome,
      expectedConclusions: [...dual.conclusions],
      expectedReport: text(encodeAnchorReport(dual)),
    },
  };
  return {
    'evidence.json': evidence,
    'envelope.json': envelope,
    'golden.json': new TextEncoder().encode(`${JSON.stringify(golden, null, 2)}\n`),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const built = build();
  if (process.argv.includes('--write')) {
    for (const name of FILES) {
      if (existsSync(DIR + name)) fail(`${name} exists; golden values are immutable (delete it deliberately to rebuild)`);
    }
    for (const name of FILES) writeFileSync(DIR + name, built[name], { flag: 'wx' });
    console.log(`wrote ${FILES.join(', ')}`);
  } else {
    const stale = FILES.filter((name) => !existsSync(DIR + name) || !Buffer.from(readFileSync(DIR + name)).equals(Buffer.from(built[name])));
    if (stale.length) {
      console.error(`genesis fixtures differ from the build: ${stale.join(', ')}`);
      process.exit(1);
    }
    console.log('genesis fixtures are current');
  }
}
