#!/usr/bin/env node
// tools/prepare/prepare-live.mjs: the controlled, READ-ONLY, keyless live preparation entry point
// (RN-NET-03B2-C3; ADR-RN-018 Amendment C1, ADR-RN-016 Amendment C1, ADR-RN-019 Amendment C1, E1
// and E2). DISABLED FOR LIVE NETWORK ACCESS IN THIS MILESTONE.
//
// What it is: the one command that may, after its own read-only authorization, read the account
// and fee state a Genesis transaction is bound from, and write the unsigned intent for gate D.
// Here it is the interface and its checks, exercised only against injected, simulated transports:
//   - `prepareLive({ argv, deps })` runs the whole flow with an injected transport (tests only);
//   - run as a command, it refuses at once (RNPL_LIVE_DISABLED, exit 3): it reads no file, builds
//     no transport and contacts nothing. It imports no transport, and the guard keeps it so.
//
// The flow, in order; any failure refuses the run, and nothing is read before step 8:
//   1. exactly these flags, each once: --network --authorization --endpoints --evidence-dir. There
//      is no retry, fee, field, provider, block or force option; the budget is fixed in code;
//   2. --network is xrpl:testnet or evm:11155111; --evidence-dir is the agreed directory
//      (AGREED_EVIDENCE_DIR, not yet agreed);
//   3. the authorization (rnnet.preparation-authorization.v1, a private file) names that network,
//      the Genesis Proof 01 commitment and purpose, the exact request budget (XRPL 4, Sepolia 16),
//      and a notAfter that has not passed and is at most 60 minutes ahead; on XRPL its sender is
//      the classic address of its signingPubKey;
//   4. the endpoint file is exactly the reviewed providers, and they are the authorization's;
//   5. Sepolia: both providers must be recorded as accepting the block-hash object on every pinned
//      read (SEPOLIA_COMPATIBILITY, from the C6 check). Until then the run is BLOCKED here, before
//      any read: there is no reviewed fallback (ADR-RN-018 Amendment C1, P4);
//   6. the founder approves this one run by typing the network and the authorization digest's last
//      16 hex digits, after seeing every value it is bound to;
//   7. the run directory <evidence-dir>/<authorizationId>/ is created: one run per authorization;
//   8. packages/tx-prepare reads through the request policy (tools/prepare/policy.mjs), which
//      admits exactly the planned requests in their planned forms, one attempt each;
//   9. the evidence and, if prepared, the intent are written privately; the intent digest is shown.
// It holds no key, imports nothing from signer/, tools/keytool/, chain-submit or tools/submit/, and
// sends no write method: none is in its plan.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { addressFromPublicKey, IntentNetwork, payloadHex, XRPL } from '../../packages/tx-intent/src/index.mjs';
import { prepareSepoliaIntent, prepareXrplIntent } from '../../packages/tx-prepare/src/index.mjs';
import { PreparationAuthorizationError, readPreparationAuthorization, utcSeconds } from './authorization.mjs';
import {
  AGREED_EVIDENCE_DIR,
  checkAgreedEvidenceDir,
  entryNetwork,
  GENESIS_COMMITMENT,
  parseArguments,
  PrepareEntryCode,
  PrepareEntryError,
  readPrivateText,
  requireApproval,
  REVIEWED_PREPARATION_PROVIDERS,
  reviewedProviders,
  SEPOLIA_COMPATIBILITY,
  sepoliaCompatibilityBlock,
} from './entry.mjs';
import { checkEvidenceDirectory, createRunDirectory, PREPARATION_EVIDENCE_FORMAT, storedText, writeNewFile } from './evidence.mjs';
import { createPreparationPolicy, PREPARATION_RUN_REQUESTS } from './policy.mjs';

/** False in RN-NET-03B2-C3. A test pins it, and the command line refuses while it is false. */
export const LIVE_NETWORK_ACCESS = false;
export const PREPARE_FLAGS = Object.freeze(['network', 'authorization', 'endpoints', 'evidence-dir']);
/** Exit codes, by outcome. Only PREPARED is 0, and a prepared intent is not yet approved (gate D). */
export const PREPARE_EXIT = Object.freeze({ PREPARED: 0, REFUSED: 2, LIVE_DISABLED: 3, BLOCKED: 4 });
/** An authorization may be written at most this long before it is void (one sitting). */
export const MAX_AUTHORIZATION_AHEAD_SECONDS = 3600;
/** The broadcaster refuses once LastLedgerSequence - validated ledger <= this (ADR-RN-019 §5). */
export const XRPL_SUBMISSION_MARGIN = 4;

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const refuse = (code, detail) => {
  throw new PrepareEntryError(code, detail);
};

const NEXT_STEP = Object.freeze({
  PREPARED: 'Not approved yet. Gate D: the founder reviews this intent and approves it by its digest in the key tool (a separate authorization).',
  REFUSED: 'Nothing was prepared. A new run needs a new authorization (a new authorizationId).',
  BLOCKED: 'Sepolia preparation cannot run under the reviewed strategy. Do not retry another way: the C6 compatibility record, or a reviewed amendment, comes first.',
});

/** The XRPL window a prepared intent leaves, in ledgers and seconds at 3 to 5 s per ledger. */
export function xrplWindow(intent) {
  const last = intent.transaction.LastLedgerSequence;
  const lowest = Math.min(...intent.preparation.providers.map((p) => p.validatedLedger.index));
  const usable = last - XRPL_SUBMISSION_MARGIN - lowest;
  return Object.freeze({ lastLedgerSequence: last, voidAtLedger: last - XRPL_SUBMISSION_MARGIN, fromLedger: lowest, usableLedgers: usable, usableSeconds: Object.freeze([usable * 3, usable * 5]) });
}

/**
 * The whole flow with injected dependencies. Returns { exitCode, outcome, code, providerId,
 * blocked, intentDigest, intent, runDirectory, message }.
 * @param {{ argv: string[], deps: { readText?, transport, now, approve, getuid?, agreed?, reviewed?, compatibility? } }} options
 */
export async function prepareLive({ argv, deps }) {
  try {
    const args = parseArguments(argv, PREPARE_FLAGS);
    const network = entryNetwork(args.network);
    checkAgreedEvidenceDir(args['evidence-dir'], Object.hasOwn(deps, 'agreed') ? deps.agreed : AGREED_EVIDENCE_DIR);
    const readText = deps.readText ?? readPrivateText;
    let parsed;
    try {
      parsed = readPreparationAuthorization(readText(args.authorization));
    } catch (error) {
      if (error instanceof PreparationAuthorizationError) refuse(PrepareEntryCode.AUTHORIZATION, error.detail);
      throw error;
    }
    const { authorization: a, digest } = parsed;
    if (a.network !== network) refuse(PrepareEntryCode.NETWORK_MISMATCH, `the authorization is for ${a.network}`);
    if (a.purpose !== 'genesis-proof-01' || a.commitment !== GENESIS_COMMITMENT) refuse(PrepareEntryCode.NOT_GENESIS, 'the authorization is not for the Genesis Proof 01 commitment');
    if (a.requestBudget !== PREPARATION_RUN_REQUESTS[network]) refuse(PrepareEntryCode.AUTHORIZATION, `requestBudget must be ${PREPARATION_RUN_REQUESTS[network]} on ${network}`);
    if (network === IntentNetwork.XRPL_TESTNET && addressFromPublicKey(Buffer.from(a.signingPubKey, 'hex')) !== a.sender) {
      refuse(PrepareEntryCode.AUTHORIZATION, 'sender is not the classic address of signingPubKey');
    }
    const clock = () => {
      const seconds = deps.now();
      if (!Number.isSafeInteger(seconds) || seconds <= 0) throw new TypeError('now() must return Unix seconds');
      return seconds;
    };
    const notAfter = utcSeconds(a.notAfter);
    const checkedAt = clock();
    if (checkedAt > notAfter) refuse(PrepareEntryCode.AUTHORIZATION_EXPIRED, `void since ${a.notAfter}`);
    if (notAfter - checkedAt > MAX_AUTHORIZATION_AHEAD_SECONDS) refuse(PrepareEntryCode.AUTHORIZATION, 'notAfter is more than 60 minutes ahead');
    let endpoints;
    try {
      endpoints = JSON.parse(readText(args.endpoints));
    } catch (error) {
      if (error instanceof PrepareEntryError) throw error;
      refuse(PrepareEntryCode.ENDPOINTS_NOT_REVIEWED, 'not JSON');
    }
    const providers = reviewedProviders(endpoints, network, a.providerIds, deps.reviewed ?? REVIEWED_PREPARATION_PROVIDERS);

    if (network === IntentNetwork.SEPOLIA) {
      const block = sepoliaCompatibilityBlock(a.providerIds, Object.hasOwn(deps, 'compatibility') ? deps.compatibility : SEPOLIA_COMPATIBILITY);
      if (block !== null) {
        const why = block.recorded ? 'recorded as refusing the block-hash object' : 'not yet recorded as accepting the block-hash object (C6)';
        return result({ outcome: 'BLOCKED', code: PrepareEntryCode.COMPATIBILITY_UNRECORDED, providerId: block.providerId, blocked: block.reason, detail: `${block.providerId}: ${why}` });
      }
    }

    await requireApproval(deps.approve, {
      network,
      digest,
      lines: [
        `PREPARE (read-only, no key) on ${network}, providers ${a.providerIds.join(' then ')}, exactly ${a.requestBudget} requests`,
        `authorization ${a.authorizationId}, valid until ${a.notAfter}`,
        `sender ${a.sender}${a.signingPubKey === null ? '' : `, SigningPubKey ${a.signingPubKey}`}`,
        `commitment ${a.commitment} (${a.purpose})`,
        network === IntentNetwork.XRPL_TESTNET
          ? `LastLedgerSequence = lowest validated ledger + ${XRPL.lastLedgerOffset}; submission void once ${XRPL_SUBMISSION_MARGIN} or fewer ledgers remain`
          : 'reads pinned to one agreed block hash (lowest head - 2); no fallback',
        `scope: ${a.scope}`,
        `evidence ${args['evidence-dir']}/${a.authorizationId}/`,
      ],
    });

    // The time preparation checks freshness against is read AFTER the approval, immediately before
    // the first request: the founder's reading time must not make fresh blocks look "in the future"
    // (found by the C3 rehearsal). The authorization is checked again at that time.
    const now = clock();
    if (now > notAfter) refuse(PrepareEntryCode.AUTHORIZATION_EXPIRED, `void since ${a.notAfter} (expired during the approval)`);
    checkEvidenceDirectory(args['evidence-dir'], deps.getuid ?? (typeof process.getuid === 'function' ? () => process.getuid() : undefined));
    const runDirectory = createRunDirectory(args['evidence-dir'], a.authorizationId);

    const exchanges = [];
    const responses = [];
    const recording = async (request) => {
      const entry = { providerId: request.providerId, request: Buffer.from(request.body).toString('utf8'), requestSha256: sha256(request.body) };
      exchanges.push(entry);
      try {
        const response = await deps.transport(request);
        if (response !== null && typeof response === 'object' && response.body instanceof Uint8Array) {
          entry.status = response.status;
          entry.responseSha256 = sha256(response.body);
          entry.responseFile = `response-${String(exchanges.length).padStart(2, '0')}.bin`;
          responses.push({ name: entry.responseFile, body: response.body });
        }
        return response;
      } catch (error) {
        entry.error = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : 'TRANSPORT_ERROR';
        throw error;
      }
    };
    const policy = createPreparationPolicy({ network, providers, sender: a.sender, data: network === IntentNetwork.SEPOLIA ? `0x${payloadHex(a.commitment)}` : undefined });
    const transport = policy.wrap(recording);
    let outcome;
    try {
      const prepared = network === IntentNetwork.XRPL_TESTNET
        ? await prepareXrplIntent({ commitment: a.commitment, account: a.sender, signingPubKey: a.signingPubKey, providers, transport, now })
        : await prepareSepoliaIntent({ commitment: a.commitment, from: a.sender, providers, transport, now });
      outcome = policy.violation === null && policy.complete() && exchanges.length === a.requestBudget
        ? { outcome: 'PREPARED', code: null, providerId: null, blocked: null, intent: prepared.intent, intentDigest: prepared.digest }
        : { outcome: 'REFUSED', code: PrepareEntryCode.REQUEST_POLICY, providerId: null, blocked: null, detail: policy.violation ?? 'the planned requests were not all made' };
    } catch (error) {
      if (policy.violation !== null) outcome = { outcome: 'REFUSED', code: PrepareEntryCode.REQUEST_POLICY, providerId: null, blocked: null, detail: policy.violation };
      else if (error?.name === 'PrepError') outcome = { outcome: error.blocked ? 'BLOCKED' : 'REFUSED', code: error.code, providerId: error.providerId, blocked: error.blocked, detail: error.message };
      else throw error;
    }

    for (const { name, body } of responses) writeNewFile(runDirectory, name, body);
    const evidence = {
      format: PREPARATION_EVIDENCE_FORMAT,
      authorizationId: a.authorizationId,
      authorizationDigest: digest,
      network,
      providerIds: [...a.providerIds],
      observedAt: now,
      outcome: outcome.outcome,
      code: outcome.code,
      providerId: outcome.providerId,
      blocked: outcome.blocked,
      intentDigest: outcome.intentDigest ?? null,
      requestCount: exchanges.length,
      exchanges,
    };
    writeNewFile(runDirectory, 'evidence.json', storedText(evidence));
    if (outcome.outcome === 'PREPARED') writeNewFile(runDirectory, 'intent.json', storedText(outcome.intent));
    return result({ ...outcome, runDirectory });
  } catch (error) {
    if (error instanceof PrepareEntryError) return result({ outcome: 'REFUSED', code: error.code, providerId: null, blocked: null, detail: error.message });
    throw error;
  }
}

function result({ outcome, code, providerId, blocked, intent = null, intentDigest = null, runDirectory = null, detail }) {
  const lines = [`${outcome}${code ? ` ${code}` : ''}${detail ? ` (${detail})` : ''}`];
  if (intent !== null) {
    lines.push(`intent digest: ${intentDigest}`, `intent (canonical JSON): ${canonicalize(intent)}`);
    if (intent.network === IntentNetwork.XRPL_TESTNET) {
      const w = xrplWindow(intent);
      lines.push(`LastLedgerSequence ${w.lastLedgerSequence}: submission void from validated ledger ${w.voidAtLedger}; ${w.usableLedgers} ledgers (${w.usableSeconds[0]} to ${w.usableSeconds[1]} s) for gate D and gate E.`);
    }
  }
  lines.push(NEXT_STEP[outcome]);
  return Object.freeze({ exitCode: PREPARE_EXIT[outcome], outcome, code, providerId, blocked, intentDigest, intent, runDirectory, message: lines.join('\n') });
}

/** The command line: refuses while LIVE_NETWORK_ACCESS is false, before reading anything. */
export function main() {
  process.stderr.write(`${PrepareEntryCode.LIVE_DISABLED}: live network access is disabled in RN-NET-03B2-C3. The C6 read-only check, ADR-RN-018 Amendment C1 acceptance and a reviewed change are required.\n`);
  return PREPARE_EXIT.LIVE_DISABLED;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main();
