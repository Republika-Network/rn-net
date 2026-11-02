#!/usr/bin/env node
// tools/submit/submit-anchor.mjs: the controlled live submission entry point (RN-NET-03B2-C2;
// ADR-RN-019 Amendment C1, E1 to E5). DISABLED FOR LIVE NETWORK ACCESS IN THIS MILESTONE.
//
// What it is: the one command that may, after gate E, send one founder-authorized write. Here it is
// the interface and its checks, exercised only against injected, simulated transports:
//   - `submitAnchor({ argv, deps })` runs the whole flow with an injected transport (tests only);
//   - run as a command, it refuses at once (RNSA_LIVE_DISABLED, exit 3): it reads no file, builds no
//     transport and contacts nothing. It does not import tools/live/, and the guard keeps it that
//     way (WRITE_TRANSPORT_JOINERS is empty). Enabling it is a reviewed change at gate E.
//
// The flow, in order; any failure refuses the run:
//   1. exactly these flags, each once: --network --authorization --intent --approved-digest
//      --signed-transaction --endpoints --log-dir --evidence-dir. There is no retry, fee, field,
//      provider or force option. The budget is fixed in code (tools/submit/policy.mjs).
//   2. --network is xrpl:testnet or evm:11155111, and the authorization names that same network;
//   3. the endpoint file is exactly the reviewed providers (REVIEWED_PROVIDERS);
//   4. the authorization, intent and signed transaction are private files (0600, not links);
//   5. the founder approves this one run by typing the network and the authorization digest's
//      last 16 hex digits, after seeing every value it is bound to (separate per network, and per
//      submission);
//   6. runBroadcast (tools/submit/broadcaster.mjs) does the rest: it consumes the authorization,
//      re-verifies the intent and signed bytes with both verifiers, matches the authorization,
//      makes the planned pre-submit reads, writes ATTEMPTING and attempt.json durably, sends the
//      one write, classifies it, and records the result. It never retries.
// It holds no key, imports nothing from signer/, and cannot sign: it passes the given bytes through.
import { fileURLToPath } from 'node:url';
import { readAuthorization } from '../../packages/chain-submit/src/index.mjs';
import { runBroadcast } from './broadcaster.mjs';
import { EntryCode, EntryError, entryNetwork, parseArguments, readPrivateText, requireApproval, reviewedEndpoints, REVIEWED_PROVIDERS } from './entry.mjs';

/** False in RN-NET-03B2-C2. A test pins it, and the command line refuses while it is false. */
export const LIVE_NETWORK_ACCESS = false;
export const SUBMIT_FLAGS = Object.freeze(['network', 'authorization', 'intent', 'approved-digest', 'signed-transaction', 'endpoints', 'log-dir', 'evidence-dir']);
/** Exit codes, by outcome. Only ACCEPTED_PROVISIONAL is 0, and it is not proof of inclusion. */
export const SUBMIT_EXIT = Object.freeze({ ACCEPTED_PROVISIONAL: 0, REFUSED: 2, LIVE_DISABLED: 3, NOT_SENT: 10, REJECTED: 11, UNCERTAIN: 12 });

const NEXT_STEP = Object.freeze({
  ACCEPTED_PROVISIONAL: 'Provisional only: not proof of inclusion. Verify with a separately authorized status check, then gate F.',
  NOT_SENT: 'Nothing was sent. Another attempt needs a new authorization (attempt + 1).',
  REJECTED: 'Refused by the provider. Another attempt needs a new authorization (attempt + 1); changed bytes need a new gate D.',
  UNCERTAIN: 'Do not resend. The next step is a status check under its own rnnet.status-authorization.v1.',
});

/** A file's text, without the one newline that ends a file written by an editor. */
const fileText = (readText, path) => {
  const text = readText(path);
  return text.endsWith('\n') ? text.slice(0, -1) : text;
};

/**
 * The whole flow with injected dependencies. Returns { exitCode, code, result, message }.
 * @param {{ argv: string[], deps: { readText, transport, referenceVerifier, now, approve, reviewed? } }} options
 */
export async function submitAnchor({ argv, deps }) {
  try {
    const args = parseArguments(argv, SUBMIT_FLAGS);
    const network = entryNetwork(args.network);
    const reviewed = deps.reviewed ?? REVIEWED_PROVIDERS;
    const readText = deps.readText ?? readPrivateText;
    const authorizationText = readText(args.authorization);
    let parsed;
    try {
      parsed = readAuthorization(authorizationText);
    } catch (error) {
      throw new EntryError(EntryCode.AUTHORIZATION, error.code ?? 'unreadable');
    }
    const { authorization, digest } = parsed;
    if (authorization.network !== network) throw new EntryError(EntryCode.NETWORK_MISMATCH, `the authorization is for ${authorization.network}`);
    let endpoints;
    try {
      endpoints = JSON.parse(readText(args.endpoints));
    } catch (error) {
      if (error instanceof EntryError) throw error;
      throw new EntryError(EntryCode.ENDPOINTS_NOT_REVIEWED, 'not JSON');
    }
    reviewedEndpoints(endpoints, network, reviewed);
    const inputs = {
      intent: fileText(readText, args.intent),
      approvedDigest: args['approved-digest'],
      signedTransaction: fileText(readText, args['signed-transaction']),
      authorization: authorizationText,
    };
    await requireApproval(deps.approve, {
      network,
      digest,
      lines: [
        `SUBMIT one ${authorization.dryRun ? 'DRY RUN (no write)' : 'WRITE'} on ${network} to provider ${authorization.providerId}`,
        `attempt ${authorization.attempt} (${authorization.kind}), sender ${authorization.sender}, sequence ${authorization.sequence}`,
        `intent ${authorization.intentDigest}`,
        `blob ${authorization.blobSha256}`,
        `transaction hash ${authorization.transactionHash}`,
        `validity ${JSON.stringify(authorization.validity)}`,
        `scope: ${authorization.scope}`,
      ],
    });
    const result = await runBroadcast({
      inputs,
      environment: { endpoints, transport: deps.transport, referenceVerifier: deps.referenceVerifier, now: deps.now, logDir: args['log-dir'], evidenceDir: args['evidence-dir'] },
    });
    return Object.freeze({ exitCode: SUBMIT_EXIT[result.outcome], code: result.code, result, message: `${result.outcome} ${result.code}. ${NEXT_STEP[result.outcome]}` });
  } catch (error) {
    if (error instanceof EntryError) return Object.freeze({ exitCode: SUBMIT_EXIT.REFUSED, code: error.code, result: null, message: error.message });
    throw error;
  }
}

/** The command line: refuses while LIVE_NETWORK_ACCESS is false, before reading anything. */
export function main() {
  process.stderr.write(`${EntryCode.LIVE_DISABLED}: live network access is disabled in RN-NET-03B2-C2. Gate E (ADR-RN-019) and a reviewed change are required.\n`);
  return SUBMIT_EXIT.LIVE_DISABLED;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main();
