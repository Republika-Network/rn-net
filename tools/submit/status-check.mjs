#!/usr/bin/env node
// tools/submit/status-check.mjs: the controlled, READ-ONLY status-check entry point (RN-NET-03B2-C2;
// ADR-RN-019 Amendment C1, E1 and E5). DISABLED FOR LIVE NETWORK ACCESS IN THIS MILESTONE.
//
// It runs one status check of one attempt, under its own rnnet.status-authorization.v1, through
// runStatusCheck (tools/submit/status.mjs). It never writes to a network:
//   - every request passes the read-only policy (only READ_ONLY_METHODS, never a write method,
//     the two named providers, a fixed ceiling), checked before the transport sees it;
//   - the guard refuses any route from this file to tools/submit/broadcaster.mjs, the write run;
//   - run as a command, it refuses at once (RNSA_LIVE_DISABLED, exit 3) and contacts nothing.
// Its finding is never proof (ADR-RN-015); CHAIN_PROVEN is never produced.
//
// Flags, exactly, each once: --network --authorization --intent --endpoints --log-dir --evidence-dir.
// The founder approves each run by typing the network and the last 16 hex digits of the status
// authorization's digest.
import { fileURLToPath } from 'node:url';
import { readStatusAuthorization } from '../../packages/chain-submit/src/index.mjs';
import { checkAgreedDirectories, EntryCode, EntryError, entryNetwork, parseArguments, readPrivateText, requireApproval, reviewedEndpoints, REVIEWED_PROVIDERS } from './entry.mjs';
import { runStatusCheck } from './status.mjs';

/** False in RN-NET-03B2-C2. A test pins it, and the command line refuses while it is false. */
export const LIVE_NETWORK_ACCESS = false;
export const STATUS_FLAGS = Object.freeze(['network', 'authorization', 'intent', 'endpoints', 'log-dir', 'evidence-dir']);
/** Exit codes: 0 only for a finding written as RESOLVED (INCLUDED, EXPIRED or PENDING). */
export const STATUS_EXIT = Object.freeze({ RESOLVED: 0, REFUSED: 2, LIVE_DISABLED: 3, UNRESOLVED: 12 });

/**
 * One status check with injected dependencies. Returns { exitCode, code, finding, result, message }.
 * @param {{ argv: string[], deps: { readText, transport, now, approve, reviewed? } }} options
 */
export async function statusCheck({ argv, deps }) {
  try {
    const args = parseArguments(argv, STATUS_FLAGS);
    const network = entryNetwork(args.network);
    checkAgreedDirectories(args, deps.agreed);
    const readText = deps.readText ?? readPrivateText;
    const authorizationText = readText(args.authorization);
    let parsed;
    try {
      parsed = readStatusAuthorization(authorizationText);
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
    reviewedEndpoints(endpoints, network, deps.reviewed ?? REVIEWED_PROVIDERS);
    const intentText = readText(args.intent);
    await requireApproval(deps.approve, {
      network,
      digest,
      lines: [
        `STATUS CHECK (read-only) on ${network}, providers ${authorization.providerIds.join(' and ')}`,
        `attempt entry ${authorization.attemptEntry}`,
        `sender ${authorization.sender}, sequence ${authorization.sequence}, transaction hash ${authorization.transactionHash}`,
        `scope: ${authorization.scope}`,
        `submission log ${args['log-dir']}, evidence ${args['evidence-dir']}`,
      ],
    });
    const result = await runStatusCheck({
      inputs: { authorization: authorizationText, intent: intentText.endsWith('\n') ? intentText.slice(0, -1) : intentText },
      environment: { endpoints, transport: deps.transport, now: deps.now, logDir: args['log-dir'], evidenceDir: args['evidence-dir'] },
    });
    const resolved = result.finding !== null && result.finding !== 'UNRESOLVED';
    const exitCode = resolved ? STATUS_EXIT.RESOLVED : result.finding === 'UNRESOLVED' ? STATUS_EXIT.UNRESOLVED : STATUS_EXIT.REFUSED;
    return Object.freeze({ exitCode, code: result.code, finding: result.finding, result, message: `${result.finding ?? 'REFUSED'} ${result.code ?? ''}`.trim() });
  } catch (error) {
    if (error instanceof EntryError) return Object.freeze({ exitCode: STATUS_EXIT.REFUSED, code: error.code, finding: null, result: null, message: error.message });
    throw error;
  }
}

/** The command line: refuses while LIVE_NETWORK_ACCESS is false, before reading anything. */
export function main() {
  process.stderr.write(`${EntryCode.LIVE_DISABLED}: live network access is disabled in RN-NET-03B2-C2. Gate E (ADR-RN-019) and a reviewed change are required.\n`);
  return STATUS_EXIT.LIVE_DISABLED;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main();
