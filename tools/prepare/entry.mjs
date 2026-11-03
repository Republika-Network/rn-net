// What the live preparation entry point checks before any read (RN-NET-03B2-C3; ADR-RN-018
// Amendment C1, ADR-RN-019 Amendment C1, E1): an exact flag list, the reviewed providers, the
// agreed evidence directory, the recorded Sepolia provider compatibility, private-file reads and
// the founder's typed approval of one run.
//
// Self-contained on purpose: it shares no file with tools/submit/ (the write path), so preparation
// never reaches chain-submit, even through a helper. A test pins REVIEWED_PREPARATION_PROVIDERS to
// config/rpc-endpoints.json and to the providers tools/submit/ reviews.
import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { loadEndpointConfig } from '../../packages/chain-readonly/src/index.mjs';
import { IntentNetwork } from '../../packages/tx-intent/src/index.mjs';

/** Refusal codes of the preparation entry point (RNPL_*: no preparation code was reached). */
export const PrepareEntryCode = Object.freeze({
  USAGE: 'RNPL_USAGE',
  LIVE_DISABLED: 'RNPL_LIVE_DISABLED',
  NETWORK_NOT_ALLOWED: 'RNPL_NETWORK_NOT_ALLOWED',
  NETWORK_MISMATCH: 'RNPL_NETWORK_MISMATCH',
  ENDPOINTS_NOT_REVIEWED: 'RNPL_ENDPOINTS_NOT_REVIEWED',
  FILE: 'RNPL_FILE',
  AUTHORIZATION: 'RNPL_AUTHORIZATION',
  AUTHORIZATION_EXPIRED: 'RNPL_AUTHORIZATION_EXPIRED',
  AUTHORIZATION_USED: 'RNPL_AUTHORIZATION_USED',
  NOT_GENESIS: 'RNPL_NOT_GENESIS',
  APPROVAL_REFUSED: 'RNPL_APPROVAL_REFUSED',
  DIRECTORY_NOT_AGREED: 'RNPL_DIRECTORY_NOT_AGREED',
  COMPATIBILITY_UNRECORDED: 'RNPL_COMPATIBILITY_UNRECORDED',
  REQUEST_POLICY: 'RNPL_REQUEST_POLICY',
  EVIDENCE: 'RNPL_EVIDENCE',
});

export class PrepareEntryError extends Error {
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'PrepareEntryError';
    this.code = code;
  }
}

/** The only networks preparation accepts. Never a mainnet. */
export const PREPARE_NETWORKS = Object.freeze([IntentNetwork.XRPL_TESTNET, IntentNetwork.SEPOLIA]);

/**
 * The reviewed providers (config/rpc-endpoints.json, ADR-RN-013) by id, network, URL and operator,
 * in the order a run reads them. Operators are distinct, as preparation requires.
 */
export const REVIEWED_PREPARATION_PROVIDERS = Object.freeze([
  Object.freeze({ id: 'xrpl-testnet-ripple', network: IntentNetwork.XRPL_TESTNET, url: 'https://s.altnet.rippletest.net:51234/', operator: 'Ripple' }),
  Object.freeze({ id: 'xrpl-testnet-xrpl-labs', network: IntentNetwork.XRPL_TESTNET, url: 'https://testnet.xrpl-labs.com/', operator: 'XRPL Labs' }),
  Object.freeze({ id: 'sepolia-publicnode', network: IntentNetwork.SEPOLIA, url: 'https://ethereum-sepolia-rpc.publicnode.com/', operator: 'PublicNode' }),
  Object.freeze({ id: 'sepolia-1rpc', network: IntentNetwork.SEPOLIA, url: 'https://public.1rpc.io/sepolia', operator: 'Automata 1RPC' }),
]);

/**
 * The Genesis Proof 01 commitment (fixtures/genesis-proof-01, immutable). Preparation binds only
 * this commitment: an authorization naming another is refused (a modified payload never reaches a
 * provider). A test pins it to golden.json.
 */
export const GENESIS_COMMITMENT = 'sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7';

/**
 * The agreed evidence directory (ADR-RN-019 §7: a new private directory outside every repository).
 * Each run creates <dir>/<authorizationId>/, which makes each authorization single-use there. Not
 * agreed in RN-NET-03B2-C3, so it is null and no run can pass; agreeing it is a reviewed change.
 */
export const AGREED_EVIDENCE_DIR = null;

/**
 * Sepolia provider compatibility (ADR-RN-018 Amendment C1, P4 and P5), per provider: whether the
 * C6 read-only check recorded that it accepts {blockHash, requireCanonical: true} on the account
 * reads (`eip1898AccountReads`) and on eth_estimateGas (`estimateGasBlockHash`). null: not yet
 * recorded. Until both are recorded true for both providers, Sepolia preparation is BLOCKED before
 * any read: there is no reviewed alternative estimation strategy. Recording them is a reviewed
 * change, citing the C6 evidence.
 */
export const SEPOLIA_COMPATIBILITY = Object.freeze({
  'sepolia-publicnode': Object.freeze({ eip1898AccountReads: null, estimateGasBlockHash: null }),
  'sepolia-1rpc': Object.freeze({ eip1898AccountReads: null, estimateGasBlockHash: null }),
});

/** Refuses unless --evidence-dir is exactly the agreed directory. */
export function checkAgreedEvidenceDir(value, agreed = AGREED_EVIDENCE_DIR) {
  if (typeof agreed !== 'string') throw new PrepareEntryError(PrepareEntryCode.DIRECTORY_NOT_AGREED, 'no evidence directory is agreed');
  if (value !== agreed) throw new PrepareEntryError(PrepareEntryCode.DIRECTORY_NOT_AGREED, '--evidence-dir is not the agreed evidence directory');
}

/**
 * The Sepolia block, if any, as { reason, providerId }: null when both providers are recorded as
 * accepting the block-hash object on every pinned read.
 */
export function sepoliaCompatibilityBlock(providerIds, compatibility = SEPOLIA_COMPATIBILITY) {
  for (const id of providerIds) {
    const record = compatibility?.[id];
    if (record?.eip1898AccountReads !== true) return { reason: 'BLOCK_HASH_READ_REFUSED', providerId: id, recorded: record?.eip1898AccountReads === false };
    if (record?.estimateGasBlockHash !== true) return { reason: 'GAS_ESTIMATION_UNAVAILABLE', providerId: id, recorded: record?.estimateGasBlockHash === false };
  }
  return null;
}

/** Parses `argv` against exactly `flags` (each `--name value`, each exactly once, all required). */
export function parseArguments(argv, flags) {
  if (!Array.isArray(argv) || argv.length !== flags.length * 2) throw new PrepareEntryError(PrepareEntryCode.USAGE, `exactly ${flags.map((f) => `--${f} <value>`).join(' ')}`);
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = typeof argv[i] === 'string' && argv[i].startsWith('--') ? argv[i].slice(2) : null;
    const value = argv[i + 1];
    if (flag === null || !flags.includes(flag) || Object.hasOwn(out, flag)) throw new PrepareEntryError(PrepareEntryCode.USAGE, `unexpected argument ${JSON.stringify(argv[i])}`);
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) throw new PrepareEntryError(PrepareEntryCode.USAGE, `--${flag} needs a value`);
    out[flag] = value;
  }
  return out;
}

/** The --network value, refused unless it is one of PREPARE_NETWORKS. */
export function entryNetwork(value) {
  if (!PREPARE_NETWORKS.includes(value)) throw new PrepareEntryError(PrepareEntryCode.NETWORK_NOT_ALLOWED, String(value));
  return value;
}

/**
 * Checks an rnnet.rpc-endpoints.v1 document against `reviewed` and returns the run's providers in
 * the authorized order: every provider of the document must be reviewed (same network, URL and
 * operator), and the document must name exactly the two reviewed providers of `network`, which
 * must be the authorization's `providerIds`.
 */
export function reviewedProviders(endpoints, network, providerIds, reviewed = REVIEWED_PREPARATION_PROVIDERS) {
  let providers;
  try {
    providers = loadEndpointConfig(endpoints);
  } catch {
    throw new PrepareEntryError(PrepareEntryCode.ENDPOINTS_NOT_REVIEWED, 'not an rnnet.rpc-endpoints.v1 document');
  }
  for (const p of providers) {
    const known = reviewed.find((r) => r.id === p.id);
    if (!known || known.network !== p.network || known.url !== p.url || known.operator !== p.operator) throw new PrepareEntryError(PrepareEntryCode.ENDPOINTS_NOT_REVIEWED, p.id);
  }
  const wanted = reviewed.filter((r) => r.network === network).map((r) => r.id).sort().join(',');
  const named = providers.filter((p) => p.network === network).map((p) => p.id).sort().join(',');
  if (wanted !== named || wanted.split(',').length !== 2) throw new PrepareEntryError(PrepareEntryCode.ENDPOINTS_NOT_REVIEWED, `the providers of ${network}`);
  if ([...providerIds].sort().join(',') !== wanted) throw new PrepareEntryError(PrepareEntryCode.AUTHORIZATION, 'providerIds are not the reviewed providers of this network');
  return providerIds.map((id) => {
    const p = providers.find((x) => x.id === id);
    return Object.freeze({ id: p.id, network: p.network, url: p.url, operator: p.operator });
  });
}

/**
 * Reads a private file the founder names: an absolute path to a regular file (not a symbolic
 * link), owned by this user, mode 0600, at most `maxBytes`. Returns its text.
 */
export function readPrivateText(path, maxBytes = 65_536) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new PrepareEntryError(PrepareEntryCode.FILE, 'an absolute path is required');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new PrepareEntryError(PrepareEntryCode.FILE, `${path}: cannot be opened (missing, or a symbolic link)`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new PrepareEntryError(PrepareEntryCode.FILE, `${path}: not a regular file`);
    if ((stat.mode & 0o777) !== 0o600) throw new PrepareEntryError(PrepareEntryCode.FILE, `${path}: mode is not 0600`);
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new PrepareEntryError(PrepareEntryCode.FILE, `${path}: not owned by this user`);
    if (stat.size > maxBytes) throw new PrepareEntryError(PrepareEntryCode.FILE, `${path}: larger than ${maxBytes} bytes`);
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/**
 * The founder's approval of one run: the prompt shows every value the run is bound to, and the
 * answer must be exactly `<network> <last 16 hex digits of the authorization digest>`.
 * @param {(prompt: string) => Promise<string>} approve asks the founder; injected
 */
export async function requireApproval(approve, { network, digest, lines }) {
  if (typeof approve !== 'function') throw new PrepareEntryError(PrepareEntryCode.APPROVAL_REFUSED, 'no approval route');
  const expected = `${network} ${digest.slice(-16)}`;
  const prompt = [
    ...lines,
    `authorization digest: ${digest}`,
    `To approve this one read-only preparation run on ${network}, type: ${network} <last 16 hex digits of the authorization digest>`,
  ].join('\n');
  let answer;
  try {
    answer = await approve(prompt);
  } catch {
    throw new PrepareEntryError(PrepareEntryCode.APPROVAL_REFUSED, 'the approval prompt failed');
  }
  if (typeof answer !== 'string' || answer.replace(/\r?\n$/, '') !== expected) throw new PrepareEntryError(PrepareEntryCode.APPROVAL_REFUSED, 'the answer does not match');
}
