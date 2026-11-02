// What the two controlled entry points share (RN-NET-03B2-C2; ADR-RN-019 Amendment C1, E1):
// argument parsing with an exact flag list, the reviewed provider allowlist, private-file reads,
// and the founder's typed approval of one network and one authorization.
//
// No network, no transport, no key: this file only checks text and files the founder names.
import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { loadEndpointConfig } from '../../packages/chain-readonly/src/index.mjs';
import { SubmitNetwork } from '../../packages/chain-submit/src/index.mjs';

/** Refusal codes of the entry points (outside chain-submit: no run was started). */
export const EntryCode = Object.freeze({
  USAGE: 'RNSA_USAGE',
  LIVE_DISABLED: 'RNSA_LIVE_DISABLED',
  NETWORK_NOT_ALLOWED: 'RNSA_NETWORK_NOT_ALLOWED',
  NETWORK_MISMATCH: 'RNSA_NETWORK_MISMATCH',
  ENDPOINTS_NOT_REVIEWED: 'RNSA_ENDPOINTS_NOT_REVIEWED',
  FILE: 'RNSA_FILE',
  AUTHORIZATION: 'RNSA_AUTHORIZATION',
  APPROVAL_REFUSED: 'RNSA_APPROVAL_REFUSED',
  DIRECTORY_NOT_AGREED: 'RNSA_DIRECTORY_NOT_AGREED',
});

export class EntryError extends Error {
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'EntryError';
    this.code = code;
  }
}

/** The only networks either entry point accepts. Never a mainnet. */
export const ENTRY_NETWORKS = Object.freeze([SubmitNetwork.XRPL_TESTNET, SubmitNetwork.SEPOLIA]);

/**
 * The reviewed providers (config/rpc-endpoints.json, ADR-RN-013), pinned here by id, network and
 * URL. A live run refuses an endpoint file that differs in any of them; a test pins this list to
 * the committed configuration.
 */
export const REVIEWED_PROVIDERS = Object.freeze([
  Object.freeze({ id: 'xrpl-testnet-ripple', network: SubmitNetwork.XRPL_TESTNET, url: 'https://s.altnet.rippletest.net:51234/' }),
  Object.freeze({ id: 'xrpl-testnet-xrpl-labs', network: SubmitNetwork.XRPL_TESTNET, url: 'https://testnet.xrpl-labs.com/' }),
  Object.freeze({ id: 'sepolia-publicnode', network: SubmitNetwork.SEPOLIA, url: 'https://ethereum-sepolia-rpc.publicnode.com/' }),
  Object.freeze({ id: 'sepolia-1rpc', network: SubmitNetwork.SEPOLIA, url: 'https://public.1rpc.io/sepolia' }),
]);

/**
 * The agreed submission-log and evidence directories (ADR-RN-019 §5: "a gate-E run starts by
 * checking that its directory is the agreed one"). The log is what makes an authorization
 * single-use, so a run may never choose another one: the same authorization against a fresh log
 * would be accepted again (C2 review F1). Not agreed in RN-NET-03B2-C2, so both are null and no run
 * can pass; agreeing them is a gate-E prerequisite and a reviewed change here.
 */
export const AGREED_DIRECTORIES = Object.freeze({ logDir: null, evidenceDir: null });

/** Refuses unless --log-dir and --evidence-dir are exactly the agreed directories. */
export function checkAgreedDirectories(args, agreed = AGREED_DIRECTORIES) {
  if (agreed === null || typeof agreed !== 'object' || typeof agreed.logDir !== 'string' || typeof agreed.evidenceDir !== 'string') {
    throw new EntryError(EntryCode.DIRECTORY_NOT_AGREED, 'no log and evidence directories are agreed');
  }
  if (args['log-dir'] !== agreed.logDir) throw new EntryError(EntryCode.DIRECTORY_NOT_AGREED, '--log-dir is not the agreed log directory');
  if (args['evidence-dir'] !== agreed.evidenceDir) throw new EntryError(EntryCode.DIRECTORY_NOT_AGREED, '--evidence-dir is not the agreed evidence directory');
}

/**
 * Parses `argv` against exactly `flags` (each `--name value`, each exactly once, all required).
 * There is no other option: no retry, fee, field, provider-override or force flag exists.
 */
export function parseArguments(argv, flags) {
  if (!Array.isArray(argv) || argv.length !== flags.length * 2) throw new EntryError(EntryCode.USAGE, `exactly ${flags.map((f) => `--${f} <value>`).join(' ')}`);
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = typeof argv[i] === 'string' && argv[i].startsWith('--') ? argv[i].slice(2) : null;
    const value = argv[i + 1];
    if (flag === null || !flags.includes(flag) || Object.hasOwn(out, flag)) throw new EntryError(EntryCode.USAGE, `unexpected argument ${JSON.stringify(argv[i])}`);
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) throw new EntryError(EntryCode.USAGE, `--${flag} needs a value`);
    out[flag] = value;
  }
  return out;
}

/** The --network value, refused unless it is one of ENTRY_NETWORKS. */
export function entryNetwork(value) {
  if (!ENTRY_NETWORKS.includes(value)) throw new EntryError(EntryCode.NETWORK_NOT_ALLOWED, String(value));
  return value;
}

/**
 * Checks an rnnet.rpc-endpoints.v1 document against `reviewed` and returns it. Every provider of
 * the document must be a reviewed one with the same network and URL, and the document must name
 * exactly the two reviewed providers of `network`.
 */
export function reviewedEndpoints(endpoints, network, reviewed = REVIEWED_PROVIDERS) {
  let providers;
  try {
    providers = loadEndpointConfig(endpoints);
  } catch {
    throw new EntryError(EntryCode.ENDPOINTS_NOT_REVIEWED, 'not an rnnet.rpc-endpoints.v1 document');
  }
  for (const p of providers) {
    const known = reviewed.find((r) => r.id === p.id);
    if (!known || known.network !== p.network || known.url !== p.url) throw new EntryError(EntryCode.ENDPOINTS_NOT_REVIEWED, p.id);
  }
  const wanted = reviewed.filter((r) => r.network === network).map((r) => r.id).sort().join(',');
  const named = providers.filter((p) => p.network === network).map((p) => p.id).sort().join(',');
  if (wanted !== named || wanted.split(',').length !== 2) throw new EntryError(EntryCode.ENDPOINTS_NOT_REVIEWED, `the providers of ${network}`);
  return endpoints;
}

/**
 * Reads a private file the founder names: an absolute path to a regular file (not a symbolic
 * link), owned by this user, mode 0600, at most `maxBytes`. Returns its text.
 */
export function readPrivateText(path, maxBytes = 65_536) {
  if (typeof path !== 'string' || !isAbsolute(path)) throw new EntryError(EntryCode.FILE, 'an absolute path is required');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new EntryError(EntryCode.FILE, `${path}: cannot be opened (missing, or a symbolic link)`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new EntryError(EntryCode.FILE, `${path}: not a regular file`);
    if ((stat.mode & 0o777) !== 0o600) throw new EntryError(EntryCode.FILE, `${path}: mode is not 0600`);
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new EntryError(EntryCode.FILE, `${path}: not owned by this user`);
    if (stat.size > maxBytes) throw new EntryError(EntryCode.FILE, `${path}: larger than ${maxBytes} bytes`);
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/**
 * The founder's approval of one run: the prompt shows every value the run is bound to, and the
 * answer must be exactly `<network> <last 16 hex digits of the authorization digest>`. Typing
 * the network makes each network's approval separate; the digest suffix makes each submission's
 * approval separate (every authorization has its own digest). Anything else refuses the run
 * before it starts, so nothing is consumed.
 * @param {(prompt: string) => Promise<string>} approve asks the founder; injected
 */
export async function requireApproval(approve, { network, digest, lines }) {
  if (typeof approve !== 'function') throw new EntryError(EntryCode.APPROVAL_REFUSED, 'no approval route');
  const expected = `${network} ${digest.slice(-16)}`;
  const prompt = [
    ...lines,
    `authorization digest: ${digest}`,
    `To approve this one run on ${network}, type: ${network} <last 16 hex digits of the authorization digest>`,
  ].join('\n');
  let answer;
  try {
    answer = await approve(prompt);
  } catch {
    throw new EntryError(EntryCode.APPROVAL_REFUSED, 'the approval prompt failed');
  }
  if (typeof answer !== 'string' || answer.replace(/\r?\n$/, '') !== expected) throw new EntryError(EntryCode.APPROVAL_REFUSED, 'the answer does not match');
}
