// What the C6 entry point checks before any request, and how it keeps its private evidence
// (RN-NET-03B2-C6-LIVE): the exact flags, the reviewed endpoint file (pinned by digest), the
// manifest digest, the authorization's binding to the four reviewed providers and the 22-request
// budget, its expiry, the agreed evidence directory, private-file reads, the founder's typed
// approval and the write-once run directory.
//
// Self-contained on purpose: it shares no file with tools/prepare/ or tools/submit/, so the C6 run
// never reaches preparation, the write path, the signer or the key tool, even through a helper
// (guard: compat-live-reaches-write-or-key).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { canonicalBytes, canonicalize } from '../../packages/canonical/src/index.mjs';
import { C6_BUDGET, C6_PROVIDERS, C6_TOTAL_REQUESTS, manifestBytes } from '../compat/manifest.mjs';

/** Refusal codes of the C6 entry point (RNCL_*). */
export const CompatEntryCode = Object.freeze({
  USAGE: 'RNCL_USAGE',
  LIVE_DISABLED: 'RNCL_LIVE_DISABLED',
  FILE: 'RNCL_FILE',
  ENDPOINTS_NOT_REVIEWED: 'RNCL_ENDPOINTS_NOT_REVIEWED',
  MANIFEST_MISMATCH: 'RNCL_MANIFEST_MISMATCH',
  AUTHORIZATION: 'RNCL_AUTHORIZATION',
  AUTHORIZATION_EXPIRED: 'RNCL_AUTHORIZATION_EXPIRED',
  AUTHORIZATION_USED: 'RNCL_AUTHORIZATION_USED',
  APPROVAL_REFUSED: 'RNCL_APPROVAL_REFUSED',
  DIRECTORY_NOT_AGREED: 'RNCL_DIRECTORY_NOT_AGREED',
  EVIDENCE: 'RNCL_EVIDENCE',
  NOT_REPRODUCED: 'RNCL_NOT_REPRODUCED',
});

export class CompatEntryError extends Error {
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'CompatEntryError';
    this.code = code;
  }
}
const refuse = (code, detail) => {
  throw new CompatEntryError(code, detail);
};

/**
 * The reviewed C6 manifest: SHA-256 of manifestBytes() (docs/genesis/rn-net-03b2c6-provider-compatibility.md §0).
 * The entry point recomputes it from the code and refuses unless code, this constant and the
 * authorization all name the same value.
 */
export const C6_MANIFEST_SHA256 = 'sha256:2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037';
/**
 * The reviewed endpoint file: SHA-256 of the canonical bytes of config/rpc-endpoints.json (ADR-RN-013).
 * Any other provider list, URL, operator or note is refused before anything else is read.
 */
export const REVIEWED_ENDPOINTS_SHA256 = 'sha256:14ce613018c9f59f4c6a601e0333d979f3d3f46d84dfe8290e1445aeb4361246';
/**
 * The agreed private evidence directory (H11: a new directory outside every repository). null: not
 * agreed in RN-NET-03B2-C6-LIVE, so no run can pass; agreeing it is part of the enabling change.
 */
export const AGREED_EVIDENCE_DIR = null;
/** An authorization may be written at most this long before it is void (one sitting). */
export const MAX_AUTHORIZATION_AHEAD_SECONDS = 3600;
export const COMPAT_FLAGS = Object.freeze(['authorization', 'endpoints', 'evidence-dir']);

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** The manifest digest the code computes now. */
export const computedManifestSha256 = () => sha256(manifestBytes());

/** Parses `argv` against exactly `flags` (each `--name value`, each exactly once, all required). */
export function parseArguments(argv, flags = COMPAT_FLAGS) {
  if (!Array.isArray(argv) || argv.length !== flags.length * 2) refuse(CompatEntryCode.USAGE, `exactly ${flags.map((f) => `--${f} <value>`).join(' ')}`);
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = typeof argv[i] === 'string' && argv[i].startsWith('--') ? argv[i].slice(2) : null;
    const value = argv[i + 1];
    if (flag === null || !flags.includes(flag) || Object.hasOwn(out, flag)) refuse(CompatEntryCode.USAGE, `unexpected argument ${JSON.stringify(argv[i])}`);
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) refuse(CompatEntryCode.USAGE, `--${flag} needs a value`);
    out[flag] = value;
  }
  return out;
}

/** Refuses unless --evidence-dir is exactly the agreed directory. */
export function checkAgreedEvidenceDir(value, agreed = AGREED_EVIDENCE_DIR) {
  if (typeof agreed !== 'string') refuse(CompatEntryCode.DIRECTORY_NOT_AGREED, 'no evidence directory is agreed');
  if (value !== agreed) refuse(CompatEntryCode.DIRECTORY_NOT_AGREED, '--evidence-dir is not the agreed evidence directory');
}

/**
 * Reads a file the founder names: an absolute path to a regular file (not a symbolic link), at
 * most `maxBytes`; when `privateTo` is given, also mode 0600 and (unless it is null) owned by that uid.
 * Returns its text.
 */
export function readFileText(path, { maxBytes = 65_536, privateTo = undefined } = {}) {
  if (typeof path !== 'string' || !isAbsolute(path)) refuse(CompatEntryCode.FILE, 'an absolute path is required');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    refuse(CompatEntryCode.FILE, `${path}: cannot be opened (missing, or a symbolic link)`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) refuse(CompatEntryCode.FILE, `${path}: not a regular file`);
    if (stat.size > maxBytes) refuse(CompatEntryCode.FILE, `${path}: larger than ${maxBytes} bytes`);
    if (privateTo !== undefined) {
      if ((stat.mode & 0o777) !== 0o600) refuse(CompatEntryCode.FILE, `${path}: mode is not 0600`);
      if (privateTo !== null && stat.uid !== privateTo) refuse(CompatEntryCode.FILE, `${path}: not owned by this user`);
    }
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/** The parsed endpoint file, refused unless its canonical bytes are exactly the reviewed file's. */
export function reviewedEndpoints(text) {
  let endpoints;
  try {
    endpoints = JSON.parse(text);
    if (sha256(canonicalBytes(endpoints)) === REVIEWED_ENDPOINTS_SHA256) return endpoints;
  } catch {
    // refused below
  }
  return refuse(CompatEntryCode.ENDPOINTS_NOT_REVIEWED, 'the endpoint file is not the reviewed config/rpc-endpoints.json');
}

/**
 * Checks that the authorization binds exactly this run: the manifest digest (as the code computes
 * it, and as reviewed), the four reviewed providers at their reviewed URLs with their per-provider
 * budget, in manifest order, and 22 requests in total.
 */
export function checkBinding(a, computed = computedManifestSha256()) {
  if (computed !== C6_MANIFEST_SHA256) refuse(CompatEntryCode.MANIFEST_MISMATCH, `the code's manifest is ${computed}, not the reviewed ${C6_MANIFEST_SHA256}`);
  if (a.manifestSha256 !== C6_MANIFEST_SHA256) refuse(CompatEntryCode.MANIFEST_MISMATCH, `the authorization names manifest ${a.manifestSha256}`);
  const expected = C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url }));
  if (canonicalize(a.providers) !== canonicalize(expected)) refuse(CompatEntryCode.AUTHORIZATION, 'providers are not the four reviewed providers, at their reviewed URLs, with their manifest budget, in manifest order');
  if (a.requestBudget !== C6_TOTAL_REQUESTS) refuse(CompatEntryCode.AUTHORIZATION, `requestBudget must be ${C6_TOTAL_REQUESTS}`);
}

/**
 * The founder's approval of one run: the prompt shows every value the run is bound to, and the
 * answer must be exactly `c6 <last 16 hex digits of the authorization digest>`.
 * @param {(prompt: string) => Promise<string>} approve asks the founder; injected
 */
export async function requireApproval(approve, { digest, lines }) {
  if (typeof approve !== 'function') refuse(CompatEntryCode.APPROVAL_REFUSED, 'no approval route');
  const expected = `c6 ${digest.slice(-16)}`;
  const prompt = [...lines, `authorization digest: ${digest}`, 'To approve this one read-only C6 run, type: c6 <last 16 hex digits of the authorization digest>'].join('\n');
  let answer;
  try {
    answer = await approve(prompt);
  } catch {
    refuse(CompatEntryCode.APPROVAL_REFUSED, 'the approval prompt failed');
  }
  if (typeof answer !== 'string' || answer.replace(/\r?\n$/, '') !== expected) refuse(CompatEntryCode.APPROVAL_REFUSED, 'the answer does not match');
}

// --- Private, durable, write-once evidence ------------------------------------------------------

const evidenceError = (detail) => new CompatEntryError(CompatEntryCode.EVIDENCE, detail);

function fsyncDirectory(dir) {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Refuses unless `dir` is a private directory of this user (mode 0700, not a symbolic link). */
export function checkEvidenceDirectory(dir, uid) {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch {
    throw evidenceError(`${dir} does not exist`);
  }
  if (!stat.isDirectory()) throw evidenceError(`${dir} is not a directory (or is a symbolic link)`);
  if ((stat.mode & 0o777) !== 0o700) throw evidenceError(`${dir}: mode is not 0700`);
  if (uid !== null && uid !== undefined && stat.uid !== uid) throw evidenceError(`${dir}: not owned by this user`);
}

/** Creates <evidenceDir>/<authorizationId>/ (0700); RNCL_AUTHORIZATION_USED if it exists. */
export function createRunDirectory(evidenceDir, authorizationId) {
  if (!/^[a-z0-9-]{1,64}$/.test(authorizationId)) throw new TypeError('authorization id');
  const path = join(evidenceDir, authorizationId);
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') refuse(CompatEntryCode.AUTHORIZATION_USED, `${authorizationId} already has a run in the evidence directory`);
    throw error;
  }
  fsyncDirectory(evidenceDir);
  if ((lstatSync(path).mode & 0o777) !== 0o700) throw evidenceError('run directory mode is not 0700');
  return path;
}

/** Writes `content` (text, or exact bytes) to the new file `name` in `dir`: exclusive, mode 0600, fsync of file and directory. */
export function writeNewFile(dir, name, content) {
  if (!/^[a-z0-9-]{1,40}\.(?:json|bin)$/.test(name)) throw new TypeError('evidence file name');
  const fd = openSync(join(dir, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const bytes = content instanceof Uint8Array ? Buffer.from(content) : Buffer.from(content, 'utf8');
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
    if ((fstatSync(fd).mode & 0o777) !== 0o600) throw evidenceError(`${name}: file mode is not 0600`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(dir);
}

/** The canonical text of a stored document, with one final newline. */
export const storedText = (value) => `${canonicalize(value)}\n`;
