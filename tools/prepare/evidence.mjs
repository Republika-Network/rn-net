// Private evidence of one preparation run (RN-NET-03B2-C3; ADR-RN-019 §7, ADR-RN-018 §6).
//
// <evidence-dir> is the agreed directory: a private directory (mode 0700, owned by this user, not a
// symbolic link) outside every repository. Each run creates <evidence-dir>/<authorizationId>/
// (mode 0700) BEFORE its first request: mkdir fails if it exists, so one authorization runs at most
// once there, whatever its outcome. The run then writes, exclusively and durably (mode 0600,
// fsync of the file and the directory):
//   - evidence.json: rnnet.preparation-evidence.v1, every exchange in full and the outcome;
//   - intent.json: the prepared intent's canonical JSON, only when an intent was prepared. It is
//     the --intent input of the key tool's `sign` (gate D, a separate authorization).
import { Buffer } from 'node:buffer';
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { PrepareEntryCode, PrepareEntryError } from './entry.mjs';

export const PREPARATION_EVIDENCE_FORMAT = 'rnnet.preparation-evidence.v1';

const fail = (detail) => new PrepareEntryError(PrepareEntryCode.EVIDENCE, detail);

function fsyncDirectory(dir) {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Refuses unless `dir` is a private directory of this user (mode 0700, not a symbolic link). */
export function checkEvidenceDirectory(dir, getuid) {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch {
    throw fail(`${dir} does not exist`);
  }
  if (!stat.isDirectory()) throw fail(`${dir} is not a directory (or is a symbolic link)`);
  if ((stat.mode & 0o777) !== 0o700) throw fail(`${dir}: mode is not 0700`);
  if (typeof getuid === 'function' && stat.uid !== getuid()) throw fail(`${dir}: not owned by this user`);
}

/** Creates the run's directory; RNPL_AUTHORIZATION_USED if a run of this authorization exists. */
export function createRunDirectory(evidenceDir, authorizationId) {
  if (!/^[a-z0-9-]{1,64}$/.test(authorizationId)) throw new TypeError('authorization id');
  const path = join(evidenceDir, authorizationId);
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') throw new PrepareEntryError(PrepareEntryCode.AUTHORIZATION_USED, `${authorizationId} already has a run in the evidence directory`);
    throw error;
  }
  fsyncDirectory(evidenceDir);
  if ((lstatSync(path).mode & 0o777) !== 0o700) throw fail('run directory mode is not 0700');
  return path;
}

/** Writes `content` (text, or exact bytes) to the new file `name` in `dir`, exclusively and durably, mode 0600. */
export function writeNewFile(dir, name, content) {
  const fd = openSync(join(dir, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    const bytes = content instanceof Uint8Array ? Buffer.from(content) : Buffer.from(content, 'utf8');
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
    if ((fstatSync(fd).mode & 0o777) !== 0o600) throw fail(`${name}: file mode is not 0600`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(dir);
}

/** The canonical text of a stored document, with one final newline. */
export const storedText = (value) => `${canonicalize(value)}\n`;
