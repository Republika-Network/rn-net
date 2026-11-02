// Private storage of the broadcaster (RN-NET-03B2-B3, ADR-RN-019 §5 and §7): the append-only
// submission log and the per-run evidence directory. Both live outside every repository.
//
// - A directory is used only if it is absolute, is its own real path (no symlink), is a
//   directory owned by this user with mode 0700, and is not inside a git worktree.
// - The log is one file per entry, named by its index (000000.json, 000001.json, ...), each its
//   canonical JSON and a newline, mode 0600. Entries are never changed or deleted; the only name
//   this file ever removes is its own temporary name (below).
// - An entry is written at index N only after the decision was taken on entries 0..N-1; if
//   another run wrote N first, the run is refused (RNBC_LOG_CONFLICT).
//
// Durable, exclusive creation (RN-NET-03B2-C2, B3 review N4), the same steps as the key tool's
// sign log (tools/keytool/files.mjs):
//   1. the bytes go to `.NAME.tmp` in the same directory, opened O_CREAT|O_EXCL|O_NOFOLLOW, mode
//      0600, then fsync'ed and closed;
//   2. link(temporary, final): atomic, and fails if the final name exists, so nothing is replaced;
//   3. the temporary name is removed and the directory itself is fsync'ed.
// After step 3 returns, the entry survives a power loss. ATTEMPTING is written this way before
// the transport is called, so a crash can never leave a write without its ATTEMPTING entry.
// After a crash, the final name either does not exist or holds the complete content; a leftover
// temporary name in the log refuses every later run (RNBC_LOG_CONFLICT) until the founder has
// looked at it: it is never reused, removed or skipped by this code.
import { Buffer } from 'node:buffer';
import { closeSync, constants, existsSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, unlinkSync, writeSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { BroadcastCode, BroadcastError } from '../../packages/chain-submit/src/index.mjs';

const ENTRY_NAME = /^[0-9]{6}\.json$/;
const TEMPORARY_NAME = /^\..+\.tmp$/;
const MAX_ENTRIES = 999_999;
const MAX_ENTRY_BYTES = 16_384;

/** Throws `code` unless `dir` is a private directory as described above. */
export function checkPrivateDirectory(dir, code) {
  const fail = (why) => {
    throw new BroadcastError(code, why);
  };
  if (typeof dir !== 'string' || !isAbsolute(dir)) fail('not an absolute path');
  let real;
  let stat;
  try {
    real = realpathSync(dir);
    stat = lstatSync(dir);
  } catch {
    fail('does not exist');
  }
  if (real !== dir) fail('not its own real path');
  if (!stat.isDirectory()) fail('not a directory');
  if ((stat.mode & 0o777) !== 0o700) fail('mode is not 0700');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) fail('not owned by this user');
  for (let at = dir; ; at = dirname(at)) {
    if (existsSync(join(at, '.git'))) fail('inside a git worktree');
    if (dirname(at) === at) break;
  }
}

/** Canonical JSON text and a newline: the exact bytes of a stored entry or record. */
export const storedText = (value) => `${canonicalize(value)}\n`;

/** Reads the whole log in index order; throws RNBC_LOG_INVALID if anything is out of place. */
export function readLog(dir) {
  const names = readdirSync(dir).sort();
  const temporary = names.filter((name) => TEMPORARY_NAME.test(name));
  if (temporary.length > 0) throw new BroadcastError(BroadcastCode.LOG_CONFLICT, `${temporary.join(', ')}: an entry is being written, or a run stopped part-way`);
  if (names.length > MAX_ENTRIES) throw new BroadcastError(BroadcastCode.LOG_INVALID, 'too many entries');
  return names.map((name, index) => {
    if (!ENTRY_NAME.test(name) || Number(name.slice(0, 6)) !== index) throw new BroadcastError(BroadcastCode.LOG_INVALID, `unexpected file ${JSON.stringify(name)}`);
    const path = join(dir, name);
    const stat = lstatSync(path);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.size > MAX_ENTRY_BYTES) throw new BroadcastError(BroadcastCode.LOG_INVALID, `${name}: not a private file`);
    const text = readFileSync(path, 'utf8');
    let entry;
    try {
      entry = parse(text.slice(0, -1));
    } catch {
      throw new BroadcastError(BroadcastCode.LOG_INVALID, `${name}: not canonical JSON`);
    }
    if (!text.endsWith('\n') || storedText(entry) !== text) throw new BroadcastError(BroadcastCode.LOG_INVALID, `${name}: not canonical JSON`);
    return entry;
  });
}

/** fsync()s a directory, so that a name created or removed in it survives a power loss. */
export function fsyncDirectory(dir) {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Creates `path` with `text` durably and exclusively (steps 1 to 3 above), mode 0600. Throws an
 * error with code EEXIST if `path` or its temporary name exists; any other failure is rethrown.
 */
export function writeNewFile(path, text) {
  const dir = dirname(path);
  const temporaryPath = join(dir, `.${basename(path)}.tmp`);
  if (existsSync(path)) throw Object.assign(new Error(`${basename(path)} already exists`), { code: 'EEXIST' });
  const fd = openSync(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    try {
      const bytes = Buffer.from(text, 'utf8');
      let written = 0;
      while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
      if ((fstatSync(fd).mode & 0o777) !== 0o600) throw new Error('file mode is not 0600');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    linkSync(temporaryPath, path);
  } finally {
    // The temporary name is this call's own (O_EXCL); it is removed whether or not the link was made.
    unlinkSync(temporaryPath);
    fsyncDirectory(dir);
  }
}

/** Appends `entry` at its index; RNBC_LOG_CONFLICT if that index already exists. */
export function appendEntry(dir, entry) {
  try {
    writeNewFile(join(dir, `${String(entry.index).padStart(6, '0')}.json`), storedText(entry));
  } catch (error) {
    if (error?.code === 'EEXIST') throw new BroadcastError(BroadcastCode.LOG_CONFLICT, `entry ${entry.index} already exists`);
    throw error;
  }
}

/** Creates a new run directory (mode 0700) under the evidence directory; refuses an existing one. */
export function createRunDirectory(evidenceDir, name) {
  if (!/^[a-z0-9-]{1,64}$/.test(name)) throw new TypeError('run directory name');
  const path = join(evidenceDir, name);
  mkdirSync(path, { mode: 0o700 });
  fsyncDirectory(evidenceDir);
  if ((lstatSync(path).mode & 0o777) !== 0o700) throw new BroadcastError(BroadcastCode.EVIDENCE_DIRECTORY, 'run directory mode is not 0700');
  return path;
}
