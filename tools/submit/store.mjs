// Private storage of the broadcaster (RN-NET-03B2-B3, ADR-RN-019 §5 and §7): the append-only
// submission log and the per-run evidence directory. Both live outside every repository.
//
// - A directory is used only if it is absolute, is its own real path (no symlink), is a
//   directory owned by this user with mode 0700, and is not inside a git worktree.
// - The log is one file per entry, named by its index (000000.json, 000001.json, ...), each its
//   canonical JSON and a newline, created with `wx` and mode 0600. Entries are never changed or
//   deleted; this module has no code that could.
// - An entry is written at index N only after the decision was taken on entries 0..N-1; if
//   another run wrote N first, `wx` fails and the run is refused (RNBC_LOG_CONFLICT).
import { Buffer } from 'node:buffer';
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, writeSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { BroadcastCode, BroadcastError } from '../../packages/chain-submit/src/index.mjs';

const ENTRY_NAME = /^[0-9]{6}\.json$/;
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

/** Creates `path` with `wx` and mode 0600 and writes `text` durably; throws on any failure. */
export function writeNewFile(path, text) {
  const fd = openSync(path, 'wx', 0o600);
  try {
    const bytes = Buffer.from(text, 'utf8');
    let written = 0;
    while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
    if ((fstatSync(fd).mode & 0o777) !== 0o600) throw new Error('file mode is not 0600');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
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
  if ((lstatSync(path).mode & 0o777) !== 0o700) throw new BroadcastError(BroadcastCode.EVIDENCE_DIRECTORY, 'run directory mode is not 0700');
  return path;
}
