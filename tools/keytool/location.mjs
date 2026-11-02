// Where key files, the sign log and signed output may live (ADR-RN-017 Amendment C1, K2 and K4).
//
// A private directory is accepted only if, at the moment of the check:
//   - its path is absolute and normalized (no ".", "..", repeated or trailing "/") and is its own
//     real path, so no component is a symbolic link;
//   - it is not /mnt or under it (the Windows drives WSL mounts, where 0600 is not enforced);
//   - neither it nor any ancestor holds ".git" (a repository or worktree) or looks like a bare
//     repository (HEAD, objects/ and refs/);
//   - statfs reports ext2/3/4 (magic 0xEF53), which refuses drvfs, 9p, tmpfs and network mounts;
//   - it is a directory owned by this user with mode exactly 0700.
// The checks are repeated before every read and write. They do not defend against another
// process of the same user changing the directory between checks; the operating procedure (no
// agent session during gates B and D) is the control for that.
import { closeSync, constants, fsyncSync, lstatSync, mkdirSync, openSync, realpathSync, statfsSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize } from 'node:path';
import { KeyToolCode, refuse } from './errors.mjs';

export const EXT4_MAGIC = 0xef53;

/** Production file-system facts; tests replace statfs and getuid. */
export const SYSTEM = Object.freeze({
  statfs: (path) => statfsSync(path),
  getuid: () => process.getuid(),
});

const fail = (what, why) => refuse(KeyToolCode.LOCATION, `${what}: ${why}`);

function checkPathForm(dir, what) {
  if (typeof dir !== 'string' || !isAbsolute(dir)) fail(what, 'not an absolute path');
  if (dir === '/' || normalize(dir) !== dir || dir.endsWith('/') || dir.includes('\0')) fail(what, 'not a normalized path');
  if (dir === '/mnt' || dir.startsWith('/mnt/')) fail(what, 'under /mnt (a Windows drive): use the WSL ext4 file system');
}

function checkNotInRepository(dir, what) {
  for (let at = dir; ; at = dirname(at)) {
    if (lstatOrNull(join(at, '.git')) !== null) fail(what, `inside a git repository or worktree (${at})`);
    if (lstatOrNull(join(at, 'HEAD'))?.isFile() && lstatOrNull(join(at, 'objects'))?.isDirectory() && lstatOrNull(join(at, 'refs'))?.isDirectory()) fail(what, `inside a bare git repository (${at})`);
    if (dirname(at) === at) break;
  }
}

// Only "no such name" means absent; any other error (EACCES, for example) is a refusal, so an
// unreadable ancestor cannot hide a repository.
function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return null;
    return fail(path, `cannot be inspected (${error?.code ?? 'error'})`);
  }
}

function checkFileSystem(dir, what, system) {
  let type;
  try {
    type = system.statfs(dir).type;
  } catch {
    fail(what, 'statfs failed');
  }
  if (Number(type) !== EXT4_MAGIC) fail(what, `not on ext4 (statfs type 0x${Number(type).toString(16)})`);
}

/** Everything except the mode and owner: used for the parent of a directory about to be made. */
function checkPlace(dir, what, system) {
  checkPathForm(dir, what);
  let real;
  try {
    real = realpathSync(dir);
  } catch {
    fail(what, 'does not exist');
  }
  if (real !== dir) fail(what, 'not its own real path (a symbolic link in the path)');
  checkNotInRepository(dir, what);
  checkFileSystem(dir, what, system);
}

/** Throws RNKEY_LOCATION unless `dir` is a private directory as described above. */
export function checkPrivateDirectory(dir, what, system = SYSTEM) {
  checkPlace(dir, what, system);
  const stat = lstatSync(dir);
  if (!stat.isDirectory()) fail(what, 'not a directory');
  if (stat.uid !== system.getuid()) fail(what, 'not owned by this user');
  if ((stat.mode & 0o777) !== 0o700) fail(what, `mode is ${(stat.mode & 0o777).toString(8).padStart(4, '0')}, not 0700`);
}

/** fsyncs a directory, so a new or removed name in it survives a crash. */
export function fsyncDirectory(dir) {
  const fd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Makes `dir` (one level only, mode 0700) if it does not exist, after checking its parent, then
 * checks it as a private directory. An existing directory is only checked, never changed.
 */
export function ensurePrivateDirectory(dir, what, system = SYSTEM) {
  checkPathForm(dir, what);
  if (lstatOrNull(dir) === null) {
    const parent = dirname(dir);
    checkPlace(parent, `${what} (parent)`, system);
    mkdirSync(dir, { mode: 0o700 });
    fsyncDirectory(parent);
  }
  checkPrivateDirectory(dir, what, system);
}

/** Two private directories must be distinct and neither may contain the other. */
export function checkSeparate(a, aWhat, b, bWhat) {
  if (a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`)) fail(`${aWhat} and ${bWhat}`, 'must be separate directories, neither inside the other');
}
