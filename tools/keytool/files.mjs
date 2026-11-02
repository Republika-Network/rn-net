// Durable, exclusive file creation and safe reads in a private directory (RN-NET-03B2-C4).
//
// Creation (never an overwrite):
//   1. the content is written to a temporary name in the same directory, opened with
//      O_CREAT | O_EXCL | O_NOFOLLOW and mode 0600, then fsync'ed and closed;
//   2. link(temporary, final): fails if the final name exists, so nothing is ever replaced;
//   3. the temporary name is removed and the directory fsync'ed.
// Crash recovery: after a crash, the final name either does not exist (step 2 not reached) or
// holds the complete, fsync'ed content. A leftover temporary name is never reused or removed by
// the tool: the next run refuses (RNKEY_PARTIAL_FILE / RNKEY_SIGNLOG_INCOMPLETE) and says which
// case it is, and the founder decides (see tools/keytool/README.md).
import { Buffer } from 'node:buffer';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { KeyToolCode, KeyToolError, refuse } from './errors.mjs';
import { fsyncDirectory } from './location.mjs';

/** lstat, or null if the name does not exist. */
export function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * Creates `dir/name` with `bytes` as described above. Throws `existsCode` if `name` exists and
 * `partialCode` if `temporary` exists; any other failure is rethrown.
 */
export function createDurably(dir, name, temporary, bytes, { existsCode, partialCode }) {
  const finalPath = join(dir, name);
  const temporaryPath = join(dir, temporary);
  if (lstatOrNull(finalPath) !== null) refuse(existsCode, `${name} already exists`);
  let fd;
  try {
    fd = openSync(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') refuse(partialCode, `${temporary} exists: an earlier run stopped part-way, or another run is writing`);
    throw error;
  }
  let linked = false;
  try {
    try {
      let written = 0;
      while (written < bytes.length) written += writeSync(fd, bytes, written, bytes.length - written);
      if ((fstatSync(fd).mode & 0o777) !== 0o600) throw new KeyToolError(KeyToolCode.LOCATION, 'the new file is not mode 0600');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      linkSync(temporaryPath, finalPath);
      linked = true;
    } catch (error) {
      if (error?.code === 'EEXIST') refuse(existsCode, `${name} appeared while it was being written`);
      throw error;
    }
  } finally {
    // The temporary name is this run's own (O_EXCL); it is removed whether or not the link was made.
    unlinkSync(temporaryPath);
    fsyncDirectory(dir);
  }
  return linked;
}

/**
 * Reads a private regular file (not a symbolic link, owned by this user, mode 0600, at most
 * `maxBytes`). Returns its bytes.
 */
export function readPrivateFile(path, maxBytes, getuid, code = KeyToolCode.FILE_INVALID) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error?.code === 'ELOOP') refuse(code, `${path} is a symbolic link`);
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) refuse(code, `${path} is not a regular file`);
    if (stat.uid !== getuid()) refuse(code, `${path} is not owned by this user`);
    if ((stat.mode & 0o777) !== 0o600) refuse(code, `${path} is not mode 0600`);
    if (stat.size > maxBytes) refuse(code, `${path} is larger than ${maxBytes} bytes`);
    const bytes = Buffer.alloc(stat.size);
    let read = 0;
    while (read < stat.size) {
      const n = readSync(fd, bytes, read, stat.size - read, read);
      if (n === 0) break;
      read += n;
    }
    if (read !== stat.size || readSync(fd, Buffer.alloc(1), 0, 1, read) !== 0) refuse(code, `${path} changed while it was read`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}

/** Reads a public input file (an intent or a status record): regular, not a link, bounded. */
export function readInputFile(path, maxBytes) {
  if (typeof path !== 'string' || !path.startsWith('/')) refuse(KeyToolCode.USAGE, 'input paths must be absolute');
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    refuse(KeyToolCode.FILE_INVALID, `${path}: ${error?.code ?? 'cannot be opened'}`);
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) refuse(KeyToolCode.FILE_INVALID, `${path} is not a regular file of at most ${maxBytes} bytes`);
    const bytes = Buffer.alloc(stat.size);
    let read = 0;
    while (read < stat.size) {
      const n = readSync(fd, bytes, read, stat.size - read, read);
      if (n === 0) break;
      read += n;
    }
    return bytes.subarray(0, read);
  } finally {
    closeSync(fd);
  }
}
