// The sign log on disk (ADR-RN-017 Amendment C1, K4): one file per entry in a private directory,
// outside every repository, separate from the key directory.
//
//   NNNNNN.json          entry N: its canonical JSON and one newline, mode 0600, never changed
//   .NNNNNN.json.tmp     an entry being written (files.mjs); a leftover one means a run stopped
//                        part-way and every command refuses (RNKEY_SIGNLOG_INCOMPLETE) until the
//                        founder has looked at it
//
// Anything else in the directory, a gap, a non-canonical file or an entry that breaks a rule of
// replaySignLog is RNKEY_SIGNLOG_INVALID: the tool never repairs or skips history.
// Two runs cannot both append entry N: the temporary name and link() are exclusive, and the loser
// is refused (RNKEY_SIGNLOG_CONFLICT). After each append the whole log is read and replayed again.
import { Buffer } from 'node:buffer';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { KeyToolCode, KeyToolError, refuse } from './errors.mjs';
import { createDurably, lstatOrNull, readPrivateFile } from './files.mjs';
import { checkPrivateDirectory, SYSTEM } from './location.mjs';
import { MAX_ENTRY_BYTES, replaySignLog } from './signlog.mjs';

const ENTRY_NAME = /^([0-9]{6})\.json$/;
const TEMPORARY_NAME = /^\.([0-9]{6})\.json\.tmp$/;
export const MAX_ENTRIES = 10_000;

export const entryName = (index) => `${String(index).padStart(6, '0')}.json`;
export const entryText = (entry) => `${canonicalize(entry)}\n`;

/** Parses one stored entry; its bytes must be exactly its canonical JSON and a newline. */
export function parseStoredEntry(bytes, name) {
  const text = Buffer.from(bytes).toString('utf8');
  let entry;
  try {
    if (!text.endsWith('\n') || !Buffer.from(text, 'utf8').equals(Buffer.from(bytes))) throw new Error('encoding');
    entry = parse(text.slice(0, -1));
  } catch {
    refuse(KeyToolCode.SIGNLOG_INVALID, `${name}: not canonical JSON and a newline`);
  }
  if (entryText(entry) !== text) refuse(KeyToolCode.SIGNLOG_INVALID, `${name}: not canonical JSON and a newline`);
  return entry;
}

/** Reads and replays the whole log; returns the list of entries. */
export function readSignLog(dir, system = SYSTEM) {
  checkPrivateDirectory(dir, 'sign log directory', system);
  const names = readdirSync(dir).sort();
  const temporary = names.filter((name) => TEMPORARY_NAME.test(name));
  if (temporary.length > 0) refuse(KeyToolCode.SIGNLOG_INCOMPLETE, `${temporary.join(', ')}: an entry was being written when a run stopped; see tools/keytool/README.md (crash recovery)`);
  if (names.length > MAX_ENTRIES) refuse(KeyToolCode.SIGNLOG_INVALID, 'too many entries');
  const entries = names.map((name, index) => {
    const match = ENTRY_NAME.exec(name);
    if (!match) refuse(KeyToolCode.SIGNLOG_INVALID, `unexpected file ${JSON.stringify(name)}`);
    if (Number(match[1]) !== index) refuse(KeyToolCode.SIGNLOG_INVALID, `${name}: entry ${index} is missing`);
    const stat = lstatOrNull(join(dir, name));
    if (!stat?.isFile()) refuse(KeyToolCode.SIGNLOG_INVALID, `${name}: not a regular file`);
    return parseStoredEntry(readPrivateFile(join(dir, name), MAX_ENTRY_BYTES, system.getuid, KeyToolCode.SIGNLOG_INVALID), name);
  });
  replaySignLog(entries);
  return entries;
}

/**
 * Appends `entry` (built by nextEntry from `entries`, the log as just read) and returns the log as
 * read back. Refuses if another run appended first, or if the log read back is not `entries`
 * followed by `entry`.
 */
export function appendSignLog(dir, entries, entry, system = SYSTEM) {
  checkPrivateDirectory(dir, 'sign log directory', system);
  if (entry.index !== entries.length) throw new KeyToolError(KeyToolCode.SIGNLOG_CONFLICT, 'the entry is not the next one');
  const text = entryText(entry);
  if (Buffer.byteLength(text) > MAX_ENTRY_BYTES) throw new KeyToolError(KeyToolCode.SIGNLOG_INVALID, 'entry too large');
  const name = entryName(entry.index);
  createDurably(dir, name, `.${name}.tmp`, Buffer.from(text, 'utf8'), { existsCode: KeyToolCode.SIGNLOG_CONFLICT, partialCode: KeyToolCode.SIGNLOG_CONFLICT });
  const back = readSignLog(dir, system);
  const expected = [...entries, entry].map(entryText);
  if (back.length !== expected.length || back.some((e, i) => entryText(e) !== expected[i])) throw new KeyToolError(KeyToolCode.SIGNLOG_CONFLICT, 'the log changed while this entry was appended');
  return back;
}
