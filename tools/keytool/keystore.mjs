// Encrypted key files on WSL ext4 (ADR-RN-017 Amendment C1, K2). This module stores and loads the
// rnnet.testnet-key-file.v1 object as bytes; it never sees a secret or passphrase (encryption and
// decryption are signer/src/keyfile.mjs, called by cli.mjs only).
//
//   <key dir>/xrpl-testnet.key.json   the XRPL Testnet key
//   <key dir>/sepolia.key.json        the Sepolia key
//   <key dir>/.<name>.partial         a key file being written (files.mjs)
//
// File names are fixed per network, so no argument can name a path inside the directory.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { IntentNetwork } from '../../packages/tx-intent/src/index.mjs';
import { KeyToolCode, refuse } from './errors.mjs';
import { createDurably, lstatOrNull, readPrivateFile } from './files.mjs';
import { checkPrivateDirectory, SYSTEM } from './location.mjs';

export const KEY_FILE_NAMES = Object.freeze({ [IntentNetwork.XRPL_TESTNET]: 'xrpl-testnet.key.json', [IntentNetwork.SEPOLIA]: 'sepolia.key.json' });
const MAX_KEY_FILE_BYTES = 4096;
const PUBLIC_FIELDS = ['address', 'createdAt', 'format', 'network', 'publicKey', 'purpose'];

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const nameOf = (network) => KEY_FILE_NAMES[network] ?? refuse(KeyToolCode.USAGE, 'unknown network');
const partialOf = (name) => `.${name}.partial`;

export const keyFilePath = (dir, network) => join(dir, nameOf(network));

// A leftover partial file: same inode as the final file means the link was made and only the
// clean-up was lost; otherwise the final file was never made.
function checkNoPartial(dir, name) {
  const partial = lstatOrNull(join(dir, partialOf(name)));
  if (partial === null) return;
  const final = lstatOrNull(join(dir, name));
  const linked = final !== null && final.ino === partial.ino && final.dev === partial.dev;
  refuse(
    KeyToolCode.PARTIAL_FILE,
    linked
      ? `${partialOf(name)} is a second name of ${name}: a key creation stopped after the file was complete; see tools/keytool/README.md (crash recovery)`
      : `${partialOf(name)} exists without ${name}: a key creation stopped before the file was complete; see tools/keytool/README.md (crash recovery)`,
  );
}

/** Refuses unless a key file for `network` can be created in `dir`. */
export function checkKeyFileAbsent(dir, network, system = SYSTEM) {
  checkPrivateDirectory(dir, 'key directory', system);
  const name = nameOf(network);
  checkNoPartial(dir, name);
  if (lstatOrNull(join(dir, name)) !== null) refuse(KeyToolCode.KEY_EXISTS, `${name} already exists; keys are never overwritten`);
}

/** Writes a new key file (its canonical JSON and a newline) durably; returns its bytes' SHA-256. */
export function writeKeyFile(dir, network, file, system = SYSTEM) {
  checkKeyFileAbsent(dir, network, system);
  if (file?.network !== network) refuse(KeyToolCode.KEY_MISMATCH, 'the key file is for another network');
  const name = nameOf(network);
  const bytes = Buffer.from(`${canonicalize(file)}\n`, 'utf8');
  createDurably(dir, name, partialOf(name), bytes, { existsCode: KeyToolCode.KEY_EXISTS, partialCode: KeyToolCode.PARTIAL_FILE });
  return sha256(bytes);
}

/**
 * Reads the key file for `network`: returns { file, sha256, path, publicInfo }. The bytes must be
 * canonical JSON and a newline, and the file must be for `network`. The ciphertext is opened only
 * by the caller, after the founder's approval.
 */
export function readKeyFile(dir, network, system = SYSTEM) {
  checkPrivateDirectory(dir, 'key directory', system);
  const name = nameOf(network);
  checkNoPartial(dir, name);
  const path = join(dir, name);
  if (lstatOrNull(path) === null) refuse(KeyToolCode.KEY_MISSING, `${name} does not exist`);
  const bytes = readPrivateFile(path, MAX_KEY_FILE_BYTES, system.getuid);
  const text = bytes.toString('utf8');
  let file;
  try {
    if (!text.endsWith('\n')) throw new Error('newline');
    file = parse(text.slice(0, -1));
    if (`${canonicalize(file)}\n` !== text) throw new Error('canonical');
  } catch {
    refuse(KeyToolCode.FILE_INVALID, `${name}: not canonical JSON and a newline`);
  }
  if (file === null || typeof file !== 'object' || Array.isArray(file) || file.network !== network) refuse(KeyToolCode.KEY_MISMATCH, `${name} is not a key file for ${network}`);
  const publicInfo = Object.freeze(Object.fromEntries(PUBLIC_FIELDS.map((field) => [field, file[field]])));
  return { file, sha256: sha256(bytes), path, publicInfo };
}
