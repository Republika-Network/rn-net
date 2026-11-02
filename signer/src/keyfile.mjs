// rnnet.testnet-key-file.v1 (ADR-RN-017; spec/rnnet.unsigned-tx-intent.v1.md §7): an encrypted
// testnet key, bound to one network and purpose.
//
// Nothing here reads or writes a file, generates a key or draws randomness: the caller supplies
// the salt and IV. RN-NET-03B2-C4 stores and loads key files in tools/keytool/ (ADR-RN-017 Amendment
// C1, K2), with the salt and IV from the key generator.
//
// Passphrase length: decryption accepts at least 12 characters, exactly as in B1, so every file
// B1 could make still opens. Encryption (making a new file) requires at least 20 (C4, K3).
//
//   KDF:    scrypt, N = 2^17, r = 8, p = 1, 16-byte salt, 32-byte key (about 128 MiB, so maxmem
//           is raised above the 32 MiB default)
//   Cipher: AES-256-GCM, 12-byte IV, 16-byte tag
//   AAD:    the canonical JSON of every field except `ciphertext` and `cipher.tag`
import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv, scryptSync } from 'node:crypto';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { isPlainData, TxError, TxErrorCode } from '../../packages/tx-intent/src/index.mjs';
import { bindKey } from './keys.mjs';

export const KEY_FILE_FORMAT = 'rnnet.testnet-key-file.v1';
export const KDF = Object.freeze({ name: 'scrypt', N: 131_072, r: 8, p: 1 });
const MAXMEM = 256 * 1024 * 1024;
const MIN_PASSPHRASE = 12;
/** The minimum passphrase length, in code points after NFC, for a NEW key file (RN-NET-03B2-C4). */
export const MIN_CREATION_PASSPHRASE = 20;
const HEX = (bytes) => new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
const TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const FIELDS = ['address', 'cipher', 'ciphertext', 'createdAt', 'format', 'kdf', 'network', 'publicKey', 'purpose'];

const invalid = (detail) => new TxError(TxErrorCode.KEYFILE_INVALID, detail);

function passphraseBytes(passphrase, minimum) {
  if (typeof passphrase !== 'string' || [...passphrase.normalize('NFC')].length < minimum) throw invalid(`passphrase must be at least ${minimum} characters`);
  return Buffer.from(passphrase.normalize('NFC'), 'utf8');
}

function derive(passphrase, salt, minimum) {
  const bytes = passphraseBytes(passphrase, minimum);
  try {
    return scryptSync(bytes, salt, 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: MAXMEM });
  } finally {
    bytes.fill(0);
  }
}

function aad(file) {
  const { ciphertext, cipher, ...rest } = file;
  return Buffer.from(canonicalBytes({ ...rest, cipher: { name: cipher.name, iv: cipher.iv } }));
}

/**
 * Encrypts a key; returns the key-file object. `salt` (16 bytes) and `iv` (12 bytes) are required,
 * and the passphrase must be at least MIN_CREATION_PASSPHRASE characters.
 */
export function encryptKeyFile(key, passphrase, { salt, iv, createdAt }) {
  const bound = bindKey(key);
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw invalid('salt must be 16 bytes');
  if (!(iv instanceof Uint8Array) || iv.length !== 12) throw invalid('iv must be 12 bytes');
  if (typeof createdAt !== 'string' || !TIME.test(createdAt)) throw invalid('createdAt must be YYYY-MM-DDTHH:MM:SSZ');
  const file = {
    format: KEY_FILE_FORMAT,
    network: bound.network,
    purpose: bound.purpose,
    createdAt,
    publicKey: bound.publicKey,
    address: bound.address,
    kdf: { ...KDF, salt: Buffer.from(salt).toString('hex') },
    cipher: { name: 'aes-256-gcm', iv: Buffer.from(iv).toString('hex'), tag: '' },
    ciphertext: '',
  };
  const key32 = derive(passphrase, salt, MIN_CREATION_PASSPHRASE);
  try {
    const encryption = createCipheriv('aes-256-gcm', key32, iv, { authTagLength: 16 });
    encryption.setAAD(aad(file));
    file.ciphertext = Buffer.concat([encryption.update(bound.secretKey), encryption.final()]).toString('hex');
    file.cipher.tag = encryption.getAuthTag().toString('hex');
  } finally {
    key32.fill(0);
    bound.secretKey.fill(0);
  }
  return file;
}

function checkShape(file) {
  if (file === null || typeof file !== 'object' || Array.isArray(file)) throw invalid('a key file is an object');
  if (Object.keys(file).sort().join(',') !== FIELDS.join(',')) throw invalid('unexpected or missing fields');
  if (file.format !== KEY_FILE_FORMAT) throw invalid(`format must be ${KEY_FILE_FORMAT}`);
  const { kdf, cipher } = file;
  if (kdf === null || typeof kdf !== 'object' || Object.keys(kdf).sort().join(',') !== 'N,name,p,r,salt') throw invalid('bad kdf');
  if (kdf.name !== KDF.name || kdf.N !== KDF.N || kdf.r !== KDF.r || kdf.p !== KDF.p || !HEX(16).test(kdf.salt)) throw invalid('kdf must be scrypt N=2^17 r=8 p=1 with a 16-byte salt');
  if (cipher === null || typeof cipher !== 'object' || Object.keys(cipher).sort().join(',') !== 'iv,name,tag') throw invalid('bad cipher');
  if (cipher.name !== 'aes-256-gcm' || !HEX(12).test(cipher.iv) || !HEX(16).test(cipher.tag)) throw invalid('cipher must be aes-256-gcm with a 12-byte IV and a 16-byte tag');
  if (!HEX(32).test(file.ciphertext)) throw invalid('ciphertext must be 32 bytes');
  if (typeof file.createdAt !== 'string' || !TIME.test(file.createdAt)) throw invalid('bad createdAt');
}

/**
 * Decrypts a key-file object; returns { network, purpose, secretKey }. A wrong passphrase or any
 * changed field is RNTX_KEYFILE_DECRYPT; a malformed file, or a secret whose public key or
 * address differs from the file's, is RNTX_KEYFILE_INVALID.
 */
export function decryptKeyFile(input, passphrase) {
  // Plain data only, then one canonical snapshot that every later step reads.
  if (!isPlainData(input)) throw invalid('a key file must be plain JSON data');
  const file = JSON.parse(Buffer.from(canonicalBytes(input)).toString('utf8'));
  checkShape(file);
  let secretKey;
  let key32 = null;
  try {
    key32 = derive(passphrase, Buffer.from(file.kdf.salt, 'hex'), MIN_PASSPHRASE);
    const decryption = createDecipheriv('aes-256-gcm', key32, Buffer.from(file.cipher.iv, 'hex'), { authTagLength: 16 });
    decryption.setAAD(aad(file));
    decryption.setAuthTag(Buffer.from(file.cipher.tag, 'hex'));
    const plain = Buffer.concat([decryption.update(Buffer.from(file.ciphertext, 'hex')), decryption.final()]);
    secretKey = Uint8Array.from(plain);
    plain.fill(0);
  } catch (error) {
    if (error instanceof TxError) throw error;
    throw new TxError(TxErrorCode.KEYFILE_DECRYPT, 'wrong passphrase or a changed key file');
  } finally {
    key32?.fill(0);
  }
  let bound;
  try {
    bound = bindKey({ network: file.network, purpose: file.purpose, secretKey });
  } catch {
    throw invalid('the decrypted secret is not a valid key for the file network');
  } finally {
    secretKey.fill(0);
  }
  if (bound.publicKey !== file.publicKey || bound.address !== file.address) {
    bound.secretKey.fill(0);
    throw invalid('the decrypted secret does not match the public key and address');
  }
  return { network: bound.network, purpose: bound.purpose, secretKey: bound.secretKey };
}
