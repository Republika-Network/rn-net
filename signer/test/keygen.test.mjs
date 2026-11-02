// RN-NET-03B2-C4: key generation (ADR-RN-017 Amendment C1, K1) and the creation-only passphrase
// minimum. Every key here is synthetic and exists in memory only; nothing is written.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createCipheriv, createHash, scryptSync } from 'node:crypto';
import { test } from 'node:test';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { addressFromPublicKey, SECP256K1_N, TxError } from '../../packages/tx-intent/src/index.mjs';
import { ed25519PublicKey, evmAddress, secp256k1PublicKey } from '../src/crypto.mjs';
import { decryptKeyFile, encryptKeyFile, KDF, KEY_FILE_FORMAT, MIN_CREATION_PASSPHRASE } from '../src/keyfile.mjs';
import { drawSecp256k1Secret, generateKey, keyFileRandomness, MAX_SECP256K1_DRAWS, OS_SOURCE } from '../src/keygen.mjs';
import { bindKey } from '../src/keys.mjs';

const XRPL = 'xrpl:testnet';
const SEP = 'evm:11155111';
const PURPOSE = 'genesis-proof-01';
const code = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof TxError, `not a TxError: ${error}`);
    return error.code;
  }
  return null;
};
const be = (n) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'));
const replay = (draws) => {
  const queue = draws.map((d) => (d instanceof Uint8Array ? d : be(d)));
  return { ed25519Seed: () => queue.shift(), bytes: () => queue.shift() };
};
const label = (text) => Uint8Array.from(createHash('sha256').update(`rnnet:synthetic-test-key:v1:${text}`).digest());

test('the OS source makes valid, distinct keys for both networks (in memory, discarded)', () => {
  for (const network of [XRPL, SEP]) {
    const a = generateKey({ network, purpose: PURPOSE });
    const b = generateKey({ network, purpose: PURPOSE });
    assert.equal(a.network, network);
    assert.equal(a.purpose, PURPOSE);
    assert.notEqual(a.address, b.address);
    // The returned key re-binds to the same public key and address.
    const again = bindKey({ network, purpose: PURPOSE, secretKey: a.secretKey });
    assert.equal(again.publicKey, a.publicKey);
    assert.equal(again.address, a.address);
    if (network === XRPL) {
      assert.match(a.publicKey, /^ED[0-9A-F]{64}$/);
      assert.equal(addressFromPublicKey(Buffer.from(a.publicKey, 'hex')), a.address);
    } else {
      assert.match(a.publicKey, /^04[0-9a-f]{128}$/);
      assert.equal(evmAddress(Buffer.from(a.publicKey, 'hex')), a.address);
      const k = BigInt(`0x${Buffer.from(a.secretKey).toString('hex')}`);
      assert.ok(k >= 1n && k < SECP256K1_N);
    }
    a.secretKey.fill(0);
    b.secretKey.fill(0);
  }
});

test('the OS Ed25519 seed is read back from PKCS #8 correctly', () => {
  const seed = OS_SOURCE.ed25519Seed();
  assert.equal(seed.length, 32);
  const key = generateKey({ network: XRPL, purpose: PURPOSE, source: replay([seed]) });
  assert.equal(key.publicKey, `ED${ed25519PublicKey(seed).toString('hex').toUpperCase()}`);
  seed.fill(0);
});

test('secp256k1: rejection sampling, never reduction modulo n', () => {
  const n = SECP256K1_N;
  assert.deepEqual(drawSecp256k1Secret(replay([1n])).draws, 1);
  assert.deepEqual(drawSecp256k1Secret(replay([n - 1n])).draws, 1);
  for (const rejected of [0n, n, n + 1n, n + 5n, 2n ** 256n - 1n]) {
    const { secretKey, draws } = drawSecp256k1Secret(replay([rejected, 7n]));
    assert.equal(draws, 2, `${rejected} must be redrawn`);
    assert.deepEqual(secretKey, be(7n), 'the accepted value is the second draw itself');
  }
  // n + 5 reduced would be 5: the key must not be the key of 5.
  const key = generateKey({ network: SEP, purpose: PURPOSE, source: replay([n + 5n, 9n]) });
  assert.equal(key.publicKey, secp256k1PublicKey(be(9n)).toString('hex'));
  assert.notEqual(key.publicKey, secp256k1PublicKey(be(5n)).toString('hex'));
  // A source that never gives a valid value is a broken source: refused, not reduced.
  assert.equal(code(() => drawSecp256k1Secret(replay(Array.from({ length: MAX_SECP256K1_DRAWS }, () => n)))), 'RNTX_KEY_INVALID');
  assert.equal(drawSecp256k1Secret(replay([...Array.from({ length: MAX_SECP256K1_DRAWS - 1 }, () => 0n), 3n])).draws, MAX_SECP256K1_DRAWS);
});

test('generation: network and purpose binding, and refusal of a bad source', () => {
  assert.equal(code(() => generateKey({ network: 'evm:1', purpose: PURPOSE })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => generateKey({ network: 'xrpl:mainnet', purpose: PURPOSE })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => generateKey({ network: XRPL, purpose: 'genesis-proof-02' })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => generateKey({ network: XRPL, purpose: PURPOSE, source: replay([new Uint8Array(31)]) })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => generateKey({ network: SEP, purpose: PURPOSE, source: { bytes: () => new Uint8Array(33) } })), 'RNTX_KEY_INVALID');
  assert.equal(code(() => generateKey({ network: SEP, purpose: PURPOSE, source: { bytes: () => 'not bytes' } })), 'RNTX_KEY_INVALID');
  // The same synthetic input gives the same key (deterministic test seam).
  const a = generateKey({ network: XRPL, purpose: PURPOSE, source: replay([label('c4-xrpl-1')]) });
  const b = generateKey({ network: XRPL, purpose: PURPOSE, source: replay([label('c4-xrpl-1')]) });
  assert.equal(a.address, b.address);
});

test('generation copies its input: a caller-owned source buffer is never changed', () => {
  const seed = label('c4-xrpl-1');
  const copy = Uint8Array.from(seed);
  generateKey({ network: XRPL, purpose: PURPOSE, source: { ed25519Seed: () => seed } });
  assert.deepEqual(seed, copy);
  const draw = be(11n);
  generateKey({ network: SEP, purpose: PURPOSE, source: { bytes: () => draw } });
  assert.deepEqual(draw, be(11n));
});

test('key-file randomness: 16-byte salt and 12-byte IV from the source', () => {
  const { salt, iv } = keyFileRandomness();
  assert.equal(salt.length, 16);
  assert.equal(iv.length, 12);
  const other = keyFileRandomness();
  assert.notDeepEqual(Buffer.from(salt), Buffer.from(other.salt));
  assert.equal(code(() => keyFileRandomness({ bytes: (n) => new Uint8Array(n - 1) })), 'RNTX_KEY_INVALID');
});

test('a new key file needs a 20-character passphrase; decryption still accepts 12 (B1 compatibility)', () => {
  assert.equal(MIN_CREATION_PASSPHRASE, 20);
  const key = generateKey({ network: XRPL, purpose: PURPOSE, source: replay([label('c4-xrpl-2')]) });
  const opts = { salt: new Uint8Array(16).fill(1), iv: new Uint8Array(12).fill(2), createdAt: '2026-11-02T00:00:00Z' };
  assert.equal(code(() => encryptKeyFile(key, 'x'.repeat(19), opts)), 'RNTX_KEYFILE_INVALID');
  // 20 code points after NFC, even when they take more bytes.
  const file = encryptKeyFile(key, 'é'.repeat(20), opts);
  assert.equal(decryptKeyFile(file, 'é'.repeat(20)).secretKey.length, 32);
  // A file made the B1 way with a 12-character passphrase still opens: built here by hand, with
  // the unchanged format, so the decryption rule is shown to be unchanged.
  const passphrase = 'twelve chars';
  const legacy = {
    format: KEY_FILE_FORMAT, network: XRPL, purpose: PURPOSE, createdAt: '2026-11-01T00:00:00Z', publicKey: key.publicKey, address: key.address,
    kdf: { ...KDF, salt: '01'.repeat(16) }, cipher: { name: 'aes-256-gcm', iv: '02'.repeat(12), tag: '' }, ciphertext: '',
  };
  const { ciphertext, cipher, ...rest } = legacy;
  const aad = Buffer.from(canonicalBytes({ ...rest, cipher: { name: cipher.name, iv: cipher.iv } }));
  const k = scryptSync(Buffer.from(passphrase), Buffer.from(legacy.kdf.salt, 'hex'), 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: 256 * 1024 * 1024 });
  const enc = createCipheriv('aes-256-gcm', k, Buffer.from(legacy.cipher.iv, 'hex'), { authTagLength: 16 });
  enc.setAAD(aad);
  const original = bindKey({ network: XRPL, purpose: PURPOSE, secretKey: label('c4-xrpl-2') });
  legacy.ciphertext = Buffer.concat([enc.update(original.secretKey), enc.final()]).toString('hex');
  legacy.cipher.tag = enc.getAuthTag().toString('hex');
  void ciphertext;
  assert.equal(decryptKeyFile(legacy, passphrase).secretKey.length, 32);
  assert.equal(code(() => decryptKeyFile(legacy, 'eleven char')), 'RNTX_KEYFILE_INVALID');
  assert.equal(code(() => decryptKeyFile(legacy, 'twelve chars!')), 'RNTX_KEYFILE_DECRYPT');
});

test('encryptKeyFile does not change the caller key and overwrites its own copy', () => {
  const secretKey = label('c4-xrpl-1');
  const before = Uint8Array.from(secretKey);
  encryptKeyFile({ network: XRPL, purpose: PURPOSE, secretKey }, 'a passphrase of twenty+ characters', { salt: new Uint8Array(16), iv: new Uint8Array(12), createdAt: '2026-11-02T00:00:00Z' });
  assert.deepEqual(secretKey, before);
});
