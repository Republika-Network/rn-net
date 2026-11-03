// Builds vectors/compat/sanitizer.json (RN-NET-03B2-C6-LIVE-ENABLE, review N-b and N-c): the
// expected output of sanitizeMessage on fixed cases, and the SHA-256 of its output over a seeded
// corpus that tools/reference/rnnet_compat_reference.py generates the same way. Both sides must
// reproduce every case and the corpus digest, so the JavaScript and Python sanitizers cannot drift.
//   node tools/compat/build-sanitizer-vectors.mjs [--check]
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sanitizeMessage } from './run.mjs';

export const SANITIZER_VECTORS = 'vectors/compat/sanitizer.json';
export const SANITIZER_VECTORS_FORMAT = 'rnnet.compat-sanitizer-vectors.v1';

/** The fragments the corpus strings are made of: address, credential and boundary shapes. */
export const CORPUS_FRAGMENTS = Object.freeze([
  'a', 'Z', 'q', '0', '7', '9', 'f', 'x', '.', ':', '::', '@', '=', '/', '-', '_', '+', ' ', ' ', '?', '&', '[', ']', '(', ')', '<', '>', '%', ',',
  '10.1.2.3', '198.51.100.7', '::ffff:', '2001:db8::', 'fe80::1', 'http://', 'https://', 'wss://', 'user', 'alice:hunter2', 'pass', 'password',
  'localhost', 'LocalHost', 'geth.internal', '.example.org', ':8545', ':51234', '0x', 'ab', 'deadbeef', 'Bearer ', 'token', 'key', 'apikey=',
  'secret', 'session', 'seed', 'ip_', 'v1.2.3', 'not found', 'invalid argument 1: ', 'json: cannot unmarshal', 'error',
  'é', '\u{1F600}', '\n', '\t', '\u0000', 'abcdefghijklmnop', '0123456789', 'A1b2C3d4E5f6',
]);
export const CORPUS = Object.freeze({ seed: 0x6c36_5a17, count: 4000, maxFragments: 160 });

/** xorshift32, as the Python reference computes it. */
function xorshift32(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
}

/** The corpus strings. */
export function corpusStrings({ seed, count, maxFragments } = CORPUS, fragments = CORPUS_FRAGMENTS) {
  const next = xorshift32(seed);
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const n = next() % (maxFragments + 1);
    let s = '';
    for (let k = 0; k < n; k += 1) s += fragments[next() % fragments.length];
    out.push(s);
  }
  return out;
}

/** SHA-256 over the sanitized corpus, one output per line. */
export const corpusDigest = (strings = corpusStrings()) => `sha256:${createHash('sha256').update(Buffer.from(strings.map((s) => sanitizeMessage(s)).join('\n'), 'utf8')).digest('hex')}`;

/** Fixed cases: provider-style messages kept as they are, and every mask (N-b, N-c). */
export const CASE_INPUTS = Object.freeze([
  'header for hash not found', 'Transaction not found.', 'invalid argument 1: hex string without 0x prefix', 'invalid block parameter',
  'invalid argument 1: json: cannot unmarshal object', 'limit exceeded', 'internal error', 'execution reverted',
  // N-b: IPv4 next to a word character, inside a word, with more groups, IPv4-mapped IPv6
  'ip_10.1.2.3 refused', 'x10.1.2.3y', 'v1.2.3.4.5', '10.1.2.3456', 'from ::ffff:198.51.100.7 x', '::ffff:10.1.2.3', '[::ffff:10.1.2.3]:8545', '::ffff:a01:203',
  'peer 203.0.113.9:30303 dropped', 'upstream 10.0.0.7:8545 refused', 'version 1.2.3 ok',
  // N-c: key=value, user:password, e-mail, bare host names, short tokens, credential words
  'apikey=abc123 failed', 'https://h.example/?key=abc', 'connect alice:hunter2@db.internal', 'login alice:hunter2 refused', 'mail ops@example.org',
  'dial internal-geth-3.prod.svc.cluster.local:8545 from 2001:db8:85a3::8a2e:370:7334', 'node geth-7.internal.example.com down', 'localhost refused', 'LOCALHOST:8545',
  'Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCD', 'token: 1a2b3c', 'password hunter2', 'your session expired', 'id ab12cd34ef56 unknown',
  'hexutil.Uint64 odd length', 'retry at 12:34:56', 'missing trie node 5c1f2e3d4c5b6a7980a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f607 (path )',
  // C6-LIVE-ENABLE review N3
  'user:pass:word', 'sk_live_abcdefghijklmnop', 'ghp_ABCDEFGHIJKLMNOPQRST', 'ip 2130706433', 'host 10.1 down', 'internal.10', 'my.host.1', 'user admin pass hunter2',
  'the method eth_sendRawTransaction does not exist', 'block 0x1b4 not found',
  `key 0x${'ab'.repeat(32)}`, 'aé\u{1F600}b', `${'w '.repeat(250)}198.51.100.7`, `from ::ffff:198.51.100.7 ${'a.'.repeat(5000)}`,
]);

export function buildVectors() {
  return {
    format: SANITIZER_VECTORS_FORMAT,
    cases: CASE_INPUTS.map((input) => ({ input, output: sanitizeMessage(input) })),
    corpus: { ...CORPUS, fragments: [...CORPUS_FRAGMENTS], sha256: corpusDigest() },
  };
}

export const vectorsText = () => `${JSON.stringify(buildVectors(), null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = fileURLToPath(new URL(`../../${SANITIZER_VECTORS}`, import.meta.url));
  if (process.argv.includes('--check')) {
    let current = null;
    try {
      current = readFileSync(path, 'utf8');
    } catch {
      // missing: stale
    }
    if (current !== vectorsText()) {
      process.stderr.write(`stale: ${SANITIZER_VECTORS}\n`);
      process.exitCode = 1;
    }
  } else writeFileSync(path, vectorsText());
}
