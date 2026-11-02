// Builds fixtures/keytool-c4/cases.json (RN-NET-03B2-C4): synthetic, public test data for the key
// generator and the sign log, checked by tools/keytool.test.mjs and, independently, by
// tools/reference/rnnet_keytool_reference.py.
//
// Every key here comes from a public label or a fixed byte pattern, so anyone can recompute it: no
// fixture key may ever be funded or stand for an identity. The file holds public keys, addresses,
// digests and the generator's raw input bytes, never a key file or passphrase.
//
//   node tools/signing/build-c4-fixtures.mjs          rewrite the fixtures
//   node tools/signing/build-c4-fixtures.mjs --check  exit 1 if the committed file differs
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { IntentNetwork, SECP256K1_N } from '../../packages/tx-intent/src/index.mjs';
import { generateKey, MAX_SECP256K1_DRAWS } from '../../signer/src/keygen.mjs';
import { evmAddress } from '../../txverify/src/index.mjs';
import { KeyToolError } from '../keytool/errors.mjs';
import { decideSigning, entryDigest, EntryType, nextEntry, readResignBasis, replaySignLog } from '../keytool/signlog.mjs';

export const FILE = fileURLToPath(new URL('../../fixtures/keytool-c4/cases.json', import.meta.url));
const XRPL = IntentNetwork.XRPL_TESTNET;
const SEP = IntentNetwork.SEPOLIA;
const PURPOSE = 'genesis-proof-01';

const label = (text) => createHash('sha256').update(`rnnet:synthetic-test-key:v1:${text}`).digest();
const hex32 = (n) => n.toString(16).padStart(64, '0');
const digestOf = (text) => `sha256:${createHash('sha256').update(text).digest('hex')}`;

// A synthetic source that replays fixed bytes.
function replay(draws) {
  const queue = draws.map((h) => Uint8Array.from(Buffer.from(h, 'hex')));
  return { ed25519Seed: () => queue.shift(), bytes: () => queue.shift() ?? new Uint8Array(0) };
}

function keygenCase(id, network, draws) {
  try {
    const key = generateKey({ network, purpose: PURPOSE, source: replay(draws) });
    const accepted = network === XRPL ? 1 : draws.findIndex((h) => BigInt(`0x${h}`) >= 1n && BigInt(`0x${h}`) < SECP256K1_N) + 1;
    return { id, network, draws, expect: { ok: true, acceptedDraw: accepted, publicKey: key.publicKey, address: key.address } };
  } catch (error) {
    return { id, network, draws, expect: { ok: false, code: error.code } };
  }
}

function keygenCases() {
  const n = SECP256K1_N;
  const valid = [1n, 2n, n - 1n, BigInt(`0x${label('c4-sepolia-1').toString('hex')}`) % n];
  return [
    keygenCase('ed25519-label-1', XRPL, [label('c4-xrpl-1').toString('hex')]),
    keygenCase('ed25519-label-2', XRPL, [label('c4-xrpl-2').toString('hex')]),
    keygenCase('ed25519-zero-bytes', XRPL, [hex32(0n)]),
    keygenCase('ed25519-all-ff', XRPL, ['f'.repeat(64)]),
    keygenCase('secp256k1-first-draw', SEP, [hex32(valid[3])]),
    keygenCase('secp256k1-one', SEP, [hex32(1n)]),
    keygenCase('secp256k1-n-minus-1', SEP, [hex32(n - 1n)]),
    keygenCase('secp256k1-reject-zero', SEP, [hex32(0n), hex32(2n)]),
    keygenCase('secp256k1-reject-n', SEP, [hex32(n), hex32(valid[3])]),
    // n + 5 reduced modulo n would be 5; rejection sampling discards it and takes the next draw.
    keygenCase('secp256k1-reject-n-plus-5-not-reduced', SEP, [hex32(n + 5n), hex32(n - 1n)]),
    keygenCase('secp256k1-reject-max', SEP, ['f'.repeat(64), hex32(0n), hex32(n), hex32(valid[3])]),
    keygenCase('secp256k1-all-draws-invalid', SEP, Array.from({ length: MAX_SECP256K1_DRAWS }, (_, i) => hex32(n + BigInt(i)))),
    keygenCase('secp256k1-last-draw-valid', SEP, [...Array.from({ length: MAX_SECP256K1_DRAWS - 1 }, () => hex32(0n)), hex32(2n)]),
  ];
}

// --- sign log -------------------------------------------------------------------------------------

const KEYS = {
  xrpl: generateKey({ network: XRPL, purpose: PURPOSE, source: replay([label('c4-xrpl-1').toString('hex')]) }),
  xrplOther: generateKey({ network: XRPL, purpose: PURPOSE, source: replay([label('c4-xrpl-2').toString('hex')]) }),
  sepolia: generateKey({ network: SEP, purpose: PURPOSE, source: replay([hex32(BigInt(`0x${label('c4-sepolia-1').toString('hex')}`) % SECP256K1_N)]) }),
};
const KEY_FILE = { xrpl: digestOf('c4 synthetic key file xrpl'), xrplOther: digestOf('c4 synthetic key file xrpl 2'), sepolia: digestOf('c4 synthetic key file sepolia') };
const D = (n) => digestOf(`c4 synthetic intent ${n}`);
const TXH = { xrpl: (n) => createHash('sha256').update(`c4 tx ${n}`).digest('hex').toUpperCase(), sepolia: (n) => `0x${createHash('sha256').update(`c4 tx ${n}`).digest('hex')}` };
const STATUS = (n) => ({ format: 'rnnet.submission-status.v1', authorizationDigest: digestOf(`c4 status auth ${n}`), network: XRPL, attemptEntry: digestOf(`c4 attempt ${n}`), transactionHash: TXH.xrpl(n), finding: 'EXPIRED', code: null, liveReportSha256: null, live: null, providers: [], recordedAt: '2026-11-02T13:00:00Z' });

let clock = 0;
const time = () => `2026-11-02T12:${String(Math.floor(clock / 60)).padStart(2, '0')}:${String(clock++ % 60).padStart(2, '0')}Z`;

function builder() {
  const entries = [];
  const add = (type, fields) => {
    entries.push(nextEntry(entries, type, fields, time()));
    return api;
  };
  const who = (k) => ({ network: KEYS[k].network, purpose: PURPOSE, address: KEYS[k].address });
  const api = {
    entries,
    created: (k) => add(EntryType.KEY_CREATED, { ...who(k), publicKey: KEYS[k].publicKey, keyFileSha256: KEY_FILE[k] }),
    signing: (k, seq, d) => add(EntryType.SIGNING, { ...who(k), sequence: String(seq), intentDigest: d }),
    signed: (k, seq, d, tx) => add(EntryType.SIGNED, { ...who(k), sequence: String(seq), intentDigest: d, blobSha256: digestOf(`c4 blob ${d}`), transactionHash: tx }),
    basis: (k, seq, d, expiredD, expiredTx, status) => add(EntryType.RESIGN_BASIS, { ...who(k), sequence: String(seq), intentDigest: d, expiredIntentDigest: expiredD, expiredTransactionHash: expiredTx, statusRecordDigest: status }),
  };
  return api;
}

// Re-chains `previous` after a deliberate change, so that only the intended rule fails.
function rechain(entries) {
  const out = [];
  for (const entry of entries) {
    const copy = structuredClone(entry);
    if (typeof copy.index === 'number' && copy.index === out.length) copy.previous = out.length === 0 ? null : entryDigest(out[out.length - 1]);
    out.push(copy);
  }
  return out;
}

function verdict(entries) {
  try {
    replaySignLog(entries);
    return { ok: true };
  } catch (error) {
    if (!(error instanceof KeyToolError)) throw error;
    return { ok: false, code: error.code, index: Number(/^RNKEY_SIGNLOG_INVALID: entry (\d+):/.exec(error.message)[1]) };
  }
}

function signlogCases() {
  const cases = [];
  const push = (id, entries) => cases.push({ id, entries, expect: verdict(entries) });
  const basis1 = readResignBasis(STATUS(1));
  const basis2 = readResignBasis(STATUS(2));

  push('empty', []);
  push('key-created', builder().created('xrpl').entries);
  push('both-networks-signed', builder().created('xrpl').created('sepolia').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).signing('sepolia', 0, D(2)).signed('sepolia', 0, D(2), TXH.sepolia(2)).entries);
  push('pending-at-end', builder().created('xrpl').signing('xrpl', 7, D(1)).entries);
  push('resign-after-expired', builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).signing('xrpl', 7, D(3)).signed('xrpl', 7, D(3), TXH.xrpl(3)).entries);
  push('basis-unused-at-end', builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).entries);
  push('two-resigns', builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).signing('xrpl', 7, D(3)).signed('xrpl', 7, D(3), TXH.xrpl(2)).basis('xrpl', 7, D(4), D(3), TXH.xrpl(2), basis2.statusRecordDigest).signing('xrpl', 7, D(4)).signed('xrpl', 7, D(4), TXH.xrpl(4)).entries);

  const base = builder().created('xrpl').created('sepolia').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).entries;
  const mutate = (id, change, chain = true) => {
    const copy = structuredClone(base);
    change(copy);
    push(id, chain ? rechain(copy) : copy);
  };
  mutate('wrong-previous', (e) => { e[2].previous = D(99); }, false);
  mutate('first-previous-not-null', (e) => { e[0].previous = D(99); }, false);
  mutate('gap-index', (e) => { e[3].index = 4; });
  mutate('index-not-position', (e) => { e.splice(1, 1); });
  mutate('time-goes-back', (e) => { e[3].recordedAt = '2026-11-02T11:00:00Z'; });
  mutate('bad-time', (e) => { e[1].recordedAt = '2026-11-02 12:00:00Z'; });
  // Date.parse accepts both of these; the entry time must be a real UTC second.
  mutate('impossible-date', (e) => { e[0].recordedAt = '2026-02-30T00:00:00Z'; });
  mutate('hour-24', (e) => { e[0].recordedAt = '2026-01-01T24:00:00Z'; });
  // A Sepolia public key off the curve, with the address its bytes would hash to.
  mutate('evm-public-key-off-curve', (e) => {
    const raw = Buffer.from(e[1].publicKey, 'hex');
    raw[64] ^= 1;
    e[1].publicKey = raw.toString('hex');
    e[1].address = evmAddress(raw);
  });
  mutate('unknown-type', (e) => { e[2].type = 'SIGNATURE'; });
  // Review C4-1: a non-string or inherited type is not a type (it once fell through to RESIGN_BASIS).
  for (const [id, type] of [['type-array', ['SIGNING']], ['type-constructor', 'constructor'], ['type-to-string', 'toString'], ['type-null', null], ['type-object', { SIGNING: 1 }]]) mutate(id, (e) => { e[2].type = type; });
  mutate('network-array', (e) => { e[1].network = [SEP]; });
  mutate('purpose-array', (e) => { e[2].purpose = [PURPOSE]; });
  mutate('year-0000', (e) => { e[0].recordedAt = '0000-01-01T00:00:00Z'; });
  mutate('extra-field', (e) => { e[2].note = 'x'; });
  mutate('missing-field', (e) => { delete e[3].blobSha256; });
  mutate('wrong-format', (e) => { e[1].format = 'rnnet.sign-log-entry.v2'; });
  mutate('unknown-network', (e) => { e[1].network = 'evm:1'; });
  mutate('unknown-purpose', (e) => { e[2].purpose = 'genesis-proof-02'; });
  mutate('sequence-leading-zero', (e) => { e[2].sequence = '07'; });
  mutate('sequence-too-large-xrpl', (e) => { e[2].sequence = String(2n ** 32n); e[3].sequence = String(2n ** 32n); });
  mutate('upper-case-digest', (e) => { e[2].intentDigest = e[2].intentDigest.toUpperCase(); });
  mutate('xrpl-hash-lower-case', (e) => { e[3].transactionHash = e[3].transactionHash.toLowerCase(); });
  mutate('address-not-of-public-key', (e) => { e[0].address = KEYS.xrplOther.address; });
  mutate('xrpl-public-key-lower-case', (e) => { e[0].publicKey = `ED${e[0].publicKey.slice(2).toLowerCase()}`; });
  mutate('second-key-same-network', (e) => {
    e.splice(2, 0, { ...e[0], address: KEYS.xrplOther.address, publicKey: KEYS.xrplOther.publicKey, index: 2 });
    for (let i = 3; i < e.length; i += 1) e[i].index = i;
  });
  mutate('duplicate-key-created', (e) => {
    e.splice(2, 0, { ...e[0], index: 2 });
    for (let i = 3; i < e.length; i += 1) e[i].index = i;
  });
  mutate('unregistered-address', (e) => { e[2].address = KEYS.xrplOther.address; e[3].address = KEYS.xrplOther.address; });
  mutate('signed-without-signing', (e) => { e.splice(2, 1); e[2].index = 2; });
  mutate('signed-other-digest', (e) => { e[3].intentDigest = D(9); });
  mutate('signed-other-sequence', (e) => { e[3].sequence = '8'; });
  // nextEntry refuses to build an invalid entry, so these are built by hand and chained.
  const raw = (id, extra) => push(id, rechain([...structuredClone(base), ...extra.map((x, i) => ({ format: 'rnnet.sign-log-entry.v1', index: base.length + i, previous: null, recordedAt: '2026-11-02T12:59:00Z', purpose: PURPOSE, ...x }))]));
  const xr = { network: XRPL, address: KEYS.xrpl.address };
  const sp = { network: SEP, address: KEYS.sepolia.address };
  raw('second-intent-same-sequence-no-basis', [{ ...xr, type: 'SIGNING', sequence: '7', intentDigest: D(2) }]);
  raw('higher-sequence-while-unresolved', [{ ...xr, type: 'SIGNING', sequence: '8', intentDigest: D(2) }]);
  raw('lower-sequence-while-unresolved', [{ ...xr, type: 'SIGNING', sequence: '6', intentDigest: D(2) }]);
  raw('same-digest-signed-twice', [{ ...xr, type: 'SIGNING', sequence: '7', intentDigest: D(1) }]);
  raw('two-pending-signing', [{ ...sp, type: 'SIGNING', sequence: '0', intentDigest: D(5) }, { ...sp, type: 'SIGNING', sequence: '0', intentDigest: D(6) }]);
  raw('basis-sepolia', [{ ...sp, type: 'SIGNING', sequence: '0', intentDigest: D(5) }, { ...sp, type: 'SIGNED', sequence: '0', intentDigest: D(5), blobSha256: D(50), transactionHash: TXH.sepolia(5) }, { ...sp, type: 'RESIGN_BASIS', sequence: '0', intentDigest: D(6), expiredIntentDigest: D(5), expiredTransactionHash: TXH.sepolia(5), statusRecordDigest: basis1.statusRecordDigest }]);
  raw('basis-wrong-transaction', [{ ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(2), statusRecordDigest: basis1.statusRecordDigest }]);
  raw('basis-wrong-digest', [{ ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(2), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }]);
  raw('basis-other-sequence', [{ ...xr, type: 'RESIGN_BASIS', sequence: '8', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }]);
  raw('basis-names-signed-digest', [{ ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(1), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }]);
  push('basis-before-anything-signed', rechain([
    ...builder().created('xrplOther').entries,
    { format: 'rnnet.sign-log-entry.v1', index: 1, previous: null, recordedAt: '2026-11-02T12:59:00Z', purpose: PURPOSE, network: XRPL, address: KEYS.xrplOther.address, type: 'RESIGN_BASIS', sequence: '1', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest },
  ]));
  raw('basis-while-pending', [{ ...sp, type: 'SIGNING', sequence: '0', intentDigest: D(5) }, { ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }, { ...xr, type: 'SIGNING', sequence: '7', intentDigest: D(3) }, { ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(4), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis2.statusRecordDigest }]);
  // Review C4-1, the end-to-end form: an array-typed basis for a Sepolia nonce.
  raw('sepolia-array-type-basis', [{ ...sp, type: 'SIGNING', sequence: '0', intentDigest: D(5) }, { ...sp, type: 'SIGNED', sequence: '0', intentDigest: D(5), blobSha256: D(50), transactionHash: TXH.sepolia(5) }, { ...sp, type: ['RESIGN_BASIS'], sequence: '0', intentDigest: D(6), expiredIntentDigest: D(5), expiredTransactionHash: TXH.sepolia(5), statusRecordDigest: basis1.statusRecordDigest }]);
  raw('two-unused-bases', [{ ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }, { ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(4), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis2.statusRecordDigest }]);
  raw('status-record-reused', [
    { ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest },
    { ...xr, type: 'SIGNING', sequence: '7', intentDigest: D(3) },
    { ...xr, type: 'SIGNED', sequence: '7', intentDigest: D(3), blobSha256: D(30), transactionHash: TXH.xrpl(3) },
    { ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(4), expiredIntentDigest: D(3), expiredTransactionHash: TXH.xrpl(3), statusRecordDigest: basis1.statusRecordDigest },
  ]);
  raw('signing-for-other-intent-than-basis', [{ ...xr, type: 'RESIGN_BASIS', sequence: '7', intentDigest: D(3), expiredIntentDigest: D(1), expiredTransactionHash: TXH.xrpl(1), statusRecordDigest: basis1.statusRecordDigest }, { ...xr, type: 'SIGNING', sequence: '7', intentDigest: D(4) }]);
  return cases;
}

function decisionCase(id, entries, request) {
  try {
    const { action, append } = decideSigning(entries, request);
    return { id, entries, request, expect: { ok: true, action, append } };
  } catch (error) {
    if (!(error instanceof KeyToolError)) throw error;
    return { id, entries, request, expect: { ok: false, code: error.code } };
  }
}

function decisionCases() {
  const basis1 = readResignBasis(STATUS(1));
  const basis2 = readResignBasis(STATUS(2));
  const req = (k, seq, d, resign = null, extra = {}) => ({ network: KEYS[k].network, purpose: PURPOSE, address: KEYS[k].address, publicKey: KEYS[k].publicKey, keyFileSha256: KEY_FILE[k], sequence: String(seq), intentDigest: d, resign, ...extra });
  const fresh = builder().created('xrpl').created('sepolia').entries;
  const signed = builder().created('xrpl').created('sepolia').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).signing('sepolia', 0, D(2)).signed('sepolia', 0, D(2), TXH.sepolia(2)).entries;
  const pending = builder().created('xrpl').signing('xrpl', 7, D(1)).entries;
  const withBasis = builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).entries;
  const resignPending = builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).signing('xrpl', 7, D(3)).entries;
  const resigned = builder().created('xrpl').signing('xrpl', 7, D(1)).signed('xrpl', 7, D(1), TXH.xrpl(1)).basis('xrpl', 7, D(3), D(1), TXH.xrpl(1), basis1.statusRecordDigest).signing('xrpl', 7, D(3)).signed('xrpl', 7, D(3), TXH.xrpl(3)).entries;
  const expired3 = { statusRecordDigest: basis2.statusRecordDigest, expiredTransactionHash: TXH.xrpl(3) };
  return [
    decisionCase('fresh-sign-xrpl', fresh, req('xrpl', 7, D(1))),
    decisionCase('fresh-sign-sepolia', fresh, req('sepolia', 0, D(2))),
    decisionCase('empty-log-not-registered', [], req('xrpl', 7, D(1))),
    decisionCase('other-key-file-not-registered', fresh, req('xrpl', 7, D(1), null, { keyFileSha256: D(77) })),
    decisionCase('other-public-key-not-registered', fresh, req('xrpl', 7, D(1), null, { publicKey: KEYS.xrplOther.publicKey })),
    decisionCase('other-purpose-not-registered', fresh, req('xrpl', 7, D(1), null, { purpose: 'genesis-proof-02' })),
    decisionCase('same-digest-again', signed, req('xrpl', 7, D(1))),
    decisionCase('same-digest-again-sepolia', signed, req('sepolia', 0, D(2))),
    decisionCase('other-intent-same-sequence', signed, req('xrpl', 7, D(9))),
    decisionCase('higher-sequence', signed, req('xrpl', 8, D(9))),
    decisionCase('lower-sequence', signed, req('xrpl', 6, D(9))),
    decisionCase('sepolia-same-nonce-replacement', signed, req('sepolia', 0, D(9))),
    decisionCase('sepolia-replacement-with-basis', signed, req('sepolia', 0, D(9), { statusRecordDigest: basis1.statusRecordDigest, expiredTransactionHash: TXH.sepolia(2).slice(2).toUpperCase() })),
    decisionCase('sepolia-next-nonce', signed, req('sepolia', 1, D(9))),
    decisionCase('complete-pending', pending, req('xrpl', 7, D(1))),
    decisionCase('other-while-pending', pending, req('xrpl', 7, D(9))),
    decisionCase('complete-pending-with-basis-given', pending, req('xrpl', 7, D(1), basis1)),
    decisionCase('basis-on-fresh-key', fresh, req('xrpl', 7, D(1), basis1)),
    decisionCase('resign-with-basis', signed, req('xrpl', 7, D(3), basis1)),
    decisionCase('resign-wrong-transaction', signed, req('xrpl', 7, D(3), { ...basis1, expiredTransactionHash: TXH.xrpl(2) })),
    decisionCase('resign-other-sequence', signed, req('xrpl', 8, D(3), basis1)),
    decisionCase('resign-digest-already-signed', signed, req('xrpl', 7, D(1), basis1)),
    decisionCase('continue-after-basis', withBasis, req('xrpl', 7, D(3))),
    decisionCase('continue-after-basis-same-basis', withBasis, req('xrpl', 7, D(3), basis1)),
    decisionCase('continue-after-basis-other-basis', withBasis, req('xrpl', 7, D(3), basis2)),
    decisionCase('other-intent-after-basis', withBasis, req('xrpl', 7, D(4), basis2)),
    decisionCase('complete-resign-pending', resignPending, req('xrpl', 7, D(3), basis1)),
    decisionCase('complete-resign-pending-other-basis', resignPending, req('xrpl', 7, D(3), basis2)),
    decisionCase('resign-reuses-status-record', resigned, req('xrpl', 7, D(4), { ...basis1, expiredTransactionHash: TXH.xrpl(3) })),
    decisionCase('resign-again-new-status-record', resigned, req('xrpl', 7, D(4), expired3)),
    decisionCase('first-intent-again-after-resign', resigned, req('xrpl', 7, D(1))),
    decisionCase('expired-transaction-not-latest', resigned, req('xrpl', 7, D(4), { statusRecordDigest: basis2.statusRecordDigest, expiredTransactionHash: TXH.xrpl(1) })),
  ];
}

function statusCases() {
  const ok = STATUS(1);
  const one = (id, record) => {
    try {
      return { id, record, expect: { ok: true, ...readResignBasis(record) } };
    } catch (error) {
      if (!(error instanceof KeyToolError)) throw error;
      return { id, record, expect: { ok: false, code: error.code } };
    }
  };
  return [
    one('expired', ok),
    one('included', { ...ok, finding: 'INCLUDED' }),
    one('unresolved', { ...ok, finding: 'UNRESOLVED' }),
    one('sepolia', { ...ok, network: SEP }),
    one('other-format', { ...ok, format: 'rnnet.submission-record.v1' }),
    one('lower-case-hash', { ...ok, transactionHash: ok.transactionHash.toLowerCase() }),
    one('not-an-object', [ok]),
  ];
}

export function build() {
  clock = 0;
  const value = {
    format: 'rnnet.keytool-c4-fixtures',
    note: 'RN-NET-03B2-C4 synthetic fixtures: public test data only; never fund these keys',
    keygen: keygenCases(),
    signlog: signlogCases(),
    decisions: decisionCases(),
    statusRecords: statusCases(),
  };
  return `${JSON.stringify(value, null, 1)}\n`;
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  const text = build();
  if (process.argv.includes('--check')) {
    process.exitCode = readFileSync(FILE, 'utf8') === text ? 0 : 1;
  } else {
    writeFileSync(FILE, text);
  }
}
