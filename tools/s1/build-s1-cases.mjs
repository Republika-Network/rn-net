// Builds fixtures/s1-preparation/cases.json: the preparation-format allowlist cases of RN-NET S1
// (spec/rnnet.unsigned-tx-intent.v1.md §2). Each case is a preparation member, the network of the
// signing-b1 intent it is placed in, and the decision stated BY HAND below (accept or refuse).
// packages/tx-intent (makeIntent) and tools/reference/rnnet_tx_reference.py (intent_ok) must each
// reach that decision independently.
//
//   node tools/s1/build-s1-cases.mjs           # check the committed file is current
//   node tools/s1/build-s1-cases.mjs --write   # write it (refuses to overwrite)
//
// Historical records are copied from the committed fixtures, unchanged.
import { Buffer } from 'node:buffer';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalBytes } from '../../packages/canonical/src/index.mjs';
import { makeIntent } from '../../packages/tx-intent/src/index.mjs';

export const PATH = fileURLToPath(new URL('../../fixtures/s1-preparation/cases.json', import.meta.url));
export const FORMAT = 'rnnet.s1-preparation-cases.v1';
const fixture = (p) => JSON.parse(readFileSync(new URL(`../../fixtures/${p}`, import.meta.url), 'utf8'));

export function baseIntents() {
  return { 'xrpl:testnet': fixture('signing-b1/xrpl-intent.json'), 'evm:11155111': fixture('signing-b1/sepolia-intent.json') };
}

function historical() {
  const b2 = fixture('preparation-b2/cases.json').cases.filter((c) => c.expected.intent);
  return {
    sepoliaV1: b2.find((c) => c.network === 'evm:11155111').expected.intent.preparation,
    xrplV1: b2.find((c) => c.network === 'xrpl:testnet').expected.intent.preparation,
    synthetic: baseIntents()['evm:11155111'].preparation,
  };
}

export function cases() {
  const h = historical();
  const v1 = h.sepoliaV1;
  const gas = { ruleSetId: 'amsterdam', fork: 'amsterdam', standard: 12672, floor: 14688, need: 14688, gasLimit: 30000 };
  const S = 'evm:11155111';
  const X = 'xrpl:testnet';
  const without = (o, k) => Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));
  return [
    // Accepted: exactly the historical shapes.
    { id: 'historical-sepolia-v1', network: S, preparation: v1, accept: true },
    { id: 'historical-xrpl-v1', network: X, preparation: h.xrplV1, accept: true },
    { id: 'historical-synthetic-with-note', network: S, preparation: h.synthetic, accept: true },
    { id: 'historical-synthetic-with-note-xrpl', network: X, preparation: baseIntents()[X].preparation, accept: true },
    { id: 'synthetic-source-only', network: S, preparation: { source: 'synthetic' }, accept: true },
    { id: 'synthetic-empty-note', network: X, preparation: { source: 'synthetic', note: '' }, accept: true },
    // Refused: other or future versions, whatever else they carry.
    { id: 'v2-record', network: S, preparation: { ...v1, format: 'rnnet.tx-preparation.v2', rules: 'ADR-RN-018-C2', gas }, accept: false },
    { id: 'v9-record', network: S, preparation: { format: 'rnnet.tx-preparation.v9', anything: 1 }, accept: false },
    { id: 'v1-relabelled-v2', network: S, preparation: { ...v1, format: 'rnnet.tx-preparation.v2' }, accept: false },
    { id: 'v1-with-gas', network: S, preparation: { ...v1, gas }, accept: false },
    { id: 'v1-with-c2-rules', network: S, preparation: { ...v1, rules: 'ADR-RN-018-C2' }, accept: false },
    { id: 'v1-source-synthetic', network: S, preparation: { ...v1, source: 'synthetic' }, accept: false },
    { id: 'v1-source-other', network: X, preparation: { ...h.xrplV1, source: 'rpc-write' }, accept: false },
    { id: 'v1-missing-source', network: S, preparation: without(v1, 'source'), accept: false },
    { id: 'v1-missing-observed-at', network: S, preparation: without(v1, 'observedAt'), accept: false },
    { id: 'format-not-a-string', network: S, preparation: { ...v1, format: 1 }, accept: false },
    { id: 'format-wrong-case', network: S, preparation: { ...v1, format: 'rnnet.tx-preparation.V1' }, accept: false },
    { id: 'format-null', network: S, preparation: { ...v1, format: null }, accept: false },
    { id: 'missing-source', network: S, preparation: { note: 'no source' }, accept: false },
    { id: 'unknown-source', network: S, preparation: { source: 'other' }, accept: false },
    { id: 'synthetic-with-format', network: S, preparation: { source: 'synthetic', format: 'rnnet.tx-preparation.v1' }, accept: false },
    { id: 'synthetic-extra-member', network: S, preparation: { source: 'synthetic', note: 'x', gas }, accept: false },
    { id: 'synthetic-note-number', network: X, preparation: { source: 'synthetic', note: 7 }, accept: false },
    { id: 'synthetic-note-null', network: X, preparation: { source: 'synthetic', note: null }, accept: false },
    { id: 'empty-object', network: S, preparation: {}, accept: false },
    { id: 'array', network: S, preparation: [h.synthetic], accept: false },
    { id: 'string', network: S, preparation: 'rnnet.tx-preparation.v1', accept: false },
    { id: 'null', network: S, preparation: null, accept: false },
  ];
}

const jsAccepts = (c) => {
  try {
    makeIntent({ ...baseIntents()[c.network], preparation: c.preparation });
    return true;
  } catch (error) {
    if (error?.code !== 'RNTX_INTENT_INVALID') throw error;
    return false;
  }
};

export function build() {
  const list = cases();
  for (const c of list) if (jsAccepts(c) !== c.accept) throw new Error(`${c.id}: makeIntent ${c.accept ? 'refused' : 'accepted'} it`);
  const doc = { format: FORMAT, status: 'SYNTHETIC test cases; decisions stated by hand; historical records copied unchanged', cases: list };
  return `${Buffer.from(canonicalBytes(doc)).toString('utf8')}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = build();
  if (process.argv.includes('--write')) {
    if (existsSync(PATH)) throw new Error(`${PATH} exists; remove it first to rebuild`);
    writeFileSync(PATH, text, { flag: 'wx' });
    console.log(`wrote ${PATH}`);
  } else {
    const current = existsSync(PATH) && readFileSync(PATH, 'utf8') === text;
    console.log(current ? 's1 cases: current' : 's1 cases: NOT current');
    process.exit(current ? 0 : 1);
  }
}
