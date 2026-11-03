#!/usr/bin/env node
// Builds fixtures/compat-c6/ (RN-NET-03B2-C6-PREP) from the simulated scenarios. OFFLINE: every
// response comes from tools/compat/simulated.mjs; no provider is contacted.
//   manifest.json  the 22-request manifest, as describeManifest() gives it;
//   cases.json     per scenario: the transcript of simulated responses, in the order sent, and
//                  the evidence runCompatibility produced from it.
// `--check` compares instead of writing (tools/compat.test.mjs does the same in-process).
import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describeManifest } from './manifest.mjs';
import { runCompatibility } from './run.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from './simulated.mjs';

export const C6_FIXTURES_FORMAT = 'rnnet.provider-compat-c6-fixtures.v1';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PAD_MIN = 1024;

/** A transport that records each simulated answer as a transcript entry. */
function recording(inner, transcript) {
  return async (request) => {
    const entry = { providerId: request.providerId };
    transcript.push(entry);
    try {
      const response = await inner(request);
      let text = Buffer.from(response.body).toString('utf8');
      const trimmed = text.replace(/ +$/, '');
      const pad = text.length - trimmed.length >= PAD_MIN ? text.length - trimmed.length : 0;
      if (pad > 0) text = trimmed;
      Object.assign(entry, { status: response.status, text, pad });
      return response;
    } catch (error) {
      entry.error = error.code;
      throw error;
    }
  };
}

/** A transport that answers from a transcript, in order, and refuses anything else. */
export function replayTranscript(transcript) {
  let i = 0;
  return async (request) => {
    const entry = transcript[i++];
    if (!entry || entry.providerId !== request.providerId) throw new Error('replay: request out of order');
    if (entry.error) throw Object.assign(new Error(entry.error), { code: entry.error });
    return { status: entry.status, body: Buffer.concat([Buffer.from(entry.text, 'utf8'), Buffer.alloc(entry.pad, 0x20)]) };
  };
}

export async function buildCases(endpoints) {
  const cases = [];
  for (const s of SCENARIOS) {
    const transcript = [];
    const { evidence } = await runCompatibility({ endpoints, transport: recording(simulatedTransport(s), transcript), now: SIM_NOW });
    cases.push({ name: s.name, models: s.models, now: SIM_NOW, transcript, evidence });
  }
  return { format: C6_FIXTURES_FORMAT, note: 'Simulated providers only. No response here is a real provider answer.', cases };
}

export const fixtureText = (value) => `${JSON.stringify(value, null, 1)}\n`;

async function main() {
  const endpoints = JSON.parse(readFileSync(`${ROOT}config/rpc-endpoints.json`, 'utf8'));
  const files = { 'fixtures/compat-c6/manifest.json': fixtureText(describeManifest()), 'fixtures/compat-c6/cases.json': fixtureText(await buildCases(endpoints)) };
  const check = process.argv.includes('--check');
  let stale = 0;
  for (const [path, text] of Object.entries(files)) {
    if (check) {
      let current = null;
      try {
        current = readFileSync(`${ROOT}${path}`, 'utf8');
      } catch {
        // missing
      }
      if (current !== text) {
        stale += 1;
        process.stderr.write(`stale: ${path}\n`);
      }
    } else writeFileSync(`${ROOT}${path}`, text);
  }
  return stale === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = await main();
