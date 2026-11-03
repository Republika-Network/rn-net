// Builds fixtures/compat-c6-live/ (RN-NET-03B2-C6-LIVE): complete run directories of the C6 entry
// point over SIMULATED providers (tools/compat/simulated.mjs), each with a fixed authorization.
// No response in them is a real provider answer. The Python reference checks every directory from
// its files alone (rnnet_compat_reference.py), and tools/compat-live.test.mjs checks they are current.
//   node tools/compat-live/build-c6-live-fixtures.mjs [--check]
import { Buffer } from 'node:buffer';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { C6_BUDGET, C6_PROVIDERS } from '../compat/manifest.mjs';
import { SCENARIOS, SIM_NOW, simulatedTransport } from '../compat/simulated.mjs';
import { compatAuthorizationDigest, readCompatAuthorization } from './authorization.mjs';
import { executeRun } from './compat-live.mjs';
import { C6_MANIFEST_SHA256, writeNewFile } from './entry.mjs';
import { RUN_FILES } from './report.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const FIXTURE_DIR = 'fixtures/compat-c6-live';
/** The evidence directory the fixture authorizations name (a name only: fixtures are built in a temporary directory). */
export const FIXTURE_EVIDENCE_DIR = '/srv/rnnet-c6-evidence';
const NOT_AFTER = SIM_NOW + 1800;
const iso = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

/** The fixture authorization text of `name` (canonical JSON and one newline). */
export function fixtureAuthorization(name) {
  const a = {
    authorizationId: `c6-fixture-${name}`,
    evidenceDir: FIXTURE_EVIDENCE_DIR,
    format: 'rnnet.compat-authorization.v1',
    manifestSha256: C6_MANIFEST_SHA256,
    notAfter: iso(NOT_AFTER),
    providers: C6_PROVIDERS.map((p) => ({ id: p.id, requests: C6_BUDGET[p.id], url: p.url })),
    publication: 'none',
    requestBudget: 22,
    scope: 'RN-NET-03B2-C6 read-only provider compatibility check, simulated fixture: no key, no write, no publication',
  };
  return `${canonicalize(a)}\n`;
}

const deep = (depth) => `${'['.repeat(depth)}${']'.repeat(depth)}`;
const scenario = (name) => SCENARIOS.find((s) => s.name === name);
/** A transport that never answers one request (by manifest method and provider), for the deadline. */
const hangOn = (providerId, method, inner) => async (request) => {
  if (request.providerId === providerId && JSON.parse(Buffer.from(request.body).toString('utf8')).method === method) return new Promise(() => {});
  return inner(request);
};
/** The policy's deadline in the fixtures: fires one macrotask later, after any simulated answer. */
const immediateDeadline = () => new Promise((resolve) => setImmediate(resolve));
const neverDeadline = () => new Promise(() => {});

/** The run fixtures: name, transport, clock and deadline. */
export const RUN_FIXTURES = Object.freeze([
  ...['all-compatible', 'estimate-gas-refused-both', 'pin-hash-disagreement', 'finality-lag-blocks-window', 'account-read-refused-1rpc', 'xrpl-wrong-network-labs', 'head-timeout-1rpc', 'error-message-mapped-ipv6-and-long', 'response-too-large']
    .map((name) => ({ name, transport: () => simulatedTransport(scenario(name)) })),
  // The deadline is the policy's own: a provider that never answers is a TIMEOUT after timeoutMs.
  { name: 'deadline-hang-1rpc-head', transport: () => hangOn('sepolia-1rpc', 'eth_getBlockByNumber', simulatedTransport({})), sleep: immediateDeadline },
  // The authorization expires during the run: the policy refuses from that request on; nothing more is sent.
  { name: 'authorization-expires-mid-run', transport: () => simulatedTransport({}), expiresAfterCalls: 10 },
  // A response that cannot be stored stops the run; it is never read as a transport error (review F1).
  { name: 'response-storage-fails', transport: () => simulatedTransport({}), storeFailsAtCall: 6 },
  // JSON nesting at the limit on both sides (C6-LIVE review N-a): depth 64 is read, 65 is not, and
  // a very deep body is refused, not a crash.
  {
    name: 'json-depth-edges',
    transport: () => simulatedTransport({
      override: {
        X02: { text: `{"result":{"status":"success","info":{}},"x":${deep(20_000)}}` },
        S01: { text: `{"jsonrpc":"2.0","id":1,"result":"0xaa36a7","x":${deep(63)}}` },
        S02: { text: `{"jsonrpc":"2.0","id":1,"result":"0xaa36a7","x":${deep(64)}}` },
      },
    }),
  },
]);

/** Runs fixture `f` in a new temporary directory; returns Map name -> bytes of the run directory. */
export async function buildRunFixture(f, endpoints) {
  const base = mkdtempSync(join(tmpdir(), 'rnnet-c6-live-'));
  try {
    chmodSync(base, 0o700);
    const runDirectory = join(base, 'run');
    mkdirSync(runDirectory, { mode: 0o700 });
    const authorizationText = fixtureAuthorization(f.name);
    const { authorization, digest } = readCompatAuthorization(authorizationText);
    if (digest !== compatAuthorizationDigest(authorization)) throw new Error('digest');
    writeNewFile(runDirectory, RUN_FILES.authorization, authorizationText);
    let calls = 0;
    const clock = () => {
      calls += 1;
      return f.expiresAfterCalls !== undefined && calls > f.expiresAfterCalls ? NOT_AFTER + 1 : SIM_NOW;
    };
    const store = (dir, name, body) => {
      if (f.storeFailsAtCall !== undefined && name === `response-${String(f.storeFailsAtCall).padStart(2, '0')}.bin`) throw Object.assign(new Error('simulated I/O error'), { code: 'EIO' });
      return writeNewFile(dir, name, body);
    };
    await executeRun({ authorizationText, authorization, digest, endpoints, transport: f.transport(), now: SIM_NOW, clock, notAfter: NOT_AFTER, runDirectory, sleep: f.sleep ?? neverDeadline, store });
    return new Map(readdirSync(runDirectory).sort().map((name) => [name, readFileSync(join(runDirectory, name))]));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

async function main() {
  const check = process.argv.includes('--check');
  const endpoints = JSON.parse(readFileSync(join(ROOT, 'config/rpc-endpoints.json'), 'utf8'));
  let stale = 0;
  for (const f of RUN_FIXTURES) {
    const files = await buildRunFixture(f, endpoints);
    const dir = join(ROOT, FIXTURE_DIR, f.name);
    if (check) {
      let existing = [];
      try {
        existing = readdirSync(dir).sort();
      } catch {
        // missing: stale
      }
      const same = existing.join(',') === [...files.keys()].join(',') && [...files].every(([name, bytes]) => readFileSync(join(dir, name)).equals(bytes));
      if (!same) {
        stale += 1;
        process.stderr.write(`stale: ${FIXTURE_DIR}/${f.name}\n`);
      }
    } else {
      rmSync(dir, { recursive: true, force: true });
      mkdirSync(dir, { recursive: true });
      for (const [name, bytes] of files) writeFileSync(join(dir, name), bytes);
    }
  }
  return stale === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = await main();
