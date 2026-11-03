// The offline end-to-end rehearsal of Genesis Proof 01 (RN-NET-03B2-C3; ADR-RN-016 Amendment C1,
// "rehearsed end to end against simulated providers first, with timings").
//
// One run drives the real entry points, with injected dependencies only, on a simulated clock:
//   1. evidence      RN-NET-02 verifies fixtures/genesis-proof-01 and its commitment;
//   2. payload       the commitment's exact 42-byte anchor payload, checked against golden.json;
//   3. preparation   tools/prepare/prepare-live.mjs (typed approval, then XRPL 4 or Sepolia 16 reads);
//   4. intent        gate D in the key tool: the founder reviews the intent, types its digest's end;
//   5. signing       passphrase, scrypt, one signature and the key tool's self-check (synthetic key);
//   6. verification  the signed bytes, verified by txverify (JS) and by the reference verifier;
//   7. authorization the founder checks the drafted rnnet.broadcast-authorization.v1 and saves it;
//   8. submission    tools/submit/submit-anchor.mjs (typed approval, pre-submit reads, one write);
//   9. duplicate     the same authorization again: refused by the submission log, nothing sent;
//  10. status        a separately authorized tools/submit/status-check.mjs, after a wait;
//  11. assembly      the evidence digests of every stage, in one report.
// Each stage's elapsed time is measured on the simulated clock: requests cost `requestMs`,
// human steps their scripted durations, and the clock moves for nothing else.
//
// Synthetic only: the keys are the public fixtures/signing-b1 test keys (derived from public labels,
// never funded), the providers are simulated (`*.fixture.invalid`), and every directory is a new
// private directory under the system temporary directory, removed afterwards. No network is used.
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeAnchorPayload } from '../../packages/anchor/src/index.mjs';
import { canonicalize } from '../../packages/canonical/src/index.mjs';
import { entryDigest, readAuthorization, readStatusAuthorization } from '../../packages/chain-submit/src/index.mjs';
import { verifyEvidence } from '../../packages/verifier/src/index.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import { fixtureKey } from '../../signer/test/fixture-keys.mjs';
import { run as keytool } from '../keytool/cli.mjs';
import { preparationAuthorizationDigest } from '../prepare/authorization.mjs';
import { prepareLive } from '../prepare/prepare-live.mjs';
import { readLog } from '../submit/store.mjs';
import { statusCheck } from '../submit/status-check.mjs';
import { submitAnchor } from '../submit/submit-anchor.mjs';
import { createClock, createNetworks, ENDPOINTS, NOW, PROVIDERS } from './network.mjs';

export const REHEARSAL_FORMAT = 'rnnet.genesis-rehearsal.v1';
export const X = 'xrpl:testnet';
export const S = 'evm:11155111';
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const GENESIS = join(ROOT, 'fixtures/genesis-proof-01/');
const LABEL = { [X]: 'rn-net-03b2b1-xrpl-1', [S]: 'rn-net-03b2b1-sepolia-1' };
const SENDER = { [X]: 'rPMhDyWFH1uu1kMwheshzpaMouWr75XRa2', [S]: '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86' };
const PUBLIC_KEY = 'ED0C325AFF74C97AEA604FCC239998CA6EC98741D97991842E1F649325C57DEE66';
const PASSPHRASE = 'a synthetic C3 rehearsal passphrase, never real';
const SCOPE = 'Synthetic RN-NET-03B2-C3 rehearsal. Simulated providers and public test keys only; never sent to any network.';
const LOOPBACK_ONLY = {
  readProc: (name) => ({ 'net/dev': 'Inter-|\n face |\n    lo: 0 0 0\n', 'net/route': '', 'net/ipv6_route': '', uid_map: '         0       1000          1\n' })[name],
  interfaces: () => [],
};

/**
 * The nominal durations, in whole seconds (requests: `requestMs`), of the steps. Human steps are estimates
 * for a founder who reads every value; the machine steps stand for CPU time (scrypt and the two
 * verifications), which the simulated clock does not otherwise see.
 */
export const PROFILE = Object.freeze({
  requestMs: 500,
  machine: 1,
  preparationApproval: 20,
  intentReview: 60,
  passphrase: 10,
  scryptAndSign: 2,
  authorizationDraft: 45,
  submitApproval: 15,
  statusWait: { [X]: 30, [S]: 900 },
  statusApproval: 15,
});

const iso = (seconds) => `${new Date(seconds * 1000).toISOString().slice(0, 19)}Z`;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function privateDir(parent, name) {
  const path = join(parent, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function writePrivate(path, text) {
  writeFileSync(path, text, { mode: 0o600, flag: 'wx' });
  return path;
}

/**
 * One rehearsal run. Returns the timeline report (plain data, deterministic for given options).
 * @param {{ id: string, network: string, closeSeconds?: number, profile?: object, referenceVerifier: Function, duplicate?: boolean }} options
 */
export async function rehearse({ id, network, closeSeconds = 4, profile: overrides = {}, referenceVerifier, duplicate = true }) {
  const profile = { ...PROFILE, ...overrides, statusWait: { ...PROFILE.statusWait, ...overrides.statusWait } };
  const clock = createClock(NOW);
  const nets = createNetworks({ clock, closeSeconds, requestSeconds: profile.requestMs / 1000 });
  const ids = network === X ? PROVIDERS.xrpl : PROVIDERS.sepolia;
  const stages = [];
  const xrplView = (atMs = clock.ms()) => (network === X ? Math.min(...ids.map((p) => nets.xrplLedger(p, atMs))) : null);
  const stage = async (name, body) => {
    const startMs = clock.ms();
    const value = await body();
    stages.push({ stage: name, startMs: startMs - NOW * 1000, endMs: clock.ms() - NOW * 1000, elapsedMs: clock.ms() - startMs, xrplLedger: xrplView() });
    return value;
  };
  const base = mkdtempSync(join(realpathSync(tmpdir()), 'rnnet-c3-rehearsal-'));
  chmodSync(base, 0o700);
  try {
    const dirs = Object.fromEntries(['inputs', 'prepare', 'keys', 'signlog', 'signed', 'submitlog', 'submitevidence'].map((n) => [n, privateDir(base, n)]));

    // 1-2. The Genesis evidence and its exact payload.
    const commitment = await stage('evidence', async () => {
      const golden = JSON.parse(readFileSync(join(GENESIS, 'golden.json'), 'utf8'));
      const report = verifyEvidence(new Uint8Array(readFileSync(join(GENESIS, 'evidence.json'))), { commitment: { envelope: new Uint8Array(readFileSync(join(GENESIS, 'envelope.json'))), digest: golden.envelope.commitment } });
      if (report.outcome !== 'PASS') throw new Error('the Genesis evidence does not verify');
      clock.advance(profile.machine);
      return golden.envelope.commitment;
    });
    const payload = await stage('payload', async () => {
      const golden = JSON.parse(readFileSync(join(GENESIS, 'golden.json'), 'utf8'));
      const bytes = Buffer.from(encodeAnchorPayload(commitment));
      if (bytes.length !== 42 || bytes.toString('hex') !== golden.anchorPayload.hex) throw new Error('the anchor payload is not the golden one');
      return bytes.toString('hex');
    });

    // 3. Preparation, through the disabled-for-live entry point with injected dependencies.
    const prepAuthorization = {
      authorizationId: `${id}-prepare`, commitment, format: 'rnnet.preparation-authorization.v1', network, notAfter: iso(clock.now() + 1800),
      providerIds: [...ids], purpose: 'genesis-proof-01', requestBudget: network === X ? 4 : 16, scope: SCOPE, sender: SENDER[network], signingPubKey: network === X ? PUBLIC_KEY : null,
    };
    writePrivate(join(dirs.inputs, 'preparation-authorization.json'), `${canonicalize(prepAuthorization)}\n`);
    writePrivate(join(dirs.inputs, 'endpoints.json'), JSON.stringify(ENDPOINTS));
    const prepTransport = nets.preparationTransport();
    const prepared = await stage('preparation', () => prepareLive({
      argv: ['--network', network, '--authorization', join(dirs.inputs, 'preparation-authorization.json'), '--endpoints', join(dirs.inputs, 'endpoints.json'), '--evidence-dir', dirs.prepare],
      deps: {
        transport: prepTransport, now: clock.now, agreed: dirs.prepare, reviewed: ENDPOINTS.providers, compatibility: Object.fromEntries(PROVIDERS.sepolia.map((p) => [p, { eip1898AccountReads: true, estimateGasBlockHash: true }])),
        approve: async () => {
          clock.advance(profile.preparationApproval);
          return `${network} ${preparationAuthorizationDigest(prepAuthorization).slice(-16)}`;
        },
      },
    }));
    if (prepared.outcome !== 'PREPARED') throw new Error(`${id}: preparation ${prepared.message}`);
    const intent = prepared.intent;
    const intentPath = join(prepared.runDirectory, 'intent.json');

    // 4-5. Gate D in the key tool, with a synthetic key created for this run.
    const key = fixtureKey(network, LABEL[network]);
    const environment = (answers) => ({
      terminal: () => ({
        write: () => {},
        readLine: async () => {
          const [text, seconds] = answers.shift();
          clock.advance(seconds);
          return Buffer.from(text, 'utf8');
        },
        close() {},
      }),
      out: () => {},
      now: clock.date,
      system: { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() },
      net: LOOPBACK_ONLY,
      source: { ed25519Seed: () => Uint8Array.from(key.secretKey), bytes: (n) => (n === 32 ? Uint8Array.from(key.secretKey) : new Uint8Array(n).fill(n)) },
    });
    const keygen = await keytool(['keygen', '--network', network, '--purpose', 'genesis-proof-01', '--key-dir', dirs.keys, '--log-dir', dirs.signlog], environment([[PASSPHRASE, 0], [PASSPHRASE, 0]]));
    if (keygen !== 0) throw new Error(`${id}: keygen exited ${keygen}`);
    const signArgs = ['sign', '--network', network, '--key-dir', dirs.keys, '--log-dir', dirs.signlog, '--out-dir', dirs.signed, '--intent', intentPath, '--approved-digest', prepared.intentDigest];
    const answers = [[prepared.intentDigest.slice(-16), profile.intentReview], [PASSPHRASE, profile.passphrase]];
    const startSign = clock.ms();
    const signedExit = await keytool(signArgs, environment(answers));
    if (signedExit !== 0) throw new Error(`${id}: sign exited ${signedExit}`);
    clock.advance(profile.scryptAndSign);
    // The two human steps of the key tool, split at the passphrase prompt.
    stages.push({ stage: 'intent', startMs: startSign - NOW * 1000, endMs: startSign + profile.intentReview * 1000 - NOW * 1000, elapsedMs: profile.intentReview * 1000, xrplLedger: xrplView(startSign + profile.intentReview * 1000) });
    stages.push({ stage: 'signing', startMs: startSign + profile.intentReview * 1000 - NOW * 1000, endMs: clock.ms() - NOW * 1000, elapsedMs: clock.ms() - startSign - profile.intentReview * 1000, xrplLedger: xrplView() });
    const outputName = readdirSync(dirs.signed).filter((n) => !n.startsWith('.')).sort()[0];
    const signed = JSON.parse(readFileSync(join(dirs.signed, outputName), 'utf8'));

    // 6. Both verifiers, on the bytes the broadcaster will receive.
    const intentText = canonicalize(intent);
    const verification = await stage('verification', async () => {
      const js = verifySignedTransaction({ intent, approvedDigest: prepared.intentDigest, signedTransaction: signed.signedTransaction });
      const reference = referenceVerifier(intentText, prepared.intentDigest, signed.signedTransaction);
      clock.advance(profile.machine);
      if (js.outcome !== 'PASS' || canonicalize(js) !== canonicalize(reference)) throw new Error(`${id}: the verifiers disagree`);
      return js;
    });

    // 7. The founder's broadcast authorization, from the key tool's draft values.
    const authorization = await stage('authorization', async () => {
      clock.advance(profile.authorizationDraft);
      return {
        attempt: 1, authorizationId: `${id}-submit-1`, blobSha256: signed.blobSha256, dryRun: false, format: 'rnnet.broadcast-authorization.v1', intentDigest: prepared.intentDigest, kind: 'first', network,
        previousAttempt: null, providerId: ids[0], scope: SCOPE, sender: SENDER[network], sequence: String(network === X ? intent.transaction.Sequence : BigInt(intent.transaction.nonce)), transactionHash: signed.transactionHash,
        validity: network === X ? { lastLedgerSequence: intent.transaction.LastLedgerSequence } : { notAfter: iso(clock.now() + 3000) },
      };
    });
    const authorizationText = `${canonicalize(authorization)}\n`;
    writePrivate(join(dirs.inputs, 'broadcast-authorization.json'), authorizationText);
    writePrivate(join(dirs.inputs, 'intent.json'), `${intentText}\n`);
    writePrivate(join(dirs.inputs, 'signed.txt'), `${signed.signedTransaction}\n`);
    const submitArgv = [
      '--network', network, '--authorization', join(dirs.inputs, 'broadcast-authorization.json'), '--intent', join(dirs.inputs, 'intent.json'), '--approved-digest', prepared.intentDigest,
      '--signed-transaction', join(dirs.inputs, 'signed.txt'), '--endpoints', join(dirs.inputs, 'endpoints.json'), '--log-dir', dirs.submitlog, '--evidence-dir', dirs.submitevidence,
    ];
    const bound = { sequence: network === X ? intent.transaction.Sequence : null, intent, transactionHash: signed.transactionHash };
    const submitDeps = (transport, approvalSeconds) => ({
      transport, referenceVerifier, now: clock.now, reviewed: ENDPOINTS.providers.map(({ id: pid, network: n, url }) => ({ id: pid, network: n, url })), agreed: { logDir: dirs.submitlog, evidenceDir: dirs.submitevidence },
      approve: async () => {
        clock.advance(approvalSeconds);
        return `${network} ${readAuthorization(authorizationText).digest.slice(-16)}`;
      },
    });

    // 8. The submission.
    const submitTransport = nets.submissionTransport(network, bound);
    const submission = await stage('submission', () => submitAnchor({ argv: submitArgv, deps: submitDeps(submitTransport, profile.submitApproval) }));
    // The ledgers the broadcaster's expiry check reads (ADR-RN-019 §5): server_info's validated
    // ledger and account_info's ledger, per provider, with the simulated time of each answer.
    const presubmit = submitTransport.exchanges.filter((e) => e.method === 'server_info' || e.method === 'account_info').map((e) => {
      const result = JSON.parse(e.response.body).result;
      return { providerId: e.providerId, method: e.method, atMs: Math.round(e.at * 1000), ledger: e.method === 'server_info' ? result.info.validated_ledger.seq : result.ledger_index };
    });

    // 9. The same authorization again: the log makes it single-use.
    let duplicateResult = null;
    if (duplicate) {
      const again = nets.submissionTransport(network, bound);
      duplicateResult = await stage('duplicate', () => submitAnchor({ argv: submitArgv, deps: submitDeps(again, profile.submitApproval) }));
      duplicateResult = { exitCode: duplicateResult.exitCode, code: duplicateResult.code, outcome: duplicateResult.result?.outcome ?? null, requests: again.exchanges.length, writes: again.exchanges.filter((e) => ['submit', 'eth_sendRawTransaction'].includes(e.method)).length };
    }

    // 10. The status check, separately authorized, after a wait.
    let status = null;
    if (submission.result?.outcome === 'ACCEPTED_PROVISIONAL') {
      clock.advance(profile.statusWait[network]);
      const attempt = readLog(dirs.submitlog).filter((e) => e.kind === 'ATTEMPTING').at(-1);
      const statusAuthorization = {
        attemptEntry: entryDigest(attempt), authorizationId: `${id}-status-1`, format: 'rnnet.status-authorization.v1', network, providerIds: [...ids], scope: SCOPE,
        sender: attempt.sender, sequence: attempt.sequence, transactionHash: attempt.transactionHash,
      };
      const statusText = `${canonicalize(statusAuthorization)}\n`;
      writePrivate(join(dirs.inputs, 'status-authorization.json'), statusText);
      const statusTransport = nets.submissionTransport(network, bound);
      const checked = await stage('status', () => statusCheck({
        argv: ['--network', network, '--authorization', join(dirs.inputs, 'status-authorization.json'), '--intent', join(dirs.inputs, 'intent.json'), '--endpoints', join(dirs.inputs, 'endpoints.json'), '--log-dir', dirs.submitlog, '--evidence-dir', dirs.submitevidence],
        deps: {
          transport: statusTransport, now: clock.now, reviewed: submitDeps().reviewed, agreed: { logDir: dirs.submitlog, evidenceDir: dirs.submitevidence },
          approve: async () => {
            clock.advance(profile.statusApproval);
            return `${network} ${readStatusAuthorization(statusText).digest.slice(-16)}`;
          },
        },
      }));
      status = { exitCode: checked.exitCode, finding: checked.finding, code: checked.code, requests: statusTransport.exchanges.length };
    }

    // 11. Evidence assembly: the digest of every stage's output, in order.
    const assembly = await stage('assembly', async () => ({
      commitment,
      payloadHex: payload,
      preparationEvidenceSha256: sha256(readFileSync(join(prepared.runDirectory, 'evidence.json'))),
      intentDigest: prepared.intentDigest,
      blobSha256: signed.blobSha256,
      transactionHash: signed.transactionHash,
      broadcastAuthorizationDigest: readAuthorization(authorizationText).digest,
      submissionLog: readLog(dirs.submitlog).map((e) => ({ index: e.index, kind: e.kind, digest: entryDigest(e) })),
    }));

    const lastLedgerSequence = network === X ? intent.transaction.LastLedgerSequence : null;
    return {
      id,
      network,
      closeSeconds: network === X ? closeSeconds : null,
      profile,
      stages,
      intentText,
      approvedDigest: prepared.intentDigest,
      signedTransaction: signed.signedTransaction,
      verification,
      preparation: {
        requests: prepTransport.exchanges.length,
        observed: prepTransport.exchanges.map((e) => ({ providerId: e.providerId, method: e.method, atMs: Math.round(e.at * 1000), request: e.request, response: e.response.body })),
        lastLedgerSequence,
      },
      submission: {
        exitCode: submission.exitCode,
        outcome: submission.result?.outcome ?? null,
        code: submission.code,
        requests: submitTransport.exchanges.length,
        writes: nets.state.writes.length,
        presubmit,
        ledgersLeftAtPresubmit: network === X ? lastLedgerSequence - Math.max(...presubmit.map((p) => p.ledger)) : null,
      },
      duplicate: duplicateResult,
      status,
      assembly,
      totalElapsedMs: clock.ms() - NOW * 1000,
    };
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}
