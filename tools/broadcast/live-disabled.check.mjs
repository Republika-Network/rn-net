// The live entry points refuse as commands (RN-NET-03B2-C3; the C6 entry point, RN-NET-03B2-C6-LIVE). Run by tools/ci/offline-checks.sh
// inside the network namespace, without the test preload (which refuses subprocesses).
//
// Each entry point is started as a command with plausible arguments naming files that do not exist.
// Each must exit 3 with its LIVE_DISABLED code on stderr, print nothing on stdout and read nothing:
// the paths do not exist, so any attempt to read them would give another error first.
//   node tools/broadcast/live-disabled.check.mjs
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const at = (path) => fileURLToPath(new URL(`../${path}`, import.meta.url));
const missing = '/nonexistent-rnnet-c3';
const COMMANDS = [
  ['prepare/prepare-live.mjs', 'RNPL_LIVE_DISABLED', ['--network', 'xrpl:testnet', '--authorization', `${missing}/a.json`, '--endpoints', `${missing}/e.json`, '--evidence-dir', missing]],
  ['prepare/prepare-live.mjs', 'RNPL_LIVE_DISABLED', ['--network', 'evm:11155111', '--authorization', `${missing}/a.json`, '--endpoints', `${missing}/e.json`, '--evidence-dir', missing]],
  ['submit/submit-anchor.mjs', 'RNSA_LIVE_DISABLED', ['--network', 'xrpl:testnet', '--authorization', `${missing}/a.json`, '--intent', `${missing}/i.json`, '--approved-digest', `sha256:${'0'.repeat(64)}`, '--signed-transaction', `${missing}/s.txt`, '--endpoints', `${missing}/e.json`, '--log-dir', missing, '--evidence-dir', missing]],
  ['submit/status-check.mjs', 'RNSA_LIVE_DISABLED', ['--network', 'evm:11155111', '--authorization', `${missing}/a.json`, '--intent', `${missing}/i.json`, '--endpoints', `${missing}/e.json`, '--log-dir', missing, '--evidence-dir', missing]],
];

let failures = 0;
for (const [path, code, args] of COMMANDS) {
  const child = spawnSync(process.execPath, [at(path), ...args], { encoding: 'utf8', env: {}, timeout: 10_000 });
  const ok = child.status === 3 && child.stdout === '' && child.stderr.startsWith(`${code}: live network access is disabled`);
  if (!ok) failures += 1;
  console.log(`${ok ? 'ok' : 'FAIL'} ${path} ${args[1]}: exit ${child.status}`);
}
console.log(`live-disabled check: ${COMMANDS.length - failures}/${COMMANDS.length} entry points refuse`);

// RN-NET-03B2-C6-H3: on the activation branch the C6 command (compat-live/compat-live.mjs) is
// ACTIVATED for one founder-authorized run, so it is NEVER started here, not even with invalid
// arguments: running the activated command is not allowed in CI or in tests. Its state is read from
// its source instead, and this check fails unless exactly the two reviewed switches changed. The
// post-run deactivation change restores it to the list above (docs/genesis/rn-net-03b2c6-h3-activation.md §5).
const c6 = readFileSync(at('compat-live/compat-live.mjs'), 'utf8');
const c6Entry = readFileSync(at('compat-live/entry.mjs'), 'utf8');
const live = /^export const LIVE_NETWORK_ACCESS = (true|false);$/m.exec(c6)?.[1];
const agreed = /^export const AGREED_EVIDENCE_DIR = (null|'[^'\n]*');$/m.exec(c6Entry)?.[1];
const activated = live === 'true' && agreed === "'/home/vicvalch/rn-net-private/c6-evidence'";
const disabled = live === 'false' && agreed === 'null';
console.log(`${activated || disabled ? 'ok' : 'FAIL'} compat-live/compat-live.mjs: not executed; LIVE_NETWORK_ACCESS=${live}, AGREED_EVIDENCE_DIR=${agreed} (${activated ? 'ACTIVATED for the single H3 run' : disabled ? 'disabled' : 'UNREVIEWED STATE'})`);
if (!activated && !disabled) failures += 1;
process.exitCode = failures === 0 ? 0 : 1;
