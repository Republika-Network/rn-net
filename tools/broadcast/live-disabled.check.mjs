// The three live entry points refuse as commands (RN-NET-03B2-C3). Run by tools/ci/offline-checks.sh
// inside the network namespace, without the test preload (which refuses subprocesses).
//
// Each entry point is started as a command with plausible arguments naming files that do not exist.
// Each must exit 3 with its LIVE_DISABLED code on stderr, print nothing on stdout and read nothing:
// the paths do not exist, so any attempt to read them would give another error first.
//   node tools/broadcast/live-disabled.check.mjs
import { spawnSync } from 'node:child_process';
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
process.exitCode = failures === 0 ? 0 : 1;
