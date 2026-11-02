// Concurrent access to the submission log by separate processes (RN-NET-03B2-C2). Run by
// tools/ci/offline-checks.sh inside the network namespace, without the test preload (which refuses
// subprocesses). Offline: it writes only to a new private directory under the system temporary
// directory, and removes it.
//
// For each round, N writer processes (concurrent-log-worker.mjs) start together and each appends
// one entry at the log's current length. The log must stay valid: contiguous entries, each written
// whole by exactly one writer (no torn or merged file), one entry per writer that reported OK, a
// refusal (RNBC_LOG_CONFLICT) for every other, and no temporary name left behind.
//   node tools/broadcast/concurrent-log.check.mjs
import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKER = fileURLToPath(new URL('./concurrent-log-worker.mjs', import.meta.url));
const ROUNDS = 5;
const WRITERS = 8;
const run = (args) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'inherit'], env: {} });
  let out = '';
  child.stdout.on('data', (chunk) => (out += chunk));
  child.on('error', reject);
  child.on('close', (code) => (code === 0 ? resolve(out.trim()) : reject(new Error(`worker exited ${code}`))));
});

let failures = 0;
for (let round = 0; round < ROUNDS; round++) {
  const root = mkdtempSync(join(tmpdir(), 'rnnet-c2-concurrent-'));
  try {
    chmodSync(root, 0o700);
    const logDir = join(root, 'log');
    const start = join(root, 'start');
    mkdirSync(logDir, { mode: 0o700 });
    const workers = Array.from({ length: WRITERS }, (_, i) => run([WORKER, logDir, start, String(round * WRITERS + i)]));
    await new Promise((resolve) => setTimeout(resolve, 300));
    writeFileSync(start, '');
    const results = await Promise.all(workers);
    const names = readdirSync(logDir).sort();
    const ok = results.filter((r) => r === 'OK').length;
    const refused = results.filter((r) => r === 'RNBC_LOG_CONFLICT').length;
    const contiguous = names.every((n, i) => n === `${String(i).padStart(6, '0')}.json`);
    const whole = names.every((n) => {
      const text = readFileSync(join(logDir, n), 'utf8');
      return text.endsWith('}\n') && text.indexOf('\n') === text.length - 1 && JSON.parse(text).index === Number(n.slice(0, 6));
    });
    const digests = new Set(names.map((n) => JSON.parse(readFileSync(join(logDir, n), 'utf8')).authorizationDigest));
    const good = ok >= 1 && ok + refused === WRITERS && names.length === ok && contiguous && whole && digests.size === names.length;
    if (!good) {
      failures += 1;
      console.error(`round ${round}: ${ok} OK, ${refused} refused, files ${names.join(' ')}, results ${results.join(' ')}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
console.log(`concurrent log: ${ROUNDS - failures}/${ROUNDS} rounds of ${WRITERS} concurrent writers kept the log valid`);
process.exit(failures ? 1 : 0);
