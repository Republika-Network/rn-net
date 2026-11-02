// One writer of tools/broadcast/concurrent-log.check.mjs (RN-NET-03B2-C2): waits for the start
// file, then appends one RUN_STARTED entry for its own authorization digest at the log's current
// length, exactly as a broadcaster run does, and prints OK or the refusal code. Offline.
//   node tools/broadcast/concurrent-log-worker.mjs <log directory> <start file> <worker number>
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { checkLog, EntryKind, makeEntry } from '../../packages/chain-submit/src/index.mjs';
import { appendEntry, readLog } from '../submit/store.mjs';

const [, , logDir, startFile, worker] = process.argv;
const digest = `sha256:${createHash('sha256').update(`worker-${worker}`).digest('hex')}`;
while (!existsSync(startFile)) {
  // A short spin: the workers start together, so that their appends contend.
}
try {
  const log = readLog(logDir);
  checkLog(log);
  appendEntry(logDir, makeEntry(log.length, EntryKind.RUN_STARTED, { authorizationDigest: digest, network: 'xrpl:testnet', sender: 'rConcurrentWorker', sequence: '1', mode: 'submit' }));
  process.stdout.write('OK\n');
} catch (error) {
  process.stdout.write(`${error.code ?? 'ERROR'}\n`);
}
