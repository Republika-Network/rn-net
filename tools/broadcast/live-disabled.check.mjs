// The live entry points refuse as commands (RN-NET-03B2-C3; the C6 entry point, RN-NET-03B2-C6-LIVE;
// dual mode since RN-NET-03B2-C6-H3, review R1). Run by tools/ci/offline-checks.sh inside the network
// namespace, without the test preload (which refuses subprocesses).
//
// The decision is tools/broadcast/live-disabled.mjs (tested by tools/live-disabled.test.mjs without
// starting anything). This script reads the two C6 switches from the source FIRST, then:
//   - DISABLED (false, null): starts all five entry points, the C6 command included, each with
//     arguments naming files that do not exist; each must exit 3 with its LIVE_DISABLED code on
//     stderr and print nothing on stdout. The C6 command also runs with a probe (no network module
//     may be loaded) and an empty private evidence directory that must stay empty. Only then does it
//     report 5/5;
//   - ACTIVATED (true, the H3 directory): NEVER starts the C6 command; starts the other four, and
//     reports that C6 is ACTIVATED and not every entry point is disabled;
//   - anything else: UNREVIEWED CONFIGURATION, fails, starts nothing.
//   node tools/broadcast/live-disabled.check.mjs
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { C6_COMMAND, C6_ENTRY, C6_ENTRY_POINT, liveDisabledCheck } from './live-disabled.mjs';

const at = (path) => fileURLToPath(new URL(`../${path}`, import.meta.url));

function run(entry) {
  if (entry !== C6_ENTRY_POINT) {
    const child = spawnSync(process.execPath, [at(entry.path), ...entry.args], { encoding: 'utf8', env: {}, timeout: 10_000 });
    return { status: child.status, stdout: child.stdout, stderr: child.stderr };
  }
  // The disabled C6 command: an empty 0700 evidence directory to watch, and the exit probe on fd 3.
  const base = mkdtempSync(join(tmpdir(), 'rnnet-live-disabled-'));
  try {
    chmodSync(base, 0o700);
    const child = spawnSync(process.execPath, ['--import', at('broadcast/live-disabled-probe.mjs'), at(entry.path), ...entry.args, base], { encoding: 'utf8', env: {}, timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
    let networkModules = null;
    try {
      networkModules = JSON.parse(child.output[3]).networkModules;
    } catch {
      // no probe record: refused below
    }
    return { status: child.status, stdout: child.stdout, stderr: child.stderr, networkModules, evidenceUntouched: readdirSync(base).length === 0 };
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

const result = liveDisabledCheck({ commandSource: readFileSync(at(C6_COMMAND), 'utf8'), entrySource: readFileSync(at(C6_ENTRY), 'utf8'), run });
for (const line of result.lines) console.log(line);
process.exitCode = result.exitCode;
