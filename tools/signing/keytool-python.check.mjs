// RN-NET-03B2-C4: the key tool's sign-log reader (tools/keytool/signlog-store.mjs) and the
// independent Python reference (rnnet_keytool_reference.py --check-log) must give the same verdict
// on real sign-log directories, valid and corrupted. Run by tools/ci/offline-checks.sh inside the
// network namespace, without the test preload (which refuses subprocesses). Offline; it writes only
// to a disposable directory under the system temporary directory, with public fixture entries.
//   node tools/signing/keytool-python.check.mjs [/absolute/path/to/python3]
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { entryName, entryText, readSignLog } from '../keytool/signlog-store.mjs';

const python = process.argv[2] ?? 'python3';
const reference = fileURLToPath(new URL('../reference/rnnet_keytool_reference.py', import.meta.url));
const cases = JSON.parse(readFileSync(new URL('../../fixtures/keytool-c4/cases.json', import.meta.url), 'utf8'));
const SYSTEM = { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() };
const base = mkdtempSync(join(realpathSync(tmpdir()), 'rnnet-c4-py-'));

const js = (dir) => {
  try {
    readSignLog(dir, SYSTEM);
    return { ok: true, code: null };
  } catch (error) {
    return { ok: false, code: error.code ?? 'unexpected' };
  }
};
// A Python crash is a verdict too ("crashed"), so it can never pass as agreement.
const py = (dir) => {
  try {
    return JSON.parse(execFileSync(python, ['-I', '-B', reference, '--check-log', dir], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  } catch {
    return { ok: null, code: 'crashed' };
  }
};
const agree = (a, b) => a.ok === b.ok && a.code === b.code;

let n = 0;
const directory = (entries, change = () => {}) => {
  const dir = join(base, `log-${(n += 1)}`);
  mkdirSync(dir, { mode: 0o700 });
  chmodSync(dir, 0o700);
  entries.forEach((entry, i) => writeFileSync(join(dir, entryName(i)), entryText(entry), { mode: 0o600 }));
  change(dir);
  return dir;
};

const results = [];
try {
  // Every committed sign-log case, written as files.
  for (const c of cases.signlog) results.push([`fixture ${c.id}`, directory(c.entries), c.expect.ok]);
  // File-level damage to a valid log.
  const valid = cases.signlog.find((c) => c.id === 'resign-after-expired').entries;
  const damage = {
    temporary: (dir) => writeFileSync(join(dir, '.000007.json.tmp'), 'x', { mode: 0o600 }),
    gap: (dir) => unlinkSync(join(dir, entryName(2))),
    reordered: (dir) => {
      const a = readFileSync(join(dir, entryName(1)));
      writeFileSync(join(dir, entryName(1)), readFileSync(join(dir, entryName(2))));
      writeFileSync(join(dir, entryName(2)), a);
    },
    truncated: (dir) => writeFileSync(join(dir, entryName(3)), readFileSync(join(dir, entryName(3))).subarray(0, 40)),
    'no-newline': (dir) => writeFileSync(join(dir, entryName(3)), readFileSync(join(dir, entryName(3))).subarray(0, -1)),
    'pretty-printed': (dir) => writeFileSync(join(dir, entryName(0)), `${JSON.stringify(JSON.parse(readFileSync(join(dir, entryName(0)), 'utf8')), null, 1)}\n`),
    'rewritten-field': (dir) => {
      const entry = JSON.parse(readFileSync(join(dir, entryName(2)), 'utf8'));
      entry.blobSha256 = `sha256:${'9'.repeat(64)}`;
      writeFileSync(join(dir, entryName(2)), entryText(entry));
    },
    'duplicate-member': (dir) => writeFileSync(join(dir, entryName(0)), readFileSync(join(dir, entryName(0)), 'utf8').replace('{"address"', '{"address":"x","address"')),
    'stray-file': (dir) => writeFileSync(join(dir, 'notes.txt'), 'x', { mode: 0o600 }),
    'mode-0644': (dir) => chmodSync(join(dir, entryName(1)), 0o644),
    'directory-0755': (dir) => chmodSync(dir, 0o755),
    'last-removed': (dir) => unlinkSync(join(dir, entryName(valid.length - 1))),
    'oversized': (dir) => writeFileSync(join(dir, entryName(valid.length)), `${'x'.repeat(5000)}\n`, { mode: 0o600 }),
  };
  for (const [name, change] of Object.entries(damage)) results.push([`damaged ${name}`, directory(valid, change), null]);

  let failed = 0;
  for (const [name, dir, expected] of results) {
    const a = js(dir);
    const b = py(dir);
    const ok = agree(a, b) && (expected === null || a.ok === expected);
    if (!ok) {
      failed += 1;
      console.error(`keytool sign log: ${name}: JavaScript ${JSON.stringify(a)}, Python ${JSON.stringify(b)}`);
    }
  }
  // Negative controls: the comparison notices a disagreement and a crash, and damage is refused.
  if (agree({ ok: true, code: null }, { ok: false, code: 'RNKEY_SIGNLOG_INVALID' }) || agree({ ok: false, code: 'X' }, { ok: null, code: 'crashed' })) failed += 1;
  if (js(results.find(([name]) => name === 'damaged gap')[1]).ok) failed += 1;
  console.log(`keytool sign log: ${results.length - failed}/${results.length} directories agree (JavaScript and Python)`);
  process.exitCode = failed ? 1 : 0;
} finally {
  for (const name of readdirSync(base)) chmodSync(join(base, name), 0o700);
  rmSync(base, { recursive: true, force: true });
}
