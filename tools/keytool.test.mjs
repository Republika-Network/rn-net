// RN-NET-03B2-C4: the founder key tool (tools/keytool/), offline, with synthetic keys only.
//
// Every run uses a disposable directory under the system temporary directory, an injected
// terminal (scripted input), an injected file-system type and an injected network view. No real
// terminal, key, network or repository path is used. The keys come from the public B1 fixture
// labels, so their signatures can be compared with the committed B1 golden fixtures.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/canonical/src/index.mjs';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../packages/canonical/src/index.mjs';
import { INTENT_DIGEST_DOMAIN, intentDigest, makeIntent } from '../packages/tx-intent/src/index.mjs';
import { cases as s1Cases } from './s1/build-s1-cases.mjs';
import { fixtureKey } from '../signer/test/fixture-keys.mjs';
import { parseArguments, run } from './keytool/cli.mjs';
import { KeyToolError } from './keytool/errors.mjs';
import { checkNoNetwork, checkNotRealRoot } from './keytool/isolation.mjs';
import { ensurePrivateDirectory, checkPrivateDirectory } from './keytool/location.mjs';
import { readKeyFile } from './keytool/keystore.mjs';
import { decideSigning, EntryType, nextEntry, replaySignLog } from './keytool/signlog.mjs';
import { appendSignLog, entryName, entryText, readSignLog } from './keytool/signlog-store.mjs';
import { lineEditor, openTerminal } from './keytool/terminal.mjs';
import { LABELS } from './signing/build-b1-fixtures.mjs';
import { build as buildC4, FILE as C4_FILE } from './signing/build-c4-fixtures.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const B1 = join(ROOT, 'fixtures/signing-b1');
const golden = JSON.parse(readFileSync(join(B1, 'golden.json'), 'utf8'));
const XRPL = 'xrpl:testnet';
const SEP = 'evm:11155111';
const PURPOSE = 'genesis-proof-01';
const PASS = 'a synthetic C4 test passphrase, never real';
const INTENT = { [XRPL]: join(B1, 'xrpl-intent.json'), [SEP]: join(B1, 'sepolia-intent.json') };
const SIGNED = { [XRPL]: golden.signed.xrpl, [SEP]: golden.signed.sepolia };
const KEY = { [XRPL]: fixtureKey(XRPL, LABELS.xrpl), [SEP]: fixtureKey(SEP, LABELS.sepolia) };
const OTHER = { [XRPL]: fixtureKey(XRPL, LABELS.xrplOther), [SEP]: fixtureKey(SEP, LABELS.sepoliaOther) };
const LOOPBACK_ONLY = {
  readProc: (name) => ({ 'net/dev': 'Inter-|\n face |\n    lo: 0 0 0\n', 'net/route': '', 'net/ipv6_route': '', uid_map: '         0       1000          1\n' })[name],
  interfaces: () => [],
};

function workspace() {
  const base = mkdtempSync(join(realpathSync(tmpdir()), 'rnnet-c4-'));
  chmodSync(base, 0o700);
  const dirs = { base, keys: join(base, 'keys'), log: join(base, 'log'), out: join(base, 'out') };
  mkdirSync(dirs.out, { mode: 0o700 });
  return dirs;
}

/** A scripted environment. `inputs` are the lines the founder types, in order. */
function environment({ inputs = [], key = null, statfsType = 0xef53, getuid = () => process.getuid(), net = LOOPBACK_ONLY, fill = 0 } = {}) {
  const transcript = [];
  const prompts = [];
  const queue = [...inputs];
  return {
    transcript,
    prompts,
    left: () => queue.length,
    text: () => transcript.join(''),
    terminal: () => ({
      write: (t) => transcript.push(t),
      readLine: async ({ echo }) => {
        prompts.push({ echo, prompt: transcript.at(-1) });
        if (queue.length === 0) throw new KeyToolError('RNKEY_ABORTED', 'no scripted input left');
        return Buffer.from(queue.shift(), 'utf8');
      },
      close() {},
    }),
    out: (t) => transcript.push(t),
    now: () => new Date('2026-11-02T12:00:00Z'),
    system: { statfs: () => ({ type: statfsType }), getuid },
    net,
    source: key && {
      ed25519Seed: () => Uint8Array.from(key.secretKey),
      bytes: (n) => (n === 32 ? Uint8Array.from(key.secretKey) : new Uint8Array(n).fill(n + fill)),
    },
  };
}

const keygenArgs = (network, d) => ['keygen', '--network', network, '--purpose', PURPOSE, '--key-dir', d.keys, '--log-dir', d.log];
const signArgs = (network, d, { intent = INTENT[network], digest = SIGNED[network].intentDigest, extra = [] } = {}) => [
  'sign', '--network', network, '--key-dir', d.keys, '--log-dir', d.log, '--out-dir', d.out, '--intent', intent, '--approved-digest', digest, ...extra,
];
const last16 = (digest) => digest.slice(-16);

async function keygen(network, d, key = KEY[network], inputs = [PASS, PASS], fill = 0) {
  const e = environment({ inputs, key, fill });
  const exit = await run(keygenArgs(network, d), e);
  return { exit, e };
}
async function sign(network, d, opts = {}) {
  const digest = opts.digest ?? SIGNED[network].intentDigest;
  const e = environment({ inputs: opts.inputs ?? [last16(digest), PASS], ...(opts.env ?? {}) });
  const exit = await run(signArgs(network, d, { ...opts, digest }), e);
  return { exit, e };
}
const refusedWith = (e, code) => assert.match(e.text(), new RegExp(`refused: ${code}\\b`), e.text());
const files = (dir) => {
  try {
    return readdirSync(dir).sort();
  } catch {
    return [];
  }
};
const mode = (path) => statSync(path).mode & 0o777;

// Secret canaries: the key bytes in every encoding a leak might take, and the passphrase.
function assertNoSecrets(d, e, keys = Object.values(KEY)) {
  const needles = [Buffer.from(PASS, 'utf8')];
  for (const key of keys) {
    const raw = Buffer.from(key.secretKey);
    needles.push(raw, Buffer.from(raw.toString('hex')), Buffer.from(raw.toString('hex').toUpperCase()), Buffer.from(raw.toString('base64')), Buffer.from(raw.toString('base64url')));
  }
  const haystacks = [['transcript', Buffer.from(e.text(), 'utf8')]];
  const walk = (dir) => {
    for (const name of files(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else haystacks.push([path, readFileSync(path)]);
    }
  };
  walk(d.base);
  for (const [where, bytes] of haystacks) for (const needle of needles) assert.equal(bytes.indexOf(needle), -1, `a secret canary appears in ${where}`);
}

// --- arguments, terminal and isolation -------------------------------------------------------------

test('arguments: no passphrase option, every option once, absolute paths, known networks only', () => {
  const ok = parseArguments(['show', '--network', XRPL, '--key-dir', '/x']);
  assert.equal(ok.command, 'show');
  const usage = (argv) => {
    try {
      parseArguments(argv);
    } catch (error) {
      return error.code;
    }
    return null;
  };
  for (const flag of ['--passphrase', '--password', '--secret', '--seed', '--key', '--pass']) assert.equal(usage(['keygen', flag, 'x', '--network', XRPL]), 'RNKEY_USAGE', flag);
  assert.equal(usage(['keygen', '--network', XRPL, '--network', XRPL, '--purpose', PURPOSE, '--key-dir', '/a', '--log-dir', '/b']), 'RNKEY_USAGE');
  assert.equal(usage(['keygen', '--network', 'evm:1', '--purpose', PURPOSE, '--key-dir', '/a', '--log-dir', '/b']), 'RNKEY_USAGE');
  assert.equal(usage(['keygen', '--network', XRPL, '--purpose', 'other', '--key-dir', '/a', '--log-dir', '/b']), 'RNKEY_USAGE');
  assert.equal(usage(['keygen', '--network', XRPL, '--purpose', PURPOSE, '--key-dir', '/a']), 'RNKEY_USAGE');
  assert.equal(usage(['keygen', '--network', XRPL, '--purpose', PURPOSE, '--key-dir', '--log-dir', '/b']), 'RNKEY_USAGE');
  assert.equal(usage(['sign', '--network', XRPL, '--key-dir', '/a', '--log-dir', '/b', '--out-dir', '/c', '--intent', '/i', '--approved-digest', `sha256:${'A'.repeat(64)}`]), 'RNKEY_USAGE');
  assert.equal(usage(['export', '--network', XRPL]), 'RNKEY_USAGE');
  assert.equal(usage([]), 'RNKEY_USAGE');
});

test('usage errors exit 2 and print no prompt', async () => {
  const e = environment();
  assert.equal(await run(['keygen', '--passphrase', PASS], e), 2);
  assert.equal(e.prompts.length, 0);
  assert.doesNotMatch(e.text(), new RegExp(PASS));
});

test('terminal: refused without an interactive terminal', () => {
  const tryOpen = (io) => {
    try {
      openTerminal(io).close();
      return 'opened';
    } catch (error) {
      return error.code;
    }
  };
  assert.equal(tryOpen({ stdin: { isTTY: false }, stdout: { isTTY: true } }), 'RNKEY_NOT_INTERACTIVE');
  assert.equal(tryOpen({ stdin: { isTTY: true }, stdout: { isTTY: false } }), 'RNKEY_NOT_INTERACTIVE');
  assert.equal(tryOpen({ stdin: { isTTY: undefined }, stdout: { isTTY: undefined } }), 'RNKEY_NOT_INTERACTIVE');
  // The test runner itself is not interactive: the production defaults refuse too, unless this
  // happens to run from a real terminal.
  const outcome = tryOpen(undefined);
  assert.ok(['RNKEY_NOT_INTERACTIVE', 'opened'].includes(outcome));
  if (!process.stdin.isTTY) assert.equal(outcome, 'RNKEY_NOT_INTERACTIVE');
});

test('terminal line editing: Enter, Backspace over UTF-8, aborts and refusals; no echo unless asked', () => {
  const feed = (bytes, echo = false) => {
    const echoed = [];
    const editor = lineEditor({ echo, write: (b) => echoed.push(Buffer.from(b)) });
    for (const chunk of bytes) {
      const result = editor.push(Buffer.from(chunk));
      if (result) return { ...result, echoed: Buffer.concat(echoed).toString('utf8') };
    }
    return { pending: true, echoed: Buffer.concat(echoed).toString('utf8') };
  };
  assert.equal(feed(['abc\r']).value.toString(), 'abc');
  assert.equal(feed(['ab', 'c\n']).value.toString(), 'abc');
  assert.equal(feed(['abé\x7f\x7fc\r']).value.toString(), 'ac');
  assert.equal(feed(['\x7f\x7fx\r']).value.toString(), 'x');
  assert.equal(feed(['secret\r']).echoed, '', 'nothing is echoed without echo');
  assert.equal(feed(['ab\r'], true).echoed, 'ab');
  assert.equal(feed(['ab\x03']).error.code, 'RNKEY_ABORTED');
  assert.equal(feed(['\x04']).error.code, 'RNKEY_ABORTED');
  assert.equal(feed(['a\x1b[A\r']).error.code, 'RNKEY_INPUT_INVALID');
  assert.equal(feed(['a\tb\r']).error.code, 'RNKEY_INPUT_INVALID');
  assert.equal(feed(['x'.repeat(1025)]).error.code, 'RNKEY_INPUT_INVALID');
  assert.equal(feed(['x'.repeat(1024), '\r']).value.length, 1024);
  assert.ok(feed(['abc']).pending);
});

test('isolation: loopback only, no routes off loopback, never real root; read failures refuse', () => {
  const code = (fn) => {
    try {
      fn();
    } catch (error) {
      return error.code;
    }
    return null;
  };
  assert.equal(code(() => checkNoNetwork(LOOPBACK_ONLY)), null);
  const net = (over) => ({ ...LOOPBACK_ONLY, readProc: (n) => (n in over ? over[n] : LOOPBACK_ONLY.readProc(n)), interfaces: over.interfaces ?? LOOPBACK_ONLY.interfaces });
  assert.equal(code(() => checkNoNetwork(net({ 'net/dev': 'h\nh\n lo: 0\n eth0: 0\n' }))), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNoNetwork(net({ 'net/dev': 'h\nh\n' }))), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNoNetwork(net({ interfaces: () => ['lo', 'wlan0'] }))), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNoNetwork(net({ 'net/route': 'Iface\tDestination\neth0\t00000000\n' }))), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNoNetwork(net({ 'net/ipv6_route': '00 00 00 00 00 00 00 00 00 eth0\n' }))), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNoNetwork(net({ 'net/ipv6_route': '00 00 00 00 00 00 00 00 00       lo\n' }))), null);
  assert.equal(code(() => checkNoNetwork({ ...LOOPBACK_ONLY, readProc: () => { throw new Error('EACCES'); } })), 'RNKEY_NETWORK_PRESENT');
  assert.equal(code(() => checkNotRealRoot(() => 0, net({ uid_map: '0 0 4294967295\n' }))), 'RNKEY_REAL_ROOT');
  assert.equal(code(() => checkNotRealRoot(() => 0, LOOPBACK_ONLY)), null);
  assert.equal(code(() => checkNotRealRoot(() => 1000, net({ uid_map: '0 0 4294967295\n' }))), null);
});

test('keygen and sign refuse before any prompt when a network interface is present', async () => {
  const d = workspace();
  const eth = { ...LOOPBACK_ONLY, readProc: (n) => (n === 'net/dev' ? 'h\nh\n lo: 0\n eth0: 0\n' : LOOPBACK_ONLY.readProc(n)) };
  const e = environment({ inputs: [PASS, PASS], key: KEY[XRPL], net: eth });
  assert.equal(await run(keygenArgs(XRPL, d), e), 1);
  refusedWith(e, 'RNKEY_NETWORK_PRESENT');
  assert.equal(e.prompts.length, 0);
  assert.deepEqual(files(d.keys), []);
  const s = environment({ inputs: ['x', PASS], net: eth });
  assert.equal(await run(signArgs(XRPL, d), s), 1);
  refusedWith(s, 'RNKEY_NETWORK_PRESENT');
  assert.equal(s.prompts.length, 0);
});

// --- storage locations -----------------------------------------------------------------------------

test('locations: absolute, normalized, real, not /mnt, not in a repository, ext4, owned, 0700', () => {
  const d = workspace();
  const system = { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() };
  const code = (fn) => {
    try {
      fn();
    } catch (error) {
      return error.code;
    }
    return null;
  };
  mkdirSync(join(d.base, 'ok'), { mode: 0o700 });
  assert.equal(code(() => checkPrivateDirectory(join(d.base, 'ok'), 'dir', system)), null);
  for (const bad of ['relative/dir', `${d.base}/ok/`, `${d.base}/./ok`, `${d.base}/x/../ok`, `${d.base}//ok`, '/', '/mnt/c/Users/x', '/mnt', '/mnt/wsl/keys']) {
    assert.equal(code(() => checkPrivateDirectory(bad, 'dir', system)), 'RNKEY_LOCATION', bad);
  }
  // A symbolic link anywhere in the path.
  symlinkSync(join(d.base, 'ok'), join(d.base, 'link'));
  assert.equal(code(() => checkPrivateDirectory(join(d.base, 'link'), 'dir', system)), 'RNKEY_LOCATION');
  // Inside a worktree (.git file or directory) or a bare repository.
  for (const [name, make] of [['wt-file', (p) => writeFileSync(join(p, '.git'), 'gitdir: /elsewhere\n')], ['wt-dir', (p) => mkdirSync(join(p, '.git'))], ['bare', (p) => { writeFileSync(join(p, 'HEAD'), 'ref: refs/heads/main\n'); mkdirSync(join(p, 'objects')); mkdirSync(join(p, 'refs')); }]]) {
    const repo = join(d.base, name);
    mkdirSync(join(repo, 'inner'), { recursive: true, mode: 0o700 });
    chmodSync(repo, 0o700);
    make(repo);
    assert.equal(code(() => checkPrivateDirectory(join(repo, 'inner'), 'dir', system)), 'RNKEY_LOCATION', name);
  }
  // The real repository this test runs in is refused too.
  assert.equal(code(() => checkPrivateDirectory(join(ROOT, 'fixtures'), 'dir', system)), 'RNKEY_LOCATION');
  // Not ext4 (drvfs, 9p, tmpfs, overlay), statfs failing, wrong owner, wrong mode.
  for (const type of [0x01021994, 0x01021997, 0x794c7630, 0x65735546, 0]) assert.equal(code(() => checkPrivateDirectory(join(d.base, 'ok'), 'dir', { ...system, statfs: () => ({ type }) })), 'RNKEY_LOCATION');
  assert.equal(code(() => checkPrivateDirectory(join(d.base, 'ok'), 'dir', { ...system, statfs: () => { throw new Error('ENOSYS'); } })), 'RNKEY_LOCATION');
  assert.equal(code(() => checkPrivateDirectory(join(d.base, 'ok'), 'dir', { ...system, getuid: () => process.getuid() + 1 })), 'RNKEY_LOCATION');
  for (const m of [0o750, 0o755, 0o600, 0o777, 0o1700]) {
    chmodSync(join(d.base, 'ok'), m);
    assert.equal(code(() => checkPrivateDirectory(join(d.base, 'ok'), 'dir', system)), (m & 0o777) === 0o700 ? null : 'RNKEY_LOCATION', m.toString(8));
  }
  chmodSync(join(d.base, 'ok'), 0o700);
  writeFileSync(join(d.base, 'file'), '', { mode: 0o700 });
  assert.equal(code(() => checkPrivateDirectory(join(d.base, 'file'), 'dir', system)), 'RNKEY_LOCATION');
  // ensurePrivateDirectory makes one level only, 0700, and never changes an existing directory.
  ensurePrivateDirectory(join(d.base, 'made'), 'dir', system);
  assert.equal(mode(join(d.base, 'made')), 0o700);
  assert.equal(code(() => ensurePrivateDirectory(join(d.base, 'a', 'b'), 'dir', system)), 'RNKEY_LOCATION');
  mkdirSync(join(d.base, 'open'), { mode: 0o755 });
  chmodSync(join(d.base, 'open'), 0o755);
  assert.equal(code(() => ensurePrivateDirectory(join(d.base, 'open'), 'dir', system)), 'RNKEY_LOCATION');
  assert.equal(mode(join(d.base, 'open')), 0o755);
});

test('the key, log and output directories must be separate', async () => {
  const d = workspace();
  for (const [keys, log] of [[d.keys, d.keys], [d.keys, join(d.keys, 'log')], [join(d.log, 'keys'), d.log]]) {
    const e = environment({ inputs: [PASS, PASS], key: KEY[XRPL] });
    assert.equal(await run(['keygen', '--network', XRPL, '--purpose', PURPOSE, '--key-dir', keys, '--log-dir', log], e), 1);
    refusedWith(e, 'RNKEY_LOCATION');
    assert.equal(e.prompts.length, 0);
  }
  const e = environment({ inputs: ['x', PASS] });
  assert.equal(await run(['sign', '--network', XRPL, '--key-dir', d.keys, '--log-dir', d.log, '--out-dir', d.log, '--intent', INTENT[XRPL], '--approved-digest', SIGNED[XRPL].intentDigest], e), 1);
  refusedWith(e, 'RNKEY_LOCATION');
});

test('keygen refuses a non-ext4 or repository location before asking for a passphrase', async () => {
  const d = workspace();
  const e = environment({ inputs: [PASS, PASS], key: KEY[XRPL], statfsType: 0x01021997 });
  assert.equal(await run(keygenArgs(XRPL, d), e), 1);
  refusedWith(e, 'RNKEY_LOCATION');
  assert.equal(e.prompts.length, 0);
  const inRepo = { keys: join(ROOT, 'fixtures', 'c4-never-keys'), log: join(d.base, 'log') };
  const r = environment({ inputs: [PASS, PASS], key: KEY[XRPL] });
  assert.equal(await run(keygenArgs(XRPL, inRepo), r), 1);
  refusedWith(r, 'RNKEY_LOCATION');
  assert.throws(() => statSync(inRepo.keys), /ENOENT/);
});

// --- key generation ----------------------------------------------------------------------------------

test('keygen: one encrypted, bound key file per network, 0600 in a 0700 directory; public KEY_CREATED entry', async () => {
  const d = workspace();
  for (const network of [XRPL, SEP]) {
    const { exit, e } = await keygen(network, d);
    assert.equal(exit, 0, e.text());
    // Two passphrase prompts, both without echo.
    assert.deepEqual(e.prompts.map((p) => p.echo), [false, false]);
    assert.match(e.text(), new RegExp(`network: +${network}`));
    assert.match(e.text(), new RegExp(`purpose: +${PURPOSE}`));
    assert.match(e.text(), /Nothing is signed/);
    assertNoSecrets(d, e);
  }
  assert.equal(mode(d.keys), 0o700);
  assert.equal(mode(d.log), 0o700);
  assert.deepEqual(files(d.keys), ['sepolia.key.json', 'xrpl-testnet.key.json']);
  for (const name of files(d.keys)) assert.equal(mode(join(d.keys, name)), 0o600);
  const entries = readSignLog(d.log, { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() });
  assert.deepEqual(entries.map((x) => x.type), ['KEY_CREATED', 'KEY_CREATED']);
  for (const [i, network] of [[0, XRPL], [1, SEP]]) {
    const stored = readKeyFile(d.keys, network, { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() });
    assert.equal(stored.file.format, 'rnnet.testnet-key-file.v1');
    assert.equal(stored.file.network, network);
    assert.equal(stored.file.purpose, PURPOSE);
    assert.deepEqual(Object.keys(stored.file.kdf).sort(), ['N', 'name', 'p', 'r', 'salt']);
    assert.equal(stored.file.kdf.N, 131072);
    assert.equal(entries[i].address, stored.file.address);
    assert.equal(entries[i].publicKey, stored.file.publicKey);
    assert.equal(entries[i].keyFileSha256, stored.sha256);
    assert.equal(entries[i].address, network === XRPL ? 'rPMhDyWFH1uu1kMwheshzpaMouWr75XRa2' : '0x57db031993583fe0cbbf42dbfcf6489e0fb70b86');
  }
  for (const name of files(d.log)) assert.equal(mode(join(d.log, name)), 0o600);
  // show prints public metadata only and needs no terminal.
  const s = environment();
  s.terminal = () => assert.fail('show must not open the terminal');
  assert.equal(await run(['show', '--network', XRPL, '--key-dir', d.keys, '--log-dir', d.log], s), 0);
  assert.match(s.text(), /registered: yes/);
  assert.doesNotMatch(s.text(), /ciphertext|salt|tag/);
  assertNoSecrets(d, s);
});

test('keygen refusals leave nothing behind: short or different passphrases, abort', async () => {
  for (const [inputs, codeWanted] of [
    [['x'.repeat(19), 'x'.repeat(19)], 'RNKEY_PASSPHRASE_SHORT'],
    [[' '.repeat(5), PASS], 'RNKEY_PASSPHRASE_SHORT'],
    [[PASS, `${PASS}!`], 'RNKEY_PASSPHRASE_MISMATCH'],
    [[PASS], 'RNKEY_ABORTED'],
    [[], 'RNKEY_ABORTED'],
  ]) {
    const d = workspace();
    const { exit, e } = await keygen(XRPL, d, KEY[XRPL], inputs);
    assert.equal(exit, 1);
    refusedWith(e, codeWanted);
    assert.deepEqual(files(d.keys), [], codeWanted);
    assert.deepEqual(files(d.log), [], codeWanted);
    assert.doesNotMatch(e.text(), /x{19}/);
  }
});

test('keygen never overwrites: an existing file, a recorded key or a leftover partial file', async () => {
  const d = workspace();
  assert.equal((await keygen(XRPL, d)).exit, 0);
  const before = readFileSync(join(d.keys, 'xrpl-testnet.key.json'));
  const again = await keygen(XRPL, d, OTHER[XRPL]);
  assert.equal(again.exit, 1);
  refusedWith(again.e, 'RNKEY_KEY_EXISTS');
  assert.equal(again.e.prompts.length, 0);
  assert.deepEqual(readFileSync(join(d.keys, 'xrpl-testnet.key.json')), before);
  // The file removed, but the log still records a key for this network and purpose.
  rmSync(join(d.keys, 'xrpl-testnet.key.json'));
  const recorded = await keygen(XRPL, d, OTHER[XRPL]);
  refusedWith(recorded.e, 'RNKEY_KEY_EXISTS');
  // A leftover partial file, with and without the final name.
  const p = workspace();
  ensurePrivateDirectory(p.keys, 'k');
  writeFileSync(join(p.keys, '.sepolia.key.json.partial'), 'x', { mode: 0o600 });
  const partial = await keygen(SEP, p);
  refusedWith(partial.e, 'RNKEY_PARTIAL_FILE');
  assert.match(partial.e.text(), /before the file was complete/);
  const q = workspace();
  assert.equal((await keygen(SEP, q)).exit, 0);
  linkSync(join(q.keys, 'sepolia.key.json'), join(q.keys, '.sepolia.key.json.partial'));
  const s = environment();
  assert.equal(await run(['show', '--network', SEP, '--key-dir', q.keys], s), 1);
  refusedWith(s, 'RNKEY_PARTIAL_FILE');
  assert.match(s.text(), /after the file was complete/);
});

// --- signing ---------------------------------------------------------------------------------------

test('sign: full digest shown, last 16 typed, passphrase without echo; bytes equal the B1 golden fixtures', async () => {
  for (const network of [XRPL, SEP]) {
    const d = workspace();
    assert.equal((await keygen(network, d)).exit, 0);
    const { exit, e } = await sign(network, d);
    assert.equal(exit, 0, e.text());
    const digest = SIGNED[network].intentDigest;
    const shown = e.transcript.slice(0, e.transcript.findIndex((t) => /Type the last 16/.test(t))).join('');
    assert.ok(shown.includes(digest), 'the whole digest is shown before the confirmation');
    assert.ok(shown.includes(digest.slice(7).match(/.{4}/g).join(' ')));
    assert.match(shown, new RegExp(`network: +${network}`));
    assert.match(shown, new RegExp(`purpose: +${PURPOSE}`));
    assert.match(shown, network === XRPL ? /Sequence: +1000001[\s\S]*Fee \(drops\)[\s\S]*LastLedgerSequence/ : /nonce:[\s\S]*maxFeePerGas/);
    assert.deepEqual(e.prompts.map((p) => p.echo), [true, false], 'confirmation echoed, passphrase not');
    assert.match(e.prompts[0].prompt, /last 16 characters/);
    const [name] = files(d.out);
    assert.equal(mode(join(d.out, name)), 0o600);
    const output = JSON.parse(readFileSync(join(d.out, name), 'utf8'));
    assert.equal(output.signedTransaction, SIGNED[network].signedTransaction);
    assert.equal(output.blobSha256, SIGNED[network].blobSha256);
    assert.equal(output.transactionHash, SIGNED[network].transactionHash);
    assert.equal(output.verification.outcome, 'PASS');
    const entries = readSignLog(d.log, { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() });
    assert.deepEqual(entries.map((x) => x.type), ['KEY_CREATED', 'SIGNING', 'SIGNED']);
    assert.equal(entries[2].blobSha256, output.blobSha256);
    assert.equal(entries[2].transactionHash, output.transactionHash);
    assert.equal(entries[1].intentDigest, digest);
    assertNoSecrets(d, e);
  }
});

test('sign: the typed confirmation must be exactly the last 16 characters; nothing is logged otherwise', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  const digest = SIGNED[XRPL].intentDigest;
  const hex = digest.slice(7);
  for (const typed of [hex.slice(-15), `${hex.slice(-16)} `, ` ${hex.slice(-16)}`, hex.slice(-16).toUpperCase(), hex.slice(-17, -1), hex, digest, hex.slice(0, 16), '']) {
    const { exit, e } = await sign(XRPL, d, { inputs: [typed, PASS] });
    assert.equal(exit, 1);
    refusedWith(e, 'RNKEY_CONFIRMATION_MISMATCH');
    assert.equal(e.prompts.length, 1, 'no passphrase prompt after a failed confirmation');
  }
  assert.deepEqual(files(d.log), ['000000.json']);
  assert.deepEqual(files(d.out), []);
});

test('sign: the approved digest must equal the recomputed one exactly, before any prompt', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  const digest = SIGNED[XRPL].intentDigest;
  for (const wrong of [`${digest.slice(0, -1)}${digest.at(-1) === '0' ? '1' : '0'}`, SIGNED[SEP].intentDigest]) {
    const { exit, e } = await sign(XRPL, d, { digest: wrong, inputs: [last16(wrong), PASS] });
    assert.equal(exit, 1);
    refusedWith(e, 'RNTX_INTENT_DIGEST_MISMATCH');
    assert.equal(e.prompts.length, 0);
  }
  assert.deepEqual(files(d.log), ['000000.json']);
});

test('sign: wrong passphrase, network or purpose; unregistered or tampered key files', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  await keygen(SEP, d);
  // Wrong passphrase: refused after the confirmation, with no SIGNING entry.
  const wrong = await sign(XRPL, d, { inputs: [last16(SIGNED[XRPL].intentDigest), 'another passphrase, also long'] });
  refusedWith(wrong.e, 'RNTX_KEYFILE_DECRYPT');
  assert.doesNotMatch(wrong.e.text(), /another passphrase/);
  assert.equal(readSignLog(d.log).length, 2);
  // The intent's network differs from --network.
  const net = environment({ inputs: ['x', PASS] });
  assert.equal(await run(signArgs(XRPL, d, { intent: INTENT[SEP], digest: SIGNED[SEP].intentDigest }), net), 2);
  refusedWith(net, 'RNKEY_USAGE');
  // A key file for another sender (another network's key cannot even be read for this network).
  const o = workspace();
  await keygen(XRPL, o, OTHER[XRPL]);
  const other = await sign(XRPL, o);
  refusedWith(other.e, 'RNKEY_KEY_MISMATCH');
  assert.equal(other.e.prompts.length, 0);
  // A key file the sign log does not record (a log from another key generation).
  const u = workspace();
  await keygen(XRPL, u);
  const v = workspace();
  await keygen(XRPL, v, KEY[XRPL], [PASS, PASS], 1); // the same key, another salt: another key file
  rmSync(u.log, { recursive: true });
  mkdirSync(u.log, { mode: 0o700 });
  for (const name of files(v.log)) writeFileSync(join(u.log, name), readFileSync(join(v.log, name)), { mode: 0o600 });
  const unregistered = await sign(XRPL, u);
  refusedWith(unregistered.e, 'RNKEY_KEY_NOT_REGISTERED');
  assert.equal(unregistered.e.prompts.length, 0);
  // Tampered key file: a changed public field is no longer the registered file.
  const t = workspace();
  await keygen(XRPL, t);
  const path = join(t.keys, 'xrpl-testnet.key.json');
  const file = JSON.parse(readFileSync(path, 'utf8'));
  file.createdAt = '2026-11-03T00:00:00Z';
  chmodSync(path, 0o600);
  writeFileSync(path, `${canonicalize(file)}\n`);
  const tampered = await sign(XRPL, t);
  refusedWith(tampered.e, 'RNKEY_KEY_NOT_REGISTERED');
  // Not canonical, wrong mode, a symbolic link.
  writeFileSync(path, `${JSON.stringify(file, null, 1)}\n`);
  refusedWith((await sign(XRPL, t)).e, 'RNKEY_FILE_INVALID');
  writeFileSync(path, `${canonicalize(file)}\n`);
  chmodSync(path, 0o644);
  refusedWith((await sign(XRPL, t)).e, 'RNKEY_FILE_INVALID');
  rmSync(path);
  symlinkSync(join(d.keys, 'xrpl-testnet.key.json'), path);
  refusedWith((await sign(XRPL, t)).e, 'RNKEY_FILE_INVALID');
});

test('sign: replay protection: the same digest again, another intent, another sequence', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  assert.equal((await sign(XRPL, d)).exit, 0);
  const again = await sign(XRPL, d);
  assert.equal(again.exit, 1);
  refusedWith(again.e, 'RNTX_ALREADY_SIGNED');
  assert.equal(again.e.prompts.length, 0, 'no prompt: the blob already written is the output');
  assert.match(again.e.text(), /The signed output is/);
  const base = JSON.parse(readFileSync(INTENT[XRPL], 'utf8'));
  for (const change of [(tx) => { tx.LastLedgerSequence += 20; }, (tx) => { tx.Sequence += 1; tx.LastLedgerSequence += 1; }, (tx) => { tx.Fee = '15'; }]) {
    const intent = structuredClone(base);
    change(intent.transaction);
    const path = join(d.base, `intent-${Math.random().toString(16).slice(2)}.json`);
    writeFileSync(path, canonicalize(makeIntent(intent)));
    const digest = intentDigest(intent);
    const r = await sign(XRPL, d, { intent: path, digest });
    assert.equal(r.exit, 1);
    refusedWith(r.e, 'RNTX_SEQUENCE_UNRESOLVED');
    assert.equal(r.e.prompts.length, 0);
  }
  assert.equal(readSignLog(d.log).length, 3);
});

test('sign: an XRPL re-sign needs an EXPIRED status record for the latest blob, used once', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  await sign(XRPL, d);
  const first = JSON.parse(readFileSync(join(d.out, files(d.out)[0]), 'utf8'));
  const base = JSON.parse(readFileSync(INTENT[XRPL], 'utf8'));
  const intentWith = (lls) => {
    const intent = structuredClone(base);
    intent.transaction.LastLedgerSequence = lls;
    const path = join(d.base, `intent-${lls}.json`);
    writeFileSync(path, canonicalize(makeIntent(intent)));
    return { path, digest: intentDigest(intent) };
  };
  const status = (transactionHash, extra = {}) => {
    const record = { format: 'rnnet.submission-status.v1', authorizationDigest: `sha256:${'1'.repeat(64)}`, network: XRPL, attemptEntry: `sha256:${'2'.repeat(64)}`, transactionHash, finding: 'EXPIRED', code: null, liveReportSha256: null, live: null, providers: [], recordedAt: '2026-11-02T12:30:00Z', ...extra };
    const path = join(d.base, `status-${Math.random().toString(16).slice(2)}.json`);
    writeFileSync(path, `${canonicalize(record)}\n`);
    return path;
  };
  const second = intentWith(1000040);
  // Not EXPIRED, or not for the blob that was signed: refused before any prompt.
  for (const bad of [status(first.transactionHash, { finding: 'INCLUDED' }), status('A'.repeat(64)), status(first.transactionHash, { network: SEP })]) {
    const r = await sign(XRPL, d, { intent: second.path, digest: second.digest, extra: ['--resign-basis', bad] });
    refusedWith(r.e, 'RNKEY_RESIGN_BASIS_INVALID');
    assert.equal(r.e.prompts.length, 0);
  }
  const basis = status(first.transactionHash);
  const ok = await sign(XRPL, d, { intent: second.path, digest: second.digest, extra: ['--resign-basis', basis] });
  assert.equal(ok.exit, 0, ok.e.text());
  assert.match(ok.e.text(), /sign-log action: RESIGN/);
  assert.deepEqual(readSignLog(d.log).map((x) => x.type), ['KEY_CREATED', 'SIGNING', 'SIGNED', 'RESIGN_BASIS', 'SIGNING', 'SIGNED']);
  // The same status record cannot authorize a third intent.
  const third = intentWith(1000060);
  const reused = await sign(XRPL, d, { intent: third.path, digest: third.digest, extra: ['--resign-basis', basis] });
  refusedWith(reused.e, 'RNKEY_RESIGN_BASIS_INVALID');
  // The first intent cannot come back.
  refusedWith((await sign(XRPL, d)).e, 'RNTX_ALREADY_SIGNED');
});

test('sign: Sepolia has no re-sign or replacement path', async () => {
  const d = workspace();
  await keygen(SEP, d);
  await sign(SEP, d);
  const base = JSON.parse(readFileSync(INTENT[SEP], 'utf8'));
  const intent = structuredClone(base);
  intent.transaction.maxPriorityFeePerGas = '0x1';
  const path = join(d.base, 'replacement.json');
  writeFileSync(path, canonicalize(makeIntent(intent)));
  const r = await sign(SEP, d, { intent: path, digest: intentDigest(intent) });
  refusedWith(r.e, 'RNTX_SEQUENCE_UNRESOLVED');
});

// --- crash recovery and corrupted history --------------------------------------------------------------

const SYSTEM = { statfs: () => ({ type: 0xef53 }), getuid: () => process.getuid() };

test('crash after SIGNING: the same digest is completed once, to the same bytes', async () => {
  for (const network of [XRPL, SEP]) {
    const d = workspace();
    await keygen(network, d);
    const entries = readSignLog(d.log, SYSTEM);
    const stored = readKeyFile(d.keys, network, SYSTEM);
    const sequence = network === XRPL ? '1000001' : String(BigInt(JSON.parse(readFileSync(INTENT[network], 'utf8')).transaction.nonce));
    appendSignLog(d.log, entries, nextEntry(entries, EntryType.SIGNING, { network, purpose: PURPOSE, address: stored.file.address, sequence, intentDigest: SIGNED[network].intentDigest }, '2026-11-02T12:00:00Z'), SYSTEM);
    // Another intent is refused while that one is pending.
    const base = JSON.parse(readFileSync(INTENT[network], 'utf8'));
    if (network === XRPL) base.transaction.LastLedgerSequence += 5;
    else base.transaction.maxPriorityFeePerGas = '0x1';
    const path = join(d.base, 'other.json');
    writeFileSync(path, canonicalize(makeIntent(base)));
    refusedWith((await sign(network, d, { intent: path, digest: intentDigest(base) })).e, 'RNTX_SEQUENCE_UNRESOLVED');
    const done = await sign(network, d);
    assert.equal(done.exit, 0, done.e.text());
    assert.match(done.e.text(), /sign-log action: COMPLETE/);
    const output = JSON.parse(readFileSync(join(d.out, files(d.out)[0]), 'utf8'));
    assert.equal(output.signedTransaction, SIGNED[network].signedTransaction);
    assert.deepEqual(readSignLog(d.log, SYSTEM).map((x) => x.type), ['KEY_CREATED', 'SIGNING', 'SIGNED']);
  }
});

test('crash after SIGNED, before the output link: the staged copy is checked and linked, without signing', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  await sign(XRPL, d);
  const [name] = files(d.out);
  // Simulate the stop: the final name missing, only the staged (partial) name present.
  linkSync(join(d.out, name), join(d.out, `.${name}.partial`));
  unlinkSync(join(d.out, name));
  const r = await sign(XRPL, d);
  refusedWith(r.e, 'RNTX_ALREADY_SIGNED');
  assert.equal(r.e.prompts.length, 0);
  assert.deepEqual(files(d.out), [name]);
  assert.equal(JSON.parse(readFileSync(join(d.out, name), 'utf8')).signedTransaction, SIGNED[XRPL].signedTransaction);
  // A staged copy with other bytes is refused, never linked.
  linkSync(join(d.out, name), join(d.d ?? d.base, 'keep'));
  unlinkSync(join(d.out, name));
  const forged = JSON.parse(readFileSync(join(d.base, 'keep'), 'utf8'));
  forged.blobSha256 = `sha256:${'0'.repeat(64)}`;
  writeFileSync(join(d.out, `.${name}.partial`), `${canonicalize(forged)}\n`, { mode: 0o600 });
  refusedWith((await sign(XRPL, d)).e, 'RNKEY_OUTPUT_CONFLICT');
  assert.deepEqual(files(d.out), [`.${name}.partial`]);
  // Review C4-3: other signed bytes with the SIGNED entry's hashes copied in are refused too.
  const swapped = JSON.parse(readFileSync(join(d.base, 'keep'), 'utf8'));
  swapped.signedTransaction = `DEADBEEF${swapped.signedTransaction.slice(8)}`;
  writeFileSync(join(d.out, `.${name}.partial`), `${canonicalize(swapped)}\n`, { mode: 0o600 });
  refusedWith((await sign(XRPL, d)).e, 'RNKEY_OUTPUT_CONFLICT');
  // And so is a pretty-printed copy of the right output.
  writeFileSync(join(d.out, `.${name}.partial`), `${JSON.stringify(JSON.parse(readFileSync(join(d.base, 'keep'), 'utf8')), null, 1)}\n`, { mode: 0o600 });
  refusedWith((await sign(XRPL, d)).e, 'RNKEY_OUTPUT_CONFLICT');
  assert.deepEqual(files(d.out), [`.${name}.partial`]);
});

test('keygen refuses a clock earlier than the sign log before any key exists (review C4-4)', async () => {
  const d = workspace();
  assert.equal((await keygen(XRPL, d)).exit, 0);
  const e = environment({ inputs: [PASS, PASS], key: KEY[SEP] });
  e.now = () => new Date('2026-11-02T11:59:00Z');
  assert.equal(await run(keygenArgs(SEP, d), e), 1);
  refusedWith(e, 'RNKEY_SIGNLOG_INVALID');
  assert.equal(e.prompts.length, 0);
  assert.deepEqual(files(d.keys), ['xrpl-testnet.key.json']);
  assert.equal((await keygen(SEP, d)).exit, 0, 'a correct clock then works');
});

test('a leftover temporary log entry, a gap, a stray or non-canonical file: every command refuses', async () => {
  const d = workspace();
  await keygen(XRPL, d);
  const show = async () => {
    const e = environment();
    await run(['show', '--network', XRPL, '--key-dir', d.keys, '--log-dir', d.log], e);
    return e;
  };
  writeFileSync(join(d.log, '.000001.json.tmp'), 'x', { mode: 0o600 });
  refusedWith(await show(), 'RNKEY_SIGNLOG_INCOMPLETE');
  refusedWith((await sign(XRPL, d)).e, 'RNKEY_SIGNLOG_INCOMPLETE');
  refusedWith((await keygen(SEP, d)).e, 'RNKEY_SIGNLOG_INCOMPLETE');
  unlinkSync(join(d.log, '.000001.json.tmp'));
  const original = readFileSync(join(d.log, '000000.json'));
  for (const [what, act, undo] of [
    ['gap', () => writeFileSync(join(d.log, '000002.json'), original, { mode: 0o600 }), () => unlinkSync(join(d.log, '000002.json'))],
    ['stray', () => writeFileSync(join(d.log, 'notes.txt'), 'x', { mode: 0o600 }), () => unlinkSync(join(d.log, 'notes.txt'))],
    ['pretty', () => writeFileSync(join(d.log, '000000.json'), `${JSON.stringify(JSON.parse(original), null, 1)}\n`), () => writeFileSync(join(d.log, '000000.json'), original)],
    ['no-newline', () => writeFileSync(join(d.log, '000000.json'), original.subarray(0, -1)), () => writeFileSync(join(d.log, '000000.json'), original)],
    ['flipped-byte', () => { const b = Buffer.from(original); b[b.indexOf('"address":"r') + 13] ^= 1; writeFileSync(join(d.log, '000000.json'), b); }, () => writeFileSync(join(d.log, '000000.json'), original)],
    ['mode', () => chmodSync(join(d.log, '000000.json'), 0o644), () => chmodSync(join(d.log, '000000.json'), 0o600)],
    ['symlink', () => { unlinkSync(join(d.log, '000000.json')); writeFileSync(join(d.base, 'elsewhere.json'), original, { mode: 0o600 }); symlinkSync(join(d.base, 'elsewhere.json'), join(d.log, '000000.json')); }, () => { unlinkSync(join(d.log, '000000.json')); writeFileSync(join(d.log, '000000.json'), original, { mode: 0o600 }); }],
  ]) {
    act();
    refusedWith(await show(), 'RNKEY_SIGNLOG_INVALID');
    refusedWith((await sign(XRPL, d)).e, 'RNKEY_SIGNLOG_INVALID');
    undo();
  }
  assert.equal((await show()).text().includes('consistent'), true);
});

test('two runs cannot both append the same entry: the later one is refused', () => {
  const d = workspace();
  ensurePrivateDirectory(d.log, 'log', SYSTEM);
  const key = fixtureKey(XRPL, LABELS.xrpl);
  void key;
  const created = { network: XRPL, purpose: PURPOSE, address: 'rPMhDyWFH1uu1kMwheshzpaMouWr75XRa2', publicKey: 'ED0C325AFF74C97AEA604FCC239998CA6EC98741D97991842E1F649325C57DEE66', keyFileSha256: `sha256:${'3'.repeat(64)}` };
  const stale = [];
  appendSignLog(d.log, stale, nextEntry(stale, EntryType.KEY_CREATED, created, '2026-11-02T12:00:00Z'), SYSTEM);
  const entries = readSignLog(d.log, SYSTEM);
  const a = nextEntry(entries, EntryType.SIGNING, { network: XRPL, purpose: PURPOSE, address: created.address, sequence: '1', intentDigest: `sha256:${'4'.repeat(64)}` }, '2026-11-02T12:00:01Z');
  const b = nextEntry(entries, EntryType.SIGNING, { network: XRPL, purpose: PURPOSE, address: created.address, sequence: '1', intentDigest: `sha256:${'5'.repeat(64)}` }, '2026-11-02T12:00:01Z');
  appendSignLog(d.log, entries, a, SYSTEM);
  assert.throws(() => appendSignLog(d.log, entries, b, SYSTEM), (e) => e.code === 'RNKEY_SIGNLOG_CONFLICT');
  // A run that read the log before another run wrote cannot append at a stale index either.
  assert.throws(() => appendSignLog(d.log, stale, nextEntry(stale, EntryType.KEY_CREATED, created, '2026-11-02T12:00:00Z'), SYSTEM), (e) => e.code === 'RNKEY_SIGNLOG_CONFLICT');
  assert.equal(readSignLog(d.log, SYSTEM).length, 2);
  assert.deepEqual(files(d.log), [entryName(0), entryName(1)]);
});

// --- the sign log format: fixtures, and JavaScript against Python --------------------------------------

test('the committed C4 fixtures are exactly what the generator builds', () => {
  assert.equal(readFileSync(C4_FILE, 'utf8'), buildC4());
});

test('the sign log replays every committed case as recorded', () => {
  const cases = JSON.parse(readFileSync(C4_FILE, 'utf8'));
  for (const c of cases.signlog) {
    let got;
    try {
      replaySignLog(c.entries);
      got = { ok: true };
    } catch (error) {
      got = { ok: false, code: error.code, index: Number(/entry (\d+):/.exec(error.message)[1]) };
    }
    assert.deepEqual(got, c.expect, c.id);
  }
  for (const c of cases.decisions) {
    let got;
    try {
      got = { ok: true, ...decideSigning(c.entries, c.request) };
    } catch (error) {
      got = { ok: false, code: error.code };
    }
    assert.deepEqual(got, c.expect, c.id);
  }
  assert.ok(cases.signlog.filter((c) => !c.expect.ok).length >= 30);
});

// JavaScript against the independent Python reference on real directories is
// tools/signing/keytool-python.check.mjs (a subprocess, so it runs outside this preloaded test run,
// still inside the network namespace), and the reference itself runs in tools/ci/offline-checks.sh.

test('RN-NET S1: keytool sign refuses an unsupported preparation before the confirmation, the passphrase and any sign-log write', async () => {
  const s1 = Object.fromEntries(s1Cases().map((c) => [c.id, c]));
  const d = workspace();
  const { exit } = await keygen(SEP, d);
  assert.equal(exit, 0);
  const logBefore = files(d.log);
  const base = JSON.parse(readFileSync(INTENT[SEP], 'utf8'));
  for (const id of ['v2-record', 'v9-record']) {
    const intent = { ...base, preparation: s1[id].preparation };
    const path = join(d.base, `${id}.json`);
    writeFileSync(path, canonicalize(intent), { mode: 0o600 });
    const digest = `sha256:${createHash('sha256').update(INTENT_DIGEST_DOMAIN).update(canonicalBytes(intent)).digest('hex')}`;
    const { exit: signExit, e } = await sign(SEP, d, { intent: path, digest });
    assert.notEqual(signExit, 0, id);
    assert.match(e.text(), /RNTX_INTENT_INVALID/, id);
    assert.equal(e.left(), 2, `${id}: neither the confirmation nor the passphrase was asked`);
    assert.deepEqual(files(d.log), logBefore, `${id}: no sign-log entry`);
    assert.deepEqual(files(d.out), [], `${id}: nothing signed`);
  }
});
