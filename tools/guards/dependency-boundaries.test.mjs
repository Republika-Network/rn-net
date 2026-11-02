import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { check, DEV_DEPENDENCIES, importsOf, SIGNER_DEPENDENCIES } from './dependency-boundaries.mjs';

const rules = (path, content) => check([{ path, content }]).map((f) => f.rule);

test('extracts static, re-export and dynamic import specifiers', () => {
  const src = [
    "import a from 'node:crypto';",
    "import { b } from './b.mjs';",
    "export { c } from '../c.mjs';",
    "import './side-effect.mjs';",
    "const d = await import('node:fs');",
  ].join('\n');
  assert.deepEqual(importsOf(src), ['node:crypto', './b.mjs', '../c.mjs', './side-effect.mjs', 'node:fs']);
});

test('allows declared built-ins and public entry points', () => {
  assert.deepEqual(rules('packages/commitment/src/x.mjs', "import { createHash } from 'node:crypto';"), []);
  assert.deepEqual(rules('packages/commitment/src/x.mjs', "import { parse } from '../../canonical/src/index.mjs';"), []);
  assert.deepEqual(rules('packages/canonical/src/a.mjs', "import { b } from './b.mjs';"), []);
  assert.deepEqual(rules('packages/canonical/test/a.test.mjs', "import { test } from 'node:test';"), []);
});

test('rejects network built-ins, third-party packages and wrong-direction imports', () => {
  assert.deepEqual(rules('packages/canonical/src/a.mjs', "import net from 'node:net';"), [
    'builtin-export-not-allowed:node:net#default',
    'builtin-not-allowed:node:net',
  ]);
  assert.deepEqual(rules('packages/commitment/src/a.mjs', "import { Client } from 'xrpl';"), ['third-party-import:xrpl']);
  assert.deepEqual(rules('packages/commitment/src/a.mjs', "const v = await import('viem');"), ['third-party-import:viem']);
  assert.deepEqual(rules('packages/canonical/src/a.mjs', "import x from '../../commitment/src/index.mjs';"), ['package-not-allowed:commitment']);
  assert.deepEqual(rules('packages/commitment/src/a.mjs', "import x from '../../canonical/src/parse.mjs';"), ['private-import:canonical/src/parse.mjs']);
  assert.deepEqual(rules('packages/commitment/src/a.mjs', "import x from '../../../tools/guards/lib.mjs';"), ['import-outside-packages']);
  assert.deepEqual(rules('packages/newpkg/src/a.mjs', ''), ['unregistered-package']);
});

test('rejects declared dependencies in any package.json', () => {
  assert.deepEqual(rules('packages/canonical/package.json', '{"dependencies":{"left-pad":"1.3.0"}}'), ['undeclared-dependencies']);
  assert.deepEqual(rules('package.json', '{"devDependencies":{"typescript":"5.0.0"}}'), ['undeclared-devDependencies']);
  assert.deepEqual(rules('package.json', '{"private":true}'), []);
});

test('only the root manifest may declare the allowed development dependency, at its exact version (RN-NET-01K)', () => {
  assert.deepEqual(rules('package.json', '{"devDependencies":{"acorn":"8.19.0"}}'), []);
  assert.deepEqual(rules('package.json', '{"devDependencies":{"acorn":"^8.19.0"}}'), ['undeclared-devDependencies']);
  assert.deepEqual(rules('package.json', '{"devDependencies":{"acorn":"8.19.0","acorn-walk":"8.3.4"}}'), ['undeclared-devDependencies']);
  assert.deepEqual(rules('package.json', '{"dependencies":{"acorn":"8.19.0"}}'), ['undeclared-dependencies']);
  assert.deepEqual(rules('packages/canonical/package.json', '{"devDependencies":{"acorn":"8.19.0"}}'), ['undeclared-devDependencies']);
  assert.deepEqual(rules('tools/package.json', '{"devDependencies":{"acorn":"8.19.0"}}'), ['undeclared-devDependencies']);
  // Packages may never import it.
  assert.deepEqual(rules('packages/canonical/src/x.mjs', "import { parse } from 'acorn';"), ['third-party-import:acorn']);
});

test('the lockfile holds exactly the allowed development dependency', () => {
  const lock = (packages) => JSON.stringify({ lockfileVersion: 3, packages });
  const root = { '': { devDependencies: { acorn: '8.19.0' } } };
  const acorn = { ...DEV_DEPENDENCIES.acorn, dev: true };
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': acorn })), []);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, version: '8.18.0' } })), ['undeclared-lockfile-packages']);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, dev: undefined } })), ['undeclared-lockfile-packages']);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, resolved: 'https://example.org/acorn-8.19.0.tgz' } })), ['undeclared-lockfile-packages']);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, integrity: 'sha512-AAAA' } })), ['undeclared-lockfile-packages']);
  assert.deepEqual(rules('package-lock.json', lock({ 'node_modules/acorn': acorn, x: {} })), ['undeclared-lockfile-packages']);
  assert.deepEqual(
    rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, dependencies: { 'is-number': '7.0.0' } } })),
    ['undeclared-lockfile-packages'],
  );
  assert.deepEqual(
    rules('package-lock.json', lock({ ...root, 'node_modules/acorn': acorn, 'node_modules/x': { version: '1.0.0', dev: true } })),
    ['undeclared-lockfile-packages'],
  );
  assert.deepEqual(rules('packages/canonical/package-lock.json', lock({ ...root, 'node_modules/acorn': acorn })), [
    'undeclared-lockfile-packages',
    'non-module-file',
  ]);
});

// RN-NET-01H, finding F6: the bypasses reported by the RN-NET-01 independent review.
test('flags the import forms and loaders reported as bypasses', () => {
  const cases = {
    'import{connect}from"node:net";': 'builtin-not-allowed:node:net',
    "import/**/net from 'node:net';": 'builtin-not-allowed:node:net',
    "/* a */import net from 'node:net';": 'builtin-not-allowed:node:net',
    "import net from 'net';": 'third-party-import:net',
    "import x from 'node:net' with { type: 'json' };": 'builtin-not-allowed:node:net',
    'const n = await import(`node:net`);': 'forbidden-construct:dynamic-import-non-literal',
    "const m = 'node:' + 'net'; await import(m);": 'forbidden-construct:dynamic-import-non-literal',
    "const net = process.getBuiltinModule('node:net');": 'forbidden-construct:process-internals',
    "const { getBuiltinModule: g } = process; g('node:net');": 'forbidden-construct:get-builtin-module',
    "process.binding('tcp_wrap');": 'forbidden-construct:process-internals',
    "process['binding']('tcp_wrap');": 'forbidden-construct:process-internals',
    "globalThis['fet' + 'ch']('https://example.org');": 'forbidden-construct:computed-global-access',
    "await fetch('https://example.org');": 'forbidden-construct:global-fetch',
    "new WebSocket('wss://example.org');": 'forbidden-construct:websocket',
    "const w = new Worker('./x.mjs');": 'forbidden-construct:worker',
    "const net = require('node:net');": 'forbidden-construct:require',
    "import { createRequire } from 'node:module';": 'forbidden-construct:create-require',
    "eval('1');": 'forbidden-construct:eval',
    "const f = new Function('return 1');": 'forbidden-construct:function-constructor',
  };
  for (const [source, rule] of Object.entries(cases)) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes(rule), `${source} -> ${rule}`);
  }
});

test('only ES modules (and a README) may live in a package, in any directory', () => {
  assert.deepEqual(rules('packages/canonical/src/x.cjs', "require('node:net');"), ['non-module-file']);
  assert.deepEqual(rules('packages/canonical/src/x.js', ''), ['non-module-file']);
  assert.deepEqual(rules('packages/canonical/data.json', '{}'), ['non-module-file']);
  assert.deepEqual(rules('packages/canonical/README.md', '# x'), []);
  assert.deepEqual(rules('packages/canonical/lib/x.mjs', "import net from 'node:net';"), [
    'builtin-export-not-allowed:node:net#default',
    'builtin-not-allowed:node:net',
  ]);
});

test('ordinary code is not flagged', () => {
  const ok = [
    "new URL('../vectors/', import.meta.url);",
    'const isFunction = (f) => typeof f === "function";',
    'const fetched = cache.fetchAll;',
    "const workers = 'Workers';",
  ];
  for (const source of ok) assert.deepEqual(rules('packages/conformance/src/x.mjs', source), [], source);
});

// RN-NET-01J, N2: imports are read as tokens. These are the forms the RN-NET-01H independent
// review showed loading node:net while the guard reported nothing, and their close variants.
test('flags imports with comments between any tokens', () => {
  const cases = [
    "import net from // note\n  'node:net';",
    "import net /* a */ from /* b */ 'node:net';",
    "import { connect } from // note\n 'node:net';",
    "import * as net from\n// note\n'node:net';",
    "export { connect } from // note\n 'node:net';",
    "export * from /* a */ 'node:net';",
    "const n = await import( // note\n 'node:net');",
    "import net from 'node:\\u006eet';", // escapes are decoded before the check
  ];
  for (const source of cases) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes('builtin-not-allowed:node:net'), source);
  }
});

test('flags string-literal import and export names', () => {
  const cases = [
    "import { 'connect' as c } from 'node:net';",
    "import { default as d, 'connect' as c } from 'node:net';",
    "export { 'connect' as c } from 'node:net';",
    "export * as 'net' from 'node:net';",
    "import from from 'node:net';",
    "import { from } from 'node:net';",
    "import d, { 'connect' as c } from 'node:net';",
    "import d, * as n from 'node:net';",
  ];
  for (const source of cases) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes('builtin-not-allowed:node:net'), source);
  }
});

test('flags aliased, optional, indirect and constructor routes to code loading', () => {
  const cases = {
    'const f = fetch; f(url);': 'forbidden-identifier:fetch',
    'fetch?.(url);': 'forbidden-identifier:fetch',
    "(0, eval)('1');": 'forbidden-identifier:eval',
    "(() => {}).constructor('return 1')();": 'constructor-access',
    "(async () => {})?.constructor('return 1');": 'constructor-access',
    "(() => {})['constructor']('return 1');": 'forbidden-string:constructor',
    "Reflect.get(process, 'getBuiltinModule');": 'process-access',
    "Reflect.get(o, 'getBuiltinModule');": 'forbidden-string:getBuiltinModule',
    'const { getBuiltinModule } = process;': 'process-access',
    'const p = process; p.binding(x);': 'process-access',
    'const home = process.env.HOME;': 'process-access',
    'const g = globalThis;': 'forbidden-identifier:globalThis',
    "import('node:' + 'net');": 'dynamic-import-non-literal',
    'import(`node:net`);': 'dynamic-import-non-literal',
  };
  for (const [source, rule] of Object.entries(cases)) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes(rule), `${source} -> ${rule}`);
  }
});

test('fails closed on source the parser rejects', () => {
  const cases = [
    "import net from 'node:net", // unterminated string
    '/* unterminated',
    'const a = `x${1}',
    "const s = '\\101';", // legacy octal escape, not allowed in modules
    'const a = `${ 1', // unterminated substitution
    'import net, 5 from "node:net";',
    'import { a b } from "node:net";',
    'export { a } from net;',
    'export * as a;',
    "<!-- x\nimport net from 'node:net';", // HTML-like comments are not allowed in modules
    'with (a) {}', // not allowed in strict code
  ];
  for (const source of cases) assert.ok(rules('packages/canonical/src/x.mjs', source).includes('unsupported-syntax'), source);
});

test('escaped identifiers are read as the names they spell', () => {
  assert.ok(rules('packages/canonical/src/x.mjs', '\\u0065val("1");').includes('forbidden-identifier:eval'));
  assert.ok(rules('packages/canonical/src/x.mjs', 'const g = glob\\u0061lThis;').includes('forbidden-identifier:globalThis'));
  assert.ok(rules('packages/canonical/src/x.mjs', "import net from 'node:\\u006eet';").includes('builtin-not-allowed:node:net'));
});

test('imports in comments, strings and regular expressions are not imports', () => {
  const text = [
    "// import net from 'node:net';",
    "/* export * from 'node:net'; */",
    "const s = \"import net from 'node:http'\";",
    "const r = /import x from 'node:dns'/;",
  ];
  for (const source of text) {
    assert.deepEqual(importsOf(source), [], source);
    // The raw-text layer still reports them: it is deliberately more conservative.
    assert.notDeepEqual(rules('packages/canonical/src/x.mjs', source), [], source);
  }
  const ok = [
    "const t = `${'a'}`;",
    'const m = import.meta.url;',
    'const isFunction = (f) => typeof f === "function";',
    'class A { constructor() {} }',
    'const n = process.hrtime.bigint();',
    'export const a = 1; export function b() {} export { a as c, };',
  ];
  for (const source of ok) assert.deepEqual(rules('packages/canonical/test/x.test.mjs', source), [], source);
});

test('regular expressions and divisions are read by the parser, whatever surrounds them', () => {
  // A regular expression read as a division (or the reverse) could let a fake template literal
  // hide the import below; the line comment hides it from simple raw patterns.
  const hidden = (prefix) => `${prefix}/\`/.test('');\nimport net from // c\n  'node:net'; // \``;
  for (const prefix of ['if (a) ', 'while (a) ', 'function f() {}\n', 'x: {}\n', 'switch (a) { case 1: {}\n}\n', 'export default ']) {
    assert.deepEqual(importsOf(hidden(prefix)), ['node:net'], prefix);
    assert.ok(rules('packages/canonical/src/x.mjs', hidden(prefix)).includes('builtin-not-allowed:node:net'), prefix);
  }
  // Code the earlier tokenizer had to reject is now read and accepted.
  const ok = [
    'const m = (a + b) / 2 / c;',
    'const r = x.return / 2 / y;',
    "const r = x.of / 2; const s = '/';",
    'const of = 4; const y = of / 2;',
    'let i = 0; const j = i++ / 2 + i-- / 2;',
    'x: {}\n/a/.test(s);',
    'function f() {}\n/x/.test(s);',
    'const g = function () {} / 1;',
    'const k = class {} / 1;',
    'for (; {} / 1; ) break;',
    'if (a) /x/.test(s);',
    'for await (const x of y) /x/.test(x);',
    'const o = { import: 1, if: 2, for: 3 };',
    'const t = `${a / 2}`; const u = /`/;',
  ];
  for (const source of ok) assert.deepEqual(rules('packages/canonical/test/x.test.mjs', source), [], source);
});

// RN-NET-01J and RN-NET-01K: the bypasses found by independent reviews, kept verbatim in
// fixtures/dependency-bypasses/. Each is a valid module that, run from packages/canonical/src/,
// loads node:net or acorn, or reaches eval, process or the Function constructor, while an earlier
// guard reported nothing: b01-b07 at 9521fff, b08 at a4b2e30 (merged as 0b32565), b09-b15 at
// f416539 (the first AST-based guard), b16-b19 at fbb0064 (through allowed built-ins; each is
// checked where that built-in is allowed).
const fixtures = new URL('./fixtures/dependency-bypasses/', import.meta.url);
const read = (name) => readFileSync(new URL(name, fixtures), 'utf8');
const EXPECTED = {
  'b01-export-default.mjs': 'builtin-not-allowed:node:net',
  'b02-postfix.mjs': 'builtin-not-allowed:node:net',
  'b03-fnexpr.mjs': 'builtin-not-allowed:node:net',
  'b04-forawait.mjs': 'builtin-not-allowed:node:net',
  'b05-classexpr.mjs': 'builtin-not-allowed:node:net',
  'b06-extends.mjs': 'builtin-not-allowed:node:net',
  'b07-hidden-process.mjs': 'process-access',
  'b08-for-head.mjs': 'builtin-not-allowed:node:net',
  'b09-percent-dotdot.mjs': 'unsupported-specifier:./%2e%2e/%2e%2e/%2e%2e/tools/x/evil.mjs',
  'b10-percent-acorn.mjs': 'unsupported-specifier:./%2e%2e/%2e%2e/%2e%2e/node_modules/acorn/dist/acorn.mjs',
  'b11-backslash.mjs': 'unsupported-specifier:./..\\..\\..\\tools/x/evil.mjs',
  'b12-destructured-constructor.mjs': 'constructor-access',
  'b13-shorthand-constructor.mjs': 'constructor-access',
  'b14-percent-dynamic.mjs': 'unsupported-specifier:./%2e%2e/%2e%2e/%2e%2e/tools/x/evil.mjs',
  'b15-param-default-constructor.mjs': 'constructor-access',
  'b16-node-test-run.mjs': ['packages/canonical/test/x.test.mjs', 'builtin-export-not-allowed:node:test#run'],
  'b17-crypto-setengine.mjs': ['packages/commitment/src/x.mjs', 'builtin-export-not-allowed:node:crypto#setEngine'],
  'b18-fs-symlink.mjs': ['packages/conformance/src/x.mjs', 'builtin-export-not-allowed:node:fs#symlinkSync'],
  'b19-fs-copy.mjs': ['packages/conformance/src/x.mjs', 'builtin-export-not-allowed:node:fs#copyFileSync'],
};

test('every reviewed bypass is present and has an expectation', () => {
  const present = readdirSync(fixtures).filter((name) => name.endsWith('.mjs')).sort();
  assert.deepEqual(present, Object.keys(EXPECTED).sort());
});

test('each reviewed bypass is reported from the syntax tree', () => {
  for (const [name, expected] of Object.entries(EXPECTED)) {
    const [path, rule] = Array.isArray(expected) ? expected : ['packages/canonical/src/x.mjs', expected];
    assert.ok(rules(path, read(name)).includes(rule), `${name} -> ${rule}`);
  }
  for (const name of ['b01-export-default.mjs', 'b02-postfix.mjs', 'b03-fnexpr.mjs', 'b04-forawait.mjs', 'b05-classexpr.mjs',
    'b06-extends.mjs', 'b08-for-head.mjs']) {
    assert.deepEqual(importsOf(read(name)), ['node:net'], name);
  }
});

test('b01-b07 are also caught by the raw layer; b08 shows why it is only a second layer', () => {
  const rawLayer = /^(?:string-named-import-clause$|forbidden-word:|forbidden-construct:)/;
  for (const name of Object.keys(EXPECTED).filter((n) => n < 'b09')) {
    const raw = rules('packages/canonical/src/x.mjs', read(name)).filter((rule) => rawLayer.test(rule));
    if (name === 'b08-for-head.mjs') assert.deepEqual(raw, [], 'a quote in a comment defeats the raw specifier pattern');
    else assert.ok(raw.length > 0, name);
  }
});

test('relative specifiers must resolve the same way as in Node, or are reported', () => {
  const unsupported = [
    "import x from './%2e%2e/a.mjs';",
    "import x from './a%2Emjs';",
    "import x from '.\\\\a.mjs';",
    "import x from './a.mjs?x';",
    "import x from './a.mjs#x';",
    "import x from './/a.mjs';",
    "import x from '.';",
    "import x from '../';",
    "await import('./%2e%2e/a.mjs');",
    "export * from './%2e%2e/a.mjs';",
  ];
  for (const source of unsupported) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).some((r) => r.startsWith('unsupported-specifier:')), source);
  }
  assert.deepEqual(rules('packages/commitment/src/x.mjs', "import { parse } from '../../canonical/src/index.mjs';"), []);
  assert.deepEqual(rules('packages/canonical/src/x.mjs', "import x from './a-b_c.d.mjs';"), []);
  assert.deepEqual(rules('packages/canonical/test/x.test.mjs', "import x from '../src/index.mjs';"), []);
});

test('constructor is reported in every form except a class constructor method', () => {
  const cases = [
    'const { constructor: F } = () => {};',
    'const { constructor } = () => {};',
    'function f({ constructor: F } = () => {}) { return F; }',
    '({ constructor: F } = () => {});',
    'const o = { constructor: 1 };',
    'const c = f.constructor;',
    'const c = f?.constructor;',
    'class A { static constructor() {} }',
    'const \\u0063onstructor = 1;',
  ];
  for (const source of cases) assert.ok(rules('packages/canonical/src/x.mjs', source).includes('constructor-access'), source);
  assert.deepEqual(rules('packages/canonical/src/x.mjs', 'class A { constructor() { this.a = 1; } }'), []);
  assert.deepEqual(rules('packages/canonical/src/x.mjs', 'class A extends Error { constructor(m) { super(m); } }'), []);
});

// An allowed built-in still has exports that load code or reach outside the package; the
// independent review of fbb0064 ran each of these (node:test run with isolation 'none' imported
// a file outside packages/, setEngine loaded a shared object, symlinkSync and copyFileSync made a
// same-package path that a literal import then loaded).
test('only allowlisted exports of allowed built-ins may be imported', () => {
  const cases = {
    "import { run } from 'node:test';": ['packages/canonical/test/x.test.mjs', 'builtin-export-not-allowed:node:test#run'],
    "import { setEngine } from 'node:crypto';": ['packages/commitment/src/x.mjs', 'builtin-export-not-allowed:node:crypto#setEngine'],
    "import { symlinkSync } from 'node:fs';": ['packages/conformance/src/x.mjs', 'builtin-export-not-allowed:node:fs#symlinkSync'],
    "import { copyFileSync } from 'node:fs';": ['packages/conformance/src/x.mjs', 'builtin-export-not-allowed:node:fs#copyFileSync'],
    "import { writeFileSync as w } from 'node:fs';": ['packages/conformance/src/x.mjs', 'builtin-export-not-allowed:node:fs#writeFileSync'],
    "import { 'setEngine' as e } from 'node:crypto';": ['packages/commitment/src/x.mjs', 'builtin-export-not-allowed:node:crypto#setEngine'],
    "import * as crypto from 'node:crypto';": ['packages/commitment/src/x.mjs', 'builtin-export-not-allowed:node:crypto#*'],
    "import crypto from 'node:crypto';": ['packages/commitment/src/x.mjs', 'builtin-export-not-allowed:node:crypto#default'],
    "import t, { test } from 'node:test';": ['packages/canonical/test/x.test.mjs', 'builtin-export-not-allowed:node:test#default'],
    "const fs = await import('node:fs');": ['packages/conformance/src/x.mjs', 'builtin-dynamic-import:node:fs'],
    "export { setEngine } from 'node:crypto';": ['packages/commitment/src/x.mjs', 'builtin-reexport:node:crypto'],
    "export * from 'node:fs';": ['packages/conformance/src/x.mjs', 'builtin-reexport:node:fs'],
  };
  for (const [source, [path, rule]] of Object.entries(cases)) assert.ok(rules(path, source).includes(rule), `${source} -> ${rule}`);
  // Exactly what the packages use today.
  assert.deepEqual(rules('packages/conformance/src/x.mjs', "import { readFileSync } from 'node:fs';\nimport { fileURLToPath } from 'node:url';"), []);
  assert.deepEqual(rules('packages/canonical/test/x.test.mjs', "import assert from 'node:assert/strict';\nimport { test } from 'node:test';"), []);
  assert.deepEqual(rules('packages/commitment/src/x.mjs', "import { Buffer } from 'node:buffer';\nimport { createHash } from 'node:crypto';"), []);
});

// RN-NET-01K: the independent review of 43dc44c showed production code borrowing test-only
// built-ins through a same-package test helper (canonical/src has no allowed built-ins).
test('production code cannot import test files or helpers of its own package', () => {
  const helper = "import { test } from 'node:test';\nimport { Buffer } from 'node:buffer';\nexport { test, Buffer };\n";
  const reviewed = check([
    { path: 'packages/canonical/test/helper.mjs', content: helper },
    { path: 'packages/canonical/src/y.mjs', content: "import { test, Buffer } from '../test/helper.mjs';\n" },
  ]);
  assert.deepEqual(reviewed, [{ path: 'packages/canonical/src/y.mjs', rule: 'production-imports-non-production:test/helper.mjs' }]);
  const cases = {
    'packages/canonical/src/a.mjs': "export { test } from '../test/helper.mjs';",
    'packages/commitment/src/a.mjs': "export * from '../test/helper.mjs';",
    'packages/conformance/src/a.mjs': "const h = await import('../test/helper.mjs');",
    'packages/canonical/src/sub/a.mjs': "import { test } from '../../test/helper.mjs';",
    'packages/canonical/src/b.mjs': "import x from './../test/a.test.mjs';",
    'packages/canonical/lib/a.mjs': "import { test } from '../test/helper.mjs';", // outside test/ is production
    'packages/canonical/src/c.mjs': "import x from '../helpers/h.mjs';", // a helper anywhere outside src/
  };
  for (const [path, source] of Object.entries(cases)) {
    assert.ok(rules(path, source).some((r) => r.startsWith('production-imports-non-production:')), `${path}: ${source}`);
  }
  // A re-export chain inside src/ is reported where it first leaves src/.
  const chain = check([
    { path: 'packages/canonical/src/a.mjs', content: "export * from './b.mjs';" },
    { path: 'packages/canonical/src/b.mjs', content: "export { test } from '../test/helper.mjs';" },
  ]);
  assert.deepEqual(chain, [{ path: 'packages/canonical/src/b.mjs', rule: 'production-imports-non-production:test/helper.mjs' }]);
});

test('test code keeps its imports and the accepted node:test capabilities', () => {
  const ok = {
    'packages/canonical/test/a.test.mjs': "import { canonicalize } from '../src/index.mjs';\nimport { helper } from './helper.mjs';",
    'packages/commitment/test/a.test.mjs': "import { parse } from '../../canonical/src/index.mjs';",
    'packages/canonical/test/b.test.mjs':
      "import { test } from 'node:test';\ntest('x', async (t) => { t.mock.fn(); await t.test('y', () => {}); });\nconst s = test.run({ files: [] });\ntest.mock.fn();\ntest.snapshot.setResolveSnapshotPath(() => 'x');",
    'packages/canonical/src/a.mjs': "import { b } from './b.mjs';\nimport { c } from './sub/c.mjs';",
  };
  for (const [path, source] of Object.entries(ok)) assert.deepEqual(rules(path, source), [], path);
});

test('symlinks, shrinkwrap files, .npmrc and install-changing manifest fields are reported', () => {
  for (const path of ['packages/canonical/src/s.mjs', 'packages/canonical', 'packages']) {
    assert.deepEqual(check([{ path, content: null, symlink: true }]).map((f) => f.rule), ['symlink-in-package'], path);
  }
  assert.deepEqual(rules('npm-shrinkwrap.json', '{}'), ['not-allowed:npm-shrinkwrap.json']);
  assert.deepEqual(rules('.npmrc', 'registry=https://example.org/'), ['not-allowed:.npmrc']);
  assert.deepEqual(rules('tools/.npmrc', ''), ['not-allowed:.npmrc']);
  for (const field of ['overrides', 'workspaces', 'bundleDependencies', 'bundledDependencies']) {
    assert.deepEqual(rules('package.json', JSON.stringify({ [field]: {} })), [`manifest-field-not-allowed:${field}`]);
  }
});

test('raw rules: string-named import clauses and forbidden words, wherever they appear', () => {
  const cases = {
    "import { 'connect' as c } from 'node:net';": 'string-named-import-clause',
    "export { c as 'connect' } from './x.mjs';": 'string-named-import-clause',
    "import d, { 'a' as b } from './x.mjs';": 'string-named-import-clause',
    'const s = "eval";': 'forbidden-word:eval',
    '// uses fetch': 'forbidden-word:fetch',
    'const p = process.env;': 'forbidden-word:process',
    'x.process();': 'forbidden-word:process',
  };
  for (const [source, rule] of Object.entries(cases)) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes(rule), `${source} -> ${rule}`);
  }
});

test('supported code stays accepted', () => {
  const ok = [
    "import { createHash } from 'node:crypto';\nimport { b as c, d } from './b.mjs';\nimport * as e from './e.mjs';\nimport f, { g } from './f.mjs';",
    "export { h } from './h.mjs';\nexport * from './i.mjs';\nexport * as j from './j.mjs';\nexport default 1;",
    "import /* a */ k /* b */ from /* c */ './k.mjs'; // d\nimport l from // e\n  './l.mjs';",
    "const m = await import('./m.mjs');\nconst n = await import('./n.mjs', { with: { type: 'json' } });",
    'const r = /[/]\\//g.test(s) ? /a/i : x / 2;\nconst q = s.replace(/\\s+/g, " ") / 1;',
    'export default /x/;\nclass A extends B {}\nfor await (const x of y) /z/.test(x);',
    'const t0 = process.hrtime.bigint(); const v = process.versions.node;',
  ];
  for (const source of ok) assert.deepEqual(rules('packages/commitment/test/x.test.mjs', source), [], source);
});

test('a line comment ends at every line terminator, including U+2028 and U+2029', () => {
  for (const terminator of ['\n', '\r', '\u2028', '\u2029']) {
    const source = `// note${terminator}import net from 'node:net';`;
    assert.deepEqual(importsOf(source), ['node:net'], JSON.stringify(terminator));
  }
});

// RN-NET-02: the verifier package checks signatures with built-in crypto, and can never sign.
test('the verifier may verify signatures but no production code may sign or hold a private key', () => {
  assert.deepEqual(rules('packages/verifier/src/x.mjs', "import { createHash, createPublicKey, verify } from 'node:crypto';\nimport { Buffer } from 'node:buffer';"), []);
  assert.deepEqual(rules('packages/verifier/src/x.mjs', "import { parse } from '../../canonical/src/index.mjs';\nimport { verifyCommitment } from '../../commitment/src/index.mjs';"), []);
  for (const name of ['sign', 'generateKeyPairSync', 'createPrivateKey']) {
    for (const pkg of ['verifier', 'commitment']) {
      assert.ok(rules(`packages/${pkg}/src/x.mjs`, `import { ${name} } from 'node:crypto';`).includes(`builtin-export-not-allowed:node:crypto#${name}`), `${pkg}: ${name}`);
    }
    assert.deepEqual(rules('packages/verifier/test/x.test.mjs', `import { ${name} } from 'node:crypto';`), [], `test: ${name}`);
  }
  assert.deepEqual(rules('packages/conformance/test/x.test.mjs', "import { verifyEvidence } from '../../verifier/src/index.mjs';"), []);
  // Only the verifier package may verify signatures.
  for (const name of ['createPublicKey', 'verify']) {
    assert.ok(rules('packages/commitment/src/x.mjs', `import { ${name} } from 'node:crypto';`).includes(`builtin-export-not-allowed:node:crypto#${name}`), name);
  }
  assert.ok(rules('packages/verifier/src/x.mjs', "import x from '../../conformance/src/vectors.mjs';").includes('package-not-allowed:conformance'));
  assert.ok(rules('packages/verifier/src/x.mjs', "import { readFileSync } from 'node:fs';").includes('builtin-not-allowed:node:fs'));
});

// RN-NET-03B2-B1 (ADR-RN-017): the signer project, its pinned dependencies and its boundaries.
test('the signer manifest declares exactly the two pinned noble packages, and nothing that runs', () => {
  const ok = { private: true, dependencies: { '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0' } };
  assert.deepEqual(rules('signer/package.json', JSON.stringify(ok)), []);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ dependencies: { '@noble/curves': '^2.4.0', '@noble/hashes': '2.4.0' } })), ['undeclared-dependencies']);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ dependencies: { '@noble/curves': '2.4.0' } })), ['signer-dependencies-incomplete']);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ dependencies: { ...ok.dependencies, '@noble/ciphers': '2.4.0' } })), ['undeclared-dependencies', 'signer-dependencies-incomplete']);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ ...ok, scripts: { postinstall: 'x' } })), ['signer-manifest-field-not-allowed:scripts']);
  assert.deepEqual(rules('signer/package.json', JSON.stringify({ ...ok, workspaces: ['x'] })), ['manifest-field-not-allowed:workspaces']);
  // Nowhere else may declare them.
  assert.deepEqual(rules('package.json', JSON.stringify({ dependencies: ok.dependencies })), ['undeclared-dependencies']);
  assert.deepEqual(rules('packages/tx-intent/package.json', JSON.stringify({ dependencies: ok.dependencies })), ['undeclared-dependencies']);
});

test('the signer lockfile holds exactly the pinned packages, by version, source and integrity', () => {
  const lock = (packages) => JSON.stringify({ lockfileVersion: 3, packages });
  const entry = (name) => {
    const { version, resolved, integrity, dependencies } = SIGNER_DEPENDENCIES[name];
    return { version, resolved, integrity, license: 'MIT', ...(dependencies ? { dependencies } : {}) };
  };
  const good = { '': { name: 'rn-net-signer', dependencies: { '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0' } }, 'node_modules/@noble/curves': entry('@noble/curves'), 'node_modules/@noble/hashes': entry('@noble/hashes') };
  const signerLock = (packages) => JSON.stringify({ name: 'rn-net-signer', lockfileVersion: 3, requires: true, packages });
  assert.deepEqual(rules('signer/package-lock.json', signerLock(good)), []);
  const bad = [
    { ...good, 'node_modules/@noble/hashes': { ...entry('@noble/hashes'), version: '2.3.0' } },
    { ...good, 'node_modules/@noble/hashes': { ...entry('@noble/hashes'), integrity: 'sha512-AAAA' } },
    { ...good, 'node_modules/@noble/hashes': { ...entry('@noble/hashes'), resolved: 'https://example.org/h.tgz' } },
    { ...good, 'node_modules/@noble/hashes': { ...entry('@noble/hashes'), dev: true } },
    { ...good, 'node_modules/@noble/curves': { ...entry('@noble/curves'), dependencies: { '@noble/hashes': '^2.4.0' } } },
    { ...good, 'node_modules/@noble/ciphers': { version: '2.4.0' } },
    { '': {}, 'node_modules/@noble/curves': entry('@noble/curves') },
  ];
  for (const packages of bad) assert.deepEqual(rules('signer/package-lock.json', signerLock(packages)), ['undeclared-lockfile-packages']);
  // The root lockfile may not hold them.
  assert.deepEqual(rules('package-lock.json', lock(good)), ['undeclared-lockfile-packages']);
});

test('signer code: allowed built-ins, exports, libraries and packages only', () => {
  assert.deepEqual(rules('signer/src/a.mjs', "import { createCipheriv, scryptSync } from 'node:crypto';"), []);
  assert.deepEqual(rules('signer/src/a.mjs', "import { randomBytes } from 'node:crypto';"), ['builtin-export-not-allowed:node:crypto#randomBytes']);
  assert.deepEqual(rules('signer/src/a.mjs', "import { generateKeyPairSync } from 'node:crypto';"), ['builtin-export-not-allowed:node:crypto#generateKeyPairSync']);
  assert.deepEqual(rules('signer/src/a.mjs', "import { x } from '../../packages/tx-intent/src/index.mjs';"), []);
  assert.deepEqual(rules('signer/src/a.mjs', "import { x } from '../../packages/tx-intent/src/xrpl.mjs';"), ['signer-import-not-allowed:packages/tx-intent/src/xrpl.mjs']);
  assert.deepEqual(rules('signer/src/a.mjs', "import { x } from '../test/fixture-keys.mjs';"), ['production-imports-non-production:test/fixture-keys.mjs']);
  assert.deepEqual(rules('signer/test/a.test.mjs', "import { test } from 'node:test';\nimport { x } from './fixture-keys.mjs';"), []);
  assert.deepEqual(rules('signer/bin/a.mjs', ''), ['non-module-file']);
  assert.deepEqual(rules('signer/src/a.js', ''), ['non-module-file']);
  assert.ok(rules('signer/src/a.mjs', 'const g = globalThis;').includes('forbidden-identifier:globalThis'));
});

test('new packages are registered with their allowlists', () => {
  assert.deepEqual(rules('packages/tx-intent/src/a.mjs', "import { types } from 'node:util';"), []);
  assert.deepEqual(rules('packages/verifier/src/a.mjs', "import { types } from 'node:util';"), ['builtin-export-not-allowed:node:util#types', 'builtin-not-allowed:node:util']);
  assert.deepEqual(rules('packages/broadcast-handoff/src/a.mjs', "import { x } from '../../tx-intent/src/index.mjs';"), []);
  assert.deepEqual(rules('packages/broadcast-handoff/src/a.mjs', "import { x } from '../../chain-readonly/src/index.mjs';"), ['package-not-allowed:chain-readonly']);
  assert.deepEqual(rules('packages/broadcast-handoff/src/a.mjs', "import https from 'node:https';"), ['builtin-export-not-allowed:node:https#default', 'builtin-not-allowed:node:https']);
});

// RN-NET-03B2-B2 (ADR-RN-018): tx-prepare reads through chain-readonly and binds through tx-intent,
// and nothing else: no signer, no transport, no network module, no key API.
test('tx-prepare is limited to chain-readonly, tx-intent and hashing', () => {
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../chain-readonly/src/index.mjs';\nimport { y } from '../../tx-intent/src/index.mjs';\nimport { createHash } from 'node:crypto';\nimport { Buffer } from 'node:buffer';"), []);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../chain-readonly/src/rpc.mjs';"), ['private-import:chain-readonly/src/rpc.mjs']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../anchor/src/index.mjs';"), ['package-not-allowed:anchor']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../broadcast-handoff/src/index.mjs';"), ['package-not-allowed:broadcast-handoff']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../../signer/src/sign.mjs';"), ['import-outside-packages']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { x } from '../../../tools/live/https-transport.mjs';"), ['import-outside-packages']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import https from 'node:https';"), ['builtin-export-not-allowed:node:https#default', 'builtin-not-allowed:node:https']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { sign } from 'node:crypto';"), ['builtin-export-not-allowed:node:crypto#sign']);
  assert.deepEqual(rules('packages/tx-prepare/src/a.mjs', "import { types } from 'node:util';"), ['builtin-export-not-allowed:node:util#types', 'builtin-not-allowed:node:util']);
  assert.ok(rules('packages/tx-prepare/src/a.mjs', "const r = await fetch('https://example.org/');").length > 0);
  // Nothing depends on tx-prepare: not the signer, not the hand-off, not the read-only package.
  assert.deepEqual(rules('packages/chain-readonly/src/a.mjs', "import { x } from '../../tx-prepare/src/index.mjs';"), ['package-not-allowed:tx-prepare']);
  assert.deepEqual(rules('packages/broadcast-handoff/src/a.mjs', "import { x } from '../../tx-prepare/src/index.mjs';"), ['package-not-allowed:tx-prepare']);
  assert.deepEqual(rules('signer/src/a.mjs', "import { x } from '../../packages/tx-prepare/src/index.mjs';"), ['signer-import-not-allowed:packages/tx-prepare/src/index.mjs']);
});

// RN-NET-03B2-B1 independent review, finding 6: routes the first guard version missed.
test('key-generation routes and indirect signer imports are reported', () => {
  assert.ok(rules('signer/src/a.mjs', 'const r = crypto.getRandomValues(new Uint8Array(32));').includes('global-crypto'));
  assert.ok(rules('signer/src/a.mjs', "import { secp256k1 } from '@noble/curves/secp256k1.js';\nconst k = secp256k1.utils.randomSecretKey();").includes('key-generation:randomSecretKey'));
  assert.ok(rules('signer/src/a.mjs', 'const k = s.keygen();').includes('key-generation:keygen'));
  assert.ok(rules('packages/broadcast-handoff/src/a.mjs', 'const k = crypto.subtle;').includes('global-crypto'));
  assert.ok(rules('signer/test/a.test.mjs', "import { generateKeyPairSync } from 'node:crypto';").includes('builtin-export-not-allowed:node:crypto#generateKeyPairSync'));
  assert.deepEqual(rules('tools/x.mjs', 'const m = await import(`../signer/src/sign.mjs`);'), ['signer-importer-not-allowed']);
  assert.deepEqual(rules('scripts/sign.mjs', "import { createSigner } from '../signer/src/sign.mjs';"), ['signer-importer-not-allowed']);
  assert.deepEqual(rules('tools/x.js', "import { createSigner } from '../signer/src/sign.mjs';"), ['signer-importer-not-allowed']);
});

test('the signer lockfile root entry and top-level fields must match the manifest', () => {
  const entry = (name) => {
    const { version, resolved, integrity, dependencies } = SIGNER_DEPENDENCIES[name];
    return { version, resolved, integrity, license: 'MIT', ...(dependencies ? { dependencies } : {}) };
  };
  const root = { name: 'rn-net-signer', dependencies: { '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0' } };
  const packages = (r) => ({ '': r, 'node_modules/@noble/curves': entry('@noble/curves'), 'node_modules/@noble/hashes': entry('@noble/hashes') });
  const lock = (r, extra = {}) => JSON.stringify({ name: 'rn-net-signer', lockfileVersion: 3, requires: true, packages: packages(r), ...extra });
  assert.deepEqual(rules('signer/package-lock.json', lock(root)), []);
  for (const bad of [lock({ ...root, dependencies: { ...root.dependencies, '@noble/curves': '^2.4.0' } }), lock({ ...root, bin: { s: 'x' } }), lock({ ...root, workspaces: ['x'] }), lock(root, { extra: 1 })]) {
    assert.deepEqual(rules('signer/package-lock.json', bad), ['undeclared-lockfile-packages']);
  }
});

test('destructured key-generation helpers and TypeScript files are reported (re-review)', () => {
  assert.ok(rules('signer/src/a.mjs', 'const { randomSecretKey } = s.utils;\nrandomSecretKey();').includes('key-generation:randomSecretKey'));
  assert.deepEqual(rules('tools/x.mts', "import { createSigner } from '../signer/src/sign.mjs';"), ['signer-importer-not-allowed']);
});

// --- RN-NET-03B2-B3: chain-submit, txverify/ and the broadcaster harness (ADR-RN-019) -----------

test('chain-submit: hashing only, no signer/, txverify/, node:fs, chain-readonly or key API', () => {
  assert.deepEqual(rules('packages/chain-submit/src/a.mjs', "import { x } from '../../tx-intent/src/index.mjs';"), []);
  assert.deepEqual(rules('packages/chain-submit/src/a.mjs', "import { x } from '../../broadcast-handoff/src/index.mjs';"), []);
  assert.ok(rules('packages/chain-submit/src/a.mjs', "import { readFileSync } from 'node:fs';").includes('builtin-not-allowed:node:fs'));
  assert.ok(rules('packages/chain-submit/src/a.mjs', "import { x } from '../../../txverify/src/index.mjs';").includes('import-outside-packages'));
  assert.ok(rules('packages/chain-submit/src/a.mjs', "import { x } from '../../../signer/src/sign.mjs';").includes('import-outside-packages'));
  assert.ok(rules('packages/chain-submit/src/a.mjs', "import { x } from '../../chain-readonly/src/index.mjs';").includes('package-not-allowed:chain-readonly'));
  for (const name of ['sign', 'createPrivateKey', 'createPublicKey', 'verify', 'randomBytes']) {
    assert.ok(rules('packages/chain-submit/src/a.mjs', `import { ${name} } from 'node:crypto';`).includes(`builtin-export-not-allowed:node:crypto#${name}`), name);
  }
});

test('nothing under packages/ may import chain-submit, chain-readonly least of all', () => {
  for (const pkg of ['chain-readonly', 'tx-prepare', 'broadcast-handoff', 'tx-intent', 'anchor', 'verifier', 'canonical']) {
    assert.ok(rules(`packages/${pkg}/src/a.mjs`, "import { x } from '../../chain-submit/src/index.mjs';").includes('package-not-allowed:chain-submit'), pkg);
  }
});

test('no file joins chain-submit to the network transport, and only tools/ may import chain-submit', () => {
  const join = "import { submitRequestBytes } from '../packages/chain-submit/src/index.mjs';\nimport { httpsTransport } from './live/https-transport.mjs';";
  assert.ok(rules('tools/submit-anchor.mjs', join).includes('write-transport-join'));
  assert.ok(rules('tools/x.test.mjs', join).includes('write-transport-join'));
  assert.ok(rules('tools/submit/submit-anchor.mjs', join.replaceAll("'../", "'../../").replace("'./live", "'../live")).includes('write-transport-join'));
  assert.ok(rules('tools/x.mjs', "import { x } from '../packages/chain-submit/src/index.mjs';\nconst t = await import(`./live/https-${'transport'}.mjs`);").includes('write-transport-join'));
  assert.ok(rules('scripts/send.mjs', "import { x } from '../packages/chain-submit/src/index.mjs';").includes('chain-submit-importer-not-allowed'));
  assert.ok(rules('tools/live/send.mjs', "import { x } from '../../packages/chain-submit/src/index.mjs';").includes('chain-submit-importer-not-allowed'));
  assert.deepEqual(rules('tools/broadcast/x.mjs', "import { x } from '../../packages/chain-submit/src/index.mjs';"), []);
});

test('tools/submit/: no command line, no transport or network module, no signer/, hashing only', () => {
  const r = (content, path = 'tools/submit/a.mjs') => rules(path, content);
  assert.deepEqual(r("import { createHash } from 'node:crypto';\nimport { readFileSync } from 'node:fs';\nimport { x } from '../../txverify/src/index.mjs';"), []);
  assert.ok(r('const [, , file] = process.argv;').includes('submit-entry-point'));
  assert.ok(r('if (import.meta.main) run();').includes('submit-entry-point'));
  assert.ok(r('#!/usr/bin/env node\nexport const a = 1;').includes('submit-entry-point'));
  assert.ok(r("import { httpsTransport } from '../live/https-transport.mjs';").includes('submit-imports-transport'));
  assert.ok(r("import { x } from '../live/other.mjs';").includes('submit-imports-transport'));
  for (const mod of ['node:https', 'node:http', 'node:net', 'node:tls', 'node:dns', 'node:dgram', 'node:http2', 'node:worker_threads', 'node:readline']) {
    assert.ok(r(`import x from '${mod}';`).includes(`submit-module-not-allowed:${mod}`), mod);
  }
  assert.ok(r("import { createSigner } from '../../signer/src/sign.mjs';").includes('signer-importer-not-allowed'));
  for (const name of ['sign', 'createPrivateKey', 'generateKeyPairSync', 'randomBytes']) assert.ok(r(`import { ${name} } from 'node:crypto';`).includes(`submit-crypto-export-not-allowed:${name}`), name);
  assert.ok(r("import { execFileSync } from 'node:child_process';").includes('submit-subprocess-not-allowed:module'));
  assert.deepEqual(r("import { execFileSync } from 'node:child_process';", 'tools/submit/python-verifier.mjs'), []);
  assert.ok(r("import { spawn } from 'node:child_process';", 'tools/submit/python-verifier.mjs').includes('submit-subprocess-not-allowed:spawn'));
  assert.ok(r('const r = await fetch(url);').includes('forbidden-identifier:fetch'));
  assert.ok(r('const k = crypto.getRandomValues(b);').includes('global-crypto'));
  assert.ok(r("import x from 'some-library';").includes('third-party-import:some-library'));
});

test('txverify/: verification only (noble keccak_256 and secp256k1 recovery), never signer/', () => {
  const r = (content, path = 'txverify/src/a.mjs') => rules(path, content);
  assert.deepEqual(r("import { keccak_256 } from '@noble/hashes/sha3.js';\nimport { secp256k1 } from '@noble/curves/secp256k1.js';\nconst s = secp256k1.Signature.fromBytes(b, 'recovered');\nconst p = s.recoverPublicKey(d);\nconst ok = secp256k1.verify(s, d, p);"), []);
  assert.deepEqual(r("import { createPublicKey, verify } from 'node:crypto';\nimport { x } from '../../packages/tx-intent/src/index.mjs';"), []);
  for (const [code, rule] of [
    ['secp256k1.sign(d, k);', 'txverify-secp256k1-member:sign'],
    ['secp256k1.getPublicKey(k);', 'txverify-signing-api:getPublicKey'],
    ['secp256k1.utils.randomSecretKey();', 'txverify-signing-api:utils'],
    ['secp256k1.keygen();', 'txverify-signing-api:keygen'],
    ["secp256k1['sign'](d, k);", 'txverify-computed-member'],
    ['const { sign } = secp256k1;', 'txverify-secp256k1-alias'],
    ['const c = secp256k1;\nc.sign(d, k);', 'txverify-secp256k1-alias'],
    ['getSharedSecret(a, b);', 'txverify-signing-api:getSharedSecret'],
  ]) assert.ok(r(`import { secp256k1 } from '@noble/curves/secp256k1.js';\n${code}`).includes(rule), code);
  assert.ok(r("import { secp256k1 as c } from '@noble/curves/secp256k1.js';").includes('txverify-library-export-not-allowed:secp256k1'));
  assert.ok(r("import * as all from '@noble/curves/secp256k1.js';").includes('txverify-library-export-not-allowed:*'));
  assert.ok(r("import { sha256 } from '@noble/hashes/sha2.js';").includes('third-party-import:@noble/hashes/sha2.js'));
  assert.ok(r("import { sign } from 'node:crypto';").includes('builtin-export-not-allowed:node:crypto#sign'));
  assert.ok(r("import { createPrivateKey } from 'node:crypto';").includes('builtin-export-not-allowed:node:crypto#createPrivateKey'));
  assert.ok(r("import { readFileSync } from 'node:fs';").includes('builtin-not-allowed:node:fs'));
  assert.ok(r("import { x } from '../../signer/src/crypto.mjs';").includes('txverify-import-not-allowed:signer/src/crypto.mjs'));
  assert.ok(r("import { x } from '../../packages/chain-submit/src/index.mjs';").includes('txverify-import-not-allowed:packages/chain-submit/src/index.mjs'));
  assert.ok(r("import { x } from '../test/helper.mjs';").includes('production-imports-non-production:test/helper.mjs'));
  assert.ok(r('export const a = 1;', 'txverify/scripts/a.mjs').includes('non-module-file'));
  assert.ok(check([{ path: 'txverify', content: null, symlink: true }]).some((f) => f.rule === 'symlink-in-package'));
});

test('txverify/ manifest and lockfile pin exactly the two noble packages under its own name', () => {
  const manifest = { name: 'rn-net-txverify', private: true, dependencies: { '@noble/curves': '2.4.0', '@noble/hashes': '2.4.0' } };
  assert.deepEqual(rules('txverify/package.json', JSON.stringify(manifest)), []);
  assert.ok(rules('txverify/package.json', JSON.stringify({ ...manifest, name: 'rn-net-signer' })).includes('txverify-manifest-name'));
  assert.ok(rules('txverify/package.json', JSON.stringify({ ...manifest, scripts: { postinstall: 'x' } })).includes('signer-manifest-field-not-allowed:scripts'));
  assert.ok(rules('txverify/package.json', JSON.stringify({ ...manifest, dependencies: { ...manifest.dependencies, 'left-pad': '1.0.0' } })).includes('undeclared-dependencies'));
  const lock = JSON.parse(readFileSync(new URL('../../txverify/package-lock.json', import.meta.url), 'utf8'));
  assert.deepEqual(rules('txverify/package-lock.json', JSON.stringify(lock)), []);
  assert.ok(rules('txverify/package-lock.json', JSON.stringify({ ...lock, name: 'rn-net-signer' })).includes('undeclared-lockfile-packages'));
  const signerLock = JSON.parse(readFileSync(new URL('../../signer/package-lock.json', import.meta.url), 'utf8'));
  assert.ok(rules('txverify/package-lock.json', JSON.stringify(signerLock)).includes('undeclared-lockfile-packages'));
});

test('signer/ may use txverify/ through its entry point only', () => {
  assert.deepEqual(rules('signer/src/a.mjs', "import { keccak256 } from '../../txverify/src/index.mjs';"), []);
  assert.ok(rules('signer/src/a.mjs', "import { keccak256 } from '../../txverify/src/crypto.mjs';").includes('signer-import-not-allowed:txverify/src/crypto.mjs'));
});

test('an entry point reaching the write path through tools/submit/ is a join too (B3 review B1)', () => {
  const entry = (submit, live) => `#!/usr/bin/env node
import { runBroadcast } from '${submit}/broadcaster.mjs';
import { pythonReferenceVerifier } from '${submit}/python-verifier.mjs';
import { httpsTransport } from '${live}/https-transport.mjs';
const [, , ...args] = process.argv;
await runBroadcast({ inputs: JSON.parse(args[0]), environment: { transport: httpsTransport, referenceVerifier: pythonReferenceVerifier() } });
`;
  for (const [path, submit, live] of [
    ['tools/submit-anchor.mjs', './submit', './live'],
    ['tools/live/submit-anchor.mjs', '../submit', '.'],
    ['scripts/submit-anchor.mjs', '../tools/submit', '../tools/live'],
    ['tools/broadcast/send.mjs', '../submit', '../live'],
    // Specifiers that do not resolve to the real files are still read as reaching them.
    ['tools/live/send.mjs', './submit', './live'],
  ]) {
    assert.ok(rules(path, entry(submit, live)).includes('write-transport-join'), path);
  }
  assert.ok(rules('scripts/run.mjs', "import { runStatusCheck } from '../tools/submit/status.mjs';").includes('chain-submit-importer-not-allowed'));
  assert.deepEqual(rules('tools/broadcast/x.mjs', "import { runBroadcast } from '../submit/broadcaster.mjs';"), []);
});

test('the write path and the transport never meet through re-exports (B3 review B1, re-check)', () => {
  const many = (files) => check(files.map(([path, content]) => ({ path, content, symlink: false }))).filter((f) => f.rule === 'write-transport-join-transitive').map((f) => f.path);
  const transport = ['tools/live/https-transport.mjs', 'export const httpsTransport = () => {};'];
  const harness = ['tools/submit/broadcaster.mjs', 'export const runBroadcast = () => {};'];
  // Route 1: the harness re-exported from an allowed directory.
  assert.deepEqual(many([transport, harness,
    ['tools/broadcast/run.mjs', "export { runBroadcast } from '../submit/broadcaster.mjs';"],
    ['tools/send.mjs', "import { runBroadcast } from './broadcast/run.mjs';\nimport { httpsTransport } from './live/https-transport.mjs';"],
  ]), ['tools/send.mjs']);
  // Route 2: the transport re-exported from a plain helper.
  assert.deepEqual(many([transport, harness,
    ['tools/net.mjs', "export { httpsTransport as t } from './live/https-transport.mjs';"],
    ['tools/broadcast/send.mjs', "import { runBroadcast } from '../submit/broadcaster.mjs';\nimport { t } from '../net.mjs';"],
  ]), ['tools/broadcast/send.mjs']);
  // Through chain-submit and a literal dynamic import, two hops away.
  assert.deepEqual(many([transport, ['packages/chain-submit/src/index.mjs', 'export const a = 1;'],
    ['tools/a.mjs', "export * from '../packages/chain-submit/src/index.mjs';"],
    ['tools/b.mjs', "export * from './a.mjs';"],
    ['scripts/c.mjs', "import { a } from '../tools/b.mjs';\nconst t = await import('../tools/live/https-transport.mjs');"],
  ]), ['scripts/c.mjs']);
  // Either side alone is fine.
  assert.deepEqual(many([transport, harness,
    ['tools/broadcast/run.mjs', "export { runBroadcast } from '../submit/broadcaster.mjs';"],
    ['tools/verify.mjs', "import { httpsTransport } from './live/https-transport.mjs';"],
  ]), []);
});

test('the write/network closure: queries, joins inside the write side, symlinks, copied transports (B3 review B1, third check)', () => {
  const found = (files) => check(files.map(([path, content, symlink]) => ({ path, content, symlink: symlink === true }))).filter((f) => ['write-transport-join-transitive', 'symlink-in-package'].includes(f.rule)).map((f) => `${f.path}:${f.rule}`);
  const transport = ['tools/live/https-transport.mjs', "import { request } from 'node:https';\nexport const httpsTransport = () => request;"];
  const harness = ['tools/submit/broadcaster.mjs', 'export const runBroadcast = () => {};'];
  const entry = (from, net) => ['tools/send.mjs', `import { runBroadcast } from '${from}';\nimport { t } from '${net}';`];
  const join = 'tools/send.mjs:write-transport-join-transitive';
  // 1. A query or fragment on either import.
  assert.deepEqual(found([transport, harness, ['tools/net.mjs', "export { httpsTransport as t } from './live/https-transport.mjs?v=1';"], entry('./submit/broadcaster.mjs', './net.mjs')]), [join]);
  assert.deepEqual(found([transport, harness, ['tools/net.mjs', "export { httpsTransport as t } from './live/https-transport.mjs';"], entry('./submit/broadcaster.mjs#x', './net.mjs')]), [join]);
  // 2. A join inside tools/submit/ itself.
  assert.deepEqual(found([transport, harness, ['tools/net.mjs', "export { httpsTransport as t } from './live/https-transport.mjs';"],
    ['tools/submit/live.mjs', "import { runBroadcast } from './broadcaster.mjs';\nimport { t } from '../net.mjs';"]]), ['tools/submit/live.mjs:write-transport-join-transitive']);
  // 3. A symlink anywhere under tools/.
  assert.deepEqual(found([['tools/sub', null, true]]), ['tools/sub:symlink-in-package']);
  // 4. A copy of the transport: any file importing a network built-in counts as one.
  assert.deepEqual(found([harness, ['tools/net/https-client.mjs', "import { request } from 'node:https';\nexport const t = request;"], entry('./submit/broadcaster.mjs', './net/https-client.mjs')]), [join]);
  // Percent-encoded specifiers are read as Node reads them.
  assert.deepEqual(found([transport, harness, ['tools/net.mjs', "export { httpsTransport as t } from './live/https-transport.mjs';"], entry('./%73ubmit/broadcaster.mjs', './net.mjs')]), [join]);
});

test('the transport path counts as network even when the file itself is not in the list', () => {
  const found = check([
    { path: 'tools/broadcast/run.mjs', content: "export { runBroadcast } from '../submit/broadcaster.mjs';", symlink: false },
    { path: 'tools/send.mjs', content: "import { runBroadcast } from './broadcast/run.mjs';\nimport { httpsTransport } from './live/https-transport.mjs';", symlink: false },
  ]).filter((f) => f.rule === 'write-transport-join-transitive').map((f) => f.path);
  assert.deepEqual(found, ['tools/send.mjs']);
});

// RN-NET-03B2-C4 (ADR-RN-017 Amendment C1, K1 to K5): the narrow exceptions for key generation and
// the terminal, each pinned, and the limits of the founder key tool.
test('C4 key generation: randomness in signer/src/keygen.mjs only, through two exports only', () => {
  const keygen = 'signer/src/keygen.mjs';
  assert.deepEqual(rules(keygen, "import { generateKeyPairSync, randomBytes } from 'node:crypto';"), []);
  for (const name of ['randomFillSync', 'randomInt', 'generateKeyPair', 'createSecretKey', 'getRandomValues', 'webcrypto']) {
    assert.ok(rules(keygen, `import { ${name} } from 'node:crypto';`).includes(`builtin-export-not-allowed:node:crypto#${name}`), name);
  }
  // noble's key generation stays refused, in keygen.mjs too.
  assert.ok(rules(keygen, "import { secp256k1 } from '@noble/curves/secp256k1.js';\nconst k = secp256k1.utils.randomSecretKey();").includes('key-generation:randomSecretKey'));
  assert.ok(rules(keygen, 'const k = s.keygen();').includes('key-generation:keygen'));
  assert.ok(rules(keygen, 'const r = crypto.getRandomValues(new Uint8Array(32));').includes('global-crypto'));
  assert.ok(rules(keygen, "import { readFileSync } from 'node:fs';").includes('builtin-not-allowed:node:fs'));
  // The same imports anywhere else in signer/ are refused, as before C4.
  for (const path of ['signer/src/sign.mjs', 'signer/src/keyfile.mjs', 'signer/src/keygen2.mjs', 'signer/test/a.test.mjs']) {
    assert.ok(rules(path, "import { randomBytes } from 'node:crypto';").includes('builtin-export-not-allowed:node:crypto#randomBytes'), path);
  }
  // Only signer tests may import keygen.mjs inside signer/.
  assert.deepEqual(rules('signer/src/sign.mjs', "import { generateKey } from './keygen.mjs';"), ['signer-keygen-import-not-allowed']);
  assert.deepEqual(rules('signer/test/a.test.mjs', "import { test } from 'node:test';\nimport { generateKey } from '../src/keygen.mjs';"), []);
  // Outside signer/, only the key tool's entry point, its tests and the C4 fixture generator.
  assert.deepEqual(rules('tools/keytool/cli.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';"), []);
  assert.deepEqual(rules('tools/signing/build-b1-fixtures.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';"), ['keygen-importer-not-allowed', 'keygen-reached-transitively']);
  assert.deepEqual(rules('tools/broadcast/build-b3-fixtures.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';"), ['keygen-importer-not-allowed', 'keygen-reached-transitively']);
  assert.ok(rules('tools/genesis/x.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';").includes('keygen-importer-not-allowed'));
  assert.ok(rules('tools/submit/x.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';").includes('keygen-importer-not-allowed'));
});

test('C4 key tool: only cli.mjs imports signer/ (three files of it), and only terminal.mjs touches the terminal', () => {
  const cli = 'tools/keytool/cli.mjs';
  assert.deepEqual(rules(cli, "import { createSigner } from '../../signer/src/sign.mjs';\nimport { encryptKeyFile } from '../../signer/src/keyfile.mjs';"), []);
  assert.ok(rules(cli, "import { bindKey } from '../../signer/src/keys.mjs';").includes('keytool-signer-import-not-allowed:signer/src/keys.mjs'));
  assert.ok(rules(cli, "import { secp256k1SignDigest } from '../../signer/src/crypto.mjs';").includes('keytool-signer-import-not-allowed:signer/src/crypto.mjs'));
  assert.ok(rules(cli, "import { fixtureKey } from '../../signer/test/fixture-keys.mjs';").includes('keytool-signer-import-not-allowed:signer/test/fixture-keys.mjs'));
  for (const path of ['tools/keytool/keystore.mjs', 'tools/keytool/signlog.mjs', 'tools/keytool/new.mjs']) {
    const found = rules(path, "import { createSigner } from '../../signer/src/sign.mjs';");
    assert.ok(found.includes('signer-importer-not-allowed') && found.includes('keytool-signer-import-not-allowed:signer/src/sign.mjs'), path);
  }
  // The terminal.
  assert.deepEqual(rules('tools/keytool/terminal.mjs', "import { isatty, ReadStream } from 'node:tty';\nconst f = '/dev/tty';\nconst s = (x) => x.setRawMode(true);"), []);
  for (const content of ["import { ReadStream } from 'node:tty';", "const f = '/dev/tty';", 'const s = (x) => x.setRawMode(false);']) {
    assert.ok(rules(cli, content).includes('keytool-terminal-outside-terminal-module'), content);
    assert.ok(rules('tools/keytool/signlog.mjs', content).includes('keytool-terminal-outside-terminal-module'), content);
  }
  // Only cli.mjs is an entry point.
  assert.deepEqual(rules(cli, '#!/usr/bin/env node\nconst a = process.argv;'), []);
  assert.ok(rules('tools/keytool/signlog.mjs', 'const a = process.argv;').includes('keytool-entry-point'));
  assert.ok(rules('tools/keytool/signlog.mjs', '#!/usr/bin/env node\n').includes('keytool-entry-point'));
});

test('C4 key tool: no environment variable, network, child process, code loader or randomness', () => {
  const path = 'tools/keytool/cli.mjs';
  for (const content of ['const p = process.env.PASS;', 'const p = process?.env;', "const p = process['env'];", 'const { env } = process;', 'const { argv, env: e } = process;', 'const p = process;']) {
    assert.ok(rules(path, content).includes('keytool-environment'), content);
  }
  for (const mod of ['node:https', 'node:http', 'node:net', 'node:tls', 'node:dns', 'node:dgram', 'node:http2', 'node:child_process', 'node:worker_threads', 'node:cluster', 'node:vm', 'node:readline', 'node:module', 'node:inspector']) {
    assert.ok(rules(path, `import x from '${mod}';`).includes(`keytool-module-not-allowed:${mod}`), mod);
  }
  for (const name of ['randomBytes', 'generateKeyPairSync', 'createPrivateKey', 'sign', 'scryptSync', 'createDecipheriv']) {
    assert.ok(rules(path, `import { ${name} } from 'node:crypto';`).includes(`keytool-crypto-export-not-allowed:${name}`), name);
  }
  assert.deepEqual(rules(path, "import { createHash } from 'node:crypto';"), []);
  assert.ok(rules(path, "const r = await fetch('https://example.org/');").length > 0);
  assert.ok(rules(path, 'const m = await import(name);').includes('dynamic-import-non-literal'));
  assert.ok(rules(path, "import { secp256k1 } from '@noble/curves/secp256k1.js';").includes('third-party-import:@noble/curves/secp256k1.js'));
  assert.ok(rules(path, 'const r = crypto.getRandomValues(new Uint8Array(8));').includes('global-crypto'));
  assert.ok(rules(path, 'const r = c.randomBytes(8);').includes('key-generation:randomBytes'));
  // The command is named keygen: as a string or key it is allowed here, as a member it is not.
  assert.deepEqual(rules(path, "const OPTIONS = { keygen: 1 };\nconst c = 'keygen';"), []);
  assert.ok(rules(path, 'const k = s.keygen();').includes('key-generation:keygen'));
  assert.ok(rules(path, "const k = s['keygen']();").includes('key-generation:keygen'));
});

test('C4 key tool: imports only its own files, canonical, tx-intent and txverify; never the network side', () => {
  const path = 'tools/keytool/keystore.mjs';
  for (const ok of ['./errors.mjs', '../../packages/canonical/src/index.mjs', '../../packages/tx-intent/src/index.mjs', '../../txverify/src/index.mjs']) assert.deepEqual(rules(path, `import { x } from '${ok}';`), [], ok);
  for (const bad of ['../live/https-transport.mjs', '../submit/broadcaster.mjs', '../../packages/chain-readonly/src/index.mjs', '../../packages/chain-submit/src/index.mjs', '../../packages/tx-prepare/src/index.mjs', '../../packages/tx-intent/src/xrpl.mjs', '../verify-live-anchor.mjs', '../broadcast/simulated.mjs']) {
    assert.ok(rules(path, `import { x } from '${bad}';`).some((r) => r.startsWith('keytool-import-not-allowed') || r === 'chain-submit-importer-not-allowed' || r === 'write-transport-join'), bad);
  }
  assert.deepEqual(rules('tools/keytool/notes.txt', 'x'), ['non-module-file']);
  assert.deepEqual(rules('tools/keytool/README.md', 'x'), []);
  assert.deepEqual(rules('tools/keytool/sub/x.mjs', ''), ['keytool-file-name']);
  // Transitively: a key-tool file may not reach a network file through anything it imports.
  const found = check([
    { path: 'tools/keytool/a.mjs', content: "import { x } from './b.mjs';", symlink: false },
    { path: 'tools/keytool/b.mjs', content: "import { request } from 'node:https';", symlink: false },
  ]).map((f) => `${f.path}:${f.rule}`);
  assert.ok(found.includes('tools/keytool/a.mjs:keytool-reaches-network'));
  assert.ok(found.includes('tools/keytool/b.mjs:keytool-reaches-network'));
  assert.ok(found.includes('tools/keytool/b.mjs:keytool-module-not-allowed:node:https'));
});

test('C4 review 5: no other secret route in the key tool, and no transitive reach of keygen or the key tool', () => {
  const path = 'tools/keytool/cli.mjs';
  for (const content of ["readFileSync('/proc/self/environ');", 'readFileSync(`/proc/${p}/environ`);', 'process.stdin.read();', "process.stdin.on('data', f);", 'readFileSync(0);', "writeFileSync('/dev/stderr', x);", "readFileSync('/dev/stdin');", "readFileSync('/dev/fd/0');", 'const u = os.userInfo();']) {
    assert.ok(rules(path, content).includes('keytool-io-route'), content);
  }
  assert.ok(!rules('tools/keytool/isolation.mjs', "readFileSync(`/proc/self/${name}`, 'utf8');").includes('keytool-io-route'));
  const found = (files) => check(files.map(([p, c]) => ({ path: p, content: c, symlink: false }))).filter((f) => f.rule === 'keygen-reached-transitively').map((f) => f.path);
  const keygen = ['signer/src/keygen.mjs', 'export const generateKey = () => {};'];
  const fixtures = ['tools/signing/build-c4-fixtures.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';\nexport const build = () => generateKey;"];
  assert.deepEqual(found([keygen, fixtures, ['tools/broadcast/x.mjs', "import { build } from '../signing/build-c4-fixtures.mjs';"]]), ['tools/broadcast/x.mjs']);
  assert.deepEqual(found([keygen, ['tools/keytool/cli.mjs', "import { generateKey } from '../../signer/src/keygen.mjs';"], ['tools/keytool.test.mjs', "import { run } from './keytool/cli.mjs';"]]), []);
  assert.deepEqual(found([['tools/keytool/signlog.mjs', 'export const x = 1;'], ['tools/signing/keytool-python.check.mjs', "import { x } from '../keytool/signlog.mjs';"], ['tools/live/y.mjs', "import { x } from '../signing/keytool-python.check.mjs';"]]), ['tools/live/y.mjs']);
});

test('C4 does not widen B1/B3 isolation: the broadcaster, packages and txverify still cannot reach the signer', () => {
  // Not through the key tool either.
  for (const [path, spec] of [['tools/submit/x.mjs', '../keytool/cli.mjs'], ['tools/broadcast/x.mjs', '../keytool/signlog.mjs'], ['tools/genesis/x.mjs', '../keytool/%63li.mjs'], ['tools/x.mjs', './keytool/cli.mjs']]) {
    assert.ok(rules(path, `import { run } from '${spec}';`).includes('keytool-importer-not-allowed'), `${path} ${spec}`);
  }
  assert.ok(rules('tools/x.mjs', 'const m = await import(`./keytool/${name}`);').includes('keytool-importer-not-allowed'));
  assert.deepEqual(rules('tools/keytool.test.mjs', "import { run } from './keytool/cli.mjs';"), []);
  assert.ok(rules('tools/submit/x.mjs', "import { createSigner } from '../../signer/src/sign.mjs';").includes('signer-importer-not-allowed'));
  assert.ok(rules('packages/chain-submit/src/x.mjs', "import { x } from '../../../tools/keytool/cli.mjs';").includes('import-outside-packages'));
  assert.ok(rules('txverify/src/x.mjs', "import { x } from '../../signer/src/keygen.mjs';").some((r) => r.startsWith('txverify-import-not-allowed')));
  assert.ok(rules('packages/tx-intent/src/x.mjs', "import { randomBytes } from 'node:crypto';").includes('builtin-export-not-allowed:node:crypto#randomBytes'));
});
