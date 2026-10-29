import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, importsOf } from './dependency-boundaries.mjs';

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
  assert.deepEqual(rules('packages/canonical/src/a.mjs', "import net from 'node:net';"), ['builtin-not-allowed:node:net']);
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
  assert.deepEqual(rules('packages/canonical/lib/x.mjs', "import net from 'node:net';"), ['builtin-not-allowed:node:net']);
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

test('fails closed on source outside the supported language', () => {
  const cases = {
    "import net from 'node:net": 'unsupported-syntax', // unterminated string
    '/* unterminated': 'unsupported-syntax',
    'const a = `x${1}': 'unsupported-syntax',
    '\\u0065val("1");': 'unsupported-syntax', // escaped identifier
    "const s = '\\101';": 'unsupported-syntax', // legacy octal escape
    'const a = `${ 1': 'unsupported-syntax', // unterminated substitution
    'import net, 5 from "node:net";': 'unrecognized-import',
    'import { a b } from "node:net";': 'unrecognized-import',
    'export { a } from net;': 'unrecognized-export',
    'export * as a;': 'unrecognized-export',
    'const o = { import: 1 };': 'unrecognized-import',
  };
  for (const [source, rule] of Object.entries(cases)) {
    assert.ok(rules('packages/canonical/src/x.mjs', source).includes(rule), `${source} -> ${rule}`);
  }
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
    'export const a = 1; export function b() {} export { a as c, b, };',
  ];
  for (const source of ok) assert.deepEqual(rules('packages/canonical/test/x.test.mjs', source), [], source);
});

test('regular expressions are told from divisions by context, failing closed where ambiguous', () => {
  // A regular expression read as a division would let a fake template literal hide the import
  // below from the tokens; the line comment hides it from simple raw patterns.
  const hidden = (prefix) => `${prefix}/\`/.test('');\nimport net from // c\n  'node:net'; // \``;
  for (const prefix of ['if (a) ', 'while (a) ', 'function f() {}\n', 'x: {}\n', 'switch (a) { case 1: {}\n']) {
    assert.ok(rules('packages/canonical/src/x.mjs', hidden(prefix)).includes('builtin-not-allowed:node:net'), prefix);
  }
  assert.deepEqual(importsOf(hidden('if (a) ')), ['node:net']);
  // Where only a parser could tell, the file is reported.
  assert.ok(rules('packages/canonical/src/x.mjs', 'x: {}\n/a/.test(s);').includes('unsupported-syntax'));
  assert.ok(rules('packages/canonical/src/x.mjs', 'const of = 4; const y = of / 2;').includes('unsupported-syntax'));
  // Ordinary divisions and regular expressions.
  const ok = [
    'const m = (a + b) / 2 / c;',
    'const r = x.return / 2 / y;',
    "const r = x.of / 2; const s = '/';",
    "const r = x.typeof / 2; const s = '/';",
    'if (a) /x/.test(s);',
    'function f() {}\n/x/.test(s);',
    'const o = { a: [1] }; const q = o.a[0] / 2;',
    'const t = `${a / 2}`; const u = /`/;',
  ];
  for (const source of ok) assert.deepEqual(rules('packages/canonical/test/x.test.mjs', source), [], source);
});
