import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
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
  const acorn = { version: '8.19.0', dev: true };
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': acorn })), []);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { ...acorn, version: '8.18.0' } })), ['undeclared-lockfile-packages']);
  assert.deepEqual(rules('package-lock.json', lock({ ...root, 'node_modules/acorn': { version: '8.19.0' } })), ['undeclared-lockfile-packages']);
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

// RN-NET-01J and RN-NET-01K, N2: the bypasses found by independent reviews, kept verbatim in
// fixtures/dependency-bypasses/. Each is a valid module that loads node:net (or reaches
// process.getBuiltinModule and eval) while an earlier guard reported nothing: b1-b7 at 9521fff,
// b8 at a4b2e30 (merged as 0b32565).
const fixtures = new URL('./fixtures/dependency-bypasses/', import.meta.url);
const bypasses = readdirSync(fixtures).filter((name) => name.endsWith('.mjs')).sort();

test('the eight reviewed bypasses are all present', () => {
  assert.deepEqual(bypasses, [
    'b1-export-default.mjs', 'b2-postfix.mjs', 'b3-fnexpr.mjs', 'b4-forawait.mjs', 'b5-classexpr.mjs', 'b6-extends.mjs',
    'b7-hidden-process.mjs', 'b8-for-head.mjs',
  ]);
});

test('each reviewed bypass is caught by the syntax tree', () => {
  const read = (name) => readFileSync(new URL(name, fixtures), 'utf8');
  for (const name of bypasses.filter((n) => n !== 'b7-hidden-process.mjs')) {
    assert.deepEqual(importsOf(read(name)), ['node:net'], name);
    assert.ok(rules('packages/canonical/src/x.mjs', read(name)).includes('builtin-not-allowed:node:net'), name);
  }
  const b7 = rules('packages/canonical/src/x.mjs', read('b7-hidden-process.mjs'));
  assert.ok(b7.includes('process-access') && b7.includes('forbidden-identifier:eval'), String(b7));
});

test('b1-b7 are also caught by the raw layer; b8 shows why the raw layer is only a second layer', () => {
  const rawLayer = /^(?:string-named-import-clause$|forbidden-word:)/;
  for (const name of bypasses) {
    const found = rules('packages/canonical/src/x.mjs', readFileSync(new URL(name, fixtures), 'utf8'));
    const raw = found.filter((rule) => rawLayer.test(rule) || rule.startsWith('forbidden-construct:'));
    if (name === 'b8-for-head.mjs') assert.deepEqual(raw, [], 'a quote in a comment defeats the raw specifier pattern');
    else assert.ok(raw.length > 0, `${name}: raw layer: ${found}`);
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
