// Enforces the import boundaries between RN-NET packages: Node.js built-ins only, no
// third-party packages, no network modules, and cross-package imports only through each
// package's public entry point (src/index.mjs).
//
// This is a source-code lint and a defense-in-depth control that catches honest mistakes and
// makes evasion visible in review. It is not a sandbox: JavaScript can always reach a module
// through constructions no static analysis can follow (a property name assembled at run time,
// for example). Network isolation of tests is enforced separately (tools/ci/offline-checks.sh).
//
// Sources are parsed into a syntax tree by Acorn (a maintained ECMAScript parser, the only
// development dependency; see docs/adr/ADR-RN-005-guard-parser-dependency.md), so comments,
// strings, template literals and regular expressions are told apart the way the language does.
// A file Acorn cannot parse as a module is reported (`unsupported-syntax`), never skipped. The
// raw-text patterns run over the whole file as a second, more conservative layer. Only
// packages/** is checked; tools/ is repository tooling and may use any built-in.
import { parse } from 'acorn';

// Built-in modules each package may import. Tests (packages/*/test/) may also use the test-only
// modules; everything else in a package is production code and may import, within its own
// package, only files under src/.
export const ALLOWED_BUILTINS = {
  canonical: [],
  commitment: ['node:buffer', 'node:crypto'],
  conformance: ['node:buffer', 'node:fs', 'node:url'],
  verifier: ['node:buffer', 'node:crypto'],
  anchor: ['node:buffer', 'node:crypto'],
  'chain-readonly': ['node:buffer', 'node:crypto'],
  'tx-intent': ['node:buffer', 'node:crypto', 'node:util'],
  'broadcast-handoff': ['node:buffer', 'node:crypto'],
  'tx-prepare': ['node:buffer', 'node:crypto'],
  // The write-request builder and classifier (ADR-RN-019 §4): hashing only, no node:fs.
  'chain-submit': ['node:buffer', 'node:crypto'],
};
const TEST_BUILTINS = ['node:test', 'node:assert/strict', 'node:buffer', 'node:crypto'];

// The only exports of those built-ins that may be imported, by name ('default' for a default
// import). An allowed module still has exports that load code or reach outside the package
// (node:test `run`, node:crypto `setEngine`, node:fs `symlinkSync`), so the allowlist is per
// export: namespace imports, other names, re-exports and dynamic imports of built-ins are
// reported.
export const ALLOWED_BUILTIN_EXPORTS = {
  'node:assert/strict': ['default'],
  'node:buffer': ['Buffer'],
  'node:crypto': ['createHash'],
  'node:fs': ['readFileSync'],
  'node:test': ['test'],
  'node:url': ['fileURLToPath'],
};
// Further exports allowed in one package's production code only.
export const PACKAGE_BUILTIN_EXPORTS = {
  // createPublicKey and verify check Ed25519 signatures (RN-NET-02); they cannot sign.
  verifier: { 'node:crypto': ['createPublicKey', 'verify'] },
  // types.isProxy refuses Proxy objects in intents (ADR-RN-016 §3).
  'tx-intent': { 'node:util': ['types'] },
};
// Further exports allowed in test code only. Signing exists only to build test inputs, so
// production code can never hold or use a private key.
export const TEST_BUILTIN_EXPORTS = {
  'node:crypto': ['createPrivateKey', 'generateKeyPairSync', 'sign'],
};

// The only third-party packages in the repository: development tooling, never imported by
// packages/** (docs/adr/ADR-RN-005-guard-parser-dependency.md). Exact versions.
export const DEV_DEPENDENCIES = {
  acorn: {
    version: '8.19.0',
    resolved: 'https://registry.npmjs.org/acorn/-/acorn-8.19.0.tgz',
    integrity: 'sha512-oJlA3XiRm7Cyk6qFD2Jn8ak9B7jSy0qy00ADO3+8dpT0LSjFihQYv4C02LFCSYJV3Q37xYwwRy5m+IpIiUzqWw==',
  },
};
// Fields a pinned lockfile entry may have; anything else (nested dependencies, for example) is
// reported.
const LOCKFILE_ENTRY_FIELDS = ['version', 'resolved', 'integrity', 'dev', 'license', 'bin', 'engines'];

// The signer project (signer/, ADR-RN-017): a separate npm project with its own manifest and
// lockfile, holding exactly these runtime dependencies, pinned by version, source and integrity.
// Founder-approved for RN-NET-03B2-B1 only (offline, test-only signing toolchain).
export const SIGNER_DEPENDENCIES = {
  '@noble/curves': {
    version: '2.4.0',
    resolved: 'https://registry.npmjs.org/@noble/curves/-/curves-2.4.0.tgz',
    integrity: 'sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==',
    dependencies: { '@noble/hashes': '2.4.0' },
  },
  '@noble/hashes': {
    version: '2.4.0',
    resolved: 'https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz',
    integrity: 'sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==',
  },
};
const SIGNER_LOCKFILE_ENTRY_FIELDS = ['version', 'resolved', 'integrity', 'license', 'engines', 'funding', 'dependencies'];
// Manifest fields the signer project may not have: no executable, no install or run scripts.
const SIGNER_MANIFEST_FIELDS_NOT_ALLOWED = ['bin', 'scripts', 'exports', 'main', 'type', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
// What signer/ code may import. No node:fs, node:readline, network modules or child processes:
// in B1 the signer can only be called from code with key bytes its caller already holds.
export const SIGNER_BUILTINS = ['node:buffer', 'node:crypto'];
export const SIGNER_BUILTIN_EXPORTS = {
  'node:buffer': ['Buffer'],
  'node:crypto': ['createHash', 'createPrivateKey', 'createPublicKey', 'sign', 'verify', 'scryptSync', 'createCipheriv', 'createDecipheriv'],
};
export const SIGNER_THIRD_PARTY = ['@noble/hashes/sha3.js', '@noble/curves/secp256k1.js'];
// RN-NET packages signer/ may import, through their public entry points only.
export const SIGNER_PACKAGES = ['canonical', 'tx-intent'];
// The only tools/ files that may import signer/ (the B1 fixture generator and tests). A raw-text
// check over tools/, which is otherwise exempt: defense in depth, with review as the control.
export const SIGNER_IMPORTERS = ['tools/signing/build-b1-fixtures.mjs', 'tools/signing.test.mjs', 'tools/broadcast/build-b3-fixtures.mjs'];
// The guard's own tests hold such imports as string test data; they are exempt from that check
// only, by exact path.
const SIGNER_IMPORT_TEST_DATA = ['tools/guards/dependency-boundaries.test.mjs'];

// txverify/ (ADR-RN-019 §3): a separate npm project for VERIFICATION ONLY, with the same pinned noble
// packages as signer/. Founder-approved for verification-only use in RN-NET-03B2-B3; that approval
// covers no key creation and no signing. It may import only these built-in exports, the two noble
// entry points, and the canonical and tx-intent packages; never signer/.
export const TXVERIFY_DEPENDENCIES = SIGNER_DEPENDENCIES;
export const TXVERIFY_BUILTINS = ['node:buffer', 'node:crypto'];
export const TXVERIFY_BUILTIN_EXPORTS = { 'node:buffer': ['Buffer'], 'node:crypto': ['createHash', 'createPublicKey', 'verify'] };
export const TXVERIFY_THIRD_PARTY = { '@noble/hashes/sha3.js': ['keccak_256'], '@noble/curves/secp256k1.js': ['secp256k1'] };
export const TXVERIFY_PACKAGES = ['canonical', 'tx-intent'];
// The only properties txverify/ may read from `secp256k1`: the signature class (fromBytes(...,
// 'recovered') and recoverPublicKey) and verify. Names that sign, derive or generate keys are
// reported wherever they appear in txverify/.
export const TXVERIFY_SECP256K1_MEMBERS = ['Signature', 'verify'];
export const TXVERIFY_DENIED_NAMES = new Set([
  'sign', 'signAsync', 'getPublicKey', 'getSharedSecret', 'randomSecretKey', 'randomPrivateKey', 'keygen', 'utils', 'createPrivateKey',
  'generateKeyPair', 'generateKeyPairSync', 'scryptSync', 'createCipheriv', 'createDecipheriv', 'privateKey', 'secretKey',
]);

// The broadcaster harness (tools/submit/, ADR-RN-019 §4 and §1). Keyless and, in B3, offline: it may
// not import signer/, a network module or the network transport, has no command line, and may use
// node:crypto only to hash. Only python-verifier.mjs may start a subprocess (the Python reference).
export const SUBMIT_TOOLS = 'tools/submit/';
export const SUBMIT_FORBIDDEN_MODULES = ['node:http', 'node:https', 'node:http2', 'node:net', 'node:tls', 'node:dns', 'node:dgram', 'node:worker_threads', 'node:cluster', 'node:readline', 'node:repl', 'node:inspector', 'node:vm'];
export const SUBMIT_SUBPROCESS_FILES = ['tools/submit/python-verifier.mjs'];
export const SUBMIT_CRYPTO_EXPORTS = ['createHash'];
// Files that may join packages/chain-submit to tools/live/https-transport.mjs, the only network
// transport. None in RN-NET-03B2-B3: a live entry point needs gate E and its own review.
export const WRITE_TRANSPORT_JOINERS = [];
// Files outside packages/ that may import packages/chain-submit.
export const CHAIN_SUBMIT_IMPORTERS = /^(?:tools\/submit\/[^/]+\.mjs|tools\/broadcast\/[^/]+\.mjs|tools\/[^/]+\.test\.mjs|txverify\/test\/[^/]+\.test\.mjs)$/;
// Manifest fields that change what npm installs or links, beyond the dependency lists.
const MANIFEST_FIELDS_NOT_ALLOWED = ['overrides', 'workspaces', 'bundleDependencies', 'bundledDependencies'];

// A relative specifier the guard can resolve exactly as Node does: `./` or `../` followed by
// plain path segments. Node resolves specifiers as URLs, so percent-encoding (`%2e%2e` is `..`),
// backslashes (`\` is `/` in file URLs), queries and fragments could reach a file other than
// the one the specifier appears to name; such specifiers are reported, not resolved.
const RELATIVE_SPECIFIER = /^\.\.?(?:\/[A-Za-z0-9_.-]+)+$/;

// Packages each package may depend on.
export const ALLOWED_PACKAGES = {
  canonical: [],
  commitment: ['canonical'],
  conformance: ['canonical', 'commitment', 'verifier', 'anchor'],
  verifier: ['canonical', 'commitment'],
  anchor: ['canonical'],
  'chain-readonly': ['canonical', 'anchor'],
  'tx-intent': ['canonical', 'anchor'],
  'broadcast-handoff': ['tx-intent'],
  // Read-only preparation (ADR-RN-018): reads through chain-readonly, binds through tx-intent.
  'tx-prepare': ['chain-readonly', 'tx-intent'],
  // The only write requests RN-NET can express (ADR-RN-019 §4). No package lists chain-submit, so
  // nothing under packages/ can import it; chain-readonly stays read-only.
  'chain-submit': ['canonical', 'tx-intent', 'broadcast-handoff'],
};

// Whitespace, block comments or line comments, as allowed between tokens.
const GAP = String.raw`(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*`;
const STATIC_SPECIFIER = new RegExp(String.raw`(?<![\w$.])(?:import|export)\b${GAP}(?:[^'";]*?\bfrom\b${GAP})?(['"])([^'"\n]+)\1`, 'g');
const DYNAMIC_SPECIFIER = new RegExp(String.raw`(?<![\w$.])import${GAP}\(${GAP}(['"])([^'"\n]+)\1`, 'g');

// Constructions that load code or reach the network without a static import specifier.
export const FORBIDDEN_CONSTRUCTS = [
  { id: 'dynamic-import-non-literal', pattern: new RegExp(String.raw`(?<![\w$.])import${GAP}\(${GAP}(?!['"])`) },
  { id: 'require', pattern: /\brequire\s*\(/ },
  { id: 'create-require', pattern: /\bcreateRequire\b/ },
  { id: 'process-internals', pattern: /\bprocess\s*(?:\.\s*|\[\s*['"`])(?:binding|_linkedBinding|dlopen|getBuiltinModule)\b/ },
  { id: 'get-builtin-module', pattern: /\bgetBuiltinModule\b/ },
  { id: 'computed-global-access', pattern: /\b(?:globalThis|process|global)\s*\[/ },
  { id: 'global-fetch', pattern: /\bfetch\s*\(/ },
  { id: 'websocket', pattern: /\bWebSocket\b/ },
  { id: 'worker', pattern: /\bWorker\b/ },
  { id: 'eval', pattern: /\beval\s*\(/ },
  { id: 'function-constructor', pattern: /\bnew\s+Function\b|\bFunction\s*\(/ },
];

// Identifiers that load code, reach the network or reach objects that can (the global object,
// the process, the Function constructor). Flagged wherever they appear as a name, so aliasing
// (`const f = fetch`), optional calls and indirect eval are covered too. Property names after
// `.` are not names and are handled by the member rules below.
export const FORBIDDEN_IDENTIFIERS = [
  'eval', 'Function', 'fetch', 'WebSocket', 'Worker', 'require', 'createRequire', 'getBuiltinModule', 'globalThis', 'global',
  'module', 'WebAssembly', 'XMLHttpRequest', 'EventSource', 'importScripts',
];
// `process` may only be used for these properties.
const PROCESS_PROPERTIES = ['hrtime', 'version', 'versions'];
// String literals that name a code-loading route, so `x['constructor']` and
// `Reflect.get(o, 'getBuiltinModule')` are flagged. A name assembled from pieces at run time is
// beyond a static lint.
const FORBIDDEN_STRINGS = new Set([
  ...FORBIDDEN_IDENTIFIERS, 'constructor', 'process', 'binding', '_linkedBinding', 'dlopen',
]);

const PARSE_OPTIONS = { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true };

/** Child nodes of an ESTree node, with the key that holds each. */
function* children(node) {
  for (const [key, value] of Object.entries(node)) {
    if (Array.isArray(value)) {
      for (const item of value) if (item && typeof item.type === 'string') yield [key, item];
    } else if (value && typeof value.type === 'string') {
      yield [key, value];
    }
  }
}

// Whether an Identifier is only a property or member name here, not a reference to a binding.
function isPropertyName(node, parent, key) {
  if (!parent) return false;
  if (parent.type === 'MemberExpression') return key === 'property' && !parent.computed;
  if (parent.type === 'Property') return key === 'key' && !parent.computed && !parent.shorthand;
  if (parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition') return key === 'key' && !parent.computed;
  if (parent.type === 'ImportSpecifier') return key === 'imported';
  if (parent.type === 'ExportSpecifier') return key === 'exported';
  return false;
}

/**
 * Reads the module specifiers of a parsed module and reports code-loading constructions.
 * Returns { specifiers, problems }.
 */
function analyze(program) {
  const specifiers = [];
  const problems = [];
  const builtinImports = []; // { source, name } for each binding imported from a built-in
  const isBuiltin = (source) => typeof source === 'string' && source.startsWith('node:');
  const moduleName = (node) => (node.type === 'Identifier' ? node.name : node.value);
  const visit = (node, parent, key) => {
    switch (node.type) {
      case 'ImportDeclaration':
        specifiers.push(node.source.value);
        if (isBuiltin(node.source.value)) {
          for (const binding of node.specifiers) {
            const name =
              binding.type === 'ImportDefaultSpecifier' ? 'default' : binding.type === 'ImportNamespaceSpecifier' ? '*' : moduleName(binding.imported);
            builtinImports.push({ source: node.source.value, name });
          }
        }
        break;
      case 'ExportAllDeclaration':
      case 'ExportNamedDeclaration':
        if (node.source) {
          specifiers.push(node.source.value);
          if (isBuiltin(node.source.value)) problems.push(`builtin-reexport:${node.source.value}`);
        }
        break;
      case 'ImportExpression':
        // import('<specifier>') with a string literal; anything else is computed. A built-in
        // imported dynamically arrives as a whole namespace, so it is reported.
        if (node.source.type === 'Literal' && typeof node.source.value === 'string') {
          specifiers.push(node.source.value);
          if (isBuiltin(node.source.value)) problems.push(`builtin-dynamic-import:${node.source.value}`);
        } else {
          problems.push('dynamic-import-non-literal');
        }
        break;
      case 'Identifier':
        // `constructor` reaches the Function constructor from any function (`f.constructor`,
        // `const { constructor } = f`); only a class's own constructor method may use the name.
        if (node.name === 'constructor' && !(parent?.type === 'MethodDefinition' && parent.kind === 'constructor')) {
          problems.push('constructor-access');
        }
        if (isPropertyName(node, parent, key)) break;
        if (FORBIDDEN_IDENTIFIERS.includes(node.name)) problems.push(`forbidden-identifier:${node.name}`);
        if (node.name === 'process') {
          const allowed =
            parent?.type === 'MemberExpression' && key === 'object' && !parent.computed &&
            PROCESS_PROPERTIES.includes(parent.property.name);
          if (!allowed) problems.push('process-access');
        }
        break;
      case 'Literal':
        if (typeof node.value === 'string' && FORBIDDEN_STRINGS.has(node.value)) problems.push(`forbidden-string:${node.value}`);
        break;
      case 'TemplateElement':
        if (FORBIDDEN_STRINGS.has(node.value.cooked ?? node.value.raw)) problems.push(`forbidden-string:${node.value.cooked ?? node.value.raw}`);
        break;
    }
    for (const [childKey, child] of children(node)) visit(child, node, childKey);
  };
  visit(program, null, null);
  return { specifiers, problems, builtinImports };
}

/** Module specifiers of a source: every import, re-export and literal dynamic import, in order. */
export function importsOf(content) {
  return analyze(parse(content, PARSE_OPTIONS)).specifiers;
}

// The earlier raw-text extraction, kept as a conservative second layer.
function rawImportsOf(content) {
  return [...content.matchAll(STATIC_SPECIFIER), ...content.matchAll(DYNAMIC_SPECIFIER)].map((m) => m[2]);
}

// Raw-text rules that do not depend on tokenizing correctly: they match anywhere in the file,
// comments and strings included, so they hold even where the parse is somehow wrong. They are
// deliberately broad; reword a comment rather than weaken them.
const RAW_WORD = (word) => new RegExp(String.raw`(?<![\w$])${word}(?![\w$])`);
const RAW_RULES = [
  ...FORBIDDEN_IDENTIFIERS.map((word) => ({ id: `forbidden-word:${word}`, pattern: RAW_WORD(word) })),
  {
    id: 'forbidden-word:process',
    pattern: new RegExp(String.raw`(?<![\w$])process(?![\w$])(?!${GAP}\.${GAP}(?:hrtime|versions?)(?![\w$]))`),
  },
  // import { 'name' as x } and export { x as 'name' }: the raw specifier patterns cannot read them.
  { id: 'string-named-import-clause', pattern: new RegExp(String.raw`(?<![\w$.])(?:import|export)${GAP}(?:[\w$]+${GAP},${GAP})?\{[^}]*['"\x60]`) },
];

/** Repository path a relative specifier names, or null where Node's URL resolution differs. */
function resolve(fromPath, specifier) {
  if (!RELATIVE_SPECIFIER.test(specifier)) return null;
  const parts = fromPath.split('/').slice(0, -1);
  for (const segment of specifier.split('/')) {
    if (segment === '..') parts.pop();
    else if (segment !== '.') parts.push(segment);
  }
  const resolved = parts.join('/');
  // Cross-check against URL resolution, the way Node resolves module specifiers.
  const viaUrl = new URL(specifier, `file:///repository/${fromPath}`).pathname;
  return viaUrl === `/repository/${resolved}` ? resolved : null;
}

export function check(files) {
  const findings = [];
  const add = (path, rule) => findings.push({ path, rule });

  for (const { path, content, symlink } of files) {
    const name = path.split('/').at(-1);
    if (name === 'npm-shrinkwrap.json' || name === '.npmrc') add(path, `not-allowed:${name}`);
    if (name === 'package.json' && content !== null) {
      const manifest = JSON.parse(content);
      for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const declared = Object.entries(manifest[key] ?? {});
        const allowed = path === 'package.json' && key === 'devDependencies' ? DEV_DEPENDENCIES : (path === 'signer/package.json' || path === 'txverify/package.json') && key === 'dependencies' ? SIGNER_DEPENDENCIES : {};
        if (declared.some(([dependency, version]) => allowed[dependency]?.version !== version)) add(path, `undeclared-${key}`);
      }
      if (path === 'signer/package.json' || path === 'txverify/package.json') {
        const declared = Object.keys(manifest.dependencies ?? {}).sort().join(',');
        if (declared !== Object.keys(SIGNER_DEPENDENCIES).sort().join(',')) add(path, 'signer-dependencies-incomplete');
        for (const field of SIGNER_MANIFEST_FIELDS_NOT_ALLOWED) if (Object.hasOwn(manifest, field)) add(path, `signer-manifest-field-not-allowed:${field}`);
        if (path === 'txverify/package.json' && manifest.name !== 'rn-net-txverify') add(path, 'txverify-manifest-name');
      }
      for (const field of MANIFEST_FIELDS_NOT_ALLOWED) if (Object.hasOwn(manifest, field)) add(path, `manifest-field-not-allowed:${field}`);
    }
    if (name === 'package-lock.json' && content !== null) {
      // Exactly the root project and the allowed development dependencies, pinned by version,
      // source and integrity.
      const entries = Object.entries(JSON.parse(content).packages ?? {});
      const expected = new Map(Object.entries(DEV_DEPENDENCIES).map(([dependency, pin]) => [`node_modules/${dependency}`, pin]));
      const matches = ([where, entry]) => {
        if (where === '') return true;
        const pin = expected.get(where);
        return (
          pin !== undefined &&
          entry.dev === true &&
          ['version', 'resolved', 'integrity'].every((field) => entry[field] === pin[field]) &&
          Object.keys(entry).every((field) => LOCKFILE_ENTRY_FIELDS.includes(field))
        );
      };
      const valid = path === 'package-lock.json' && entries.length === expected.size + 1 && Object.hasOwn(Object.fromEntries(entries), '') && entries.every(matches);
      if (path === 'signer/package-lock.json' || path === 'txverify/package-lock.json') {
        const projectName = path === 'signer/package-lock.json' ? 'rn-net-signer' : 'rn-net-txverify';
        // Exactly the signer project and its pinned runtime dependencies (never `dev`).
        const pins = new Map(Object.entries(SIGNER_DEPENDENCIES).map(([dependency, pin]) => [`node_modules/${dependency}`, pin]));
        const pinned = ([where, entry]) => {
          if (where === '') return true;
          const pin = pins.get(where);
          return (
            pin !== undefined &&
            entry.dev === undefined &&
            ['version', 'resolved', 'integrity'].every((field) => entry[field] === pin[field]) &&
            JSON.stringify(entry.dependencies ?? null) === JSON.stringify(pin.dependencies ?? null) &&
            Object.keys(entry).every((field) => SIGNER_LOCKFILE_ENTRY_FIELDS.includes(field))
          );
        };
        const lockfile = JSON.parse(content);
        const rootEntry = Object.fromEntries(entries)[''];
        const wantedRoot = { name: projectName, dependencies: Object.fromEntries(Object.entries(SIGNER_DEPENDENCIES).map(([d, pin]) => [d, pin.version])) };
        const rootValid =
          Object.keys(lockfile).sort().join(',') === 'lockfileVersion,name,packages,requires' &&
          lockfile.name === projectName && lockfile.lockfileVersion === 3 && lockfile.requires === true &&
          rootEntry !== undefined && JSON.stringify(Object.keys(rootEntry).sort()) === '["dependencies","name"]' &&
          rootEntry.name === wantedRoot.name &&
          JSON.stringify(Object.entries(rootEntry.dependencies).sort()) === JSON.stringify(Object.entries(wantedRoot.dependencies).sort());
        const signerValid = rootValid && entries.length === pins.size + 1 && entries.every(pinned);
        if (!signerValid) add(path, 'undeclared-lockfile-packages');
      } else if (!valid) add(path, 'undeclared-lockfile-packages');
    }
    // Node resolves a symlinked module's imports from its real path, not from where it is linked;
    // a linked package directory moves everything under it.
    // tools/ too: a link (tools/sub -> tools/submit) would hide the write side from the import graph.
    if (symlink && (path === 'packages' || path.startsWith('packages/') || path === 'signer' || path.startsWith('signer/') || path === 'txverify' || path.startsWith('txverify/') || path === 'tools' || path.startsWith('tools/'))) {
      add(path, 'symlink-in-package');
      continue;
    }
    if (path.startsWith('signer/')) {
      checkSigner(path, content, add);
      continue;
    }
    if (path.startsWith('txverify/')) {
      checkTxverify(path, content, add);
      continue;
    }
    if (!path.startsWith('packages/') && /\.(mjs|js|cjs|mts|cts|ts)$/.test(path) && content !== null) {
      checkToolsSignerImports(path, content, add);
      checkWriteTransportJoin(path, content, add);
      if (path.startsWith(SUBMIT_TOOLS)) checkSubmitTools(path, content, add);
      if (path.startsWith('tools/')) continue;
    }
    const match = /^packages\/([^/]+)\/(.+)$/.exec(path);
    if (!match) continue;
    const [, pkg, rest] = match;
    if (!Object.hasOwn(ALLOWED_PACKAGES, pkg)) {
      add(path, 'unregistered-package');
      continue;
    }
    // Only ES modules (plus a README or manifest) may live in a package, so no code file escapes
    // the checks below (.js, .cjs, ...).
    if (!path.endsWith('.mjs')) {
      if (!path.endsWith('/README.md') && !path.endsWith('/package.json')) add(path, 'non-module-file');
      continue;
    }
    if (content === null) {
      add(path, 'unreadable-module');
      continue;
    }
    for (const { id, pattern } of FORBIDDEN_CONSTRUCTS) {
      if (pattern.test(content)) add(path, `forbidden-construct:${id}`);
    }
    for (const { id, pattern } of RAW_RULES) {
      if (pattern.test(content)) add(path, id);
    }
    let analysis;
    try {
      analysis = analyze(parse(content, PARSE_OPTIONS));
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      add(path, 'unsupported-syntax');
      analysis = { specifiers: [], problems: [], builtinImports: [] };
    }
    for (const problem of new Set(analysis.problems)) add(path, problem);
    const area = rest.startsWith('test/') ? 'test' : 'src';
    if (area === 'src') for (const route of keyGenerationRoutes(content)) add(path, route);
    for (const { source, name } of analysis.builtinImports) {
      const allowed = [
        ...(ALLOWED_BUILTIN_EXPORTS[source] ?? []),
        ...(PACKAGE_BUILTIN_EXPORTS[pkg]?.[source] ?? []),
        ...(area === 'test' ? (TEST_BUILTIN_EXPORTS[source] ?? []) : []),
      ];
      if (!allowed.includes(name)) add(path, `builtin-export-not-allowed:${source}#${name}`);
    }
    const builtins = area === 'test' ? [...ALLOWED_BUILTINS[pkg], ...TEST_BUILTINS] : ALLOWED_BUILTINS[pkg];
    for (const specifier of new Set([...analysis.specifiers, ...rawImportsOf(content)])) {
      if (specifier.startsWith('node:')) {
        if (!builtins.includes(specifier)) add(path, `builtin-not-allowed:${specifier}`);
        continue;
      }
      if (!specifier.startsWith('.')) {
        add(path, `third-party-import:${specifier}`);
        continue;
      }
      const target = resolve(path, specifier);
      if (target === null) {
        add(path, `unsupported-specifier:${specifier}`);
        continue;
      }
      const targetMatch = /^packages\/([^/]+)\/(.+)$/.exec(target);
      if (!targetMatch) {
        add(path, 'import-outside-packages');
        continue;
      }
      const [, targetPkg, targetRest] = targetMatch;
      if (targetPkg === pkg) {
        // Production code (everything outside test/) imports only production code: never a test
        // file or helper, which may use test-only built-ins and capabilities.
        if (area === 'src' && !targetRest.startsWith('src/')) add(path, `production-imports-non-production:${targetRest}`);
        continue;
      }
      if (!ALLOWED_PACKAGES[pkg].includes(targetPkg)) add(path, `package-not-allowed:${targetPkg}`);
      else if (targetRest !== 'src/index.mjs') add(path, `private-import:${targetPkg}/${targetRest}`);
    }
  }
  checkWriteTransportClosure(files, add);
  return findings;
}

// The write path and the network may never meet, however indirectly (B3 review B1): over the
// graph of relative imports (static, re-exports and literal dynamic imports, with any query or
// fragment removed) of every file given:
// - a network file is tools/live/https-transport.mjs or any file importing a network built-in;
// - a write-side file (packages/chain-submit/, tools/submit/) may not reach a network file;
// - any other file may not reach both a write-side file and a network file,
// unless WRITE_TRANSPORT_JOINERS names it. A name assembled at run time is beyond a static lint.
export const TRANSPORT_FILE = 'tools/live/https-transport.mjs';
export const NETWORK_BUILTINS = ['node:http', 'node:https', 'node:http2', 'node:net', 'node:tls', 'node:dns', 'node:dgram'];
function checkWriteTransportClosure(files, add) {
  const exempt = new Set([...SIGNER_IMPORT_TEST_DATA, 'tools/guards/dependency-boundaries.mjs']);
  const edges = new Map();
  const network = new Set();
  for (const { path, content } of files) {
    if (content === null || !/\.(mjs|js|cjs|mts|cts|ts)$/.test(path) || exempt.has(path)) continue;
    let specifiers = rawImportsOf(content);
    try {
      specifiers = [...specifiers, ...importsOf(content)];
    } catch {
      // unparseable sources are reported elsewhere; the raw specifiers still count
    }
    specifiers = [...new Set(specifiers)];
    if (path === TRANSPORT_FILE || specifiers.some((sp) => NETWORK_BUILTINS.includes(sp) || NETWORK_BUILTINS.includes(`node:${sp}`))) network.add(path);
    const targets = [];
    for (const sp of specifiers.filter((x) => x.startsWith('.'))) {
      // Percent-encoding and backslashes are decoded the way Node's URL resolution reads them; a
      // specifier that still names no repository path (test data above the root) adds no edge.
      const bare = sp.replace(/[?#].*$/s, '');
      const target = resolve(path, bare) ?? resolve(path, safeDecode(bare).replace(/[?#].*$/s, ''));
      if (target !== null) targets.push(target);
    }
    edges.set(path, targets);
  }
  const isWrite = (p) => p.startsWith('packages/chain-submit/') || p.startsWith(SUBMIT_TOOLS);
  for (const path of edges.keys()) {
    if (WRITE_TRANSPORT_JOINERS.includes(path)) continue;
    const seen = new Set([path]);
    const stack = [path];
    while (stack.length) {
      const at = stack.pop();
      for (const next of edges.get(at) ?? []) if (!seen.has(next)) { seen.add(next); stack.push(next); }
    }
    const reachesNetwork = [...seen].some((p) => p === TRANSPORT_FILE || network.has(p));
    const reachesWrite = [...seen].some(isWrite);
    if (isWrite(path) ? reachesNetwork : reachesWrite && reachesNetwork && path !== TRANSPORT_FILE) add(path, 'write-transport-join-transitive');
  }
}

// signer/ (ADR-RN-017): parsed like packages/, with its own allowlist of built-ins, exports,
// third-party specifiers and RN-NET packages.
function checkSigner(path, content, add) {
  const rest = path.slice('signer/'.length);
  if (['package.json', 'package-lock.json', 'README.md'].includes(rest)) return;
  if (!path.endsWith('.mjs') || !/^(src|test)\//.test(rest)) {
    add(path, 'non-module-file');
    return;
  }
  if (content === null) {
    add(path, 'unreadable-module');
    return;
  }
  for (const { id, pattern } of FORBIDDEN_CONSTRUCTS) if (pattern.test(content)) add(path, `forbidden-construct:${id}`);
  for (const { id, pattern } of RAW_RULES) if (pattern.test(content)) add(path, id);
  let analysis;
  try {
    analysis = analyze(parse(content, PARSE_OPTIONS));
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    add(path, 'unsupported-syntax');
    analysis = { specifiers: [], problems: [], builtinImports: [] };
  }
  for (const problem of new Set(analysis.problems)) add(path, problem);
  for (const route of keyGenerationRoutes(content)) add(path, route);
  const area = rest.startsWith('test/') ? 'test' : 'src';
  for (const { source, name } of analysis.builtinImports) {
    // Signer tests get the test built-ins, but not the test-only key APIs of packages/.
    const allowed = [...(SIGNER_BUILTIN_EXPORTS[source] ?? []), ...(area === 'test' ? ALLOWED_BUILTIN_EXPORTS[source] ?? [] : [])];
    if (!allowed.includes(name)) add(path, `builtin-export-not-allowed:${source}#${name}`);
  }
  const builtins = area === 'test' ? [...SIGNER_BUILTINS, ...TEST_BUILTINS] : SIGNER_BUILTINS;
  for (const specifier of new Set([...analysis.specifiers, ...rawImportsOf(content)])) {
    if (specifier.startsWith('node:')) {
      if (!builtins.includes(specifier)) add(path, `builtin-not-allowed:${specifier}`);
      continue;
    }
    if (!specifier.startsWith('.')) {
      if (!SIGNER_THIRD_PARTY.includes(specifier)) add(path, `third-party-import:${specifier}`);
      continue;
    }
    const target = resolve(path, specifier);
    if (target === null) {
      add(path, `unsupported-specifier:${specifier}`);
      continue;
    }
    if (target.startsWith('signer/')) {
      if (area === 'src' && !target.startsWith('signer/src/')) add(path, `production-imports-non-production:${target.slice('signer/'.length)}`);
      continue;
    }
    // The signer's self-check uses the shared verifier (ADR-RN-019 §3), through its entry point.
    if (target === 'txverify/src/index.mjs') continue;
    const pkg = /^packages\/([^/]+)\/src\/index\.mjs$/.exec(target);
    if (!pkg || !SIGNER_PACKAGES.includes(pkg[1])) add(path, `signer-import-not-allowed:${target}`);
  }
}

// tools/ is trusted tooling and exempt from the import allowlists, except that only the files in
// SIGNER_IMPORTERS may import signer/ or the signer's libraries.
function checkToolsSignerImports(path, content, add) {
  if (SIGNER_IMPORTERS.includes(path) || SIGNER_IMPORT_TEST_DATA.includes(path)) return;
  // Routes the specifier patterns cannot read: a template-literal import(), or a require-style
  // loader on one line, naming the signer directory.
  if (/import\s*\(\s*`[^`]*\bsigner\/|createRequire[^\n]*\bsigner\//.test(content)) add(path, 'signer-importer-not-allowed');
  for (const specifier of new Set(rawImportsOf(content))) {
    if (specifier.startsWith('@noble/')) add(path, 'signer-library-outside-signer');
    if (!specifier.startsWith('.')) continue;
    const target = resolve(path, specifier);
    if (target === 'signer' || target?.startsWith('signer/')) add(path, 'signer-importer-not-allowed');
    // A specifier the guard cannot resolve exactly (percent-encoding, backslashes) is reported
    // only if it could name signer/; the guard's own tests use such specifiers as test data.
    else if (target === null && /signer/i.test(safeDecode(specifier))) add(path, 'signer-importer-not-allowed');
  }
}

function safeDecode(specifier) {
  try {
    return decodeURIComponent(specifier).replaceAll('\\', '/');
  } catch {
    return specifier;
  }
}

// Names that generate keys or reach randomness without an import: the global WebCrypto object and
// the key-generation helpers of the signer's libraries. Reported in packages/ and signer/ (B1 has
// no key generation, ADR-RN-017 §5). A name built at run time is beyond a static lint.
const KEYGEN_PROPERTIES = new Set(['randomSecretKey', 'randomPrivateKey', 'keygen', 'getRandomValues', 'generateKey', 'generateKeyPair', 'generateKeyPairSync', 'randomBytes', 'subtle']);
export function keyGenerationRoutes(content) {
  const found = new Set();
  let program;
  try {
    program = parse(content, PARSE_OPTIONS);
  } catch {
    return found;
  }
  const visit = (node, parent, key) => {
    if (node.type === 'Identifier' && node.name === 'crypto' && !isPropertyName(node, parent, key)) found.add('global-crypto');
    if (node.type === 'MemberExpression' && !node.computed && KEYGEN_PROPERTIES.has(node.property.name)) found.add(`key-generation:${node.property.name}`);
    if (node.type === 'Literal' && typeof node.value === 'string' && KEYGEN_PROPERTIES.has(node.value)) found.add(`key-generation:${node.value}`);
    // Destructuring, as in `const { randomSecretKey } = secp256k1.utils`.
    if (node.type === 'Property' && !node.computed && node.key.type === 'Identifier' && KEYGEN_PROPERTIES.has(node.key.name)) found.add(`key-generation:${node.key.name}`);
    for (const [childKey, child] of children(node)) visit(child, node, childKey);
  };
  visit(program, null, null);
  return found;
}

// A file outside packages/ that imports packages/chain-submit or tools/submit/: it must be one of the allowed
// importers, and it may not also reach the network transport unless WRITE_TRANSPORT_JOINERS names
// it (none in RN-NET-03B2-B3). The transport check is raw text: any mention of https-transport in
// such a file is reported, whatever the import form.
function checkWriteTransportJoin(path, content, add) {
  // The guard's own source and tests name these paths as patterns and test data.
  if (SIGNER_IMPORT_TEST_DATA.includes(path) || path === 'tools/guards/dependency-boundaries.mjs') return;
  const targets = [...new Set(rawImportsOf(content))].filter((s) => s.startsWith('.')).map((s) => resolve(path, s));
  // Reaching the write path means importing chain-submit or the harness in tools/submit/ (which
  // imports chain-submit). Raw text: any file naming either is treated as importing it.
  const importsSubmit =
    targets.some((t) => t?.startsWith('packages/chain-submit/') || t?.startsWith(SUBMIT_TOOLS)) ||
    /chain-submit\/src|submit\/(?:broadcaster|status|store|python-verifier)(?:\.mjs)?\b/.test(content);
  if (!importsSubmit) return;
  if (!CHAIN_SUBMIT_IMPORTERS.test(path)) add(path, 'chain-submit-importer-not-allowed');
  if (WRITE_TRANSPORT_JOINERS.includes(path)) return;
  // A computed dynamic import could assemble the transport's path at run time, so such a file may
  // not have one at all; nor may it import anything under tools/live/.
  let computedImport = true;
  try {
    computedImport = analyze(parse(content, PARSE_OPTIONS)).problems.includes('dynamic-import-non-literal');
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
  }
  if (/https-transport|httpsTransport/.test(content) || computedImport || targets.some((t) => t?.startsWith('tools/live/'))) add(path, 'write-transport-join');
}

// tools/submit/: the keyless, offline broadcaster harness.
function checkSubmitTools(path, content, add) {
  if (!path.endsWith('.mjs')) {
    if (!path.endsWith('/README.md')) add(path, 'non-module-file');
    return;
  }
  if (content.startsWith('#!') || /process\s*\.\s*argv|import\s*\.\s*meta\s*\.\s*main/.test(content)) add(path, 'submit-entry-point');
  if (/https-transport|httpsTransport/.test(content)) add(path, 'submit-imports-transport');
  let program;
  try {
    program = parse(content, PARSE_OPTIONS);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    add(path, 'unsupported-syntax');
    return;
  }
  const analysis = analyze(program);
  for (const problem of new Set(analysis.problems)) if (problem !== 'process-access') add(path, problem);
  for (const route of keyGenerationRoutes(content)) add(path, route);
  for (const { source, name } of analysis.builtinImports) {
    if (source === 'node:crypto' && !SUBMIT_CRYPTO_EXPORTS.includes(name)) add(path, `submit-crypto-export-not-allowed:${name}`);
    if (source === 'node:child_process' && !(SUBMIT_SUBPROCESS_FILES.includes(path) && name === 'execFileSync')) add(path, `submit-subprocess-not-allowed:${name}`);
  }
  for (const specifier of new Set([...analysis.specifiers, ...rawImportsOf(content)])) {
    if (specifier.startsWith('node:')) {
      if (SUBMIT_FORBIDDEN_MODULES.includes(specifier)) add(path, `submit-module-not-allowed:${specifier}`);
      if (specifier === 'node:child_process' && !SUBMIT_SUBPROCESS_FILES.includes(path)) add(path, 'submit-subprocess-not-allowed:module');
      continue;
    }
    if (!specifier.startsWith('.')) {
      add(path, `third-party-import:${specifier}`);
      continue;
    }
    const target = resolve(path, specifier);
    if (target === null) add(path, `unsupported-specifier:${specifier}`);
    else if (target.startsWith('tools/live/')) add(path, 'submit-imports-transport');
    else if (target.startsWith('signer/') || target.startsWith('tools/signing/')) add(path, 'signer-importer-not-allowed');
  }
}

// txverify/ (ADR-RN-019 §3): parsed like signer/, with a verification-only allowlist.
function checkTxverify(path, content, add) {
  const rest = path.slice('txverify/'.length);
  if (['package.json', 'package-lock.json', 'README.md'].includes(rest)) return;
  if (!path.endsWith('.mjs') || !/^(src|test)\//.test(rest)) {
    add(path, 'non-module-file');
    return;
  }
  if (content === null) {
    add(path, 'unreadable-module');
    return;
  }
  for (const { id, pattern } of FORBIDDEN_CONSTRUCTS) if (pattern.test(content)) add(path, `forbidden-construct:${id}`);
  for (const { id, pattern } of RAW_RULES) if (pattern.test(content)) add(path, id);
  let program;
  try {
    program = parse(content, PARSE_OPTIONS);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    add(path, 'unsupported-syntax');
    return;
  }
  const analysis = analyze(program);
  for (const problem of new Set(analysis.problems)) add(path, problem);
  for (const route of keyGenerationRoutes(content)) add(path, route);
  const area = rest.startsWith('test/') ? 'test' : 'src';
  for (const { source, name } of analysis.builtinImports) {
    const allowed = [...(TXVERIFY_BUILTIN_EXPORTS[source] ?? []), ...(area === 'test' ? [...(ALLOWED_BUILTIN_EXPORTS[source] ?? [])] : [])];
    if (!allowed.includes(name)) add(path, `builtin-export-not-allowed:${source}#${name}`);
  }
  const builtins = area === 'test' ? [...TXVERIFY_BUILTINS, ...TEST_BUILTINS, 'node:fs', 'node:url'] : TXVERIFY_BUILTINS;
  // The noble entry points, and exactly the named imports each may give.
  for (const node of program.body) {
    if (node.type !== 'ImportDeclaration' || !Object.hasOwn(TXVERIFY_THIRD_PARTY, node.source.value)) continue;
    for (const binding of node.specifiers) {
      const name = binding.type === 'ImportSpecifier' ? (binding.imported.name ?? binding.imported.value) : '*';
      if (!TXVERIFY_THIRD_PARTY[node.source.value].includes(name) || binding.local.name !== name) add(path, `txverify-library-export-not-allowed:${name}`);
    }
  }
  for (const specifier of new Set([...analysis.specifiers, ...rawImportsOf(content)])) {
    if (specifier.startsWith('node:')) {
      if (!builtins.includes(specifier)) add(path, `builtin-not-allowed:${specifier}`);
      continue;
    }
    if (!specifier.startsWith('.')) {
      if (!Object.hasOwn(TXVERIFY_THIRD_PARTY, specifier)) add(path, `third-party-import:${specifier}`);
      continue;
    }
    const target = resolve(path, specifier);
    if (target === null) {
      add(path, `unsupported-specifier:${specifier}`);
      continue;
    }
    if (target.startsWith('txverify/')) {
      if (area === 'src' && !target.startsWith('txverify/src/')) add(path, `production-imports-non-production:${target.slice('txverify/'.length)}`);
      continue;
    }
    if (area === 'test' && target.startsWith('fixtures/') ) continue;
    const pkg = /^packages\/([^/]+)\/src\/index\.mjs$/.exec(target);
    if (!pkg || !TXVERIFY_PACKAGES.includes(pkg[1])) add(path, `txverify-import-not-allowed:${target}`);
  }
  // Verification only: no name that signs, derives or generates a key, and only the allowed
  // members of secp256k1.
  const visit = (node, parent, key) => {
    if (node.type === 'MemberExpression') {
      if (node.computed && node.object.type === 'Identifier' && node.object.name === 'secp256k1') add(path, 'txverify-computed-member');
      if (!node.computed && TXVERIFY_DENIED_NAMES.has(node.property.name)) add(path, `txverify-signing-api:${node.property.name}`);
      if (!node.computed && node.object.type === 'Identifier' && node.object.name === 'secp256k1' && !TXVERIFY_SECP256K1_MEMBERS.includes(node.property.name)) {
        add(path, `txverify-secp256k1-member:${node.property.name}`);
      }
    }
    if (node.type === 'Identifier' && TXVERIFY_DENIED_NAMES.has(node.name) && !isPropertyName(node, parent, key)) add(path, `txverify-signing-api:${node.name}`);
    if (node.type === 'Property' && !node.computed && node.key.type === 'Identifier' && TXVERIFY_DENIED_NAMES.has(node.key.name)) add(path, `txverify-signing-api:${node.key.name}`);
    if (node.type === 'Literal' && typeof node.value === 'string' && TXVERIFY_DENIED_NAMES.has(node.value)) add(path, `txverify-signing-api:${node.value}`);
    // `const { x } = secp256k1` and aliases of secp256k1 would hide its members.
    if (node.type === 'VariableDeclarator' && node.init?.type === 'Identifier' && node.init.name === 'secp256k1') add(path, 'txverify-secp256k1-alias');
    for (const [childKey, child] of children(node)) visit(child, node, childKey);
  };
  visit(program, null, null);
}
