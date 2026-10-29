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

// Built-in modules each package may import. Tests may also use the test-only modules.
export const ALLOWED_BUILTINS = {
  canonical: [],
  commitment: ['node:buffer', 'node:crypto'],
  conformance: ['node:buffer', 'node:fs', 'node:url'],
};
const TEST_BUILTINS = ['node:test', 'node:assert/strict', 'node:buffer', 'node:crypto'];

// The only third-party packages in the repository: development tooling, never imported by
// packages/** (docs/adr/ADR-RN-005-guard-parser-dependency.md). Exact versions.
export const DEV_DEPENDENCIES = {
  acorn: {
    version: '8.19.0',
    resolved: 'https://registry.npmjs.org/acorn/-/acorn-8.19.0.tgz',
    integrity: 'sha512-oJlA3XiRm7Cyk6qFD2Jn8ak9B7jSy0qy00ADO3+8dpT0LSjFihQYv4C02LFCSYJV3Q37xYwwRy5m+IpIiUzqWw==',
  },
};
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
  conformance: ['canonical', 'commitment'],
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
  const visit = (node, parent, key) => {
    switch (node.type) {
      case 'ImportDeclaration':
      case 'ExportAllDeclaration':
        specifiers.push(node.source.value);
        break;
      case 'ExportNamedDeclaration':
        if (node.source) specifiers.push(node.source.value);
        break;
      case 'ImportExpression':
        // import('<specifier>') with a string literal; anything else is computed.
        if (node.source.type === 'Literal' && typeof node.source.value === 'string') specifiers.push(node.source.value);
        else problems.push('dynamic-import-non-literal');
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
  return { specifiers, problems };
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
        const allowed = path === 'package.json' && key === 'devDependencies' ? DEV_DEPENDENCIES : {};
        if (declared.some(([dependency, version]) => allowed[dependency]?.version !== version)) add(path, `undeclared-${key}`);
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
        return pin !== undefined && entry.dev === true && ['version', 'resolved', 'integrity'].every((field) => entry[field] === pin[field]);
      };
      const valid = path === 'package-lock.json' && entries.length === expected.size + 1 && Object.hasOwn(Object.fromEntries(entries), '') && entries.every(matches);
      if (!valid) add(path, 'undeclared-lockfile-packages');
    }
    const match = /^packages\/([^/]+)\/(.+)$/.exec(path);
    if (!match) continue;
    const [, pkg, rest] = match;
    if (!Object.hasOwn(ALLOWED_PACKAGES, pkg)) {
      add(path, 'unregistered-package');
      continue;
    }
    // Node resolves a symlinked module's imports from its real path, not from where it is linked.
    if (symlink) {
      add(path, 'symlink-in-package');
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
      analysis = { specifiers: [], problems: [] };
    }
    for (const problem of new Set(analysis.problems)) add(path, problem);
    const area = rest.startsWith('test/') ? 'test' : 'src';
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
      if (targetPkg === pkg) continue;
      if (!ALLOWED_PACKAGES[pkg].includes(targetPkg)) add(path, `package-not-allowed:${targetPkg}`);
      else if (targetRest !== 'src/index.mjs') add(path, `private-import:${targetPkg}/${targetRest}`);
    }
  }
  return findings;
}
