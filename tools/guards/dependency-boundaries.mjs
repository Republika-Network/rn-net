// Enforces the import boundaries between RN-NET packages: Node.js built-ins only, no
// third-party packages, no network modules, and cross-package imports only through each
// package's public entry point (src/index.mjs).
//
// This is a source-code lint and a defense-in-depth control that catches honest mistakes and
// makes evasion visible in review. It is not a sandbox: JavaScript can always reach a module
// through constructions no static scan can follow (a property name assembled at run time, for
// example). Network isolation of tests is enforced separately (tools/ci/offline-checks.sh).
//
// Sources are read as tokens (js-tokens.mjs), so comments, strings, template literals and
// regular expressions are separated out before imports and names are read; the tokenizer's known
// limits are described there. The supported language is deliberately narrow and fails closed: a
// file the tokenizer cannot read, or an import or export it does not recognize, is reported. The
// earlier raw-text patterns still run over the whole file as a second, more conservative layer.
// Only packages/** is checked; tools/ is repository tooling and may use any built-in.
import { tokenize, UnsupportedSyntax } from './js-tokens.mjs';

// Built-in modules each package may import. Tests may also use the test-only modules.
export const ALLOWED_BUILTINS = {
  canonical: [],
  commitment: ['node:buffer', 'node:crypto'],
  conformance: ['node:buffer', 'node:fs', 'node:url'],
};
const TEST_BUILTINS = ['node:test', 'node:assert/strict', 'node:buffer', 'node:crypto'];

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

const isPunctuator = (token, value) => token?.type === 'punctuator' && token.value === value;
const isName = (token, value) => token?.type === 'identifier' && token.value === value;
const isMemberAccess = (token) => isPunctuator(token, '.') || isPunctuator(token, '?.');

/**
 * Reads the module specifiers of a tokenized source and reports constructions outside the
 * supported language. Returns { specifiers, problems }.
 */
function analyze(tokens) {
  const specifiers = [];
  const problems = [];

  // Reads `{ a, b as c, 'd' as e, }` from tokens[i] (the `{`); returns the index after `}`, or -1.
  const isModuleName = (token) => token?.type === 'identifier' || token?.type === 'string';
  const namedClause = (i) => {
    i += 1;
    while (!isPunctuator(tokens[i], '}')) {
      if (!isModuleName(tokens[i])) return -1;
      i += 1;
      if (isName(tokens[i], 'as')) {
        if (!isModuleName(tokens[i + 1])) return -1;
        i += 2;
      }
      if (isPunctuator(tokens[i], ',')) i += 1;
      else if (!isPunctuator(tokens[i], '}')) return -1;
    }
    return i + 1;
  };
  // Expects `from '<specifier>'` at tokens[i]; returns the index after it, or -1.
  const fromClause = (i) => {
    if (!isName(tokens[i], 'from') || tokens[i + 1]?.type !== 'string') return -1;
    specifiers.push(tokens[i + 1].value);
    return i + 2;
  };

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const previous = tokens[i - 1];
    if (token.type !== 'identifier' || isMemberAccess(previous)) {
      if (token.type === 'identifier' && token.value === 'constructor') problems.push('constructor-access');
      if ((token.type === 'string' || token.type === 'template') && FORBIDDEN_STRINGS.has(token.value)) {
        problems.push(`forbidden-string:${token.value}`);
      }
      continue;
    }
    if (FORBIDDEN_IDENTIFIERS.includes(token.value)) problems.push(`forbidden-identifier:${token.value}`);
    if (token.value === 'process') {
      if (!isPunctuator(tokens[i + 1], '.') || !PROCESS_PROPERTIES.includes(tokens[i + 2]?.value)) problems.push('process-access');
    }

    if (token.value === 'import') {
      const next = tokens[i + 1];
      if (isPunctuator(next, '(')) {
        // import('<specifier>') or import('<specifier>', options); anything else is computed.
        const argument = tokens[i + 2];
        if (argument?.type === 'string' && (isPunctuator(tokens[i + 3], ')') || isPunctuator(tokens[i + 3], ','))) {
          specifiers.push(argument.value);
        } else {
          problems.push('dynamic-import-non-literal');
        }
      } else if (isPunctuator(next, '.')) {
        if (!isName(tokens[i + 2], 'meta')) problems.push('unrecognized-import');
      } else if (next?.type === 'string') {
        specifiers.push(next.value); // import '<specifier>'
      } else {
        // import a from, import * as a from, import { ... } from, import a, { ... } from
        let j = i + 1;
        if (next?.type === 'identifier' && !isName(next, 'from')) j += 1;
        else if (isName(next, 'from') && isName(tokens[i + 2], 'from')) j += 1; // a binding named `from`
        if (isPunctuator(tokens[j], ',')) j += 1;
        if (isPunctuator(tokens[j], '*') && isName(tokens[j + 1], 'as') && tokens[j + 2]?.type === 'identifier') j += 3;
        else if (isPunctuator(tokens[j], '{')) j = namedClause(j);
        if (j === -1 || j === i + 1 || fromClause(j) === -1) problems.push('unrecognized-import');
      }
    } else if (token.value === 'export') {
      const next = tokens[i + 1];
      if (isPunctuator(next, '*')) {
        // export * from, export * as a from
        let j = i + 2;
        if (isName(tokens[j], 'as') && (tokens[j + 1]?.type === 'identifier' || tokens[j + 1]?.type === 'string')) j += 2;
        if (fromClause(j) === -1) problems.push('unrecognized-export');
      } else if (isPunctuator(next, '{')) {
        // export { ... } with an optional from clause
        const j = namedClause(i + 1);
        if (j === -1) problems.push('unrecognized-export');
        else if (isName(tokens[j], 'from')) {
          if (fromClause(j) === -1) problems.push('unrecognized-export');
        }
      }
      // Any other export is a declaration, which declares no specifier.
    }
  }
  return { specifiers, problems };
}

/** Module specifiers of a source: every token-level import and re-export, in order. */
export function importsOf(content) {
  return analyze(tokenize(content)).specifiers;
}

// The earlier raw-text extraction, kept as a conservative second layer.
function rawImportsOf(content) {
  return [...content.matchAll(STATIC_SPECIFIER), ...content.matchAll(DYNAMIC_SPECIFIER)].map((m) => m[2]);
}

// Raw-text rules that do not depend on tokenizing correctly: they match anywhere in the file,
// comments and strings included, so code the tokenizer misreads is still seen. They are
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

function resolve(fromPath, specifier) {
  const parts = fromPath.split('/').slice(0, -1);
  for (const segment of specifier.split('/')) {
    if (segment === '..') parts.pop();
    else if (segment !== '.') parts.push(segment);
  }
  return parts.join('/');
}

export function check(files) {
  const findings = [];
  const add = (path, rule) => findings.push({ path, rule });

  for (const { path, content } of files) {
    if (path.endsWith('package.json') && content !== null) {
      const manifest = JSON.parse(content);
      for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        if (manifest[key] && Object.keys(manifest[key]).length > 0) add(path, `undeclared-${key}`);
      }
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
      analysis = analyze(tokenize(content));
    } catch (error) {
      if (!(error instanceof UnsupportedSyntax)) throw error;
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
