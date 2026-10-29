# ADR-RN-005: Dependency-boundary guard: parser dependency and capability boundaries

- Status: Accepted (founder approval, RN-NET-01K)
- Date: 2026-10-29

## Context

The dependency-boundary guard (`tools/guards/dependency-boundaries.mjs`) checks that the code in
`packages/` imports only the Node.js built-ins and package entry points it is allowed, and uses
no code-loading routes. To do that it must find every import in a source file and know how
each one resolves.

RN-NET-01J read imports with a small tokenizer written in this repository. Independent reviews
kept finding valid modules that load `node:net` while the guard reported nothing: seven at
`9521fff`, then one at `a4b2e30` (merged as `0b32565`). Each came from guessing the grammar,
such as whether a `/` starts a regular expression or is a division, and patching that
guesswork case by case did not converge.

RN-NET-01K replaced the tokenizer with a parser. Independent reviews of the parser-based guard
found no parsing bypass. They did find bypasses of other kinds:

- specifiers that Node resolves as URLs (`%2e%2e`, backslashes);
- the `constructor` route to the Function constructor;
- capabilities of built-ins that were already allowed (`node:test` `run`, `node:crypto`
  `setEngine`, `node:fs` `symlinkSync`);
- production code borrowing test-only built-ins through a test helper.

A static check cannot restrict everything reachable through an object it allows; that would
take a JavaScript sandbox, which is a different project.

## Decision

### 1. Parser: Acorn, development-only

- **How the guard reads code.**
  - It parses every `.mjs` file in `packages/` with Acorn, a maintained ECMAScript parser.
  - It reads imports, re-exports, dynamic imports and names from the syntax tree.
  - A file Acorn cannot parse as a module is reported (`unsupported-syntax`), never skipped.
- **The dependency.** `acorn@8.19.0` is approved by the founder as the repository's only
  third-party package, for development only. It is MIT-licensed and has no dependencies of its
  own.
  - It is pinned by version, source URL and integrity hash in the root `package.json` and
    `package-lock.json`.
  - CI installs it with `npm ci --ignore-scripts` before network isolation.
  - Dependency review covers it.
- **Enforced by the guard:**
  - only the root manifest may declare Acorn, at exactly that version;
  - the lockfile may contain nothing else;
  - `npm-shrinkwrap.json`, `.npmrc` and the manifest fields `overrides`, `workspaces` and
    `bundleDependencies` are refused;
  - any import of `acorn` from `packages/` is reported, by name or by path.
- **Runtime packages have no dependencies.**

### 2. Production code: everything in `packages/*/` outside `test/`, normally `src/`

Production code is capability-restricted. The guard enforces these rules:

- **Built-ins.**
  - Only the built-ins allowed for that package may be imported, and only by allowed named
    export. Today these are `createHash`, `Buffer`, `readFileSync` and `fileURLToPath`, and
    `canonical` has none.
  - Namespace imports, default imports, re-exports and dynamic imports of built-ins are
    reported.
- **Same-package imports.**
  - Within its own package, production code may import only files under `src/`.
  - It never imports a test file or helper, whether directly, by re-export (`export … from`,
    `export * from`) or by a literal dynamic import.
  - A re-export chain is reported at the first file that leaves `src/`.
- **Other packages.** Production code may import another package only through that allowed
  package's public entry point (`src/index.mjs`).
- **Specifiers and symlinks.**
  - Relative specifiers are resolved only in a plain `./` or `../` form, and the result is
    cross-checked against URL resolution, the way Node resolves specifiers.
  - Percent-encoding, backslashes, queries and fragments are reported.
  - Symlinks under `packages/` are reported.
- **Code-loading routes.** These are reported wherever they appear as names, including
  aliased, optional, indirect or destructured uses:
  - `eval`, `Function`, `globalThis`, `global`, `require`, `createRequire`,
    `getBuiltinModule`, `fetch`, `WebSocket` and `Worker`;
  - any use of `constructor` other than a class's own constructor method;
  - non-literal `import()`;
  - `process` other than `process.hrtime` and `process.version(s)`;
  - string literals naming these routes.
- **Second layer.** Raw-text patterns run over every file. They are deliberately broad: they
  also flag these words in comments and strings.

### 3. Test code: `packages/*/test/`

- **Trust.** Test files and development dependencies are trusted development inputs, reviewed
  like any other change. They are not untrusted submissions.
- **Accepted capabilities.** Tests may use the legitimate capabilities of the allowed test
  built-ins, including `test.run`, `mock` and `snapshot` on `node:test`'s `test` and on the test
  context.
- **Still enforced:**
  - the import allowlist, including the per-export allowlist for named imports;
  - the package boundaries;
  - the specifier, symlink and code-loading name rules.
- **Not claimed.** The guard does not claim to restrict every method reachable through an
  allowed object.

### 4. Trust boundary and isolation

- **The guard** is a lint and a defense-in-depth control over source code. It is not a security
  boundary for executing untrusted code.
- **The network namespace** that `tools/ci/offline-checks.sh` proves before every run is the
  primary network-isolation control for test runs.
  - It isolates the network only. It is not filesystem, process or arbitrary-code isolation.
  - Code running in the tests can read and write the checkout and start processes the
    environment allows.
- **The test preload** (`tools/offline.mjs`) is JavaScript-level instrumentation and defense in
  depth.

### 5. A general-purpose JavaScript sandbox is out of scope

Static inspection cannot follow every runtime path in JavaScript. Containing arbitrary code
needs runtime isolation: a separate process or VM with restricted capabilities. RN-NET does not
execute untrusted code, so that work is not undertaken here.

## Consequences

- **Enforced:** everything listed under Decision 1–3. Each historical bypass is kept verbatim
  in `tools/guards/fixtures/dependency-bypasses/` and is reported.
- **Not enforced** (known limits of static inspection):
  - names built at run time, such as `obj['con' + 'structor']`;
  - reflection that never names the object it reaches, such as finding the Function
    constructor among an object's property descriptors;
  - capabilities of allowed objects in test code, which are accepted (Decision 3);
  - globals available without an import, such as the global `Buffer` or WebCrypto in
    production code;
  - code outside `packages/`: `tools/` is repository tooling and may use any built-in.
- **Parser differences.**
  - Node.js could accept syntax that Acorn rejects; that syntax is reported, so the guard fails
    closed.
  - Node could also parse a construct differently from Acorn. That is not expected for a
    conforming parser and was not found in review, but it is not excluded.
- **Supply chain.**
  - One package is fetched from the npm registry in CI. It is verified against the lockfile
    integrity hash, with install scripts disabled.
  - Changing the version is a deliberate, reviewed change to the pin in this guard.
- **Unchanged:** the runtime packages, specifications, canonical outputs, commitments and
  conformance vectors.
