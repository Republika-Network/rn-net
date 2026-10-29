# ADR-RN-005: A parser dependency for the dependency-boundary guard

- Status: Proposed (RN-NET-01K)
- Date: 2026-10-28

## Context

The dependency-boundary guard (`tools/guards/dependency-boundaries.mjs`) checks that code in
`packages/` imports only allowed Node.js built-ins and package entry points, and uses no
code-loading routes. To do that it must find every import in a source file.

Telling an import from text inside a string, comment, template literal or regular
expression needs the JavaScript grammar. In particular, whether `/` starts a regular
expression or is a division depends on the context.

RN-NET-01J tried to do this with a small tokenizer written in this repository. Three
independent reviews in a row found valid modules that load `node:net` while the guard
reported nothing:

- seven bypasses at `9521fff`;
- one more at `a4b2e30`, which was merged as `0b32565`.

Each bypass came from a wrong guess about `/`. A rule set reasoned from the grammar is not a
parser, and patching it case by case did not converge.

The repository has no third-party dependencies, and the runtime packages must stay that way.

## Decision

1. The guard parses each source in `packages/` with Acorn, a maintained ECMAScript parser.
   The guard reads imports, re-exports, dynamic imports and code-loading names from the
   syntax tree. The homemade tokenizer is removed.
2. Acorn is a **development dependency only**:
   - it is pinned exactly (`8.19.0`, MIT, no dependencies of its own);
   - it is recorded in the root `package.json` and `package-lock.json`;
   - it is installed in CI with `npm ci --ignore-scripts` before network isolation.
3. Nothing in `packages/` may import it, and no other third-party package is allowed. The
   guard enforces both:
   - the root manifest may declare exactly the allowlisted development dependency at its exact
     version, and no other manifest may declare any dependency;
   - the lockfile may contain nothing else;
   - an import of `acorn` from `packages/` is reported.
4. A file Acorn cannot parse as an ECMAScript module is reported (`unsupported-syntax`), not
   skipped.
5. The raw-text patterns stay as a second, more conservative layer. They run over the whole
   file text, so they apply even if the parse were wrong.

## Consequences

- **What it removes:**
  - the class of bypasses that came from misreading `/`, strings, comments or templates;
  - false positives on valid code the tokenizer had to reject.
- **What it does not remove:**
  - The guard is still a lint, not a sandbox. A name assembled at run time, or a forbidden
    object reached indirectly, is beyond static analysis.
  - Node.js could in principle accept syntax Acorn rejects (reported, so fail closed) or parse
    a construct differently from Acorn (not expected for a conforming parser, but not
    excluded).
  - Network isolation of tests still comes from the network namespace
    (`tools/ci/offline-checks.sh`).
- **Supply chain:**
  - one pinned package is fetched from the npm registry in CI, verified against the lockfile
    integrity hash, with install scripts disabled;
  - dependency review covers the lockfile, and updates are deliberate changes to the pinned
    version.
- The runtime packages, specifications, canonical outputs, commitments and conformance vectors
  are unchanged.
