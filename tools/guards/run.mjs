// Runs every repository guard over the tracked files. Exits 1 if any guard reports a finding.
import { formatFindings, trackedFiles } from './lib.mjs';
import * as dependencyBoundaries from './dependency-boundaries.mjs';
import * as forbiddenPaths from './forbidden-paths.mjs';
import * as formatNamespace from './format-namespace.mjs';
import * as secretShapes from './secret-shapes.mjs';
import * as upstreamContent from './upstream-content.mjs';

const guards = {
  'forbidden-paths': forbiddenPaths,
  'secret-shapes': secretShapes,
  'format-namespace': formatNamespace,
  'upstream-content': upstreamContent,
  'dependency-boundaries': dependencyBoundaries,
};

const files = trackedFiles();
let failed = false;
for (const [name, guard] of Object.entries(guards)) {
  const findings = guard.check(files);
  if (findings.length > 0) {
    failed = true;
    console.error(formatFindings(name, findings).join('\n'));
  } else {
    console.log(`${name}: ok (${files.length} files)`);
  }
}
process.exit(failed ? 1 : 0);
