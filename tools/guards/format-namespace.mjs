// RN-NET format identifiers use the `rnnet.` namespace (ADR-RN-001). The shorter `rn.`
// prefix is already used elsewhere in the ecosystem and must not be reused here.
import { scanLines } from './lib.mjs';

// External formats RN-NET may name, each added only with its recorded authorization.
export const EXTERNAL_FORMATS = [];

export const rules = [{ id: 'rn-prefix', pattern: /(^|[^A-Za-z0-9_.-])rn\.[a-z][a-z0-9_-]*/ }];

const FORMAT_FIELD = /"format"\s*:\s*"([^"]*)"/g;

export function check(files) {
  const findings = scanLines(files, rules);
  for (const { path, content } of files) {
    if (content === null || !path.endsWith('.json')) continue;
    content.split('\n').forEach((text, index) => {
      for (const [, id] of text.matchAll(FORMAT_FIELD)) {
        if (!id.startsWith('rnnet.') && !EXTERNAL_FORMATS.includes(id)) {
          findings.push({ path, line: index + 1, rule: 'unregistered-format' });
        }
      }
    });
  }
  return findings;
}
