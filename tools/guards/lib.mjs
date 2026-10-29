// Shared helpers for the repository guards. Node.js 22 built-ins only; the dependency-boundary
// guard alone also uses Acorn (ADR-RN-005).
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const MAX_BYTES = 2 * 1024 * 1024;

/** Tracked files as { path, content, symlink }. Binary and oversized files get content null. */
export function trackedFiles(root = process.cwd()) {
  const out = execFileSync('git', ['ls-files', '-z'], { cwd: root });
  return out
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((path) => ({ path, content: readText(join(root, path)), symlink: lstatSync(join(root, path)).isSymbolicLink() }));
}

function readText(file) {
  if (statSync(file).size > MAX_BYTES) return null;
  const bytes = readFileSync(file);
  return bytes.includes(0) ? null : bytes.toString('utf8');
}

/** Applies line-oriented regex rules to every text file. */
export function scanLines(files, rules) {
  const findings = [];
  for (const { path, content } of files) {
    if (content === null) continue;
    const lines = content.split('\n');
    lines.forEach((text, index) => {
      for (const { id, pattern } of rules) {
        if (pattern.test(text)) findings.push({ path, line: index + 1, rule: id });
      }
    });
  }
  return findings;
}

/** Formats findings without echoing the matched text, so a leaked secret is not printed again. */
export function formatFindings(guard, findings) {
  return findings.map((f) => `${guard}: ${f.path}${f.line ? `:${f.line}` : ''} [${f.rule}]`);
}
