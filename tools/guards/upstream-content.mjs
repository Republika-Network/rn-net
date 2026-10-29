// Clean-room guard (ADR-RN-001, rule 6): flags identifiers that indicate content copied from
// proprietary or private upstream repositories.
import { createHash } from 'node:crypto';
import { scanLines } from './lib.mjs';

// Public upstream identifiers, matched case-insensitively. Bracketed characters keep this file
// from matching itself.
export const rules = [
  { id: 'upstream-package', pattern: /@aoc-[e]nterprise\//i },
  { id: 'upstream-path', pattern: /\bsrc\/[e]nterprise\//i },
  { id: 'upstream-invariant', pattern: /\bS[E]C-INV-\d/i },
  { id: 'upstream-signing-domain', pattern: /\bf[r]ontera:[a-z-]+(:[a-z0-9-]+)*:v\d/i },
];

// Names that must not appear in this public repository (private repositories, customers,
// unauthorized formats), stored as SHA-256 of the lowercase token. This only avoids
// spelling the names out; a short name can be recovered from its hash by guessing.
export const DENIED_TOKEN_HASHES = new Set([
  '6e3844e41a66cf978be351351d8ad11f527b19ec73535603de63c09985194ed7',
  '13b32ae763a4f2109110f8264f094ff62b67e312cf19ca23440a1f770d2c58d0',
  '4ed0cf5343d3f7401c0934489e4cc3697a9835ef2a4ef09a76d187e4554bea3b',
  'c1a28f0d9231aa23be93a5e6afdba1c3ff20ec18192ddd207b431c69b25458e7',
  '546b6479e98f1b2a5d920c59d8ad34ac528e20c9cca9a2ccd101e17fb976c8c2',
  'b59b3b7d3ffaf771ed3418e9ef338c11ed13f7afe62e7164936baab40b31b314',
  '2f5584775508b51fe71e1d29d1d74aa47dca448b931abb132983dd07110fa212',
  'a8d8fb226f600840b640f9c617ee8bedd615dc37f51564e3649d66d1665739c1',
]);

// Paths exempt from this guard, each added only with its recorded authorization.
export const AUTHORIZED_PATHS = [];

const TOKEN = /[a-z0-9][a-z0-9_-]*[a-z0-9]/g;

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

export function check(files) {
  const scoped = files.filter(({ path }) => !AUTHORIZED_PATHS.some((p) => path.startsWith(p)));
  const findings = scanLines(scoped, rules);
  for (const { path, content } of scoped) {
    if (content === null) continue;
    content.split('\n').forEach((text, index) => {
      for (const [token] of text.toLowerCase().matchAll(TOKEN)) {
        if (DENIED_TOKEN_HASHES.has(sha256(token))) {
          findings.push({ path, line: index + 1, rule: 'denied-name' });
          break;
        }
      }
    });
  }
  return findings;
}
