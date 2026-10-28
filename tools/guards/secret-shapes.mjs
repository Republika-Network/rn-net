// Detects credential-shaped text in tracked files. Heuristic: it complements, and does not
// replace, GitHub secret scanning and push protection.
import { scanLines } from './lib.mjs';

const BASE58 = '[1-9A-HJ-NP-Za-km-z]';

export const rules = [
  { id: 'pem-private-key', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  // XRPL family seeds: secp256k1 ("s" + 28) and ed25519 ("sEd" + 28).
  { id: 'xrpl-seed', pattern: new RegExp(`(^|[^A-Za-z0-9])s(Ed)?${BASE58}{28}($|[^A-Za-z0-9])`) },
  // 64 hex digits next to a key-like word. Bare 64-hex values are transaction hashes and digests.
  {
    id: 'hex-private-key',
    pattern: /(priv(ate)?[_ -]?key|secret|mnemonic|seed)[^0-9A-Za-z\n]{0,6}(0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/i,
  },
  { id: 'github-token', pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/ },
  { id: 'npm-token', pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'aws-access-key', pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  {
    id: 'secret-assignment',
    pattern: /^\s*(export\s+)?[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SEED|MNEMONIC)[A-Z0-9_]*\s*[=:]\s*['"]?[^\s'"$]{8,}/,
  },
];

export function check(files) {
  return scanLines(files, rules);
}
