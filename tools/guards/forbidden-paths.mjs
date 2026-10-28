// Rejects tracked files whose path alone shows key material or packed artifacts.
// Mirrors .gitignore, so a forced `git add -f` is still caught in CI.

export const rules = [
  { id: 'env-file', pattern: /(^|\/)\.env(\.[^/]*)?$/ },
  { id: 'key-file', pattern: /\.(pem|key|p8|p12|pfx|jks|keystore|seed)$/i },
  { id: 'ssh-key', pattern: /(^|\/)id_(rsa|ed25519|ecdsa)(\.pub)?$/ },
  { id: 'key-directory', pattern: /(^|\/)(keys|\.secrets)\// },
  { id: 'packed-artifact', pattern: /\.tgz$/i },
];

export function check(files) {
  const findings = [];
  for (const { path } of files) {
    for (const { id, pattern } of rules) {
      if (pattern.test(path)) findings.push({ path, rule: id });
    }
  }
  return findings;
}
