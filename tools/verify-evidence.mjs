#!/usr/bin/env node
// Verifies an rnnet.synthetic-evidence.v1 file and prints its rnnet.verification-report.v1
// report (canonical JSON, one line). It reads only the files named on the command line, makes
// no network calls, holds no keys, and writes a file only when --output is given.
//
//   node tools/verify-evidence.mjs <evidence-file>
//       [--commitment <envelope-file> --commitment-digest <sha256:...>]
//       [--output <report-file>]
//
// Exit codes: 0 PASS, 1 FAIL, 2 UNSUPPORTED, 64 usage error, 66 an input file cannot be read.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodeReport, verifyEvidence } from '../packages/verifier/src/index.mjs';

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, UNSUPPORTED: 2, USAGE: 64, NO_INPUT: 66 });
const USAGE =
  'usage: node tools/verify-evidence.mjs <evidence-file> [--commitment <envelope-file> --commitment-digest <sha256:...>] [--output <report-file>]';

function parseArguments(argv) {
  const options = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const argument = argv[i];
    if (['--commitment', '--commitment-digest', '--output'].includes(argument)) {
      if (i + 1 >= argv.length || Object.hasOwn(options, argument)) return null;
      options[argument] = argv[++i];
    } else if (argument.startsWith('-')) {
      return null;
    } else {
      positional.push(argument);
    }
  }
  if (positional.length !== 1) return null;
  if (Object.hasOwn(options, '--commitment') !== Object.hasOwn(options, '--commitment-digest')) return null;
  return { evidence: positional[0], envelope: options['--commitment'], digest: options['--commitment-digest'], output: options['--output'] };
}

/**
 * @param {string[]} argv arguments after the script name
 * @param {{ readFile: (path: string) => Uint8Array, writeFile: (path: string, data: Uint8Array) => void,
 *   stdout: (text: string) => void, stderr: (text: string) => void }} io
 * @returns {number} the exit code
 */
export function main(argv, io) {
  const args = parseArguments(argv);
  if (args === null) {
    io.stderr(`${USAGE}\n`);
    return EXIT.USAGE;
  }
  let evidence;
  let envelope;
  try {
    evidence = io.readFile(args.evidence);
    if (args.envelope !== undefined) envelope = io.readFile(args.envelope);
  } catch (error) {
    io.stderr(`verify-evidence: cannot read input: ${error.code ?? error.message}\n`);
    return EXIT.NO_INPUT;
  }
  const options = envelope === undefined ? {} : { commitment: { envelope, digest: args.digest } };
  const report = verifyEvidence(evidence, options);
  const text = `${new TextDecoder().decode(encodeReport(report))}\n`;
  if (args.output !== undefined) io.writeFile(args.output, new TextEncoder().encode(text));
  else io.stdout(text);
  return EXIT[report.outcome];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2), {
    readFile: (path) => new Uint8Array(readFileSync(path)),
    writeFile: (path, data) => writeFileSync(path, data, { flag: 'wx' }),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
  });
}
