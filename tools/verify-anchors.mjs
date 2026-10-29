#!/usr/bin/env node
// Checks a supplied XRPL Testnet observation and a supplied Ethereum Sepolia observation against
// one rnnet.evidence-commitment.v1 commitment, offline, and prints the
// rnnet.anchor-verification-report.v1 report (canonical JSON, one line). It reads only the files
// named on the command line, never opens a URL or contacts a network, holds no keys, and writes
// a file only when --output is given. A PASS means the supplied data is consistent; it is not
// proof that either transaction exists.
//
//   node tools/verify-anchors.mjs --commitment <sha256:...> --xrpl <file> --evm <file> [--output <file>]
//
// Exit codes: 0 PASS, 1 FAIL, 2 UNSUPPORTED, 64 usage error, 66 an input file cannot be read,
// 73 the --output file cannot be created (it already exists, for example).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodeAnchorReport, verifyDualAnchor } from '../packages/anchor/src/index.mjs';

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, UNSUPPORTED: 2, USAGE: 64, NO_INPUT: 66, CANNOT_CREATE: 73 });
const USAGE = 'usage: node tools/verify-anchors.mjs --commitment <sha256:...> --xrpl <file> --evm <file> [--output <file>]';
const OPTIONS = ['--commitment', '--xrpl', '--evm', '--output'];
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;

function parseArguments(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!OPTIONS.includes(argv[i]) || i + 1 >= argv.length || Object.hasOwn(options, argv[i])) return null;
    options[argv[i]] = argv[i + 1];
  }
  if (!COMMITMENT.test(options['--commitment'] ?? '') || !options['--xrpl'] || !options['--evm']) return null;
  return options;
}

/**
 * @param {string[]} argv
 * @param {{ readFile: (path: string) => Uint8Array, writeFile: (path: string, data: Uint8Array) => void,
 *   stdout: (text: string) => void, stderr: (text: string) => void }} io
 * @returns {number} the exit code
 */
export function main(argv, io) {
  const options = parseArguments(argv);
  if (options === null) {
    io.stderr(`${USAGE}\n`);
    return EXIT.USAGE;
  }
  let xrpl;
  let evm;
  try {
    xrpl = io.readFile(options['--xrpl']);
    evm = io.readFile(options['--evm']);
  } catch (error) {
    io.stderr(`verify-anchors: cannot read input: ${error.code ?? error.message}\n`);
    return EXIT.NO_INPUT;
  }
  const report = verifyDualAnchor({ xrpl, evm }, options['--commitment']);
  const text = `${new TextDecoder().decode(encodeAnchorReport(report))}\n`;
  if (options['--output'] === undefined) io.stdout(text);
  else {
    try {
      io.writeFile(options['--output'], new TextEncoder().encode(text));
    } catch (error) {
      io.stderr(`verify-anchors: cannot create output: ${error.code ?? error.message}\n`);
      return EXIT.CANNOT_CREATE;
    }
  }
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
