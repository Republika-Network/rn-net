#!/usr/bin/env node
// Read-only verification of an RN-NET anchor transaction on XRPL Testnet or Ethereum Sepolia
// (RN-NET-03B1). Providers are named by id from config/rpc-endpoints.json, the reviewed allowlist;
// no URL is ever taken from the command line. Only read-only methods can be sent. Nothing is
// signed, submitted or funded.
//
//   Live:    node tools/verify-live-anchor.mjs --network xrpl-testnet|sepolia --tx <hash>
//              --commitment <sha256:...> (--rpc <provider-id> [--rpc <id>] | --compare-providers)
//              [--capture <file>] [--output <file>]
//   Replay:  node tools/verify-live-anchor.mjs --offline-replay <capture-file> --commitment <sha256:...>
//              [--output <file>]      (never opens a connection)
//
// The report (stdout or --output) is the deterministic rnnet.live-observation-report.v1 core. The
// capture holds the exact bytes exchanged and the retrieval time. Files are never overwritten.
// Exit codes: 0 PASS, 1 FAIL, 2 UNSUPPORTED, 3 INDETERMINATE (no source available),
// 64 usage error, 66 an input cannot be read, 73 an output cannot be created.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  CAPTURE_FORMAT, checkCapture, encodeLiveReport, loadEndpointConfig, Network, recordingTransport, replayTransport, verifyLiveAnchor,
} from '../packages/chain-readonly/src/index.mjs';

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, UNSUPPORTED: 2, INDETERMINATE: 3, USAGE: 64, NO_INPUT: 66, CANNOT_CREATE: 73 });
export const CONFIG_PATH = fileURLToPath(new URL('../config/rpc-endpoints.json', import.meta.url));
const NETWORKS = { 'xrpl-testnet': Network.XRPL_TESTNET, sepolia: Network.SEPOLIA };
const COMMITMENT = /^sha256:[0-9a-f]{64}$/;
const USAGE = 'usage: node tools/verify-live-anchor.mjs --network xrpl-testnet|sepolia --tx <hash> --commitment <sha256:...> (--rpc <provider-id>... | --compare-providers) [--capture <file>] [--output <file>]\n'
  + '       node tools/verify-live-anchor.mjs --offline-replay <capture-file> --commitment <sha256:...> [--output <file>]';

function parseArguments(argv) {
  const single = ['--network', '--tx', '--commitment', '--capture', '--output', '--offline-replay'];
  const options = { rpc: [] };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--compare-providers') {
      if (options.compare) return null;
      options.compare = true;
    } else if (flag === '--rpc' || single.includes(flag)) {
      const value = argv[++i];
      if (value === undefined || value.startsWith('--')) return null;
      if (flag === '--rpc') options.rpc.push(value);
      else if (Object.hasOwn(options, flag)) return null;
      else options[flag] = value;
    } else return null;
  }
  if (!COMMITMENT.test(options['--commitment'] ?? '')) return null;
  if (options['--offline-replay'] !== undefined) {
    // Replay takes everything from the capture; live-only options are refused.
    if (options.rpc.length || options.compare || options['--network'] || options['--tx'] || options['--capture']) return null;
    return options;
  }
  const network = NETWORKS[options['--network']];
  if (!network) return null;
  const tx = options['--tx'] ?? '';
  options.network = network;
  options.tx = network === Network.XRPL_TESTNET ? (/^[0-9A-Fa-f]{64}$/.test(tx) ? tx.toUpperCase() : null) : (/^0x[0-9A-Fa-f]{64}$/.test(tx) ? tx.toLowerCase() : null);
  if (options.tx === null) return null;
  if (options.compare === (options.rpc.length > 0)) return null; // exactly one of --rpc and --compare-providers
  return options;
}

/**
 * @param {string[]} argv
 * @param {{ readFile, writeFile, stdout, stderr, liveTransport: () => Promise<Function>, now: () => string }} io
 * @returns {Promise<number>} the exit code
 */
export async function main(argv, io) {
  const options = parseArguments(argv);
  if (options === null) {
    io.stderr(`${USAGE}\n`);
    return EXIT.USAGE;
  }
  let report;
  let capture;
  if (options['--offline-replay'] !== undefined) {
    let recorded;
    try {
      recorded = checkCapture(JSON.parse(new TextDecoder().decode(io.readFile(options['--offline-replay']))));
    } catch (error) {
      io.stderr(`verify-live-anchor: cannot read capture: ${error.code ?? error.message}\n`);
      return EXIT.NO_INPUT;
    }
    const providers = recorded.providers.map((p) => ({ id: p.id, network: recorded.network, url: `${p.origin}/`, operator: p.operator }));
    try {
      report = await verifyLiveAnchor({ network: recorded.network, transactionHash: recorded.transactionHash, expectedCommitment: options['--commitment'], providers, transport: replayTransport(recorded) });
    } catch (error) {
      io.stderr(`verify-live-anchor: ${error.message}\n`);
      return EXIT.NO_INPUT;
    }
  } else {
    let configured;
    try {
      configured = loadEndpointConfig(JSON.parse(new TextDecoder().decode(io.readFile(CONFIG_PATH))));
    } catch (error) {
      io.stderr(`verify-live-anchor: cannot load ${CONFIG_PATH}: ${error.message}\n`);
      return EXIT.NO_INPUT;
    }
    const forNetwork = configured.filter((p) => p.network === options.network);
    const providers = options.compare ? forNetwork : options.rpc.map((id) => forNetwork.find((p) => p.id === id));
    if (providers.length === 0 || providers.some((p) => p === undefined) || new Set(providers.map((p) => p.id)).size !== providers.length) {
      io.stderr(`verify-live-anchor: unknown or duplicate provider for ${options.network}; configured: ${forNetwork.map((p) => p.id).join(', ')}\n`);
      return EXIT.USAGE;
    }
    const exchanges = [];
    const startedAt = io.now();
    const transport = recordingTransport(await io.liveTransport(), exchanges);
    report = await verifyLiveAnchor({ network: options.network, transactionHash: options.tx, expectedCommitment: options['--commitment'], providers, transport });
    capture = {
      format: CAPTURE_FORMAT,
      network: options.network,
      transactionHash: options.tx,
      providers: providers.map((p) => ({ id: p.id, operator: p.operator, origin: p.origin })),
      retrieval: { startedAt, finishedAt: io.now(), tool: 'tools/verify-live-anchor.mjs' },
      exchanges,
    };
  }
  const text = `${new TextDecoder().decode(encodeLiveReport(report))}\n`;
  try {
    if (capture && options['--capture'] !== undefined) io.writeFile(options['--capture'], new TextEncoder().encode(`${JSON.stringify(capture, null, 2)}\n`));
    if (options['--output'] !== undefined) io.writeFile(options['--output'], new TextEncoder().encode(text));
    else io.stdout(text);
  } catch (error) {
    io.stderr(`verify-live-anchor: cannot create output: ${error.code ?? error.message}\n`);
    return EXIT.CANNOT_CREATE;
  }
  return EXIT[report.outcome];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2), {
    readFile: (path) => new Uint8Array(readFileSync(path)),
    writeFile: (path, data) => writeFileSync(path, data, { flag: 'wx' }),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    // Loaded only in live mode, so replay never loads any network code.
    liveTransport: async () => (await import('./live/https-transport.mjs')).httpsTransport,
    now: () => new Date().toISOString(),
  });
}
