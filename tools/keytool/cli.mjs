#!/usr/bin/env node
// The founder's key tool (RN-NET-03B2-C4; ADR-RN-017 Amendment C1, K1 to K5). Local terminal use
// only, under `unshare -rn`:
//
//   unshare -rn node tools/keytool/cli.mjs keygen --network <net> --purpose genesis-proof-01 \
//       --key-dir <dir> --log-dir <dir>
//   node tools/keytool/cli.mjs show --network <net> --key-dir <dir> [--log-dir <dir>]
//   unshare -rn node tools/keytool/cli.mjs sign --network <net> --key-dir <dir> --log-dir <dir> \
//       --out-dir <dir> --intent <file> --approved-digest sha256:<64 hex> [--resign-basis <file>]
//
// <net> is xrpl:testnet or evm:11155111. Every path is absolute. A passphrase is read from the
// terminal only: there is no option, environment variable or file for it.
//
// RN-NET-03B2-C4 implements and tests this tool offline. Running keygen or sign for real is gate B
// or gate D, each a separate founder authorization per network; neither is authorized here.
//
// This is the only file under tools/keytool/ that may import signer/ (the guard pins this).
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { linkSync, realpathSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, parse } from '../../packages/canonical/src/index.mjs';
import { approvedIntent, IntentNetwork, intentSender, intentSequence, PURPOSES, TxError } from '../../packages/tx-intent/src/index.mjs';
import { verifySignedTransaction } from '../../txverify/src/index.mjs';
import { decryptKeyFile, encryptKeyFile, MIN_CREATION_PASSPHRASE } from '../../signer/src/keyfile.mjs';
import { generateKey, keyFileRandomness, OS_SOURCE } from '../../signer/src/keygen.mjs';
import { createSigner } from '../../signer/src/sign.mjs';
import { KeyToolCode, KeyToolError, refuse } from './errors.mjs';
import { createDurably, lstatOrNull, readInputFile, readPrivateFile } from './files.mjs';
import { checkNoNetwork, checkNotRealRoot, SYSTEM_NET } from './isolation.mjs';
import { checkKeyFileAbsent, readKeyFile, writeKeyFile } from './keystore.mjs';
import { checkPrivateDirectory, checkSeparate, ensurePrivateDirectory, fsyncDirectory, SYSTEM } from './location.mjs';
import { decideSigning, EntryType, nextEntry, readResignBasis, replaySignLog, SignAction } from './signlog.mjs';
import { appendSignLog, readSignLog } from './signlog-store.mjs';
import { openTerminal } from './terminal.mjs';

const OPTIONS = {
  keygen: { required: ['network', 'purpose', 'key-dir', 'log-dir'], optional: [] },
  show: { required: ['network', 'key-dir'], optional: ['log-dir'] },
  sign: { required: ['network', 'key-dir', 'log-dir', 'out-dir', 'intent', 'approved-digest'], optional: ['resign-basis'] },
};
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CONFIRM_LENGTH = 16;
const MAX_INPUT_BYTES = 65_536;
const MAX_OUTPUT_BYTES = 16_384;
const NETWORK_SLUG = { [IntentNetwork.XRPL_TESTNET]: 'xrpl-testnet', [IntentNetwork.SEPOLIA]: 'sepolia' };

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const isoSeconds = (date) => `${date.toISOString().slice(0, 19)}Z`;

/** The production environment. Tests replace every member. */
export const PRODUCTION = Object.freeze({
  terminal: () => openTerminal(),
  out: (text) => process.stdout.write(text),
  now: () => new Date(),
  system: SYSTEM,
  net: SYSTEM_NET,
  source: OS_SOURCE,
});

/** Parses `<command> --name value ...`. Every option once, every value present, nothing else. */
export function parseArguments(argv) {
  const [command, ...rest] = argv;
  const spec = OPTIONS[command];
  if (!spec) refuse(KeyToolCode.USAGE, 'the command is keygen, show or sign');
  const options = {};
  for (let at = 0; at < rest.length; at += 2) {
    const flag = rest[at];
    const value = rest[at + 1];
    const name = typeof flag === 'string' && flag.startsWith('--') ? flag.slice(2) : null;
    if (name === null || ![...spec.required, ...spec.optional].includes(name)) refuse(KeyToolCode.USAGE, `unknown option ${JSON.stringify(flag)} (a passphrase is never an option)`);
    if (Object.hasOwn(options, name)) refuse(KeyToolCode.USAGE, `--${name} given twice`);
    if (typeof value !== 'string' || value === '' || value.startsWith('--')) refuse(KeyToolCode.USAGE, `--${name} needs a value`);
    options[name] = value;
  }
  for (const name of spec.required) if (!Object.hasOwn(options, name)) refuse(KeyToolCode.USAGE, `--${name} is required`);
  if (!Object.values(IntentNetwork).includes(options.network)) refuse(KeyToolCode.USAGE, '--network is xrpl:testnet or evm:11155111');
  if (Object.hasOwn(options, 'purpose') && !PURPOSES.includes(options.purpose)) refuse(KeyToolCode.USAGE, `--purpose is one of ${PURPOSES.join(', ')}`);
  if (Object.hasOwn(options, 'approved-digest') && !DIGEST.test(options['approved-digest'])) refuse(KeyToolCode.USAGE, '--approved-digest is sha256:<64 lower-case hex>');
  return { command, options };
}

// The terminal input as a string, then the bytes are overwritten. A string cannot be erased in
// JavaScript; this is the documented limit of the toolchain.
async function readText(terminal, prompt, echo) {
  terminal.write(prompt);
  const bytes = await terminal.readLine({ echo });
  try {
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes)) refuse(KeyToolCode.INPUT_INVALID, 'the input is not valid UTF-8');
    return text;
  } finally {
    bytes.fill(0);
  }
}

const codePoints = (text) => [...text.normalize('NFC')].length;

function prepareRun(env) {
  checkNotRealRoot(env.system.getuid, env.net);
  checkNoNetwork(env.net);
  return env.terminal();
}

// --- keygen --------------------------------------------------------------------------------------

async function keygen(options, env) {
  const { network, purpose } = options;
  const keyDir = options['key-dir'];
  const logDir = options['log-dir'];
  checkSeparate(keyDir, 'key directory', logDir, 'sign log directory');
  const terminal = prepareRun(env);
  try {
    ensurePrivateDirectory(keyDir, 'key directory', env.system);
    ensurePrivateDirectory(logDir, 'sign log directory', env.system);
    checkKeyFileAbsent(keyDir, network, env.system);
    const entries = readSignLog(logDir, env.system);
    const replayed = replaySignLog(entries);
    // One time for the key file and its log entry, checked against the log BEFORE a key exists,
    // so a clock that went back cannot leave an unrecorded key file (review C4-4).
    const createdAt = isoSeconds(env.now());
    if (createdAt < replayed.lastTime) refuse(KeyToolCode.SIGNLOG_INVALID, `the clock (${createdAt}) is earlier than the last sign-log entry (${replayed.lastTime}); nothing was created`);
    for (const state of replayed.byAddress.values()) {
      if (state.key.network === network && state.key.purpose === purpose) refuse(KeyToolCode.KEY_EXISTS, `the sign log already records a key for ${network} ${purpose} (${state.key.address})`);
    }
    terminal.write(
      [
        'RN-NET key generation: TESTNET ONLY, no value',
        `network:   ${network}`,
        `purpose:   ${purpose}`,
        `key file:  ${join(keyDir, network === IntentNetwork.XRPL_TESTNET ? 'xrpl-testnet.key.json' : 'sepolia.key.json')}`,
        `sign log:  ${logDir}`,
        `The passphrase is read twice from this terminal, without echo; at least ${MIN_CREATION_PASSPHRASE} characters.`,
        'RN-NET never stores it. Losing it loses the key.',
        '',
      ].join('\n'),
    );
    const first = await readText(terminal, 'passphrase: ', false);
    if (codePoints(first) < MIN_CREATION_PASSPHRASE) refuse(KeyToolCode.PASSPHRASE_SHORT, `the passphrase must be at least ${MIN_CREATION_PASSPHRASE} characters`);
    const second = await readText(terminal, 'passphrase again: ', false);
    if (first.normalize('NFC') !== second.normalize('NFC')) refuse(KeyToolCode.PASSPHRASE_MISMATCH, 'the two passphrases differ; nothing was created');

    const key = generateKey({ network, purpose, source: env.source });
    let file;
    try {
      file = encryptKeyFile(key, first, { ...keyFileRandomness(env.source), createdAt });
    } finally {
      key.secretKey.fill(0);
    }
    const keyFileSha256 = writeKeyFile(keyDir, network, file, env.system);
    // Read back: the stored bytes decrypt with the passphrase to the same public key and address.
    const stored = readKeyFile(keyDir, network, env.system);
    if (stored.sha256 !== keyFileSha256) refuse(KeyToolCode.FILE_INVALID, 'the key file read back differs from the one written');
    const check = decryptKeyFile(stored.file, first);
    check.secretKey.fill(0);
    const entry = nextEntry(entries, EntryType.KEY_CREATED, { network, purpose, address: file.address, publicKey: file.publicKey, keyFileSha256 }, createdAt);
    appendSignLog(logDir, entries, entry, env.system);
    const summary = [
      'KEY CREATED (public metadata only)',
      `network:        ${network}`,
      `purpose:        ${purpose}`,
      `address:        ${file.address}`,
      `public key:     ${file.publicKey}`,
      `key file:       ${stored.path}`,
      `key file hash:  ${keyFileSha256}`,
      `sign log entry: ${entry.index} (KEY_CREATED)`,
      'Nothing is signed. Funding is gate C and signing is gate D, each a separate authorization.',
      '',
    ].join('\n');
    terminal.write(summary);
    env.out(summary);
    return 0;
  } finally {
    terminal.close();
  }
}

// --- show ----------------------------------------------------------------------------------------

function show(options, env) {
  const { network } = options;
  const stored = readKeyFile(options['key-dir'], network, env.system);
  const lines = ['KEY FILE (public metadata only)', ...Object.entries(stored.publicInfo).map(([k, v]) => `${k}: ${v}`), `path: ${stored.path}`, `sha256: ${stored.sha256}`];
  if (Object.hasOwn(options, 'log-dir')) {
    checkSeparate(options['key-dir'], 'key directory', options['log-dir'], 'sign log directory');
    const entries = readSignLog(options['log-dir'], env.system);
    const state = replaySignLog(entries).byAddress.get(stored.publicInfo.address);
    const registered = state?.key.keyFileSha256 === stored.sha256 && state.key.publicKey === stored.publicInfo.publicKey;
    lines.push(`sign log: ${entries.length} entries, consistent`, `registered: ${registered ? 'yes (KEY_CREATED matches this file)' : 'NO: no KEY_CREATED entry for exactly this file'}`);
    if (registered) {
      lines.push(`signed sequence: ${state.sequence ?? 'none'}`, `pending SIGNING: ${state.pending ?? 'none'}`, `signed digests: ${[...state.signed.keys()].join(' ') || 'none'}`, `unused RESIGN_BASIS: ${state.basis?.intentDigest ?? 'none'}`);
    }
  }
  env.out(`${lines.join('\n')}\n`);
  return 0;
}

// --- sign ----------------------------------------------------------------------------------------

function describe(intent) {
  const tx = intent.transaction;
  if (intent.network === IntentNetwork.XRPL_TESTNET) {
    return [
      `sender (Account):   ${tx.Account}`,
      `SigningPubKey:      ${tx.SigningPubKey}`,
      `TransactionType:    ${tx.TransactionType}`,
      `Sequence:           ${tx.Sequence}`,
      `Fee (drops):        ${tx.Fee}`,
      `LastLedgerSequence: ${tx.LastLedgerSequence}`,
      `payload (MemoData): ${tx.Memos[0].Memo.MemoData}`,
    ];
  }
  return [
    `sender (from):        ${tx.from}`,
    `to:                   ${tx.to}`,
    `chainId:              ${tx.chainId}`,
    `nonce:                ${tx.nonce}`,
    `value:                ${tx.value}`,
    `gas:                  ${tx.gas}`,
    `maxFeePerGas:         ${tx.maxFeePerGas}`,
    `maxPriorityFeePerGas: ${tx.maxPriorityFeePerGas}`,
    `payload (input):      ${tx.input}`,
  ];
}

const outputName = (intent, digest) => `${NETWORK_SLUG[intent.network]}-${intentSequence(intent)}-${digest.slice(7, 23)}.signed.json`;

function parseJson(bytes, what) {
  try {
    return parse(Buffer.from(bytes).toString('utf8').replace(/\n$/, ''));
  } catch {
    return refuse(KeyToolCode.FILE_INVALID, `${what} is not valid JSON`);
  }
}

// The signed output, written in two steps around the SIGNED entry (K4: SIGNED before the blob is
// written out): the bytes go to `.<name>.partial` (fsync'ed), then SIGNED is appended, then the
// partial is linked to its final name. Returns the final path.
function stageOutput(outDir, name, bytes, system) {
  const partial = join(outDir, `.${name}.partial`);
  const existing = lstatOrNull(partial);
  if (existing !== null) {
    if (!readPrivateFile(partial, MAX_OUTPUT_BYTES, system.getuid).equals(bytes)) refuse(KeyToolCode.OUTPUT_CONFLICT, `${partial} holds other bytes`);
    return;
  }
  // Written under a second temporary name and linked to the partial name, so the partial name only
  // ever holds complete bytes.
  createDurably(outDir, `.${name}.partial`, `.${name}.partial.tmp`, bytes, { existsCode: KeyToolCode.OUTPUT_CONFLICT, partialCode: KeyToolCode.OUTPUT_CONFLICT });
}

async function sign(options, env) {
  const { network } = options;
  const keyDir = options['key-dir'];
  const logDir = options['log-dir'];
  const outDir = options['out-dir'];
  const approvedDigest = options['approved-digest'];
  checkSeparate(keyDir, 'key directory', logDir, 'sign log directory');
  checkSeparate(keyDir, 'key directory', outDir, 'output directory');
  checkSeparate(logDir, 'sign log directory', outDir, 'output directory');
  const terminal = prepareRun(env);
  try {
    for (const [dir, what] of [[keyDir, 'key directory'], [logDir, 'sign log directory'], [outDir, 'output directory']]) checkPrivateDirectory(dir, what, env.system);

    // 1. The intent, checked and matched EXACTLY against the approved digest (recomputed here).
    const intent = approvedIntent(parseJson(readInputFile(options.intent, MAX_INPUT_BYTES), 'the intent'), approvedDigest);
    if (intent.network !== network) refuse(KeyToolCode.USAGE, `the intent is for ${intent.network}, not ${network}`);

    // 2. The key file, public part only: bound to the intent's network, purpose and sender.
    const stored = readKeyFile(keyDir, network, env.system);
    const info = stored.publicInfo;
    if (info.purpose !== intent.purpose) refuse(KeyToolCode.KEY_MISMATCH, `the key is for purpose ${info.purpose}`);
    if (info.address !== intentSender(intent)) refuse(KeyToolCode.KEY_MISMATCH, 'the intent sender is not the key address');
    if (network === IntentNetwork.XRPL_TESTNET && intent.transaction.SigningPubKey !== info.publicKey) refuse(KeyToolCode.KEY_MISMATCH, 'SigningPubKey is not the key');

    // 3. The re-sign basis, if any, and the sign-log decision.
    const resign = Object.hasOwn(options, 'resign-basis') ? readResignBasis(parseJson(readInputFile(options['resign-basis'], MAX_INPUT_BYTES), 'the status record')) : null;
    const request = { network, purpose: intent.purpose, address: info.address, publicKey: info.publicKey, keyFileSha256: stored.sha256, sequence: String(intentSequence(intent)), intentDigest: approvedDigest, resign };
    let entries = readSignLog(logDir, env.system);
    let decision;
    try {
      decision = decideSigning(entries, request);
    } catch (error) {
      if (error?.code === KeyToolCode.ALREADY_SIGNED) recoverOutput(entries, request, intent, outDir, env, terminal);
      throw error;
    }

    // 4. The founder sees everything and confirms by typing the end of the digest.
    const hex = approvedDigest.slice('sha256:'.length);
    terminal.write(
      [
        'RN-NET signing: TESTNET ONLY',
        `network:  ${intent.network}`,
        `purpose:  ${intent.purpose}`,
        `key file: ${stored.path} (${stored.sha256})`,
        ...describe(intent),
        `commitment: ${intent.commitment}`,
        `sign-log action: ${decision.action}${resign ? ` (re-sign after EXPIRED ${resign.expiredTransactionHash}, status record ${resign.statusRecordDigest})` : ''}`,
        'intent (canonical JSON):',
        canonicalize(intent),
        '',
        'intent digest (recomputed here; it equals the approved digest exactly):',
        `  ${approvedDigest}`,
        `  ${hex.match(/.{4}/g).join(' ')}`,
        '',
      ].join('\n'),
    );
    const typed = await readText(terminal, `Type the last ${CONFIRM_LENGTH} characters of the digest to approve: `, true);
    if (typed !== hex.slice(-CONFIRM_LENGTH)) refuse(KeyToolCode.CONFIRMATION_MISMATCH, 'the characters typed are not the end of the digest; nothing was signed');

    // 5. The passphrase, then the secret, for as short a time as possible.
    const passphrase = await readText(terminal, 'passphrase: ', false);
    const secret = decryptKeyFile(stored.file, passphrase);
    let result;
    try {
      // The log is read again: another run may have written since the decision above.
      entries = readSignLog(logDir, env.system);
      decision = decideSigning(entries, request);
      const at = () => isoSeconds(env.now());
      const common = { network, purpose: intent.purpose, address: info.address, sequence: request.sequence, intentDigest: approvedDigest };
      if (decision.action === SignAction.RESIGN) {
        entries = appendSignLog(logDir, entries, nextEntry(entries, EntryType.RESIGN_BASIS, { ...common, expiredIntentDigest: replaySignLog(entries).byAddress.get(info.address).latest.intentDigest, expiredTransactionHash: resign.expiredTransactionHash, statusRecordDigest: resign.statusRecordDigest }, at()), env.system);
      }
      if (decision.action !== SignAction.COMPLETE) entries = appendSignLog(logDir, entries, nextEntry(entries, EntryType.SIGNING, common, at()), env.system);
      result = createSigner().sign(intent, approvedDigest, { network, purpose: secret.purpose, secretKey: secret.secretKey });
      const name = outputName(intent, approvedDigest);
      const bytes = Buffer.from(`${canonicalize(result)}\n`, 'utf8');
      stageOutput(outDir, name, bytes, env.system);
      entries = appendSignLog(logDir, entries, nextEntry(entries, EntryType.SIGNED, { ...common, blobSha256: result.blobSha256, transactionHash: result.transactionHash }, at()), env.system);
      const finalPath = linkOutput(outDir, name, bytes, env.system);
      const summary = signedSummary(intent, result, finalPath, entries.length - 1);
      terminal.write(summary);
      env.out(summary);
      return 0;
    } finally {
      secret.secretKey.fill(0);
    }
  } finally {
    terminal.close();
  }
}

// Links the staged output to its final name and removes the staging name (same bytes, same inode).
function linkOutput(outDir, name, bytes, system) {
  const finalPath = join(outDir, name);
  const partial = join(outDir, `.${name}.partial`);
  if (lstatOrNull(finalPath) === null) {
    if (!readPrivateFile(partial, MAX_OUTPUT_BYTES, system.getuid).equals(bytes)) refuse(KeyToolCode.OUTPUT_CONFLICT, `${partial} holds other bytes`);
    linkStaged(outDir, partial, finalPath);
  } else if (!readPrivateFile(finalPath, MAX_OUTPUT_BYTES, system.getuid).equals(bytes)) {
    refuse(KeyToolCode.OUTPUT_CONFLICT, `${finalPath} holds other bytes`);
  } else if (lstatOrNull(partial) !== null) {
    linkStaged(outDir, partial, null);
  }
  return finalPath;
}

// RNTX_ALREADY_SIGNED: the blob already written is the output. If a run stopped after SIGNED but
// before the final link, the staged copy (its hash checked against the SIGNED entry) is linked now;
// nothing is signed and no passphrase is asked for.
function recoverOutput(entries, request, intent, outDir, env, terminal) {
  const state = replaySignLog(entries).byAddress.get(request.address);
  const signedEntry = entries[state.signed.get(request.intentDigest).index];
  const name = outputName(intent, request.intentDigest);
  const finalPath = join(outDir, name);
  const partial = join(outDir, `.${name}.partial`);
  for (const path of [finalPath, partial]) {
    if (lstatOrNull(path) === null) continue;
    const bytes = readPrivateFile(path, MAX_OUTPUT_BYTES, env.system.getuid);
    const output = parseJson(bytes, path);
    // The staged copy is re-verified, not trusted (review C4-3): its bytes are its canonical JSON,
    // its signed transaction verifies against the approved intent, and the recomputed blob and
    // transaction hashes are the SIGNED entry's.
    const verification = verifySignedTransaction({ intent, approvedDigest: request.intentDigest, signedTransaction: output?.signedTransaction });
    const consistent =
      output !== null && typeof output === 'object' && `${canonicalize(output)}\n` === bytes.toString('utf8') &&
      verification.outcome === 'PASS' && verification.blobSha256 === signedEntry.blobSha256 && verification.transactionHash === signedEntry.transactionHash &&
      output.blobSha256 === signedEntry.blobSha256 && output.transactionHash === signedEntry.transactionHash && output.intentDigest === request.intentDigest &&
      canonicalize(output.verification) === canonicalize(verification);
    if (!consistent) refuse(KeyToolCode.OUTPUT_CONFLICT, `${path} does not match sign-log entry ${signedEntry.index}`);
    const published = linkOutput(outDir, name, bytes, env.system);
    terminal.write(`Already signed (sign-log entry ${signedEntry.index}). The signed output is ${published}\n`);
    return;
  }
  terminal.write(`Already signed (sign-log entry ${signedEntry.index}), and no output file for it is in ${outDir}.\n`);
}

function signedSummary(intent, result, path, entryIndex) {
  const validity = intent.network === IntentNetwork.XRPL_TESTNET ? `lastLedgerSequence ${intent.transaction.LastLedgerSequence} (void at ${intent.transaction.LastLedgerSequence - 4})` : 'notAfter: chosen by the founder';
  return [
    'SIGNED (offline; nothing was sent)',
    `network:          ${result.network}`,
    `intent digest:    ${result.intentDigest}`,
    `blob sha256:      ${result.blobSha256}`,
    `transaction hash: ${result.transactionHash}`,
    `self-verification: ${result.verification.outcome}`,
    `signed output:    ${path}`,
    `sign-log entry:   ${entryIndex} (SIGNED)`,
    'For the rnnet.broadcast-authorization.v1 draft (gate E, a separate authorization):',
    `  network ${result.network}, sender ${intentSender(intent)}, sequence ${intentSequence(intent)}`,
    `  intentDigest ${result.intentDigest}, blobSha256 ${result.blobSha256}, transactionHash ${result.transactionHash}`,
    `  validity: ${validity}`,
    '',
  ].join('\n');
}

// Links the partial name to the final name (if given; link() never replaces), then removes the
// partial name and fsyncs the directory.
function linkStaged(outDir, partial, finalPath) {
  if (finalPath !== null) {
    try {
      linkSync(partial, finalPath);
    } catch (error) {
      if (error?.code === 'EEXIST') refuse(KeyToolCode.OUTPUT_CONFLICT, `${finalPath} appeared while it was being written`);
      throw error;
    }
  }
  unlinkSync(partial);
  fsyncDirectory(outDir);
}

// --- entry point ---------------------------------------------------------------------------------

/** Runs one command. Returns the exit code: 0 done, 1 refused, 2 usage. */
export async function run(argv, env = PRODUCTION) {
  let parsed;
  try {
    parsed = parseArguments(argv);
  } catch (error) {
    env.out(`${error.message}\n`);
    return 2;
  }
  try {
    if (parsed.command === 'keygen') return await keygen(parsed.options, env);
    if (parsed.command === 'show') return show(parsed.options, env);
    return await sign(parsed.options, env);
  } catch (error) {
    if (error instanceof KeyToolError || error instanceof TxError) {
      env.out(`refused: ${error.message}\n`);
      return error.code === KeyToolCode.USAGE ? 2 : 1;
    }
    env.out(`refused: unexpected ${error?.name ?? 'error'}${error?.code ? ` ${error.code}` : ''}\n`);
    return 1;
  }
}

const invokedDirectly = (() => {
  try {
    return process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
