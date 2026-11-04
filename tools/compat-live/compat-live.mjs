#!/usr/bin/env node
// tools/compat-live/compat-live.mjs: the controlled, READ-ONLY, keyless C6 provider compatibility
// command (RN-NET-03B2-C6-LIVE, enabling code reviewed in C6-LIVE-ENABLE;
// docs/genesis/rn-net-03b2c6-provider-compatibility.md §8, spec/rnnet.compat-authorization.v1.md).
// LIVE NETWORK ACCESS IS DISABLED: while LIVE_NETWORK_ACCESS is false, the command refuses at once
// (RNCL_LIVE_DISABLED, exit 3), before it reads an argument, a file or the environment, builds a
// transport or contacts anything.
//
// This is the ONLY file that joins the C6 run to a transport (COMPAT_TRANSPORT_JOINERS). Enabling
// it is a separate, founder-controlled, reviewed change that sets BOTH:
//   - LIVE_NETWORK_ACCESS = true here, and
//   - AGREED_EVIDENCE_DIR in tools/compat-live/entry.mjs (null today: every run is refused);
// and then one run needs the founder's H3 authorization (rnnet.compat-authorization.v1) and the
// typed approval `c6 <last 16 hex digits of its digest>` on the terminal.
//
// What it wires, and nothing more: the C6 transport (c6-transport.mjs: four reviewed URLs, 22
// requests, 10 s, 256 KiB, no proxy, explicit TLS, public addresses only), the /dev/tty approval
// (tty-approval.mjs), the system clock and uid, into the flow (command.mjs, flow.mjs). It holds no
// key, imports nothing of the signer, txverify, the key tool, tools/signing/, preparation or the
// write path, and sends no write method (guard: compat-live-reaches-write-or-key).
import { fileURLToPath } from 'node:url';
import { runCommand, systemSeconds } from './command.mjs';
import { CompatEntryCode } from './entry.mjs';
import { COMPAT_EXIT } from './flow.mjs';
import { createTtyApproval } from './tty-approval.mjs';

/**
 * False: restored by the RN-NET-03B2-C6-H3 post-run deactivation (docs/genesis/rn-net-03b2c6-h3-activation.md
 * §5) after the one authorized run. A test pins it; the command refuses while it is false.
 */
export const LIVE_NETWORK_ACCESS = false;

/** The command line: refuses while LIVE_NETWORK_ACCESS is false, before reading anything. */
export async function main() {
  if (!LIVE_NETWORK_ACCESS) {
    process.stderr.write(`${CompatEntryCode.LIVE_DISABLED}: live network access is disabled. A separately reviewed, founder-controlled enabling change and the founder's H3 authorization are required.\n`);
    return COMPAT_EXIT.LIVE_DISABLED;
  }
  // Loaded only once enabled: the disabled command never loads the transport or node:https.
  const { createC6Transport } = await import('./c6-transport.mjs');
  return runCommand({
    argv: process.argv.slice(2),
    env: process.env,
    execArgv: process.execArgv,
    createTransport: createC6Transport,
    approve: createTtyApproval(),
    now: systemSeconds,
    getuid: () => process.getuid(),
    write: (text) => process.stdout.write(text),
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = await main();
