// The C6 command once enabled (RN-NET-03B2-C6-LIVE-ENABLE), with its outside dependencies
// INJECTED: it holds no transport and reaches no network file, so the tests run it whole with a
// fake transport and a fake terminal. tools/compat-live/compat-live.mjs passes the real ones
// (createC6Transport, the /dev/tty approval, the system clock and uid), and only while its
// LIVE_NETWORK_ACCESS is true.
//
// Before anything is read, the transport is built from the process environment and Node.js
// options, and refused (RNCL_TRANSPORT_ENVIRONMENT, exit 2) if a proxy, TLS override, extra CA,
// NODE_OPTIONS or any Node.js option is present. Then the flow of flow.mjs runs: the agreed evidence
// directory, the H3 authorization and its binding, the reviewed endpoint file, the typed approval
// on the terminal, the durable evidence and the replay.
import { compatLive, COMPAT_EXIT } from './flow.mjs';

/**
 * @param {{ argv: string[], env: object, execArgv: string[], createTransport: ({ env, execArgv }) => Function,
 *           approve: (prompt: string) => Promise<string>, now: () => number, getuid: () => number,
 *           write: (text: string) => void, agreed?: string|null, io?: object }} options
 * Returns the exit code.
 */
export async function runCommand({ argv, env, execArgv, createTransport, approve, now, getuid, write, agreed, io }) {
  let transport;
  try {
    transport = createTransport({ env, execArgv });
  } catch (error) {
    if (error?.code !== 'RNCL_TRANSPORT_ENVIRONMENT') throw error;
    write(`REFUSED ${error.message}\nNo C6 run was started and nothing was read or sent.\n`);
    return COMPAT_EXIT.REFUSED;
  }
  const deps = { transport, now, approve, getuid, ...(agreed === undefined ? {} : { agreed }), ...(io === undefined ? {} : { io }) };
  const result = await compatLive({ argv, deps });
  write(`${result.message}\n`);
  return result.exitCode;
}

/** The system clock, in Unix seconds. */
export const systemSeconds = () => Math.floor(Date.now() / 1000);
