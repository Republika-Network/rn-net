// Preloaded (--import) into the DISABLED C6 command by tools/broadcast/live-disabled.check.mjs only
// (RN-NET-03B2-C6-H3, review R1). At exit it writes, to file descriptor 3, the network modules the
// process loaded (none may be: the disabled command must not load the transport or node:https).
// It changes nothing in the command's behaviour.
import { writeSync } from 'node:fs';

const NETWORK = /^NativeModule (?:http|https|http2|tls|dns|_http_client|_http_agent|_tls_wrap|dgram)$/;
process.on('exit', () => {
  const loaded = process.moduleLoadList.filter((m) => NETWORK.test(m)).map((m) => m.slice('NativeModule '.length));
  writeSync(3, JSON.stringify({ networkModules: loaded }));
});
