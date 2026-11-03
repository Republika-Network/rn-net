// The decision of the live-disabled check (tools/broadcast/live-disabled.check.mjs), with the
// command runner INJECTED so that it is tested without starting anything (RN-NET-03B2-C6-H3, review
// R1). It imports no entry point and starts no process: the check script passes a runner that does.
//
// The C6 command (compat-live/compat-live.mjs) is in exactly one of two reviewed states, read from
// its source before anything is started:
//   - DISABLED: LIVE_NETWORK_ACCESS = false and AGREED_EVIDENCE_DIR = null. The C6 command is then
//     STARTED like the other four and must refuse (exit 3, RNCL_LIVE_DISABLED, nothing on stdout,
//     no network module loaded, the evidence directory untouched). Only then are five entry points
//     reported as refusing;
//   - ACTIVATED: LIVE_NETWORK_ACCESS = true and AGREED_EVIDENCE_DIR = the H3 directory. The C6
//     command is NEVER started. The other four are, and the result says that C6 is ACTIVATED and
//     that not every entry point is disabled.
// Anything else (a mixed pair, another directory, a switch missing or written twice) is an
// UNREVIEWED CONFIGURATION: the check fails at once and starts nothing.

export const C6_COMMAND = 'compat-live/compat-live.mjs';
export const C6_ENTRY = 'compat-live/entry.mjs';
/** The H3 evidence directory of the reviewed activation (docs/genesis/rn-net-03b2c6-h3-activation.md). */
export const H3_EVIDENCE_DIR = '/home/vicvalch/rn-net-private/c6-evidence';
export const C6_STATE = Object.freeze({ DISABLED: 'DISABLED', ACTIVATED: 'ACTIVATED', UNREVIEWED: 'UNREVIEWED CONFIGURATION' });

/** Paths the commands are given: none exists, so any attempt to read one gives another error first. */
export const MISSING = '/nonexistent-rnnet-c3';
/** The four other live entry points, always started; each must refuse with its own code. */
export const OTHER_ENTRY_POINTS = Object.freeze([
  Object.freeze({ path: 'prepare/prepare-live.mjs', code: 'RNPL_LIVE_DISABLED', args: Object.freeze(['--network', 'xrpl:testnet', '--authorization', `${MISSING}/a.json`, '--endpoints', `${MISSING}/e.json`, '--evidence-dir', MISSING]) }),
  Object.freeze({ path: 'prepare/prepare-live.mjs', code: 'RNPL_LIVE_DISABLED', args: Object.freeze(['--network', 'evm:11155111', '--authorization', `${MISSING}/a.json`, '--endpoints', `${MISSING}/e.json`, '--evidence-dir', MISSING]) }),
  Object.freeze({ path: 'submit/submit-anchor.mjs', code: 'RNSA_LIVE_DISABLED', args: Object.freeze(['--network', 'xrpl:testnet', '--authorization', `${MISSING}/a.json`, '--intent', `${MISSING}/i.json`, '--approved-digest', `sha256:${'0'.repeat(64)}`, '--signed-transaction', `${MISSING}/s.txt`, '--endpoints', `${MISSING}/e.json`, '--log-dir', MISSING, '--evidence-dir', MISSING]) }),
  Object.freeze({ path: 'submit/status-check.mjs', code: 'RNSA_LIVE_DISABLED', args: Object.freeze(['--network', 'evm:11155111', '--authorization', `${MISSING}/a.json`, '--intent', `${MISSING}/i.json`, '--endpoints', `${MISSING}/e.json`, '--log-dir', MISSING, '--evidence-dir', MISSING]) }),
]);
/** The C6 command, started in the DISABLED state only; `evidenceDir` is replaced by an empty private directory to watch. */
export const C6_ENTRY_POINT = Object.freeze({ path: C6_COMMAND, code: 'RNCL_LIVE_DISABLED', args: Object.freeze(['--authorization', `${MISSING}/a.json`, '--endpoints', `${MISSING}/e.json`, '--evidence-dir']) });

/** Network modules whose loading means a transport was reached (net is loaded for stdio pipes, so it is not one). */
export const NETWORK_MODULES = Object.freeze(['http', 'https', 'http2', 'tls', 'dns', '_http_client', '_http_agent', '_tls_wrap', 'dgram']);

/** The one value of `export const <name> = <value>;` in `source`, or null if it is not there exactly once. */
function soleValue(source, name, valuePattern) {
  if (typeof source !== 'string') return null;
  const all = [...source.matchAll(new RegExp(`^\\s*export\\s+(?:const|let|var)\\s+${name}\\b.*$`, 'gm'))];
  if (all.length !== 1) return null;
  const m = new RegExp(`^export const ${name} = (${valuePattern});$`).exec(all[0][0]);
  return m === null ? null : m[1];
}

/** The C6 state, from the sources of compat-live.mjs and entry.mjs. */
export function c6State(commandSource, entrySource) {
  const live = soleValue(commandSource, 'LIVE_NETWORK_ACCESS', "true|false");
  const agreed = soleValue(entrySource, 'AGREED_EVIDENCE_DIR', "null|'[^'\\\\\\n]*'");
  let state = C6_STATE.UNREVIEWED;
  if (live === 'false' && agreed === 'null') state = C6_STATE.DISABLED;
  else if (live === 'true' && agreed === `'${H3_EVIDENCE_DIR}'`) state = C6_STATE.ACTIVATED;
  return Object.freeze({ state, live, agreed });
}

/** Whether one started entry point refused as required. */
export function refused(entry, result) {
  if (result === null || typeof result !== 'object') return false;
  const base = result.status === 3 && result.stdout === '' && typeof result.stderr === 'string' && result.stderr.startsWith(`${entry.code}: live network access is disabled`);
  if (entry !== C6_ENTRY_POINT) return base;
  // The C6 command is also watched: no network module loaded, the evidence directory untouched.
  return base && Array.isArray(result.networkModules) && result.networkModules.length === 0 && result.evidenceUntouched === true;
}

/**
 * The check. `commandSource` and `entrySource` are the sources of the C6 command and entry.mjs;
 * `run(entry)` starts one entry point and returns { status, stdout, stderr } (and, for C6,
 * networkModules and evidenceUntouched). Returns { exitCode, state, started, refusing, lines }.
 */
export function liveDisabledCheck({ commandSource, entrySource, run }) {
  const s = c6State(commandSource, entrySource);
  const switches = `LIVE_NETWORK_ACCESS=${s.live ?? '(not exactly once)'}, AGREED_EVIDENCE_DIR=${s.agreed ?? '(not exactly once)'}`;
  const lines = [];
  const started = [];
  if (s.state === C6_STATE.UNREVIEWED) {
    lines.push(`FAIL ${C6_COMMAND}: UNREVIEWED CONFIGURATION (${switches}); nothing was started`);
    lines.push('live-disabled check: FAILED: UNREVIEWED CONFIGURATION');
    return Object.freeze({ exitCode: 1, state: s.state, started, refusing: 0, lines });
  }
  const entries = s.state === C6_STATE.DISABLED ? [...OTHER_ENTRY_POINTS, C6_ENTRY_POINT] : [...OTHER_ENTRY_POINTS];
  let refusing = 0;
  for (const entry of entries) {
    started.push(entry.path);
    let result;
    try {
      result = run(entry);
    } catch {
      result = null;
    }
    const ok = refused(entry, result);
    if (ok) refusing += 1;
    const extra = entry === C6_ENTRY_POINT && result ? `; network modules loaded: ${(result.networkModules ?? ['?']).join(',') || 'none'}; evidence directory untouched: ${result.evidenceUntouched === true}` : '';
    lines.push(`${ok ? 'ok' : 'FAIL'} ${entry.path} ${entry.args[1]}: exit ${result?.status ?? '?'}${extra}`);
  }
  if (s.state === C6_STATE.DISABLED) {
    const all = refusing === entries.length;
    lines.push(`${all ? 'ok' : 'FAIL'} ${C6_COMMAND}: DISABLED (${switches}), started and ${all ? 'refused' : 'checked'}`);
    lines.push(all ? `live-disabled check: ${refusing}/${entries.length} entry points refuse (C6 disabled)` : `live-disabled check: FAILED: ${refusing}/${entries.length} entry points refuse`);
    return Object.freeze({ exitCode: all ? 0 : 1, state: s.state, started, refusing, lines });
  }
  const others = refusing === entries.length;
  lines.push(`ok ${C6_COMMAND}: ACTIVATED (${switches}): NOT executed, NOT disabled`);
  lines.push(others
    ? `live-disabled check: ${refusing}/${entries.length} other entry points refuse; C6 is ACTIVATED: NOT all live entry points are disabled`
    : `live-disabled check: FAILED: ${refusing}/${entries.length} other entry points refuse; C6 is ACTIVATED`);
  return Object.freeze({ exitCode: others ? 0 : 1, state: s.state, started, refusing, lines });
}
