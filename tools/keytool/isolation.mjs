// The run-time network check of keygen and sign (ADR-RN-017 Amendment C1, K1 and K3). Both are
// run under `unshare -rn`; this check refuses to continue if the process can see any network
// interface other than loopback or any route that does not go through loopback. It reads the
// process's own network namespace (/proc/self/net), never /sys/class/net, which shows the
// namespace sysfs was mounted in. It cannot start a namespace itself (no child processes here).
// Any read failure is a refusal.
import { readFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { KeyToolCode, refuse } from './errors.mjs';

export const SYSTEM_NET = Object.freeze({
  readProc: (name) => readFileSync(`/proc/self/${name}`, 'utf8'),
  interfaces: () => Object.keys(networkInterfaces()),
});

function read(net, name) {
  try {
    return net.readProc(name);
  } catch {
    return refuse(KeyToolCode.NETWORK_PRESENT, `could not read /proc/self/${name}; refusing`);
  }
}

/** Throws RNKEY_NETWORK_PRESENT unless loopback is the only interface and every route uses it. */
export function checkNoNetwork(net = SYSTEM_NET) {
  const dev = read(net, 'net/dev').split('\n').slice(2).filter((line) => line.trim() !== '');
  const names = dev.map((line) => line.split(':')[0].trim());
  if (names.length === 0 || names.some((name) => name !== 'lo')) refuse(KeyToolCode.NETWORK_PRESENT, `interfaces other than loopback: ${names.filter((n) => n !== 'lo').join(' ') || '(none listed, not even lo)'}; run under unshare -rn`);
  let listed;
  try {
    listed = net.interfaces();
  } catch {
    refuse(KeyToolCode.NETWORK_PRESENT, 'could not list network interfaces');
  }
  if (listed.some((name) => name !== 'lo')) refuse(KeyToolCode.NETWORK_PRESENT, `interfaces with addresses other than loopback: ${listed.join(' ')}`);
  const v4 = read(net, 'net/route').split('\n').slice(1).filter((line) => line.trim() !== '');
  if (v4.some((line) => line.trim().split(/\s+/)[0] !== 'lo')) refuse(KeyToolCode.NETWORK_PRESENT, 'an IPv4 route that does not use loopback');
  const v6 = read(net, 'net/ipv6_route').split('\n').filter((line) => line.trim() !== '');
  if (v6.some((line) => line.trim().split(/\s+/).at(-1) !== 'lo')) refuse(KeyToolCode.NETWORK_PRESENT, 'an IPv6 route that does not use loopback');
}

/** Refuses real root (uid 0 mapped to uid 0): `unshare -rn` maps the founder's own uid to 0. */
export function checkNotRealRoot(getuid, net = SYSTEM_NET) {
  if (getuid() !== 0) return;
  const first = read(net, 'uid_map').trim().split('\n')[0]?.trim().split(/\s+/) ?? [];
  if (first[0] === '0' && first[1] === '0') refuse(KeyToolCode.REAL_ROOT, 'refusing to run as real root');
}
