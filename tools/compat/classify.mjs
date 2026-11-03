// Classification of one C6 run (RN-NET-03B2-C6-PREP). Pure: it reads only the sanitized
// exchanges of the evidence and the time the run started.
//
//   PASS        the provider showed the behaviour the reviewed code needs;
//   BLOCKED     the reviewed code would refuse on what the provider returned (a wrong network, a
//               refused block-hash form, a hash it served although unknown, a disagreement, a
//               missing field). It is a finding about this observation, not a promise it persists;
//   UNRESOLVED  no conclusion: no answer, a transient state (staleness, skew, rate limit), a
//               request not sent, or a fact this run cannot settle.
// A network's verdict is BLOCKED if any of its checks is, PASS if all are, otherwise UNRESOLVED.
// A repeated run is a new founder authorization, never a retry.
import { C6_CALLDATA, C6_PROVIDERS, C6_REQUESTS, C6_XRPL_RANGE } from './manifest.mjs';

export const Status = Object.freeze({ PASS: 'PASS', BLOCKED: 'BLOCKED', UNRESOLVED: 'UNRESOLVED' });
/** The rippled release whose fail_hard behaviour was read (docs/genesis/rn-net-03b2c2-fail-hard-rippled-3.4.1.md). */
export const FAIL_HARD_CHECKED_VERSION = '3.4.1';
export const C6_RULES = Object.freeze({
  xrplMaxAgeSeconds: 30,
  xrplMaxSkewLedgers: 4,
  sepoliaHeadMaxAgeSeconds: 60,
  sepoliaHeadMaxAheadSeconds: 15,
  sepoliaPinMaxAgeSeconds: 90,
  sepoliaMaxSkewBlocks: 4,
  gasLimit: 30_000,
  /** The verifier walks at most this many parent hashes (ANCESTRY_LIMIT). */
  ancestryLimit: 256,
  /** Finalized heads at most this far apart leave a joint walk window of 192 blocks or more (about 38 min). */
  finalityPassBlocks: 64,
  /** Further apart than this leaves under 64 blocks (about 13 min), less than one finality period. */
  finalityBlockedBlocks: 192,
});

const { PASS, BLOCKED, UNRESOLVED } = Status;
const XRPL_IDS = C6_PROVIDERS.filter((p) => p.network === 'xrpl:testnet').map((p) => p.id);
const SEPOLIA_IDS = C6_PROVIDERS.filter((p) => p.network === 'evm:11155111').map((p) => p.id);

/** Intrinsic gas of the C6 estimate's call: 21,000 + 16 per non-zero and 4 per zero calldata byte. */
export function intrinsicGas(data = C6_CALLDATA) {
  let gas = 21_000;
  for (let i = 2; i < data.length; i += 2) gas += data.slice(i, i + 2) === '00' ? 4 : 16;
  return gas;
}

/** Parses complete_ledgers ("a-b,c,d-e") into ranges, or null. */
export function parseLedgerRanges(text) {
  if (typeof text !== 'string' || text === 'empty') return null;
  const ranges = [];
  for (const part of text.split(',')) {
    const m = /^(\d{1,10})(?:-(\d{1,10}))?$/.exec(part);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (hi < lo) return null;
    ranges.push([lo, hi]);
  }
  return ranges;
}

const big = (q) => BigInt(q);
const num = (q) => Number(BigInt(q));

/** Checks, verdicts, the Sepolia branch and the compatibility candidate for `evidence`. */
export function classify(evidence) {
  const now = evidence.observedAt;
  const ex = Object.fromEntries(evidence.exchanges.map((e) => [e.id, e]));
  const of = (form, id) => ex[C6_REQUESTS.find((r) => r.form === form && r.providerId === id).id];
  const checks = [];
  const add = (id, status, detail) => checks.push({ id, status, detail });
  const noAnswer = (e) => (e.outcome === 'NOT_SENT' ? `not sent: ${e.notSentReason}` : `no usable answer: ${e.outcome}`);

  // --- XRPL ---------------------------------------------------------------------------------
  const validated = {};
  for (const id of XRPL_IDS) {
    const e = of('server_info', id);
    const o = e.outcome === 'OK' ? e.observed : null;
    if (o === null) {
      for (const c of ['identity', 'build_version', 'validated', 'history']) add(`xrpl.${c}.${id}`, UNRESOLVED, noAnswer(e));
    } else {
      add(`xrpl.identity.${id}`, o.networkId === 1 ? PASS : BLOCKED, o.networkId === 1 ? 'network_id 1' : `network_id ${o.networkId}`);
      if (o.networkId !== 1) {
        for (const c of ['build_version', 'validated', 'history']) add(`xrpl.${c}.${id}`, UNRESOLVED, 'not read: wrong network');
      } else {
        if (o.buildVersion === null) add(`xrpl.build_version.${id}`, UNRESOLVED, 'no build_version');
        else add(`xrpl.build_version.${id}`, o.buildVersion === FAIL_HARD_CHECKED_VERSION ? PASS : UNRESOLVED, o.buildVersion === FAIL_HARD_CHECKED_VERSION ? `${o.buildVersion}, the release whose fail_hard was read` : `${o.buildVersion}: fail_hard must be read at this release before gate E`);
        if (o.validatedSeq === null || o.validatedHash === null || o.validatedAge === null) add(`xrpl.validated.${id}`, BLOCKED, 'validated_ledger {seq, hash, age} missing');
        else {
          validated[id] = o;
          add(`xrpl.validated.${id}`, o.validatedAge <= C6_RULES.xrplMaxAgeSeconds ? PASS : UNRESOLVED, `seq ${o.validatedSeq}, age ${o.validatedAge} s`);
        }
        const ranges = parseLedgerRanges(o.completeLedgers);
        if (o.validatedSeq === null) add(`xrpl.history.${id}`, BLOCKED, 'no validated ledger to measure history from');
        else if (ranges === null) add(`xrpl.history.${id}`, BLOCKED, `complete_ledgers ${o.completeLedgers}`);
        else {
          const lo = o.validatedSeq - C6_XRPL_RANGE;
          const covered = ranges.some(([a, b]) => a <= lo && b >= o.validatedSeq);
          add(`xrpl.history.${id}`, covered ? PASS : BLOCKED, `${covered ? 'covers' : 'does not cover'} ${lo}-${o.validatedSeq}`);
        }
      }
    }
    const t = of('tx_absent_range', id);
    if (t.outcome === 'RPC_ERROR' && t.rpcError.error === 'txnNotFound') add(`xrpl.tx_lookup.${id}`, t.rpcError.searchedAll === true ? PASS : BLOCKED, `txnNotFound, searched_all ${t.rpcError.searchedAll}`);
    else if (t.outcome === 'RPC_ERROR') add(`xrpl.tx_lookup.${id}`, BLOCKED, `error ${t.rpcError.error}`);
    else if (t.outcome === 'OK') add(`xrpl.tx_lookup.${id}`, UNRESOLVED, 'the absent transaction was reported found');
    else add(`xrpl.tx_lookup.${id}`, UNRESOLVED, noAnswer(t));
  }
  const [va, vb] = XRPL_IDS.map((id) => validated[id]);
  if (!va || !vb) add('xrpl.agreement', UNRESOLVED, 'a validated ledger is missing');
  else if (va.validatedSeq === vb.validatedSeq && va.validatedHash !== vb.validatedHash) add('xrpl.agreement', BLOCKED, `ledger ${va.validatedSeq} reported with two hashes`);
  else {
    const skew = Math.abs(va.validatedSeq - vb.validatedSeq);
    add('xrpl.agreement', skew <= C6_RULES.xrplMaxSkewLedgers ? PASS : UNRESOLVED, `skew ${skew} ledgers`);
  }

  // --- Sepolia ------------------------------------------------------------------------------
  const heads = {};
  const finals = {};
  for (const id of SEPOLIA_IDS) {
    const c = of('chain_id', id);
    if (c.outcome !== 'OK') add(`sepolia.identity.${id}`, UNRESOLVED, noAnswer(c));
    else add(`sepolia.identity.${id}`, c.observed.chainId === '0xaa36a7' ? PASS : BLOCKED, `chain id ${c.observed.chainId}`);
    const h = of('head', id);
    const hb = h.outcome === 'OK' ? h.observed.block : undefined;
    if (hb === undefined) add(`sepolia.head.${id}`, UNRESOLVED, noAnswer(h));
    else if (hb === null || hb.number === null || hb.hash === null || hb.timestamp === null || hb.baseFeePerGas === null) add(`sepolia.head.${id}`, BLOCKED, 'latest block {number, hash, timestamp, baseFeePerGas} missing');
    else {
      heads[id] = hb;
      const age = now - num(hb.timestamp);
      const fresh = age <= C6_RULES.sepoliaHeadMaxAgeSeconds && -age < C6_RULES.sepoliaHeadMaxAheadSeconds;
      add(`sepolia.head.${id}`, fresh ? PASS : UNRESOLVED, `block ${num(hb.number)}, age ${age} s`);
    }
  }
  const [ha, hbb] = SEPOLIA_IDS.map((id) => heads[id]);
  if (!ha || !hbb) add('sepolia.head_agreement', UNRESOLVED, 'a head is missing');
  else if (ha.number === hbb.number && ha.hash !== hbb.hash) add('sepolia.head_agreement', BLOCKED, `block ${num(ha.number)} reported with two hashes`);
  else {
    const skew = Math.abs(num(ha.number) - num(hbb.number));
    add('sepolia.head_agreement', skew <= C6_RULES.sepoliaMaxSkewBlocks ? PASS : UNRESOLVED, `skew ${skew} blocks`);
  }

  const pins = SEPOLIA_IDS.map((id) => of('pin', id));
  if (pins.some((p) => p.outcome !== 'OK')) add('sepolia.pin_agreement', UNRESOLVED, pins.map((p) => `${p.providerId}: ${p.outcome === 'OK' ? 'ok' : noAnswer(p)}`).join('; '));
  else {
    const blocks = pins.map((p) => p.observed.block);
    if (blocks.some((b) => b === null || b.hash === null || b.timestamp === null || b.number === null)) add('sepolia.pin_agreement', BLOCKED, 'a pinned block {number, hash, timestamp} is missing');
    else if (blocks.some((b) => b.number !== blocks[0].number)) add('sepolia.pin_agreement', BLOCKED, 'a provider returned another block number for P');
    else if (blocks.some((b) => b.hash !== blocks[0].hash)) add('sepolia.pin_agreement', BLOCKED, `block ${num(blocks[0].number)} pinned with two hashes`);
    else {
      const age = now - num(blocks[0].timestamp);
      add('sepolia.pin_agreement', age <= C6_RULES.sepoliaPinMaxAgeSeconds ? PASS : UNRESOLVED, `block ${num(blocks[0].number)}, one hash, age ${age} s`);
    }
  }

  const intrinsic = intrinsicGas();
  const candidate = {};
  for (const id of SEPOLIA_IDS) {
    const account = [];
    for (const [form, name] of [['nonce_at_hash', 'nonce'], ['balance_at_hash', 'balance'], ['code_at_hash', 'code']]) {
      const e = of(form, id);
      let s;
      if (e.outcome === 'OK') s = e.observed.value === null ? BLOCKED : PASS;
      else if (e.outcome === 'RPC_ERROR') s = BLOCKED;
      else s = UNRESOLVED;
      account.push(s);
      add(`sepolia.eip1898.${name}.${id}`, s, e.outcome === 'OK' ? (e.observed.value === null ? 'result is not the expected type' : `result ${e.observed.value}`) : e.outcome === 'RPC_ERROR' ? rpcDetail(e) : noAnswer(e));
    }
    const g = of('estimate_at_hash', id);
    let gs;
    if (g.outcome === 'OK') {
      const v = g.observed.value;
      gs = v !== null && num(v) >= intrinsic && num(v) <= C6_RULES.gasLimit ? PASS : BLOCKED;
      add(`sepolia.estimate_gas.${id}`, gs, v === null ? 'result is not a QUANTITY' : `estimate ${num(v)} (intrinsic ${intrinsic}, limit ${C6_RULES.gasLimit})`);
    } else {
      gs = g.outcome === 'RPC_ERROR' ? BLOCKED : UNRESOLVED;
      add(`sepolia.estimate_gas.${id}`, gs, g.outcome === 'RPC_ERROR' ? rpcDetail(g) : noAnswer(g));
    }
    const u = of('balance_unknown_hash', id);
    if (u.outcome === 'RPC_ERROR') add(`sepolia.unknown_hash.${id}`, PASS, `refused: ${rpcDetail(u)}`);
    else if (u.outcome === 'OK') add(`sepolia.unknown_hash.${id}`, BLOCKED, 'served a block hash it cannot know');
    else add(`sepolia.unknown_hash.${id}`, UNRESOLVED, noAnswer(u));
    const f = of('finalized', id);
    const fb = f.outcome === 'OK' ? f.observed.block : undefined;
    if (fb === undefined) add(`sepolia.finalized.${id}`, UNRESOLVED, noAnswer(f));
    else if (fb === null || fb.number === null || fb.hash === null) add(`sepolia.finalized.${id}`, BLOCKED, 'finalized block {number, hash} missing');
    else {
      finals[id] = num(fb.number);
      const lag = heads[id] ? num(heads[id].number) - finals[id] : null;
      add(`sepolia.finalized.${id}`, lag === null || lag >= 0 ? PASS : BLOCKED, lag === null ? `finalized ${finals[id]}` : `finalized ${finals[id]}, ${lag} blocks behind its head`);
    }
    const tri = (list) => (list.every((s) => s === PASS) ? true : list.some((s) => s === BLOCKED) ? false : null);
    candidate[id] = { eip1898AccountReads: tri(account), estimateGasBlockHash: tri([gs]) };
  }
  const [fa, fbb] = SEPOLIA_IDS.map((id) => finals[id]);
  let finality = null;
  if (fa === undefined || fbb === undefined) add('sepolia.finality_window', UNRESOLVED, 'a finalized block is missing');
  else {
    const apart = Math.abs(fa - fbb);
    const joint = Math.max(0, C6_RULES.ancestryLimit - apart);
    finality = { finalizedApartBlocks: apart, jointWindowBlocks: joint, jointWindowSeconds: joint * 12 };
    const s = apart <= C6_RULES.finalityPassBlocks ? PASS : apart > C6_RULES.finalityBlockedBlocks ? BLOCKED : UNRESOLVED;
    add('sepolia.finality_window', s, `finalized heads ${apart} blocks apart; joint walk window ${joint} blocks (about ${Math.round((joint * 12) / 60)} min)`);
  }

  const status = (prefix) => checks.filter((c) => c.id.startsWith(prefix));
  const verdictOf = (list) => (list.some((c) => c.status === BLOCKED) ? BLOCKED : list.every((c) => c.status === PASS) ? PASS : UNRESOLVED);
  const verdict = { xrpl: verdictOf(status('xrpl.')), sepolia: verdictOf(status('sepolia.')) };
  return { checks, verdict, sepoliaBranches: branches(checks, verdict.sepolia), compatibilityCandidate: candidate, finality };
}

function rpcDetail(e) {
  const r = e.rpcError;
  return `JSON-RPC error ${r.code ?? r.error ?? '?'}${r.message ? `: ${r.message}` : ''}${e.httpStatus !== 200 ? ` (HTTP ${e.httpStatus})` : ''}`;
}

/**
 * The decision branches (docs/genesis/rn-net-03b2c6-provider-compatibility.md §6) this run
 * supports: A (compatible), B (account reads work, eth_estimateGas refuses the block-hash form),
 * C (block-hash agreement fails), D (finality lag leaves no usable window), E (any other BLOCKED
 * Sepolia check: an account read refused, an unknown hash served, a wrong chain, a malformed
 * block; outside A to D), or UNRESOLVED. B, C, D and E can hold together.
 */
export function branches(checks, sepoliaVerdict) {
  if (sepoliaVerdict === PASS) return ['A'];
  const sepolia = checks.filter((c) => c.id.startsWith('sepolia.'));
  const blocked = sepolia.filter((c) => c.status === BLOCKED);
  const accountAllPass = sepolia.filter((c) => c.id.startsWith('sepolia.eip1898.')).every((c) => c.status === PASS);
  const isC = (c) => c.id === 'sepolia.head_agreement' || c.id === 'sepolia.pin_agreement';
  const isB = (c) => accountAllPass && c.id.startsWith('sepolia.estimate_gas.');
  const isD = (c) => c.id === 'sepolia.finality_window';
  const out = [];
  if (blocked.some(isB)) out.push('B');
  if (blocked.some(isC)) out.push('C');
  if (blocked.some(isD)) out.push('D');
  if (blocked.some((c) => !isB(c) && !isC(c) && !isD(c))) out.push('E');
  return out.length > 0 ? out : ['UNRESOLVED'];
}
