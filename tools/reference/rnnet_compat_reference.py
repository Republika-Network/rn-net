#!/usr/bin/env python3
"""Independent reproduction of the C6 provider compatibility run (RN-NET-03B2-C6-PREP; ADR-RN-018
Amendment C1, P5; docs/genesis/rn-net-03b2c6-provider-compatibility.md).

Re-implements, without the JavaScript tools:
  - the manifest: the four reviewed providers at their configured URLs, the 22 read-only requests
    and their per-provider budget, the label-derived hashes, the Genesis calldata and the public
    test address; no write method;
  - the exact request bytes (canonical JSON) of every request the run sends, from what earlier
    responses showed (the XRPL range, the pin = lowest head - 2, each provider's pinned hash), and
    which requests are NOT_SENT for want of a dependency or after a wrong network;
  - strict parsing of each simulated response and its outcome, sanitized error and observation;
  - every check's PASS / BLOCKED / UNRESOLVED status, both verdicts, the Sepolia decision
    branches, the compatibility candidate and the finality-window numbers.
The free-text `detail` of each check is not compared; everything else in the evidence is.

Checks fixtures/compat-c6/ from the transcripts alone, and every run directory of the C6 entry
point in fixtures/compat-c6-live/ (RN-NET-03B2-C6-LIVE) from its files alone. Offline; standard
library only.
Run: python3 -I -B <this file>
     python3 -I -B <this file> --run <run directory> [--record]
       checks ONE run directory of tools/compat-live/compat-live.mjs: the authorization's binding,
       every request rebuilt byte for byte, every response digest, the evidence recomputed, the
       report rebuilt byte for byte; --record writes the result to python-reference.txt (0600, once).
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

PROVIDERS = [
    ("xrpl-testnet-ripple", "xrpl:testnet", "https://s.altnet.rippletest.net:51234/"),
    ("xrpl-testnet-xrpl-labs", "xrpl:testnet", "https://testnet.xrpl-labs.com/"),
    ("sepolia-publicnode", "evm:11155111", "https://ethereum-sepolia-rpc.publicnode.com/"),
    ("sepolia-1rpc", "evm:11155111", "https://public.1rpc.io/sepolia"),
]
NETWORK = {p: n for p, n, _ in PROVIDERS}
XRPL_IDS = [p for p, n, _ in PROVIDERS if n == "xrpl:testnet"]
SEP_IDS = [p for p, n, _ in PROVIDERS if n == "evm:11155111"]
BUDGET = {"xrpl-testnet-ripple": 2, "xrpl-testnet-xrpl-labs": 2, "sepolia-publicnode": 9, "sepolia-1rpc": 9}
READ_ONLY = {
    "xrpl:testnet": {"server_info", "tx", "ledger", "account_info"},
    "evm:11155111": {"eth_chainId", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByHash", "eth_getBlockByNumber",
                     "eth_getTransactionCount", "eth_getBalance", "eth_getCode", "eth_estimateGas"},
}
WRITE = {"submit", "submit_multisigned", "sign", "sign_for", "wallet_propose", "eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "eth_signTransaction", "personal_sign"}
MAX_BYTES = 262_144
TEST_ADDRESS = "0x57db031993583fe0cbbf42dbfcf6489e0fb70b86"
COMMITMENT = "a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7"
# rnnet.anchor-payload.v1 (ADR-RN-009): "RNNETANC", version 1, type 1 (sha256), then the digest.
CALLDATA = "0x" + (b"RNNETANC" + bytes([1, 1]) + bytes.fromhex(COMMITMENT)).hex()
ABSENT_TX = hashlib.sha256(b"rnnet:c6:absent-xrpl-transaction:v1").hexdigest().upper()
UNKNOWN_HASH = "0x" + hashlib.sha256(b"rnnet:c6:unknown-sepolia-block:v1").hexdigest()
RANGE = 999
PIN_DEPTH = 2
FAIL_HARD_VERSION = "3.4.1"

# (id, provider, method, form, needs), in order.
P_R, P_L, P_P, P_1 = (p for p, _, _ in PROVIDERS)
REQUESTS = [
    ("X01", P_R, "server_info", "server_info", []), ("X02", P_L, "server_info", "server_info", []),
    ("X03", P_R, "tx", "tx_absent_range", ["identity", "validated"]), ("X04", P_L, "tx", "tx_absent_range", ["identity", "validated"]),
    ("S01", P_P, "eth_chainId", "chain_id", []), ("S02", P_1, "eth_chainId", "chain_id", []),
    ("S03", P_P, "eth_getBlockByNumber", "head", ["identity"]), ("S04", P_1, "eth_getBlockByNumber", "head", ["identity"]),
    ("S05", P_P, "eth_getBlockByNumber", "pin", ["identity", "both_heads"]), ("S06", P_1, "eth_getBlockByNumber", "pin", ["identity", "both_heads"]),
]
for prov, base in ((P_P, 7), (P_1, 11)):
    for k, (m, f) in enumerate([("eth_getTransactionCount", "nonce_at_hash"), ("eth_getBalance", "balance_at_hash"), ("eth_getCode", "code_at_hash"), ("eth_estimateGas", "estimate_at_hash")]):
        REQUESTS.append((f"S{base + k:02d}", prov, m, f, ["identity", "own_pin"]))
REQUESTS += [("S15", P_P, "eth_getBalance", "balance_unknown_hash", ["identity"]), ("S16", P_1, "eth_getBalance", "balance_unknown_hash", ["identity"]),
             ("S17", P_P, "eth_getBlockByNumber", "finalized", ["identity"]), ("S18", P_1, "eth_getBlockByNumber", "finalized", ["identity"])]

QUANTITY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)")
EVM_HASH = re.compile(r"0x[0-9a-f]{64}")
DATA = re.compile(r"0x(?:[0-9a-f]{2}){0,64}")
XRPL_HASH = re.compile(r"[0-9A-F]{64}")
BUILD = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[a-z0-9]{1,16}(?:\.\d{1,4})?)?")
LEDGERS = re.compile(r"(?:empty|[0-9,-]{1,256})")
STATE = re.compile(r"[a-z_]{1,32}")
RPC_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
SAFE = 2 ** 53 - 1
SYNCED = ("full", "proposing", "validating")
TRANSIENT = (-32005, -32090, -32603)
TRANSPORT_CODES = ("RNLO_TIMEOUT", "RNLO_CONNECTION", "RNLO_RESPONSE_TOO_LARGE", "RNLO_REDIRECT", "RNLO_BLOCKED_ADDRESS")
MANIFEST_SHA256 = "2a45e37c0067e6e7e9aaa0705a298c712335b9a85060e332f794bac935088037"


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_text(provider, method, params):
    assert method in READ_ONLY[NETWORK[provider]] and method not in WRITE
    if NETWORK[provider] == "xrpl:testnet":
        return canon({"method": method, "params": [params]})
    return canon({"id": 1, "jsonrpc": "2.0", "method": method, "params": params})


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def safe_int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and -SAFE <= v <= SAFE else None


def match(rx, v):
    return v if isinstance(v, str) and rx.fullmatch(v) else None


def is_obj(v):
    return isinstance(v, dict)


def strict_json(data):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def no_constant(_):
        raise ValueError("constant")

    text = data.decode("utf-8")
    check_depth(text)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=no_constant)


MAX_DEPTH = 64


def check_depth(text):
    """packages/chain-readonly's limit, without recursion: the top value is at depth 1 and no value may
    be deeper than 64, so a container at depth 64 must be empty (C6-LIVE review N-a: the reference had
    no limit, accepted what the run refuses, and crashed on very deep input)."""
    depth, in_string, escape, must_close = 0, False, False, False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch in " \t\n\r":
            continue
        if must_close and ch not in "]}":
            raise ValueError("nesting too deep")
        must_close = False
        if ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting too deep")
            must_close = depth == MAX_DEPTH
        elif ch in "]}":
            depth -= 1
        elif ch == '"':
            in_string = True


def sanitize(value):
    if not isinstance(value, str):
        return None
    # JS cuts its UTF-16 string at 2048 units before mapping; mapped per code point, an astral
    # character split by that cut is two "?" either way, so cutting the UTF-16 encoding matches.
    units = value.encode("utf-16-le", "surrogatepass")
    if len(units) > 4096:
        value = units[:4096].decode("utf-16-le", "surrogatepass")
    ascii_text = "".join(ch if " " <= ch <= "~" else "?" for ch in value)
    if len(ascii_text) > 512:
        ascii_text = re.sub(r"\S*$", "", ascii_text[:512])
    ascii_text = re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://\S*", "<url>", ascii_text)
    ascii_text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:\d{1,5}\b", "<host>", ascii_text)
    ascii_text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", ascii_text)
    ascii_text = re.sub(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}", lambda m: "<ip>" if re.search(r"[0-9A-Fa-f]", m.group(0)) else m.group(0), ascii_text)
    ascii_text = re.sub(r"[A-Za-z0-9_+/=-]{32,}", lambda m: m.group(0) if re.fullmatch(r"0x[0-9a-fA-F]+", m.group(0)) else "<token>", ascii_text)
    return ascii_text[:160]


def block_of(r):
    if not is_obj(r):
        return None
    return {"number": match(QUANTITY, r.get("number")), "hash": match(EVM_HASH, r.get("hash")), "timestamp": match(QUANTITY, r.get("timestamp")), "baseFeePerGas": match(QUANTITY, r.get("baseFeePerGas"))}


def observe(form, r):
    if form == "server_info":
        info = r.get("info") if is_obj(r.get("info")) else {}
        v = info.get("validated_ledger") if is_obj(info.get("validated_ledger")) else {}
        return {"networkId": safe_int(info.get("network_id")), "buildVersion": match(BUILD, info.get("build_version")), "serverState": match(STATE, info.get("server_state")),
                "completeLedgers": match(LEDGERS, info.get("complete_ledgers")), "validatedSeq": safe_int(v.get("seq")), "validatedHash": match(XRPL_HASH, v.get("hash")), "validatedAge": safe_int(v.get("age"))}
    if form == "tx_absent_range":
        return {"found": True}
    if form == "chain_id":
        return {"chainId": match(QUANTITY, r)}
    if form in ("head", "pin", "finalized"):
        return {"block": block_of(r)}
    if form == "code_at_hash":
        return {"value": match(DATA, r)}
    return {"value": match(QUANTITY, r)}


def interpret(provider, form, status, body):
    out = {"outcome": None, "httpStatus": status, "rpcError": None, "observed": None}
    if len(body) > MAX_BYTES:
        return {**out, "outcome": "TOO_LARGE"}
    if status == 429:
        return {**out, "outcome": "RATE_LIMITED"}
    try:
        env = strict_json(body)
    except (ValueError, UnicodeDecodeError):
        return {**out, "outcome": "INVALID_RESPONSE" if status == 200 else "HTTP_STATUS"}
    if NETWORK[provider] == "xrpl:testnet":
        result = env.get("result") if is_obj(env) else None
        if is_obj(result) and result.get("status") == "error":
            sa = result.get("searched_all")
            return {**out, "outcome": "RPC_ERROR", "rpcError": {"error": match(RPC_NAME, result.get("error")), "code": safe_int(result.get("error_code")), "searchedAll": sa if isinstance(sa, bool) else None, "message": sanitize(result.get("error_message"))}}
        if status != 200:
            return {**out, "outcome": "HTTP_STATUS"}
        if not is_obj(result) or result.get("status") != "success":
            return {**out, "outcome": "INVALID_RESPONSE"}
        return {**out, "outcome": "OK", "observed": observe(form, result)}
    well = is_obj(env) and env.get("jsonrpc") == "2.0" and env.get("id") == 1 and not isinstance(env.get("id"), bool)
    if well and "error" in env:
        e = env["error"] if is_obj(env["error"]) else {}
        return {**out, "outcome": "RPC_ERROR", "rpcError": {"error": None, "code": safe_int(e.get("code")), "searchedAll": None, "message": sanitize(e.get("message"))}}
    if status != 200:
        return {**out, "outcome": "HTTP_STATUS"}
    if not well or "result" not in env:
        return {**out, "outcome": "INVALID_RESPONSE"}
    return {**out, "outcome": "OK", "observed": observe(form, env["result"])}


def build_params(form, provider, st):
    pinned = lambda h: {"blockHash": h, "requireCanonical": True}  # noqa: E731
    if form == "server_info":
        return {"api_version": 2}
    if form == "tx_absent_range":
        mx = st["validated"].get(provider)
        if mx is None or mx < RANGE:
            return None
        return {"api_version": 2, "binary": False, "max_ledger": mx, "min_ledger": mx - RANGE, "transaction": ABSENT_TX}
    if form == "chain_id":
        return []
    if form == "head":
        return ["latest", False]
    if form == "pin":
        return [st["pin"], False] if st["pin"] is not None else None
    if form in ("nonce_at_hash", "balance_at_hash", "code_at_hash"):
        h = st["pin_hash"].get(provider)
        return [TEST_ADDRESS, pinned(h)] if h else None
    if form == "estimate_at_hash":
        h = st["pin_hash"].get(provider)
        return [{"data": CALLDATA, "from": TEST_ADDRESS, "to": TEST_ADDRESS, "value": "0x0"}, pinned(h)] if h else None
    if form == "balance_unknown_hash":
        return [TEST_ADDRESS, pinned(UNKNOWN_HASH)]
    if form == "finalized":
        return ["finalized", False]
    raise AssertionError(form)


def unmet(needs, provider, st):
    for n in needs:
        if n == "identity" and st["identity"].get(provider) is not True:
            return "identity not confirmed"
        if n == "validated" and st["validated"].get(provider) is None:
            return "no validated ledger"
        if n == "both_heads" and st["pin"] is None:
            return "no head on both providers"
        if n == "own_pin" and not st["pin_hash"].get(provider):
            return "no pinned block on this provider"
    return None


def replay(transcript):
    """Runs the manifest against a transcript; returns (exchanges, count, per-provider, problems)."""
    st = {"identity": {}, "validated": {}, "heads": {}, "pin": None, "pin_hash": {}}
    sent = {p: 0 for p in BUDGET}
    exchanges, problems, i = [], [], 0
    for seq, (rid, prov, method, form, needs) in enumerate(REQUESTS, 1):
        rec = {"seq": seq, "id": rid, "providerId": prov, "method": method, "request": None, "requestSha256": None, "outcome": "NOT_SENT", "transportCode": None, "httpStatus": None,
               "responseSha256": None, "responseBytes": None, "rpcError": None, "observed": None, "notSentReason": None}
        exchanges.append(rec)
        miss = unmet(needs, prov, st)
        params = None if miss else build_params(form, prov, st)
        if miss or params is None:
            rec["notSentReason"] = miss or "dependency"
            continue
        text = request_text(prov, method, params)
        rec["request"], rec["requestSha256"] = text, sha(text.encode("utf-8"))
        sent[prov] += 1
        if sent[prov] > BUDGET[prov]:
            problems.append("budget")
        if i >= len(transcript) or transcript[i]["providerId"] != prov:
            problems.append(f"{rid}: transcript out of order")
            break
        t = transcript[i]
        i += 1
        if "error" in t:
            code = t["error"] if t["error"] in TRANSPORT_CODES else None
            rec["transportCode"] = code
            rec["outcome"] = {"RNLO_TIMEOUT": "TIMEOUT", "RNLO_RESPONSE_TOO_LARGE": "TOO_LARGE"}.get(code, "TRANSPORT_ERROR")
            continue
        body = t["body"] if "body" in t else t["text"].encode("utf-8") + b" " * t["pad"]
        rec["responseSha256"], rec["responseBytes"] = sha(body), len(body)
        rec.update(interpret(prov, form, t["status"], body))
        if rec["outcome"] != "OK":
            continue
        o = rec["observed"]
        if form == "server_info":
            st["identity"][prov] = o["networkId"] == 1
            if st["identity"][prov] and o["validatedSeq"] is not None:
                st["validated"][prov] = o["validatedSeq"]
        elif form == "chain_id":
            st["identity"][prov] = o["chainId"] == "0xaa36a7"
        elif form == "head" and o["block"] is not None and o["block"]["number"] is not None and o["block"]["hash"] is not None:
            st["heads"][prov] = int(o["block"]["number"], 16)
            if all(p in st["heads"] for p in SEP_IDS):
                low = min(st["heads"][p] for p in SEP_IDS)
                if low >= PIN_DEPTH:
                    st["pin"] = hex(low - PIN_DEPTH)
        elif form == "pin" and o["block"] is not None and o["block"]["number"] == st["pin"] and o["block"]["hash"] is not None:
            st["pin_hash"][prov] = o["block"]["hash"]
    if i != len(transcript):
        problems.append("unused transcript entries")
    return exchanges, sum(sent.values()), sent, problems


def intrinsic():
    """Gas used at least: max(standard, EIP-7623 floor); tokens are 1 per zero and 4 per non-zero byte."""
    tokens = sum(1 if b == 0 else 4 for b in bytes.fromhex(CALLDATA[2:]))
    return max(21_000 + 4 * tokens, 21_000 + 10 * tokens)


def transient(e):
    return e["outcome"] == "RPC_ERROR" and e["rpcError"]["code"] in TRANSIENT


def ranges(text):
    if not isinstance(text, str) or text == "empty":
        return None
    out = []
    for part in text.split(","):
        m = re.fullmatch(r"(\d{1,10})(?:-(\d{1,10}))?", part)
        if not m:
            return None
        lo = int(m.group(1))
        hi = lo if m.group(2) is None else int(m.group(2))
        if hi < lo:
            return None
        out.append((lo, hi))
    return out


def classify(now, exchanges):
    ex = {e["id"]: e for e in exchanges}
    of = lambda form, p: ex[next(r[0] for r in REQUESTS if r[3] == form and r[1] == p)]  # noqa: E731
    checks = []
    add = lambda cid, s: checks.append((cid, s))  # noqa: E731
    validated = {}
    for p in XRPL_IDS:
        e = of("server_info", p)
        o = e["observed"] if e["outcome"] == "OK" else None
        if o is None:
            for c in ("identity", "build_version", "validated", "history"):
                add(f"xrpl.{c}.{p}", "UNRESOLVED")
        else:
            add(f"xrpl.identity.{p}", "PASS" if o["networkId"] == 1 else "BLOCKED")
            if o["networkId"] != 1:
                for c in ("build_version", "validated", "history"):
                    add(f"xrpl.{c}.{p}", "UNRESOLVED")
            else:
                add(f"xrpl.build_version.{p}", "PASS" if o["buildVersion"] == FAIL_HARD_VERSION else "UNRESOLVED")
                if None in (o["validatedSeq"], o["validatedHash"], o["validatedAge"]) or o["validatedSeq"] < 0 or o["validatedAge"] < 0:
                    add(f"xrpl.validated.{p}", "BLOCKED")
                elif o["serverState"] not in SYNCED:
                    add(f"xrpl.validated.{p}", "UNRESOLVED")
                else:
                    validated[p] = o
                    add(f"xrpl.validated.{p}", "PASS" if o["validatedAge"] <= 30 else "UNRESOLVED")
                rg = ranges(o["completeLedgers"])
                if o["validatedSeq"] is None or rg is None:
                    add(f"xrpl.history.{p}", "BLOCKED")
                else:
                    lo = o["validatedSeq"] - RANGE
                    add(f"xrpl.history.{p}", "PASS" if any(a <= lo and b >= o["validatedSeq"] for a, b in rg) else "BLOCKED")
        t = of("tx_absent_range", p)
        if t["outcome"] == "RPC_ERROR" and t["rpcError"]["error"] == "txnNotFound":
            add(f"xrpl.tx_lookup.{p}", "PASS" if t["rpcError"]["searchedAll"] is True else "BLOCKED")
        elif t["outcome"] == "RPC_ERROR":
            add(f"xrpl.tx_lookup.{p}", "BLOCKED")
        else:
            add(f"xrpl.tx_lookup.{p}", "UNRESOLVED")
    va, vb = (validated.get(p) for p in XRPL_IDS)
    if not va or not vb:
        add("xrpl.agreement", "UNRESOLVED")
    elif va["validatedSeq"] == vb["validatedSeq"] and va["validatedHash"] != vb["validatedHash"]:
        add("xrpl.agreement", "BLOCKED")
    else:
        add("xrpl.agreement", "PASS" if abs(va["validatedSeq"] - vb["validatedSeq"]) <= 4 else "UNRESOLVED")

    heads, finals = {}, {}
    for p in SEP_IDS:
        c = of("chain_id", p)
        add(f"sepolia.identity.{p}", "UNRESOLVED" if c["outcome"] != "OK" else "PASS" if c["observed"]["chainId"] == "0xaa36a7" else "BLOCKED")
        h = of("head", p)
        if h["outcome"] != "OK":
            add(f"sepolia.head.{p}", "UNRESOLVED")
        else:
            b = h["observed"]["block"]
            if b is None or None in (b["number"], b["hash"], b["timestamp"], b["baseFeePerGas"]):
                add(f"sepolia.head.{p}", "BLOCKED")
            else:
                heads[p] = b
                age = now - int(b["timestamp"], 16)
                add(f"sepolia.head.{p}", "PASS" if age <= 60 and -age < 15 else "UNRESOLVED")
    ha, hb = (heads.get(p) for p in SEP_IDS)
    if not ha or not hb:
        add("sepolia.head_agreement", "UNRESOLVED")
    elif ha["number"] == hb["number"] and ha["hash"] != hb["hash"]:
        add("sepolia.head_agreement", "BLOCKED")
    else:
        add("sepolia.head_agreement", "PASS" if abs(int(ha["number"], 16) - int(hb["number"], 16)) <= 4 else "UNRESOLVED")
    pins = [of("pin", p) for p in SEP_IDS]
    if any(x["outcome"] != "OK" for x in pins):
        add("sepolia.pin_agreement", "UNRESOLVED")
    else:
        asked = json.loads(pins[0]["request"])["params"][0]
        bl = [x["observed"]["block"] for x in pins]
        if any(b is None or None in (b["hash"], b["timestamp"], b["number"], b["baseFeePerGas"]) for b in bl):
            add("sepolia.pin_agreement", "BLOCKED")
        elif any(b["number"] != asked or b["hash"] != bl[0]["hash"] or b["timestamp"] != bl[0]["timestamp"] or b["baseFeePerGas"] != bl[0]["baseFeePerGas"] for b in bl):
            add("sepolia.pin_agreement", "BLOCKED")
        else:
            add("sepolia.pin_agreement", "PASS" if now - int(bl[0]["timestamp"], 16) <= 90 else "UNRESOLVED")

    gas_min = intrinsic()
    candidate = {}
    for p in SEP_IDS:
        acct = []
        for form, name in (("nonce_at_hash", "nonce"), ("balance_at_hash", "balance"), ("code_at_hash", "code")):
            e = of(form, p)
            s = ("BLOCKED" if e["observed"]["value"] is None else "PASS") if e["outcome"] == "OK" else "BLOCKED" if e["outcome"] == "RPC_ERROR" and not transient(e) else "UNRESOLVED"
            acct.append(s)
            add(f"sepolia.eip1898.{name}.{p}", s)
        g = of("estimate_at_hash", p)
        if g["outcome"] == "OK":
            v = g["observed"]["value"]
            gs = "PASS" if v is not None and gas_min <= int(v, 16) <= 30_000 else "BLOCKED"
        else:
            gs = "BLOCKED" if g["outcome"] == "RPC_ERROR" and not transient(g) else "UNRESOLVED"
        add(f"sepolia.estimate_gas.{p}", gs)
        u = of("balance_unknown_hash", p)
        add(f"sepolia.unknown_hash.{p}", "UNRESOLVED" if transient(u) else "PASS" if u["outcome"] == "RPC_ERROR" else "BLOCKED" if u["outcome"] == "OK" else "UNRESOLVED")
        f = of("finalized", p)
        if f["outcome"] != "OK":
            add(f"sepolia.finalized.{p}", "UNRESOLVED")
        else:
            b = f["observed"]["block"]
            if b is None or None in (b["number"], b["hash"]):
                add(f"sepolia.finalized.{p}", "BLOCKED")
            else:
                finals[p] = int(b["number"], 16)
                lag = int(heads[p]["number"], 16) - finals[p] if p in heads else None
                add(f"sepolia.finalized.{p}", "PASS" if lag is None or lag >= 0 else "BLOCKED")
        tri = lambda xs: True if all(x == "PASS" for x in xs) else False if "BLOCKED" in xs else None  # noqa: E731
        candidate[p] = {"eip1898AccountReads": tri(acct), "estimateGasBlockHash": tri([gs])}
    finality = None
    if any(p not in finals for p in SEP_IDS):
        add("sepolia.finality_window", "UNRESOLVED")
    else:
        apart = abs(finals[SEP_IDS[0]] - finals[SEP_IDS[1]])
        joint = max(0, 256 - apart)
        finality = {"finalizedApartBlocks": apart, "jointWindowBlocks": joint, "jointWindowSeconds": joint * 12}
        add("sepolia.finality_window", "PASS" if apart <= 64 else "BLOCKED" if apart > 192 else "UNRESOLVED")

    def verdict(prefix):
        xs = [s for c, s in checks if c.startswith(prefix)]
        return "BLOCKED" if "BLOCKED" in xs else "PASS" if all(s == "PASS" for s in xs) else "UNRESOLVED"

    v = {"xrpl": verdict("xrpl."), "sepolia": verdict("sepolia.")}
    return checks, v, branches(checks, v["sepolia"]), candidate, finality


def branches(checks, sepolia_verdict):
    if sepolia_verdict == "PASS":
        return ["A"]
    sep = [(c, s) for c, s in checks if c.startswith("sepolia.")]
    blocked = [c for c, s in sep if s == "BLOCKED"]
    refused = {c.rsplit(".", 1)[1] for c in blocked if c.startswith("sepolia.eip1898.")}
    is_est = lambda c: c.startswith("sepolia.estimate_gas.")  # noqa: E731
    is_c = lambda c: c in ("sepolia.head_agreement", "sepolia.pin_agreement")  # noqa: E731
    is_b = lambda c: is_est(c) and c.rsplit(".", 1)[1] not in refused  # noqa: E731
    is_d = lambda c: c == "sepolia.finality_window"  # noqa: E731
    out = [name for name, pred in (("B", is_b), ("C", is_c), ("D", is_d)) if any(pred(c) for c in blocked)]
    if any(not (is_est(c) or is_c(c) or is_d(c)) for c in blocked):
        out.append("E")
    return out or ["UNRESOLVED"]


def checks_of(root):
    config = json.loads((root / "config/rpc-endpoints.json").read_text("utf-8"))
    manifest = json.loads((root / "fixtures/compat-c6/manifest.json").read_text("utf-8"))
    yield "config has exactly the four reviewed providers at their URLs", sorted((p["id"], p["network"], p["url"]) for p in config["providers"]) == sorted(PROVIDERS)
    yield "manifest providers are the reviewed providers, in order", [(p["id"], p["network"], p["url"]) for p in manifest["providers"]] == PROVIDERS
    yield "manifest has 22 requests", manifest["totalRequests"] == 22 and len(manifest["requests"]) == 22 == len(REQUESTS)
    yield "manifest budget per provider", manifest["budget"] == BUDGET and all(sum(1 for r in manifest["requests"] if r["providerId"] == p) == n for p, n in BUDGET.items())
    yield "manifest requests are the reference's, in order, at the provider's URL", [(r["id"], r["providerId"], r["method"], r["form"], r["needs"]) for r in manifest["requests"]] == [(a, b, c, d, e) for a, b, c, d, e in REQUESTS] and all(
        r["url"] == dict((p, u) for p, _, u in PROVIDERS)[r["providerId"]] for r in manifest["requests"])
    yield "manifest methods are read-only, none writes", all(r["method"] in READ_ONLY[NETWORK[r["providerId"]]] and r["method"] not in WRITE for r in manifest["requests"]) and not any(WRITE & s for s in READ_ONLY.values())
    yield "manifest limits: one attempt, 10 s, 256 KiB, no retry, no fallback", manifest["limits"] == {"attempts": 1, "timeoutMs": 10_000, "maxResponseBytes": MAX_BYTES} and manifest["retry"] is False and manifest["fallback"] is False
    yield "manifest constants are the label-derived values", (manifest["testAddress"], manifest["calldata"], manifest["absentXrplTransaction"], manifest["unknownBlockHash"], manifest["pinDepth"]) == (TEST_ADDRESS, CALLDATA, ABSENT_TX, UNKNOWN_HASH, PIN_DEPTH)
    yield "the manifest's canonical digest is the one a read authorization binds", hashlib.sha256(canon(manifest).encode("utf-8")).hexdigest() == MANIFEST_SHA256
    yield "the estimate minimum is the EIP-7623 floor, 22,680", intrinsic() == 22_680
    b1 = (root / "fixtures/signing-b1/golden.json").read_text("utf-8")
    yield "the test address is the B1 label-derived address", TEST_ADDRESS in b1

    fixture = json.loads((root / "fixtures/compat-c6/cases.json").read_text("utf-8"))
    seen_branches = set()
    for case in fixture["cases"]:
        exp = case["evidence"]
        exchanges, count, sent, problems = replay(case["transcript"])
        checks, verdict, br, candidate, finality = classify(case["now"], exchanges)
        seen_branches.update(br)
        same = (not problems and exchanges == exp["exchanges"] and count == exp["requestCount"] and sent == exp["sentPerProvider"]
                and exp["format"] == "rnnet.provider-compat-evidence.v1" and exp["observedAt"] == case["now"]
                and checks == [(c["id"], c["status"]) for c in exp["checks"]] and verdict == exp["verdict"] and br == exp["sepoliaBranches"]
                and candidate == exp["compatibilityCandidate"] and finality == exp["finality"]
                and set(exp) == {"format", "observedAt", "requestCount", "sentPerProvider", "exchanges", "checks", "verdict", "sepoliaBranches", "compatibilityCandidate", "finality"})
        yield f"{case['name']} -> X {verdict['xrpl']}, S {verdict['sepolia']} {'+'.join(br)} ({count} requests)", same
        yield f"{case['name']}: at most 22 requests, within each provider's budget, none repeated on a provider", count <= 22 and all(sent[p] <= BUDGET[p] for p in BUDGET) and len({(e["providerId"], e["request"]) for e in exchanges if e["request"]}) == count
    yield "every decision branch A to E and UNRESOLVED is covered", seen_branches >= {"A", "B", "C", "D", "E", "UNRESOLVED"}
    names = {c["name"] for c in fixture["cases"]}
    yield "every threshold has a fixture on each side", all(f"edge-{n}" in names for n in (
        "head-skew-4", "head-age-60", "head-age-61", "head-ahead-14", "head-ahead-15", "pin-age-90", "pin-age-91", "finality-apart-64", "finality-apart-65",
        "finality-apart-192", "finality-apart-193", "estimate-22679", "estimate-30000", "xrpl-age-30", "xrpl-age-31", "xrpl-skew-4", "xrpl-skew-5"))


# --- RN-NET-03B2-C6-LIVE: a run directory of the C6 entry point ---------------------------------

AUTH_FIELDS = ["authorizationId", "evidenceDir", "format", "manifestSha256", "notAfter", "providers", "publication", "requestBudget", "scope"]
AUTH_DOMAIN = b"rnnet:compat-authorization:v1\x00"
RUN_FILES = {"authorization.json", "transcript.json", "evidence.json", "report.json"}
CALL_FIELDS = {"call", "providerId", "requestSha256", "status", "responseFile", "responseSha256", "responseBytes", "error", "policy"}
UTC = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")


def stored(value):
    return canon(value) + "\n"


def read_authorization(text):
    """Parses and checks an rnnet.compat-authorization.v1 text; returns (authorization, digest)."""
    body = text[:-1] if text.endswith("\n") else text
    a = json.loads(body)
    assert canon(a) == body, "authorization is not canonical"
    assert isinstance(a, dict) and sorted(a) == AUTH_FIELDS, "authorization fields"
    assert a["format"] == "rnnet.compat-authorization.v1"
    assert re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", a["authorizationId"])
    assert a["publication"] == "none"
    assert UTC.fullmatch(a["notAfter"])
    digest = "sha256:" + hashlib.sha256(AUTH_DOMAIN + body.encode("utf-8")).hexdigest()
    return a, digest


def overall(verdict, violation):
    if "BLOCKED" in (verdict["xrpl"], verdict["sepolia"]):
        return "BLOCKED"
    return "PASS" if verdict == {"xrpl": "PASS", "sepolia": "PASS"} and violation is None else "UNRESOLVED"


def run_checks(run_dir: Path, private: bool):
    """Checks one run directory from its files alone: the authorization's binding, every request
    rebuilt byte for byte, every response's digest, and the evidence and report recomputed here."""
    names = {p.name for p in run_dir.iterdir()}
    raw = lambda name: (run_dir / name).read_bytes()  # noqa: E731
    yield "the run directory holds the four run files", RUN_FILES <= names
    if not RUN_FILES <= names:
        return
    if private:
        yield "the run directory is private (0700) and every file in it is 0600", (run_dir.stat().st_mode & 0o777) == 0o700 and all(((run_dir / n).stat().st_mode & 0o777) == 0o600 for n in names)
    auth_text = raw("authorization.json").decode("utf-8")
    a, digest = read_authorization(auth_text)
    yield "the authorization binds the reviewed manifest digest", a["manifestSha256"] == "sha256:" + MANIFEST_SHA256
    yield "the authorization names the four reviewed providers at their URLs with their budget, in manifest order", a["providers"] == [{"id": p, "requests": BUDGET[p], "url": u} for p, _, u in PROVIDERS]
    yield "the authorization budget is exactly 22 requests", a["requestBudget"] == 22 == sum(BUDGET.values())
    transcript_text = raw("transcript.json").decode("utf-8")
    transcript = json.loads(transcript_text)
    yield "the transcript is canonical", stored(transcript) == transcript_text and transcript["format"] == "rnnet.provider-compat-transcript.v1" and set(transcript) == {"format", "calls"}
    calls = transcript["calls"]
    yield "the transcript calls are numbered in order, with exactly the recorded fields", [c["call"] for c in calls] == list(range(1, len(calls) + 1)) and all(set(c) == CALL_FIELDS for c in calls)
    files = {c["responseFile"] for c in calls if c["responseFile"] is not None}
    yield "the run directory holds exactly the run files and the recorded responses", names - {"python-reference.txt"} == RUN_FILES | files
    replayable, bodies_ok = [], True
    for c in calls:
        if c["policy"] is not None or c["error"] is not None:
            replayable.append({"providerId": c["providerId"], "error": c["error"]})
            bodies_ok = bodies_ok and c["responseFile"] is None and c["status"] is None
            continue
        body = raw(c["responseFile"])
        bodies_ok = bodies_ok and c["responseFile"] == f"response-{c['call']:02d}.bin" and sha(body) == c["responseSha256"] and len(body) == c["responseBytes"] <= MAX_BYTES
        replayable.append({"providerId": c["providerId"], "status": c["status"], "body": body})
    yield "every stored response matches its recorded digest and size, within 256 KiB", bodies_ok
    exchanges, count, sent, problems = replay(replayable)
    sent_requests = [e for e in exchanges if e["request"] is not None]
    yield "the transcript replays in manifest order with no unused call", not problems
    yield "every request the run sent is the one rebuilt here, byte for byte", [c["requestSha256"] for c in calls] == [e["requestSha256"] for e in sent_requests]
    yield "at most 22 requests, within each provider's budget, no write method", count == len(calls) <= 22 and all(sent[p] <= BUDGET[p] for p in BUDGET) and all(json.loads(e["request"])["method"] not in WRITE for e in sent_requests)
    evidence_text = raw("evidence.json").decode("utf-8")
    ev = json.loads(evidence_text)
    yield "the evidence is canonical", stored(ev) == evidence_text
    checks, verdict, br, candidate, finality = classify(ev["observedAt"], exchanges)
    yield "the evidence is what this reference computes (the free-text details aside)", (
        set(ev) == {"format", "observedAt", "requestCount", "sentPerProvider", "exchanges", "checks", "verdict", "sepoliaBranches", "compatibilityCandidate", "finality", "authorizationId", "authorizationDigest", "manifestSha256"}
        and ev["format"] == "rnnet.provider-compat-evidence.v1" and ev["exchanges"] == exchanges and ev["requestCount"] == count and ev["sentPerProvider"] == sent
        and [(c["id"], c["status"]) for c in ev["checks"]] == checks and ev["verdict"] == verdict and ev["sepoliaBranches"] == br
        and ev["compatibilityCandidate"] == candidate and ev["finality"] == finality
        and (ev["authorizationId"], ev["authorizationDigest"], ev["manifestSha256"]) == (a["authorizationId"], digest, a["manifestSha256"]))
    violation = next((c["policy"] for c in calls if c["policy"] is not None), None)
    if violation is None:
        # A response that could not be stored stops the run (C6-LIVE review F1).
        violation = next((f"response storage failed at call {c['call']}" for c in calls if c["error"] == "RNCL_STORAGE"), None)
    report = {
        "format": "rnnet.provider-compat-report.v1", "authorizationId": a["authorizationId"], "authorizationDigest": digest,
        "authorizationFileSha256": sha(auth_text.encode("utf-8")), "manifestSha256": a["manifestSha256"],
        "providers": a["providers"], "requestBudget": a["requestBudget"], "publication": a["publication"],
        "observedAt": ev["observedAt"], "requestCount": count, "sentPerProvider": sent,
        "forwardedRequests": sum(1 for c in calls if c["policy"] is None), "policyViolation": violation,
        "transcriptSha256": sha(transcript_text.encode("utf-8")), "evidenceSha256": sha(evidence_text.encode("utf-8")),
        "responses": [{"call": c["call"], "file": c["responseFile"], "bytes": c["responseBytes"], "sha256": c["responseSha256"]} for c in calls if c["responseFile"] is not None],
        "checks": [{"id": c, "status": s} for c, s in checks], "verdict": verdict, "sepoliaBranches": br,
        "compatibilityCandidate": candidate, "finality": finality, "overall": overall(verdict, violation),
    }
    report_text = raw("report.json").decode("utf-8")
    yield f"report.json is rebuilt byte for byte here: {report['overall']} (XRPL {verdict['xrpl']}, Sepolia {verdict['sepolia']} {'+'.join(br)}), {sha(report_text.encode('utf-8'))}", stored(report) == report_text


def run_main(run_dir: Path, record: bool) -> int:
    results = []
    try:
        results = list(run_checks(run_dir, private=True))
    except (AssertionError, KeyError, TypeError, ValueError, OSError) as error:
        results.append((f"the run directory could not be checked: {type(error).__name__}", False))
    failed = [name for name, ok in results if not ok]
    lines = [("ok   " if ok else "FAIL ") + name for name, ok in results]
    lines.append(f"compat run reference: {len(results) - len(failed)}/{len(results)} checks agree; {'AGREES' if not failed and results else 'DOES NOT AGREE'}")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if record:
        # Written once, privately and durably, beside the run's own files.
        fd = os.open(run_dir / "python-reference.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    return 1 if failed or not results else 0


def fixture_run_checks(root: Path):
    base = root / "fixtures/compat-c6-live"
    dirs = sorted(p for p in base.iterdir() if p.is_dir())
    overalls = set()
    for d in dirs:
        for name, ok in run_checks(d, private=False):
            if name.startswith("report.json is rebuilt"):
                overalls.add(name.split(": ", 1)[1].split(" ", 1)[0])
            yield f"compat-c6-live/{d.name}: {name}", ok
    yield "the C6-LIVE run fixtures cover PASS, BLOCKED and UNRESOLVED", overalls >= {"PASS", "BLOCKED", "UNRESOLVED"}


def main(root: Path) -> int:
    results = list(checks_of(root)) + list(fixture_run_checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"compat reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--run" and sys.argv[3:] in ([], ["--record"]):
        sys.exit(run_main(Path(sys.argv[2]), sys.argv[3:] == ["--record"]))
    if len(sys.argv) != 1:
        sys.exit("usage: rnnet_compat_reference.py [--run <run directory> [--record]]")
    sys.exit(main(HERE.parent.parent))
