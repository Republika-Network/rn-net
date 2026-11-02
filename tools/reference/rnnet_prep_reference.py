#!/usr/bin/env python3
"""Independent reproduction of read-only transaction preparation (ADR-RN-018; RN-NET-03B2-B2, and
RN-NET-03B2-C3 for ADR-RN-016 Amendment C1 (+ 80) and ADR-RN-018 Amendment C1 (Sepolia two-pass,
block-hash pinning, and the "blocked" mark on a pinned-read JSON-RPC error).

Re-implements, without the JavaScript packages:
  - the exact read-only request bytes of each preparation step (spec/rnnet.tx-preparation.v1.md §3),
    compared with every recorded request, so both sides agree on the request list;
  - strict parsing of the recorded responses (duplicate keys refused; numbers that are not safe
    integers kept as their text, never as floats) and the response-envelope rules;
  - the shape checks, the freshness, consistency, fee, nonce, sequence and balance rules, their
    precedence and their error codes (§4);
  - binding of the Genesis templates and the rnnet.tx-preparation.v1 record (§5).
The resulting intent is checked and digested with rnnet_tx_reference.py, loaded by path.

Checks every case of fixtures/preparation-b2/cases.json from its recorded exchanges alone.
Offline; standard library only. Run: python3 -I -B <this file>
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tx_ref = load("rnnet_tx_reference")
anchor_ref = tx_ref.anchor_ref
SAFE = 2**53 - 1
GWEI = 10**9
MAX_RESPONSE_BYTES = 262_144
U32 = 0xFFFFFFFF

COMMITMENT = re.compile(r"sha256:[0-9a-f]{64}")
XRPL_ACCOUNT = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
XRPL_KEY = re.compile(r"ED[0-9A-F]{64}")
LEDGER_HASH = re.compile(r"[0-9A-F]{64}")
DROPS = re.compile(r"(?:0|[1-9][0-9]{0,17})")
EVM_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
EVM_HASH = re.compile(r"0x[0-9a-f]{64}")
QUANTITY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)")
HEX_DATA = re.compile(r"0x(?:[0-9a-f]{2})*")
DECIMAL = re.compile(r"(0|[1-9][0-9]{0,29})(?:\.([0-9]{1,30}))?(?:[eE]([+-]?[0-9]{1,2}))?")
RPC_ERROR_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")

SYNCED = ("full", "proposing", "validating")
XRPL_FEE = 12
# ADR-RN-016 Amendment C1 (RN-NET-03B2-C3): LastLedgerSequence = lowest validated ledger + 80.
XRPL_LAST_LEDGER_OFFSET = 80
SEPOLIA_GAS_LIMIT = 30_000
TIP = 1 * GWEI
FEE_CAP = 20 * GWEI


class Raw:
    """A JSON number with no safe-integer value, kept as its exact text."""

    def __init__(self, text):
        self.text = text


class Refusal(Exception):
    def __init__(self, code, provider=None, blocked=None):
        super().__init__(code)
        self.code = code
        self.provider = provider
        self.blocked = blocked


class Mismatch(Exception):
    """The recorded exchanges do not fit this reproduction: a disagreement, never a refusal."""


class ReadFail(Exception):
    """A read failure, with the RNLO code the JavaScript reader would raise."""

    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_u32(v):
    return is_int(v) and 0 <= v <= U32


def no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def depth_ok(value, depth=1):
    if depth > 64:
        return False
    if isinstance(value, dict):
        return all(depth_ok(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return all(depth_ok(v, depth + 1) for v in value)
    return True


def parse_strict(body: bytes):
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ReadFail("RNLO_INVALID_JSON")
    if text.startswith(chr(0xFEFF)):
        raise ReadFail("RNLO_INVALID_JSON")

    def integer(t):
        # As the JavaScript parser: -0 and anything outside the safe range stay as text. Long
        # literals are never converted (Python limits int() to 4300 digits).
        if t == "-0" or len(t.lstrip("-")) > 16:
            return Raw(t)
        n = int(t)
        return n if -SAFE <= n <= SAFE else Raw(t)

    def constant(_):
        raise ValueError("constant")

    try:
        value = json.loads(text, object_pairs_hook=no_duplicates, parse_float=Raw, parse_int=integer, parse_constant=constant)
    except (ValueError, RecursionError):
        raise ReadFail("RNLO_INVALID_JSON")
    if not depth_ok(value):
        raise ReadFail("RNLO_INVALID_JSON")
    return value


def request_bytes(network, method, params) -> bytes:
    body = {"method": method, "params": [params]} if network == "xrpl:testnet" else {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    return tx_ref.canon(body)


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


class Provider:
    """Answers one provider's requests from its recorded exchanges, in order."""

    def __init__(self, network, entry, exchanges):
        self.network = network
        self.id = entry["id"]
        self.operator = entry["operator"]
        self.queue = [e for e in exchanges if e["providerId"] == self.id]
        self.digests = []

    def call(self, method, params):
        self.last_method = method
        self.last_params_pinned = isinstance(params, list) and any(isinstance(x, dict) and "blockHash" in x for x in params)
        body = request_bytes(self.network, method, params)
        if not self.queue:
            raise Mismatch(f"{self.id}: no recorded exchange for {method}")
        e = self.queue.pop(0)
        if e["request"].encode("utf-8") != body:
            raise Mismatch(f"{self.id}: request for {method} differs")
        entry = {"method": method, "requestSha256": sha(body)}
        self.digests.append(entry)
        if "error" in e:
            raise ReadFail(e["error"])
        resp = e["response"]["body"].encode("utf-8")
        entry["responseSha256"] = sha(resp)
        if len(resp) > MAX_RESPONSE_BYTES:
            raise ReadFail("RNLO_RESPONSE_TOO_LARGE")
        status = e["response"]["status"]
        if status != 200:
            raise ReadFail("RNLO_HTTP_STATUS")
        envelope = parse_strict(resp)
        return self.interpret(envelope)

    def interpret(self, envelope):
        if not isinstance(envelope, dict):
            raise ReadFail("RNLO_INVALID_RESPONSE")
        if self.network == "xrpl:testnet":
            result = envelope.get("result")
            if not isinstance(result, dict):
                raise ReadFail("RNLO_INVALID_RESPONSE")
            if result.get("status") == "error":
                if result.get("error") == "txnNotFound":
                    raise ReadFail("RNLO_NOT_FOUND")
                err = result.get("error")
                raise ReadFail("RNLO_RPC_ERROR", err if isinstance(err, str) and RPC_ERROR_NAME.fullmatch(err) else "")
            if result.get("status") != "success":
                raise ReadFail("RNLO_INVALID_RESPONSE")
            return result
        if envelope.get("jsonrpc") != "2.0" or not is_int(envelope.get("id")) or envelope.get("id") != 1:
            raise ReadFail("RNLO_INVALID_RESPONSE")
        if "error" in envelope:
            raise ReadFail("RNLO_RPC_ERROR")
        if "result" not in envelope:
            raise ReadFail("RNLO_INVALID_RESPONSE")
        return envelope["result"]


def refusal_of(fail: ReadFail, provider_id):
    if fail.code in ("RNLO_WRONG_NETWORK", "RNLO_NETWORK_UNKNOWN"):
        return Refusal("RNTP_WRONG_NETWORK", provider_id)
    if fail.code in ("RNLO_INVALID_JSON", "RNLO_INVALID_RESPONSE"):
        return Refusal("RNTP_MALFORMED", provider_id)
    if fail.code == "RNLO_NOT_FOUND":
        return Refusal("RNTP_PROVIDER_ERROR", provider_id)
    if fail.code == "RNLO_RPC_ERROR":
        return Refusal("RNTP_ACCOUNT_NOT_FOUND" if fail.detail == "actNotFound" else "RNTP_PROVIDER_ERROR", provider_id)
    return Refusal("RNTP_PROVIDER_UNAVAILABLE", provider_id)


# --- exact decimals --------------------------------------------------------------------------------

def decimal(value):
    """(num, den) of a non-negative safe integer or a Raw number's text; None otherwise."""
    if is_int(value) and 0 <= value <= SAFE:
        text = str(value)
    elif isinstance(value, Raw):
        text = value.text
    else:
        return None
    m = DECIMAL.fullmatch(text)
    if not m:
        return None
    whole, frac, exp = m.group(1), m.group(2) or "", int(m.group(3) or "0")
    e = exp - len(frac)
    digits = int(whole + frac)
    return (digits * 10**e, 1) if e >= 0 else (digits, 10**-e)


def drops(value):
    d = decimal(value)
    if d is None:
        return None
    num, den = d
    if (num * 1_000_000) % den:
        return None
    v = num * 1_000_000 // den
    return v if v <= 10**17 else None


# --- readers ---------------------------------------------------------------------------------------

def bad():
    return ReadFail("RNLO_INVALID_RESPONSE")


def read_xrpl(p: Provider, account):
    server = p.call("server_info", {"api_version": 2})
    info = server.get("info")
    if not isinstance(info, dict):
        raise bad()
    if "network_id" not in info:
        raise ReadFail("RNLO_NETWORK_UNKNOWN")
    if not (is_int(info["network_id"]) and -SAFE <= info["network_id"] <= SAFE):
        raise bad()
    if info["network_id"] != 1:
        raise ReadFail("RNLO_WRONG_NETWORK")
    if not isinstance(info.get("server_state"), str):
        raise bad()
    vl = info.get("validated_ledger")
    if not isinstance(vl, dict):
        raise bad()
    if not is_u32(vl.get("seq")) or vl["seq"] == 0:
        raise bad()
    if not isinstance(vl.get("hash"), str) or not LEDGER_HASH.fullmatch(vl["hash"]):
        raise bad()
    if not (is_int(vl.get("age")) and 0 <= vl["age"] <= SAFE):
        raise bad()
    base, rbase, rinc = drops(vl.get("base_fee_xrp")), drops(vl.get("reserve_base_xrp")), drops(vl.get("reserve_inc_xrp"))
    if base is None or base == 0 or rbase is None or rinc is None:
        raise bad()
    load_factor = decimal(info.get("load_factor"))
    if load_factor is None or load_factor[0] < load_factor[1]:
        raise bad()

    r = p.call("account_info", {"account": account, "ledger_index": "validated", "signer_lists": True, "api_version": 2})
    if not isinstance(r.get("validated"), bool):
        raise bad()
    if not is_u32(r.get("ledger_index")) or r["ledger_index"] == 0:
        raise bad()
    if not isinstance(r.get("ledger_hash"), str) or not LEDGER_HASH.fullmatch(r["ledger_hash"]):
        raise bad()
    d = r.get("account_data")
    if not isinstance(d, dict):
        raise bad()
    if not isinstance(d.get("Account"), str) or not XRPL_ACCOUNT.fullmatch(d["Account"]):
        raise bad()
    if not isinstance(d.get("Balance"), str) or not DROPS.fullmatch(d["Balance"]):
        raise bad()
    if not is_u32(d.get("Sequence")) or d["Sequence"] == 0:
        raise bad()
    if not is_u32(d.get("OwnerCount")) or not is_u32(d.get("Flags")):
        raise bad()
    if "RegularKey" in d and (not isinstance(d["RegularKey"], str) or not XRPL_ACCOUNT.fullmatch(d["RegularKey"])):
        raise bad()
    if not isinstance(r.get("signer_lists"), list):
        raise bad()
    return {
        "state": info["server_state"], "seq": vl["seq"], "hash": vl["hash"], "age": vl["age"],
        "base": base, "rbase": rbase, "rinc": rinc, "load": load_factor,
        "a_index": r["ledger_index"], "a_hash": r["ledger_hash"], "a_validated": r["validated"],
        "account": d["Account"], "balance": int(d["Balance"]), "sequence": d["Sequence"], "owners": d["OwnerCount"],
        "flags": d["Flags"], "regular_key": "RegularKey" in d, "signers": len(r["signer_lists"]),
    }


def quantity(v):
    if not isinstance(v, str) or not QUANTITY.fullmatch(v):
        raise bad()
    return v


def block_of(block):
    if not isinstance(block, dict):
        raise bad()
    number = quantity(block.get("number"))
    if not isinstance(block.get("hash"), str) or not EVM_HASH.fullmatch(block["hash"]):
        raise bad()
    return {"number": number, "hash": block["hash"], "timestamp": quantity(block.get("timestamp")), "baseFeePerGas": quantity(block.get("baseFeePerGas"))}


def read_sepolia_head(p: Provider):
    if quantity(p.call("eth_chainId", [])) != "0xaa36a7":
        raise ReadFail("RNLO_WRONG_NETWORK")
    return block_of(p.call("eth_getBlockByNumber", ["latest", False]))


def read_sepolia_pin(p: Provider, number):
    return block_of(p.call("eth_getBlockByNumber", [number, False]))


def read_sepolia_pinned(p: Provider, sender, data, block_hash):
    at = {"blockHash": block_hash, "requireCanonical": True}
    latest = quantity(p.call("eth_getTransactionCount", [sender, at]))
    pending = quantity(p.call("eth_getTransactionCount", [sender, "pending"]))
    if int(latest, 16) >= 2**64 or int(pending, 16) >= 2**64:
        raise bad()
    balance = quantity(p.call("eth_getBalance", [sender, at]))
    code = p.call("eth_getCode", [sender, at])
    if not isinstance(code, str) or not HEX_DATA.fullmatch(code):
        raise bad()
    estimate = quantity(p.call("eth_estimateGas", [{"from": sender, "to": sender, "value": "0x0", "data": data}, at]))
    return {"latest": latest, "pending": pending, "balance": balance, "code": code, "estimate": estimate}


# --- preparation -----------------------------------------------------------------------------------

def check_input(case):
    inp, net = case["input"], case["network"]
    if not isinstance(inp.get("commitment"), str) or not COMMITMENT.fullmatch(inp["commitment"]):
        raise Refusal("RNTP_INPUT_INVALID")
    now = inp.get("now")
    if not (is_int(now) and 0 < now <= SAFE):
        raise Refusal("RNTP_INPUT_INVALID")
    providers = inp.get("providers")
    if not isinstance(providers, list) or not 2 <= len(providers) <= 4:
        raise Refusal("RNTP_INPUT_INVALID")
    ids, urls, operators = set(), set(), set()
    for p in providers:
        if not isinstance(p, dict) or not all(isinstance(p.get(k), str) for k in ("id", "url", "operator")):
            raise Refusal("RNTP_INPUT_INVALID")
        if p.get("network") != net or p["id"] in ids or p["url"] in urls or p["operator"] in operators:
            raise Refusal("RNTP_INPUT_INVALID")
        ids.add(p["id"])
        urls.add(p["url"])
        operators.add(p["operator"])
    if net == "xrpl:testnet":
        key, account = inp.get("signingPubKey"), inp.get("account")
        if not isinstance(key, str) or not XRPL_KEY.fullmatch(key):
            raise Refusal("RNTP_INPUT_INVALID")
        if not isinstance(account, str) or not XRPL_ACCOUNT.fullmatch(account) or tx_ref.address_from_public_key(bytes.fromhex(key)) != account:
            raise Refusal("RNTP_INPUT_INVALID")
    elif not isinstance(inp.get("from"), str) or not EVM_ADDRESS.fullmatch(inp["from"]):
        raise Refusal("RNTP_INPUT_INVALID")


def preparation(now, providers):
    return {"format": "rnnet.tx-preparation.v1", "source": "rpc-read", "rules": "ADR-RN-018", "observedAt": now, "providers": providers}


def prepare_xrpl(case, providers):
    inp = case["input"]
    readings = []
    for p in providers:
        try:
            o = read_xrpl(p, inp["account"])
        except ReadFail as fail:
            raise refusal_of(fail, p.id)
        checks = [
            ("RNTP_NOT_SYNCED", o["state"] not in SYNCED),
            ("RNTP_STALE", o["age"] > 30),
            ("RNTP_INCONSISTENT", o["a_validated"] is not True),
            ("RNTP_INCONSISTENT", not 0 <= o["a_index"] - o["seq"] <= 2),
            ("RNTP_INCONSISTENT", o["a_index"] == o["seq"] and o["a_hash"] != o["hash"]),
            ("RNTP_INCONSISTENT", o["account"] != inp["account"]),
            ("RNTP_ACCOUNT_UNSUITABLE", o["regular_key"]),
            ("RNTP_ACCOUNT_UNSUITABLE", o["flags"] & 0x00100000 != 0),
            ("RNTP_ACCOUNT_UNSUITABLE", o["signers"] != 0),
            ("RNTP_FEE_TOO_HIGH", o["base"] * o["load"][0] > XRPL_FEE * o["load"][1]),
            ("RNTP_INSUFFICIENT_BALANCE", o["balance"] < o["rbase"] + o["owners"] * o["rinc"] + XRPL_FEE),
        ]
        for code, failed in checks:
            if failed:
                raise Refusal(code, p.id)
        readings.append((p, o))
    seqs = [o["seq"] for _, o in readings]
    ledgers = [(o["seq"], o["hash"]) for _, o in readings] + [(o["a_index"], o["a_hash"]) for _, o in readings]
    if max(seqs) - min(seqs) > 4 or len(dict(ledgers)) != len(set(ledgers)) or len({o["sequence"] for _, o in readings}) != 1:
        raise Refusal("RNTP_INCONSISTENT")
    payload = anchor_ref.encode_payload(inp["commitment"]).hex().upper()
    tx = {
        "TransactionType": "AccountSet", "Account": inp["account"], "Fee": str(XRPL_FEE), "Sequence": readings[0][1]["sequence"],
        "LastLedgerSequence": min(seqs) + XRPL_LAST_LEDGER_OFFSET, "Memos": [{"Memo": {"MemoType": b"rnnet.anchor-payload.v1".hex().upper(), "MemoData": payload}}],
        "SigningPubKey": inp["signingPubKey"],
    }
    record = preparation(inp["now"], [{"id": p.id, "operator": p.operator, "validatedLedger": {"index": o["seq"], "hash": o["hash"]},
                                      "accountLedger": {"index": o["a_index"], "hash": o["a_hash"]}, "exchanges": p.digests} for p, o in readings])
    return tx, record


def prepare_sepolia(case, providers):
    """ADR-RN-018 Amendment C1: head pass, pin P = lowest head - 2 agreed by hash, pinned pass."""
    inp = case["input"]
    now = inp["now"]
    payload = anchor_ref.encode_payload(inp["commitment"])
    data = "0x" + payload.hex()
    zeros = payload.count(0)
    tokens = zeros + 4 * (len(payload) - zeros)
    intrinsic = max(21000 + 4 * tokens, 21000 + 10 * tokens)

    def read(p, fn, *args, pinned=False):
        try:
            return fn(p, *args)
        except ReadFail as fail:
            r = refusal_of(fail, p.id)
            # Only a read that carried the block-hash object: not the pending nonce.
            if pinned and fail.code == "RNLO_RPC_ERROR" and p.last_params_pinned:
                r.blocked = "GAS_ESTIMATION_UNAVAILABLE" if p.last_method == "eth_estimateGas" else "BLOCK_HASH_READ_REFUSED"
            raise r

    def fresh(block, max_age, pid):
        ts = int(block["timestamp"], 16)
        for code, failed in [("RNTP_STALE", now - ts > max_age), ("RNTP_STALE", ts - now >= 15), ("RNTP_FEE_TOO_HIGH", int(block["baseFeePerGas"], 16) > 19 * GWEI)]:
            if failed:
                raise Refusal(code, pid)

    heads = []
    for p in providers:
        head = read(p, read_sepolia_head)
        fresh(head, 60, p.id)
        heads.append(head)
    heights = [int(b["number"], 16) for b in heads]
    if max(heights) - min(heights) > 4 or len({b["number"] for b in heads}) != len({(b["number"], b["hash"]) for b in heads}):
        raise Refusal("RNTP_INCONSISTENT")
    pin_number = min(heights) - 2
    if pin_number < 0:
        raise Refusal("RNTP_INCONSISTENT")
    pins = []
    for p, head in zip(providers, heads):
        pin = read(p, read_sepolia_pin, hex(pin_number))
        if pin["number"] != hex(pin_number) or pin["hash"] == head["hash"] or int(pin["timestamp"], 16) > int(head["timestamp"], 16):
            raise Refusal("RNTP_INCONSISTENT", p.id)
        fresh(pin, 90, p.id)
        pins.append(pin)
    if len({b["hash"] for b in pins}) != 1 or len({(b["timestamp"], b["baseFeePerGas"]) for b in pins}) != 1:
        raise Refusal("RNTP_INCONSISTENT")
    pin = pins[0]
    readings = []
    for p in providers:
        o = read(p, read_sepolia_pinned, inp["from"], data, pin["hash"], pinned=True)
        est = int(o["estimate"], 16)
        for code, failed in [("RNTP_NONCE_PENDING", o["pending"] != o["latest"]), ("RNTP_ACCOUNT_UNSUITABLE", o["code"] != "0x"),
                             ("RNTP_GAS_TOO_HIGH", est > SEPOLIA_GAS_LIMIT), ("RNTP_INCONSISTENT", est < intrinsic)]:
            if failed:
                raise Refusal(code, p.id)
        readings.append((p, o))
    if len({o["latest"] for _, o in readings}) != 1:
        raise Refusal("RNTP_INCONSISTENT")
    max_fee = min(2 * int(pin["baseFeePerGas"], 16) + TIP, FEE_CAP)
    for p, o in readings:
        if int(o["balance"], 16) < SEPOLIA_GAS_LIMIT * max_fee:
            raise Refusal("RNTP_INSUFFICIENT_BALANCE", p.id)
    tx = {
        "type": "0x2", "chainId": "0xaa36a7", "nonce": readings[0][1]["latest"], "from": inp["from"], "to": inp["from"], "value": "0x0",
        "input": data, "gas": hex(SEPOLIA_GAS_LIMIT), "maxFeePerGas": hex(max_fee), "maxPriorityFeePerGas": hex(TIP), "accessList": [],
    }
    record = preparation(now, [{"id": p.id, "operator": p.operator, "block": dict(pin), "estimateGas": o["estimate"], "exchanges": p.digests}
                               for p, o in readings])
    return tx, record


def reproduce(case):
    """(outcome, code, provider id, blocked, digest, intent, unused exchange count)."""
    providers = []
    try:
        check_input(case)
        providers = [Provider(case["network"], e, case["exchanges"]) for e in case["input"]["providers"]]
        prepare = prepare_xrpl if case["network"] == "xrpl:testnet" else prepare_sepolia
        tx, record = prepare(case, providers)
    except Refusal as r:
        return "FAIL", r.code, r.provider, r.blocked, None, None, sum(len(p.queue) for p in providers)
    intent = {"format": "rnnet.unsigned-tx-intent.v1", "network": case["network"], "purpose": "genesis-proof-01",
              "commitment": case["input"]["commitment"], "transaction": tx, "preparation": record}
    if not tx_ref.intent_ok(intent):
        return "FAIL", "RNTP_INTENT_INVALID", None, None, None, None, 0
    return "PASS", None, None, None, tx_ref.intent_digest(intent), intent, sum(len(p.queue) for p in providers)


def checks(root: Path):
    raw = (root / "fixtures/preparation-b2/cases.json").read_bytes()
    doc = json.loads(raw)
    yield "fixtures file is canonical", raw == tx_ref.canon(doc) + b"\n"
    yield "fixtures format", doc["format"] == "rnnet.preparation-b2-fixtures.v2" and doc["status"].startswith("SYNTHETIC")
    cases = doc["cases"]
    yield "corpus size", len(cases) >= 60 and sum(c["expected"]["outcome"] == "PASS" for c in cases) >= 8
    yield "case ids unique", len({c["id"] for c in cases}) == len(cases)
    yield "no real host in the corpus", all(p["url"].endswith(".fixture.invalid/") for c in cases for p in c["input"]["providers"])
    for case in cases:
        exp = case["expected"]
        try:
            outcome, code, provider, blocked, digest, intent, unused = reproduce(case)
        except Mismatch as m:
            yield f"{case['id']}: {m}", False
            continue
        same = (outcome, code, provider, blocked, digest) == (exp["outcome"], exp["code"], exp["providerId"], exp["blocked"], exp["digest"])
        if outcome == "PASS":
            same = same and tx_ref.canon(intent) == tx_ref.canon(exp["intent"])
        yield f"{case['id']} -> {code or 'PASS'}", same and unused == 0
    sep = [c for c in cases if c["network"] == "evm:11155111" and c["exchanges"]]
    yield "every Sepolia account read is pinned to a block hash", all(
        json.loads(e["request"])["params"][1] == "pending" or isinstance(json.loads(e["request"])["params"][1], dict)
        for c in sep for e in c["exchanges"] if json.loads(e["request"])["method"] in ("eth_getTransactionCount", "eth_getBalance", "eth_getCode", "eth_estimateGas"))
    yield "no Sepolia read uses an unpinned state tag other than the head and the pending nonce", all(
        json.loads(e["request"])["params"] in (["latest", False],) or json.loads(e["request"])["method"] != "eth_getBlockByNumber" or QUANTITY.fullmatch(str(json.loads(e["request"])["params"][0]))
        for c in sep for e in c["exchanges"])
    yield "both blocked reasons are covered", {c["expected"]["blocked"] for c in cases} >= {"BLOCK_HASH_READ_REFUSED", "GAS_ESTIMATION_UNAVAILABLE"}


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"prep reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
