#!/usr/bin/env python3
"""Independent reproduction of the RN-NET-03B2-B3 keyless broadcaster (ADR-RN-019).

Re-implements, without the JavaScript packages, every decision of a broadcaster run over the
committed fixtures (fixtures/broadcast-b3/cases.json):
  - the input check, the rnnet.broadcast-authorization.v1 shape and digest, and its exact match
    with the verified intent and blob, and its validity (XRPL ledger margin, Sepolia time);
  - the verification: the rnnet.signed-tx-verification.v1 record of the signed bytes, computed by
    rnnet_tx_reference.py (original Keccak-256, secp256k1 recovery and RFC 8032 Ed25519), compared
    with the second verifier's record and any supplied records;
  - the submission-log rules (rnnet.submission-log-entry.v1): consistency, consumed
    authorizations, unresolved attempts, attempt numbers, links, permitted cases, inclusion;
  - the pre-submit reads, replayed from the recorded exchanges with the strict JSON rules;
  - the exact write request bytes, the classification of the write's answer, and the
    rnnet.submission-record.v1 record, its digest and the appended log entries;
  - for status checks: the status authorization, the absence reads (ledger-ranged tx with
    searched_all, account_info past LastLedgerSequence; the Sepolia nonce), the finding, the
    rnnet.submission-status.v1 record and the RESOLVED entry.

For a status check, the RN-NET-03B1 live-observation report (each provider's reads, the RN-NET-03A
adapter record, agreement and finality) is recomputed from the recorded exchanges, and its digest
is compared (B3 review N3); every exchange must be used.
Out of scope, stated: the JavaScript broadcaster's own re-checks after both verifiers agree (the
hand-off's recomputation and txverify's own signature and hash check) are not modelled here as
separate steps. The verification they repeat is rnnet_tx_reference.py's own record (signature
recovery, hashes, decoding, every field), which this file recomputes for every case.

It also confirms that each case's second-verifier record is what rnnet_tx_reference.py itself
produces (unless the case deliberately tampers with it). Offline; standard library only.
Run: python3 -I -B <this file>
"""
import datetime
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


tx = load("rnnet_tx_reference")
prep = load("rnnet_prep_reference")
canon = tx.canon

MAX_RESPONSE = 262_144
MAX_BLOB = 4096
TRANSPORT_CODES = {"RNLO_TIMEOUT", "RNLO_CONNECTION", "RNLO_RESPONSE_TOO_LARGE", "RNLO_REDIRECT", "RNLO_BLOCKED_ADDRESS"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
AUTH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}")
PROVIDER_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SCOPE = re.compile(r"[\x20-\x7e]{1,1000}")
SEQUENCE = re.compile(r"(?:0|[1-9][0-9]{0,19})")
XRPL_ACCOUNT = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
EVM_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
XRPL_HASH = re.compile(r"[0-9A-F]{64}")
EVM_HASH = re.compile(r"0x[0-9a-f]{64}")
EVM_HASH_ANY = re.compile(r"0x[0-9a-fA-F]{64}")
QUANTITY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)")
UTC = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z")
ENGINE = re.compile(r"(tes|tec|tel|tem|tef|ter)[A-Z][A-Za-z0-9_]{0,63}")
RANGES = {"tes": (0, 0), "tec": (100, 255), "tel": (-399, -300), "tem": (-299, -200), "tef": (-199, -100), "ter": (-99, -1)}
FLAGS = ["accepted", "applied", "broadcast", "kept", "queued"]
AUTH_FIELDS = sorted(["attempt", "authorizationId", "blobSha256", "dryRun", "format", "intentDigest", "kind", "network", "previousAttempt",
                      "providerId", "scope", "sender", "sequence", "transactionHash", "validity"])
STATUS_AUTH_FIELDS = sorted(["attemptEntry", "authorizationId", "format", "network", "providerIds", "scope", "sender", "sequence", "transactionHash"])
INPUTS = {"approvedDigest", "authorization", "intent", "signedTransaction", "verificationRecords"}
REQUIRED = {"approvedDigest", "authorization", "intent", "signedTransaction"}
COMMON = ["authorizationDigest", "format", "index", "kind", "network", "sender", "sequence"]
ENTRY_FIELDS = {
    "RUN_STARTED": sorted(COMMON + ["mode"]),
    "ATTEMPTING": sorted(COMMON + ["attempt", "blobSha256", "intentDigest", "observedLedger", "providerId", "transactionHash"]),
    "RESULT": sorted(COMMON + ["attemptEntry", "code", "outcome", "record"]),
    "RESOLVED": sorted(COMMON + ["attemptEntry", "finding", "record"]),
}
RESOLVED = {"xrpl:testnet": ["INCLUDED", "EXPIRED"], "evm:11155111": ["INCLUDED", "PENDING"]}
OUTCOMES = {"NOT_SENT", "ACCEPTED_PROVISIONAL", "REJECTED", "UNCERTAIN"}


class Refuse(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Mismatch(Exception):
    """The recorded exchanges do not fit this reproduction."""


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def tagged(domain: str, value) -> str:
    return sha(domain.encode("utf-8") + canon(value))


def entry_digest(e):
    return tagged("rnnet:submission-log-entry:v1\x00", e)


def iso(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_seconds(text):
    m = UTC.fullmatch(text) if isinstance(text, str) else None
    if not m:
        return None
    try:
        d = datetime.datetime(*map(int, m.groups()), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return int(d.timestamp())


def parse_canonical(text):
    """The value of canonical JSON text (optionally followed by one newline), or None."""
    if not isinstance(text, str):
        return None
    body = text[:-1] if text.endswith("\n") else text

    def no_dup(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate")
            out[k] = v
        return out

    def constant(_):
        raise ValueError("constant")

    try:
        value = json.loads(body, object_pairs_hook=no_dup, parse_constant=constant)
        if not tx.canon_values_ok(value) or canon(value) != body.encode("utf-8"):
            return None
    except (ValueError, RecursionError, tx.ref.RefError, UnicodeEncodeError):
        return None
    return value


# --- authorizations --------------------------------------------------------------------------------

def sender_and_hash_ok(network, sender, h):
    if network == "xrpl:testnet":
        return isinstance(sender, str) and XRPL_ACCOUNT.fullmatch(sender) and isinstance(h, str) and XRPL_HASH.fullmatch(h)
    return isinstance(sender, str) and EVM_ADDRESS.fullmatch(sender) and isinstance(h, str) and EVM_HASH.fullmatch(h)


def read_authorization(text):
    a = parse_canonical(text)
    bad = Refuse("RNBC_AUTHORIZATION_INVALID")
    if not isinstance(a, dict) or sorted(a) != AUTH_FIELDS or a["format"] != "rnnet.broadcast-authorization.v1":
        raise bad
    ok = (
        isinstance(a["authorizationId"], str) and AUTH_ID.fullmatch(a["authorizationId"])
        and a["network"] in ("xrpl:testnet", "evm:11155111")
        and isinstance(a["providerId"], str) and PROVIDER_ID.fullmatch(a["providerId"])
        and is_int(a["attempt"]) and 1 <= a["attempt"] <= 64
        and a["kind"] in ("first", "resend", "replacement")
        and (a["attempt"] == 1) == (a["kind"] == "first")
        and (a["previousAttempt"] is None if a["attempt"] == 1 else isinstance(a["previousAttempt"], str) and DIGEST.fullmatch(a["previousAttempt"]))
        and all(isinstance(a[f], str) and DIGEST.fullmatch(a[f]) for f in ("intentDigest", "blobSha256"))
    )
    if not ok or not sender_and_hash_ok(a["network"], a["sender"], a["transactionHash"]):
        raise bad
    if not (isinstance(a["sequence"], str) and SEQUENCE.fullmatch(a["sequence"])):
        raise bad
    v = a["validity"]
    if a["network"] == "xrpl:testnet":
        if not (isinstance(v, dict) and sorted(v) == ["lastLedgerSequence"] and is_int(v["lastLedgerSequence"]) and 1 <= v["lastLedgerSequence"] <= 0xFFFFFFFF):
            raise bad
    elif not (isinstance(v, dict) and sorted(v) == ["notAfter"] and utc_seconds(v["notAfter"]) is not None):
        raise bad
    if not isinstance(a["dryRun"], bool) or not (isinstance(a["scope"], str) and SCOPE.fullmatch(a["scope"])):
        raise bad
    return a, tagged("rnnet:broadcast-authorization:v1\x00", a)


def read_status_authorization(text):
    a = parse_canonical(text)
    bad = Refuse("RNBC_AUTHORIZATION_INVALID")
    if not isinstance(a, dict) or sorted(a) != STATUS_AUTH_FIELDS or a["format"] != "rnnet.status-authorization.v1":
        raise bad
    ids = a["providerIds"]
    ok = (
        isinstance(a["authorizationId"], str) and AUTH_ID.fullmatch(a["authorizationId"])
        and a["network"] in ("xrpl:testnet", "evm:11155111")
        and isinstance(ids, list) and len(ids) == 2 and all(isinstance(i, str) and PROVIDER_ID.fullmatch(i) for i in ids) and ids[0] != ids[1]
        and isinstance(a["attemptEntry"], str) and DIGEST.fullmatch(a["attemptEntry"])
        and sender_and_hash_ok(a["network"], a["sender"], a["transactionHash"])
        and isinstance(a["sequence"], str) and SEQUENCE.fullmatch(a["sequence"])
        and isinstance(a["scope"], str) and SCOPE.fullmatch(a["scope"])
    )
    if not ok:
        raise bad
    return a, tagged("rnnet:status-authorization:v1\x00", a)


# --- the log ---------------------------------------------------------------------------------------

def key(e):
    return (e["network"], e["sender"], e["sequence"])


def check_log(entries):
    runs, attempts, attempted = {}, {}, set()
    for i, e in enumerate(entries):
        fail = Refuse("RNBC_LOG_INVALID")
        if not isinstance(e, dict) or e.get("format") != "rnnet.submission-log-entry.v1" or e.get("index") != i or e.get("kind") not in ENTRY_FIELDS or sorted(e) != ENTRY_FIELDS[e["kind"]]:
            raise fail
        if e["network"] not in RESOLVED or not isinstance(e["sender"], str) or not isinstance(e["sequence"], str):
            raise fail
        if not isinstance(e["authorizationDigest"], str) or not DIGEST.fullmatch(e["authorizationDigest"]):
            raise fail
        run = runs.get(e["authorizationDigest"])
        k = e["kind"]
        if k == "RUN_STARTED":
            if e["mode"] not in ("submit", "status") or run:
                raise fail
            runs[e["authorizationDigest"]] = e
        elif k == "ATTEMPTING":
            if not run or run["mode"] != "submit" or key(run) != key(e) or e["authorizationDigest"] in attempted or not is_int(e["attempt"]) or e["attempt"] < 1:
                raise fail
            attempted.add(e["authorizationDigest"])
            attempts[entry_digest(e)] = {"entry": e, "result": None}
        elif k == "RESULT":
            a = attempts.get(e["attemptEntry"])
            if not a or a["result"] or a["entry"]["authorizationDigest"] != e["authorizationDigest"] or key(a["entry"]) != key(e):
                raise fail
            if e["outcome"] not in OUTCOMES or not isinstance(e["code"], str) or not isinstance(e["record"], str) or not DIGEST.fullmatch(e["record"]):
                raise fail
            a["result"] = e
        else:
            a = attempts.get(e["attemptEntry"])
            if not run or run["mode"] != "status" or key(run) != key(e) or not a or key(a["entry"]) != key(e):
                raise fail
            if e["finding"] not in RESOLVED[e["network"]] or not isinstance(e["record"], str) or not DIGEST.fullmatch(e["record"]):
                raise fail


def decide_attempt(log, a):
    check_log(log)
    k = key(a)
    mine = [e for e in log if e["kind"] != "RUN_STARTED" and key(e) == k]
    if any(e["kind"] == "RESOLVED" and e["finding"] == "INCLUDED" for e in mine):
        raise Refuse("RNBC_LOG_ALREADY_INCLUDED")
    attempts = [e for e in mine if e["kind"] == "ATTEMPTING"]
    for att in attempts:
        d = entry_digest(att)
        if not any(e["index"] > att["index"] and e.get("attemptEntry") == d and e["kind"] in ("RESULT", "RESOLVED") for e in mine):
            raise Refuse("RNBC_LOG_UNRESOLVED_ATTEMPT")
    if a["attempt"] != len(attempts) + 1:
        raise Refuse("RNBC_LOG_ATTEMPT_NUMBER")
    if not attempts:
        return
    outcomes = [e for e in mine if e["kind"] in ("RESULT", "RESOLVED")]
    latest = outcomes[-1] if outcomes else None
    if latest is None or a["previousAttempt"] != entry_digest(latest):
        raise Refuse("RNBC_LOG_LINK_MISMATCH")
    last = attempts[-1]
    resolves_last = latest["kind"] == "RESOLVED" and latest["attemptEntry"] == entry_digest(last)
    if a["kind"] == "resend":
        same = a["intentDigest"] == last["intentDigest"] and a["blobSha256"] == last["blobSha256"]
        after_result = latest["kind"] == "RESULT" and latest["outcome"] in ("REJECTED", "NOT_SENT")
        if same and (after_result or (resolves_last and latest["finding"] == "PENDING")):
            return
        raise Refuse("RNBC_LOG_CASE_NOT_PERMITTED")
    if a["kind"] == "replacement":
        wanted = "EXPIRED" if a["network"] == "xrpl:testnet" else "PENDING"
        if not any(e["blobSha256"] == a["blobSha256"] for e in attempts) and resolves_last and latest["finding"] == wanted:
            return
    raise Refuse("RNBC_LOG_CASE_NOT_PERMITTED")


def entry(index, kind, **fields):
    e = {"format": "rnnet.submission-log-entry.v1", "index": index, "kind": kind, **fields}
    assert sorted(e) == ENTRY_FIELDS[kind], kind
    return e


# --- replayed reads --------------------------------------------------------------------------------

class Network:
    """Answers requests from the recorded exchanges in their global order, as the JS replay does."""

    def __init__(self, network, exchanges):
        self.network = network
        self.queue = list(exchanges)
        self.requests = 0

    def next(self, provider_id, body: bytes):
        if not self.queue:
            raise Mismatch("no recorded exchange")
        e = self.queue.pop(0)
        if e["providerId"] != provider_id or e["request"].encode("utf-8") != body:
            raise Mismatch(f"request differs: {body[:60]!r}")
        self.requests += 1
        return e

    def call(self, provider_id, method, params):
        e = self.next(provider_id, prep.request_bytes(self.network, method, params))
        if "error" in e:
            raise prep.ReadFail(e["error"] if e["error"] in TRANSPORT_CODES else "RNLO_CONNECTION")
        body = e["response"]["body"].encode("utf-8")
        status = e["response"]["status"]
        if len(body) > MAX_RESPONSE:
            raise prep.ReadFail("RNLO_RESPONSE_TOO_LARGE")
        if status == 429:
            raise prep.ReadFail("RNLO_RATE_LIMITED")
        if status != 200:
            raise prep.ReadFail("RNLO_HTTP_STATUS")
        envelope = prep.parse_strict(body)
        return interpret(self.network, envelope)


def interpret(network, envelope):
    if not isinstance(envelope, dict):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    if network == "xrpl:testnet":
        r = envelope.get("result")
        if not isinstance(r, dict):
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        if r.get("status") == "error":
            if r.get("error") == "txnNotFound":
                raise prep.ReadFail("RNLO_NOT_FOUND", "searched_all" if r.get("searched_all") is True else "")
            raise prep.ReadFail("RNLO_RPC_ERROR")
        if r.get("status") != "success":
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        return r
    if envelope.get("jsonrpc") != "2.0" or not is_int(envelope.get("id")) or envelope.get("id") != 1:
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    if "error" in envelope:
        raise prep.ReadFail("RNLO_RPC_ERROR")
    if "result" not in envelope:
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    return envelope["result"]


def u32(v):
    return is_int(v) and 0 < v <= 0xFFFFFFFF


def quantity(v):
    if not isinstance(v, str) or not QUANTITY.fullmatch(v):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    return int(v, 16)


def presubmit(net, providers, a, verified):
    observed = None
    t = verified["transaction"]
    for p in providers:
        if p["network"] == "xrpl:testnet":
            info = net.call(p["id"], "server_info", {"api_version": 2})
            i = info.get("info")
            if not isinstance(i, dict):
                raise prep.ReadFail("RNLO_INVALID_RESPONSE")
            if "network_id" not in i:
                raise prep.ReadFail("RNLO_NETWORK_UNKNOWN")
            if not (is_int(i["network_id"]) and i["network_id"] == 1):
                raise prep.ReadFail("RNLO_WRONG_NETWORK")
            vl = i.get("validated_ledger")
            v = vl.get("seq") if isinstance(vl, dict) else None
            if not u32(v):
                raise prep.ReadFail("RNLO_INVALID_RESPONSE")
            acc = net.call(p["id"], "account_info", {"account": verified["sender"], "ledger_index": "validated", "api_version": 2})
            d = acc.get("account_data")
            if not u32(acc.get("ledger_index")) or not isinstance(d, dict) or not u32(d.get("Sequence")):
                raise prep.ReadFail("RNLO_INVALID_RESPONSE")
            if acc.get("validated") is not True or d.get("Account") != verified["sender"]:
                raise Refuse("RNBC_PRESUBMIT_ACCOUNT")
            if str(d["Sequence"]) != verified["sequence"]:
                raise Refuse("RNBC_PRESUBMIT_SEQUENCE")
            ledger = max(v, acc["ledger_index"])
            if ledger >= a["validity"]["lastLedgerSequence"] - 4:
                raise Refuse("RNBC_AUTHORIZATION_EXPIRED")
            observed = max(observed or 0, ledger)
            try:
                net.call(p["id"], "tx", {"transaction": verified["transactionHash"], "binary": False, "api_version": 2})
            except prep.ReadFail as f:
                if f.code == "RNLO_NOT_FOUND":
                    continue
                raise
            raise Refuse("RNBC_PRESUBMIT_ALREADY_KNOWN")
        c = net.call(p["id"], "eth_chainId", [])
        if not isinstance(c, str) or not QUANTITY.fullmatch(c):
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        if c != "0xaa36a7":
            raise prep.ReadFail("RNLO_WRONG_NETWORK")
        block = net.call(p["id"], "eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, dict):
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        if quantity(block.get("baseFeePerGas")) > int(t["maxFeePerGas"], 16) - int(t["maxPriorityFeePerGas"], 16):
            raise Refuse("RNBC_PRESUBMIT_BASE_FEE")
        for tag in ("latest", "pending"):
            if quantity(net.call(p["id"], "eth_getTransactionCount", [t["from"], tag])) != int(t["nonce"], 16):
                raise Refuse("RNBC_PRESUBMIT_NONCE")
        if net.call(p["id"], "eth_getTransactionByHash", [verified["transactionHash"]]) is not None:
            raise Refuse("RNBC_PRESUBMIT_ALREADY_KNOWN")
        if quantity(net.call(p["id"], "eth_getBalance", [t["from"], "latest"])) < int(t["gas"], 16) * int(t["maxFeePerGas"], 16):
            raise Refuse("RNBC_PRESUBMIT_BALANCE")
    return observed


# --- the write -------------------------------------------------------------------------------------

def submit_request(network, signed) -> bytes:
    if network == "xrpl:testnet":
        ok = re.fullmatch(r"(?:[0-9A-F]{2})+", signed) and len(signed) // 2 <= MAX_BLOB
        body = {"method": "submit", "params": [{"tx_blob": signed, "fail_hard": True}]}
    else:
        ok = re.fullmatch(r"0x(?:[0-9a-f]{2})+", signed) and (len(signed) - 2) // 2 <= MAX_BLOB
        body = {"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [signed]}
    assert ok
    return canon(body)


def classify(network, response, signed, expected_hash):
    c = {"httpStatus": None, "transportError": None, "returnedTransactionHash": None, "xrpl": None, "sepolia": None}

    def done(outcome, code):
        return {**c, "outcome": outcome, "code": code}

    if "transportError" in response:
        c["transportError"] = response["transportError"]
        return done("NOT_SENT", "RNBC_NOT_SENT_BLOCKED_ADDRESS") if c["transportError"] == "RNLO_BLOCKED_ADDRESS" else done("UNCERTAIN", "RNBC_UNCERTAIN_TRANSPORT")
    c["httpStatus"] = response["status"]
    if response["status"] != 200:
        return done("UNCERTAIN", "RNBC_UNCERTAIN_HTTP_STATUS")
    if response.get("invalidJson"):
        return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
    env = response["envelope"]
    if network == "xrpl:testnet":
        r = env.get("result") if isinstance(env, dict) else None
        if not isinstance(r, dict):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
        if r.get("status") == "error":
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RPC_ERROR")
        if r.get("status") != "success":
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
        eng, code = r.get("engine_result"), r.get("engine_result_code")
        if not isinstance(eng, str) or not ENGINE.fullmatch(eng) or not (is_int(code) and abs(code) <= 2**53 - 1):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
        lo, hi = RANGES[eng[:3]]
        if not lo <= code <= hi or (eng == "tesSUCCESS") != (code == 0):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
        flags = {f: (r[f] if isinstance(r.get(f), bool) else None) for f in FLAGS}
        c["xrpl"] = {"engineResult": eng, "engineResultCode": code, **flags}
        tj = r.get("tx_json")
        if not isinstance(r.get("tx_blob"), str) or not isinstance(tj, dict) or not isinstance(tj.get("hash"), str) or not XRPL_HASH.fullmatch(tj["hash"]):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
        c["returnedTransactionHash"] = tj["hash"]
        if r["tx_blob"] != signed:
            return done("UNCERTAIN", "RNBC_UNCERTAIN_BLOB_MISMATCH")
        if tj["hash"] != expected_hash:
            return done("UNCERTAIN", "RNBC_UNCERTAIN_HASH_MISMATCH")
        if any(flags[f] is None for f in FLAGS):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_FLAGS")
        if eng == "tesSUCCESS":
            good = flags["accepted"] and flags["broadcast"] and not flags["queued"]
            return done("ACCEPTED_PROVISIONAL", "RNBC_ACCEPTED") if good else done("UNCERTAIN", "RNBC_UNCERTAIN_FLAGS")
        if eng[:3] in ("tes", "tec") or eng in ("tefALREADY", "tefPAST_SEQ", "tefNO_TICKET", "terQUEUED"):
            return done("UNCERTAIN", "RNBC_UNCERTAIN_ENGINE_RESULT")
        silent = not any(flags[f] for f in FLAGS)
        return done("REJECTED", "RNBC_REJECTED") if silent else done("UNCERTAIN", "RNBC_UNCERTAIN_FLAGS")
    if not isinstance(env, dict) or env.get("jsonrpc") != "2.0" or not (is_int(env.get("id")) and env["id"] == 1):
        return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
    if ("error" in env) == ("result" in env):
        return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
    if "error" in env:
        e = env["error"]
        code = e["code"] if isinstance(e, dict) and is_int(e.get("code")) and abs(e["code"]) <= 2**53 - 1 else None
        msg = sha(e["message"].encode("utf-8")) if isinstance(e, dict) and isinstance(e.get("message"), str) else None
        c["sepolia"] = {"errorCode": code, "errorMessageSha256": msg}
        return done("UNCERTAIN", "RNBC_UNCERTAIN_RPC_ERROR")
    res = env["result"]
    if not isinstance(res, str) or not EVM_HASH_ANY.fullmatch(res):
        return done("UNCERTAIN", "RNBC_UNCERTAIN_RESPONSE")
    c["returnedTransactionHash"] = res
    if res != expected_hash:
        return done("UNCERTAIN", "RNBC_UNCERTAIN_HASH_MISMATCH")
    return done("ACCEPTED_PROVISIONAL", "RNBC_ACCEPTED")


def write(net, provider_id, network, signed, expected_hash):
    body = submit_request(network, signed)
    e = net.next(provider_id, body)
    req = sha(body)
    if "error" in e:
        code = e["error"] if e["error"] in TRANSPORT_CODES else "RNLO_CONNECTION"
        return req, None, classify(network, {"transportError": code}, signed, expected_hash)
    raw = e["response"]["body"].encode("utf-8")
    resp = sha(raw)
    if len(raw) > MAX_RESPONSE:
        return req, resp, classify(network, {"transportError": "RNLO_RESPONSE_TOO_LARGE"}, signed, expected_hash)
    try:
        env = prep.parse_strict(raw)
        r = {"status": e["response"]["status"], "envelope": env}
    except prep.ReadFail:
        r = {"status": e["response"]["status"], "invalidJson": True}
    return req, resp, classify(network, r, signed, expected_hash)


# --- one submit run --------------------------------------------------------------------------------

def run_submit(case, endpoints):
    inputs = case["inputs"]
    step = case["clockStepPerRequest"]
    st = {"auth": None, "digest": None, "verified": None, "log": list(case["logBefore"]), "attempt": None}
    net = None

    def now():
        # The clock advances by a fixed step per request sent (the fixture's model).
        return case["now"] + step * (net.requests if net else 0)

    def finish(outcome, code, cls=None, req=None, resp=None):
        a, v = st["auth"], st["verified"]
        cls = cls or {}
        record = {
            "format": "rnnet.submission-record.v1",
            "authorizationDigest": st["digest"],
            "network": a["network"] if a else None,
            "providerId": a["providerId"] if a else None,
            "intentDigest": v["intentDigest"] if v else (a["intentDigest"] if a else None),
            "blobSha256": v["blobSha256"] if v else (a["blobSha256"] if a else None),
            "expectedTransactionHash": v["transactionHash"] if v else (a["transactionHash"] if a else None),
            "returnedTransactionHash": cls.get("returnedTransactionHash"),
            "requestSha256": req,
            "responseSha256": resp,
            "httpStatus": cls.get("httpStatus"),
            "transportError": cls.get("transportError"),
            "outcome": outcome,
            "code": code,
            "xrpl": cls.get("xrpl"),
            "sepolia": cls.get("sepolia"),
            "dryRun": bool(a and a["dryRun"]),
            "recordedAt": iso(now()),
        }
        digest = tagged("rnnet:submission-record:v1\x00", record)
        if st["attempt"]:
            st["log"].append(entry(len(st["log"]), "RESULT", authorizationDigest=st["digest"], network=a["network"], sender=a["sender"], sequence=a["sequence"],
                                   attemptEntry=st["attempt"], outcome=outcome, code=code, record=digest))
        return {"outcome": outcome, "code": code, "record": record, "recordDigest": digest, "requests": net.requests if net else 0,
                "writes": 1 if req is not None or (cls and cls.get("transportError")) else 0, "appended": st["log"][len(case["logBefore"]):]}

    try:
        keys = set(inputs)
        if not keys <= INPUTS or not REQUIRED <= keys or case["environmentExtra"] is not None:
            raise Refuse("RNBC_INPUT_INVALID")
        supplied = inputs.get("verificationRecords", [])
        if not isinstance(supplied, list) or len(supplied) > 2 or not isinstance(inputs["intent"], str):
            raise Refuse("RNBC_INPUT_INVALID")
        a, digest = read_authorization(inputs["authorization"])
        check_log(st["log"])
        if any(e["kind"] == "RUN_STARTED" and e["authorizationDigest"] == digest for e in st["log"]):
            raise Refuse("RNBC_AUTHORIZATION_USED")
        st["log"].append(entry(len(st["log"]), "RUN_STARTED", authorizationDigest=digest, network=a["network"], sender=a["sender"], sequence=a["sequence"], mode="submit"))
        st["auth"], st["digest"] = a, digest
        providers = [p for p in endpoints["providers"] if p["network"] == a["network"]]
        if len(providers) != 2 or not any(p["id"] == a["providerId"] for p in providers):
            raise Refuse("RNBC_PROVIDER_NOT_ALLOWED")
        # Verification: the intent text must be canonical; then both verifiers' records agree.
        intent = parse_canonical(inputs["intent"]) if not inputs["intent"].endswith("\n") else None
        if intent is None:
            raise Refuse("RNTX_INTENT_INVALID")
        own = tx.verify(intent, inputs["approvedDigest"], inputs["signedTransaction"])
        if canon(own) != canon(case["referenceRecord"]):
            raise Refuse("RNBC_VERIFIER_DISAGREEMENT")
        if own["outcome"] != "PASS":
            raise Refuse(own["code"])
        for rec in supplied:
            if canon(rec) != canon(own):
                raise Refuse("RNBC_SUPPLIED_RECORD_MISMATCH")
        t = intent["transaction"]
        xrpl = intent["network"] == "xrpl:testnet"
        verified = {
            "network": intent["network"], "sender": t["Account"] if xrpl else t["from"], "sequence": str(t["Sequence"] if xrpl else int(t["nonce"], 16)),
            "intentDigest": inputs["approvedDigest"], "blobSha256": own["blobSha256"], "transactionHash": own["transactionHash"], "transaction": t,
        }
        st["verified"] = verified
        for f in ("network", "sender", "sequence", "intentDigest", "blobSha256", "transactionHash"):
            if a[f] != verified[f]:
                raise Refuse("RNBC_AUTHORIZATION_MISMATCH")
        if xrpl and a["validity"]["lastLedgerSequence"] != t["LastLedgerSequence"]:
            raise Refuse("RNBC_AUTHORIZATION_MISMATCH")
        if not xrpl and now() > utc_seconds(a["validity"]["notAfter"]):
            raise Refuse("RNBC_AUTHORIZATION_EXPIRED")
        decide_attempt(st["log"], a)
        net = Network(a["network"], case["exchanges"])
        try:
            observed = presubmit(net, providers, a, verified)
        except prep.ReadFail as f:
            raise Refuse(f.code)
        if a["dryRun"]:
            raise Refuse("RNBC_DRY_RUN")
        if not xrpl and now() > utc_seconds(a["validity"]["notAfter"]):
            raise Refuse("RNBC_AUTHORIZATION_EXPIRED")
        decide_attempt(st["log"], a)
        att = entry(len(st["log"]), "ATTEMPTING", authorizationDigest=digest, network=a["network"], sender=a["sender"], sequence=a["sequence"], attempt=a["attempt"],
                    providerId=a["providerId"], intentDigest=verified["intentDigest"], blobSha256=verified["blobSha256"], transactionHash=verified["transactionHash"],
                    observedLedger=observed)
        st["log"].append(att)
        st["attempt"] = entry_digest(att)
        req, resp, cls = write(net, a["providerId"], a["network"], inputs["signedTransaction"], verified["transactionHash"])
        result = finish(cls["outcome"], cls["code"], cls, req, resp)
        result["writes"] = 1
        result["unused"] = len(net.queue)
        return result
    except Refuse as r:
        result = finish("NOT_SENT", r.code)
        result["unused"] = len(net.queue) if net else len(case["exchanges"])
        return result


# --- one status run --------------------------------------------------------------------------------

def decide_finding(network, live, absence):
    final = "PROVIDER_REPORTED_VALIDATED" if network == "xrpl:testnet" else "PROVIDER_REPORTED_FINALIZED"
    if live["outcome"] == "PASS" and live["agreement"] == "AGREEMENT" and final in live["statuses"] and all(o == "OBSERVED" for o in live["outcomes"]):
        return "INCLUDED"
    unseen = len(live["outcomes"]) == 2 and all(o == "NOT_FOUND" for o in live["outcomes"])
    if unseen and len(absence) == 2 and all(absence):
        return "EXPIRED" if network == "xrpl:testnet" else "PENDING"
    return "UNRESOLVED"


def absence_of(net, pid, intent, attempt):
    t = intent["transaction"]
    try:
        if intent["network"] == "xrpl:testnet":
            info = net.call(pid, "server_info", {"api_version": 2})
            i = info.get("info") if isinstance(info.get("info"), dict) else {}
            if i.get("network_id") != 1:
                return False
            vl = i.get("validated_ledger") if isinstance(i.get("validated_ledger"), dict) else {}
            v = vl.get("seq")
            if not (is_int(v) and 0 < v <= 0xFFFFFFFF) or v <= t["LastLedgerSequence"]:
                return False
            frm = attempt["observedLedger"]
            if not (is_int(frm) and 0 < frm <= 0xFFFFFFFF) or frm > v or v - frm > 1000:
                return False
            try:
                net.call(pid, "tx", {"transaction": attempt["transactionHash"], "binary": False, "min_ledger": frm, "max_ledger": v, "api_version": 2})
                return False
            except prep.ReadFail as f:
                if f.code != "RNLO_NOT_FOUND" or f.detail != "searched_all":
                    return False
            acc = net.call(pid, "account_info", {"account": t["Account"], "ledger_index": v, "api_version": 2})
            d = acc.get("account_data") if isinstance(acc.get("account_data"), dict) else {}
            return acc.get("validated") is True and acc.get("ledger_index") == v and d.get("Account") == t["Account"] and d.get("Sequence") == t["Sequence"]
        return net.call(pid, "eth_getTransactionCount", [t["from"], "latest"]) == t["nonce"]
    except prep.ReadFail:
        return False


def skip_not_found_reads(net, network, pid, h):
    """The live report's two reads for a transaction the provider does not have."""
    if network == "xrpl:testnet":
        info = net.call(pid, "server_info", {"api_version": 2})
        if (info.get("info") or {}).get("network_id") != 1:
            raise Mismatch("server_info")
        try:
            net.call(pid, "tx", {"transaction": h, "binary": False, "api_version": 2})
        except prep.ReadFail as f:
            if f.code == "RNLO_NOT_FOUND":
                return
        raise Mismatch("tx was found")
    if net.call(pid, "eth_chainId", []) != "0xaa36a7" or net.call(pid, "eth_getTransactionByHash", [h]) is not None:
        raise Mismatch("transaction was found")


# --- the live-observation report of a status check (B3 review N3) ---------------------------------
# Recomputed from the recorded exchanges, as packages/chain-readonly does it (readers.mjs and
# live.mjs; spec/rnnet.live-observation-report.v1.md): each provider's reads, the RN-NET-03A
# adapter's record (rnnet_anchor_reference.py), agreement, and the report's exact bytes. Nothing of
# the report is taken from the fixture's expected record any more.

anchor = load("rnnet_anchor_reference")
RETRYABLE = {"RNLO_TIMEOUT", "RNLO_CONNECTION", "RNLO_RATE_LIMITED", "RNLO_HTTP_STATUS_RETRYABLE"}
LIVE_MAX_ATTEMPTS = 2
ANCESTRY_LIMIT = 256
OUTCOME_OF_ERROR = {
    "RNLO_NOT_FOUND": "NOT_FOUND", "RNLO_WRONG_NETWORK": "WRONG_NETWORK", "RNLO_NETWORK_UNKNOWN": "WRONG_NETWORK",
    "RNLO_HASH_MISMATCH": "INCONSISTENT", "RNLO_LEDGER_MISMATCH": "INCONSISTENT", "RNLO_BLOCK_MISMATCH": "INCONSISTENT",
    "RNLO_INVALID_JSON": "INVALID_RESPONSE", "RNLO_INVALID_RESPONSE": "INVALID_RESPONSE", "RNLO_RPC_ERROR": "INVALID_RESPONSE",
    "RNLO_UNSUPPORTED_API_VERSION": "INVALID_RESPONSE",
}
LIVE_BASIS = {
    "observed": "As returned by the named RPC providers; not authenticated.",
    "agreement": "The providers returned the same material data. Their operational independence is not established, and agreement is not a consensus proof.",
    "validated": "The provider reports the transaction in a validated ledger, and its ledger read agrees; not authenticated.",
    "finalized": "The provider's finalized block descends, by parent hashes it returned, from the transaction's block; not authenticated.",
    "unresolvedFinality": "Validation or finality could not be established from the providers.",
    "proof": "No authenticated proof of inclusion (validated ledger header and validator signatures, or a consensus light client) was verified.",
}


def live_call(net, pid, method, params):
    """chain-readonly's call() with its default of two attempts for the retryable failures."""
    last = None
    for _ in range(LIVE_MAX_ATTEMPTS):
        e = net.next(pid, prep.request_bytes(net.network, method, params))
        try:
            if "error" in e:
                raise prep.ReadFail(e["error"] if e["error"] in TRANSPORT_CODES else "RNLO_CONNECTION")
            body = e["response"]["body"].encode("utf-8")
            status = e["response"]["status"]
            if len(body) > MAX_RESPONSE:
                raise prep.ReadFail("RNLO_RESPONSE_TOO_LARGE")
            if status == 429:
                raise prep.ReadFail("RNLO_RATE_LIMITED")
            if status in (502, 503, 504):
                raise prep.ReadFail("RNLO_HTTP_STATUS_RETRYABLE")
            if status != 200:
                raise prep.ReadFail("RNLO_HTTP_STATUS")
            return interpret(net.network, prep.parse_strict(body))
        except prep.ReadFail as f:
            last = f
            if f.code not in RETRYABLE:
                raise
    raise prep.ReadFail("RNLO_HTTP_STATUS") if last.code == "RNLO_HTTP_STATUS_RETRYABLE" else last


def observation_bytes(value):
    try:
        return canon(value)
    except Exception:
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")


def obj(v):
    return isinstance(v, dict)


def read_xrpl_live(net, pid, h):
    info = live_call(net, pid, "server_info", {"api_version": 2})
    i = info.get("info") if obj(info) and obj(info.get("info")) else {}
    if "network_id" not in i:
        raise prep.ReadFail("RNLO_NETWORK_UNKNOWN")
    if i["network_id"] != 1:
        raise prep.ReadFail("RNLO_WRONG_NETWORK")
    t = live_call(net, pid, "tx", {"transaction": h, "binary": False, "api_version": 2})
    if not obj(t):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    if not obj(t.get("tx_json")):
        raise prep.ReadFail("RNLO_UNSUPPORTED_API_VERSION")
    if t.get("hash") != h:
        raise prep.ReadFail("RNLO_HASH_MISMATCH")
    if not obj(t.get("meta")):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    confirmed = False
    if t.get("validated") is True:
        if not is_int(t.get("ledger_index")):
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        led = live_call(net, pid, "ledger", {"ledger_index": t["ledger_index"], "transactions": False, "expand": False, "api_version": 2})
        header = led.get("ledger") if obj(led.get("ledger")) else None
        if led.get("validated") is not True:
            raise prep.ReadFail("RNLO_LEDGER_MISMATCH")
        if led.get("ledger_index") != t["ledger_index"] or led.get("ledger_hash") != t.get("ledger_hash"):
            raise prep.ReadFail("RNLO_LEDGER_MISMATCH")
        if header is not None and (("ledger_hash" in header and header["ledger_hash"] != t.get("ledger_hash")) or ("ledger_index" in header and header["ledger_index"] != t["ledger_index"])):
            raise prep.ReadFail("RNLO_LEDGER_MISMATCH")
        confirmed = True
    record = {k: v for k, v in t.items() if k not in ("status", "warnings")}
    observation = {"format": "rnnet.anchor-observation.v1", "network": "xrpl:testnet", "tx": record}
    result = t["meta"].get("TransactionResult")
    material = {"hash": t["hash"], "ledger_index": t.get("ledger_index"), "ledger_hash": t.get("ledger_hash"), "validated": t.get("validated") is True,
                "result": result if isinstance(result, str) else None, "tx_json": t["tx_json"]}
    return observation_bytes(observation), observation_bytes(material), {"validated": confirmed}


def read_evm_live(net, pid, h):
    chain = live_call(net, pid, "eth_chainId", [])
    if not isinstance(chain, str) or not QUANTITY.fullmatch(chain):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    if chain != "0xaa36a7":
        raise prep.ReadFail("RNLO_WRONG_NETWORK")
    t = live_call(net, pid, "eth_getTransactionByHash", [h])
    if t is None:
        raise prep.ReadFail("RNLO_NOT_FOUND")
    if not obj(t):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    if t.get("hash") != h:
        raise prep.ReadFail("RNLO_HASH_MISMATCH")
    r = live_call(net, pid, "eth_getTransactionReceipt", [h])
    if r is not None and not obj(r):
        raise prep.ReadFail("RNLO_INVALID_RESPONSE")
    finality = {"finalized": "UNRESOLVED", "safe": "UNRESOLVED"}
    if t.get("blockHash") is not None:
        if not isinstance(t["blockHash"], str) or not EVM_HASH.fullmatch(t["blockHash"]):
            raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        for f in ("blockNumber", "transactionIndex"):
            if not isinstance(t.get(f), str) or not QUANTITY.fullmatch(t[f]):
                raise prep.ReadFail("RNLO_INVALID_RESPONSE")
        b = live_call(net, pid, "eth_getBlockByHash", [t["blockHash"], False])
        if not obj(b) or b.get("hash") != t["blockHash"] or b.get("number") != t["blockNumber"]:
            raise prep.ReadFail("RNLO_BLOCK_MISMATCH")
        index = int(t["transactionIndex"], 16)
        txs = b.get("transactions")
        if not isinstance(txs, list) or index >= len(txs) or txs[index] != h:
            raise prep.ReadFail("RNLO_BLOCK_MISMATCH")
        finality = {}
        for tag in ("finalized", "safe"):
            if tag == "safe" and finality["finalized"] in ("IN_ANCESTRY", "CONFLICT"):
                finality["safe"] = finality["finalized"]
                continue
            finality[tag] = walk_live(net, pid, tag, b["hash"], int(b["number"], 16))
    observation = {"format": "rnnet.anchor-observation.v1", "network": "evm:11155111", "transaction": dict(t), "receipt": None if r is None else dict(r)}
    material = {"hash": t["hash"], "blockHash": t.get("blockHash"), "blockNumber": t.get("blockNumber"), "transactionIndex": t.get("transactionIndex"),
                "input": t.get("input"), "from": t.get("from"), "to": t.get("to"), "status": None if r is None else r.get("status"), "finality": finality}
    return observation_bytes(observation), observation_bytes(material), {"finality": finality}


def walk_live(net, pid, tag, target_hash, target_height):
    try:
        head = live_call(net, pid, "eth_getBlockByNumber", [tag, False])
    except prep.ReadFail as f:
        if f.code == "RNLO_RPC_ERROR":
            return "UNRESOLVED"
        raise
    if not obj(head) or not isinstance(head.get("number"), str) or not QUANTITY.fullmatch(head["number"]) or not isinstance(head.get("hash"), str) or not EVM_HASH.fullmatch(head["hash"]):
        return "UNRESOLVED"
    current, height = head, int(head["number"], 16)
    if height < target_height:
        return "NOT_REACHED"
    if height - target_height > ANCESTRY_LIMIT:
        return "UNRESOLVED"
    steps = 0
    while height > target_height:
        if steps >= ANCESTRY_LIMIT:
            raise prep.ReadFail("RNLO_BLOCK_MISMATCH")
        parent_hash = current.get("parentHash")
        if not isinstance(parent_hash, str) or not EVM_HASH.fullmatch(parent_hash):
            raise prep.ReadFail("RNLO_BLOCK_MISMATCH")
        parent = live_call(net, pid, "eth_getBlockByHash", [parent_hash, False])
        if not obj(parent) or parent.get("hash") != parent_hash or parent.get("number") != hex(height - 1):
            raise prep.ReadFail("RNLO_BLOCK_MISMATCH")
        current, height, steps = parent, height - 1, steps + 1
    return "IN_ANCESTRY" if current["hash"] == target_hash else "CONFLICT"


def live_report(net, network, h, commitment, providers):
    """The rnnet.live-observation-report.v1 report, as a plain value."""
    entries = []
    for p in providers:
        e = {"id": p["id"], "operator": p["operator"]}
        try:
            data, material, extra = (read_xrpl_live if network == "xrpl:testnet" else read_evm_live)(net, p["id"], h)
            rec = (anchor.verify_xrpl if network == "xrpl:testnet" else anchor.verify_evm)(data, commitment)
            e.update({"outcome": "OBSERVED", "observationSha256": sha(data), "materialSha256": sha(material), "record": rec})
            if network == "xrpl:testnet":
                e["providerValidated"] = extra["validated"]
            else:
                e["finality"] = extra["finality"]
        except prep.ReadFail as f:
            e.update({"outcome": OUTCOME_OF_ERROR.get(f.code, "UNAVAILABLE"), "error": f.code})
        entries.append(e)
    comparable = [e for e in entries if e["outcome"] in ("OBSERVED", "NOT_FOUND")]
    answers = {e["materialSha256"] if e["outcome"] == "OBSERVED" else "NOT_FOUND" for e in comparable}
    if not comparable:
        agreement = "SOURCE_UNAVAILABLE"
    elif len(answers) > 1:
        agreement = "DISAGREEMENT"
    elif len(comparable) == 1:
        agreement = "INSUFFICIENT_SOURCES"
    else:
        agreement = "AGREEMENT"
    findings = []
    for e in entries:
        if e["outcome"] != "OBSERVED":
            findings.append({"code": e["error"], "severity": "unavailable" if e["outcome"] == "UNAVAILABLE" else "error", "subject": f"providers.{e['id']}"})
        elif e["record"]["outcome"] != "PASS":
            findings.append({"code": "RNLO_RECORD_NOT_PASSED", "severity": "error", "subject": f"providers.{e['id']}"})
        fin = e.get("finality")
        if fin and (fin["finalized"] == "CONFLICT" or fin["safe"] == "CONFLICT"):
            findings.append({"code": "RNLO_FINALITY_CONFLICT", "severity": "error", "subject": f"providers.{e['id']}"})
    if agreement == "DISAGREEMENT":
        findings.append({"code": "RNLO_PROVIDER_DISAGREEMENT", "severity": "error", "subject": "providers"})
    observed = [e for e in entries if e["outcome"] == "OBSERVED"]
    hard = any(f["severity"] == "error" and f["code"] != "RNLO_RECORD_NOT_PASSED" for f in findings) or any(e["record"]["outcome"] == "FAIL" for e in observed) or (comparable and not observed)
    if hard:
        outcome = "FAIL"
    elif not observed:
        outcome = "INDETERMINATE"
    elif any(e["record"]["outcome"] == "UNSUPPORTED" for e in observed):
        outcome = "UNSUPPORTED"
    else:
        outcome = "PASS"
    xrpl = network == "xrpl:testnet"
    final = bool(observed) and all((e["providerValidated"] if xrpl else e["finality"]["finalized"] == "IN_ANCESTRY") for e in observed)
    statuses = []
    if observed:
        statuses.append("OBSERVED_FROM_RPC")
    if final:
        statuses.append("PROVIDER_REPORTED_VALIDATED" if xrpl else "PROVIDER_REPORTED_FINALIZED")
    if agreement == "AGREEMENT":
        statuses.append("MULTI_PROVIDER_AGREEMENT")
    if agreement == "DISAGREEMENT":
        statuses.append("DISAGREEMENT")
    if not final:
        statuses.append("UNRESOLVED")
    statements = []
    if observed:
        statements.append({"subject": "providerObservation", "classification": "CLAIMED", "basis": LIVE_BASIS["observed"]})
    if agreement == "AGREEMENT":
        statements.append({"subject": "providerAgreement", "classification": "CLAIMED", "basis": LIVE_BASIS["agreement"]})
    if final:
        statements.append({"subject": "finality", "classification": "CLAIMED", "basis": LIVE_BASIS["validated" if xrpl else "finalized"]})
    else:
        statements.append({"subject": "finality", "classification": "UNRESOLVED", "basis": LIVE_BASIS["unresolvedFinality"]})
    statements.append({"subject": "chainInclusionProof", "classification": "UNRESOLVED", "basis": LIVE_BASIS["proof"]})
    return {"format": "rnnet.live-observation-report.v1", "network": network, "transactionHash": h, "expectedCommitment": commitment,
            "outcome": outcome, "agreement": agreement, "statuses": statuses, "providers": entries, "findings": findings, "statements": statements}


def run_status(case, endpoints):
    inputs, now = case["inputs"], case["now"]
    log = list(case["logBefore"])
    a, digest = read_status_authorization(inputs["authorization"])
    check_log(log)
    if any(e["kind"] == "RUN_STARTED" and e["authorizationDigest"] == digest for e in log):
        return {"code": "RNBC_AUTHORIZATION_USED"}
    log.append(entry(len(log), "RUN_STARTED", authorizationDigest=digest, network=a["network"], sender=a["sender"], sequence=a["sequence"], mode="status"))
    expected = case["expected"]["record"]

    def record(finding, code, live=None, providers=None, live_sha=None):
        rec = {"format": "rnnet.submission-status.v1", "authorizationDigest": digest, "network": a["network"], "attemptEntry": a["attemptEntry"],
               "transactionHash": a["transactionHash"], "finding": finding, "code": code, "liveReportSha256": live_sha, "live": live,
               "providers": providers or [], "recordedAt": iso(now)}
        d = tagged("rnnet:submission-status:v1\x00", rec)
        if finding not in (None, "UNRESOLVED"):
            log.append(entry(len(log), "RESOLVED", authorizationDigest=digest, network=a["network"], sender=a["sender"], sequence=a["sequence"],
                             attemptEntry=a["attemptEntry"], finding=finding, record=d))
        return {"finding": finding, "code": code, "record": rec, "recordDigest": d, "appended": log[len(case["logBefore"]):]}

    attempt = next((e for e in log if e["kind"] == "ATTEMPTING" and entry_digest(e) == a["attemptEntry"]), None)
    if attempt is None or any(attempt[f] != a[f] for f in ("network", "sender", "sequence", "transactionHash")):
        return record(None, "RNBC_STATUS_MISMATCH")
    intent = parse_canonical(inputs["intent"]) if not inputs["intent"].endswith("\n") else None
    if intent is None or not tx.intent_ok(intent) or tx.intent_digest(intent) != attempt["intentDigest"]:
        return record(None, "RNBC_STATUS_MISMATCH")
    configured = {p["id"]: p for p in endpoints["providers"] if p["network"] == a["network"]}
    if any(i not in configured for i in a["providerIds"]):
        return record(None, "RNBC_PROVIDER_NOT_ALLOWED")
    # The live report is recomputed from the exchanges (B3 review N3), then the absence reads; every
    # recorded exchange must be used, in order.
    net = Network(a["network"], case["exchanges"])
    report = live_report(net, a["network"], a["transactionHash"], intent["commitment"], [configured[pid] for pid in a["providerIds"]])
    live = {"outcome": report["outcome"], "agreement": report["agreement"], "statuses": report["statuses"], "outcomes": [p["outcome"] for p in report["providers"]]}
    absence = []
    if all(o == "NOT_FOUND" for o in live["outcomes"]):
        for pid in a["providerIds"]:
            absence.append(absence_of(net, pid, intent, attempt))
    if net.queue:
        raise Mismatch("unused exchanges")
    finding = decide_finding(a["network"], live, absence)
    providers = [{"id": pid, "observation": live["outcomes"][i], "absence": absence[i] if i < len(absence) else None} for i, pid in enumerate(a["providerIds"])]
    return record(finding, "RNBC_STATUS_UNRESOLVED" if finding == "UNRESOLVED" else None, live, providers, sha(canon(report)))


# --- checks ----------------------------------------------------------------------------------------

def checks(root: Path):
    data = json.loads((root / "fixtures/broadcast-b3/cases.json").read_text("utf-8"))
    yield "fixtures format", data["format"] == "rnnet.broadcast-b3-fixtures.v1" and data["status"].startswith("SYNTHETIC")
    yield "providers are synthetic", all(p["url"].endswith(".fixture.invalid/") for p in data["endpoints"]["providers"])
    yield "submit corpus present", len(data["submit"]) >= 150
    codes = set()
    for case in data["submit"]:
        e = case["expected"]
        # The second verifier's record is what the Python reference itself produces.
        if not case["referenceTampered"]:
            ref = json.loads(tx.cli_verify(case["inputs"]["intent"], case["inputs"]["approvedDigest"], case["inputs"]["signedTransaction"]))
            yield f"{case['id']}: second-verifier record reproduced", canon(ref) == canon(case["referenceRecord"])
        try:
            got = run_submit(case, data["endpoints"])
        except Mismatch as m:
            yield f"{case['id']}: exchanges fit ({m})", False
            continue
        codes.add(got["code"])
        yield f"{case['id']} -> {e['outcome']} {e['code']}", (got["outcome"], got["code"]) == (e["outcome"], e["code"])
        yield f"{case['id']}: record and digest", canon(got["record"]) == canon(e["record"]) and got["recordDigest"] == e["recordDigest"]
        yield f"{case['id']}: log entries", canon(got["appended"]) == canon(e["appended"])
        yield f"{case['id']}: requests {e['requests']}, writes {e['writes']}", got["requests"] == e["requests"] and got["writes"] == e["writes"] and got["unused"] == 0
        if e["writes"] == 1:
            a = json.loads(case["inputs"]["authorization"])
            body = submit_request(a["network"], case["inputs"]["signedTransaction"])
            yield f"{case['id']}: exact write request", case["exchanges"][-1]["request"].encode("utf-8") == body and e["record"]["requestSha256"] == sha(body)
    yield "codes covered", len(codes) >= 50
    for case in data["statusChecks"]:
        e = case["expected"]
        try:
            got = run_status(case, data["endpoints"])
        except Mismatch as m:
            yield f"{case['id']}: exchanges fit ({m})", False
            continue
        yield f"{case['id']} -> {e['finding']}", got.get("finding") == e["finding"] and got.get("code") == e["code"]
        yield f"{case['id']}: record, digest and log", canon(got["record"]) == canon(e["record"]) and got["recordDigest"] == e["recordDigest"] and canon(got["appended"]) == canon(e["appended"])
        yield f"{case['id']}: never writes", not any('"method":"submit"' in x["request"] or "eth_sendRawTransaction" in x["request"] for x in case["exchanges"])


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"broadcast reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
