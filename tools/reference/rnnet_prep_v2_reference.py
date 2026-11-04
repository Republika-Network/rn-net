#!/usr/bin/env python3
"""Independent reference for fork-aware Sepolia preparation and rnnet.tx-preparation.v2 (RN-NET-03B2-WP3).

Written from spec/rnnet.tx-preparation.v2.md and ADR-RN-018 Amendment C2, not from the JavaScript.
From fixtures/preparation-v2/cases.json it:
  * replays every preparation from the recorded exchanges alone, through the Python v1 provider
    model (rnnet_prep_reference: request bytes, strict parsing, read failures) and the Python gas
    twin (rnnet_gas_rules_reference), and rebuilds the v2 record, the Stage A candidate
    (rnnet.tx-preparation-v2-candidate.v1) and its candidate-domain digest, or the refusal: code,
    provider, RNTX_GAS_* code, blocked reason, and every exchange used;
  * re-verifies every candidate with its own verifier: envelope, digest domain, version, pin
    agreement, fee binding, and recomputed rule set, fork, review, standard, floor, need and limit;
  * checks that a candidate is never an intent: the S1 Python intent_ok refuses every candidate
    and every v2 preparation placed in an intent;
  * checks that v1 replay is untouched: the B2 fixtures still reproduce under the v1 reference,
    and a v1 record is refused as v2.

The rules reviews are the fixtures' TEST records; there is no operational authority here.
Offline; standard library only; no Node.js. Run: python3 -I -B <this file>
"""
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prep = _load("rnnet_prep_reference")  # v1 provider replay, request bytes, parsing
gas = _load("rnnet_gas_rules_reference")  # the independent gas engine twin
tx_ref = prep.tx_ref

V2 = "rnnet.tx-preparation.v2"
CANDIDATE = "rnnet.tx-preparation-v2-candidate.v1"
CANDIDATE_DOMAIN = b"rnnet:tx-preparation-v2-candidate:v1\x00"
RULES = "ADR-RN-018-C2"
LIMIT = 30000
PLAN = ["eth_chainId", "eth_getBlockByNumber", "eth_getBlockByNumber", "eth_getTransactionCount", "eth_getTransactionCount",
        "eth_getBalance", "eth_getCode", "eth_estimateGas"]


class Refused(Exception):
    def __init__(self, code, provider=None, gas_rules=None, blocked=None):
        super().__init__(code)
        self.code, self.provider, self.gas_rules, self.blocked = code, provider, gas_rules, blocked


def via_gas(fn):
    """A gas-twin refusal as a preparation refusal: the limit is GAS_TOO_HIGH, anything else INCONSISTENT."""
    try:
        return fn()
    except gas.Refusal as r:
        raise Refused("RNTP_GAS_TOO_HIGH" if r.code == gas.LIMIT_CODE else "RNTP_INCONSISTENT", None, r.code)


def candidate_ok(c) -> bool:
    """The Stage A envelope: exact members, Sepolia, the Genesis purpose, a v2 top level, the anchor transaction."""
    if not isinstance(c, dict) or set(c) != {"commitment", "format", "network", "preparation", "purpose", "transaction"}:
        return False
    if c["format"] != CANDIDATE or c["network"] != "evm:11155111" or c["purpose"] != "genesis-proof-01":
        return False
    if not isinstance(c["commitment"], str) or not prep.COMMITMENT.fullmatch(c["commitment"]):
        return False
    p = c["preparation"]
    if not isinstance(p, dict) or set(p) != {"format", "gas", "observedAt", "providers", "rules", "source"} or p["format"] != V2:
        return False
    return tx_ref.sepolia_tx_ok(c["transaction"], c["commitment"]) and int(c["transaction"]["nonce"], 16) < 2**64


def candidate_digest(c) -> str:
    return "sha256:" + prep.hashlib.sha256(CANDIDATE_DOMAIN + tx_ref.canon(c)).hexdigest()


def max_fee(base_fee_hex):
    return min(2 * int(base_fee_hex, 16) + prep.TIP, prep.FEE_CAP)


# --- preparation ------------------------------------------------------------------------------

def prepare_v2(case, providers, review):
    inp = case["input"]
    now, sender = inp["now"], inp["from"]
    via_gas(lambda: gas.review_ok(review, now, now))  # before any request
    payload = prep.anchor_ref.encode_payload(inp["commitment"])
    data = "0x" + payload.hex()

    def read(p, fn, *args, pinned=False):
        try:
            return fn(p, *args)
        except prep.ReadFail as fail:
            r = prep.refusal_of(fail, p.id)
            blocked = None
            if pinned and fail.code == "RNLO_RPC_ERROR" and p.last_params_pinned:
                blocked = "GAS_ESTIMATION_UNAVAILABLE" if p.last_method == "eth_estimateGas" else "BLOCK_HASH_READ_REFUSED"
            raise Refused(r.code, r.provider, None, blocked)

    def fresh(block, max_age, pid):
        ts = int(block["timestamp"], 16)
        if now - ts > max_age or ts - now >= 15:
            raise Refused("RNTP_STALE", pid)
        if int(block["baseFeePerGas"], 16) > 19 * prep.GWEI:
            raise Refused("RNTP_FEE_TOO_HIGH", pid)

    heads = []
    for p in providers:
        b = read(p, prep.read_sepolia_head)
        fresh(b, 60, p.id)
        heads.append(b)
    heights = [int(b["number"], 16) for b in heads]
    if max(heights) - min(heights) > 4 or any(a["number"] == b["number"] and a["hash"] != b["hash"] for a in heads for b in heads):
        raise Refused("RNTP_INCONSISTENT")
    number = min(heights) - 2
    if number < 0:
        raise Refused("RNTP_INCONSISTENT")
    pins = []
    for p, head in zip(providers, heads):
        pin = read(p, prep.read_sepolia_pin, hex(number))
        if pin["number"] != hex(number) or pin["hash"] == head["hash"] or int(pin["timestamp"], 16) > int(head["timestamp"], 16):
            raise Refused("RNTP_INCONSISTENT", p.id)
        fresh(pin, 90, p.id)
        pins.append(pin)
    pin = pins[0]
    if any(b["hash"] != pin["hash"] for b in pins) or any((b["timestamp"], b["baseFeePerGas"]) != (pin["timestamp"], pin["baseFeePerGas"]) for b in pins):
        raise Refused("RNTP_INCONSISTENT")

    seen = []
    for p in providers:
        o = read(p, prep.read_sepolia_pinned, sender, data, pin["hash"], pinned=True)
        if o["pending"] != o["latest"]:
            raise Refused("RNTP_NONCE_PENDING", p.id)
        if o["code"] != "0x":
            raise Refused("RNTP_ACCOUNT_UNSUITABLE", p.id)
        seen.append((p, o))
    if len({o["latest"] for _, o in seen}) != 1:
        raise Refused("RNTP_INCONSISTENT")
    fee = max_fee(pin["baseFeePerGas"])
    tx = {"type": "0x2", "chainId": "0xaa36a7", "nonce": seen[0][1]["latest"], "from": sender, "to": sender, "value": "0x0", "input": data,
          "gas": hex(LIMIT), "maxFeePerGas": hex(fee), "maxPriorityFeePerGas": hex(prep.TIP), "accessList": []}
    g = via_gas(lambda: gas.evaluate({"transaction": tx, "commitment": inp["commitment"], "providerIds": [p.id for p, _ in seen],
                                      "codeEvidence": {p.id: o["code"] for p, o in seen}, "pinTimestamp": int(pin["timestamp"], 16),
                                      "now": now, "review": review}))
    for p, o in seen:
        e = int(o["estimate"], 16)
        if e > LIMIT:
            raise Refused("RNTP_GAS_TOO_HIGH", p.id)
        if e < g["need"]:
            raise Refused("RNTP_INCONSISTENT", p.id)
    for p, o in seen:
        if int(o["balance"], 16) < LIMIT * fee:
            raise Refused("RNTP_INSUFFICIENT_BALANCE", p.id)
    record = {
        "format": V2, "source": "rpc-read", "rules": RULES, "observedAt": now,
        "gas": {"ruleSetId": g["ruleSetId"], "fork": g["fork"], "reviewDigest": g["reviewDigest"], "review": review,
                "standard": g["standard"], "floor": g["floor"], "need": g["need"], "gasLimit": LIMIT},
        "providers": [{"id": p.id, "operator": p.operator, "block": dict(pin), "code": o["code"], "estimateGas": o["estimate"], "exchanges": p.digests}
                      for p, o in seen],
    }
    return tx, record


def check_input_v2(case):
    if sorted(case["input"]) != ["commitment", "from", "now", "providers"]:
        raise Refused("RNTP_INPUT_INVALID")
    try:
        prep.check_input(case)
    except prep.Refusal as r:
        raise Refused(r.code, r.provider)


def reproduce(case):
    providers = []
    try:
        check_input_v2(case)
        providers = [prep.Provider(case["network"], e, case["exchanges"]) for e in case["input"]["providers"]]
        tx, record = prepare_v2(case, providers, case["testRulesReview"])
    except Refused as r:
        used = len(case["exchanges"]) - sum(len(p.queue) for p in providers)
        return {"outcome": "FAIL", "code": r.code, "providerId": r.provider, "gasRules": r.gas_rules, "blocked": r.blocked, "digest": None, "candidate": None}, used
    candidate = {"format": CANDIDATE, "network": "evm:11155111", "purpose": "genesis-proof-01",
                 "commitment": case["input"]["commitment"], "transaction": tx, "preparation": record}
    if not candidate_ok(candidate):
        return {"outcome": "FAIL", "code": "RNTP_INTENT_INVALID", "providerId": None, "gasRules": None, "blocked": None, "digest": None, "candidate": None}, 0
    used = len(case["exchanges"]) - sum(len(p.queue) for p in providers)
    return {"outcome": "PASS", "code": None, "providerId": None, "gasRules": None, "blocked": None, "digest": candidate_digest(candidate), "candidate": candidate}, used


# --- the record verifier ----------------------------------------------------------------------

def is_qty(v):
    return isinstance(v, str) and prep.QUANTITY.fullmatch(v) is not None


def verify(intent, digest, authority):  # `intent` is the candidate under check
    """'PASS' or [code, gasRules]: the spec §6 order."""
    def invalid():
        raise Refused("RNTP_INTENT_INVALID")

    def inconsistent(pid=None, rules=None):
        raise Refused("RNTP_INCONSISTENT", pid, rules)

    try:
        try:
            ok = candidate_ok(intent)
        except (KeyError, TypeError, ValueError):
            ok = False
        if not ok or not isinstance(digest, str) or candidate_digest(intent) != digest:
            invalid()
        p = intent["preparation"]
        if sorted(p) != sorted(["format", "source", "rules", "observedAt", "gas", "providers"]):
            invalid()
        if p["format"] != V2 or p["source"] != "rpc-read" or p["rules"] != RULES:
            invalid()
        if not (gas.is_int(p["observedAt"]) and p["observedAt"] > 0):
            invalid()
        g = p["gas"]
        if not isinstance(g, dict) or sorted(g) != sorted(["ruleSetId", "fork", "reviewDigest", "review", "standard", "floor", "need", "gasLimit"]):
            invalid()
        if not all(gas.is_int(g[k]) and g[k] >= 0 for k in ("standard", "floor", "need", "gasLimit")):
            invalid()
        if not (isinstance(g["ruleSetId"], str) and isinstance(g["fork"], str) and isinstance(g["reviewDigest"], str)
                and prep.COMMITMENT.fullmatch(g["reviewDigest"])):
            invalid()
        entries = p["providers"]
        if not isinstance(entries, list) or not 2 <= len(entries) <= 4:
            invalid()
        ids, ops = set(), set()
        for e in entries:
            if not isinstance(e, dict) or sorted(e) != sorted(["id", "operator", "block", "code", "estimateGas", "exchanges"]):
                invalid()
            if not (isinstance(e["id"], str) and e["id"] and e["id"] not in ids and isinstance(e["operator"], str) and e["operator"] not in ops):
                invalid()
            ids.add(e["id"])
            ops.add(e["operator"])
            b = e["block"]
            if not isinstance(b, dict) or sorted(b) != sorted(["number", "hash", "timestamp", "baseFeePerGas"]) or not prep.EVM_HASH.fullmatch(str(b["hash"])) \
                    or not all(is_qty(b[k]) for k in ("number", "timestamp", "baseFeePerGas")):
                invalid()
            if not isinstance(e["code"], str) or not is_qty(e["estimateGas"]):
                invalid()
            xs = e["exchanges"]
            if not isinstance(xs, list) or [x.get("method") if isinstance(x, dict) else None for x in xs] != PLAN:
                invalid()
            if not all(sorted(x) == ["method", "requestSha256", "responseSha256"] and prep.COMMITMENT.fullmatch(str(x["requestSha256"]))
                       and prep.COMMITMENT.fullmatch(str(x["responseSha256"])) for x in xs):
                invalid()
        pin = entries[0]["block"]
        if any(e["block"] != pin for e in entries):
            inconsistent()
        tx = intent["transaction"]
        if tx["gas"] != hex(LIMIT) or g["gasLimit"] != LIMIT:
            inconsistent()
        if tx["maxFeePerGas"] != hex(max_fee(pin["baseFeePerGas"])):
            inconsistent()
        r = via_gas(lambda: gas.evaluate({"transaction": tx, "commitment": intent["commitment"], "providerIds": [e["id"] for e in entries],
                                          "codeEvidence": {e["id"]: e["code"] for e in entries}, "pinTimestamp": int(pin["timestamp"], 16),
                                          "now": p["observedAt"], "review": authority}))
        if g["review"] != authority:
            inconsistent()
        if any(g[k] != r[k] for k in ("ruleSetId", "fork", "reviewDigest", "standard", "floor", "need", "gasLimit")):
            inconsistent()
        for e in entries:
            v = int(e["estimateGas"], 16)
            if v > LIMIT:
                raise Refused("RNTP_GAS_TOO_HIGH", e["id"])
            if v < r["need"]:
                inconsistent(e["id"])
    except Refused as x:
        return [x.code, x.gas_rules]
    return "PASS"


# --- checks -----------------------------------------------------------------------------------

def checks(root: Path):
    raw = (root / "fixtures/preparation-v2/cases.json").read_bytes()
    doc = json.loads(raw)
    yield "fixtures file is canonical", raw == tx_ref.canon(doc) + b"\n"
    yield "fixtures format and synthetic status", doc["format"] == "rnnet.preparation-v2-fixtures.v1" and doc["status"].startswith("SYNTHETIC")
    yield "every test rules review is labelled TEST ONLY", all(c["testRulesReview"] is None or c["testRulesReview"]["reviewer"].startswith("TEST ONLY")
                                                               for c in doc["preparations"])

    preps = doc["preparations"]
    bad = []
    for c in preps:
        got, used = reproduce(c)
        if got != c["expected"] or used != len(c["exchanges"]):
            bad.append(c["id"])
    for name in bad:
        print("  preparation disagrees:", name)
    yield f"{len(preps) - len(bad)}/{len(preps)} preparations reproduced from the exchanges alone (intent, digest, refusal, requests)", not bad

    by = {c["id"]: c for c in preps}
    g = by["amsterdam-pass-estimate-14847"]["expected"]["candidate"]["preparation"]["gas"]
    yield "Amsterdam: need 14,688 (standard 12,672), estimate 14,847 accepted", (g["need"], g["standard"], g["floor"], g["ruleSetId"]) == (14688, 12672, 14688, "amsterdam")
    pr = by["prague-pass"]["expected"]["candidate"]["preparation"]["gas"]
    os_ = by["osaka-pass"]["expected"]["candidate"]["preparation"]["gas"]
    yield "Prague and Osaka: need 22,680 under rule set prague", pr["need"] == os_["need"] == 22680 and pr["ruleSetId"] == os_["ruleSetId"] == "prague" and os_["fork"] == "osaka"
    yield "every accepted v2 candidate keeps gas 0x7530 and 16 requests", all(c["expected"]["candidate"]["transaction"]["gas"] == "0x7530" and len(c["exchanges"]) == 16
                                                                         for c in preps if c["expected"]["outcome"] == "PASS")
    pre_read = [c for c in preps if c["id"].startswith(("review-", "input-"))]
    yield "review and input refusals send no request", pre_read and all(c["exchanges"] == [] for c in pre_read)
    yield "the review-injection input is refused", by["input-review-injection"]["expected"]["code"] == "RNTP_INPUT_INVALID"

    recs = doc["records"]
    rbad = [r["id"] for r in recs if verify(r["candidate"], r["candidateDigest"], r["testRulesReview"]) != r["expected"]]
    for name in rbad:
        print("  record disagrees:", name)
    yield f"{len(recs) - len(rbad)}/{len(recs)} candidates verified independently (valid, tampered, downgraded, confused with an intent)", not rbad
    tamper = [r for r in recs if r["id"].startswith("tamper-")]
    yield f"all {len(tamper)} tampered records are refused", tamper and all(r["expected"] != "PASS" for r in tamper)
    yield "a v1 intent is refused as a v2 candidate", next(r for r in recs if r["id"] == "v1-intent-refused")["expected"] == ["RNTP_INTENT_INVALID", None]
    passes = [c for c in preps if c["expected"]["outcome"] == "PASS"]
    yield "a candidate is never an intent (S1 intent_ok refuses every candidate)", passes and not any(tx_ref.intent_ok(c["expected"]["candidate"]) for c in passes)
    yield "a candidate relabelled as an intent is refused (S1 refuses its v2 preparation)", not any(
        tx_ref.intent_ok({**c["expected"]["candidate"], "format": "rnnet.unsigned-tx-intent.v1"}) for c in passes)
    yield "the candidate digest is never the intent-domain digest", all(
        candidate_digest(c["expected"]["candidate"]) != tx_ref.intent_digest(c["expected"]["candidate"]) for c in passes)
    yield "no authority: every v2 record is refused", next(r for r in recs if r["id"] == "no-authority")["expected"] == ["RNTP_INCONSISTENT", "RNTX_GAS_RULES_UNREVIEWED"]

    # v1 is untouched: the B2 fixtures still reproduce under the v1 reference, and none is v2.
    b2 = json.loads((root / "fixtures/preparation-b2/cases.json").read_bytes())
    v1_ok = all(prep.reproduce(c)[4] == c["expected"]["digest"] for c in b2["cases"])
    yield "v1: every B2 case still reproduces its digest under the v1 reference", v1_ok
    yield "v1: no B2 record is v2", all(c["expected"]["intent"] is None or c["expected"]["intent"]["preparation"]["format"] == "rnnet.tx-preparation.v1" for c in b2["cases"])
    yield "a v2 case is not a v1 preparation (the v1 reference disagrees with it)", prep.reproduce({**by["amsterdam-pass-estimate-14847"], "expected": None})[4] != by["amsterdam-pass-estimate-14847"]["expected"]["digest"]


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"prep v2 reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
