#!/usr/bin/env python3
"""Independent reference for the fork-aware gas rules (ADR-RN-018 Amendment C2; RN-NET-03B2-WP2).

Written from the ADR and the EIP texts, not from the JavaScript. It:
  * expresses the rules in its own form: tokens for Prague, and "64 gas per calldata byte" for
    the EIP-7976 floor;
  * keeps its own copies of the Sepolia activations and of the pinned G2 sources;
  * recomputes every case of fixtures/gas-rules-wp2/vectors.json, results and refusal codes;
  * checks golden values it derives itself, that the ADR text carries every timestamp and source
    digest, and that a deliberately wrong constant is caught by the vectors (negative control).

Offline; standard library only; no Node.js. Run: python3 -I -B <this file>
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canonical = _load("rnnet_reference")  # RN-NET-01 canonical JSON, Python side

# --- Reviewed facts (ADR-RN-018 C2 G1, G2, G5) ----------------------------------------------

PRAGUE_T, OSAKA_T, BPO1_T, BPO2_T, AMSTERDAM_T = 1741159776, 1760427360, 1761017184, 1761607008, 1791294816
FORKS = [  # (activation time, fork, rule set); Osaka and the BPO forks keep Prague's gas
    (PRAGUE_T, "prague", "prague"),
    (OSAKA_T, "osaka", "prague"),
    (BPO1_T, "bpo1", "prague"),
    (BPO2_T, "bpo2", "prague"),
    (AMSTERDAM_T, "amsterdam", "amsterdam"),
]
SOURCES = [
    ("eth-clients/sepolia:metadata/genesis.json", "7b1b9d9549787b6bbf538f943304c4cf84f7e39e", "d558a75ef48e6fdb224b063c84c309de8a55995e263db63515b79ad4432a37df"),
    ("ethereum/execution-specs:src/ethereum/forks/amsterdam/vm/gas.py", "16898000911c1e3caa57be08509536c10ae92d3e", "67973191c49234387186ad17316c556adab73723f782e95104dd3a949132367c"),
    ("ethereum/execution-specs:src/ethereum/forks/amsterdam/transactions.py", "16898000911c1e3caa57be08509536c10ae92d3e", "846e1b579e133ab2e282ca19e85903b2b7a969d47b0b8511cf70c938e38d7188"),
    ("ethereum/go-ethereum:params/protocol_params.go", "3d858f858a458effb2a563788aedf1fe65e1f0d3", "94657cdf80d2f0b136ff6d89003326f496d3b1ba1abcb1a855b7b98c941e9e28"),
    ("ethereum/go-ethereum:core/state_transition.go", "3d858f858a458effb2a563788aedf1fe65e1f0d3", "72e7a68d1f180069920dd5db624fe8fbc7f4cb96f4491d3478239a91ae3d170d"),
    ("ethereum/go-ethereum:eth/gasestimator/gasestimator.go", "3d858f858a458effb2a563788aedf1fe65e1f0d3", "5b2949f6c16abf05cf5ad5a1ecd985c0adc693530c11b9b6e0221aefa70fcf68"),
    ("ethereum/go-ethereum:internal/ethapi/api.go", "3d858f858a458effb2a563788aedf1fe65e1f0d3", "df5d20455fe37005d4b953a448a019f5ba0ec7aaee258060c7ed28d142743990"),
]
LIMIT = 30000
BEFORE, AFTER = 3600, 86400  # Q2
MAX_AGE = 30 * 24 * 3600  # Q1
TIME_MAX = (1 << 40) - 1
SAFE_MAX = (1 << 53) - 1
SEPOLIA_CHAIN = "0xaa36a7"
TX_KEYS = {"type", "chainId", "nonce", "from", "to", "value", "input", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "accessList"}
BLOB_KEYS = ["maxFeePerBlobGas", "blobVersionedHashes", "blobs", "sidecar"]

# EIP-level constants, written as the EIPs state them.
G_TX = 21000  # Yellow Paper G_transaction (Prague base)
EIP2780_TX_BASE = 12000  # Amsterdam: sender base; a self-transfer adds no recipient or value cost
STANDARD_TOKEN_COST = 4  # EIP-7623: standard cost per token (= 4/zero byte, 16/non-zero byte)
EIP7623_FLOOR_PER_TOKEN = 10
EIP7976_FLOOR_PER_BYTE = 64  # EIP-7976: "64 gas per calldata byte (both zero and non-zero)"


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def refuse(code):
    raise Refusal(code)


INPUT, UNSUPPORTED, UNREVIEWED, BOUNDARY, PRECONDITION, LIMIT_CODE, OVERFLOW = (
    "RNTX_GAS_INPUT_INVALID", "RNTX_GAS_RULES_UNSUPPORTED", "RNTX_GAS_RULES_UNREVIEWED",
    "RNTX_GAS_FORK_BOUNDARY", "RNTX_GAS_PRECONDITION", "RNTX_GAS_LIMIT_EXCEEDED", "RNTX_GAS_OVERFLOW")


def is_int(v):
    return type(v) is int  # excludes bool and float


def is_time(t):
    return is_int(t) and 0 <= t <= TIME_MAX


def need_time(t):
    if not is_time(t):
        refuse(INPUT)
    return t


# --- Gas arithmetic -------------------------------------------------------------------------

def gas_for_counts(rule, zeros, nonzeros, floor_per_byte=EIP7976_FLOOR_PER_BYTE, prague_floor=EIP7623_FLOOR_PER_TOKEN):
    if rule not in ("prague", "amsterdam"):
        refuse(UNSUPPORTED)
    if not (is_int(zeros) and zeros >= 0 and zeros <= SAFE_MAX and is_int(nonzeros) and nonzeros >= 0 and nonzeros <= SAFE_MAX):
        refuse(INPUT)
    tokens = zeros + 4 * nonzeros
    if rule == "prague":
        standard = G_TX + STANDARD_TOKEN_COST * tokens
        floor = G_TX + prague_floor * tokens
    else:
        standard = EIP2780_TX_BASE + STANDARD_TOKEN_COST * tokens
        floor = EIP2780_TX_BASE + floor_per_byte * (zeros + nonzeros)
    if standard > SAFE_MAX or floor > SAFE_MAX:
        refuse(OVERFLOW)
    return {"ruleSetId": rule, "zeroBytes": zeros, "nonzeroBytes": nonzeros, "standard": standard, "floor": floor, "need": max(standard, floor)}


HEX = re.compile(r"0x(?:[0-9a-f]{2})*")


def gas_for_input(rule, data, **kw):
    if not isinstance(data, str) or not HEX.fullmatch(data):
        refuse(INPUT)
    raw = bytes.fromhex(data[2:])
    return gas_for_counts(rule, raw.count(0), len(raw) - raw.count(0), **kw)


def within_limit(need):
    if not is_int(need) or need < 0 or need > SAFE_MAX:
        refuse(INPUT)
    if need > LIMIT:
        refuse(LIMIT_CODE)
    return LIMIT - need


# --- Fork selection -------------------------------------------------------------------------

def rules_at(t):
    need_time(t)
    applicable = [f for f in FORKS if f[0] <= t]
    if not applicable:
        refuse(UNSUPPORTED)
    when, fork, rule = applicable[-1]
    return {"ruleSetId": rule, "fork": fork, "activationTimestamp": when}


def rule_matches(rule, t):
    if not isinstance(rule, str) or rule not in ("prague", "amsterdam"):
        refuse(UNSUPPORTED)
    if rules_at(t)["ruleSetId"] != rule:
        refuse(UNSUPPORTED)


def table_ok(table):
    if not isinstance(table, list) or not table:
        refuse(UNSUPPORTED)
    names, last = set(), None
    for e in table:
        if not isinstance(e, dict) or set(e) != {"fork", "timestamp", "ruleSetId"}:
            refuse(UNSUPPORTED)
        if not isinstance(e["fork"], str) or not re.fullmatch(r"[a-z0-9]+", e["fork"]) or e["fork"] in names:
            refuse(UNSUPPORTED)
        names.add(e["fork"])
        if not is_time(e["timestamp"]) or (last is not None and e["timestamp"] <= last):
            refuse(UNSUPPORTED)
        last = e["timestamp"]
        if e["ruleSetId"] not in ("prague", "amsterdam"):
            refuse(UNSUPPORTED)
    if table[0]["ruleSetId"] != "prague":
        refuse(UNSUPPORTED)


# --- Review horizon (Q1) --------------------------------------------------------------------

def review_ok(review, pin, now):
    need_time(pin)
    need_time(now)
    if review is None:
        refuse(UNREVIEWED)
    if not isinstance(review, dict) or set(review) != {"reviewedAt", "reviewer", "horizon", "sources", "knownUnreviewedActivations"}:
        refuse(UNREVIEWED)
    at, who, horizon = review["reviewedAt"], review["reviewer"], review["horizon"]
    if not is_time(at) or at == 0:
        refuse(UNREVIEWED)
    if now < at:  # a review dated after the evaluation is not a recorded review
        refuse(UNREVIEWED)
    if not isinstance(who, str) or not who.strip() or len(who) > 200:
        refuse(UNREVIEWED)
    listed = review["sources"]
    if not isinstance(listed, list) or len(listed) != len(SOURCES):
        refuse(UNREVIEWED)
    for item, (src, rev, digest) in zip(listed, SOURCES):
        if item != {"source": src, "revision": rev, "sha256": "sha256:" + digest}:
            refuse(UNREVIEWED)
    later = review["knownUnreviewedActivations"]
    if not isinstance(later, list):
        refuse(UNREVIEWED)
    previous = FORKS[-1][0]
    for a in later:
        if not is_time(a) or a <= previous:
            refuse(UNREVIEWED)
        previous = a
    if not is_time(horizon) or horizon <= at or horizon - at > MAX_AGE:
        refuse(UNREVIEWED)
    if later and horizon > later[0]:
        refuse(UNREVIEWED)
    if max(pin, now) >= horizon:
        refuse(UNREVIEWED)
    digest = "sha256:" + hashlib.sha256(canonical.canonicalize(review).encode("utf-8")).hexdigest()
    return {"reviewDigest": digest, "horizon": horizon}


# --- Fork boundary (Q2) ---------------------------------------------------------------------

def boundary_ok(pin, now, extra):
    need_time(pin)
    need_time(now)
    if not isinstance(extra, list) or not all(is_time(a) for a in extra):
        refuse(INPUT)
    window = range(pin - BEFORE, now + AFTER + 1)  # inclusive at both ends
    if any(a in window for a in [f[0] for f in FORKS] + extra):
        refuse(BOUNDARY)
    if rules_at(pin)["ruleSetId"] != rules_at(now)["ruleSetId"]:
        refuse(BOUNDARY)


# --- Transaction and code preconditions (G4) ------------------------------------------------

def genesis_payload(commitment):
    return b"RNNETANC" + bytes([1, 1]) + bytes.fromhex(commitment[len("sha256:"):])


def preconditions_ok(tx, commitment, providers, codes):
    if not isinstance(commitment, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", commitment):
        refuse(INPUT)
    if not isinstance(tx, dict):
        refuse(PRECONDITION)
    keys = set(tx)
    if "authorizationList" in keys or any(k in keys for k in BLOB_KEYS) or keys != TX_KEYS:
        refuse(PRECONDITION)
    sender = tx["from"]
    shape = (
        tx["type"] == "0x2"
        and tx["chainId"] == SEPOLIA_CHAIN
        and isinstance(sender, str) and re.fullmatch(r"0x[0-9a-f]{40}", sender) is not None
        and tx["to"] is not None and tx["to"] == sender
        and tx["value"] == "0x0"
        and tx["accessList"] == []
        and tx["gas"] == hex(LIMIT)
        and isinstance(tx["input"], str) and HEX.fullmatch(tx["input"]) is not None
    )
    if not shape:
        refuse(PRECONDITION)
    if bytes.fromhex(tx["input"][2:]) != genesis_payload(commitment):
        refuse(PRECONDITION)  # length, magic, version, format and commitment, as one byte-exact test
    if not isinstance(providers, list) or not all(isinstance(p, str) and p for p in providers) or len(set(providers)) != len(providers) or len(providers) < 2:
        refuse(PRECONDITION)
    if not isinstance(codes, dict) or set(codes) != set(providers):
        refuse(PRECONDITION)
    values = [codes[p] for p in providers]
    if not all(isinstance(v, str) and HEX.fullmatch(v) for v in values):
        refuse(PRECONDITION)
    if any(v != "0x" for v in values):  # includes 0xef0100… delegations and any disagreement
        refuse(PRECONDITION)


# --- The composed evaluator -----------------------------------------------------------------

def evaluate(arg, **kw):
    expected = {"transaction", "commitment", "providerIds", "codeEvidence", "pinTimestamp", "now", "review"}
    if not isinstance(arg, dict) or set(arg) != expected:
        refuse(INPUT)
    pin, now, review = arg["pinTimestamp"], arg["now"], arg["review"]
    if not (is_time(pin) and is_time(now)) or now - pin < 0:  # the pinned block precedes or equals now
        refuse(INPUT)
    digest = review_ok(review, pin, now)["reviewDigest"]
    at_pin = rules_at(pin)
    boundary_ok(pin, now, review["knownUnreviewedActivations"])
    preconditions_ok(arg["transaction"], arg["commitment"], arg["providerIds"], arg["codeEvidence"])
    gas = gas_for_input(at_pin["ruleSetId"], arg["transaction"]["input"], **kw)
    margin = within_limit(gas["need"])
    return {"ruleSetId": at_pin["ruleSetId"], "fork": at_pin["fork"], "reviewDigest": digest, "zeroBytes": gas["zeroBytes"], "nonzeroBytes": gas["nonzeroBytes"],
            "standard": gas["standard"], "floor": gas["floor"], "need": gas["need"], "gasLimit": LIMIT, "margin": margin}


def outcome(kind, i, **kw):
    table = {
        "calldata": lambda: gas_for_counts(i["ruleSetId"], i["zeroBytes"], i["nonzeroBytes"], **kw),
        "calldataInput": lambda: gas_for_input(i["ruleSetId"], i["input"], **kw),
        "select": lambda: rules_at(i.get("timestamp")),
        "ruleForTimestamp": lambda: rule_matches(i["ruleSetId"], i["timestamp"]),
        "table": lambda: table_ok(i["table"]),
        "limit": lambda: within_limit(i["need"]),
        "horizon": lambda: review_ok(i["review"], i["pinTimestamp"], i["now"]),
        "boundary": lambda: boundary_ok(i["pinTimestamp"], i["now"], i["extra"]),
        "preconditions": lambda: preconditions_ok(i["transaction"], i["commitment"], i["providerIds"], i.get("codeEvidence")),
        "evaluate": lambda: evaluate(i["input"], **kw),
    }
    try:
        return {"ok": table[kind]()}
    except Refusal as r:
        return {"error": r.code}


# --- Checks ---------------------------------------------------------------------------------

GENESIS = "sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7"


def checks(root: Path):
    doc = json.loads((root / "fixtures/gas-rules-wp2/vectors.json").read_text("utf-8"))
    cases = doc["cases"]
    yield "vector file format", doc["format"] == "rnnet.gas-rules-vectors.v1" and len(cases) >= 150

    disagree = [c["name"] for c in cases if outcome(c["kind"], c["input"]) != c["expect"]]
    for name in disagree:
        print("  disagrees:", name)
    yield f"{len(cases) - len(disagree)}/{len(cases)} vectors recomputed independently agree", not disagree

    # Golden values derived here, from the payload bytes and the EIP formulas.
    p = genesis_payload(GENESIS)
    yield "the Genesis payload is 42 non-zero bytes", len(p) == 42 and p.count(0) == 0
    pr, am = gas_for_counts("prague", 0, 42), gas_for_counts("amsterdam", 0, 42)
    yield "Prague/Osaka Genesis need 22,680 (standard 21,672)", (pr["need"], pr["standard"], pr["floor"]) == (22680, 21672, 22680)
    yield "Amsterdam Genesis need 14,688 (standard 12,672)", (am["need"], am["standard"], am["floor"]) == (14688, 12672, 14688)
    yield "42 zero bytes: Prague 21,420; Amsterdam 14,688", gas_for_counts("prague", 42, 0)["need"] == 21420 and gas_for_counts("amsterdam", 42, 0)["need"] == 14688
    by_name = {c["name"]: c for c in cases}
    required = ["golden prague: the Genesis payload", "golden amsterdam: the Genesis payload", "golden prague: 42 zero bytes", "golden amsterdam: 42 zero bytes",
                "golden prague: 10 zero, 32 non-zero", "golden amsterdam: 10 zero, 32 non-zero", "evaluate: Amsterdam, Genesis", "evaluate: Prague, Genesis", "evaluate: Osaka fork pin"]
    yield "the required golden and evaluator vectors are present", all(n in by_name for n in required)
    ev = by_name.get("evaluate: Amsterdam, Genesis", {}).get("expect", {}).get("ok", {})
    yield "the Amsterdam evaluator vector: 14,688 under the fixed 30,000 (margin 15,312)", ev.get("need") == 14688 and ev.get("gasLimit") == 30000 and ev.get("margin") == 15312
    edges = {n: by_name[n]["expect"] for n in by_name if n.startswith("boundary: A ")}
    yield "boundary edges: −3601 and +86401 allowed; −3600, inside and +86400 refused", edges == {
        "boundary: A = pin − 3601": {"ok": None}, "boundary: A = pin − 3600": {"error": BOUNDARY},
        "boundary: A between pin and now": {"error": BOUNDARY}, "boundary: A = now + 86400": {"error": BOUNDARY}, "boundary: A = now + 86401": {"ok": None}}
    yield "every accepted Genesis evaluation is within the limit and above both terms", all(
        c["expect"]["ok"]["need"] <= LIMIT and c["expect"]["ok"]["need"] >= max(c["expect"]["ok"]["standard"], c["expect"]["ok"]["floor"])
        for c in cases if c["kind"] == "evaluate" and "ok" in c["expect"])

    r1 = {n: by_name[n]["expect"] for n in by_name if n.startswith("R1 ")}
    r2 = {n: by_name[n]["expect"] for n in by_name if n.startswith("R2 ")}
    yield "review R1 vectors: pin = now and pin < now allowed; pin = now + 1 and malformed refused", (
        "ok" in r1.get("R1 evaluate: pin = now", {}) and "ok" in r1.get("R1 evaluate: pin < now", {})
        and r1.get("R1 evaluate: pin = now + 1") == {"error": INPUT} and r1.get("R1 evaluate: malformed pin") == {"error": INPUT}
        and r1.get("R1 evaluate: malformed now") == {"error": INPUT} and r1.get("R1 evaluate: pin after now, also past the horizon (R1 first)") == {"error": INPUT})
    yield "review R2 vectors: reviewedAt = now and < now allowed; now + 1 and future-extended refused", (
        "ok" in r2.get("R2 horizon: reviewedAt = now", {}) and "ok" in r2.get("R2 horizon: reviewedAt < now", {})
        and r2.get("R2 horizon: reviewedAt = now + 1") == {"error": UNREVIEWED} and r2.get("R2 horizon: future review cannot extend the window") == {"error": UNREVIEWED}
        and "ok" in r2.get("R2 evaluate: reviewedAt = now", {}) and r2.get("R2 evaluate: reviewedAt = now + 1") == {"error": UNREVIEWED})

    # The ADR carries every reviewed fact this reference uses.
    adr = (root / "docs/adr/ADR-RN-018-transaction-preparation-reads.md").read_text("utf-8")
    yield "ADR C2 G1 lists every activation timestamp", all(str(t) in adr for t, _, _ in FORKS)
    yield "ADR C2 G2 lists every pinned revision and digest", all(rev in adr and dig in adr for _, rev, dig in SOURCES)
    yield "ADR Q1/Q2 values", "3,600" in adr and "86,400" in adr and "2,592,000" in adr

    # Negative controls: a wrong constant must be caught by the vectors.
    wrong_7976 = [c for c in cases if outcome(c["kind"], c["input"], floor_per_byte=60) != c["expect"]]
    wrong_7623 = [c for c in cases if outcome(c["kind"], c["input"], prague_floor=11) != c["expect"]]
    yield f"negative control: an EIP-7976 floor of 60/byte disagrees on {len(wrong_7976)} vectors", len(wrong_7976) > 0
    yield f"negative control: an EIP-7623 floor of 11/token disagrees on {len(wrong_7623)} vectors", len(wrong_7623) > 0


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"gas-rules reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
