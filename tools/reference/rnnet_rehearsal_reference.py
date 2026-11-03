#!/usr/bin/env python3
"""Independent reproduction of the RN-NET-03B2-C3 offline rehearsal's critical decisions.

Checks every report of fixtures/rehearsal-c3/rehearsal.json without the JavaScript code:
  - the Genesis commitment and its exact 42-byte anchor payload (rnnet_anchor_reference.py);
  - preparation, recomputed from the recorded provider answers (rnnet_prep_reference.py): the
    intent and its digest, so the XRPL "+ 80 from the lower provider ledger" binding and the
    Sepolia two-pass, block-hash-pinned reads are reproduced, not read back;
  - the simulated clock: every XRPL answer reports the ledger the clock model gives at its time;
  - the signed transaction, verified again by rnnet_tx_reference.py, whose record must equal the
    one the run used;
  - the broadcaster's expiry decision before any write: XRPL refuses once a validated ledger it
    reads is LastLedgerSequence - 4 or later (at least 5 must remain); Sepolia once the clock is
    past the authorization's notAfter, written 3000 s after the authorization stage;
  - the window: the latest gate-D review submits with exactly 5 ledgers left, one second more
    leaves 4 and is refused; a slower ledger gives a longer window;
  - the duplicate authorization is refused with no request; each stage's elapsed time is what the
    profile gives it.
Offline; standard library only. Run: python3 -I -B <this file>
"""
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prep_ref = load("rnnet_prep_reference")
tx_ref = prep_ref.tx_ref
anchor_ref = prep_ref.anchor_ref

NOW = 1_793_491_200
XRPL_START_LEDGER = 5_000_000
MARGIN = 4
SEPOLIA_NOT_AFTER_AHEAD = 3000
GENESIS_COMMITMENT = "sha256:a20c2311ec1b1084409446fd3e78a49004328ee0521237647bb9e909b6a06ee7"


def ledger_at(close, provider_id, at_ms):
    """The clock model: one ledger per `close` seconds; provider b reports one ledger less."""
    return XRPL_START_LEDGER + at_ms // (close * 1000) - (1 if provider_id.endswith("-b") else 0)


def preparation_case(report, intent):
    """The recorded preparation as a B2-style case, for rnnet_prep_reference.reproduce."""
    p = intent["preparation"]
    providers = [{"id": e["id"], "network": report["network"], "url": f"https://{e['id']}.fixture.invalid/", "operator": e["operator"]} for e in p["providers"]]
    inp = {"commitment": intent["commitment"], "now": p["observedAt"], "providers": providers}
    if report["network"] == "xrpl:testnet":
        inp.update({"account": intent["transaction"]["Account"], "signingPubKey": intent["transaction"]["SigningPubKey"]})
    else:
        inp["from"] = intent["transaction"]["from"]
    exchanges = [{"providerId": e["providerId"], "request": e["request"], "response": {"status": 200, "body": e["response"]}} for e in report["preparation"]["observed"]]
    return {"network": report["network"], "input": inp, "exchanges": exchanges}


def xrpl_decision(report, lls):
    """The broadcaster's pre-submit expiry rule, provider by provider, in reading order."""
    by_provider = {}
    for e in report["submission"]["presubmit"]:
        by_provider.setdefault(e["providerId"], []).append(e["ledger"])
    for ledgers in by_provider.values():
        if max(ledgers) >= lls - MARGIN:
            return "NOT_SENT"
    return "SENT"


def stage(report, name):
    return next((s for s in report["stages"] if s["stage"] == name), None)


def checks(root: Path):
    raw = (root / "fixtures/rehearsal-c3/rehearsal.json").read_bytes()
    doc = json.loads(raw)
    yield "fixture is canonical", raw == tx_ref.canon(doc) + b"\n"
    yield "fixture format", doc["format"] == "rnnet.genesis-rehearsal.v1" and doc["status"].startswith("SYNTHETIC")
    golden = json.loads((root / "fixtures/genesis-proof-01/golden.json").read_text("utf-8"))
    yield "the Genesis commitment is the golden one", golden["envelope"]["commitment"] == GENESIS_COMMITMENT
    reports = {r["id"]: r for r in doc["reports"]}
    yield "one report per scenario", [s["id"] for s in doc["scenarios"]] == [r["id"] for r in doc["reports"]]
    for r in doc["reports"]:
        rid = r["id"]
        intent = json.loads(r["intentText"])
        prof = r["profile"]
        xrpl = r["network"] == "xrpl:testnet"
        # Evidence and payload.
        payload = anchor_ref.encode_payload(GENESIS_COMMITMENT)
        yield f"{rid}: 42-byte payload", len(payload) == 42 and r["assembly"]["payloadHex"] == payload.hex() == golden["anchorPayload"]["hex"]
        yield f"{rid}: intent canonical, valid, digest", tx_ref.canon(intent) == r["intentText"].encode("utf-8") and tx_ref.intent_ok(intent) and tx_ref.intent_digest(intent) == r["approvedDigest"] == r["assembly"]["intentDigest"]
        # Preparation, recomputed from the recorded answers.
        outcome, code, _, _, digest, rebuilt, unused = prep_ref.reproduce(preparation_case(r, intent))
        yield f"{rid}: preparation reproduced", outcome == "PASS" and digest == r["approvedDigest"] and tx_ref.canon(rebuilt) == r["intentText"].encode("utf-8") and unused == 0
        yield f"{rid}: preparation request count", r["preparation"]["requests"] == len(r["preparation"]["observed"]) == (4 if xrpl else 16)
        if xrpl:
            close = r["closeSeconds"]
            seqs = [json.loads(e["response"])["result"]["info"]["validated_ledger"]["seq"] for e in r["preparation"]["observed"] if e["method"] == "server_info"]
            model = all(json.loads(e["response"])["result"]["info"]["validated_ledger"]["seq"] == ledger_at(close, e["providerId"], e["atMs"]) for e in r["preparation"]["observed"] if e["method"] == "server_info")
            yield f"{rid}: preparation ledgers follow the clock", model
            lls = min(seqs) + 80
            yield f"{rid}: LastLedgerSequence = lower provider ledger + 80", intent["transaction"]["LastLedgerSequence"] == lls == r["preparation"]["lastLedgerSequence"]
            yield f"{rid}: pre-submit ledgers follow the clock", all(e["ledger"] == ledger_at(close, e["providerId"], e["atMs"]) for e in r["submission"]["presubmit"])
            decision = xrpl_decision(r, lls)
            left = lls - max(e["ledger"] for e in r["submission"]["presubmit"])
            yield f"{rid}: ledgers left", left == r["submission"]["ledgersLeftAtPresubmit"]
            expected = ("ACCEPTED_PROVISIONAL", "RNBC_ACCEPTED", 1) if decision == "SENT" else ("NOT_SENT", "RNBC_AUTHORIZATION_EXPIRED", 0)
            yield f"{rid}: expiry decision {decision}", (r["submission"]["outcome"], r["submission"]["code"], r["submission"]["writes"]) == expected and (decision == "SENT") == (left >= MARGIN + 1)
        else:
            pins = {json.dumps(json.loads(e["request"])["params"][1], sort_keys=True) for e in r["preparation"]["observed"] if json.loads(e["request"])["method"] in ("eth_getBalance", "eth_getCode", "eth_estimateGas")}
            yield f"{rid}: one pinned block hash", len(pins) == 1 and json.loads(next(iter(pins)))["requireCanonical"] is True
            auth_end = stage(r, "authorization")["endMs"]
            not_after = NOW + auth_end // 1000 + SEPOLIA_NOT_AFTER_AHEAD
            approved_at = NOW + (stage(r, "submission")["startMs"] + prof["submitApproval"] * 1000) // 1000
            expired = approved_at > not_after
            expected = ("NOT_SENT", "RNBC_AUTHORIZATION_EXPIRED", 0) if expired else ("ACCEPTED_PROVISIONAL", "RNBC_ACCEPTED", 1)
            yield f"{rid}: notAfter decision", (r["submission"]["outcome"], r["submission"]["code"], r["submission"]["writes"]) == expected
        # The signed transaction, verified independently; the record is the one the run used.
        record = tx_ref.cli_verify(r["intentText"], r["approvedDigest"], r["signedTransaction"])
        yield f"{rid}: Python verifies the signed transaction", record == tx_ref.canon(r["verification"]) + b"\n" and r["verification"]["outcome"] == "PASS"
        yield f"{rid}: hashes bound", r["verification"]["blobSha256"] == r["assembly"]["blobSha256"] and r["verification"]["transactionHash"] == r["assembly"]["transactionHash"]
        # The duplicate authorization and the status check.
        d = r["duplicate"]
        yield f"{rid}: duplicate refused, nothing sent", d is not None and d["code"] == "RNBC_AUTHORIZATION_USED" and d["requests"] == 0 and d["writes"] == 0
        sent = r["submission"]["outcome"] == "ACCEPTED_PROVISIONAL"
        yield f"{rid}: status only after acceptance", (r["status"] is not None and r["status"]["finding"] == "INCLUDED") if sent else r["status"] is None
        # Elapsed times: what the profile gives each stage.
        req = prof["requestMs"]
        yield f"{rid}: stage times", (
            stage(r, "intent")["elapsedMs"] == prof["intentReview"] * 1000
            and stage(r, "authorization")["elapsedMs"] == prof["authorizationDraft"] * 1000
            and stage(r, "preparation")["elapsedMs"] == prof["preparationApproval"] * 1000 + r["preparation"]["requests"] * req
            and stage(r, "submission")["elapsedMs"] == prof["submitApproval"] * 1000 + r["submission"]["requests"] * req
            and stage(r, "signing")["elapsedMs"] == (prof["passphrase"] + prof["scryptAndSign"]) * 1000
            and all(b["startMs"] >= a["endMs"] for a, b in zip(r["stages"], r["stages"][1:]))
        )
    # The windows.
    previous = 0
    for w in doc["windows"]:
        c = w["closeSeconds"]
        ok, late = reports[f"xrpl-{c}s-latest-intent-review"], reports[f"xrpl-{c}s-intent-review-one-second-too-long"]
        yield f"window {c}s: latest review submits with 5 left", ok["profile"]["intentReview"] == w["latestIntentReviewSeconds"] and ok["submission"]["outcome"] == "ACCEPTED_PROVISIONAL" and ok["submission"]["ledgersLeftAtPresubmit"] == 5
        yield f"window {c}s: one second more is refused with 4 left", late["profile"]["intentReview"] == w["latestIntentReviewSeconds"] + 1 and late["submission"]["outcome"] == "NOT_SENT" and late["submission"]["ledgersLeftAtPresubmit"] == 4
        yield f"window {c}s: longer than the last", w["latestIntentReviewSeconds"] > previous
        previous = w["latestIntentReviewSeconds"]


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"rehearsal reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
