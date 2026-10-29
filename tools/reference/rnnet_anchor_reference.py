#!/usr/bin/env python3
"""Second implementation of rnnet.anchor-payload.v1 and rnnet.anchor-record.v1.

Written from spec/rnnet.anchor-payload.v1.md and spec/rnnet.anchor-record.v1.md and checked
against every vector in vectors/anchor/. It rebuilds each expected record and report in full and
compares the canonical text byte for byte. Offline; standard library only. It reuses the
canonical JSON parser and serializer of rnnet_reference.py, loaded by path.
Run: python3 -I -B <this file>
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("rnnet_reference", HERE / "rnnet_reference.py")
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)

# --- rnnet.anchor-payload.v1 ------------------------------------------------------------------

MAGIC = b"RNNETANC"
LENGTH = 42


class Fail(Exception):
    def __init__(self, code, subject):
        super().__init__(code)
        self.code = code
        self.subject = subject


def decode_payload(data: bytes, subject="payload") -> str:
    if len(data) < 8 or data[:8] != MAGIC:
        raise Fail("RNAP_NOT_ANCHOR_PAYLOAD", subject)
    if len(data) < 9:
        raise Fail("RNAP_INVALID_LENGTH", subject)
    if data[8] != 1:
        raise Fail("RNAP_UNSUPPORTED_VERSION", subject)
    if len(data) != LENGTH:
        raise Fail("RNAP_INVALID_LENGTH", subject)
    if data[9] != 1:
        raise Fail("RNAP_UNSUPPORTED_COMMITMENT_FORMAT", subject)
    return "sha256:" + data[10:].hex()


def encode_payload(commitment: str) -> bytes:
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", commitment)
    return MAGIC + bytes([1, 1]) + bytes.fromhex(commitment[7:])


# --- observations and records -----------------------------------------------------------------

XRPL, EVM = "xrpl:testnet", "evm:11155111"
MEMBERS = {XRPL: ["format", "network", "tx"], EVM: ["format", "network", "transaction", "receipt"]}
UNSUPPORTED = {
    "RNAO_UNSUPPORTED_FORMAT", "RNAO_UNSUPPORTED_VERSION", "RNAX_UNSUPPORTED_TRANSACTION_TYPE",
    "RNAE_UNSUPPORTED_TRANSACTION_TYPE", "RNAP_UNSUPPORTED_VERSION", "RNAP_UNSUPPORTED_COMMITMENT_FORMAT",
}
BASIS = {
    "payload": "Decoded from the supplied transaction data and equal to the payload of the expected commitment.",
    "network": "Named by the supplier of the record and consistent with the transaction's own network fields; not authenticated.",
    "status": "Stated by the supplied transaction data; not authenticated.",
    "inclusion": "The supplied data names the ledger or block that includes the transaction; no inclusion proof was checked.",
    "xrpl_finality": "The supplied data states the transaction is in a validated ledger; not authenticated.",
    "evm_finality": "The supplied data shows inclusion in a block, not finality.",
    "hash": "Not recomputed from the signed transaction, so not bound to the data that was checked.",
    "submitter": "The sending account as stated by the supplied data.",
}


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def jtype(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def parse_observation(data: bytes, network):
    if len(data) > 65_536:
        raise Fail("RNAO_TOO_LARGE", "")
    try:
        obs = ref.parse(data)
    except ref.RefError as e:
        raise Fail(e.code, "") from None
    if not isinstance(obs, dict):
        raise Fail("RNAO_NOT_OBJECT", "")
    for f in ("format", "network"):
        if f not in obs:
            raise Fail("RNAO_MISSING_FIELD", f)
        if not isinstance(obs[f], str):
            raise Fail("RNAO_FIELD_TYPE", f)
        if f == "format" and obs["format"] != "rnnet.anchor-observation.v1":
            v = obs["format"].startswith("rnnet.anchor-observation.")
            raise Fail("RNAO_UNSUPPORTED_VERSION" if v else "RNAO_UNSUPPORTED_FORMAT", "format")
    if obs["network"] != network:
        raise Fail("RNAO_WRONG_NETWORK", "network")
    if any(k not in MEMBERS[network] for k in obs):
        raise Fail("RNAO_UNKNOWN_FIELD", "")
    for f in MEMBERS[network]:
        if f not in obs:
            raise Fail("RNAO_MISSING_FIELD", f)
    return obs


def finding(code, subject):
    return {"code": code, "severity": "unsupported" if code in UNSUPPORTED else "error", "subject": subject}


def run(findings, fn):
    try:
        fn()
        return True
    except Fail as e:
        findings.append(finding(e.code, e.subject))
        return False


def new_record(network, expected, data):
    return {
        "format": "rnnet.anchor-record.v1", "network": network, "expectedCommitment": expected,
        "input": {"sha256": "sha256:" + hashlib.sha256(data).hexdigest()}, "findings": [], "statements": [],
    }


def finish(rec, finality_class, finality_basis):
    f = rec["findings"]
    rec["outcome"] = "PASS" if not f else ("UNSUPPORTED" if all(x["code"] in UNSUPPORTED for x in f) else "FAIL")
    if rec["outcome"] == "PASS":
        rec["assurance"] = "CONSISTENT_WITH_SUPPLIED_DATA"
        st = lambda s, c, b: {"subject": s, "classification": c, "basis": BASIS[b]}
        rec["statements"] = [
            st("anchorPayload", "VERIFIED", "payload"), st("network", "CLAIMED", "network"),
            st("transactionStatus", "CLAIMED", "status"), st("inclusion", "CLAIMED", "inclusion"),
            st("finality", finality_class, finality_basis), st("transactionHash", "UNRESOLVED", "hash"),
            st("submitter", "CLAIMED", "submitter"),
        ]
    return rec


def take_payload(rec, data, expected, subject):
    commitment = decode_payload(data, subject)
    rec["payload"] = {"hex": data.hex(), "commitment": commitment, "matchesExpected": commitment == expected}
    if commitment != expected:
        raise Fail("RNAP_COMMITMENT_MISMATCH", subject)


# --- XRPL (§3) ------------------------------------------------------------------------------------

UHEX64 = re.compile(r"[0-9A-F]{64}")
ACCOUNT = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
MEMO_TYPE = b"rnnet.anchor-payload.v1".hex().upper()
MEMO_HEX = re.compile(r"(?:[0-9A-F]{2}){0,1024}")


def xrpl_structure(tx):
    if not isinstance(tx, dict):
        raise Fail("RNAX_FIELD_TYPE", "tx")
    for f, t in (("hash", "string"), ("ledger_index", "number"), ("ledger_hash", "string"), ("validated", "boolean"), ("meta", "object"), ("tx_json", "object")):
        if f not in tx:
            raise Fail("RNAX_MISSING_FIELD", "tx." + f)
        if jtype(tx[f]) != t:
            raise Fail("RNAX_FIELD_TYPE", "tx." + f)
    if not UHEX64.fullmatch(tx["hash"]):
        raise Fail("RNAX_INVALID_HASH", "tx.hash")
    if not UHEX64.fullmatch(tx["ledger_hash"]):
        raise Fail("RNAX_INVALID_LEDGER_HASH", "tx.ledger_hash")
    if not (1 <= tx["ledger_index"] <= 0xFFFFFFFF):
        raise Fail("RNAX_INVALID_LEDGER_INDEX", "tx.ledger_index")
    body, meta = tx["tx_json"], tx["meta"]
    if "NetworkID" in body:
        raise Fail("RNAX_WRONG_NETWORK", "tx.tx_json.NetworkID")
    ctids = []
    for holder, path in ((tx, "tx.ctid"), (body, "tx.tx_json.ctid")):
        if "ctid" not in holder:
            continue
        if not isinstance(holder["ctid"], str) or not re.fullmatch(r"C[0-9A-F]{15}", holder["ctid"]):
            raise Fail("RNAX_INVALID_CTID", path)
        value = int(holder["ctid"], 16)
        if value & 0xFFFF != 1:
            raise Fail("RNAX_WRONG_NETWORK", path)
        ctids.append((value, path))
    if "hash" in body and body["hash"] != tx["hash"]:
        raise Fail("RNAX_CONTRADICTORY_REFERENCE", "tx.tx_json.hash")
    if "ledger_index" in body and not (is_int(body["ledger_index"]) and body["ledger_index"] == tx["ledger_index"]):
        raise Fail("RNAX_CONTRADICTORY_REFERENCE", "tx.tx_json.ledger_index")
    if len(ctids) == 2 and ctids[0][0] != ctids[1][0]:
        raise Fail("RNAX_CONTRADICTORY_REFERENCE", "tx.tx_json.ctid")
    if ctids:
        if "TransactionIndex" not in meta:
            raise Fail("RNAX_MISSING_FIELD", "tx.meta.TransactionIndex")
        if not is_int(meta["TransactionIndex"]):
            raise Fail("RNAX_FIELD_TYPE", "tx.meta.TransactionIndex")
    for value, path in ctids:
        if (value >> 32) & 0x0FFFFFFF != tx["ledger_index"] or (value >> 16) & 0xFFFF != meta["TransactionIndex"]:
            raise Fail("RNAX_CONTRADICTORY_REFERENCE", path)
    if body.get("TransactionType") != "AccountSet":
        raise Fail("RNAX_UNSUPPORTED_TRANSACTION_TYPE", "tx.tx_json.TransactionType")
    for field in ("ClearFlag", "SetFlag", "Domain", "EmailHash", "MessageKey", "NFTokenMinter", "TickSize", "TransferRate", "WalletLocator", "WalletSize"):
        if field in body:
            raise Fail("RNAX_UNSUPPORTED_TRANSACTION_TYPE", "tx.tx_json." + field)
    if not isinstance(body.get("Account"), str) or not ACCOUNT.fullmatch(body["Account"]):
        raise Fail("RNAX_INVALID_ACCOUNT", "tx.tx_json.Account")
    if "Memos" in body:
        memos = body["Memos"]
        if not isinstance(memos, list) or len(memos) > 32:
            raise Fail("RNAX_MALFORMED_MEMO", "tx.tx_json.Memos")
        for i, w in enumerate(memos):
            s = f"tx.tx_json.Memos[{i}]"
            if not isinstance(w, dict) or len(w) != 1 or not isinstance(w.get("Memo"), dict) or not w["Memo"]:
                raise Fail("RNAX_MALFORMED_MEMO", s)
            for k, v in w["Memo"].items():
                if k not in ("MemoType", "MemoData", "MemoFormat") or not isinstance(v, str) or not MEMO_HEX.fullmatch(v):
                    raise Fail("RNAX_MALFORMED_MEMO", s)


def xrpl_anchor(tx, expected, rec):
    memos = tx["tx_json"].get("Memos", [])
    idx = [i for i, w in enumerate(memos) if w["Memo"].get("MemoType") == MEMO_TYPE]
    if not idx:
        raise Fail("RNAX_MISSING_ANCHOR", "tx.tx_json.Memos")
    if len(idx) > 1:
        raise Fail("RNAX_DUPLICATE_ANCHOR", f"tx.tx_json.Memos[{idx[1]}]")
    memo = memos[idx[0]]["Memo"]
    if "MemoFormat" in memo or "MemoData" not in memo:
        raise Fail("RNAX_MALFORMED_MEMO", f"tx.tx_json.Memos[{idx[0]}]")
    take_payload(rec, bytes.fromhex(memo["MemoData"]), expected, f"tx.tx_json.Memos[{idx[0]}].MemoData")


def xrpl_status(tx):
    if tx["validated"] is not True:
        raise Fail("RNAX_NOT_VALIDATED", "tx.validated")
    if tx["meta"].get("TransactionResult") != "tesSUCCESS":
        raise Fail("RNAX_TRANSACTION_NOT_SUCCESSFUL", "tx.meta.TransactionResult")


def verify_xrpl(data: bytes, expected):
    rec = new_record(XRPL, expected, data)
    box = {}

    def structure():
        box["tx"] = parse_observation(data, XRPL)["tx"]
        xrpl_structure(box["tx"])

    if run(rec["findings"], structure):
        tx = box["tx"]
        rec["transaction"] = {"hash": tx["hash"], "ledgerIndex": tx["ledger_index"], "ledgerHash": tx["ledger_hash"], "account": tx["tx_json"]["Account"]}
        run(rec["findings"], lambda: xrpl_anchor(tx, expected, rec))
        run(rec["findings"], lambda: xrpl_status(tx))
    return finish(rec, "CLAIMED", "xrpl_finality")


# --- Ethereum Sepolia (§4) ------------------------------------------------------------------------

HASH = re.compile(r"0x[0-9a-f]{64}")
ADDR = re.compile(r"0x[0-9a-f]{40}")
QTY = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)")
DATA = re.compile(r"0x(?:[0-9a-f]{2})*")
BLOCK = ("blockHash", "blockNumber", "transactionIndex")


def need(obj, fields, path):
    for f, types in fields:
        if f not in obj:
            raise Fail("RNAE_MISSING_FIELD", f"{path}.{f}")
        if jtype(obj[f]) not in types:
            raise Fail("RNAE_FIELD_TYPE", f"{path}.{f}")


def evm_structure(t, r):
    if not isinstance(t, dict):
        raise Fail("RNAE_FIELD_TYPE", "transaction")
    if r is not None and not isinstance(r, dict):
        raise Fail("RNAE_FIELD_TYPE", "receipt")
    s, sn = ("string",), ("string", "null")
    need(t, [("hash", s), ("chainId", s), ("type", s), ("from", s), ("input", s), ("to", sn), ("blockHash", sn), ("blockNumber", sn), ("transactionIndex", sn)], "transaction")
    if not HASH.fullmatch(t["hash"]):
        raise Fail("RNAE_INVALID_HASH", "transaction.hash")
    if not QTY.fullmatch(t["chainId"]):
        raise Fail("RNAE_FIELD_TYPE", "transaction.chainId")
    if t["chainId"] != "0xaa36a7":
        raise Fail("RNAE_WRONG_NETWORK", "transaction.chainId")
    if t["type"] not in ("0x0", "0x1", "0x2"):
        raise Fail("RNAE_UNSUPPORTED_TRANSACTION_TYPE", "transaction.type")
    if t["to"] is None:
        raise Fail("RNAE_CONTRACT_CREATION", "transaction.to")
    for f in ("from", "to"):
        if not ADDR.fullmatch(t[f]):
            raise Fail("RNAE_INVALID_ADDRESS", "transaction." + f)
    if not DATA.fullmatch(t["input"]):
        raise Fail("RNAE_INVALID_INPUT", "transaction.input")
    present = sum(t[f] is not None for f in BLOCK)
    if present not in (0, 3):
        raise Fail("RNAE_INVALID_BLOCK_REFERENCE", "transaction")
    if present:
        if not HASH.fullmatch(t["blockHash"]):
            raise Fail("RNAE_INVALID_BLOCK_REFERENCE", "transaction.blockHash")
        for f in ("blockNumber", "transactionIndex"):
            if not QTY.fullmatch(t[f]):
                raise Fail("RNAE_INVALID_BLOCK_REFERENCE", "transaction." + f)
    if r is None:
        return
    need(r, [("transactionHash", s), ("blockHash", s), ("blockNumber", s), ("transactionIndex", s), ("from", s), ("status", s), ("to", sn), ("contractAddress", sn)], "receipt")
    for f, own in (("transactionHash", "hash"), ("from", "from"), ("to", "to")):
        if r[f] != t[own]:
            raise Fail("RNAE_RECEIPT_MISMATCH", "receipt." + f)
    for f in BLOCK:
        if t[f] is None or r[f] != t[f]:
            raise Fail("RNAE_CONFLICTING_BLOCK_REFERENCE", "receipt." + f)


def evm_anchor(t, expected, rec):
    if t["input"] == "0x":
        raise Fail("RNAE_MISSING_ANCHOR", "transaction.input")
    take_payload(rec, bytes.fromhex(t["input"][2:]), expected, "transaction.input")


def evm_status(t, r):
    if r is None or t["blockHash"] is None:
        raise Fail("RNAE_PENDING", "receipt" if r is None else "transaction.blockHash")
    if r["contractAddress"] is not None:
        raise Fail("RNAE_CONTRACT_CREATION", "receipt.contractAddress")
    if r["status"] == "0x0":
        raise Fail("RNAE_TRANSACTION_REVERTED", "receipt.status")
    if r["status"] != "0x1":
        raise Fail("RNAE_INVALID_STATUS", "receipt.status")


def verify_evm(data: bytes, expected):
    rec = new_record(EVM, expected, data)
    box = {}

    def structure():
        obs = parse_observation(data, EVM)
        box["t"], box["r"] = obs["transaction"], obs["receipt"]
        evm_structure(box["t"], box["r"])

    if run(rec["findings"], structure):
        t, r = box["t"], box["r"]
        rec["transaction"] = {f: t[f] for f in ("hash", "blockHash", "blockNumber", "transactionIndex", "from", "to")}
        run(rec["findings"], lambda: evm_anchor(t, expected, rec))
        run(rec["findings"], lambda: evm_status(t, r))
    return finish(rec, "UNRESOLVED", "evm_finality")


# --- dual-chain report (§6) ----------------------------------------------------------------------

def verify_dual(xrpl, evm, expected):
    records = {}
    if xrpl is not None:
        records["xrpl"] = verify_xrpl(xrpl, expected)
    if evm is not None:
        records["evm"] = verify_evm(evm, expected)
    findings = []
    for slot in ("xrpl", "evm"):
        if slot not in records:
            findings.append({"code": "RNAD_MISSING_RECORD", "severity": "error", "subject": slot})
    for slot in ("xrpl", "evm"):
        if slot in records and records[slot]["outcome"] != "PASS":
            findings.append({"code": "RNAD_RECORD_NOT_PASSED", "severity": "error", "subject": slot})
    p = [records.get(s, {}).get("payload") for s in ("xrpl", "evm")]
    if all(p) and p[0]["hex"] != p[1]["hex"]:
        findings.append({"code": "RNAD_PAYLOAD_DIFFERS", "severity": "error", "subject": "pair"})
    conclusions = []
    if all(x and x["matchesExpected"] for x in p) and p[0]["hex"] == p[1]["hex"]:
        conclusions.append("PAYLOAD_MATCH")
    if all(s in records and records[s]["outcome"] == "PASS" for s in ("xrpl", "evm")):
        conclusions.append("RECORDS_CONSISTENT")
    conclusions.append("CHAIN_INCLUSION_UNVERIFIED")
    outcomes = [r["outcome"] for r in records.values()]
    outcome = "FAIL"
    if "PAYLOAD_MATCH" in conclusions and "RECORDS_CONSISTENT" in conclusions:
        outcome = "PASS"
    elif len(outcomes) == 2 and "UNSUPPORTED" in outcomes and "FAIL" not in outcomes:
        outcome = "UNSUPPORTED"
    return {
        "format": "rnnet.anchor-verification-report.v1", "expectedCommitment": expected, "outcome": outcome,
        "conclusions": conclusions, "records": records, "findings": findings,
        "statements": [
            {"subject": "chainInclusion", "classification": "UNRESOLVED", "basis": "No authenticated proof of inclusion was verified on either network."},
            {"subject": "anchoredEvidence", "classification": "UNRESOLVED", "basis": "An anchor binds a commitment; it says nothing about whether the evidence is true or the event happened."},
        ],
    }


# --- vector checks ---------------------------------------------------------------------------------

def main(root: Path) -> int:
    load = lambda n: json.loads((root / f"vectors/anchor/{n}.json").read_text("utf-8"))["vectors"]
    failures, count = [], 0
    for v in load("payload"):
        count += 1
        try:
            got = ("ok", decode_payload(bytes.fromhex(v["payloadHex"])))
        except Fail as e:
            got = ("error", e.code)
        want = ("error", v["expectedError"]) if "expectedError" in v else ("ok", v["expectedCommitment"])
        if got != want:
            failures.append(("payload", v["id"], got))
        if got[0] == "ok" and v["payloadHex"] != encode_payload(got[1]).hex():
            failures.append(("payload-encode", v["id"]))
    for name, fn in (("xrpl", verify_xrpl), ("evm", verify_evm)):
        for v in load(name):
            count += 1
            rec = fn(v["input"].encode("utf-8"), v["expectedCommitment"])
            if rec["outcome"] != v["expectedOutcome"] or [f["code"] for f in rec["findings"]] != v["expectedFindings"]:
                failures.append((name, v["id"], rec["outcome"], [f["code"] for f in rec["findings"]]))
            elif ref.canonicalize(rec) != v["expectedRecord"]:
                failures.append((name, v["id"], "record differs"))
    for v in load("dual"):
        count += 1
        enc = lambda k: v[k].encode("utf-8") if k in v else None
        rep = verify_dual(enc("xrpl"), enc("evm"), v["expectedCommitment"])
        if rep["outcome"] != v["expectedOutcome"] or rep["conclusions"] != v["expectedConclusions"] or ref.canonicalize(rep) != v["expectedReport"]:
            failures.append(("dual", v["id"], rep["outcome"], rep["conclusions"]))
        if "CHAIN_PROVEN" in rep["conclusions"]:
            failures.append(("dual", v["id"], "CHAIN_PROVEN must never be produced"))
    for f in failures:
        print("FAIL", *f)
    print(f"anchor reference: {count - len(failures)}/{count} vectors agree")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
