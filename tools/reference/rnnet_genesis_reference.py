#!/usr/bin/env python3
"""Independent check of the Genesis Proof 01 golden values (RN-NET-03B2-A).

Recomputes, from fixtures/genesis-proof-01/ and the specifications, without the JavaScript
packages: the evidence file SHA-256, the RN-NET-02 verification report (Ed25519 included), the
RN-NET-01 commitment, the 42-byte anchor payload, the XRPL memo and the Sepolia input, the
Sepolia intrinsic gas, the intended unsigned transaction templates, and the dual-chain report of
the synthetic rehearsal observations. Reuses the other Python references, loaded by path.
Offline; standard library only. Run: python3 -I -B <this file>
"""
import hashlib
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


ref = load("rnnet_reference")
evidence_ref = load("rnnet_evidence_reference")
anchor_ref = load("rnnet_anchor_reference")

MEMO_TYPE = b"rnnet.anchor-payload.v1".hex().upper()
SEPOLIA_CHAIN_ID = hex(11155111)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def prague_gas(data: bytes) -> dict:
    zero = data.count(0)
    nonzero = len(data) - zero
    tokens = zero + 4 * nonzero
    standard, floor = 21000 + 4 * tokens, 21000 + 10 * tokens
    return {"zeroBytes": zero, "nonzeroBytes": nonzero, "tokens": tokens, "standard": standard, "floor": floor, "gasUsed": max(standard, floor)}


def checks(root: Path):
    d = root / "fixtures/genesis-proof-01"
    evidence = (d / "evidence.json").read_bytes()
    envelope = (d / "envelope.json").read_bytes()
    g = json.loads((d / "golden.json").read_text("utf-8"))
    commitment = g["envelope"]["commitment"]
    payload = bytes.fromhex(g["anchorPayload"]["hex"])

    yield "format", g["format"] == "rnnet.genesis-preflight.v1"
    yield "evidence file sha256", sha(evidence) == g["evidence"]["fileSha256"]
    yield "envelope file sha256", sha(envelope) == g["envelope"]["fileSha256"]
    doc = json.loads(evidence)
    yield "evidence digest", "sha256:" + evidence_ref.evidence_digest(doc["body"]).hex() == g["evidence"]["evidenceDigest"]
    yield "evidence is synthetic", doc["format"] == "rnnet.synthetic-evidence.v1" and "Synthetic" in doc["body"]["payload"]["note"]

    rep = evidence_ref.report(evidence, (envelope, commitment))
    yield "RN-NET-02 outcome PASS", rep["outcome"] == "PASS" and rep["findings"] == []
    yield "RN-NET-02 report text", ref.canonicalize(rep) == g["evidence"]["verification"]["report"]
    yield "RN-NET-02 report sha256", sha(ref.canonicalize(rep).encode("utf-8")) == g["evidence"]["verification"]["reportSha256"]

    _, computed = ref.commitment(envelope)
    yield "RN-NET-01 commitment", computed == commitment and ref.verify(envelope, commitment) == {"valid": True}
    env = json.loads(envelope)
    yield "envelope binds the file and digest", env["sourceFileSha256"] == sha(evidence) and env["sourceEvidenceDigest"] == g["evidence"]["evidenceDigest"]

    yield "payload encodes", anchor_ref.encode_payload(commitment) == payload and len(payload) == 42 == g["anchorPayload"]["length"]
    yield "payload decodes", anchor_ref.decode_payload(payload) == commitment
    yield "payload header", payload[:10] == b"RNNETANC\x01\x01"

    x = g["xrpl"]
    t = x["unsignedTemplate"]
    yield "XRPL memo type", x["memoType"] == MEMO_TYPE
    yield "XRPL memo data", x["memoData"] == payload.hex().upper()
    yield "XRPL template: AccountSet, one exact memo, no NetworkID", (
        t["TransactionType"] == "AccountSet" and "NetworkID" not in t and "Flags" not in t
        and t["Memos"] == [{"Memo": {"MemoType": MEMO_TYPE, "MemoData": payload.hex().upper()}}]
        and set(t) == {"TransactionType", "Account", "Fee", "Sequence", "LastLedgerSequence", "Memos"}
    )
    yield "XRPL fee within cap", t["Fee"] == x["feeDrops"] and 0 < int(x["feeDrops"]) <= int(x["maxFeeDrops"]) <= 1000
    # 0xF9 Memos, 0xEA Memo, 0x7C+len MemoType, 0x7D+len MemoData, 0xE1, 0xF1.
    yield "XRPL memos size", x["memosSerializedBytes"] == 1 + 1 + (2 + 23) + (2 + 42) + 1 + 1 <= 1024

    s = g["sepolia"]
    e = s["unsignedTemplate"]
    yield "Sepolia chain id", s["chainId"] == e["chainId"] == SEPOLIA_CHAIN_ID == "0xaa36a7"
    yield "Sepolia input is exactly the payload", s["input"] == e["input"] == "0x" + payload.hex()
    yield "Sepolia template: type 2, zero value, self-send to bind, empty access list", (
        e["type"] == "0x2" and e["value"] == "0x0" and e["accessList"] == [] and e["to"] is None and e["from"] is None
    )
    gas = prague_gas(payload)
    yield "Sepolia intrinsic gas", all(s["gas"][k] == v for k, v in gas.items())
    yield "Sepolia gas limit covers intrinsic", int(e["gas"], 16) == s["gas"]["gasLimit"] >= gas["gasUsed"]
    yield "Sepolia fee cap", int(s["maxCostAtCapWei"]) == s["gas"]["gasLimit"] * int(s["maxFeePerGasCapWei"]) and int(e["maxPriorityFeePerGas"], 16) == int(s["maxPriorityFeePerGasWei"]) <= int(s["maxFeePerGasCapWei"])

    r = g["rehearsal"]
    dual = anchor_ref.verify_dual(r["xrplObservation"].encode("utf-8"), r["evmObservation"].encode("utf-8"), commitment)
    yield "rehearsal dual PASS", dual["outcome"] == "PASS" == r["expectedOutcome"] and dual["conclusions"] == r["expectedConclusions"]
    yield "rehearsal report text", ref.canonicalize(dual) == r["expectedReport"]
    yield "rehearsal never CHAIN_PROVEN", "CHAIN_PROVEN" not in dual["conclusions"]
    xo = json.loads(r["xrplObservation"])["tx"]["tx_json"]
    eo = json.loads(r["evmObservation"])["transaction"]
    yield "rehearsal transactions follow the templates", (
        xo["Memos"] == t["Memos"] and xo["TransactionType"] == "AccountSet" and "NetworkID" not in xo
        and eo["input"] == e["input"] and eo["to"] == eo["from"] and eo["chainId"] == SEPOLIA_CHAIN_ID
    )
    yield "rehearsal against another commitment fails", anchor_ref.verify_dual(
        r["xrplObservation"].encode("utf-8"), r["evmObservation"].encode("utf-8"), "sha256:" + "00" * 32
    )["outcome"] == "FAIL"


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"genesis reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
