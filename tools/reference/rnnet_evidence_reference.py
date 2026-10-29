#!/usr/bin/env python3
"""Second implementation of rnnet.synthetic-evidence.v1 and rnnet.verification-report.v1.

Written from spec/rnnet.synthetic-evidence.v1.md and spec/rnnet.verification-report.v1.md,
with Ed25519 implemented from RFC 8032 itself (no cryptography library, no OpenSSL), and
checked against every vector in vectors/evidence/. It rebuilds each expected report in full
and compares the canonical text byte for byte.

It reuses the canonical JSON parser and serializer and the commitment validation of
rnnet_reference.py, loaded by path. Standard library only. Run: python3 -I -B <this file>
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
RefError = ref.RefError

# --- rnnet.synthetic-evidence.v1 ------------------------------------------------------------

FORMAT = "rnnet.synthetic-evidence.v1"
CANONICAL = "rnnet.canonical-json.v1"
MAX_EVIDENCE = 262_144
MAX_PAYLOAD = 65_536
MAX_SIGNATURES = 16
DIGEST_DOMAIN = b"rnnet:synthetic-evidence:digest:v1" + bytes([0])
SIGNATURE_DOMAIN = b"rnnet:synthetic-evidence:signature:v1" + bytes([0])

DOC_FIELDS = ["format", "canonicalization", "body", "digest", "signatures"]
DOC_TYPES = {"format": str, "canonicalization": str, "body": dict, "digest": str, "signatures": list}
BODY_FIELDS = ["evidenceId", "issuer", "subject", "action", "outcome", "payload"]
RECORD_FIELDS = ["keyId", "algorithm", "publicKey", "signature"]
OUTCOMES = ["succeeded", "failed", "rejected", "unknown"]
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
ACTION = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)*")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
ALGO_PREFIX = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*:")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
UNSUPPORTED = {
    "RNSE_UNSUPPORTED_FORMAT", "RNSE_UNSUPPORTED_VERSION", "RNSE_UNSUPPORTED_CANONICALIZATION",
    "RNSE_UNSUPPORTED_DIGEST_ALGORITHM", "RNSE_UNSUPPORTED_SIGNATURE_ALGORITHM",
}


class Invalid(Exception):
    def __init__(self, code, subject):
        super().__init__(code)
        self.code = code
        self.subject = subject


def utf16(key):
    return key.encode("utf-16-be")


def is_ident(s):
    return 1 <= len(s) <= 128 and IDENT.fullmatch(s) is not None


def members(obj, fields, path):
    # An unknown member is reported by its containing object, never by its (input) name.
    if any(k not in fields for k in obj):
        raise Invalid("RNSE_UNKNOWN_FIELD", path[:-1] if path.endswith(".") else path)
    for f in fields:
        if f not in obj:
            raise Invalid("RNSE_MISSING_FIELD", path + f)


def is_type(value, expected):
    if expected is str:
        return isinstance(value, str)
    if expected is dict:
        return isinstance(value, dict)
    return isinstance(value, list)


def validate(data: bytes):
    """§6: the parsed document, or Invalid / RefError for the first failure."""
    if len(data) > MAX_EVIDENCE:
        raise Invalid("RNSE_EVIDENCE_TOO_LARGE", "")
    doc = ref.parse(data)
    if not isinstance(doc, dict):
        raise Invalid("RNSE_NOT_OBJECT", "")
    if "format" not in doc:
        raise Invalid("RNSE_MISSING_FIELD", "format")
    if not isinstance(doc["format"], str):
        raise Invalid("RNSE_FIELD_TYPE", "format")
    if doc["format"] != FORMAT:
        family = doc["format"].startswith("rnnet.synthetic-evidence.")
        raise Invalid("RNSE_UNSUPPORTED_VERSION" if family else "RNSE_UNSUPPORTED_FORMAT", "format")
    members(doc, DOC_FIELDS, "")
    for f in DOC_FIELDS:
        if not is_type(doc[f], DOC_TYPES[f]):
            raise Invalid("RNSE_FIELD_TYPE", f)
    if doc["canonicalization"] != CANONICAL:
        raise Invalid("RNSE_UNSUPPORTED_CANONICALIZATION", "canonicalization")
    digest = doc["digest"]
    if not SHA256.fullmatch(digest):
        m = ALGO_PREFIX.match(digest)
        unsupported = m is not None and m.group(0) != "sha256:"
        raise Invalid("RNSE_UNSUPPORTED_DIGEST_ALGORITHM" if unsupported else "RNSE_INVALID_DIGEST", "digest")

    body = doc["body"]
    members(body, BODY_FIELDS, "body.")
    for f in BODY_FIELDS:
        if not is_type(body[f], dict if f == "payload" else str):
            raise Invalid("RNSE_FIELD_TYPE", "body." + f)
    for f in ("evidenceId", "issuer", "subject"):
        if not is_ident(body[f]):
            raise Invalid("RNSE_INVALID_FIELD_VALUE", "body." + f)
    if not (1 <= len(body["action"]) <= 128 and ACTION.fullmatch(body["action"])):
        raise Invalid("RNSE_INVALID_FIELD_VALUE", "body.action")
    if body["outcome"] not in OUTCOMES:
        raise Invalid("RNSE_INVALID_FIELD_VALUE", "body.outcome")
    if len(ref.canonicalize(body["payload"]).encode("utf-8")) > MAX_PAYLOAD:
        raise Invalid("RNSE_PAYLOAD_TOO_LARGE", "body.payload")

    records = doc["signatures"]
    if len(records) > MAX_SIGNATURES:
        raise Invalid("RNSE_TOO_MANY_SIGNATURES", "signatures")
    for i, rec in enumerate(records):
        path = f"signatures[{i}]"
        if not isinstance(rec, dict):
            raise Invalid("RNSE_FIELD_TYPE", path)
        members(rec, RECORD_FIELDS, path + ".")
        for f in RECORD_FIELDS:
            if not isinstance(rec[f], str):
                raise Invalid("RNSE_FIELD_TYPE", f"{path}.{f}")
        if rec["algorithm"] != "ed25519":
            raise Invalid("RNSE_UNSUPPORTED_SIGNATURE_ALGORITHM", path + ".algorithm")
        if not is_ident(rec["keyId"]):
            raise Invalid("RNSE_INVALID_FIELD_VALUE", path + ".keyId")
        if not HEX64.fullmatch(rec["publicKey"]):
            raise Invalid("RNSE_INVALID_PUBLIC_KEY_ENCODING", path + ".publicKey")
        if not HEX128.fullmatch(rec["signature"]):
            raise Invalid("RNSE_INVALID_SIGNATURE_ENCODING", path + ".signature")
    for i in range(1, len(records)):
        a, b = utf16(records[i - 1]["keyId"]), utf16(records[i]["keyId"])
        if a == b:
            raise Invalid("RNSE_DUPLICATE_KEY_ID", f"signatures[{i}].keyId")
        if a > b:
            raise Invalid("RNSE_SIGNATURES_NOT_SORTED", f"signatures[{i}].keyId")
    seen = set()
    for i, rec in enumerate(records):
        if rec["publicKey"] in seen:
            raise Invalid("RNSE_DUPLICATE_PUBLIC_KEY", f"signatures[{i}].publicKey")
        seen.add(rec["publicKey"])
    return doc


def evidence_digest(body) -> bytes:
    return hashlib.sha256(DIGEST_DOMAIN + ref.canonicalize(body).encode("utf-8")).digest()


# --- Ed25519, from RFC 8032 §5.1 (strict profile of synthetic-evidence §5.3) ---------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def point_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = point_add(q, p)
        p = point_add(p, p)
        s >>= 1
    return q


def point_equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def decompress(s: bytes):
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


G_Y = 4 * pow(5, P - 2, P) % P
G = (recover_x(G_Y, 0), G_Y, 1, recover_x(G_Y, 0) * G_Y % P)
IDENTITY = (0, 1, 1, 0)


def ed25519(public_key: bytes, signature: bytes, message: bytes) -> str:
    a = decompress(public_key)
    if a is None or point_equal(point_mul(8, a), IDENTITY):
        return "KEY_REJECTED"
    r = decompress(signature[:32])
    if r is None:
        return "INVALID"
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return "INVALID"
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    return "VALID" if point_equal(point_mul(s, G), point_add(r, point_mul(k, a))) else "INVALID"


# --- rnnet.verification-report.v1 -------------------------------------------------------------

BASIS = {
    "digest": "Recomputed from the supplied body under rnnet.synthetic-evidence.v1.",
    "claim": "Stated in the evidence and bound by its digest; not checked against anything else.",
    "event": "Nothing in the evidence can show that the described event happened.",
    "none": "No signatures were supplied; nothing is known about who produced the evidence.",
    "embedded": "The signature verifies under a public key carried by the evidence itself.",
    "signer": "No trust source binds this public key to an identity.",
    "commitment": "Recomputed from the supplied envelope and equal to the presented commitment.",
    "member": "Equal to the value the verifier established from the supplied evidence.",
    "sourceRef": "An identifier only; it was not dereferenced.",
}


def hexdigest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def finding(code, subject):
    return {"code": code, "severity": "unsupported" if code in UNSUPPORTED else "error", "subject": subject}


def statement(subject, classification, basis):
    return {"subject": subject, "classification": classification, "basis": BASIS[basis]}


def report(data: bytes, commitment=None):
    rep = {
        "format": "rnnet.verification-report.v1",
        "profile": FORMAT,
        "taxonomy": "rnnet.verification-taxonomy.v1",
        "outcome": "PASS",
        "input": {"sha256": hexdigest(data)},
        "findings": [],
        "statements": [],
    }
    try:
        doc = validate(data)
    except (Invalid, RefError) as e:
        rep["findings"].append(finding(e.code, getattr(e, "subject", "")))
        rep["outcome"] = "UNSUPPORTED" if e.code in UNSUPPORTED else "FAIL"
        return rep

    body = doc["body"]
    digest = evidence_digest(body)
    computed = "sha256:" + digest.hex()
    rep["evidence"] = {"evidenceId": body["evidenceId"], "declaredDigest": doc["digest"], "computedDigest": computed}
    if computed == doc["digest"]:
        rep["statements"].append(statement("evidenceDigest", "VERIFIED", "digest"))
        for claim in ("issuer", "subject", "action", "outcome", "payload"):
            rep["statements"].append(statement("body." + claim, "CLAIMED", "claim"))
    else:
        rep["findings"].append(finding("RNSE_DIGEST_MISMATCH", "digest"))
    rep["statements"].append(statement("eventOccurrence", "UNRESOLVED", "event"))

    message = SIGNATURE_DOMAIN + digest
    results = []
    for i, rec in enumerate(doc["signatures"]):
        result = ed25519(bytes.fromhex(rec["publicKey"]), bytes.fromhex(rec["signature"]), message)
        if result == "KEY_REJECTED":
            rep["findings"].append(finding("RNSE_PUBLIC_KEY_REJECTED", f"signatures[{i}]"))
        if result == "INVALID":
            rep["findings"].append(finding("RNSE_SIGNATURE_INVALID", f"signatures[{i}]"))
        results.append({"keyId": rec["keyId"], "publicKey": rec["publicKey"], "result": result})
    rep["signatures"] = results
    if not results:
        rep["statements"].append(statement("signatures", "UNRESOLVED", "none"))
    for i, r in enumerate(results):
        if r["result"] == "VALID":
            rep["statements"].append(statement(f"signatures[{i}]", "CONSISTENT_UNDER_EMBEDDED_KEYS", "embedded"))
    for i, _ in enumerate(results):
        rep["statements"].append(statement(f"signerIdentity[{i}]", "UNRESOLVED", "signer"))

    if commitment is not None:
        rep["commitment"] = check_commitment(commitment, computed, rep)
    if rep["findings"]:
        rep["outcome"] = "FAIL"
    return rep


def check_commitment(commitment, computed, rep):
    envelope_bytes, presented = commitment
    section = {"result": "MATCH"}
    if ref.DIGEST.fullmatch(presented):
        section["presentedDigest"] = presented
    env, code = None, None
    if not ref.DIGEST.fullmatch(presented):
        code = "RNEC_INVALID_COMMITMENT_DIGEST"
    else:
        try:
            env = ref.validate(ref.parse(envelope_bytes))
        except RefError as e:
            code = e.code
        if env is not None:
            recomputed = "sha256:" + hashlib.sha256(ref.DOMAIN + ref.canonicalize(env).encode("utf-8")).hexdigest()
            if recomputed != presented:
                code = "RNEC_DIGEST_MISMATCH"
    if code is not None:
        subject = "commitment.presentedDigest" if code in ("RNEC_INVALID_COMMITMENT_DIGEST", "RNEC_DIGEST_MISMATCH") else "commitment"
        rep["findings"].append(finding(code, subject))
        section["result"] = "MISMATCH"
    if env is None:
        return section
    valid = code is None
    if valid:
        rep["statements"].append(statement("commitment", "VERIFIED", "commitment"))
    expected = [
        ("sourceFormat", FORMAT, "RNSE_COMMITMENT_SOURCE_FORMAT_MISMATCH"),
        ("sourceCanonicalization", CANONICAL, "RNSE_COMMITMENT_CANONICALIZATION_MISMATCH"),
        ("sourceEvidenceDigest", computed, "RNSE_COMMITMENT_EVIDENCE_DIGEST_MISMATCH"),
        ("sourceFileSha256", rep["input"]["sha256"], "RNSE_COMMITMENT_SOURCE_FILE_MISMATCH"),
    ]
    for member, wanted, mismatch in expected:
        if env[member] == wanted:
            if valid:
                rep["statements"].append(statement("commitment." + member, "VERIFIED", "member"))
        else:
            rep["findings"].append(finding(mismatch, "commitment." + member))
            section["result"] = "MISMATCH"
    section["sourceRef"] = env["sourceRef"]
    rep["statements"].append(statement("commitment.sourceRef", "UNRESOLVED", "sourceRef"))
    return section


# --- RFC 8032 §7.1 test vectors (public key, message, signature) -----------------------------

RFC8032 = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


def main(root: Path) -> int:
    failures = []
    for pub, msg, sig in RFC8032:
        if ed25519(bytes.fromhex(pub), bytes.fromhex(sig), bytes.fromhex(msg)) != "VALID":
            failures.append(("rfc8032", pub[:16]))
    vectors = json.loads((root / "vectors/evidence/evidence.json").read_text("utf-8"))["vectors"]
    for v in vectors:
        commitment = None
        if "commitment" in v:
            commitment = (v["commitment"]["envelope"].encode("utf-8"), v["commitment"]["digest"])
        rep = report(ref.input_bytes(v), commitment)
        codes = [f["code"] for f in rep["findings"]]
        if rep["outcome"] != v["expectedOutcome"] or codes != v["expectedFindings"]:
            failures.append((v["id"], rep["outcome"], codes))
        elif ref.canonicalize(rep) != v["expectedReport"]:
            failures.append((v["id"], "report differs"))
    for f in failures:
        print("FAIL", *f)
    print(f"evidence reference: {len(vectors) - len([f for f in failures if f[0] != 'rfc8032'])}/{len(vectors)} vectors agree"
          f"{'' if not any(f[0] == 'rfc8032' for f in failures) else '; RFC 8032 vectors FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(HERE.parent.parent))
