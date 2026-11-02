#!/usr/bin/env python3
"""Independent reproduction of the RN-NET-03B2-C4 key tool decisions (ADR-RN-017 Amendment C1).

Re-implements, without the JavaScript packages, over fixtures/keytool-c4/cases.json:
  - key generation from a given byte source: Ed25519 (RFC 8032, the seed is the key) and
    secp256k1 by rejection sampling (accept the first 32-byte draw k with 1 <= k < n, at most 8
    draws; never reduce modulo n), the public key and the address;
  - rnnet.sign-log-entry.v1: the entry shapes, the digest chain, times, the KEY_CREATED,
    SIGNING, SIGNED and RESIGN_BASIS rules, and the first entry that breaks one;
  - the signing decision (SIGN, COMPLETE, RESIGN, or the refusal code);
  - the rnnet.submission-status.v1 basis check and its digest.

With --check-log DIR it reads a real sign-log directory the way tools/keytool/signlog-store.mjs
does (names, temporary files, modes, canonical bytes) and prints one JSON verdict.

The secp256k1 and Ed25519 arithmetic and the XRPL and EVM address code are those of
rnnet_tx_reference.py (integer secp256k1, FIPS 202 Keccak, RFC 8032). No cryptography library;
offline; standard library only.
Run: python3 -I -B <this file> [--check-log DIR]
"""
import datetime
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tx = load("rnnet_tx_reference")
canon = tx.canon

XRPL, SEP = "xrpl:testnet", "evm:11155111"
NETWORKS = {XRPL, SEP}
PURPOSES = {"genesis-proof-01"}
MAX_DRAWS = 8
FORMAT = "rnnet.sign-log-entry.v1"
DOMAIN = b"rnnet:sign-log-entry:v1\x00"
STATUS_FORMAT = "rnnet.submission-status.v1"
STATUS_DOMAIN = b"rnnet:submission-status:v1\x00"
MAX_ENTRY_BYTES = 4096
MAX_ENTRIES = 10_000

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SEQUENCE = re.compile(r"(?:0|[1-9][0-9]{0,19})")
XRPL_ACCOUNT = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
XRPL_PUBLIC_KEY = re.compile(r"ED[0-9A-F]{64}")
XRPL_HASH = re.compile(r"[0-9A-F]{64}")
EVM_ADDRESS = re.compile(r"0x[0-9a-f]{40}")
EVM_PUBLIC_KEY = re.compile(r"04[0-9a-f]{128}")
EVM_HASH = re.compile(r"0x[0-9a-f]{64}")
LIMIT = {XRPL: 2**32, SEP: 2**64}

COMMON = ["address", "format", "index", "network", "previous", "purpose", "recordedAt", "type"]
FIELDS = {
    "KEY_CREATED": sorted(COMMON + ["keyFileSha256", "publicKey"]),
    "SIGNING": sorted(COMMON + ["intentDigest", "sequence"]),
    "SIGNED": sorted(COMMON + ["blobSha256", "intentDigest", "sequence", "transactionHash"]),
    "RESIGN_BASIS": sorted(COMMON + ["expiredIntentDigest", "expiredTransactionHash", "intentDigest", "sequence", "statusRecordDigest"]),
}


class Refusal(Exception):
    def __init__(self, code, index=None):
        super().__init__(code)
        self.code = code
        self.index = index


def tagged(domain: bytes, value) -> str:
    return "sha256:" + hashlib.sha256(domain + canon(value)).hexdigest()


def is_str(v, pattern):
    return isinstance(v, str) and pattern.fullmatch(v) is not None


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# --- key generation ----------------------------------------------------------------------------

def generate(network, draws):
    """(accepted draw number, public key, address) from the given byte draws; Refusal on failure."""
    draws = [bytes.fromhex(d) for d in draws]
    if network == XRPL:
        if not draws or len(draws[0]) != 32:
            raise Refusal("RNTX_KEY_INVALID")
        pub = b"\xed" + tx.ed25519_public(draws[0])
        return 1, pub.hex().upper(), tx.address_from_public_key(pub)
    for number, draw in enumerate(draws[:MAX_DRAWS], start=1):
        if len(draw) != 32:
            raise Refusal("RNTX_KEY_INVALID")
        k = int.from_bytes(draw, "big")
        if 1 <= k < tx.N:
            point = tx.ec_mul(k, tx.SG)
            pub = "04" + point[0].to_bytes(32, "big").hex() + point[1].to_bytes(32, "big").hex()
            return number, pub, tx.evm_address(point)
    raise Refusal("RNTX_KEY_INVALID")


def address_matches(network, address, public_key):
    try:
        if network == XRPL:
            tx.decode_address(address)
            return tx.address_from_public_key(bytes.fromhex(public_key)) == address
        raw = bytes.fromhex(public_key)
        x, y = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
        if x >= tx.SP or y >= tx.SP or (y * y - x * x * x - 7) % tx.SP != 0:
            return False
        return tx.evm_address((x, y)) == address
    except (ValueError, IndexError):
        return False


# --- the sign log --------------------------------------------------------------------------------

def check_shape(e, i):
    def bad():
        raise Refusal("RNKEY_SIGNLOG_INVALID", i)

    if not isinstance(e, dict) or not isinstance(e.get("type"), str) or e["type"] not in FIELDS:
        bad()
    if sorted(e) != FIELDS[e["type"]]:
        bad()
    if e["format"] != FORMAT or not is_int(e["index"]) or e["index"] != i:
        bad()
    if not isinstance(e["network"], str) or not isinstance(e["purpose"], str) or e["network"] not in NETWORKS or e["purpose"] not in PURPOSES:
        bad()
    if not is_str(e["recordedAt"], TIME) or not valid_time(e["recordedAt"]):
        bad()
    xr = e["network"] == XRPL
    if not is_str(e["address"], XRPL_ACCOUNT if xr else EVM_ADDRESS):
        bad()
    for f in ("intentDigest", "blobSha256", "keyFileSha256", "expiredIntentDigest", "statusRecordDigest"):
        if f in e and not is_str(e[f], DIGEST):
            bad()
    for f in ("transactionHash", "expiredTransactionHash"):
        if f in e and not is_str(e[f], XRPL_HASH if xr else EVM_HASH):
            bad()
    if "sequence" in e and (not is_str(e["sequence"], SEQUENCE) or int(e["sequence"]) >= LIMIT[e["network"]]):
        bad()
    if e["type"] == "KEY_CREATED":
        if not is_str(e["publicKey"], XRPL_PUBLIC_KEY if xr else EVM_PUBLIC_KEY) or not address_matches(e["network"], e["address"], e["publicKey"]):
            bad()
    if e["type"] == "RESIGN_BASIS" and not xr:
        bad()


def valid_time(text):
    try:
        datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def replay(entries):
    """The per-address state after the whole log; Refusal(RNKEY_SIGNLOG_INVALID, index) otherwise."""
    if not isinstance(entries, list):
        raise Refusal("RNKEY_SIGNLOG_INVALID", 0)
    keys, slots, used = {}, set(), set()
    previous, last = None, ""
    for i, e in enumerate(entries):
        check_shape(e, i)
        bad = Refusal("RNKEY_SIGNLOG_INVALID", i)
        if e["previous"] != previous or e["recordedAt"] < last:
            raise bad
        last = e["recordedAt"]
        previous = tagged(DOMAIN, e)
        if e["type"] == "KEY_CREATED":
            slot = (e["network"], e["purpose"])
            if e["address"] in keys or slot in slots:
                raise bad
            slots.add(slot)
            keys[e["address"]] = {"key": {k: e[k] for k in ("network", "purpose", "address", "publicKey", "keyFileSha256")},
                                  "sequence": None, "pending": None, "latest": None, "basis": None,
                                  "signed": {}, "digests": set(), "basis_for": {}}
            continue
        s = keys.get(e["address"])
        if s is None or s["key"]["network"] != e["network"] or s["key"]["purpose"] != e["purpose"]:
            raise bad
        seq = int(e["sequence"])
        d = e["intentDigest"]
        if e["type"] == "SIGNING":
            if s["pending"] is not None or d in s["digests"]:
                raise bad
            if s["sequence"] is not None:
                if seq != s["sequence"] or s["basis"] is None or s["basis"]["intentDigest"] != d:
                    raise bad
                s["basis_for"][d] = s["basis"]
                s["basis"] = None
            s["sequence"], s["pending"] = seq, d
            s["digests"].add(d)
        elif e["type"] == "SIGNED":
            if s["pending"] != d or s["sequence"] != seq:
                raise bad
            s["signed"][d] = i
            s["latest"] = (d, e["transactionHash"])
            s["pending"] = None
        elif e["type"] == "RESIGN_BASIS":
            if s["pending"] is not None or s["basis"] is not None or s["latest"] is None or s["sequence"] != seq:
                raise bad
            if s["latest"] != (e["expiredIntentDigest"], e["expiredTransactionHash"]):
                raise bad
            if e["statusRecordDigest"] in used or d in s["digests"]:
                raise bad
            used.add(e["statusRecordDigest"])
            s["basis"] = {"intentDigest": d, "statusRecordDigest": e["statusRecordDigest"], "expiredTransactionHash": e["expiredTransactionHash"]}
    return keys, used


def decide(entries, r):
    keys, used = replay(entries)
    s = keys.get(r["address"])
    if s is None or s["key"] != {"network": r["network"], "purpose": r["purpose"], "address": r["address"], "publicKey": r["publicKey"], "keyFileSha256": r["keyFileSha256"]}:
        raise Refusal("RNKEY_KEY_NOT_REGISTERED")
    d, resign, seq = r["intentDigest"], r["resign"], int(r["sequence"])

    def same(basis):
        return resign is None or (basis is not None and basis["statusRecordDigest"] == resign["statusRecordDigest"] and basis["expiredTransactionHash"] == resign["expiredTransactionHash"])

    if d in s["signed"]:
        raise Refusal("RNTX_ALREADY_SIGNED")
    if s["pending"] == d:
        if not same(s["basis_for"].get(d)):
            raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
        return "COMPLETE", ["SIGNED"]
    if s["pending"] is not None:
        raise Refusal("RNTX_SEQUENCE_UNRESOLVED")
    if s["sequence"] is None:
        if resign is not None:
            raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
        return "SIGN", ["SIGNING", "SIGNED"]
    if seq != s["sequence"]:
        raise Refusal("RNTX_SEQUENCE_UNRESOLVED")
    if s["basis"] is not None:
        if s["basis"]["intentDigest"] != d:
            raise Refusal("RNTX_SEQUENCE_UNRESOLVED")
        if not same(s["basis"]):
            raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
        return "SIGN", ["SIGNING", "SIGNED"]
    if resign is None:
        raise Refusal("RNTX_SEQUENCE_UNRESOLVED")
    if r["network"] != XRPL or resign["expiredTransactionHash"] != s["latest"][1] or resign["statusRecordDigest"] in used:
        raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
    return "RESIGN", ["RESIGN_BASIS", "SIGNING", "SIGNED"]


def resign_basis(record):
    if not isinstance(record, dict) or record.get("format") != STATUS_FORMAT or record.get("network") != XRPL or record.get("finding") != "EXPIRED":
        raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
    if not is_str(record.get("transactionHash"), XRPL_HASH):
        raise Refusal("RNKEY_RESIGN_BASIS_INVALID")
    return {"statusRecordDigest": tagged(STATUS_DOMAIN, record), "expiredTransactionHash": record["transactionHash"]}


# --- a sign-log directory ------------------------------------------------------------------------

ENTRY_NAME = re.compile(r"([0-9]{6})\.json")
TEMP_NAME = re.compile(r"\.([0-9]{6})\.json\.tmp")


def parse_stored(data: bytes):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.endswith("\n"):
        return None

    def no_dup(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate")
            out[k] = v
        return out

    try:
        value = json.loads(text[:-1], object_pairs_hook=no_dup, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ValueError:
        return None
    if not tx.canon_values_ok(value) or canon(value) + b"\n" != data:
        return None
    return value


def check_log_dir(path: Path):
    """{"ok": bool, "code": str|None, "index": int|None} for a sign-log directory."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or (st.st_mode & 0o777) != 0o700 or st.st_uid != os.getuid():
        return {"ok": False, "code": "RNKEY_LOCATION", "index": None}
    names = sorted(os.listdir(path))
    if any(TEMP_NAME.fullmatch(n) for n in names):
        return {"ok": False, "code": "RNKEY_SIGNLOG_INCOMPLETE", "index": None}
    if len(names) > MAX_ENTRIES:
        return {"ok": False, "code": "RNKEY_SIGNLOG_INVALID", "index": None}
    entries = []
    for i, name in enumerate(names):
        m = ENTRY_NAME.fullmatch(name)
        if not m or int(m.group(1)) != i:
            return {"ok": False, "code": "RNKEY_SIGNLOG_INVALID", "index": None}
        st = os.lstat(path / name)
        if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o777) != 0o600 or st.st_uid != os.getuid() or st.st_size > MAX_ENTRY_BYTES:
            return {"ok": False, "code": "RNKEY_SIGNLOG_INVALID", "index": None}
        value = parse_stored((path / name).read_bytes())
        if value is None:
            return {"ok": False, "code": "RNKEY_SIGNLOG_INVALID", "index": None}
        entries.append(value)
    try:
        replay(entries)
    except Refusal as r:
        return {"ok": False, "code": r.code, "index": r.index}
    return {"ok": True, "code": None, "index": None}


# --- the committed cases ---------------------------------------------------------------------------

def checks(root: Path):
    cases = json.loads((root / "fixtures/keytool-c4/cases.json").read_text("utf-8"))
    yield "fixture format", cases["format"] == "rnnet.keytool-c4-fixtures"
    for c in cases["keygen"]:
        try:
            draw, pub, address = generate(c["network"], c["draws"])
            got = {"ok": True, "acceptedDraw": draw, "publicKey": pub, "address": address}
        except Refusal as r:
            got = {"ok": False, "code": r.code}
        yield f"keygen {c['id']}", got == c["expect"]
        # Rejection sampling, not reduction: an accepted draw is the draw itself.
        if got["ok"] and c["network"] == SEP:
            k = int(c["draws"][got["acceptedDraw"] - 1], 16)
            yield f"keygen {c['id']} not reduced", all(not (1 <= int(d, 16) < tx.N) for d in c["draws"][: got["acceptedDraw"] - 1]) and 1 <= k < tx.N
    for c in cases["signlog"]:
        try:
            replay(c["entries"])
            got = {"ok": True}
        except Refusal as r:
            got = {"ok": False, "code": r.code, "index": r.index}
        yield f"signlog {c['id']}", got == c["expect"]
    for c in cases["decisions"]:
        try:
            action, append = decide(c["entries"], c["request"])
            got = {"ok": True, "action": action, "append": append}
        except Refusal as r:
            got = {"ok": False, "code": r.code}
        yield f"decision {c['id']}", got == c["expect"]
    for c in cases["statusRecords"]:
        try:
            got = {"ok": True, **resign_basis(c["record"])}
        except Refusal as r:
            got = {"ok": False, "code": r.code}
        yield f"status {c['id']}", got == c["expect"]


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print(f"FAIL {name}")
    print(f"rnnet_keytool_reference: {len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check-log":
        print(json.dumps(check_log_dir(Path(sys.argv[2])), sort_keys=True))
        sys.exit(0)
    sys.exit(main(HERE.parent.parent))
