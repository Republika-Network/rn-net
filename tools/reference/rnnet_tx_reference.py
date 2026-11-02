#!/usr/bin/env python3
"""Independent verification of RN-NET-03B2-B1 signed transactions (ADR-RN-017).

Re-implements, without the JavaScript packages and without any cryptography library:
  - Keccak-256 from FIPS 202 (Keccak-f[1600], original 0x01 padding; hashlib.sha3_256 differs);
  - secp256k1 public-key recovery with integer arithmetic (verification only; it never signs);
  - strict RLP and EIP-1559 decoding, and XRPL binary encoding and decoding for the Genesis
    AccountSet, with base58check addresses;
  - the ADR-RN-016 transaction checks and the rnnet.unsigned-tx-intent.v1 intent and digest;
  - the rnnet.signed-tx-verification.v1 record, with the same error precedence.
Ed25519 verification is the RFC 8032 code of rnnet_evidence_reference.py, loaded by path.

Checks the public known-answer vectors (vectors/signing/known-answers.json) and every committed
fixture and altered transaction (fixtures/signing-b1/golden.json). Offline; standard library
only. Run: python3 -I -B <this file>
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


ref = load("rnnet_reference")
ev = load("rnnet_evidence_reference")
anchor_ref = load("rnnet_anchor_reference")


class Fail(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


SAFE = 2**53 - 1


def canon_values_ok(value) -> bool:
    """rnnet.canonical-json.v1 value rules the JavaScript side enforces: safe integers only, no
    floats, no lone surrogates. (-0 and 1.0 written in JSON text are a parser matter: intents
    must be given as canonical JSON text, spec §2.)"""
    if isinstance(value, bool) or value is None:
        return True
    if isinstance(value, int):
        return -SAFE <= value <= SAFE
    if isinstance(value, float):
        return False
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, list):
        return all(canon_values_ok(v) for v in value)
    if isinstance(value, dict):
        return all(canon_values_ok(k) and canon_values_ok(v) for k, v in value.items())
    return False


def canon(value) -> bytes:
    return ref.canonicalize(value).encode("utf-8")


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --- Keccak-256 (FIPS 202 permutation, original Keccak padding) ----------------------------

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
MASK = (1 << 64) - 1


def keccak_f(a):
    for rc in RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & MASK) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & MASK if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    m = bytearray(data) + b"\x01"
    m += b"\x00" * ((-len(m)) % rate)
    m[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(m), rate):
        for j in range(rate // 8):
            a[j % 5][j // 5] ^= int.from_bytes(m[i + 8 * j:i + 8 * j + 8], "little")
        a = keccak_f(a)
    return b"".join(a[j % 5][j // 5].to_bytes(8, "little") for j in range(4))


# --- secp256k1 recovery ------------------------------------------------------------------------

SP = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SP == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, SP) % SP
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, SP) % SP
    x = (lam * lam - a[0] - b[0]) % SP
    return (x, (lam * (a[0] - x) - a[1]) % SP)


def ec_mul(k, p):
    out = None
    while k:
        if k & 1:
            out = ec_add(out, p)
        p = ec_add(p, p)
        k >>= 1
    return out


def evm_address(point) -> str:
    return "0x" + keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def recover_address(digest: bytes, y_parity: int, r: int, s: int):
    """The address that signed digest, or None if no public key recovers. Ranges are checked first by the caller."""
    x = r
    if x >= SP:
        return None
    y2 = (pow(x, 3, SP) + 7) % SP
    y = pow(y2, (SP + 1) // 4, SP)
    if y * y % SP != y2:
        return None
    if y % 2 != y_parity:
        y = SP - y
    z = int.from_bytes(digest, "big")
    ri = pow(r, -1, N)
    q = ec_add(ec_mul(s * ri % N, (x, y)), ec_mul((-z * ri) % N, SG))
    return None if q is None else evm_address(q)


# --- RLP (strict) and EIP-1559 -----------------------------------------------------------------

def rlp_encode(item) -> bytes:
    def head(length, short, long):
        if length <= 55:
            return bytes([short + length])
        lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([long + len(lb)]) + lb
    if isinstance(item, list):
        body = b"".join(rlp_encode(x) for x in item)
        return head(len(body), 0xC0, 0xF7) + body
    if len(item) == 1 and item[0] < 0x80:
        return bytes(item)
    return head(len(item), 0x80, 0xB7) + bytes(item)


def read_length(data, at, count):
    if at + count > len(data):
        raise Fail("RNTX_DECODE")
    if data[at] == 0:
        raise Fail("RNTX_NONCANONICAL_ENCODING")
    n = int.from_bytes(data[at:at + count], "big")
    if n <= 55:
        raise Fail("RNTX_NONCANONICAL_ENCODING")
    return n


MAX_RLP_DEPTH = 4


def rlp_at(data, at, depth=0):
    if at >= len(data):
        raise Fail("RNTX_DECODE")
    b = data[at]
    if b < 0x80:
        return data[at:at + 1], at + 1
    is_list = False
    if b <= 0xB7:
        start, length = at + 1, b - 0x80
        if length == 1 and start < len(data) and data[start] < 0x80:
            raise Fail("RNTX_NONCANONICAL_ENCODING")
    elif b <= 0xBF:
        count = b - 0xB7
        length = read_length(data, at + 1, count)
        start = at + 1 + count
    elif b <= 0xF7:
        is_list, start, length = True, at + 1, b - 0xC0
    else:
        count = b - 0xF7
        is_list = True
        length = read_length(data, at + 1, count)
        start = at + 1 + count
    end = start + length
    if end > len(data):
        raise Fail("RNTX_DECODE")
    if not is_list:
        return data[start:end], end
    if depth >= MAX_RLP_DEPTH:
        raise Fail("RNTX_DECODE")
    items, cursor = [], start
    while cursor < end:
        item, nxt = rlp_at(data, cursor, depth + 1)
        if nxt > end:
            raise Fail("RNTX_DECODE")
        items.append(item)
        cursor = nxt
    return items, end


def rlp_decode(data: bytes):
    item, nxt = rlp_at(data, 0)
    if nxt != len(data):
        raise Fail("RNTX_TRAILING_BYTES")
    return item


def uint(b) -> int:
    if isinstance(b, list):
        raise Fail("RNTX_DECODE")
    if len(b) > 32 or (len(b) > 0 and b[0] == 0):
        raise Fail("RNTX_NONCANONICAL_ENCODING")
    return int.from_bytes(b, "big")


def enc_uint(n: int) -> bytes:
    return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def decode_eip1559(data: bytes):
    if len(data) == 0:
        raise Fail("RNTX_DECODE")
    if data[0] != 2:
        raise Fail("RNTX_WRONG_TX_TYPE")
    items = rlp_decode(data[1:])
    if not isinstance(items, list) or len(items) != 12:
        raise Fail("RNTX_DECODE")
    chain, nonce, tip, max_fee, gas, to, value, data_, access, yp, r, s = items
    for item in (chain, nonce, tip, max_fee, gas, to, value, data_, yp, r, s):
        if isinstance(item, list):
            raise Fail("RNTX_DECODE")
    if not isinstance(access, list):
        raise Fail("RNTX_DECODE")
    if len(to) != 20:
        raise Fail("RNTX_FIELD_MISMATCH")
    access_list = []
    for entry in access:
        if not isinstance(entry, list) or len(entry) != 2 or isinstance(entry[0], list) or len(entry[0]) != 20 or not isinstance(entry[1], list):
            raise Fail("RNTX_DECODE")
        keys = []
        for key in entry[1]:
            if isinstance(key, list) or len(key) != 32:
                raise Fail("RNTX_DECODE")
            keys.append("0x" + key.hex())
        access_list.append({"address": "0x" + entry[0].hex(), "storageKeys": keys})
    q = lambda b: hex(uint(b))
    tx = {
        "type": "0x2", "chainId": q(chain), "nonce": q(nonce), "maxPriorityFeePerGas": q(tip), "maxFeePerGas": q(max_fee),
        "gas": q(gas), "to": "0x" + to.hex(), "value": q(value), "input": "0x" + data_.hex(), "accessList": access_list,
    }
    sig = (uint(yp), uint(r), uint(s))
    unsigned = b"\x02" + rlp_encode(items[:9])
    return tx, sig, unsigned


# --- XRPL --------------------------------------------------------------------------------------

FIELDS = {
    "TransactionType": (1, 2, "UInt16"), "NetworkID": (2, 1, "UInt32"), "Flags": (2, 2, "UInt32"), "Sequence": (2, 4, "UInt32"),
    "LastLedgerSequence": (2, 27, "UInt32"), "Fee": (6, 8, "Amount"), "SigningPubKey": (7, 3, "Blob"), "TxnSignature": (7, 4, "Blob"),
    "MemoType": (7, 12, "Blob"), "MemoData": (7, 13, "Blob"), "MemoFormat": (7, 14, "Blob"), "Account": (8, 1, "AccountID"),
    "ObjectEndMarker": (14, 1, "STObject"), "Memo": (14, 10, "STObject"), "ArrayEndMarker": (15, 1, "STArray"), "Memos": (15, 9, "STArray"),
}
BY_CODE = {(t, n): name for name, (t, n, _) in FIELDS.items()}
TOP = ["TransactionType", "Flags", "Sequence", "LastLedgerSequence", "Fee", "SigningPubKey", "TxnSignature", "Account", "Memos"]
MEMO_FIELDS = ["MemoType", "MemoData"]
ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
MAX_DROPS = 10**17


def order(name):
    t, n, _ = FIELDS[name]
    return t * 256 + n


def field_header(t, n) -> bytes:
    if t < 16 and n < 16:
        return bytes([(t << 4) | n])
    if t < 16:
        return bytes([t << 4, n])
    if n < 16:
        return bytes([n, t])
    return bytes([0, t, n])


def vl(length) -> bytes:
    if length <= 192:
        return bytes([length])
    if length <= 12480:
        n = length - 193
        return bytes([193 + (n >> 8), n & 0xFF])
    n = length - 12481
    return bytes([241 + (n >> 16), (n >> 8) & 0xFF, n & 0xFF])


def native_amount(drops: str) -> bytes:
    return (int(drops) | 0x4000000000000000).to_bytes(8, "big")


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def encode_address(account_id: bytes) -> str:
    payload = b"\x00" + account_id
    data = payload + dsha(payload)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = ALPHABET[rem] + out
    for byte in data:
        if byte:
            break
        out = ALPHABET[0] + out
    return out


def decode_address(address: str) -> bytes:
    n = 0
    for ch in address:
        n = n * 58 + ALPHABET.index(ch)
    lead = len(address) - len(address.lstrip(ALPHABET[0]))
    data = b"\x00" * lead + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    if len(data) != 25 or data[0] != 0 or dsha(data[:21])[:4] != data[21:]:
        raise ValueError("bad address")
    return data[1:21]


def address_from_public_key(pub: bytes) -> str:
    return encode_address(hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest())


def encode_xrpl(tx: dict) -> bytes:
    out = b""
    for name in sorted(tx, key=order):
        t, n, kind = FIELDS[name]
        value = tx[name]
        if name == "TransactionType":
            out += field_header(t, n) + (3).to_bytes(2, "big")
        elif kind == "UInt32":
            out += field_header(t, n) + value.to_bytes(4, "big")
        elif kind == "Amount":
            out += field_header(t, n) + native_amount(value)
        elif kind == "Blob":
            b = bytes.fromhex(value)
            out += field_header(t, n) + vl(len(b)) + b
        elif kind == "AccountID":
            out += field_header(t, n) + vl(20) + decode_address(value)
        elif name == "Memos":
            out += field_header(t, n)
            for entry in value:
                memo = entry["Memo"]
                out += field_header(14, 10)
                for inner in sorted(memo, key=order):
                    b = bytes.fromhex(memo[inner])
                    out += field_header(*FIELDS[inner][:2]) + vl(len(b)) + b
                out += field_header(14, 1)
            out += field_header(15, 1)
    return out


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def done(self):
        return self.at >= len(self.data)

    def take(self, n):
        if self.at + n > len(self.data):
            raise Fail("RNTX_DECODE")
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def header(self):
        first = self.take(1)[0]
        t, n = first >> 4, first & 0x0F
        if t == 0:
            t = self.take(1)[0]
            if t < 16:
                raise Fail("RNTX_NONCANONICAL_ENCODING")
        if n == 0:
            n = self.take(1)[0]
            if n < 16:
                raise Fail("RNTX_NONCANONICAL_ENCODING")
        name = BY_CODE.get((t, n))
        if name == "NetworkID":
            raise Fail("RNTX_WRONG_CHAIN")
        if name is None:
            raise Fail("RNTX_UNKNOWN_FIELD")
        return name

    def vl(self):
        b1 = self.take(1)[0]
        if b1 <= 192:
            return b1
        if b1 <= 240:
            return 193 + (b1 - 193) * 256 + self.take(1)[0]
        if b1 <= 254:
            b2, b3 = self.take(2)
            return 12481 + (b1 - 241) * 65536 + b2 * 256 + b3
        raise Fail("RNTX_DECODE")


def decode_xrpl(data: bytes) -> dict:
    tx = decode_xrpl_fields(data)
    # The bytes must be exactly the canonical serialization of what they decode to.
    try:
        canonical = encode_xrpl(tx)
    except (ValueError, OverflowError, KeyError, TypeError):
        raise Fail("RNTX_NONCANONICAL_ENCODING")
    if canonical != data:
        raise Fail("RNTX_NONCANONICAL_ENCODING")
    return tx


def decode_xrpl_fields(data: bytes) -> dict:
    r = Reader(data)
    tx, last = {}, -1
    while not r.done():
        name = r.header()
        if name not in TOP:
            raise Fail("RNTX_UNKNOWN_FIELD")
        if order(name) <= last:
            raise Fail("RNTX_NONCANONICAL_ENCODING")
        last = order(name)
        kind = FIELDS[name][2]
        if kind == "UInt16":
            code = int.from_bytes(r.take(2), "big")
            tx[name] = "AccountSet" if code == 3 else code
        elif kind == "UInt32":
            tx[name] = int.from_bytes(r.take(4), "big")
        elif kind == "Amount":
            raw = int.from_bytes(r.take(8), "big")
            if raw >> 63 or not (raw >> 62) & 1 or raw & ((1 << 62) - 1) > MAX_DROPS:
                raise Fail("RNTX_DECODE")
            tx[name] = str(raw & ((1 << 62) - 1))
        elif kind == "Blob":
            tx[name] = r.take(r.vl()).hex().upper()
        elif kind == "AccountID":
            if r.vl() != 20:
                raise Fail("RNTX_DECODE")
            tx[name] = encode_address(r.take(20))
        elif kind == "STArray":
            memos = []
            while True:
                inner = r.header()
                if inner == "ArrayEndMarker":
                    break
                if inner != "Memo":
                    raise Fail("RNTX_UNKNOWN_FIELD")
                memo, mlast = {}, -1
                while True:
                    f = r.header()
                    if f == "ObjectEndMarker":
                        break
                    if f not in MEMO_FIELDS:
                        raise Fail("RNTX_UNKNOWN_FIELD")
                    if order(f) <= mlast:
                        raise Fail("RNTX_NONCANONICAL_ENCODING")
                    mlast = order(f)
                    memo[f] = r.take(r.vl()).hex().upper()
                memos.append({"Memo": memo})
            tx[name] = memos
            if not r.done():
                raise Fail("RNTX_TRAILING_BYTES")
        else:
            raise Fail("RNTX_UNKNOWN_FIELD")
    return tx


def sha512half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


# --- ADR-RN-016 checks and the intent ------------------------------------------------------

MEMO_TYPE = b"rnnet.anchor-payload.v1".hex().upper()
QUANTITY = re.compile(r"0x(0|[1-9a-f][0-9a-f]*)")
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
XRPL_ACCOUNT = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GWEI = 10**9
SEPOLIA_FIELDS = {"type", "chainId", "nonce", "from", "to", "value", "input", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "accessList"}


def is_u32(v):
    return isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 0xFFFFFFFF


def xrpl_tx_ok(tx, commitment) -> bool:
    payload = anchor_ref.encode_payload(commitment).hex().upper()
    allowed = {"TransactionType", "Account", "Fee", "Sequence", "LastLedgerSequence", "Flags", "Memos", "SigningPubKey"}
    if not isinstance(tx, dict) or not set(tx) <= allowed:
        return False
    fee = tx.get("Fee")
    return (
        tx.get("TransactionType") == "AccountSet"
        and isinstance(tx.get("Account"), str) and XRPL_ACCOUNT.fullmatch(tx["Account"]) is not None
        and isinstance(fee, str) and re.fullmatch(r"[1-9][0-9]{0,18}", fee) is not None and int(fee) <= 1000
        and is_u32(tx.get("Sequence")) and is_u32(tx.get("LastLedgerSequence"))
        and tx.get("Flags", 0) == 0 and not isinstance(tx.get("Flags", 0), bool)
        and ("SigningPubKey" not in tx or (isinstance(tx["SigningPubKey"], str) and re.fullmatch(r"ED[0-9A-F]{64}", tx["SigningPubKey"]) is not None))
        and tx.get("Memos") == [{"Memo": {"MemoType": MEMO_TYPE, "MemoData": payload}}]
    )


def sepolia_tx_ok(tx, commitment) -> bool:
    if not isinstance(tx, dict) or set(tx) != SEPOLIA_FIELDS:
        return False
    q = lambda k: isinstance(tx[k], str) and QUANTITY.fullmatch(tx[k]) is not None
    if not all(q(k) for k in ("nonce", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas")):
        return False
    payload = anchor_ref.encode_payload(commitment)
    gas_needed = max(21000 + 4 * (payload.count(0) + 4 * (len(payload) - payload.count(0))), 21000 + 10 * (payload.count(0) + 4 * (len(payload) - payload.count(0))))
    return (
        tx["type"] == "0x2" and tx["chainId"] == "0xaa36a7"
        and isinstance(tx["from"], str) and ADDRESS.fullmatch(tx["from"]) is not None and tx["to"] == tx["from"]
        and tx["value"] == "0x0" and tx["input"] == "0x" + payload.hex() and tx["accessList"] == []
        and gas_needed <= int(tx["gas"], 16) <= 30000
        and int(tx["maxFeePerGas"], 16) <= 20 * GWEI and int(tx["maxPriorityFeePerGas"], 16) <= int(tx["maxFeePerGas"], 16)
    )


def intent_ok(intent) -> bool:
    if not isinstance(intent, dict) or sorted(intent) != ["commitment", "format", "network", "preparation", "purpose", "transaction"]:
        return False
    if intent["format"] != "rnnet.unsigned-tx-intent.v1" or intent["purpose"] != "genesis-proof-01" or not isinstance(intent["preparation"], dict):
        return False
    c = intent["commitment"]
    if not isinstance(c, str) or DIGEST.fullmatch(c) is None:
        return False
    tx = intent["transaction"]
    if intent["network"] == "xrpl:testnet":
        return xrpl_tx_ok(tx, c) and "SigningPubKey" in tx and address_from_public_key(bytes.fromhex(tx["SigningPubKey"])) == tx["Account"]
    if intent["network"] == "evm:11155111":
        return sepolia_tx_ok(tx, c) and int(tx["nonce"], 16) < 2**64  # EIP-2681
    return False


def intent_digest(intent) -> str:
    return sha256_tag(b"rnnet:unsigned-tx-intent:v1\x00" + canon(intent))


XRPL_ORDER = [("TransactionType", "RNTX_FIELD_MISMATCH"), ("Flags", "RNTX_FIELD_MISMATCH"), ("Sequence", "RNTX_NONCE_MISMATCH"),
              ("LastLedgerSequence", "RNTX_FIELD_MISMATCH"), ("Fee", "RNTX_FEE_MISMATCH"), ("Memos", "RNTX_PAYLOAD_MISMATCH"),
              ("Account", "RNTX_SENDER_MISMATCH"), ("SigningPubKey", "RNTX_SENDER_MISMATCH")]
SEPOLIA_ORDER = [("type", "RNTX_WRONG_TX_TYPE"), ("chainId", "RNTX_WRONG_CHAIN"), ("nonce", "RNTX_NONCE_MISMATCH"),
                 ("maxPriorityFeePerGas", "RNTX_FEE_MISMATCH"), ("maxFeePerGas", "RNTX_FEE_MISMATCH"), ("gas", "RNTX_FEE_MISMATCH"),
                 ("to", "RNTX_FIELD_MISMATCH"), ("value", "RNTX_FIELD_MISMATCH"), ("input", "RNTX_PAYLOAD_MISMATCH"), ("accessList", "RNTX_FIELD_MISMATCH")]


def compare(order_list, expected, actual):
    for name, code in order_list:
        if (name in expected) != (name in actual) or (name in expected and canon(expected[name]) != canon(actual[name])):
            raise Fail(code)


def check_signed(intent, data: bytes):
    tx = intent["transaction"]
    if intent["network"] == "xrpl:testnet":
        decoded = decode_xrpl(data)
        actual = {k: v for k, v in decoded.items() if k != "TxnSignature"}
        compare(XRPL_ORDER, tx, actual)
        if "TxnSignature" not in decoded:
            raise Fail("RNTX_SIGNATURE_INVALID")
        pub = bytes.fromhex(decoded["SigningPubKey"])[1:]
        sig = bytes.fromhex(decoded["TxnSignature"])
        preimage = b"STX\x00" + encode_xrpl(actual)
        if len(pub) != 32 or len(sig) != 64 or ev.ed25519(pub, sig, preimage) != "VALID":
            raise Fail("RNTX_SIGNATURE_INVALID")
        return
    decoded, (yp, r, s), unsigned = decode_eip1559(data)
    compare(SEPOLIA_ORDER, {k: v for k, v in tx.items() if k != "from"}, decoded)
    if yp > 1:
        raise Fail("RNTX_BAD_Y_PARITY")
    if r == 0 or r >= N or s == 0 or s >= N:
        raise Fail("RNTX_SIGNATURE_INVALID")
    if s > N // 2:
        raise Fail("RNTX_HIGH_S")
    sender = recover_address(keccak256(unsigned), yp, r, s)
    if sender is None:
        raise Fail("RNTX_SIGNATURE_INVALID")
    if sender != tx["from"]:
        raise Fail("RNTX_SENDER_MISMATCH")


def verify(intent, approved_digest, signed) -> dict:
    record = {"format": "rnnet.signed-tx-verification.v1", "network": None, "intentDigest": None, "blobSha256": None, "transactionHash": None, "outcome": "FAIL", "code": None}
    try:
        # Values outside rnnet.canonical-json.v1 make the intent invalid.
        valid = canon_values_ok(intent) and intent_ok(intent)
    except (ref.RefError, UnicodeEncodeError):
        valid = False
    if not valid:
        return {**record, "code": "RNTX_INTENT_INVALID"}
    if not isinstance(approved_digest, str) or DIGEST.fullmatch(approved_digest) is None or intent_digest(intent) != approved_digest:
        return {**record, "code": "RNTX_INTENT_DIGEST_MISMATCH"}
    network = intent["network"]
    record.update(network=network, intentDigest=approved_digest)
    pattern = r"(?:[0-9A-F]{2})+" if network == "xrpl:testnet" else r"0x(?:[0-9a-f]{2})+"
    if not isinstance(signed, str) or re.fullmatch(pattern, signed) is None:
        return {**record, "code": "RNTX_DECODE"}
    data = bytes.fromhex(signed if network == "xrpl:testnet" else signed[2:])
    record["blobSha256"] = sha256_tag(data)
    record["transactionHash"] = sha512half(b"TXN\x00" + data).hex().upper() if network == "xrpl:testnet" else "0x" + keccak256(data).hex()
    try:
        check_signed(intent, data)
    except Fail as failure:
        return {**record, "code": failure.code}
    return {**record, "outcome": "PASS"}


# --- test-key derivation (public keys only) ----------------------------------------------------

def label_seed(label: str) -> bytes:
    return hashlib.sha256(f"rnnet:synthetic-test-key:v1:{label}".encode("utf-8")).digest()


def ed25519_public(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    x, y, z, _ = ev.point_mul(a, ev.G)
    zi = pow(z, ev.P - 2, ev.P)
    x, y = x * zi % ev.P, y * zi % ev.P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


# --- checks ------------------------------------------------------------------------------------

def checks(root: Path):
    kat = json.loads((root / "vectors/signing/known-answers.json").read_text("utf-8"))
    yield "vectors format", kat["format"] == "rnnet.conformance-vectors.v1" and kat["kind"] == "signing-known-answers"
    for v in kat["keccak256"]:
        yield f"keccak256({v['input']!r})", keccak256(v["input"].encode("utf-8")).hex() == v["expected"]
    yield "keccak256 differs from SHA3-256", keccak256(b"").hex() != hashlib.sha3_256(b"").hexdigest()

    e = kat["eip155"]
    digest = keccak256(bytes.fromhex(e["signingDataHex"][2:]))
    yield "EIP-155 signing hash", "0x" + digest.hex() == e["signingHash"]
    yield "EIP-155 v = 35 + 2 * chainId + recovery", e["v"] == 35 + 2 * 1 + e["recoveryId"]
    yield "EIP-155 sender recovered", recover_address(digest, e["recoveryId"], int(e["r"], 16), int(e["s"], 16)) == e["sender"]
    yield "EIP-155 sender from the published key", evm_address(ec_mul(int(e["keyByteRepeated32"] * 32, 16), SG)) == e["sender"]

    for v in kat["eip1559"]:
        tx, (yp, r, s), unsigned = decode_eip1559(bytes.fromhex(v["signedHex"][2:]))
        yield f"{v['id']} decodes to its fields", tx == v["transaction"]
        yield f"{v['id']} unsigned bytes", "0x" + unsigned.hex() == v["unsignedHex"]
        yield f"{v['id']} signature", (yp, r, s) == (v["signature"]["yParity"], int(v["signature"]["r"], 16), int(v["signature"]["s"], 16)) and s <= N // 2
        yield f"{v['id']} sender recovered", recover_address(keccak256(unsigned), yp, r, s) == v["sender"]
    for v in kat["eip1559Invalid"]:
        try:
            decode_eip1559(bytes.fromhex(v["txbytes"][2:]))
            code = None
        except Fail as failure:
            code = failure.code
        yield f"{v['id']} refused", code == v["expectedCode"]

    yield "XRPL field headers", all(field_header(h["type"], h["nth"]).hex().upper() == h["expectedHex"] for h in kat["xrplFieldHeaders"])
    yield "XRPL field codes match the codec", all(FIELDS[h["field"]][:2] == (h["type"], h["nth"]) for h in kat["xrplFieldHeaders"])
    yield "XRPL native amounts", all(native_amount(a["drops"]).hex().upper() == a["expectedHex"] for a in kat["xrplNativeAmounts"])
    yield "XRPL addresses", all(decode_address(a["address"]).hex().upper() == a["accountIdHex"] and encode_address(bytes.fromhex(a["accountIdHex"])) == a["address"] for a in kat["xrplAddresses"])
    sb = kat["xrplSigningBlob"]
    codes = {**{k: v[:2] for k, v in FIELDS.items()}, **{k: tuple(v) for k, v in sb["extraFields"].items()}}
    composed = b"STX\x00"
    for name, value in sb["fields"]:
        head = field_header(*codes[name])
        if name in ("Account", "Destination"):
            composed += head + vl(20) + decode_address(value)
        elif name == "SigningPubKey":
            composed += head + vl(len(bytes.fromhex(value))) + bytes.fromhex(value)
        else:
            composed += head + bytes.fromhex(value)
    yield "XRPL signing blob (official vector)", composed.hex().upper() == sb["expectedHex"]
    th = kat["xrplTxHash"]
    yield "XRPL transaction hash (official vector)", sha512half(b"TXN\x00" + bytes.fromhex(th["blobHex"])).hex().upper() == th["expectedHash"]

    d = root / "fixtures/signing-b1"
    g = json.loads((d / "golden.json").read_text("utf-8"))
    yield "fixtures format", g["format"] == "rnnet.signing-b1-fixtures.v1" and g["status"].startswith("SYNTHETIC")
    for k in g["keys"]:
        seed = label_seed(k["label"])
        if k["network"] == "xrpl:testnet":
            pub = "ED" + ed25519_public(seed).hex().upper()
            yield f"test key {k['label']}", pub == k["publicKey"] and address_from_public_key(bytes.fromhex(pub)) == k["address"]
        else:
            point = ec_mul(int.from_bytes(seed, "big") % N, SG)
            yield f"test key {k['label']}", "04" + point[0].to_bytes(32, "big").hex() + point[1].to_bytes(32, "big").hex() == k["publicKey"] and evm_address(point) == k["address"]
    for name, signed in g["signed"].items():
        raw = (d / signed["intentFile"]).read_bytes()
        intent = json.loads(raw)
        yield f"{name} intent file is canonical", raw == canon(intent) + b"\n"
        yield f"{name} intent passes the checks", intent_ok(intent)
        yield f"{name} intent digest", intent_digest(intent) == signed["intentDigest"]
        rec = verify(intent, signed["intentDigest"], signed["signedTransaction"])
        yield f"{name} signed transaction verifies (PASS)", rec["outcome"] == "PASS" and canon(rec) == canon(signed["verification"])
        yield f"{name} hashes", rec["blobSha256"] == signed["blobSha256"] and rec["transactionHash"] == signed["transactionHash"]
    neg = g["negative"]
    yield "negative corpus present", len(neg) >= 40
    for case in neg:
        rec = verify(case["intent"], case["approvedDigest"], case["signedTransaction"])
        yield f"negative {case['id']} -> {case['expectedCode']}", rec["code"] == case["expectedCode"] and canon(rec) == canon(case["expectedVerification"])


def main(root: Path) -> int:
    results = list(checks(root))
    failed = [name for name, ok in results if not ok]
    for name in failed:
        print("FAIL", name)
    print(f"tx reference: {len(results) - len(failed)}/{len(results)} checks agree")
    return 1 if failed else 0


def cli_verify(intent_text: str, approved_digest: str, signed: str) -> bytes:
    """One record, for the broadcaster's second verifier (ADR-RN-019 §3 step 5).

    The intent must be canonical JSON text; anything else is an invalid intent, as in the
    JavaScript verifier. Returns the record's canonical JSON bytes and a newline."""
    def no_dup(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def constant(_):
        raise ValueError("constant")

    try:
        intent = json.loads(intent_text, object_pairs_hook=no_dup, parse_constant=constant)
        canonical = canon_values_ok(intent) and canon(intent) == intent_text.encode("utf-8")
    except (ValueError, RecursionError, ref.RefError, UnicodeEncodeError):
        canonical = False
    if not canonical:
        record = {"format": "rnnet.signed-tx-verification.v1", "network": None, "intentDigest": None, "blobSha256": None, "transactionHash": None, "outcome": "FAIL", "code": "RNTX_INTENT_INVALID"}
    else:
        record = verify(intent, approved_digest, signed)
    return canon(record) + b"\n"


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "verify":
        sys.stdout.buffer.write(cli_verify(sys.argv[2], sys.argv[3], sys.argv[4]))
        sys.exit(0)
    if len(sys.argv) != 1:
        print("usage: rnnet_tx_reference.py [verify <intent-json> <approved-digest> <signed-transaction>]", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(HERE.parent.parent))
