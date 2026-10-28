"""Independent reference implementation of rnnet.canonical-json.v1 and
rnnet.evidence-commitment.v1, written from the specifications in spec/ without
reference to the JavaScript packages. Python standard library only.

Run `python3 -I tools/reference/rnnet_reference.py` from the repository root to check
every conformance vector in vectors/. It exits 1 on any disagreement.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_SAFE = 2**53 - 1


class RefError(Exception):
    def __init__(self, code, field=None):
        super().__init__(code)
        self.code = code
        self.field = field


# --- rnnet.canonical-json.v1: parsing (spec §3) --------------------------------------------

def decode(data: bytes) -> str:
    if len(data) > MAX_BYTES:
        raise RefError("RNCJ_SIZE_EXCEEDED")
    if data.startswith(b"\xef\xbb\xbf"):
        raise RefError("RNCJ_BOM")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise RefError("RNCJ_INVALID_UTF8") from None


class _Parser:
    WS = " \t\n\r"
    ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

    def __init__(self, text):
        self.s = text
        self.i = 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def ws(self):
        while self.peek() and self.peek() in self.WS:
            self.i += 1

    def document(self):
        self.ws()
        if not self.peek():
            raise RefError("RNCJ_SYNTAX")
        value = self.value(0)
        self.ws()
        if self.i != len(self.s):
            raise RefError("RNCJ_TRAILING_CONTENT")
        return value

    def value(self, depth):
        c = self.peek()
        if c == "{":
            return self.obj(depth + 1)
        if c == "[":
            return self.arr(depth + 1)
        if c == '"':
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if c == word[0]:
                if self.s.startswith(word, self.i):
                    self.i += len(word)
                    return val
                raise RefError("RNCJ_SYNTAX")
        if c == "-" or c.isdigit() and c in "0123456789":
            return self.number()
        raise RefError("RNCJ_SYNTAX")

    def obj(self, depth):
        if depth > MAX_DEPTH:
            raise RefError("RNCJ_DEPTH_EXCEEDED")
        self.i += 1
        out = {}
        self.ws()
        if self.peek() == "}":
            self.i += 1
            return out
        while True:
            self.ws()
            if self.peek() != '"':
                raise RefError("RNCJ_SYNTAX")
            key = self.string()
            if key in out:
                raise RefError("RNCJ_DUPLICATE_KEY")
            self.ws()
            if self.peek() != ":":
                raise RefError("RNCJ_SYNTAX")
            self.i += 1
            self.ws()
            out[key] = self.value(depth)
            self.ws()
            c = self.peek()
            self.i += 1
            if c == "}":
                return out
            if c != ",":
                raise RefError("RNCJ_SYNTAX")

    def arr(self, depth):
        if depth > MAX_DEPTH:
            raise RefError("RNCJ_DEPTH_EXCEEDED")
        self.i += 1
        out = []
        self.ws()
        if self.peek() == "]":
            self.i += 1
            return out
        while True:
            self.ws()
            out.append(self.value(depth))
            self.ws()
            c = self.peek()
            self.i += 1
            if c == "]":
                return out
            if c != ",":
                raise RefError("RNCJ_SYNTAX")

    def hex4(self):
        h = self.s[self.i:self.i + 4]
        if not re.fullmatch(r"[0-9A-Fa-f]{4}", h):
            raise RefError("RNCJ_SYNTAX")
        self.i += 4
        return int(h, 16)

    def string(self):
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if not c:
                raise RefError("RNCJ_SYNTAX")
            self.i += 1
            if c == '"':
                return "".join(out)
            if ord(c) < 0x20:
                raise RefError("RNCJ_SYNTAX")
            if c != "\\":
                out.append(c)
                continue
            e = self.peek()
            self.i += 1
            if e in self.ESCAPES:
                out.append(self.ESCAPES[e])
                continue
            if e != "u":
                raise RefError("RNCJ_SYNTAX")
            unit = self.hex4()
            if 0xDC00 <= unit <= 0xDFFF:
                raise RefError("RNCJ_LONE_SURROGATE")
            if not 0xD800 <= unit <= 0xDBFF:
                out.append(chr(unit))
                continue
            if self.s[self.i:self.i + 2] != "\\u":
                raise RefError("RNCJ_LONE_SURROGATE")
            self.i += 2
            low = self.hex4()
            if not 0xDC00 <= low <= 0xDFFF:
                raise RefError("RNCJ_LONE_SURROGATE")
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))

    def number(self):
        m = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?").match(self.s, self.i)
        if not m:
            raise RefError("RNCJ_SYNTAX")
        if m.group(1) == "0" and self.s[m.end(1):m.end(1) + 1].isdigit():
            raise RefError("RNCJ_SYNTAX")  # leading zero
        end_int = m.end(1)
        nxt = self.s[m.end():m.end() + 1]
        if (m.group(2) is None and nxt == ".") or (m.group(3) is None and nxt in ("e", "E")):
            raise RefError("RNCJ_SYNTAX")  # incomplete fraction or exponent
        self.i = m.end()
        if m.group(2) is not None or m.group(3) is not None:
            raise RefError("RNCJ_NUMBER_NOT_INTEGER")
        lexeme = self.s[m.start():end_int]
        if lexeme == "-0":
            raise RefError("RNCJ_NEGATIVE_ZERO")
        n = int(lexeme)
        if abs(n) > MAX_SAFE:
            raise RefError("RNCJ_NUMBER_OUT_OF_RANGE")
        return n


def parse(data: bytes):
    return _Parser(decode(data)).document()


# --- rnnet.canonical-json.v1: serialization (spec §4) --------------------------------------

def _quote(s: str) -> str:
    short = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}
    out = []
    for ch in s:
        o = ord(ch)
        if o in short:
            out.append(short[o])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def canonicalize(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, list):
        return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))  # UTF-16 code unit order
        return "{" + ",".join(_quote(k) + ":" + canonicalize(v[k]) for k in keys) + "}"
    raise RefError("RNCJ_UNSUPPORTED_VALUE")


# --- rnnet.evidence-commitment.v1 (spec §3-§6) ---------------------------------------------

FORMAT = "rnnet.evidence-commitment.v1"
FIELDS = ["format", "sourceFormat", "sourceCanonicalization", "sourceEvidenceDigest", "sourceFileSha256", "sourceRef"]
DOMAIN = b"rnnet:evidence-commitment:v1\x00"
FORMAT_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+")
CANON_ID = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SOURCE_REF = re.compile(r"[a-z][a-z0-9+.-]*:[\x21-\x7e]+")


def validate(env):
    if not isinstance(env, dict):
        raise RefError("RNEC_NOT_OBJECT")
    unknown = sorted((k for k in env if k not in FIELDS), key=lambda k: k.encode("utf-16-be"))
    if unknown:
        raise RefError("RNEC_UNKNOWN_FIELD", unknown[0])
    for f in FIELDS:
        if f not in env:
            raise RefError("RNEC_MISSING_FIELD", f)
    for f in FIELDS:
        if not isinstance(env[f], str):
            raise RefError("RNEC_FIELD_TYPE", f)
    if env["format"] != FORMAT:
        code = "RNEC_UNSUPPORTED_VERSION" if env["format"].startswith("rnnet.evidence-commitment.") else "RNEC_UNSUPPORTED_FORMAT"
        raise RefError(code, "format")
    if len(env["sourceFormat"]) > 128 or not FORMAT_ID.fullmatch(env["sourceFormat"]):
        raise RefError("RNEC_INVALID_SOURCE_FORMAT", "sourceFormat")
    if len(env["sourceCanonicalization"]) > 128 or not CANON_ID.fullmatch(env["sourceCanonicalization"]):
        raise RefError("RNEC_INVALID_CANONICALIZATION_ID", "sourceCanonicalization")
    for f in ("sourceEvidenceDigest", "sourceFileSha256"):
        if not DIGEST.fullmatch(env[f]):
            raise RefError("RNEC_INVALID_DIGEST", f)
    if len(env["sourceRef"]) > 512 or not SOURCE_REF.fullmatch(env["sourceRef"]):
        raise RefError("RNEC_INVALID_SOURCE_REF", "sourceRef")
    return env


def commitment(data: bytes):
    env = validate(parse(data))
    canonical = canonicalize(env)
    return canonical, "sha256:" + hashlib.sha256(DOMAIN + canonical.encode("utf-8")).hexdigest()


def verify(data: bytes, presented: str):
    if not DIGEST.fullmatch(presented):
        return {"valid": False, "code": "RNEC_INVALID_COMMITMENT_DIGEST"}
    try:
        _, digest = commitment(data)
    except RefError as e:
        return {"valid": False, "code": e.code}
    if digest != presented:
        return {"valid": False, "code": "RNEC_DIGEST_MISMATCH"}
    return {"valid": True}


# --- vector checks -------------------------------------------------------------------------

def input_bytes(vector) -> bytes:
    if "inputHex" in vector:
        return bytes.fromhex(vector["inputHex"])
    return vector["input"].encode("utf-8")


def outcome(fn):
    try:
        return ("ok", fn())
    except RefError as e:
        return ("error", e.code, e.field)


def main(root: Path) -> int:
    failures = []
    load = lambda p: json.loads((root / p).read_text("utf-8"))
    checked = 0

    for v in load("vectors/canonical/valid.json")["vectors"]:
        checked += 1
        r = outcome(lambda: canonicalize(parse(input_bytes(v))))
        sha = hashlib.sha256(v["expected"].encode("utf-8")).hexdigest()
        if r != ("ok", v["expected"]) or sha != v["expectedSha256"]:
            failures.append((v["id"], r))

    for v in load("vectors/canonical/invalid.json")["vectors"]:
        checked += 1
        r = outcome(lambda: canonicalize(parse(input_bytes(v))))
        if r[:2] != ("error", v["expectedError"]):
            failures.append((v["id"], r))

    for v in load("vectors/commitment/valid.json")["vectors"]:
        checked += 1
        r = outcome(lambda: commitment(input_bytes(v)))
        if r != ("ok", (v["expectedCanonical"], v["expectedCommitment"])):
            failures.append((v["id"], r))

    for v in load("vectors/commitment/invalid.json")["vectors"]:
        checked += 1
        r = outcome(lambda: commitment(input_bytes(v)))
        if r[:2] != ("error", v["expectedError"]) or r[2] != v.get("expectedField"):
            failures.append((v["id"], r))

    tamper = load("vectors/tamper/commitment-tamper.json")
    for v in tamper["vectors"]:
        checked += 1
        r = verify(input_bytes(v), v["presentedDigest"])
        if r != v["expected"]:
            failures.append((v["id"], r))

    for vid, r in failures:
        print(f"FAIL {vid}: {r}")
    print(f"reference: {checked - len(failures)}/{checked} vectors agree")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(Path(__file__).resolve().parents[2]))
