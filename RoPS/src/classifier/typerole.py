#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Per-argument type recovery and consumption-role assignment for Stage 3.

Type recovery (``recover_type``) classifies each literal argument as

* ``T1`` text            -- human-readable text (the only domain of text IoCs),
* ``T2`` numeric buffer  -- IEEE-754 / integer arrays recognised from the byte
                            layout the format specification mandates,
* ``T3`` structured      -- zlib / pickle / archive payloads recognised by magic,
* ``T4`` opaque          -- undecidable (recorded as an indicator only).

Role assignment (``assign_roles``) marks each argument position as

* ``R1`` value position, ``R2`` name position (consumed by a resolver such as
  ``getattr``), or ``R3`` code position (consumed by ``eval``/``exec``/...).

``impossible_combination`` flags (type, role) pairs that are outside the object
reconstruction contract (e.g. a numeric buffer in a name position).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    # types
    "T1_TEXT", "T2_NUMERIC", "T3_STRUCTURED", "T4_OPAQUE",
    "TypeResult", "recover_type", "parse_placeholder", "parse_nested",
    "declared_width",
    "TAU", "N_MIN", "SIGMA", "N_WEAK", "PRINTABLE_CEIL",
    # roles
    "R1_VALUE", "R2_NAME", "R3_CODE",
    "assign_roles", "impossible_combination", "NAME_TAKING", "CODE_TAKING",
]


# ══════════════════════════════════════════════════════════════════════════
# Type recovery
# ══════════════════════════════════════════════════════════════════════════
T1_TEXT = "T1"
T2_NUMERIC = "T2"
T3_STRUCTURED = "T3"
T4_OPAQUE = "T4"

# Decision parameters (safety margins derived from the format specification,
# not fitted to a corpus).
TAU = 0.90              # band-hit ratio threshold for the strong test
N_MIN = 3               # minimum sample count for the strong test
PRINTABLE_CEIL = 0.75   # a buffer this printable is never T2 (text max observed 0.586)
SIGMA = 8               # support bound for the weak test
N_WEAK = 24             # minimum sample count for the weak test
PRINTABLE_STRONG = 0.95
PRINTABLE_WEAK = 0.80


# Admissible exponent bands for the top byte of little-endian floats.
#   binary64 LE:  byte_7 = s<<7 | (e >> 4),  e = a + 1023   (|x| in [2^a, 2^(a+1)))
#   binary32 LE:  byte_3 = s<<7 | (e >> 1),  e = a + 127
def _band(lo: int, hi: int) -> frozenset:
    return frozenset(b for b in range(256) if lo <= (b & 0x7F) <= hi)


S_F8 = _band(0x3B, 0x43)
S_F4 = _band(0x37, 0x47)
S_BF = S_F4
S_INT = frozenset({0x00, 0xFF})

_FLOAT_SPECS: Tuple[Tuple[int, frozenset, str], ...] = (
    (8, S_F8, "f8"), (4, S_F4, "f4"), (2, S_BF, "bf16/f2"),
)

_DTYPE_MAP: Dict[str, Tuple[int, frozenset, str]] = {
    "f8": (8, S_F8, "f8"), "d": (8, S_F8, "f8"), "float64": (8, S_F8, "f8"),
    "f4": (4, S_F4, "f4"), "f": (4, S_F4, "f4"), "float32": (4, S_F4, "f4"),
    "f2": (2, S_BF, "f2"), "e": (2, S_BF, "f2"), "float16": (2, S_BF, "f2"),
    "i8": (8, S_INT, "i8"), "q": (8, S_INT, "i8"), "int64": (8, S_INT, "i8"),
    "i4": (4, S_INT, "i4"), "i": (4, S_INT, "i4"), "int32": (4, S_INT, "i4"),
}

_STORAGE_MAP: Dict[str, str] = {
    "DoubleStorage": "f8", "FloatStorage": "f4", "HalfStorage": "f2",
    "BFloat16Storage": "f2", "LongStorage": "i8", "IntStorage": "i4",
}

PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

MAGIC_TAGS = ("zlib_magic", "pickle_magic", "pickle_magic_p0")

_CONTENT_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"We love Marisa.", "marisa_trie"),
    (b"\x78\x9c", "zlib"), (b"\x78\x01", "zlib"), (b"\x78\xda", "zlib"),
    (b"\x1f\x8b", "gzip"), (b"PK\x03\x04", "zip"), (b"\x89PNG", "png"),
)

_PLACEHOLDER = re.compile(
    r"^\[BINBYTES:([0-9a-fA-F]*)\s+len=(\d+)(?:\s+fmt=([^\]]*))?\]\s*$")

_DTYPE_DESC = re.compile(r"^[<>|=]?([a-zA-Z]\d*)$")


class TypeResult(object):
    """Internal implementation detail."""

    __slots__ = ("type", "evidence", "layer", "width", "placeholder",
                 "nested", "metrics")

    def __init__(self, type_: str, evidence: str, layer: str,
                 width: Optional[int] = None, placeholder: bool = False,
                 nested: Optional[Dict[str, Any]] = None,
                 metrics: Optional[Dict[str, Any]] = None):
        self.type = type_
        self.evidence = evidence
        self.layer = layer          # "placeholder"|"magic"|"declared"|"spec"|"text"|"fallback"
        self.width = width
        self.placeholder = placeholder
        self.nested = nested
        self.metrics = metrics or {}

    def to_dict(self) -> Dict[str, Any]:
        d = {"type": self.type, "evidence": self.evidence, "layer": self.layer}
        if self.width:
            d["width"] = self.width
        if self.placeholder:
            d["placeholder"] = True
        if self.nested:
            d["nested"] = self.nested
        if self.metrics:
            d["metrics"] = self.metrics
        return d

    def __repr__(self) -> str:      # pragma: no cover
        return "TypeResult(%s, %r, layer=%s)" % (self.type, self.evidence, self.layer)


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return b""
    try:
        return value.encode("latin1")
    except UnicodeEncodeError:
        return value.encode("utf-8", "replace")


def parse_placeholder(value: Any) -> Optional[Dict[str, Any]]:
    """Internal implementation detail."""
    if not isinstance(value, str):
        return None
    m = _PLACEHOLDER.match(value)
    if not m:
        return None
    return {"head_hex": m.group(1) or "", "len": int(m.group(2)), "fmt": m.group(3) or ""}


def _pi(buf: bytes, width: int, pset: frozenset) -> Tuple[float, int]:
    """Internal implementation detail."""
    col = buf[width - 1::width]
    if not col:
        return 0.0, 0
    return sum(1 for b in col if b in pset) / len(col), len(col)


def _int_signext(buf: bytes, width: int) -> Tuple[float, int]:
    """Internal implementation detail."""
    total = hit = 0
    for j in range(width // 2, width):
        col = buf[j::width]
        total += len(col)
        hit += sum(1 for b in col if b in S_INT)
    if not total:
        return 0.0, 0
    return hit / total, total


def _support(buf: bytes, width: int) -> Tuple[int, int]:
    """Internal implementation detail."""
    col = buf[width - 1::width]
    if not col:
        return 0, 0
    return len({b & 0x7F for b in col}), len(col)


def _printable_ratio(buf: bytes) -> float:
    if not buf:
        return 1.0
    return sum(1 for b in buf if b in PRINTABLE) / len(buf)


def _content_magic(buf: bytes) -> Optional[str]:
    for prefix, name in _CONTENT_MAGIC:
        if buf.startswith(prefix):
            return name
    if buf[:1] == b"\x80" and len(buf) > 1 and 0 <= buf[1] <= 5:
        return "pickle_proto%d" % buf[1]
    if buf[:1] in (b"c", b"(") and buf.rstrip()[-1:] == b".":
        return "pickle_proto0"
    return None


def declared_width(siblings: Optional[Iterable[Any]]) -> Optional[Tuple[int, frozenset, str]]:
    """Internal implementation detail."""
    if not siblings:
        return None
    for s in siblings:
        if not isinstance(s, str):
            continue
        for sym, key in _STORAGE_MAP.items():
            if sym in s:
                return _DTYPE_MAP.get(key)
        m = _DTYPE_DESC.match(s.strip())
        if m and m.group(1) in _DTYPE_MAP:
            return _DTYPE_MAP[m.group(1)]
    return None


def parse_nested(buf: bytes, depth: int = 0, d_max: int = 3) -> Optional[Dict[str, Any]]:
    """Internal implementation detail."""
    if depth > d_max or not buf:
        return None
    try:
        import pickletools
    except ImportError:                                  # pragma: no cover
        return None
    proto = buf[1] if (buf[:1] == b"\x80" and len(buf) > 1) else 0
    callables: List[Dict[str, str]] = []
    recent: List[str] = []
    ok = False
    try:
        for op, arg, _pos in pickletools.genops(buf):
            ok = True
            name = op.name
            if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE") and isinstance(arg, str):
                recent.append(arg)
                recent = recent[-2:]
            elif name == "GLOBAL" and isinstance(arg, str):
                parts = arg.replace("\n", " ").split()
                if len(parts) >= 2:
                    callables.append({"module": parts[0], "name": parts[1], "opname": "GLOBAL"})
            elif name == "STACK_GLOBAL" and len(recent) == 2:
                callables.append({"module": recent[0], "name": recent[1],
                                  "opname": "STACK_GLOBAL"})
                recent = []
    except Exception:
        if not ok:
            return None
    if not ok:
        return None
    return {"protocol": proto, "depth": depth + 1, "callables": callables,
            "bytes": len(buf)}


def recover_type(value: Any,
                 tags: Optional[Sequence[str]] = None,
                 siblings: Optional[Sequence[Any]] = None,
                 *, parse_nested_payload: bool = True,
                 depth: int = 0) -> TypeResult:
    """Internal implementation detail."""
    tagstr = " ".join(t for t in (tags or []) if isinstance(t, str))

    # Layer 0 -- Stage 2 placeholder for a large binary literal
    ph = parse_placeholder(value)
    if ph is not None:
        blob = ""
        try:
            blob = bytes.fromhex(ph["head_hex"]).decode("latin1")
        except Exception:
            blob = ""
        combined = tagstr + " " + ph["fmt"]
        tag_magic = next((t for t in MAGIC_TAGS if t in combined), None)
        head_magic = _content_magic(_to_bytes(blob)) if blob else None
        if tag_magic or head_magic:
            return TypeResult(T3_STRUCTURED,
                              "placeholder+magic(%s)" % (tag_magic or head_magic),
                              "placeholder", placeholder=True,
                              metrics={"declared_len": ph["len"],
                                       "magic_source": "tag" if tag_magic else "head_hex"})
        return TypeResult(T4_OPAQUE, "placeholder opaque(len=%d)" % ph["len"],
                          "placeholder", placeholder=True,
                          metrics={"declared_len": ph["len"]})

    buf = _to_bytes(value)
    if not buf:
        return TypeResult(T1_TEXT, "empty", "text")

    metrics: Dict[str, Any] = {"len_bytes": len(buf)}

    # Printable ceiling -- blocks T2 for text-like buffers
    pr = _printable_ratio(buf)
    metrics["printable"] = round(pr, 4)
    t2_ok = pr < PRINTABLE_CEIL
    if not t2_ok:
        metrics["t2_blocked_by_printable"] = True

    # Layer 1 -- magic (T3)
    magic = None
    if any(t in tagstr for t in MAGIC_TAGS):
        magic = next(t for t in MAGIC_TAGS if t in tagstr)
    else:
        magic = _content_magic(buf)
    if magic:
        nested = None
        if parse_nested_payload and ("pickle" in magic):
            nested = parse_nested(buf, depth=depth)
        return TypeResult(T3_STRUCTURED, "magic(%s)" % magic, "magic",
                          nested=nested, metrics=metrics)

    # Layer 2 -- declared dtype from sibling arguments
    decl = declared_width(siblings)
    if decl is not None:
        w, pset, nm = decl
        if pset is S_INT:
            r, n = _int_signext(buf, w)
            metrics["int_signext"] = round(r, 4)
            if n >= N_MIN and r >= TAU and t2_ok:
                return TypeResult(T2_NUMERIC, "declared %s signext=%.3f" % (nm, r),
                                  "declared", width=w, metrics=metrics)
        else:
            p, n = _pi(buf, w, pset)
            metrics["pi_%s" % nm] = round(p, 4)
            metrics["n_%s" % nm] = n
            if n >= N_MIN and p >= TAU and t2_ok:
                return TypeResult(T2_NUMERIC, "declared %s pi=%.3f n=%d" % (nm, p, n),
                                  "declared", width=w, metrics=metrics)

    # Layer 3 -- specification-derived tests (strong float, integer, weak support)
    for w, pset, nm in _FLOAT_SPECS:
        p, n = _pi(buf, w, pset)
        metrics["pi_%s" % nm.replace("/", "_")] = round(p, 4)
        if n >= N_MIN and p >= TAU and t2_ok:
            return TypeResult(T2_NUMERIC, "pi_%s=%.3f n=%d" % (nm, p, n),
                              "spec", width=w, metrics=metrics)
    for w in (8, 4):
        r, n = _int_signext(buf, w)
        if n >= N_MIN and r >= TAU and t2_ok:
            metrics["int_signext_w%d" % w] = round(r, 4)
            return TypeResult(T2_NUMERIC, "int%d signext=%.3f" % (w * 8, r),
                              "spec", width=w, metrics=metrics)
    for w in (8, 4, 2):
        s, n = _support(buf, w)
        if n >= N_WEAK and s <= SIGMA and t2_ok:
            metrics["supp_w%d" % w] = s
            return TypeResult(T2_NUMERIC, "supp_w%d=%d n=%d" % (w, s, n),
                              "spec", width=w, metrics=metrics)

    # Layer 4 -- text
    if pr >= PRINTABLE_STRONG:
        return TypeResult(T1_TEXT, "printable=%.3f" % pr, "text", metrics=metrics)
    if pr >= PRINTABLE_WEAK:
        return TypeResult(T1_TEXT, "printable=%.3f(weak)" % pr, "text", metrics=metrics)

    # Fallback -- opaque
    return TypeResult(T4_OPAQUE, "opaque printable=%.3f" % pr, "fallback", metrics=metrics)


# ══════════════════════════════════════════════════════════════════════════
# Role assignment
# ══════════════════════════════════════════════════════════════════════════
R1_VALUE = "R1"
R2_NAME = "R2"
R3_CODE = "R3"

_RESOLVERS_PATH = Path(__file__).resolve().parent.parent / "resolvers.yaml"


def _load_name_taking() -> Dict[str, Sequence[int]]:
    import yaml
    with open(_RESOLVERS_PATH, "r", encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    if not isinstance(spec, dict) or not spec.get("attribute_resolvers"):
        raise RuntimeError("resolvers.yaml is empty or malformed: %s"
                           % _RESOLVERS_PATH)

    out: Dict[str, Sequence[int]] = {}
    # Shared with Stage 2: attribute/module resolvers and their name positions
    for key in ("attribute_resolvers", "module_resolvers"):
        for e in (spec.get(key) or []):
            if not e.get("stage3_role", True):
                continue
            pos = e.get("stage3_positions") or [e["name_arg"]]
            out[str(e["canonical"])] = tuple(int(i) for i in pos)
    # Stage 3 only: callables whose argument is a name but which do not resolve
    for e in (spec.get("stage3_only_name_taking") or []):
        out[str(e["canonical"])] = tuple(int(i) for i in e["positions"])
    return out


NAME_TAKING: Dict[str, Sequence[int]] = _load_name_taking()

CODE_TAKING: Dict[str, Sequence[int]] = {
    "builtins.eval": (0,),
    "builtins.exec": (0,),
    "builtins.compile": (0,),
    "builtins.execfile": (0,),
    "os.system": (0,),
    "os.popen": (0,),
    "subprocess.getoutput": (0,),
    "subprocess.getstatusoutput": (0,),
}

IMPOSSIBLE_TYPES_FOR = {R2_NAME: ("T2", "T3", "T4"), R3_CODE: ("T2",)}


def assign_roles(canonical: str,
                 arguments_meta: Optional[Sequence[Dict[str, Any]]],
                 name_role_idx: Optional[Iterable[int]] = None) -> List[str]:
    """Internal implementation detail."""
    meta = list(arguments_meta or [])
    nr = set(int(i) for i in (name_role_idx or []) if isinstance(i, int))
    name_pos = set(NAME_TAKING.get(canonical, ()))
    code_pos = set(CODE_TAKING.get(canonical, ()))

    roles: List[str] = []
    for pos, m in enumerate(meta):
        idx = m.get("opcode_idx")
        origin = m.get("origin_idx")
        # Position within the call tuple (falls back to enumeration order)
        ap = m.get("arg_pos")
        ap = pos if not isinstance(ap, int) else ap
        if (isinstance(idx, int) and idx in nr) or (isinstance(origin, int) and origin in nr):
            roles.append(R2_NAME)
        elif ap in code_pos:
            roles.append(R3_CODE)
        elif ap in name_pos:
            roles.append(R2_NAME)
        else:
            roles.append(R1_VALUE)
    return roles


def impossible_combination(type_: str, role: str) -> bool:
    """Internal implementation detail."""
    return type_ in IMPOSSIBLE_TYPES_FOR.get(role, ())
