#!/usr/bin/env python3
"""Internal implementation detail."""
from __future__ import annotations

import ast
import dataclasses
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

import pickletools

from .rule_loader import TupleSlicingRuleSet, load_rules

# Module-level default rule set (loaded from detector/rules.yaml)
RULES: TupleSlicingRuleSet = load_rules()


UNICODE_OPS = {
    # Protocol 3+ binary unicode
    "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8", "LONG_BINUNICODE",
    
    "UNICODE",
    
    
    "STRING",
}

BYTES_OPS = {
    # Protocol 3+ binary bytes (genops arg is bytes)
    "BINBYTES", "SHORT_BINBYTES", "BINBYTES8",
    # bytearray (Protocol 5)
    "BYTEARRAY8",
}

TUPLE_OPS = {
    "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
    "EMPTY_TUPLE",
}

CALLABLE_HINT_OPS = {
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST",
}


_BINARY_NON_ASCII_THRESHOLD = 0.30
_BINARY_MIN_LEN = 64


OP_SEQUENCE_MAX = 2000

ARGREPR_MAX = 200



_URL_SIGNAL_RE = re.compile(
    r"(?:https?|ftp|ftps|sftp|file|ssh|telnet|ldap|smb|nfs)://\S",
    re.IGNORECASE,
)







_PATH_SIGNAL_RE = re.compile(
    r"(?:"
    r"(?:^|(?<=[\s\"'`,;({[]))/"      
    r"[a-zA-Z0-9_.~@%-][a-zA-Z0-9_.~@%/+-]*"  
    r"|[A-Za-z]:[/\\]\S"             
    r"|\\\\[a-zA-Z0-9._-]+[/\\]"     
    r")",
)



#:




#:




#:



ANNOTATION_ONLY_PREFIXES = (
    "entropy>=", "entropy_binary_data", "high_entropy", "literal_truncated",
)


def _generating(reasons: List[str]) -> List[str]:
    """Internal implementation detail."""
    return [r for r in reasons
            if not any(r.startswith(p) for p in ANNOTATION_ONLY_PREFIXES)]


def is_shell_like(u: str, rules: TupleSlicingRuleSet = RULES) -> bool:
    """Internal implementation detail."""
    if not u:
        return False

    s = u.strip()

    
    if any(p.compiled.match(s) for p in rules.shortcut_patterns):
        return True

    
    if len(s) < rules.shell_min_len:
        return False

    score = 0
    has_cmd = False
    has_strong_sig = False

    
    for p in rules.scored_patterns:
        
        if p.allowlist_ref:
            if rules.allowlist_patterns[p.allowlist_ref].search(s):
                continue  

        if p.compiled.search(s):
            score += p.score
            if p.name == "SHELL_CMD_RE":
                has_cmd = True
            if p.is_strong:
                has_strong_sig = True

    
    if re.search(r"\s", s):
        score += 1

    
    if not has_cmd and not has_strong_sig:
        return False

    return score >= rules.shell_score_threshold


# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#

# ----





#

# -------------------------------------------------



#








#




#     ④ (has_token ∨ has_strong) ∧ score ≥ threshold  → True

#







def is_python_code_like(u: str, rules: TupleSlicingRuleSet = RULES) -> Tuple[bool, List[str]]:
    """Internal implementation detail."""
    if not u:
        return False, []
    s = u.strip()
    evidence: List[str] = []

    
    for p in rules.python_shortcut_patterns:
        if p.compiled.search(s):
            return True, [p.name]

    
    if len(s) < rules.python_min_len:
        return False, []

    
    score = 0
    has_token = False
    has_strong = False
    token_rules = {
        "PY_CALL_SYNTAX_RE", "PY_STMT_STRUCTURE_RE",
        "PY_IMPORT_STMT_RE", "PY_CODE_STRING_RE",
    }

    for p in rules.python_scored_patterns:
        if p.compiled.search(s):
            score += p.score
            evidence.append(p.name)
            if p.name in token_rules:
                has_token = True
            if p.is_strong:
                has_strong = True

    
    if not has_token and not has_strong:
        return False, []
    if score >= rules.python_score_threshold:
        return True, evidence
    return False, []


def shannon_entropy_utf8(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode("utf-8", errors="ignore")
    if not b:
        return 0.0
    freq = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    n = len(b)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _stratified_sample(data, limit: int):
    """Internal implementation detail."""
    n = len(data)
    if not limit or n <= limit:
        return data
    chunks = 32
    per = max(limit // chunks, 1)
    step = n // chunks
    parts = []
    for k in range(chunks):
        off = k * step
        parts.append(data[off:off + per])
    return (b"" if isinstance(data, bytes) else "").join(parts)


def _analyze_bytes(data: bytes, rules: TupleSlicingRuleSet) -> Tuple[bool, List[str]]:
    """Internal implementation detail."""
    if len(data) < rules.bytes_min_size:
        return False, []
    reasons: List[str] = []
    suspicious = False

    
    if data[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e'):
        reasons.append("zlib_magic")
        suspicious = True
    
    if len(data) > 2 and data[0] == 0x80 and 2 <= data[1] <= 5:
        reasons.append("pickle_magic")
        suspicious = True
    
    if data[:1] == b'c' and b'\n' in data[:32]:
        reasons.append("pickle_magic_p0")
        suspicious = True

    
    
    
    
    
    limit = getattr(rules, "literal_scan_max_len", 0) or 0
    sample = _stratified_sample(data, limit)
    ent = shannon_entropy_bytes(sample)
    if ent > rules.bytes_entropy_threshold:
        
        
        
        reasons.append(f"high_entropy({ent:.2f})")
        suspicious = True
        if len(sample) < len(data):
            reasons.append(f"literal_truncated({len(data)})")

    
    suspicious = bool(_generating(reasons))
    return suspicious, reasons






_NATIVE_LIB_RE = re.compile(
    r"[^\s/\\]{0,200}\.(?:so|dll|dylib)(?:\.[0-9]+)?\b", re.IGNORECASE
)


def meets_any_condition(u: str, rules: TupleSlicingRuleSet = RULES) -> Tuple[bool, List[str]]:
    """Internal implementation detail."""
    reasons: List[str] = []
    ent_threshold = rules.meets_condition_ent_threshold

    
    full_len = len(u)
    limit = getattr(rules, "literal_scan_max_len", 0) or 0
    truncated = bool(limit and full_len > limit)
    scan = u[:limit] if truncated else u

    
    for name, rx in rules.structural_signal_patterns:
        if rx.search(scan):
            reasons.append(name)

    
    
    
    ent_sample = _stratified_sample(u, limit)
    ent = shannon_entropy_utf8(ent_sample)
    if ent >= ent_threshold:
        non_ascii_ratio = sum(1 for c in ent_sample if ord(c) > 127) / max(len(ent_sample), 1)
        if (non_ascii_ratio > rules.binary_non_ascii_threshold
                and full_len >= rules.binary_min_len):
            
            reasons.append(f"entropy_binary_data ({ent:.2f}, non_ascii={non_ascii_ratio:.0%})")
        else:
            
            reasons.append(f"entropy>={ent_threshold:.1f} ({ent:.2f})")

    # ③ shell command
    if is_shell_like(scan, rules=rules):
        reasons.append("has_shell_pattern")

    
    if _NATIVE_LIB_RE.search(scan):
        reasons.append("native_lib_path")

    
    if _URL_SIGNAL_RE.search(scan):
        reasons.append("has_url")
    elif _PATH_SIGNAL_RE.search(scan):
        reasons.append("has_path")

    
    
    py_ok, py_evidence = is_python_code_like(scan, rules=rules)
    if py_ok:
        reasons.append("has_python_code(" + ",".join(py_evidence) + ")")

    
    
    if truncated and reasons:
        reasons.append(f"literal_truncated({full_len})")

    
    return (len(_generating(reasons)) > 0), reasons


@dataclass
class OpLine:
    idx: int
    pos: int
    opname: str
    argrepr: str

    def render(self) -> str:
        
        
        if self.argrepr:
            return f"{self.idx:6d}: @{self.pos:<8d} {self.opname:<16s} {self.argrepr}"
        return f"{self.idx:6d}: @{self.pos:<8d} {self.opname}"


@dataclass
class StackItem:
    """Internal implementation detail."""
    kind: str          # "unicode"|"callable"|"tuple"|"list"|"dict"|"set"
                       # |"bytes"|"int"|"float"|"bool"|"none"
                       # |"result"|"ext"|"persid"|"opaque"
    opcode_idx: int    
    origin_idx: int    
    value: object      
    is_suspicious: bool = False
    reasons: List[str] = field(default_factory=list)
    children: List["StackItem"] = field(default_factory=list)
    callable_name: str = ""
    
    
    
    callable_mod: str = ""
    callable_name_part: str = ""
    callable_opname: str = ""
    
    
    
    sym_module: str = ""
    
    
    
    
    
    sym_pending_force: bool = False
    sym_pending_mod: str = ""
    sym_pending_name: str = ""
    
    
    #
    
    
    
    
    
    sym_via: List[str] = field(default_factory=list)
    
    
    name_role_idx: List[int] = field(default_factory=list)
    
    
    
    from_memo: bool = False
    memo_origin_idx: Optional[int] = None   




NESTED_RAW_MAX = 1 << 20
_NESTED_MAGIC_TAGS = ("zlib_magic", "pickle_magic", "pickle_magic_p0")


def _collect_literals(item: StackItem, out: Optional[List[dict]] = None) -> List[dict]:
    """Internal implementation detail."""
    if out is None:
        out = []
    if item.kind in ("unicode", "bytes"):
        v = item.value
        entry = {
            "kind": item.kind,
            "opcode_idx": item.opcode_idx,
            "origin_idx": item.origin_idx,
            "reasons": list(item.reasons),
            "suspicious": bool(item.is_suspicious),
        }
        if item.kind == "unicode" and isinstance(v, str):
            entry["value"] = v
            entry["len"] = len(v)
        elif item.kind == "bytes" and isinstance(v, (bytes, bytearray)):
            entry["len"] = len(v)
            entry["head_hex"] = bytes(v[:16]).hex()
            
            if (len(v) <= NESTED_RAW_MAX
                    and any(t in " ".join(item.reasons) for t in _NESTED_MAGIC_TAGS)):
                entry["nested_raw_hex"] = bytes(v).hex()
        out.append(entry)
    for c in item.children:
        _collect_literals(c, out)
    return out


# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#

# ----





#

# ----





#

#     getattr(<sym_module 'os'>, 'system')


#








#



_RESOLVERS_PATH = Path(__file__).resolve().parent.parent / "resolvers.yaml"


def _load_resolver_spec() -> Dict[str, object]:
    import yaml
    with open(_RESOLVERS_PATH, "r", encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    if not isinstance(spec, dict) or not spec.get("attribute_resolvers"):
        raise RuntimeError("resolvers.yaml is empty or malformed: %s"
                           % _RESOLVERS_PATH)
    return spec


def _names_of(entry: Dict[str, object]) -> List[str]:
    """Internal implementation detail."""
    out = [str(entry["canonical"])]
    out.extend(str(a) for a in (entry.get("aliases") or []))
    return out


_SPEC = _load_resolver_spec()


NAME_RESOLVERS: Dict[str, Tuple[int, int]] = {
    n: (int(e["obj"]), int(e["name_arg"]))
    for e in _SPEC["attribute_resolvers"] for n in _names_of(e)
}


#:



GENERATOR_RESOLVERS: FrozenSet[str] = frozenset(
    n for e in _SPEC["attribute_resolvers"] if e.get("generator") for n in _names_of(e)
)


#:


#:




FORCING_PRIMITIVES: Dict[str, bool] = {
    n: bool(e["advances"])
    for e in (_SPEC.get("forcing_primitives") or []) for n in _names_of(e)
}


MODULE_RESOLVERS: Dict[str, int] = {
    n: int(e["name_arg"])
    for e in (_SPEC.get("module_resolvers") or []) for n in _names_of(e)
}


def _lit_str(item: Optional[StackItem]) -> str:
    """Internal implementation detail."""
    if item is None or item.kind != "unicode":
        return ""
    return item.value if isinstance(item.value, str) else ""


def _arg_at(args_item: Optional[StackItem], i: int) -> Optional[StackItem]:
    """Internal implementation detail."""
    if args_item is None:
        return None
    ch = args_item.children
    return ch[i] if 0 <= i < len(ch) else None


def _callable_key(item: StackItem) -> str:
    """Internal implementation detail."""
    return item.callable_name or ("%s.%s" % (item.callable_mod, item.callable_name_part))


def _resolve_symbolic(callable_item: StackItem,
                      args_item: Optional[StackItem]) -> Tuple[str, str, str]:
    """Internal implementation detail."""
    key = _callable_key(callable_item)

    if key in MODULE_RESOLVERS:
        name = _lit_str(_arg_at(args_item, MODULE_RESOLVERS[key]))
        
        return (name.split(".")[0] if name else ""), "", ""

    spec = NAME_RESOLVERS.get(key)
    if spec is None:
        return "", "", ""
    obj_i, name_i = spec
    obj = _arg_at(args_item, obj_i)
    nm = _lit_str(_arg_at(args_item, name_i))
    if not nm:
        return "", "", ""
    
    if "." in nm and not obj:
        mod, _, leaf = nm.rpartition(".")
        return "", mod, leaf
    mod = ""
    if obj is not None:
        
        
        
        
        
        mod = obj.sym_module or _lit_str(obj) or obj.callable_name
        
        
        
        while mod.endswith(".__new__"):
            mod = mod[: -len(".__new__")]
    if not mod and "." in nm:
        mod, _, nm = nm.rpartition(".")
    if not mod:
        
        
        return "", "", ""
    return "", mod, nm


def _merge_via(callable_item: StackItem, args_item: Optional[StackItem],
               key: str) -> List[str]:
    """Internal implementation detail."""
    out: List[str] = []
    for src in [callable_item] + list((args_item.children if args_item else [])):
        for v in getattr(src, "sym_via", ()) or ():
            if v not in out:
                out.append(v)
    if key and key not in out:
        out.append(key)
    return out


def _promote_symbolic(result: StackItem, mod: str, name: str,
                      via: Optional[Sequence[str]] = None) -> None:
    """Internal implementation detail."""
    result.callable_mod = mod
    result.callable_name_part = name
    result.callable_name = ("%s.%s" % (mod, name)) if mod else name
    result.callable_opname = "SYMBOLIC_ATTR"
    if via:
        result.sym_via = list(via)


def _apply_symbolic(result: StackItem, callable_item: StackItem,
                    args_item: Optional[StackItem]) -> None:
    """Internal implementation detail."""
    key = _callable_key(callable_item)

    
    
    
    advances = FORCING_PRIMITIVES.get(key)
    if advances is not None:
        src = _arg_at(args_item, 0)
        if src is not None and src.sym_pending_force:
            via = _merge_via(callable_item, args_item, key)
            if advances:
                _promote_symbolic(result, src.sym_pending_mod,
                                  src.sym_pending_name, via)
            else:
                result.sym_pending_force = True
                result.sym_pending_mod = src.sym_pending_mod
                result.sym_pending_name = src.sym_pending_name
                result.sym_via = via
        return

    sym_mod, mod, name = _resolve_symbolic(callable_item, args_item)
    if sym_mod:
        result.sym_module = sym_mod
        result.callable_name = sym_mod
        result.callable_mod = sym_mod
        result.callable_name_part = ""
        result.callable_opname = "SYMBOLIC_MODULE"
        result.sym_via = _merge_via(callable_item, args_item, key)
        return
    if not name:
        return

    
    
    
    if key in GENERATOR_RESOLVERS:
        result.sym_pending_force = True
        result.sym_pending_mod = mod
        result.sym_pending_name = name
        result.sym_via = _merge_via(callable_item, args_item, key)
        return

    _promote_symbolic(result, mod, name,
                      _merge_via(callable_item, args_item, key))


def _callable_ref(item: StackItem) -> dict:
    """Internal implementation detail."""
    ref = {
        "module": item.callable_mod,
        "name": item.callable_name_part,
        "opname": item.callable_opname,
        "qualname": item.callable_name,
    }
    
    
    if getattr(item, "sym_via", None):
        ref["via"] = list(item.sym_via)
    return ref


def _earliest_idx(item: StackItem) -> int:
    """Internal implementation detail."""
    best = item.origin_idx
    for c in item.children:
        best = min(best, _earliest_idx(c))
    return best


def _slice_start(item: StackItem) -> int:
    """Internal implementation detail."""
    if item.from_memo:
        return item.opcode_idx
    best = item.origin_idx
    for c in item.children:
        best = min(best, _slice_start(c))
    return best


def _collect_memo_origins(item: StackItem, out: Optional[List[dict]] = None) -> List[dict]:
    """Internal implementation detail."""
    if out is None:
        out = []
    if item.from_memo:
        out.append({
            "get_idx": item.opcode_idx,
            "defined_at": item.memo_origin_idx,
            "kind": item.kind,
            "callable_name": item.callable_name or None,
        })
        return out          
    for c in item.children:
        _collect_memo_origins(c, out)
    return out


def _is_suspicious(item: StackItem) -> bool:
    """Internal implementation detail."""
    return item.is_suspicious or any(_is_suspicious(c) for c in item.children)


def _collect_suspicious_unicode(item: StackItem) -> List[StackItem]:
    """Internal implementation detail."""
    out: List[StackItem] = []
    if item.kind == "unicode" and item.is_suspicious:
        out.append(item)
    for c in item.children:
        out.extend(_collect_suspicious_unicode(c))
    return out


def _collect_all_unicode(item: StackItem) -> List[StackItem]:
    """Internal implementation detail."""
    out: List[StackItem] = []
    if item.kind == "unicode" and item.value:
        out.append(item)
    for c in item.children:
        out.extend(_collect_all_unicode(c))
    return out


def _collect_suspicious_bytes(item: StackItem) -> List[StackItem]:
    """Internal implementation detail."""
    out: List[StackItem] = []
    if item.kind == "bytes" and item.is_suspicious and item.value is not None:
        out.append(item)
    for c in item.children:
        out.extend(_collect_suspicious_bytes(c))
    return out


def _collect_all_bytes(item: StackItem) -> List[StackItem]:
    """Internal implementation detail."""
    out: List[StackItem] = []
    if item.kind == "bytes" and item.value is not None:
        out.append(item)
    for c in item.children:
        out.extend(_collect_all_bytes(c))
    return out


_CANON = None


def _canon_module():
    """Internal implementation detail."""
    global _CANON
    if _CANON is not None:
        return _CANON
    try:
        from classifier import canon as _c            
    except Exception:
        import importlib, sys as _sys
        cdir = str(Path(__file__).resolve().parent.parent / "classifier")
        if cdir not in _sys.path:
            _sys.path.insert(0, cdir)
        _c = importlib.import_module("canon")         
    _CANON = _c
    return _CANON


def _is_resolution_primitive(item: StackItem) -> bool:
    """Internal implementation detail."""
    k = _callable_key(item)
    return bool(k) and (k in NAME_RESOLVERS or k in MODULE_RESOLVERS or k in FORCING_PRIMITIVES)


def _in_denylist(item: StackItem, rules: "TupleSlicingRuleSet") -> bool:
    """Internal implementation detail."""
    S = rules.dangerous_callables_set
    if not S:
        return False
    raw = item.callable_name or ""
    if raw and raw in S:
        return True
    mod, name = item.callable_mod, item.callable_name_part
    if not (mod and name):
        if not raw or "." not in raw:
            return False
        mod, _, name = raw.rpartition(".")
    try:
        c = _canon_module()
        return c.canon(mod, name, 0).canonical in S
    except Exception:
        raise


def _emit_unresolvable(item: StackItem, idx: int, code: int,
                       results: list, used_ranges: list,
                       oplines: List[OpLine], opname: str) -> None:
    """Internal implementation detail."""
    if any(not (idx < r[0] or r[1] < idx) for r in used_ranges):
        return
    used_ranges.append([idx, idx, None])
    header = (
        "[match] unresolvable-reference | track=unresolvable | "
        "reasons=unresolvable_extension | opcode=%s | code=%d\n"
        "note=copyreg extension registry lookup; target not determinable from the stream" % (opname, code)
    )
    meta = {
        "reasons": ["unresolvable_extension"],
        "unicode": "", "unicode_val": "", "unicode_len": 0, "entropy": 0.0,
        "suspicious_index": idx, "s_idx": idx, "s_opname": opname,
        "callable_name": item.callable_name,
        "callable_idx": idx,
        "slice_start": idx, "slice_end": idx,
        "context_padding": 0,
        "invoke_opname": opname,
        "memo_origins": [],
        "callable_ref": _callable_ref(item),
        "arguments_meta": [],
        "name_role_idx": [],
    }
    results.append((idx, idx, header, meta))


def _handle_call(
    callable_item: StackItem,
    args_item: StackItem,
    reduce_idx: int,
    results: list,
    used_ranges: list,
    oplines: List[OpLine],
    rules: "TupleSlicingRuleSet",
) -> None:
    """Internal implementation detail."""
    _handle_call_unicode(callable_item, args_item, reduce_idx, results, used_ranges, oplines, rules)
    _handle_call_bytes(callable_item, args_item, reduce_idx, results, used_ranges, oplines, rules)


def _handle_call_unicode(
    callable_item: StackItem,
    args_item: StackItem,
    reduce_idx: int,
    results: list,
    used_ranges: list,
    oplines: List[OpLine],
    rules: "TupleSlicingRuleSet",
) -> None:
    """Internal implementation detail."""
    cname = callable_item.callable_name
    placeholder = False        

    
    
    
    
    #
    
    
    
    
    
    forced = bool(rules.enable_denylist and _in_denylist(callable_item, rules))

    
    
    
    

    if forced:
        leaves = _collect_all_unicode(args_item)
        if leaves:
            primary = min(leaves, key=lambda x: x.opcode_idx)
        else:
            
            
            
            
            
            primary = StackItem(
                kind="unicode",
                opcode_idx=callable_item.opcode_idx,
                origin_idx=callable_item.origin_idx,
                value="",
                reasons=["no_argument_literal"],
            )
            placeholder = True

    if not forced:
        if not _is_suspicious(args_item):
            return
        leaves = _collect_suspicious_unicode(args_item)
        if not leaves:
            return
        primary = min(leaves, key=lambda x: x.opcode_idx)

    
    
    semantic_start = min(_slice_start(callable_item), _slice_start(args_item))
    end_idx = reduce_idx
    
    padding = getattr(rules, "context_padding", None) or rules.slice_lookback
    start_idx = max(0, semantic_start - padding)

    
    
    
    
    
    if any(not (end_idx < r[0] or r[1] < semantic_start) for r in used_ranges):
        return

    
    
    
    
    
    
    
    
    
    #
    
    
    
    
    
    
    
    if not (placeholder or _is_resolution_primitive(callable_item)):
        used_ranges.append([semantic_start, end_idx, None])

    u_val = primary.value if isinstance(primary.value, str) else ""
    track_tag = "forced_callable" if forced else "content"
    header = (
        f"[match] tuple/callable-context | track={track_tag} | "
        f"reasons={','.join(primary.reasons)} | "
        f"unicode_len={len(u_val)} | entropy={shannon_entropy_utf8(u_val):.2f}\n"
        f"unicode_preview={repr(u_val[:240] + ('...(trunc)' if len(u_val) > 240 else ''))}"
    )
    meta = {
        "reasons": primary.reasons,
        "unicode": u_val,
        "unicode_val": u_val,
        "unicode_len": len(u_val),
        "entropy": float(f"{shannon_entropy_utf8(u_val):.2f}"),
        "suspicious_index": primary.opcode_idx,
        "s_idx": primary.opcode_idx,
        "s_opname": oplines[primary.opcode_idx].opname if primary.opcode_idx < len(oplines) else "",
        "callable_name": callable_item.callable_name,
        "callable_idx": callable_item.origin_idx,
        "unicode_idx": primary.opcode_idx,
        "tuple_idx": args_item.opcode_idx,
        "end_idx": end_idx,
        "forced_by_callable": forced,
        
        "slice_start": semantic_start,
        "slice_end": end_idx,
        "context_padding": padding,
        "invoke_opname": oplines[reduce_idx].opname if reduce_idx < len(oplines) else "",
        
        "memo_origins": (_collect_memo_origins(callable_item)
                         + _collect_memo_origins(args_item)),
        
        "callable_ref": _callable_ref(callable_item),          # T3
        "arguments_meta": _collect_literals(args_item),        # T5
        "name_role_idx": list(callable_item.name_role_idx),    # T6
    }
    if placeholder:
        
        
        meta["placeholder"] = True
    results.append((start_idx, end_idx, header, meta))


def _drop_shadowed_placeholders(raw: list) -> list:
    """Internal implementation detail."""
    real_ends = {r[3].get("slice_end") for r in raw
                 if isinstance(r[3], dict) and not r[3].get("placeholder")}
    out, seen = [], set()
    for r in raw:
        m = r[3] if isinstance(r[3], dict) else {}
        if not m.get("placeholder"):
            out.append(r)
            continue
        end = m.get("slice_end")
        if end in real_ends or end in seen:
            continue
        seen.add(end)
        out.append(r)
    return out


def _handle_call_bytes(
    callable_item: StackItem,
    args_item: StackItem,
    reduce_idx: int,
    results: list,
    used_ranges: list,
    oplines: List[OpLine],
    rules: "TupleSlicingRuleSet",
) -> None:
    """Internal implementation detail."""
    cname = callable_item.callable_name
    bdc_set = getattr(rules, "bytes_dangerous_callables_set", frozenset())

    
    forced_bytes = bool(
        getattr(rules, "enable_denylist", False)
        and cname and bdc_set and cname in bdc_set
    )

    if forced_bytes:
        byte_leaves = _collect_all_bytes(args_item)
    elif _is_suspicious(args_item):
        byte_leaves = _collect_suspicious_bytes(args_item)
    else:
        return

    if not byte_leaves:
        return

    
    
    
    
    

    primary_byte = byte_leaves[0]
    data: bytes = primary_byte.value if isinstance(primary_byte.value, bytes) else b""
    hex_prefix = data[:16].hex() if data else ""
    fmts = primary_byte.reasons

    semantic_start = min(_slice_start(callable_item), _slice_start(args_item))
    b_end = reduce_idx
    padding = getattr(rules, "context_padding", None) or rules.slice_lookback
    b_start = max(0, semantic_start - padding)

    if any(not (b_end < r[0] or r[1] < semantic_start) for r in used_ranges):
        return
    used_ranges.append([semantic_start, b_end, None])

    bytes_repr = f"[BINBYTES:{hex_prefix} len={len(data)} fmt={','.join(fmts)}]"
    track_tag = "forced_callable" if forced_bytes else "content"
    header = (
        f"[match] bytes/callable-context | track={track_tag} | "
        f"reasons={','.join(fmts)} | bytes_len={len(data)} | "
        f"entropy={shannon_entropy_bytes(data):.2f}\n"
        f"bytes_preview={hex_prefix}..."
    )
    meta = {
        "reasons": fmts,
        "unicode": bytes_repr,       
        "unicode_val": bytes_repr,   
        "unicode_len": len(bytes_repr),
        "entropy": float(f"{shannon_entropy_bytes(data):.2f}"),
        "suspicious_index": primary_byte.opcode_idx,
        "s_idx": primary_byte.opcode_idx,
        "s_opname": oplines[primary_byte.opcode_idx].opname if primary_byte.opcode_idx < len(oplines) else "",
        "callable_name": cname,
        "callable_idx": callable_item.origin_idx,
        "unicode_idx": primary_byte.opcode_idx,
        "tuple_idx": args_item.opcode_idx,
        "end_idx": b_end,
        "forced_by_callable": forced_bytes,
        "slice_start": semantic_start,
        "slice_end": b_end,
        "context_padding": padding,
        "invoke_opname": oplines[reduce_idx].opname if reduce_idx < len(oplines) else "",
        "memo_origins": (_collect_memo_origins(callable_item)
                         + _collect_memo_origins(args_item)),
        
        "callable_ref": _callable_ref(callable_item),          # T3
        "arguments_meta": _collect_literals(args_item),        # T5 (+T5b nested_raw_hex)
        "name_role_idx": list(callable_item.name_role_idx),    # T6
    }
    results.append((b_start, b_end, header, meta))


def simulate_pickle_stack(
    oplines: List[OpLine],
    unicode_by_idx: Dict[int, str],
    rules: "TupleSlicingRuleSet",
    bytes_by_idx: Optional[Dict[int, bytes]] = None,
) -> List[tuple]:
    """Internal implementation detail."""
    import copy as _copy

    stack: List[StackItem] = []
    metastack: List[List[StackItem]] = []
    memo: Dict[int, StackItem] = {}
    results: list = []
    used_ranges: list = []

    def _safe_pop(n: int = 1):
        if len(stack) < n:
            return None
        items = stack[-n:]
        del stack[-n:]
        return items

    def _pop_mark() -> List[StackItem]:
        if not metastack:
            return []
        items = list(stack)
        stack.clear()
        stack.extend(metastack.pop())
        return items

    for op in oplines:
        opname = op.opname
        idx = op.idx

        
        if opname in ("PROTO", "FRAME", "STOP"):
            continue

        # ── UNICODE push ──────────────────────────────────────────────
        elif opname in UNICODE_OPS:
            val = unicode_by_idx.get(idx, "")
            ok, reasons = meets_any_condition(val, rules=rules) if val else (False, [])
            stack.append(StackItem(
                kind="unicode", opcode_idx=idx, origin_idx=idx,
                value=val, is_suspicious=ok, reasons=list(reasons),
            ))

        # ── BYTES push ────────────────────────────────────────────────
        elif opname in BYTES_OPS:
            
            bdata = bytes_by_idx.get(idx, b"") if bytes_by_idx else b""
            is_susp_b, reasons_b = _analyze_bytes(bdata, rules) if bdata else (False, [])
            stack.append(StackItem(
                kind="bytes", opcode_idx=idx, origin_idx=idx,
                value=bdata if bdata else None,
                is_suspicious=is_susp_b,
                reasons=list(reasons_b),
            ))

        elif opname in ("BINSTRING", "SHORT_BINSTRING"):
            
            if idx in unicode_by_idx:
                val = unicode_by_idx[idx]
                ok, reasons = meets_any_condition(val, rules=rules) if val else (False, [])
                stack.append(StackItem(kind="unicode", opcode_idx=idx, origin_idx=idx,
                                       value=val, is_suspicious=ok, reasons=list(reasons)))
            else:
                
                stack.append(StackItem(kind="bytes", opcode_idx=idx, origin_idx=idx, value=None))

        # ── INT push ─────────────────────────────────────────────────
        elif opname in ("BININT", "BININT1", "BININT2", "INT", "LONG", "LONG1", "LONG4"):
            try:
                val = ast.literal_eval(op.argrepr)
            except Exception:
                val = None
            stack.append(StackItem(kind="int", opcode_idx=idx, origin_idx=idx, value=val))

        # ── FLOAT push ───────────────────────────────────────────────
        elif opname in ("BINFLOAT", "FLOAT"):
            stack.append(StackItem(kind="float", opcode_idx=idx, origin_idx=idx, value=None))

        # ── BOOL push ────────────────────────────────────────────────
        elif opname in ("NEWFALSE", "NEWTRUE"):
            stack.append(StackItem(kind="bool", opcode_idx=idx, origin_idx=idx,
                                   value=(opname == "NEWTRUE")))

        # ── NONE push ────────────────────────────────────────────────
        elif opname == "NONE":
            stack.append(StackItem(kind="none", opcode_idx=idx, origin_idx=idx, value=None))

        # ── GLOBAL ───────────────────────────────────────────────────
        elif opname == "GLOBAL":
            try:
                raw_arg = ast.literal_eval(op.argrepr)
                parts = raw_arg.strip().split(None, 1)
                cname = f"{parts[0]}.{parts[1]}" if len(parts) == 2 else raw_arg
            except Exception:
                cname = op.argrepr
            _gm, _gn = (parts[0], parts[1]) if len(parts) == 2 else ("", cname)
            stack.append(StackItem(kind="callable", opcode_idx=idx, origin_idx=idx,
                                   value=None, callable_name=cname,
                                   callable_mod=_gm, callable_name_part=_gn,
                                   callable_opname="GLOBAL"))

        # ── STACK_GLOBAL ─────────────────────────────────────────────
        # TOS=name, TOS-1=module → pop 2
        elif opname == "STACK_GLOBAL":
            popped = _safe_pop(2)
            if popped is None:
                continue
            module_item, name_item = popped[0], popped[1]
            mod = module_item.value if isinstance(module_item.value, str) else ""
            name = name_item.value if isinstance(name_item.value, str) else ""
            cname = f"{mod}.{name}" if (mod and name) else (mod or name or "")
            
            _nr = [i for i in (module_item.origin_idx, name_item.origin_idx)
                   if isinstance(i, int)]
            stack.append(StackItem(kind="callable", opcode_idx=idx, origin_idx=idx,
                                   value=None, callable_name=cname,
                                   callable_mod=mod, callable_name_part=name,
                                   callable_opname="STACK_GLOBAL",
                                   name_role_idx=_nr))

        
        elif opname == "EMPTY_TUPLE":
            stack.append(StackItem(kind="tuple", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=[]))

        elif opname == "TUPLE1":
            popped = _safe_pop(1)
            if popped is None:
                continue
            children = list(popped)
            stack.append(StackItem(kind="tuple", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=children,
                                   is_suspicious=any(_is_suspicious(c) for c in children)))

        elif opname == "TUPLE2":
            popped = _safe_pop(2)
            if popped is None:
                continue
            children = list(popped)
            stack.append(StackItem(kind="tuple", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=children,
                                   is_suspicious=any(_is_suspicious(c) for c in children)))

        elif opname == "TUPLE3":
            popped = _safe_pop(3)
            if popped is None:
                continue
            children = list(popped)
            stack.append(StackItem(kind="tuple", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=children,
                                   is_suspicious=any(_is_suspicious(c) for c in children)))

        elif opname == "TUPLE":
            mark_items = _pop_mark()
            children = list(mark_items)
            stack.append(StackItem(kind="tuple", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=children,
                                   is_suspicious=any(_is_suspicious(c) for c in children)))

        # ── MARK ─────────────────────────────────────────────────────
        elif opname == "MARK":
            metastack.append(list(stack))
            stack.clear()

        # ── LIST ─────────────────────────────────────────────────────
        elif opname == "EMPTY_LIST":
            stack.append(StackItem(kind="list", opcode_idx=idx, origin_idx=idx, value=None))

        elif opname == "LIST":
            mark_items = _pop_mark()
            stack.append(StackItem(kind="list", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=list(mark_items)))

        # ── DICT ─────────────────────────────────────────────────────
        elif opname == "EMPTY_DICT":
            stack.append(StackItem(kind="dict", opcode_idx=idx, origin_idx=idx, value=None))

        elif opname == "DICT":
            mark_items = _pop_mark()
            stack.append(StackItem(kind="dict", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=list(mark_items)))

        # ── SET ──────────────────────────────────────────────────────
        elif opname == "EMPTY_SET":
            stack.append(StackItem(kind="set", opcode_idx=idx, origin_idx=idx, value=None))

        elif opname == "FROZENSET":
            mark_items = _pop_mark()
            stack.append(StackItem(kind="set", opcode_idx=idx, origin_idx=idx,
                                   value=None, children=list(mark_items)))

        # ── REDUCE ───────────────────────────────────────────────────
        # stack: ..., callable, args_tuple → result
        elif opname == "REDUCE":
            popped = _safe_pop(2)
            if popped is None:
                continue
            callable_item, args_item = popped[0], popped[1]
            _handle_call(callable_item, args_item, idx, results, used_ranges, oplines, rules)
            _res = StackItem(
                kind="result", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name=callable_item.callable_name,
                
                
                
                
                callable_mod=callable_item.callable_mod,
                callable_name_part=callable_item.callable_name_part,
                callable_opname=callable_item.callable_opname,
                name_role_idx=list(callable_item.name_role_idx),
                is_suspicious=_is_suspicious(args_item),
                children=[callable_item, args_item],
            )
            _apply_symbolic(_res, callable_item, args_item)
            stack.append(_res)

        # ── NEWOBJ ───────────────────────────────────────────────────
        # stack: ..., cls, args_tuple → instance
        elif opname == "NEWOBJ":
            popped = _safe_pop(2)
            if popped is None:
                continue
            cls_item, args_item = popped[0], popped[1]
            _handle_call(cls_item, args_item, idx, results, used_ranges, oplines, rules)
            _res = StackItem(
                kind="result", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name=cls_item.callable_name,
                
                
                
                
                callable_mod=cls_item.callable_mod,
                callable_name_part=cls_item.callable_name_part,
                callable_opname=cls_item.callable_opname,
                name_role_idx=list(cls_item.name_role_idx),
                is_suspicious=_is_suspicious(args_item),
                children=[cls_item, args_item],
            )
            _apply_symbolic(_res, cls_item, args_item)
            stack.append(_res)

        # ── NEWOBJ_EX ────────────────────────────────────────────────
        # stack: ..., cls, args_tuple, kwargs_dict → instance
        elif opname == "NEWOBJ_EX":
            popped = _safe_pop(3)
            if popped is None:
                continue
            cls_item, args_item, kwargs_item = popped[0], popped[1], popped[2]
            combined = StackItem(
                kind="tuple", opcode_idx=idx, origin_idx=idx, value=None,
                children=[args_item, kwargs_item],
                is_suspicious=(_is_suspicious(args_item) or _is_suspicious(kwargs_item)),
            )
            _handle_call(cls_item, combined, idx, results, used_ranges, oplines, rules)
            _res = StackItem(
                kind="result", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name=cls_item.callable_name,
                
                
                
                
                callable_mod=cls_item.callable_mod,
                callable_name_part=cls_item.callable_name_part,
                callable_opname=cls_item.callable_opname,
                name_role_idx=list(cls_item.name_role_idx),
                is_suspicious=combined.is_suspicious,
                children=[cls_item, combined],
            )
            _apply_symbolic(_res, cls_item, combined)
            stack.append(_res)

        # ── OBJ ──────────────────────────────────────────────────────
        # MARK frame: [callable, arg1, arg2, ...]
        elif opname == "OBJ":
            mark_items = _pop_mark()
            if not mark_items:
                stack.append(StackItem(kind="result", opcode_idx=idx, origin_idx=idx, value=None))
                continue
            callable_item = mark_items[0]
            arg_items = mark_items[1:]
            args_item = StackItem(
                kind="tuple", opcode_idx=idx, origin_idx=idx, value=None,
                children=arg_items,
                is_suspicious=any(_is_suspicious(c) for c in arg_items),
            )
            _handle_call(callable_item, args_item, idx, results, used_ranges, oplines, rules)
            _res = StackItem(
                kind="result", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name=callable_item.callable_name,
                
                
                
                
                callable_mod=callable_item.callable_mod,
                callable_name_part=callable_item.callable_name_part,
                callable_opname=callable_item.callable_opname,
                name_role_idx=list(callable_item.name_role_idx),
                is_suspicious=args_item.is_suspicious,
                children=[callable_item, args_item],
            )
            _apply_symbolic(_res, callable_item, args_item)
            stack.append(_res)

        # ── INST ─────────────────────────────────────────────────────
        
        elif opname == "INST":
            mark_items = _pop_mark()
            
            _imod = _iname = ""
            try:
                raw_arg = ast.literal_eval(op.argrepr)
                parts = raw_arg.strip().split(None, 1)
                if len(parts) == 2:
                    _imod, _iname = parts[0], parts[1]
                    cname = f"{_imod}.{_iname}"
                else:
                    cname = raw_arg
            except Exception:
                cname = op.argrepr
            callable_item = StackItem(kind="callable", opcode_idx=idx, origin_idx=idx,
                                      value=None, callable_name=cname,
                                      callable_mod=_imod, callable_name_part=_iname,
                                      callable_opname="INST")
            args_item = StackItem(
                kind="tuple", opcode_idx=idx, origin_idx=idx, value=None,
                children=list(mark_items),
                is_suspicious=any(_is_suspicious(c) for c in mark_items),
            )
            _handle_call(callable_item, args_item, idx, results, used_ranges, oplines, rules)
            _res = StackItem(
                kind="result", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name=cname, is_suspicious=args_item.is_suspicious,
                callable_mod=_imod, callable_name_part=_iname, callable_opname="INST",
                children=[callable_item, args_item],
            )
            _apply_symbolic(_res, callable_item, args_item)
            stack.append(_res)

        # ── MEMO: PUT / BINPUT / LONG_BINPUT / MEMOIZE ───────────────
        elif opname == "MEMOIZE":
            if stack:
                memo[len(memo)] = stack[-1]

        elif opname in ("PUT", "BINPUT", "LONG_BINPUT"):
            if stack:
                try:
                    key = int(ast.literal_eval(op.argrepr))
                    memo[key] = stack[-1]
                except Exception:
                    pass

        # ── MEMO: GET / BINGET / LONG_BINGET ─────────────────────────
        elif opname in ("GET", "BINGET", "LONG_BINGET"):
            try:
                key = int(ast.literal_eval(op.argrepr))
                original = memo.get(key)
            except Exception:
                original = None
            if original is not None:
                retrieved = _copy.copy(original)
                retrieved.opcode_idx = idx      
                retrieved.children = list(original.children)  # shallow-copy list
                
                
                retrieved.from_memo = True
                retrieved.memo_origin_idx = (
                    original.memo_origin_idx if original.from_memo else original.origin_idx
                )
                stack.append(retrieved)
            else:
                stack.append(StackItem(kind="opaque", opcode_idx=idx, origin_idx=idx, value=None))

        # ── STACK OPS ────────────────────────────────────────────────
        elif opname == "POP":
            if stack:
                stack.pop()
            elif metastack:
                metastack.pop()

        elif opname == "POP_MARK":
            if metastack:
                stack.clear()
                stack.extend(metastack.pop())

        elif opname == "DUP":
            if stack:
                dup = _copy.copy(stack[-1])
                dup.opcode_idx = idx
                dup.children = list(stack[-1].children)
                stack.append(dup)

        
        elif opname == "APPEND":
            if len(stack) >= 2:
                val = stack.pop()
                stack[-1].children.append(val)
                if _is_suspicious(val):
                    stack[-1].is_suspicious = True

        elif opname == "APPENDS":
            mark_items = _pop_mark()
            if mark_items and stack:
                stack[-1].children.extend(mark_items)
                if any(_is_suspicious(c) for c in mark_items):
                    stack[-1].is_suspicious = True

        elif opname == "SETITEM":
            if len(stack) >= 3:
                val = stack.pop()
                key = stack.pop()
                stack[-1].children.extend([key, val])
                if _is_suspicious(val) or _is_suspicious(key):
                    stack[-1].is_suspicious = True

        elif opname == "SETITEMS":
            mark_items = _pop_mark()
            if mark_items and stack:
                stack[-1].children.extend(mark_items)
                if any(_is_suspicious(c) for c in mark_items):
                    stack[-1].is_suspicious = True

        elif opname == "ADDITEMS":
            mark_items = _pop_mark()
            if mark_items and stack:
                stack[-1].children.extend(mark_items)
                if any(_is_suspicious(c) for c in mark_items):
                    stack[-1].is_suspicious = True

        # ── BUILD ────────────────────────────────────────────────────
        # stack: ..., obj, state → obj      (obj.__setstate__(state))
        #
        
        
        
        
        
        elif opname == "BUILD":
            popped = _safe_pop(2)
            if popped is None:
                
                if stack:
                    stack.pop()
                continue
            obj_item, state_item = popped[0], popped[1]
            _handle_call(obj_item, state_item, idx, results, used_ranges, oplines, rules)
            obj_item.children.append(state_item)
            if _is_suspicious(state_item):
                obj_item.is_suspicious = True
            stack.append(obj_item)

        
        elif opname in ("EXT1", "EXT2", "EXT4"):
            
            
            
            
            #
            
            
            
            try:
                code = int(str(oplines[idx].argrepr).strip())
            except Exception:
                code = -1
            ext_item = StackItem(
                kind="ext", opcode_idx=idx, origin_idx=idx, value=None,
                callable_name="<ext:%d>" % code,
                callable_mod="", callable_name_part="ext:%d" % code,
                callable_opname="EXT",
            )
            _emit_unresolvable(ext_item, idx, code, results, used_ranges, oplines, opname)
            stack.append(ext_item)

        elif opname in ("PERSID", "BINPERSID"):
            if opname == "BINPERSID" and stack:
                stack.pop()
            stack.append(StackItem(kind="persid", opcode_idx=idx, origin_idx=idx, value=None))

        elif opname == "NEXT_BUFFER":
            stack.append(StackItem(kind="opaque", opcode_idx=idx, origin_idx=idx, value=None))

        elif opname == "READONLY_BUFFER":
            pass

        else:
            
            stack.append(StackItem(kind="opaque", opcode_idx=idx, origin_idx=idx, value=None))

    return results


def iter_genops_safe(data: bytes):
    """Internal implementation detail."""
    it = pickletools.genops(data)
    while True:
        try:
            yield next(it)
        except StopIteration:
            return
        except Exception:
            
            return


def gen_oplines(data: bytes) -> List[OpLine]:
    out: List[OpLine] = []
    i = 0
    for opcode, arg, pos in iter_genops_safe(data):
        opname = opcode.name
        
        #
        
        
        
        
        if opname in UNICODE_OPS:
            s = arg if isinstance(arg, str) else repr(arg)
            argrepr = repr(s[:ARGREPR_MAX] + (f"...(len={len(s)})" if len(s) > ARGREPR_MAX else ""))
        elif arg is None:
            argrepr = ""
        else:
            r = repr(arg)
            if len(r) > ARGREPR_MAX:
                
                n = len(arg) if isinstance(arg, (bytes, bytearray, str)) else None
                suffix = f"...(len={n})" if n is not None else "...(truncated)"
                r = r[:ARGREPR_MAX] + suffix
            argrepr = r
        out.append(OpLine(idx=i, pos=pos, opname=opname, argrepr=argrepr))
        i += 1
    return out


def find_suspicious_slices(
    oplines: List[OpLine],
    raw_data: bytes,
    rules: TupleSlicingRuleSet = RULES,
    return_meta: bool = False,
) -> List[tuple]:
    """Internal implementation detail."""
    unicode_by_idx: Dict[int, str] = {}
    bytes_by_idx: Dict[int, bytes] = {}
    i = 0
    for opcode, arg, pos in iter_genops_safe(raw_data):
        if opcode.name in UNICODE_OPS and isinstance(arg, str):
            unicode_by_idx[i] = arg
        
        #
        
        
        
        
        
        
        #
        
        
        
        
        
        #
        
        
        elif opcode.name in ("BINSTRING", "SHORT_BINSTRING", "STRING"):
            if isinstance(arg, str):
                unicode_by_idx[i] = arg
            elif isinstance(arg, (bytes, bytearray)):
                try:
                    unicode_by_idx[i] = bytes(arg).decode("utf-8")
                except UnicodeDecodeError:
                    bytes_by_idx[i] = bytes(arg)
        elif opcode.name in BYTES_OPS and isinstance(arg, bytes):
            bytes_by_idx[i] = arg
        i += 1

    raw = simulate_pickle_stack(oplines, unicode_by_idx, rules, bytes_by_idx=bytes_by_idx)
    raw = _drop_shadowed_placeholders(raw)
    if return_meta:
        return raw
    return [(s, e, h) for s, e, h, *_ in raw]
def make_rules(ent_threshold: float, enable_denylist: Optional[bool] = None) -> TupleSlicingRuleSet:
    """Internal implementation detail."""
    kw = {
        "ent_threshold": ent_threshold,
        "meets_condition_ent_threshold": ent_threshold,
    }
    if enable_denylist is not None:
        kw["enable_denylist"] = bool(enable_denylist)
    return dataclasses.replace(RULES, **kw)


def scan_one_blob(logical_name: str, data: bytes, ent_threshold: float,
                  enable_denylist: Optional[bool] = None) -> str:
    oplines = gen_oplines(data)
    rules = make_rules(ent_threshold, enable_denylist)
    slices = find_suspicious_slices(oplines, data, rules=rules)

    out_lines: List[str] = []
    out_lines.append(f"== SCAN TARGET: {logical_name} ==")
    out_lines.append(f"total_ops={len(oplines)}")
    out_lines.append("")

    if not slices:
        out_lines.append("No suspicious tuple/callable-context slices found.")
        return "\n".join(out_lines)

    for si, item in enumerate(slices, start=1):
        # item may be (s, e, header) or (s, e, header, meta, ...) depending on caller; unpack safely
        s, e, header = item[0], item[1], item[2]
        meta = item[3] if len(item) > 3 else None
        out_lines.append(f"---- HIT #{si} ----")
        out_lines.append(header)
        out_lines.append(f"slice_ops: idx {s}..{e}")
        out_lines.append("")
        for op in oplines[s:e + 1]:
            out_lines.append(op.render())
        out_lines.append("")

    return "\n".join(out_lines)




def build_json_report_for_blob(
    *,
    input_filename: str,
    carved_names: List[str],
    logical_name: str,
    data: bytes,
    ent_threshold: float,
    enable_denylist: Optional[bool] = None,
) -> dict:
    """
    Build a structured JSON report for a single extracted pickle blob.

    NOTE: This function does NOT change scanning heuristics; it only re-packages
    existing scan results (slices/oplines) into JSON.
    """
    oplines = gen_oplines(data)
    rules = make_rules(ent_threshold, enable_denylist)
    slices = find_suspicious_slices(oplines, data, rules=rules, return_meta=True)

    # exact unicode values by opcode index (UNICODE_OPS + BINSTRING utf-8 decode)
    unicode_by_idx = {}
    i = 0
    for opcode, arg, pos in iter_genops_safe(data):
        if opcode.name in UNICODE_OPS and isinstance(arg, str):
            unicode_by_idx[i] = arg
        elif opcode.name in ("BINSTRING", "SHORT_BINSTRING", "STRING"):
            
            
            if isinstance(arg, str):
                unicode_by_idx[i] = arg
            elif isinstance(arg, (bytes, bytearray)):
                try:
                    unicode_by_idx[i] = bytes(arg).decode("utf-8")
                except UnicodeDecodeError:
                    pass
        i += 1

    hits = []
    
    for item in slices:
        # item may be (s, e, header) or include extra metadata; unpack safely
        s, e, header = item[0], item[1], item[2]
        meta = item[3] if len(item) > 3 else None
        # Parse header (keeps behavior aligned with existing text output)
        reasons: List[str] = []
        unicode_val = ""
        unicode_len = None
        entropy_val = None

        # Prefer structured metadata (if provided) over parsing the header text
        if isinstance(meta, dict):
            if isinstance(meta.get("reasons"), list):
                reasons = meta.get("reasons")
            if isinstance(meta.get("unicode"), str):
                unicode_val = meta.get("unicode")
            if isinstance(meta.get("unicode_len"), int):
                unicode_len = meta.get("unicode_len")
            elif isinstance(meta.get("length"), int):
                unicode_len = meta.get("length")
            if isinstance(meta.get("entropy"), (int, float)):
                entropy_val = float(meta.get("entropy"))

        if not isinstance(meta, dict):
            lines = header.splitlines()
            if lines:
                m = re.search(r"reasons=([^|]+)", lines[0])
                if m:
                    reasons = [x for x in m.group(1).split(",") if x]
                m = re.search(r"unicode_len=(\d+)", lines[0])
                if m:
                    unicode_len = int(m.group(1))
                m = re.search(r"entropy=([0-9]+\.[0-9]+)", lines[0])
                if m:
                    try:
                        entropy_val = float(m.group(1))
                    except Exception:
                        entropy_val = None
            if len(lines) >= 2:
                m = re.search(r"unicode_preview=(.+)$", lines[1].strip())
                if m:
                    try:
                        unicode_val = ast.literal_eval(m.group(1))
                    except Exception:
                        unicode_val = m.group(1)
    
        if unicode_len is None:
            unicode_len = len(unicode_val) if isinstance(unicode_val, str) else 0
        if entropy_val is None and isinstance(unicode_val, str):
            try:
                entropy_val = float(f"{shannon_entropy_utf8(unicode_val):.2f}")
            except Exception:
                entropy_val = None

        # Build opcode sequence
        
        
        
        
        
        op_seq_span = e - s + 1
        op_seq_truncated = op_seq_span > OP_SEQUENCE_MAX
        seq_end = (s + OP_SEQUENCE_MAX - 1) if op_seq_truncated else e

        op_sequence = []
        for op in oplines[s:seq_end + 1]:
            entry = {
                "index": op.idx,
                "offset": op.pos,
                "opcode": op.opname,
            }
            if op.argrepr:
                # Keep the rendered representation to avoid lossy parsing.
                entry["argrepr"] = op.argrepr

            # For unicode ops, prefer exact unicode value if available.
            if op.opname in UNICODE_OPS and op.idx in unicode_by_idx:
                entry["arg"] = unicode_by_idx[op.idx]
            else:
                # Attempt to parse small scalar args (int/float/bool) safely.
                if op.argrepr and len(op.argrepr) <= 64:
                    try:
                        val = ast.literal_eval(op.argrepr)
                        if isinstance(val, (int, float, bool, type(None))):
                            entry["arg"] = val
                    except Exception:
                        pass

            op_sequence.append(entry)

        # Try to build a light semantic summary (best-effort)
        callable_fq = ""
        args_list: List[str] = []
        callable_op_idx = None

        # Scan within slice to find module/name prior to STACK_GLOBAL/GLOBAL
        recent_unicodes: List[Tuple[int, str]] = []
        for op in oplines[s:e + 1]:
            if op.opname in UNICODE_OPS and op.idx in unicode_by_idx:
                recent_unicodes.append((op.idx, unicode_by_idx[op.idx]))
            if op.opname == "STACK_GLOBAL":
                callable_op_idx = op.idx
                if len(recent_unicodes) >= 2:
                    mod = recent_unicodes[-2][1]
                    name = recent_unicodes[-1][1]
                    callable_fq = f"{mod}.{name}"
                elif len(recent_unicodes) == 1:
                    callable_fq = recent_unicodes[-1][1]
            elif op.opname == "GLOBAL":
                callable_op_idx = op.idx
                # GLOBAL often encodes "module name" in its argument (e.g., "builtins eval")
                if len(recent_unicodes) >= 2:
                    mod = recent_unicodes[-2][1]
                    name = recent_unicodes[-1][1]
                    callable_fq = f"{mod}.{name}"
                elif len(recent_unicodes) == 1:
                    callable_fq = recent_unicodes[-1][1]
                else:
                    try:
                        # argrepr looks like "'builtins eval'" (a quoted string)
                        s_arg = ast.literal_eval(op.argrepr)
                        if isinstance(s_arg, str):
                            parts = s_arg.strip().split()
                            if len(parts) >= 2:
                                callable_fq = f"{parts[0]}.{parts[1]}"
                            elif len(parts) == 1:
                                callable_fq = parts[0]
                    except Exception:
                        pass

        # Extract tuple args for common tuple arities
        # We take unicode values that appeared after callable_op_idx (if any).
        post_callable_unicodes = []
        for op in oplines[s:e + 1]:
            if op.opname in UNICODE_OPS and op.idx in unicode_by_idx:
                if callable_op_idx is None or op.idx > callable_op_idx:
                    post_callable_unicodes.append(unicode_by_idx[op.idx])

        # Determine tuple arity if possible
        arity = None
        for op in oplines[s:e + 1]:
            if op.opname == "TUPLE1":
                arity = 1
            elif op.opname == "TUPLE2":
                arity = 2
            elif op.opname == "TUPLE3":
                arity = 3
            elif op.opname == "EMPTY_TUPLE":
                arity = 0

        # Handle generic TUPLE (MARK ... items ... TUPLE) which has variable arity.
        if arity is None:
            tuple_idx = None
            for op in oplines[s:e + 1]:
                if op.opname == "TUPLE":
                    tuple_idx = op.idx
                    break
            if tuple_idx is not None:
                mark_idx = None
                for op in oplines[s:e + 1]:
                    if op.opname == "MARK" and (callable_op_idx is None or op.idx > callable_op_idx) and op.idx < tuple_idx:
                        mark_idx = op.idx
                if mark_idx is not None:
                    tmp_args: List[str] = []
                    for op in oplines[s:e + 1]:
                        if op.opname in UNICODE_OPS and op.idx in unicode_by_idx and mark_idx < op.idx < tuple_idx:
                            tmp_args.append(unicode_by_idx[op.idx])
                    if tmp_args:
                        args_list = tmp_args

        if arity is not None:
            args_list = post_callable_unicodes[-arity:] if arity > 0 else []

        
        
        if isinstance(meta, dict) and isinstance(meta.get("callable_name"), str) and meta["callable_name"]:
            callable_fq = meta["callable_name"]

        
        
        if isinstance(meta, dict) and isinstance(meta.get("unicode_val"), str) and meta["unicode_val"]:
            primary_uval = meta["unicode_val"]
            if args_list != [primary_uval]:
                
                rest = [a for a in args_list if a != primary_uval]
                args_list = [primary_uval] + rest

        risk = "suspicious_pickle"
        suspicious_index = None
        if isinstance(meta, dict):
            if isinstance(meta.get("suspicious_index"), int):
                suspicious_index = meta.get("suspicious_index")
            elif isinstance(meta.get("unicode_idx"), int):
                suspicious_index = meta.get("unicode_idx")
        if suspicious_index is None and unicode_val:
            for op in oplines[s:e + 1]:
                if op.opname in UNICODE_OPS and op.idx in unicode_by_idx and unicode_by_idx[op.idx] == unicode_val:
                    suspicious_index = op.idx
                    break


        forced_by_callable = bool(isinstance(meta, dict) and meta.get("forced_by_callable"))
        hits.append({
            "suspicious": {
                "op_sequence": op_sequence,
                "op_sequence_span": op_seq_span,
                "op_sequence_truncated": op_seq_truncated,
                "semantic_result": {
                    "callable": callable_fq,
                    "arguments": args_list,
                    "reason": reasons,
                    "length": unicode_len,
                    "suspicious_index": suspicious_index,
                    "entropy": entropy_val,
                    "suspicious_op_start": s,
                    "suspicious_op_end": e,
                    "risk": risk,
                    "forced_by_callable": forced_by_callable,
                    
                    "slice_start": meta.get("slice_start") if isinstance(meta, dict) else None,
                    "slice_end": meta.get("slice_end") if isinstance(meta, dict) else None,
                    
                    "invoke_opcode": meta.get("invoke_opname", "") if isinstance(meta, dict) else "",
                    
                    "memo_origins": meta.get("memo_origins", []) if isinstance(meta, dict) else [],
                    
                    
                    
                    "callable_ref": (meta.get("callable_ref")
                                     if isinstance(meta, dict) else None),
                    
                    "arguments_meta": (meta.get("arguments_meta", [])
                                       if isinstance(meta, dict) else []),
                    
                    "name_role_idx": (meta.get("name_role_idx", [])
                                      if isinstance(meta, dict) else []),
                }
            }
        })

    
    
    
    _proto = data[1] if (len(data) > 1 and data[0] == 0x80) else 0

    return {
        "model_info": {
            # user requirement: model_name / file_name are unified as input filename
            "model_name": input_filename,
            "file_name": input_filename,
            "carved": carved_names,
            "target_file": logical_name,
            "protocol": int(_proto),
        },
        # keep both for convenience; hits may be empty
        "hits": hits,
    }
