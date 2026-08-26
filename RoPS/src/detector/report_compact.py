#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal implementation detail."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_MAX_LITERAL = 256

NESTED_MAX = 1 << 20

SAMPLE_KEEP = 32

MEMO_GROUP_MIN = 64

MEMO_IDX_SAMPLE = 8

LOW_RANK_OP_MARGIN = 16

LOW_RANK_OP_CAP = 64


_NESTED_MAGIC: Tuple[bytes, ...] = (b"\x80", b"\x78\x9c", b"\x78\x01", b"\x78\xda")


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _looks_nested(value: str) -> bool:
    """Internal implementation detail."""
    if not isinstance(value, str) or len(value) > NESTED_MAX:
        return False
    try:
        raw = value.encode("latin1")
    except (UnicodeEncodeError, AttributeError):
        return False
    if raw[:1] in (b"\x80",) and len(raw) > 1 and 0 <= raw[1] <= 5:
        return True
    if any(raw.startswith(m) for m in _NESTED_MAGIC[1:]):
        return True
    
    return raw[:1] in (b"c", b"(") and raw.rstrip()[-1:] == b"."


def _shrink(value: Any, limit: int) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """Internal implementation detail."""
    if not isinstance(value, str) or len(value) <= limit:
        return value, None
    return value[:limit], {"len": len(value), "sha256": _sha256(value)}


def _arg_types(sr: Dict[str, Any]) -> Dict[int, str]:
    """Internal implementation detail."""
    out: Dict[int, str] = {}
    s3 = sr.get("stage3")
    if not isinstance(s3, dict):
        return out
    for a in s3.get("args") or []:
        if isinstance(a, dict) and isinstance(a.get("index"), int):
            out[a["index"]] = a.get("type", "")
    return out


def _keep_mask(meta: List[Any], types: Dict[int, str],
               sample_keep: int = SAMPLE_KEEP) -> Tuple[List[int], Dict[str, Any]]:
    """Internal implementation detail."""
    keep: List[int] = []
    sampled = 0
    dropped_kind: Dict[str, int] = {}
    dropped_type: Dict[str, int] = {}
    for i, e in enumerate(meta):
        if not isinstance(e, dict):
            keep.append(i)
            continue
        t = types.get(i, "")
        essential = (
            bool(e.get("suspicious"))
            or bool(e.get("nested_raw_hex"))
            or (t not in ("", "T1"))
        )
        if essential:
            keep.append(i)
            continue
        if sampled < sample_keep:
            keep.append(i)
            sampled += 1
            continue
        k = str(e.get("kind", "?"))
        dropped_kind[k] = dropped_kind.get(k, 0) + 1
        if t:
            dropped_type[t] = dropped_type.get(t, 0) + 1
    summary: Dict[str, Any] = {}
    if len(keep) != len(meta):
        summary = {
            "total": len(meta),
            "kept": len(keep),
            "omitted": len(meta) - len(keep),
            "omitted_by_kind": dropped_kind,
            "omitted_by_type": dropped_type,
            "criterion": "suspicious | nested | type!=T1 | first %d" % sample_keep,
        }
    return keep, summary


def _type_histogram(sr: Dict[str, Any]) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    s3 = sr.get("stage3")
    if not isinstance(s3, dict):
        return hist
    for a in s3.get("args") or []:
        if isinstance(a, dict):
            t = a.get("type", "?")
            hist[t] = hist.get(t, 0) + 1
    return hist


def _group_memo_origins(mo: List[Any]) -> Tuple[List[Any], Optional[Dict[str, Any]]]:
    """Internal implementation detail."""
    if len(mo) < MEMO_GROUP_MIN:
        return mo, None
    order: List[Tuple[Any, Any, Any]] = []
    groups: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for e in mo:
        if not isinstance(e, dict):
            continue
        key = (e.get("defined_at"), e.get("kind"), e.get("callable_name"))
        g = groups.get(key)
        if g is None:
            g = {"defined_at": key[0], "kind": key[1], "refs": 0, "get_idx_sample": []}
            if key[2] is not None:
                g["callable_name"] = key[2]
            groups[key] = g
            order.append(key)
        g["refs"] += 1
        if len(g["get_idx_sample"]) < MEMO_IDX_SAMPLE:
            g["get_idx_sample"].append(e.get("get_idx"))
    grouped = [groups[k] for k in order]
    if len(grouped) >= len(mo):
        return mo, None
    return grouped, {
        "total": len(mo),
        "groups": len(grouped),
        "criterion": "grouped by (defined_at, kind, callable_name); "
                     "refs preserved, get_idx sampled to %d" % MEMO_IDX_SAMPLE,
    }


def compact_report(report: Dict[str, Any], *,
                   max_literal: int = DEFAULT_MAX_LITERAL,
                   keep_nested: bool = True) -> Dict[str, Any]:
    """Internal implementation detail."""
    if max_literal <= 0:
        return report

    stats = {"op_entries_truncated": 0, "arguments_truncated": 0,
             "meta_values_truncated": 0, "meta_entries_omitted": 0,
             "stage3_args_omitted": 0, "memo_origins_grouped": 0,
             "chars_dropped": 0, "nested_kept": 0}

    for hit in report.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        sus = hit.get("suspicious")
        if not isinstance(sus, dict):
            continue

        
        #
        
        
        
        
        _sr0 = sus.get("semantic_result")
        _rank = ((_sr0 or {}).get("stage3") or {}).get("rank") if isinstance(_sr0, dict) else None
        ops = sus.get("op_sequence")
        if _rank == "low" and isinstance(ops, list) and ops:
            lo = (_sr0 or {}).get("slice_start")
            hi = (_sr0 or {}).get("slice_end")
            if isinstance(lo, int) and isinstance(hi, int):
                a, b = lo - LOW_RANK_OP_MARGIN, hi + LOW_RANK_OP_MARGIN
                kept_ops = [e for e in ops
                            if not isinstance(e, dict)
                            or not isinstance(e.get("index"), int)
                            or a <= e["index"] <= b]
                if len(kept_ops) > 2 * LOW_RANK_OP_CAP:
                    kept_ops = (kept_ops[:LOW_RANK_OP_CAP] + kept_ops[-LOW_RANK_OP_CAP:])
                if len(kept_ops) < len(ops):
                    sus["op_sequence_windowed"] = {
                        "total": len(ops), "kept": len(kept_ops),
                        "window": [a, b],
                        "criterion": "rank=low → slice +- %d, head/tail %d each"
                                     % (LOW_RANK_OP_MARGIN, LOW_RANK_OP_CAP),
                    }
                    sus["op_sequence"] = kept_ops

        for entry in sus.get("op_sequence") or []:
            if not isinstance(entry, dict):
                continue
            for key, len_key, flag_key in (
                    ("argrepr", "argrepr_len", "argrepr_truncated"),
                    ("arg", "arg_len", "arg_truncated")):
                original = entry.get(key)
                shrunk, meta = _shrink(original, max_literal)
                if meta is None:
                    continue
                stats["chars_dropped"] += len(original) - len(shrunk)
                stats["op_entries_truncated"] += 1
                entry[key] = shrunk
                entry[len_key] = meta["len"]
                entry[flag_key] = True
                if key == "arg":
                    entry["arg_sha256"] = meta["sha256"]

        
        sr = sus.get("semantic_result")
        if not isinstance(sr, dict):
            continue

        
        args = sr.get("arguments")
        if isinstance(args, list):
            truncated: Dict[str, Any] = {}
            for i, a in enumerate(args):
                if keep_nested and _looks_nested(a):
                    stats["nested_kept"] += 1
                    continue
                shrunk, meta = _shrink(a, max_literal)
                if meta is None:
                    continue
                stats["chars_dropped"] += len(a) - len(shrunk)
                stats["arguments_truncated"] += 1
                args[i] = shrunk
                truncated[str(i)] = meta
            if truncated:
                sr["arguments_truncated"] = truncated

        
        mo = sr.get("memo_origins")
        if isinstance(mo, list) and mo:
            grouped, mo_summary = _group_memo_origins(mo)
            if mo_summary:
                sr["memo_origins"] = grouped
                sr["memo_origins_compacted"] = mo_summary
                stats["memo_origins_grouped"] += mo_summary["total"] - mo_summary["groups"]

        
        meta_list = sr.get("arguments_meta")
        if not isinstance(meta_list, list) or not meta_list:
            continue

        types = _arg_types(sr)
        hist = _type_histogram(sr)
        if hist:
            s3 = sr.get("stage3")
            if isinstance(s3, dict):
                s3["type_summary"] = hist

        
        
        
        
        rank = ((sr.get("stage3") or {}).get("rank"))
        sk = 0 if rank == "low" else SAMPLE_KEEP
        keep, omit_summary = _keep_mask(meta_list, types, sk)
        keep_set = set(keep)

        for i in keep:
            e = meta_list[i]
            if not isinstance(e, dict):
                continue
            v = e.get("value")
            if keep_nested and isinstance(v, str) and _looks_nested(v):
                stats["nested_kept"] += 1
                continue
            shrunk, m = _shrink(v, max_literal)
            if m is None:
                continue
            stats["chars_dropped"] += len(v) - len(shrunk)
            stats["meta_values_truncated"] += 1
            e["value"] = shrunk
            e["value_len"] = m["len"]
            e["value_sha256"] = m["sha256"]
            e["value_truncated"] = True

        if omit_summary:
            for i in range(len(meta_list)):
                if i in keep_set:
                    continue
                e = meta_list[i]
                if isinstance(e, dict) and isinstance(e.get("value"), str):
                    stats["chars_dropped"] += len(e["value"])
            sr["arguments_meta"] = [meta_list[i] for i in keep]
            sr["arguments_meta_omitted"] = omit_summary
            stats["meta_entries_omitted"] += omit_summary["omitted"]

            
            s3 = sr.get("stage3")
            if isinstance(s3, dict) and isinstance(s3.get("args"), list):
                before = len(s3["args"])
                s3["args"] = [a for a in s3["args"]
                              if not isinstance(a, dict)
                              or a.get("index") in keep_set]
                omitted = before - len(s3["args"])
                if omitted:
                    s3["args_omitted"] = omitted
                    stats["stage3_args_omitted"] += omitted

    mi = report.setdefault("model_info", {})
    if isinstance(mi, dict):
        mi["report_compaction"] = {"max_literal": max_literal,
                                   "sample_keep": SAMPLE_KEEP, **stats}
    return report


__all__ = ["compact_report", "DEFAULT_MAX_LITERAL", "NESTED_MAX", "SAMPLE_KEEP",
           "MEMO_GROUP_MIN", "MEMO_IDX_SAMPLE"]
