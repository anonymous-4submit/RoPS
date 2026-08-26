#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal implementation detail."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


# ────────────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────────────

@dataclass
class PatternEntry:
    """Internal implementation detail."""
    name: str
    compiled: re.Pattern
    score: int = 0
    is_strong: bool = False
    is_shortcut: bool = False
    allowlist_ref: Optional[str] = None  


@dataclass
class TupleSlicingRuleSet:
    """Internal implementation detail."""
    
    ent_threshold: float = 4.5
    slice_lookback: int = 20          
    context_padding: Optional[int] = None  
    enable_denylist: bool = False     

    
    shell_min_len: int = 12
    shell_score_threshold: int = 3
    meets_condition_ent_threshold: float = 5.0

    
    
    
    python_min_len: int = 6
    python_score_threshold: int = 2

    
    
    
    binary_non_ascii_threshold: float = 0.30
    binary_min_len: int = 64
    non_ascii_meta_cutoff: float = 0.20
    
    literal_scan_max_len: int = 16384

    
    
    structural_signal_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)

    
    shortcut_patterns: List[PatternEntry] = field(default_factory=list)
    scored_patterns:   List[PatternEntry] = field(default_factory=list)
    
    allowlist_patterns: Dict[str, re.Pattern] = field(default_factory=dict)

    
    
    
    python_shortcut_patterns: List[PatternEntry] = field(default_factory=list)
    python_scored_patterns:   List[PatternEntry] = field(default_factory=list)

    
    dangerous_callables: List[str] = field(default_factory=list)
    dangerous_callables_set: frozenset = field(default_factory=frozenset)
    
    denylist_from_rules: int = 0
    denylist_from_registry: int = 0

    
    
    
    bytes_min_size: int = 16
    bytes_entropy_threshold: float = 6.0

    
    bytes_dangerous_callables: List[str] = field(default_factory=list)
    bytes_dangerous_callables_set: frozenset = field(default_factory=frozenset)

    @classmethod
    def from_yaml(cls, path: Path) -> "TupleSlicingRuleSet":
        """Internal implementation detail."""
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)

        inst = cls()

        
        scan = raw.get("scan", {})
        inst.ent_threshold  = float(scan.get("ent_threshold",  inst.ent_threshold))
        inst.slice_lookback = int(scan.get("slice_lookback",   inst.slice_lookback))
        if "context_padding" in scan:
            inst.context_padding = int(scan["context_padding"])
        inst.enable_denylist = bool(scan.get("enable_denylist", inst.enable_denylist))

        
        sd = raw.get("shell_detection", {})
        inst.shell_min_len                 = int(sd.get("min_len",                         inst.shell_min_len))
        inst.shell_score_threshold         = int(sd.get("score_threshold",                 inst.shell_score_threshold))
        inst.meets_condition_ent_threshold = float(sd.get("meets_condition_ent_threshold", inst.meets_condition_ent_threshold))

        
        pd_ = raw.get("python_detection", {})
        inst.python_min_len         = int(pd_.get("min_len",         inst.python_min_len))
        inst.python_score_threshold = int(pd_.get("score_threshold", inst.python_score_threshold))

        
        cs = raw.get("content_signals", {})
        inst.binary_non_ascii_threshold = float(
            cs.get("binary_non_ascii_threshold", inst.binary_non_ascii_threshold))
        inst.binary_min_len = int(cs.get("binary_min_len", inst.binary_min_len))
        inst.non_ascii_meta_cutoff = float(
            cs.get("non_ascii_meta_cutoff", inst.non_ascii_meta_cutoff))
        inst.literal_scan_max_len = int(
            cs.get("literal_scan_max_len", inst.literal_scan_max_len))

        
        for entry in raw.get("structural_signals", []) or []:
            inst.structural_signal_patterns.append(
                (str(entry["name"]), re.compile(entry["pattern"].strip()))
            )

        patterns = raw.get("patterns", {})

        # ── 3-pre-a) dangerous_callables (unicode) ────────────────
        
        
        
        dc_list = raw.get("dangerous_callables", [])
        base = [str(c) for c in dc_list]
        extra = _load_registry_triggers()
        merged = list(dict.fromkeys(base + extra))          
        inst.dangerous_callables = merged
        inst.dangerous_callables_set = frozenset(merged)
        inst.denylist_from_rules = len(base)
        inst.denylist_from_registry = len(set(extra) - set(base))

        
        bd = raw.get("bytes_detection", {})
        inst.bytes_min_size         = int(bd.get("min_size",         inst.bytes_min_size))
        inst.bytes_entropy_threshold = float(bd.get("entropy_threshold", inst.bytes_entropy_threshold))

        # ── 3-pre-c) bytes_dangerous_callables ────────────────────
        bdc_list = raw.get("bytes_dangerous_callables", [])
        inst.bytes_dangerous_callables = [str(c) for c in bdc_list]
        inst.bytes_dangerous_callables_set = frozenset(inst.bytes_dangerous_callables)

        
        for entry in patterns.get("allowlist", []):
            name    = entry["name"]
            pattern = entry["pattern"].strip()   
            inst.allowlist_patterns[name] = re.compile(pattern)

        
        for entry in patterns.get("shortcut", []):
            name    = entry["name"]
            pattern = entry["pattern"].strip()
            inst.shortcut_patterns.append(PatternEntry(
                name=name,
                compiled=re.compile(pattern),
                score=0,
                is_strong=False,
                is_shortcut=True,
                allowlist_ref=None,
            ))

        
        for entry in patterns.get("scored", []):
            name          = entry["name"]
            pattern       = entry["pattern"].strip()
            score         = int(entry.get("score",     0))
            is_strong     = bool(entry.get("is_strong", False))
            allowlist_ref = entry.get("allowlist_ref")   # Optional[str]

            
            if allowlist_ref and allowlist_ref not in inst.allowlist_patterns:
                raise ValueError(
                    f"Pattern '{name}' has allowlist_ref='{allowlist_ref}', which is "
                    f"missing from the allowlist section."
                )

            inst.scored_patterns.append(PatternEntry(
                name=name,
                compiled=re.compile(pattern),
                score=score,
                is_strong=is_strong,
                is_shortcut=False,
                allowlist_ref=allowlist_ref,
            ))

        # ── 6) python_shortcut ───────────────────────────────────
        
        
        
        for entry in patterns.get("python_shortcut", []):
            inst.python_shortcut_patterns.append(PatternEntry(
                name=entry["name"],
                compiled=re.compile(entry["pattern"].strip()),
                score=0, is_strong=False, is_shortcut=True, allowlist_ref=None,
            ))

        # ── 7) python_scored ─────────────────────────────────────
        
        for entry in patterns.get("python_scored", []):
            inst.python_scored_patterns.append(PatternEntry(
                name=entry["name"],
                compiled=re.compile(entry["pattern"].strip()),
                score=int(entry.get("score", 0)),
                is_strong=bool(entry.get("is_strong", False)),
                is_shortcut=False,
                allowlist_ref=None,
            ))

        return inst


# ────────────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────────────



_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "classifier" / "ioc_registry.yaml"


def _load_registry_triggers() -> List[str]:
    """Internal implementation detail."""
    with open(_REGISTRY_PATH, "r", encoding="utf-8") as fh:
        reg = yaml.safe_load(fh)
    ci = (reg or {}).get("callable_ioc") or {}
    if not ci.get("standalone"):
        raise RuntimeError("ioc_registry.yaml is empty or malformed: %s" % _REGISTRY_PATH)
    out: List[str] = []
    for sec in ("standalone", "combination_required"):
        for e in (ci.get(sec) or []):
            if e.get("benign", None) == 0 and isinstance(e.get("name"), str):
                out.append(e["name"])
    return out


def load_rules(path: Optional[Path] = None) -> TupleSlicingRuleSet:
    """Internal implementation detail."""
    if path is None:
        path = Path(__file__).parent / "rules.yaml"
    if not path.exists():
        raise FileNotFoundError(f"rules.yaml not found: {path}")
    return TupleSlicingRuleSet.from_yaml(path)
