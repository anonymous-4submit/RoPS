#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage 3 behavior classifier: IoC matching, YARA labeling, and the verdict.

Entry points used by ``pipeline.py``:

* ``analyze_one_hit(hit, protocol)`` -- canonicalizes the callable, recovers
  the type and role of every argument, matches the indicator vocabulary
  (``ioc_registry.yaml``), runs the YARA rule set (``rules.yar``), and writes
  the verdict into ``hit["suspicious"]["semantic_result"]["stage3"]``.
* ``finalize_report(doc)`` -- attaches the per-blob ``stage3_summary``.
* ``iter_hits`` / ``protocol_of`` -- small accessors for the Stage 2 report.

Verdicts: ``C`` (classified, a behavior label is attached) or ``U``
(unclassified); unclassified hits are ranked ``high`` (review) or ``low``
(demoted by one of the D-1..D-4 rules).
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yara

from .canon import canon, split_qualname
from .typerole import (
    recover_type, parse_nested, T1_TEXT, T2_NUMERIC, T3_STRUCTURED,
    assign_roles, impossible_combination, R1_VALUE, R2_NAME,
)

__all__ = ["analyze_one_hit", "iter_hits", "protocol_of", "finalize_report",
           "judge", "VERDICT_C", "VERDICT_U", "RANK_HIGH", "RANK_LOW",
           "DISQUALIFIED_ONLY", "BORDERLINE_ENTROPY_MAX"]

VERDICT_C = "C"
VERDICT_U = "U"

RANK_HIGH = "high"
RANK_LOW = "low"

# D-3: entropy below this on a path literal is treated as borderline
BORDERLINE_ENTROPY_MAX = 5.5

# D-4: tags that never qualify a hit on their own
DISQUALIFIED_ONLY = ("has_shell_substitution", "entropy_binary_data", "literal_truncated")

_PATH_TAGS = ("has_path", "has_windows_path")

# YARA rules with priority above this are ignored
MAX_PRIORITY = 3


# ══════════════════════════════════════════════════════════════════════════
# Static resources: YARA rules, IoC registry, Stage 2 denylist
# ══════════════════════════════════════════════════════════════════════════
_YARA_RULES_PATH = Path(__file__).parent / "rules.yar"
YARA_RULES: "yara.Rules" = yara.compile(filepath=str(_YARA_RULES_PATH))

_REGISTRY_PATH = Path(__file__).parent / "ioc_registry.yaml"
_DETECTOR_RULES = Path(__file__).parent.parent / "detector" / "rules.yaml"


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


_REG = _load_yaml(_REGISTRY_PATH)


def _index(section: str, bucket: str, key: str = "name") -> Dict[str, Dict[str, Any]]:
    out = {}
    for e in ((_REG.get(section) or {}).get(bucket) or []):
        if isinstance(e, dict) and e.get(key):
            out[e[key]] = e
    return out


CALLABLE_STANDALONE = _index("callable_ioc", "standalone")
CALLABLE_COMBINATION = _index("callable_ioc", "combination_required")
LITERAL_STANDALONE = _index("literal_ioc", "standalone", "tag")
LITERAL_COMBINATION = _index("literal_ioc", "combination_required", "tag")
LITERAL_DISQUALIFIED = _index("literal_ioc", "disqualified", "tag")


def _rule_tier_index(section: str, key: str = "tag") -> Dict[str, Any]:
    """Internal implementation detail."""
    out: Dict[str, Any] = {}
    for bucket in ("standalone", "combination_required"):
        for e in ((_REG.get(section) or {}).get(bucket) or []):
            if isinstance(e, dict) and e.get(key) and e.get("rule_tiers"):
                out[e[key]] = e["rule_tiers"]
    return out


LITERAL_RULE_TIERS = _rule_tier_index("literal_ioc")

NAME_DANGEROUS = frozenset((_REG.get("name_role_ioc") or {}).get("dangerous") or ())


def _load_gateways() -> frozenset:
    """Internal implementation detail."""
    d = _load_yaml(_DETECTOR_RULES)
    names = set()
    for key in ("dangerous_callables", "bytes_dangerous_callables"):
        for n in (d.get(key) or []):
            if not isinstance(n, str):
                continue
            names.add(n)
            mod, nm = split_qualname(n)
            if mod and nm:
                names.add(canon(mod, nm, 0).canonical)
    return frozenset(names)


GATEWAYS = _load_gateways()

# Gateway promotion: a Stage 2 denylist callable that is not in the registry is
# still labeled (category chosen by name pattern), when enabled in the registry.
_GW = (_REG.get("gateway_promotion") or {})
GATEWAY_PROMOTION = bool(_GW.get("enabled"))
_GW_EVIDENCE = _GW.get("evidence") or "known dangerous callable"
_GW_NAMING = [(re.compile(r["match"]), r.get("category"), r.get("subcategory"))
              for r in (_GW.get("naming") or []) if r.get("match")]
_GW_FALLBACK = _GW.get("fallback") or {"category": "Code Execution",
                                       "subcategory": "Known Dangerous Callable"}


def _gateway_label(name: str):
    """Internal implementation detail."""
    for rx, cat, sub in _GW_NAMING:
        if rx.search(name):
            return cat, sub
    return _GW_FALLBACK.get("category"), _GW_FALLBACK.get("subcategory")


# ══════════════════════════════════════════════════════════════════════════
# Hit accessors
# ══════════════════════════════════════════════════════════════════════════
def _semantic(hit: Dict[str, Any]) -> Dict[str, Any]:
    sus = hit.get("suspicious")
    if isinstance(sus, dict) and isinstance(sus.get("semantic_result"), dict):
        return sus["semantic_result"]
    return {}


def _reasons(sem: Dict[str, Any]) -> List[str]:
    r = sem.get("reason")
    return [x for x in r if isinstance(x, str)] if isinstance(r, list) else []


def _arguments(sem: Dict[str, Any]) -> List[str]:
    a = sem.get("arguments")
    return [x for x in a if isinstance(x, str)] if isinstance(a, list) else []


def ensure_semantic_result(hit: Dict[str, Any]) -> Dict[str, Any]:
    hit.setdefault("suspicious", {})
    if not isinstance(hit["suspicious"], dict):
        hit["suspicious"] = {}
    hit["suspicious"].setdefault("semantic_result", {})
    if not isinstance(hit["suspicious"]["semantic_result"], dict):
        hit["suspicious"]["semantic_result"] = {}
    return hit["suspicious"]["semantic_result"]


def add_act(sem: Dict[str, Any], big: str, sub: str, evidence: str) -> None:
    sem.setdefault("Malicious_act", [])
    if not isinstance(sem["Malicious_act"], list):
        sem["Malicious_act"] = []
    entry = {"category": big, "subcategory": sub, "evidence": evidence}
    if entry not in sem["Malicious_act"]:
        sem["Malicious_act"].append(entry)


def _base_tag(tag: str) -> str:
    """`entropy_binary_data (5.23, non_ascii=38%)` → `entropy_binary_data`."""
    return tag.split("(")[0].strip()


def _tag_rule_ids(tag: str) -> frozenset:
    """`has_python_code (PY_A_RE, PY_B_RE)` → {PY_A_RE, PY_B_RE}."""
    i = tag.find("(")
    j = tag.rfind(")")
    if i < 0 or j <= i:
        return frozenset()
    return frozenset(x.strip() for x in tag[i + 1:j].split(",") if x.strip())


# ══════════════════════════════════════════════════════════════════════════
# Field builder: canonical callable + per-argument type / role
# ══════════════════════════════════════════════════════════════════════════
def _values_by_position(args: List[str], ameta: List[Any]) -> List[Any]:
    """Internal implementation detail."""
    if not ameta:
        return list(args)
    placeholders = [a for a in args
                    if isinstance(a, str) and a.startswith("[BINBYTES:")]
    pi = 0
    out: List[Any] = []
    for m in ameta:
        if not isinstance(m, dict):
            out.append(None)
            continue
        if m.get("kind") == "bytes":
            if pi < len(placeholders):
                out.append(placeholders[pi])
                pi += 1
            else:
                out.append("[BINBYTES:%s len=%s]" % (m.get("head_hex", ""), m.get("len")))
        else:
            out.append(m.get("value"))
    return out


def build_scan_fields(hit: Dict[str, Any], protocol: int = 0) -> Dict[str, Any]:
    """Internal implementation detail."""
    sem = _semantic(hit)
    reasons = _reasons(sem)
    args = _arguments(sem)

    # Callable: prefer the structured reference, fall back to the display name
    ref = sem.get("callable_ref") if isinstance(sem.get("callable_ref"), dict) else None
    if ref and (ref.get("module") or ref.get("name")):
        mod, name = ref.get("module") or "", ref.get("name") or ""
    else:
        mod, name = split_qualname(sem.get("callable", "") or "")
    cr = canon(mod, name, protocol)

    # Arguments: recover the type of every literal, using sibling values as
    # declared-dtype evidence and the per-argument Stage 2 tags
    ameta = sem.get("arguments_meta")
    ameta = ameta if isinstance(ameta, list) else []
    values = _values_by_position(args, ameta)
    n = max(len(values), len(ameta))
    types: List[Any] = []
    for i in range(n):
        val = values[i] if i < len(values) else None
        m = ameta[i] if i < len(ameta) else {}
        if val is None and isinstance(m, dict):
            val = m.get("value")
        sibling_vals = [a for j, a in enumerate(values) if j != i]
        arg_reasons = list(reasons)
        if isinstance(m, dict) and isinstance(m.get("reasons"), list):
            arg_reasons += [x for x in m["reasons"] if isinstance(x, str)]
        tr = recover_type(val, tags=arg_reasons, siblings=sibling_vals)
        # Nested pickle payload carried as raw bytes by Stage 2
        if isinstance(m, dict) and m.get("nested_raw_hex"):
            try:
                raw = bytes.fromhex(m["nested_raw_hex"])
                nested = parse_nested(raw)
                if nested:
                    tr.nested = nested
                    tr.type = T3_STRUCTURED
                    tr.evidence = "nested payload (proto=%d)" % nested["protocol"]
            except Exception:
                pass
        types.append(tr)

    roles = assign_roles(cr.canonical, ameta if ameta else [{} for _ in range(n)],
                         sem.get("name_role_idx"))
    while len(roles) < n:
        roles.append(R1_VALUE)

    return {
        "protocol": protocol,
        "canon": cr,
        "args": args,
        "values": values,
        "meta": ameta,
        "types": types,
        "roles": roles[:n],
        "reasons": reasons,
    }


def _yara_text(fields: Dict[str, Any]) -> str:
    """Internal implementation detail."""
    parts = [fields["canon"].canonical]
    for i, a in enumerate(fields["args"]):
        tr = fields["types"][i] if i < len(fields["types"]) else None
        if tr is not None and tr.type == T2_NUMERIC:
            continue                      # numeric buffers are outside the text domain
        parts.append(a)
    text = " ".join(p for p in parts if p).strip()
    if fields["reasons"]:
        text += " [TAGS: " + " ".join(fields["reasons"]) + "]"
    return text


def _arg_view(fields: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Internal implementation detail."""
    view: List[Dict[str, Any]] = []
    meta = fields.get("meta") or []
    for i, tr in enumerate(fields["types"]):
        m = meta[i] if i < len(meta) and isinstance(meta[i], dict) else {}
        d: Dict[str, Any] = {
            "index": i,
            "type": tr.type,
            "role": fields["roles"][i] if i < len(fields["roles"]) else R1_VALUE,
            "flagged": bool(m.get("suspicious")),
            "reasons": [str(r) for r in (m.get("reasons") or [])],
        }
        nested = getattr(tr, "nested", None)
        if nested:
            d["nested_protocol"] = nested.get("protocol")
            d["nested_callables"] = nested.get("callables") or []
        view.append(d)
    return view


# ══════════════════════════════════════════════════════════════════════════
# IoC matching
# ══════════════════════════════════════════════════════════════════════════
def _rule_tier_entry(fields: Dict[str, Any], base: str) -> Optional[Dict[str, Any]]:
    """Internal implementation detail."""
    tiers = LITERAL_RULE_TIERS.get(base)
    if not tiers:
        return None
    meta = fields.get("meta") or []
    types = fields.get("types") or []
    best = None
    for i, m in enumerate(meta):
        if not isinstance(m, dict):
            continue
        tr = types[i] if i < len(types) else None
        if getattr(tr, "type", None) != T1_TEXT:
            continue
        for tag in (m.get("reasons") or []):
            if not isinstance(tag, str) or not tag.startswith(base):
                continue
            fired = _tag_rule_ids(tag)
            for rank, t in enumerate(tiers):
                req = set(t.get("require") or ())
                if req and not req.issubset(fired):
                    continue
                if len(fired) < int(t.get("min_rules") or 0):
                    continue
                if best is None or rank < best[0]:
                    best = (rank, t, fired)
                break
    if best is None:
        return None
    _, t, fired = best
    entry: Dict[str, Any] = {
        "tag": base,
        "qualification": t.get("qualification") or "combination_required",
        "rules_fired": sorted(fired),
        "tier_evidence": "%d python rules co-fired on a T1 literal "
                         "(benign base rate %s over the measured corpus)"
                         % (len(fired), t.get("benign")),
    }
    for k in ("category", "subcategory",
              "combination_category", "combination_subcategory"):
        if t.get(k):
            entry[k] = t[k]
    return entry


def _match_ioc(fields: Dict[str, Any]) -> Dict[str, Any]:
    canonical = fields["canon"].canonical
    out: Dict[str, Any] = {"callable_ioc": [], "literal_ioc": [], "name_role_ioc": []}

    # Callable vocabulary (exact match on the canonical name)
    e = CALLABLE_STANDALONE.get(canonical)
    if e:
        out["callable_ioc"].append({"name": canonical, "qualification": "standalone",
                                    "category": e.get("category"),
                                    "subcategory": e.get("subcategory")})
    else:
        e = CALLABLE_COMBINATION.get(canonical)
        if e:
            entry = {"name": canonical, "qualification": "combination_required"}
            if e.get("combination_category"):
                entry["combination_category"] = e["combination_category"]
            if e.get("combination_subcategory"):
                entry["combination_subcategory"] = e["combination_subcategory"]
            out["callable_ioc"].append(entry)
        elif GATEWAY_PROMOTION and (canonical in GATEWAYS or fields["canon"].raw in GATEWAYS):
            cat, sub = _gateway_label(canonical)
            out["callable_ioc"].append({"name": canonical, "qualification": "standalone",
                                        "category": cat, "subcategory": sub,
                                        "source": "stage2_denylist",
                                        "note": _GW_EVIDENCE})

    # Literal vocabulary: tiered tags first (co-firing rule count decides the
    # qualification), then plain tags
    tiered: Dict[str, Dict[str, Any]] = {}
    for base in LITERAL_RULE_TIERS:
        te = _rule_tier_entry(fields, base)
        if te is not None:
            tiered[base] = te
            out["literal_ioc"].append(te)

    for tag in fields["reasons"]:
        base = tag.split("(")[0].strip()
        if base in tiered:
            continue
        le = LITERAL_STANDALONE.get(base)
        if le:
            out["literal_ioc"].append({"tag": base, "qualification": "standalone",
                                       "category": le.get("category"),
                                       "subcategory": le.get("subcategory")})
            continue
        if base in LITERAL_COMBINATION or base.startswith("entropy>"):
            out["literal_ioc"].append({"tag": base, "qualification": "combination_required"})
            continue
        if base in LITERAL_DISQUALIFIED:
            out["literal_ioc"].append({"tag": base, "qualification": "disqualified"})

    # Name vocabulary: only arguments in a name position (R2)
    vals = fields.get("values") or fields["args"]
    for i, role in enumerate(fields["roles"]):
        if role != R2_NAME or i >= len(vals):
            continue
        v = (vals[i] or "").strip() if isinstance(vals[i], str) else ""
        if not v:
            continue
        hit_name, kind = None, None
        if v in NAME_DANGEROUS:
            hit_name, kind = v, "exact"
        elif v.rsplit(".", 1)[-1] in NAME_DANGEROUS:
            hit_name, kind = v.rsplit(".", 1)[-1], "last_component"
        else:
            for d in sorted(NAME_DANGEROUS):
                if d in v:
                    hit_name, kind = d, "substring"
                    break
        if hit_name:
            out["name_role_ioc"].append({"index": i, "value": v[:64],
                                         "matched": hit_name, "match_kind": kind})
    return out


# ══════════════════════════════════════════════════════════════════════════
# Verdict
# ══════════════════════════════════════════════════════════════════════════
def stage3_impossible(sem: Dict[str, Any]) -> bool:
    return bool((sem.get("stage3") or {}).get("impossible_combination"))


def _split_ioc(ioc: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    call = ioc.get("callable_ioc") or []
    lit = ioc.get("literal_ioc") or []
    name = ioc.get("name_role_ioc") or []
    return {
        "q_call": [e for e in call if e.get("qualification") == "standalone"],
        "c_call": [e for e in call if e.get("qualification") == "combination_required"],
        "q_lit": [e for e in lit if e.get("qualification") == "standalone"],
        "c_lit": [e for e in lit if e.get("qualification") == "combination_required"],
        "d_lit": [e for e in lit if e.get("qualification") == "disqualified"],
        "q_name": list(name),
    }


def _acts_from_ioc(parts: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, str]]:
    """Internal implementation detail."""
    acts: List[Dict[str, str]] = []

    for e in parts["q_call"]:
        if not e.get("category"):
            continue
        acts.append({
            "category": e["category"],
            "subcategory": e.get("subcategory") or "",
            "evidence": "callable IoC (standalone, benign base rate 0): %s" % e.get("name", ""),
        })

    for e in parts["q_lit"]:
        if not e.get("category"):
            continue
        acts.append({
            "category": e["category"],
            "subcategory": e.get("subcategory") or "",
            "evidence": "literal IoC (standalone, benign base rate 0): %s" % e.get("tag", ""),
        })

    # Combination: resolver callable x dangerous name literal
    if parts["c_call"] and parts["q_name"]:
        names = ", ".join(str(n.get("value", ""))[:32] for n in parts["q_name"])
        for e in parts["c_call"]:
            acts.append({
                "category": e.get("combination_category") or "Code Execution",
                "subcategory": e.get("combination_subcategory") or "Name Indirection Gadget",
                "evidence": "combination: %s consumes dangerous name literal (%s)"
                            % (e.get("name", ""), names),
            })

    # Combination: combination-required callable x standalone literal
    if parts["c_call"] and parts["q_lit"]:
        tags = ", ".join(str(l.get("tag", "")) for l in parts["q_lit"])
        for e in parts["c_call"]:
            if not e.get("combination_subcategory"):
                continue
            acts.append({
                "category": e.get("combination_category") or "Code Execution",
                "subcategory": e["combination_subcategory"],
                "evidence": "combination: %s carries qualified literal (%s)"
                            % (e.get("name", ""), tags),
            })
    return acts


def _demotion(sem: Dict[str, Any],
              arg_view: Sequence[Dict[str, Any]],
              gateways: frozenset) -> Optional[Dict[str, str]]:
    """Internal implementation detail."""
    # Tags from the hit plus per-argument tags; a Stage 2 denylist callable
    # (gateway) is never demoted
    tags = [_base_tag(t) for t in (sem.get("reason") or []) if isinstance(t, str)]
    for a in (arg_view or ()):
        for t in (a.get("reasons") or ()):
            if isinstance(t, str):
                bt = _base_tag(t)
                if bt not in tags:
                    tags.append(bt)
    canonical = ((sem.get("stage3") or {}).get("callable_canonical") or "")
    raw = ((sem.get("stage3") or {}).get("callable_raw") or "")
    is_gateway = canonical in gateways or raw in gateways

    # D-1: every flagged literal is a numeric buffer (T2)
    flagged = [a for a in arg_view if a.get("flagged")]
    if flagged and all(a.get("type") == "T2" for a in flagged) and not is_gateway:
        return {
            "rule": "D-1_TYPE_DOMAIN",
            "evidence": "all %d flagged literals recovered as T2 (numeric buffer); "
                        "text signatures are outside their domain" % len(flagged),
        }

    # D-4: only disqualified tags present
    if tags and all(t in DISQUALIFIED_ONLY for t in tags) and not is_gateway:
        return {
            "rule": "D-4_DISQUALIFIED_ONLY",
            "evidence": "only disqualified signals present (%s)" % ", ".join(sorted(set(tags))),
        }

    # D-2: path tags only, in a non-IO callable
    informative = [t for t in tags if t not in DISQUALIFIED_ONLY]
    if informative and all(t in _PATH_TAGS for t in informative) and not is_gateway:
        return {
            "rule": "D-2_TRAINING_CONFIG_PATH",
            "evidence": "path signal only (%s) in non-IO callable %s"
                        % (", ".join(sorted(set(informative))), canonical or raw),
        }

    # D-3: path tags plus borderline entropy, in a non-IO callable
    ent = sem.get("entropy")
    if (informative
            and all(t in _PATH_TAGS or t.startswith("entropy>") for t in informative)
            and any(t.startswith("entropy>") for t in informative)
            and isinstance(ent, (int, float)) and ent < BORDERLINE_ENTROPY_MAX
            and not is_gateway):
        return {
            "rule": "D-3_BORDERLINE_ENTROPY_PATH",
            "evidence": "borderline entropy %.2f (< %.1f) on path literal in "
                        "non-IO callable %s" % (ent, BORDERLINE_ENTROPY_MAX, canonical or raw),
        }
    return None


def judge(sem: Dict[str, Any],
          arg_view: Sequence[Dict[str, Any]],
          yara_acts: Sequence[Dict[str, str]],
          gateways: frozenset,
          yara_labels: Sequence[Dict[str, str]] = ()) -> Dict[str, Any]:
    """Internal implementation detail."""
    stage3 = sem.get("stage3") or {}
    parts = _split_ioc(stage3.get("ioc") or {})

    acts = _acts_from_ioc(parts)
    grounds: List[str] = []

    # Type x role violation
    if stage3_impossible(sem):
        grounds.append("impossible_type_role")
        acts.append({
            "category": "Code Execution",
            "subcategory": "Type-Role Violation",
            "evidence": "non-text literal consumed in a name/code position; "
                        "outside the reconstruction contract",
        })

    if parts["q_call"]:
        grounds.append("standalone_callable_ioc")
    if parts["q_lit"]:
        grounds.append("standalone_literal_ioc")
    if parts["c_call"] and parts["q_name"]:
        grounds.append("combination_callable_x_name")

    # Nested pickle payload referencing a callable
    for a in arg_view:
        for c in (a.get("nested_callables") or []):
            grounds.append("nested_callable")
            acts.append({
                "category": "Code Execution",
                "subcategory": "Nested Pickle Execution",
                "evidence": "nested pickle (proto=%s) references %s.%s"
                            % (a.get("nested_protocol"), c.get("module", ""), c.get("name", "")),
            })

    # Standalone YARA rules
    for a in yara_acts:
        if a not in acts:
            acts.append(a)
    if yara_acts:
        grounds.append("yara_rule")

    if acts:
        # Labeling-only YARA rules add labels once the hit is already classified
        for a in (yara_labels or ()):
            if a not in acts:
                acts.append(a)
        if yara_labels:
            grounds.append("yara_label")

        seen = set()
        uniq = []
        for a in acts:
            k = (a["category"], a["subcategory"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(a)
        return {"verdict": VERDICT_C, "rank": RANK_HIGH, "acts": uniq,
                "grounds": grounds, "demotion": None}

    # Unclassified: record labeling evidence, then try the demotion rules
    label_ev = [{"rule": a.get("rule", ""), "category": a.get("category", ""),
                 "subcategory": a.get("subcategory", "")} for a in (yara_labels or ())]

    dem = _demotion(sem, arg_view, gateways)
    if dem is not None:
        out = {"verdict": VERDICT_U, "rank": RANK_LOW, "acts": [],
               "grounds": [dem["rule"]], "demotion": dem}
        if label_ev:
            out["yara_labeling"] = label_ev
        return out

    out = {"verdict": VERDICT_U, "rank": RANK_HIGH, "acts": [],
           "grounds": [], "demotion": None}
    if label_ev:
        out["yara_labeling"] = label_ev
        out["grounds"] = ["yara_label_only"]
    return out


# ══════════════════════════════════════════════════════════════════════════
# Entry points
# ══════════════════════════════════════════════════════════════════════════
def analyze_one_hit(hit: Dict[str, Any], protocol: int = 0) -> None:
    """Internal implementation detail."""
    sem = ensure_semantic_result(hit)
    fields = build_scan_fields(hit, protocol)
    text = _yara_text(fields)

    cr = fields["canon"]
    stage3: Dict[str, Any] = {
        "protocol": protocol,
        "callable_canonical": cr.canonical,
        "callable_raw": cr.raw,
        "args": [],
        "ioc": _match_ioc(fields),
    }
    if cr.changed:
        stage3["canon_steps"] = list(cr.steps)
    if cr.unresolvable:
        stage3["unresolvable_reference"] = True
    impossible = False
    for i, tr in enumerate(fields["types"]):
        role = fields["roles"][i] if i < len(fields["roles"]) else R1_VALUE
        d = tr.to_dict()
        d["index"] = i
        d["role"] = role
        if impossible_combination(tr.type, role):
            d["impossible_combination"] = True
            impossible = True
        stage3["args"].append(d)
    if impossible:
        stage3["impossible_combination"] = True
    sem["stage3"] = stage3

    # YARA over the field text (canonical callable + T1/T3/T4 arguments + tags).
    # "standalone" rules can classify on their own; "labeling" rules only add
    # labels to a hit that is classified on other grounds.
    yara_acts: List[Dict[str, str]] = []
    yara_labels: List[Dict[str, str]] = []
    if text:
        for m in YARA_RULES.match(data=text.encode("utf-8", errors="replace")):
            if m.meta.get("priority", 99) > MAX_PRIORITY:
                continue
            act = {"category": m.meta["category"],
                   "subcategory": m.meta["subcategory"],
                   "evidence": m.meta["evidence"],
                   "rule": m.rule}
            if m.meta.get("qualification") == "standalone":
                yara_acts.append(act)
            else:
                yara_labels.append(act)

    result = judge(sem, _arg_view(fields), yara_acts, GATEWAYS, yara_labels=yara_labels)
    stage3["verdict"] = result["verdict"]
    stage3["rank"] = result["rank"]
    if result["grounds"]:
        stage3["grounds"] = result["grounds"]
    for a in result["acts"]:
        add_act(sem, a["category"], a["subcategory"], a["evidence"])
    if result["demotion"] is not None:
        stage3["demotion"] = result["demotion"]


def finalize_report(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Internal implementation detail."""
    hits = doc.get("hits")
    if not isinstance(hits, list):
        return doc

    n_c = n_uh = n_ul = 0
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        sem = ((hit.get("suspicious") or {}).get("semantic_result") or {})
        s3 = sem.get("stage3") or {}
        v, rank = s3.get("verdict"), s3.get("rank")
        if v == VERDICT_C:
            n_c += 1
        elif rank == RANK_LOW:
            n_ul += 1
        else:
            n_uh += 1

    mi = doc.setdefault("model_info", {})
    if isinstance(mi, dict):
        mi["stage3_summary"] = {
            "input_hits": len(hits),
            "classified": n_c,
            "unclassified_high": n_uh,
            "unclassified_low": n_ul,
            "removed": 0,
        }
    return doc


def iter_hits(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = doc.get("hits")
    if isinstance(hits, list):
        return hits
    hits = doc.get("results")
    return hits if isinstance(hits, list) else []


def protocol_of(doc: Dict[str, Any]) -> int:
    """Internal implementation detail."""
    mi = doc.get("model_info")
    if isinstance(mi, dict) and isinstance(mi.get("protocol"), int):
        return mi["protocol"]
    return 0
