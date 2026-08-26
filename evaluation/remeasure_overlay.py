#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Overlay freshly re-measured RoPS fields onto the frozen raw inputs.

`rops_remeasure.py` produces one RoPS record per sample_id. These helpers write
the RoPS-updated raw file each RQ builder consumes, replacing only the
RoPS-attributable fields and preserving the frozen baseline-tool verdicts and the
loading-harness oracle.

  RQ1: build a fresh rfp.jsonl from the carved-blob SHAs and terminal classes.
  RQ2: overlay the RoPS judgment fields onto rq2_results.jsonl.
  RQ3: overlay the RoPS judgment fields onto rq3_redesign.jsonl.
"""
import json


def _load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _by_sid(path):
    return {r["sample_id"]: r for r in _load(path)}


def rfp_from_remeasure(remeasure_jsonl, out_rfp):
    """RQ1: RoPS re-extraction -> rfp.jsonl (one record per file).

    Each stream carries the blob SHA-256, its terminal class (Serialization /
    Opaque), and found=True (RoPS carved it). build_rq1_final matches these SHAs
    against the harness oracle SHAs to score reachability.
    """
    m = _by_sid(remeasure_jsonl)
    n = 0
    with open(out_rfp, "w", encoding="utf-8") as out:
        for sid, r in m.items():
            if not str(r.get("status", "")).startswith("ok"):
                continue
            streams = [{"sha": s, "final_cls": k, "found": True}
                       for s, k in zip(r.get("blob_shas") or [], r.get("blob_kinds") or [])]
            out.write(json.dumps({"sample_id": sid,
                                  "n_rops": r.get("n_rops", 0),
                                  "streams": streams}, ensure_ascii=False) + "\n")
            n += 1
    return n


def overlay_rq2(remeasure_jsonl, in_res, out_res):
    """RQ2: replace RoPS judgment fields in rq2_results.jsonl."""
    m = _by_sid(remeasure_jsonl)
    n = 0
    with open(out_res, "w", encoding="utf-8") as out:
        for r in _load(in_res):
            rm = m.get(r["sample_id"])
            if rm and str(rm.get("status", "")).startswith("ok"):
                r["H1"] = bool(rm["rops_warn"])              # warn-or-above (unsafe + review)
                r["n_unsafe"] = int(rm["n_unsafe"])
                r["n_review"] = int(rm["n_review"])
                r["n_low"] = int(rm["n_low"])
                r["n_hits"] = int(rm["n_hits"])
                r["callables"] = list(rm.get("callables") or [])
                n += 1
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    return n


def overlay_rq3(remeasure_jsonl, in_red, out_red):
    """RQ3: replace RoPS judgment fields in rq3_redesign.jsonl."""
    m = _by_sid(remeasure_jsonl)
    n = 0
    with open(out_red, "w", encoding="utf-8") as out:
        for r in _load(in_red):
            rm = m.get(r["sample_id"])
            if rm and str(rm.get("status", "")).startswith("ok"):
                r["rops_warn"] = bool(rm["rops_warn"])
                r["rops_confirm"] = bool(rm["rops_confirm"])
                r["rops_low"] = int(rm["n_low"])
                r["or_globals"] = int(rm["or_globals"])
                n += 1
            out.write(json.dumps(r, ensure_ascii=False) + "\n")
    return n


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="overlay re-measured RoPS fields onto a raw input")
    ap.add_argument("mode", choices=["rq1", "rq2", "rq3"])
    ap.add_argument("--remeasure", required=True, help="rops_remeasured.jsonl")
    ap.add_argument("--in", dest="inp", default="", help="frozen raw input (rq2_results / rq3_redesign)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.mode == "rq1":
        k = rfp_from_remeasure(a.remeasure, a.out)
    elif a.mode == "rq2":
        k = overlay_rq2(a.remeasure, a.inp, a.out)
    else:
        k = overlay_rq3(a.remeasure, a.inp, a.out)
    print("overlaid %d records -> %s" % (k, a.out))
