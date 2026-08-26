#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-execute RoPS over the dataset and emit per-file RoPS measurements.

This runs the actual RoPS pipeline (extractor -> detector -> classifier, the same
path as RoPS/src/pipeline.py) over each model file listed in the public ledger,
and records the RoPS-attributable measurements each research question needs:

  * reachability  : the SHA-256 and terminal class of every pickle blob RoPS
                    carves (RQ1),
  * judgment      : the per-file three-valued verdict counts unsafe / review /
                    low and the reconstructed callables (RQ2, RQ3).

RoPS is static and never loads a model, so scanning malicious artifacts here does
not execute their payloads.

Output: one JSON record per sample_id (see FIELDS below). Downstream, each RQ's
`run_*.py --remeasure` overlays these RoPS fields onto the frozen baseline /
oracle raw inputs and rebuilds the results.

Usage
-----
    python3 rops_remeasure.py --dataset /data --ledger ../data/master_ledger.csv \
        --out data/rops_remeasured.jsonl [--rq 2] [--limit N]

`--dataset` is the restored dataset root containing data/<origin>/<sample_id>.<ext>
(the ledger `path` column is resolved against it). `--rq` restricts to a single
research question's corpus (used_in_RQ); omit to scan all 663 samples.
"""
import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path

# RoPS packages (RoPS/src is on PYTHONPATH; the Docker image sets it, or add it
# here for a direct run).
_SRC = Path(__file__).resolve().parent.parent / "RoPS" / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from extractor import extract_pickles                       # noqa: E402
from detector import build_json_report_for_blob            # noqa: E402
from classifier import (analyze_one_hit, iter_hits,        # noqa: E402
                        protocol_of, finalize_report)

# Per-file RoPS fields emitted for downstream overlay.
FIELDS = ("sample_id", "status", "n_rops", "blob_shas", "blob_kinds",
          "n_hits", "n_unsafe", "n_review", "n_low",
          "rops_warn", "rops_confirm", "or_globals", "callables")


def _blob_terminal(source_kind: str) -> str:
    """RoPS blob source_kind -> RQ1 terminal class."""
    return "Opaque" if (source_kind or "").startswith("pgs") else "Serialization"


def scan_file(path: Path, ent_threshold: float = 5.0) -> dict:
    """Run the full RoPS pipeline over one file and aggregate its measurements."""
    with tempfile.TemporaryDirectory() as td:
        stage1 = Path(td) / "stage1"
        stage1.mkdir(parents=True, exist_ok=True)
        report = extract_pickles(path, stage1)
        blobs = list(report.blobs or [])
        carved_names = [b.logical_name for b in blobs]

        blob_shas, blob_kinds = [], []
        n_hits = n_unsafe = n_review = n_low = 0
        callables = set()

        for blob in blobs:
            blob_shas.append(blob.sha256)
            blob_kinds.append(_blob_terminal(blob.source_kind))
            if not blob.output_path:
                continue
            data = Path(blob.output_path).read_bytes()
            jr = build_json_report_for_blob(
                input_filename=path.name,
                carved_names=carved_names,
                logical_name=blob.logical_name,
                data=data,
                ent_threshold=ent_threshold,
                enable_denylist=None,          # default (Track A + Track B), as in pipeline.py
            )
            proto = protocol_of(jr)
            for hit in iter_hits(jr):
                if isinstance(hit, dict):
                    analyze_one_hit(hit, protocol=proto)
            finalize_report(jr)
            summ = (jr.get("model_info", {}) or {}).get("stage3_summary", {}) or {}
            n_unsafe += int(summ.get("classified", 0) or 0)
            n_review += int(summ.get("unclassified_high", 0) or 0)
            n_low += int(summ.get("unclassified_low", 0) or 0)
            for hit in iter_hits(jr):
                if not isinstance(hit, dict):
                    continue
                n_hits += 1
                sr = (hit.get("suspicious", {}) or {}).get("semantic_result", {}) or {}
                c = ((sr.get("stage3", {}) or {}).get("callable_canonical")
                     or sr.get("callable"))
                if c:
                    callables.add(c)

    return {
        "n_rops": len(blobs),
        "blob_shas": blob_shas,
        "blob_kinds": blob_kinds,
        "n_hits": n_hits,
        "n_unsafe": n_unsafe,
        "n_review": n_review,
        "n_low": n_low,
        "rops_warn": (n_unsafe + n_review) >= 1,
        "rops_confirm": n_unsafe >= 1,
        "or_globals": n_hits,               # call-site (global) count, as used by the RQ3 reach heuristic
        "callables": sorted(callables),
    }


def load_corpus(ledger: str, rq):
    rows = list(csv.DictReader(open(ledger, encoding="utf-8")))
    if rq is None:
        return rows
    return [r for r in rows if str(rq) in (r.get("used_in_RQ") or "").split(";")]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True, help="restored dataset root")
    ap.add_argument("--ledger", required=True, help="public master_ledger.csv")
    ap.add_argument("--out", required=True, help="output rops_remeasured.jsonl")
    ap.add_argument("--rq", type=int, default=None, help="restrict to one RQ corpus (1/2/3)")
    ap.add_argument("--limit", type=int, default=0, help="scan at most N files (debug)")
    ap.add_argument("--entropy", type=float, default=5.0)
    args = ap.parse_args()

    rows = load_corpus(args.ledger, args.rq)
    if args.limit:
        rows = rows[:args.limit]

    n = len(rows)
    ok = err = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for i, r in enumerate(rows, 1):
            sid = r["sample_id"]
            src = Path(args.dataset) / r["path"]
            rec = {"sample_id": sid}
            if not src.is_file():
                rec.update({"status": "missing", "n_rops": 0, "blob_shas": [],
                            "blob_kinds": [], "n_hits": 0, "n_unsafe": 0,
                            "n_review": 0, "n_low": 0, "rops_warn": False,
                            "rops_confirm": False, "or_globals": 0, "callables": []})
                err += 1
            else:
                try:
                    m = scan_file(src, ent_threshold=args.entropy)
                    m["status"] = "ok"
                    rec.update(m)
                    ok += 1
                except Exception as e:                       # keep going; record the failure
                    rec.update({"status": "error:%s" % type(e).__name__, "n_rops": 0,
                                "blob_shas": [], "blob_kinds": [], "n_hits": 0,
                                "n_unsafe": 0, "n_review": 0, "n_low": 0,
                                "rops_warn": False, "rops_confirm": False,
                                "or_globals": 0, "callables": []})
                    err += 1
            out.write(json.dumps({k: rec.get(k) for k in FIELDS}, ensure_ascii=False) + "\n")
            if i % 25 == 0 or i == n:
                sys.stdout.write("\r  [%4d/%4d] ok=%d err=%d  %s        " % (i, n, ok, err, sid))
                sys.stdout.flush()

    print("\nwrote %s  (%d records: ok=%d, missing/error=%d)" % (args.out, n, ok, err))


if __name__ == "__main__":
    main()
