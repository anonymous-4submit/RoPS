#!/usr/bin/env python3
"""Internal implementation detail."""

import argparse
import json
import sys
from pathlib import Path

from extractor import extract_pickles, PickleBlob, ExtractionReport
from detector import build_json_report_for_blob
from classifier import analyze_one_hit, iter_hits, protocol_of, finalize_report
from detector.report_compact import compact_report, DEFAULT_MAX_LITERAL


def _fmt_size(n: int) -> str:
    """Internal implementation detail."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _print_single_summary(file_summary: dict) -> None:
    """Internal implementation detail."""
    bar = "─" * 64
    name = file_summary["name"]
    hits = file_summary["hits"]

    print(f"\n{bar}")
    print(f"  Scan result summary: {name}")
    print(bar)

    if not hits:
        print("  no issue — suspicious hit none detected")
        print(bar)
        return

    print(f"  Total {len(hits)} hits found\n")
    for i, h in enumerate(hits, 1):
        print(f"  [Hit {i}]")

        cname = h.get("callable", "")
        if cname:
            print(f"    callable  : {cname}")

        args = h.get("args", [])
        if args:
            for j, arg in enumerate(args):
                truncated = arg if len(arg) <= 100 else arg[:100] + "..."
                prefix = "    arguments :" if j == 0 else "              +"
                print(f"{prefix} {truncated}")

        acts = h.get("acts", [])
        if acts:
            label = "    malicious act :"
            for act in acts:
                cat = act.get("category", "")
                sub = act.get("subcategory", "")
                line = f"{cat} / {sub}" if sub else cat
                print(f"{label} {line}")
                label = "              "
        else:
            print(f"    malicious act : (not classified)")

        if i < len(hits):
            print()

    print(bar)


def _print_multi_summary(all_results: list) -> None:
    """Internal implementation detail."""
    bar = "═" * 64
    total = len(all_results)

    def _has_act(r):
        return any(h.get("acts") for h in r["hits"])

    def _cfind(r):
        
        return r.get("container_findings") or []

    def _has_review(r):
        return (any(not h.get("acts") and h.get("rank") != "low" for h in r["hits"])
                or bool(_cfind(r)))

    danger_count = sum(1 for r in all_results if _has_act(r))
    review_count = sum(1 for r in all_results if not _has_act(r) and _has_review(r))
    low_count = sum(1 for r in all_results
                    if not _has_act(r) and not _has_review(r) and r["hits"])

    print(f"\n{bar}")
    print(f"  Total scan summary:  ({total}files / unsafe {danger_count}"
          f" / review {review_count} / low {low_count})")
    print(bar)

    for r in all_results:
        name = r["name"]
        hits = r["hits"]

        if not hits:
            cf = _cfind(r)
            if cf:
                
                
                tag = f"  [Review] {name}"
                print(f"{tag:<44} container: {cf[0].get('kind','')} — {cf[0].get('member','')[:48]}")
                for extra in cf[1:3]:
                    print(f"{'':44} container: {extra.get('member','')[:48]}")
            else:
                print(f"  [No issue] {name}")
            continue

        
        acts_seen: list = []
        for h in hits:
            for act in h.get("acts", []):
                cat = act.get("category", "")
                sub = act.get("subcategory", "")
                entry = f"{cat} / {sub}" if sub else cat
                if entry and entry not in acts_seen:
                    acts_seen.append(entry)

        if acts_seen:
            tag = f"  [Unsafe] {name}"
            
            print(f"{tag:<44} {acts_seen[0]}")
            
            for extra in acts_seen[1:]:
                print(f"{'':44} {extra}")
        else:
            
            
            n_hi = sum(1 for h in hits if h.get("rank") != "low")
            n_lo = len(hits) - n_hi
            tag = f"  [Review] {name}" if n_hi else f"  [Low]    {name}"
            print(f"{tag:<44} unclassified {n_hi} high / {n_lo} low")

    print(bar)


def main():
    ap = argparse.ArgumentParser(
        description="RoPS 3-stage pipeline: extractor → detector → classifier"
    )
    ap.add_argument(
        "inputs", nargs="*",
        help="Paths to model files to analyze (pt, pth, pkl, joblib, h5, etc.)"
    )
    ap.add_argument(
        "--path",
        help="Directory path: process all files and create one output directory per file"
    )
    ap.add_argument(
        "-o", "--outdir", default="rops_output",
        help="Output directory (default: rops_output)"
    )
    ap.add_argument(
        "--entropy", type=float, default=5.0,
        help="Stage 2 suspicious-literal entropy threshold (default: 5.0)"
    )
    ap.add_argument(
        "--max-literal", type=int, default=DEFAULT_MAX_LITERAL,
        help=("Maximum literal length in reports (default: %d). Longer values retain "
              "their length and hash. Originals remain recoverable from stage1_blobs/. "
              "Use 0 to disable truncation for debugging. Stage 3 always analyzes complete "
              "arguments; truncation occurs only before serialization." % DEFAULT_MAX_LITERAL)
    )
    
    
    #   --use-denylist → True   /   --no-denylist → False (ablation)
    
    
    
    dl = ap.add_mutually_exclusive_group()
    dl.add_argument(
        "--use-denylist", dest="use_denylist", action="store_true", default=None,
        help="Force-enable Stage 2 Track A (dangerous-callable triggers).")
    dl.add_argument(
        "--no-denylist", dest="use_denylist", action="store_false",
        help="Force-disable Track A (ablation: literal-based Track B only).")
    args = ap.parse_args()

    
    paths_to_process: list = []
    use_per_file = False

    if args.path:
        dir_path = Path(args.path)
        if not dir_path.is_dir():
            print(f"[error] --path is not a directory: {dir_path}", file=sys.stderr)
            sys.exit(1)
        dir_files = sorted(f for f in dir_path.iterdir() if f.is_file())
        if not dir_files:
            print(f"[warn] Directory is empty: {dir_path}", file=sys.stderr)
        paths_to_process.extend(dir_files)
        use_per_file = True

    paths_to_process.extend(Path(p) for p in (args.inputs or []))

    if not paths_to_process:
        ap.error("Specify files to analyze or use --path.")

    outdir = Path(args.outdir)

    total_files = 0
    total_blobs = 0
    total_hits = 0
    total_demoted = 0
    all_results: list = []   

    for path in paths_to_process:
        if not path.exists():
            print(f"[skip] not found: {path}", file=sys.stderr)
            continue

        
        if use_per_file:
            file_outdir = outdir / path.stem
        else:
            file_outdir = outdir

        stage1_dir = file_outdir / "stage1_blobs"
        stage3_dir = file_outdir / "stage3_labeled"
        stage1_dir.mkdir(parents=True, exist_ok=True)
        stage3_dir.mkdir(parents=True, exist_ok=True)

        total_files += 1
        file_hit_details: list = []  

        
        stat = path.stat()
        print(
            f"\n[File] {path.name}"
            f"  |  Size: {_fmt_size(stat.st_size)}"
            f"  |  Extension: {path.suffix or '(none)'}"
        )
        print(f"[Stage 1] {path.name} -> extracting pickle data...")

        report = extract_pickles(path, stage1_dir)

        for err in report.errors:
            print(f"  [warn] {err}", file=sys.stderr)

        if not report.blobs:
            print(f"  [skip] no pickle blobs")
            
            all_results.append({"name": path.name, "hits": [],
                                "container_findings": list(getattr(report, "container_findings", []) or [])})
            continue

        
        print(f" {len(report.blobs)} blob(s) extracted:")
        for blob in report.blobs:
            print(f"    • {blob.logical_name}  ({_fmt_size(blob.size)})")

        
        carved_names = [b.logical_name for b in report.blobs]

        for blob in report.blobs:
            if not blob.output_path:
                continue

            blob_path = Path(blob.output_path)
            total_blobs += 1

            print(f"\n[Stage 2] {blob.logical_name} -> scanning suspicious tuples...")

            
            
            try:
                data = blob_path.read_bytes()
                json_report = build_json_report_for_blob(
                    input_filename=path.name,
                    carved_names=carved_names,
                    logical_name=blob.logical_name,
                    data=data,
                    ent_threshold=args.entropy,
                    enable_denylist=args.use_denylist,
                )

                hit_count = len(json_report.get("hits", []))
                print(f"  hit {hit_count} found")

                print(f"\n[Stage 3] {blob.logical_name} → malicious act classification...")

                
                
                
                _proto = protocol_of(json_report)
                for hit in iter_hits(json_report):
                    if not isinstance(hit, dict):
                        continue
                    analyze_one_hit(hit, protocol=_proto)

                
                
                
                finalize_report(json_report)
                summ = json_report.get("model_info", {}).get("stage3_summary", {})
                n_low = summ.get("unclassified_low", 0)
                print(f"  Verdict: C {summ.get('classified', 0)} / "
                      f"U-high {summ.get('unclassified_high', 0)} / U-low {n_low} (downgraded)")
                total_demoted += n_low

                for hit in iter_hits(json_report):
                    if not isinstance(hit, dict):
                        continue
                    total_hits += 1
                    sr = hit.get("suspicious", {}).get("semantic_result", {})
                    if isinstance(sr, dict):
                        file_hit_details.append({
                            "callable": sr.get("callable", "") or "",
                            "args":     sr.get("arguments", []) or [],
                            "acts":     sr.get("Malicious_act", []) or [],
                            "rank":     (sr.get("stage3") or {}).get("rank", "high"),
                        })

                
                
                
                compact_report(json_report, max_literal=args.max_literal)

                
                safe = blob.logical_name.replace("/", "__").replace("\\", "__")
                out_name = f"{path.stem}__{safe}_labeled.json"
                out_path = stage3_dir / out_name
                out_path.write_text(
                    json.dumps(json_report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                print(f"  → {out_path}")
            except Exception as e:
                msg = f"blob '{blob.logical_name}' processing failed: {type(e).__name__}: {e}"
                report.errors.append(msg)
                print(f"  [error] {msg}", file=sys.stderr)
                continue

        
        all_results.append({"name": path.name, "hits": file_hit_details,
                            "container_findings": list(getattr(report, "container_findings", []) or [])})

    print(f"\nscan finished: files {total_files}, blobs {total_blobs}, "
          f"hits {total_hits} (demoted {total_demoted})")
    print(f"results location: {outdir}/")

    
    is_single = (len(paths_to_process) == 1 and not use_per_file)
    if is_single and all_results:
        _print_single_summary(all_results[0])
    elif all_results:
        _print_multi_summary(all_results)


if __name__ == "__main__":
    main()
