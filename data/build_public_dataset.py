#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Materialize the public RoPS dataset from the internal tree.

For every row of the public ledger (master_ledger_public.csv) this script
looks up the sample's original location in the internal ledger
(MASTER_INDEX.csv), copies that file to its public destination
(OUT_ROOT/<ledger.path>) renaming it to <sample_id>.<ext>, and verifies the
copy against the SHA-256 and size recorded in the public ledger.

Nothing in the internal tree is modified or deleted; only reads happen there.

Usage
-----
    # dry run: resolve every source, check sizes, report — copies nothing
    python3 build_public_dataset.py --dry-run

    # real copy
    python3 build_public_dataset.py

    # custom locations
    python3 build_public_dataset.py \
        --data-root  /Volumes/Research/Research/DataSet/Data \
        --orig-ledger /Volumes/Research/Research/DataSet/Data/rops_eval/ledger/MASTER_INDEX.csv \
        --pub-ledger master_ledger_public.csv \
        --out-root   /Volumes/Research/Research/DataSet/Data/rops_public

Re-running is safe: a destination whose SHA-256 already matches is skipped.
"""

import argparse
import csv
import hashlib
import os
import shutil
import sys

# ---- defaults (edit here or override on the command line) -------------------
DEFAULT_DATA_ROOT   = "/Volumes/Research/Research/DataSet/Data"
DEFAULT_ORIG_LEDGER = "/Volumes/Research/Research/DataSet/Data/rops_eval/ledger/MASTER_INDEX.csv"
DEFAULT_PUB_LEDGER  = "master_ledger_public.csv"
DEFAULT_OUT_ROOT    = "/Volumes/Research/Research/DataSet/Data/rops_public"

_READ_CHUNK = 1 << 20  # 1 MiB


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def load_original_paths(orig_ledger):
    """sample_id -> original relative path (from the internal ledger)."""
    out = {}
    with open(orig_ledger, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[r["sample_id"]] = r["path"]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-root", default=DEFAULT_DATA_ROOT,
                    help="root the internal ledger paths are relative to")
    ap.add_argument("--orig-ledger", default=DEFAULT_ORIG_LEDGER,
                    help="internal MASTER_INDEX.csv (source of original paths)")
    ap.add_argument("--pub-ledger", default=DEFAULT_PUB_LEDGER,
                    help="public master_ledger_public.csv (destination paths)")
    ap.add_argument("--out-root", default=DEFAULT_OUT_ROOT,
                    help="root the public dataset is written under")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve and verify sources without copying")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip SHA-256 verification of copies (size check only)")
    args = ap.parse_args()

    orig = load_original_paths(args.orig_ledger)
    with open(args.pub_ledger, encoding="utf-8") as fh:
        pub_rows = list(csv.DictReader(fh))

    n = len(pub_rows)
    copied = skipped = 0
    errors = []

    for i, row in enumerate(pub_rows, 1):
        sid = row["sample_id"]
        rel = orig.get(sid)
        if rel is None:
            errors.append((sid, "not found in internal ledger"))
            continue

        src = os.path.join(args.data_root, rel)
        dst = os.path.join(args.out_root, row["path"])
        want_sha = row["sha256"]
        want_size = int(row["size_bytes"]) if row["size_bytes"] else None

        if not os.path.isfile(src):
            errors.append((sid, "source missing: %s" % src))
            continue

        # size sanity against the ledger (cheap; catches the wrong file early)
        actual_size = os.path.getsize(src)
        if want_size is not None and actual_size != want_size:
            errors.append((sid, "size mismatch src=%d ledger=%d" % (actual_size, want_size)))
            continue

        # idempotent skip: destination already correct
        if os.path.isfile(dst) and (args.no_verify or sha256_of(dst) == want_sha):
            skipped += 1
            _progress(i, n, "skip", sid)
            continue

        if args.dry_run:
            # in dry-run, still verify the SOURCE hash so the report is meaningful
            if not args.no_verify and want_sha:
                got = sha256_of(src)
                if got != want_sha:
                    errors.append((sid, "SRC sha mismatch got=%s ledger=%s" % (got[:12], want_sha[:12])))
                    continue
            _progress(i, n, "ok(dry)", sid)
            continue

        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

        if not args.no_verify and want_sha:
            got = sha256_of(dst)
            if got != want_sha:
                errors.append((sid, "COPY sha mismatch got=%s ledger=%s" % (got[:12], want_sha[:12])))
                try:
                    os.remove(dst)
                except OSError:
                    pass
                continue
        copied += 1
        _progress(i, n, "copied", sid)

    print("\n" + "=" * 60)
    verb = "would copy" if args.dry_run else "copied"
    print("total       : %d" % n)
    print("%-11s : %d" % (verb, copied))
    print("skipped     : %d (already present)" % skipped)
    print("errors      : %d" % len(errors))
    for sid, msg in errors[:50]:
        print("   [!] %s  %s" % (sid, msg))
    if len(errors) > 50:
        print("   ... and %d more" % (len(errors) - 50))

    sys.exit(1 if errors else 0)


def _progress(i, n, tag, sid):
    if i % 50 == 0 or i == n:
        sys.stdout.write("\r  [%4d/%4d] %-8s %s        " % (i, n, tag, sid))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
