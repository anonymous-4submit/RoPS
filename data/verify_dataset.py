#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify a restored RoPS dataset against the ledger.

Reads master_ledger.csv and, for every row, checks that
<dataset-root>/<path> exists and matches the recorded SHA-256 and size.
Use this after downloading and extracting the dataset (see DATASET.md).

Usage
-----
    python3 verify_dataset.py --root /path/to/rops_dataset
    python3 verify_dataset.py --root /data --ledger master_ledger.csv

Exit code is non-zero if any file is missing or mismatched.
"""
import argparse
import csv
import hashlib
import os
import sys

_READ_CHUNK = 1 << 20  # 1 MiB


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_READ_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", required=True,
                    help="dataset root containing data/<origin>/<sample_id>.<ext>")
    ap.add_argument("--ledger", default=os.path.join(here, "master_ledger.csv"),
                    help="path to master_ledger.csv (default: alongside this script)")
    ap.add_argument("--quick", action="store_true",
                    help="check presence and size only, skip SHA-256 (fast)")
    args = ap.parse_args()

    with open(args.ledger, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    n = len(rows)
    ok = 0
    errors = []
    for i, r in enumerate(rows, 1):
        dst = os.path.join(args.root, r["path"])
        if not os.path.isfile(dst):
            errors.append((r["sample_id"], "missing: %s" % r["path"]))
            continue
        want_size = int(r["size_bytes"]) if r["size_bytes"] else None
        if want_size is not None and os.path.getsize(dst) != want_size:
            errors.append((r["sample_id"], "size mismatch (have %d, ledger %d)"
                           % (os.path.getsize(dst), want_size)))
            continue
        if not args.quick and r["sha256"]:
            if sha256_of(dst) != r["sha256"]:
                errors.append((r["sample_id"], "SHA-256 mismatch"))
                continue
        ok += 1
        if i % 50 == 0 or i == n:
            sys.stdout.write("\r  [%4d/%4d] verified" % (i, n))
            sys.stdout.flush()

    print("\n" + "=" * 56)
    print("total   : %d" % n)
    print("verified: %d" % ok)
    print("errors  : %d" % len(errors))
    for sid, msg in errors[:50]:
        print("   [!] %s  %s" % (sid, msg))
    if len(errors) > 50:
        print("   ... and %d more" % (len(errors) - 50))
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
