#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RQ3 re-run driver.

From data/rq3_redesign.jsonl (419, all tool results + weights_only-12 combined),
regenerate rq3_final.jsonl (finalized cell judgments) and the results-table xlsx. Run from anywhere.

The full re-measurement (--full) is the heavy stage that re-runs RoPS, picklescan, modelscan, fickling,
weights_only against the original files, performed on the user's Mac with each tool runner (see README).
Usage:
    python3 run_rq3.py           # rebuild from data/
"""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')
EVAL = os.path.dirname(HERE)   # evaluation/
LEDGER = os.path.join(HERE, '..', '..', 'data', 'master_ledger.csv')


def sh(cmd):
    print('  $', ' '.join(cmd)); subprocess.check_call(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--remeasure', action='store_true',
                    help='re-run RoPS over the dataset to regenerate its judgments first')
    ap.add_argument('--dataset', default='/data', help='restored dataset root (with --remeasure)')
    a = ap.parse_args()
    red = os.path.join(DATA, 'rq3_redesign.jsonl')
    final = os.path.join(HERE, 'rq3_final.jsonl')
    xlsx = os.path.join(HERE, 'RQ3_results.xlsx')
    if a.full:
        print('Full re-measurement re-inspects the original files with each tool runner')
        print('(RoPS/picklescan/modelscan/fickling/weights_only), rebuilds rq3_redesign.jsonl, then runs the below. See README.')
        return 0

    if a.remeasure:
        rm = os.path.join(DATA, 'rops_remeasured.jsonl')
        red_rm = os.path.join(DATA, 'rq3_redesign_remeasured.jsonl')
        print('[0/2] re-running RoPS over the dataset (judgments)')
        sh([sys.executable, os.path.join(EVAL, 'rops_remeasure.py'),
            '--dataset', a.dataset, '--ledger', LEDGER, '--rq', '3', '--out', rm])
        sh([sys.executable, os.path.join(EVAL, 'remeasure_overlay.py'),
            'rq3', '--remeasure', rm, '--in', red, '--out', red_rm])
        red = red_rm
    blobs = os.path.join(DATA, 'rq3_fickling_blobs.jsonl')
    blobs_extra = os.path.join(DATA, 'rq3_blobs_new12.json')
    print('[1/2] Building rq3_final.jsonl (including fickling blob merge)')
    cmd = [sys.executable, os.path.join(HERE, 'build_rq3_final.py'), '--res', red, '--out', final]
    if os.path.exists(blobs):
        cmd += ['--blobs', blobs]
    if os.path.exists(blobs_extra):
        cmd += ['--blobs-extra', blobs_extra]
    sh(cmd)
    print('[2/2] Building results-table xlsx')
    sh([sys.executable, os.path.join(HERE, 'rq3_table.py'), '--final', final, '--out', xlsx])
    print('Done:', final, '|', xlsx)
    return 0


if __name__ == '__main__':
    sys.exit(main())
