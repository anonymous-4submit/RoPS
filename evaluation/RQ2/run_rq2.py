#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RQ2 (denylist V2) re-run driver.

Default (--rebuild): regenerate rq2_final.jsonl and the denylist table xlsx from data/.
    Axis attribution is read from data/RQ2_authoritative.xlsx (File_Attribution sheet); no trace needed.

Full reproduction (--full): compute axes from scratch using harness traces on the user's Mac.
    Requires: ~/rops/harness/traces, sota_denylist.json, rq2_results.jsonl.
    python3 build_rq2_final.py --harness ~/rops/harness --res data/rq2_results.jsonl \
        --deny data/sota_denylist.json --ledger data/MASTER_INDEX.csv --out rq2_final.jsonl
    (Harness mode stores the full set of denylisted items per file, enabling corpus re-attribution.)
Usage:
    python3 run_rq2.py            # rebuild from data/
    python3 run_rq2.py --full     # print full-reproduction command
"""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')
EVAL = os.path.dirname(HERE)   # evaluation/


def sh(cmd):
    print('  $', ' '.join(cmd)); subprocess.check_call(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--remeasure', action='store_true',
                    help='re-run RoPS over the dataset to regenerate its judgments first')
    ap.add_argument('--dataset', default='/data', help='restored dataset root (with --remeasure)')
    a = ap.parse_args()
    res = os.path.join(DATA, 'rq2_results.jsonl')
    ledger = os.path.join(HERE, '..', '..', 'data', 'master_ledger.csv')
    deny = os.path.join(DATA, 'sota_denylist.json')
    attrib = os.path.join(DATA, 'RQ2_authoritative.xlsx')
    final = os.path.join(HERE, 'rq2_final.jsonl')
    xlsx = os.path.join(HERE, 'RQ2_denylist.xlsx')

    if a.remeasure:
        rm = os.path.join(DATA, 'rops_remeasured.jsonl')
        res_rm = os.path.join(DATA, 'rq2_results_remeasured.jsonl')
        print('[0/2] re-running RoPS over the dataset (judgments)')
        sh([sys.executable, os.path.join(EVAL, 'rops_remeasure.py'),
            '--dataset', a.dataset, '--ledger', ledger, '--rq', '2', '--out', rm])
        sh([sys.executable, os.path.join(EVAL, 'remeasure_overlay.py'),
            'rq2', '--remeasure', rm, '--in', res, '--out', res_rm])
        res = res_rm

    if a.full:
        print('Full reproduction (user Mac, harness traces required):')
        print(f'  python3 {os.path.join(HERE,"build_rq2_final.py")} --harness ~/rops/harness \\')
        print(f'      --res {res} --deny {deny} --ledger {ledger} --out {final}')
        print(f'  python3 {os.path.join(HERE,"rq2_table.py")} --final {final} --out {xlsx}')
        return 0

    print('[1/2] Generating rq2_final.jsonl (file-attribution reproduction)')
    sh([sys.executable, os.path.join(HERE, 'build_rq2_final.py'),
        '--res', res, '--ledger', ledger, '--deny', deny, '--attrib', attrib, '--out', final])
    print('[2/2] Generating denylist table xlsx')
    sh([sys.executable, os.path.join(HERE, 'rq2_table.py'), '--final', final, '--out', xlsx])
    print('Done:', final, '|', xlsx)
    return 0


if __name__ == '__main__':
    sys.exit(main())
