#!/usr/bin/env python3
"""RQ1 re-run driver.

Default (--rebuild): re-generate rq1_final.jsonl and the results xlsx from the
    raw data in data/ (trace_252.jsonl, rfp.jsonl, MASTER_INDEX.csv). Runs
    instantly anywhere (a few seconds).

Full re-measurement (--full): rebuild trace and rfp from scratch on the user's
    Mac where the harness traces and RoPS sources exist. See the 'full reproduce'
    section of the README.
    (Under --full this script only prints the required commands and does not run
     them — path/environment dependencies are large, so it is safer for the user
     to review and run them directly.)

Usage:
    python3 run_rq1.py                 # rebuild from data/
    python3 run_rq1.py --full          # print full-reproduce commands
"""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


def sh(cmd):
    print('  $', ' '.join(cmd)); subprocess.check_call(cmd)


EVAL = os.path.dirname(HERE)   # evaluation/


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--remeasure', action='store_true',
                    help='re-run RoPS over the dataset to regenerate reachability first')
    ap.add_argument('--dataset', default='/data', help='restored dataset root (with --remeasure)')
    a = ap.parse_args()

    trace = os.path.join(DATA, 'trace_252.jsonl')
    rfp = os.path.join(DATA, 'rfp.jsonl')
    ledger = os.path.join(HERE, '..', '..', 'data', 'master_ledger.csv')
    final = os.path.join(HERE, 'rq1_final.jsonl')
    xlsx = os.path.join(HERE, 'RQ1_results.xlsx')

    if a.remeasure:
        rm = os.path.join(DATA, 'rops_remeasured.jsonl')
        rfp = os.path.join(DATA, 'rfp_remeasured.jsonl')
        print('[0/2] re-running RoPS over the dataset (reachability)')
        sh([sys.executable, os.path.join(EVAL, 'rops_remeasure.py'),
            '--dataset', a.dataset, '--ledger', ledger, '--rq', '1', '--out', rm])
        sh([sys.executable, os.path.join(EVAL, 'remeasure_overlay.py'),
            'rq1', '--remeasure', rm, '--out', rfp])

    if a.full:
        print('Full reproduce (user Mac, harness+RoPS required):')
        print('  # 1) harness oracle + picklescan/modelscan reachability')
        print('  python3 <scripts>/rq1_trace.py --tier 1-C,2-B,2-A,3-D --out data/trace_252.jsonl')
        print('  # 2) RoPS RFP re-extraction (terminal class + RoPS reachability)')
        print('  python3 <scripts>/rq1_rfp.py scan --tier 1-C,2-B,2-A,3-D --out <rfp_out> --restart')
        print('  #    -> copy <rfp_out>/rfp.jsonl to data/rfp.jsonl')
        print('  # 3) top-up the 2 unmeasured A5 probes (if needed):')
        print('  python3 <scripts>/rq1_rfp.py scan --tier 1-C --out <rfp_out>  # continue from done.txt')
        print('  then: python3 run_rq1.py')
        return 0

    print('[1/2] building rq1_final.jsonl')
    sh([sys.executable, os.path.join(HERE, 'build_rq1_final.py'),
        '--trace', trace, '--rfp', rfp, '--ledger', ledger, '--out', final])
    print('[2/2] building results xlsx')
    sh([sys.executable, os.path.join(HERE, 'rq1_table.py'), '--final', final, '--out', xlsx])
    print('done:', final, '|', xlsx)
    return 0


if __name__ == '__main__':
    sys.exit(main())
