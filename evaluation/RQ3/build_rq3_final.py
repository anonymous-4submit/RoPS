#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RQ3 final combined jsonl builder — self-contained.

RQ3 = RoPS vs 4 SOTA tools (picklescan · modelscan · fickling · weights-only) detection performance.
Redesigned corpus 419 = Real-world 304 (malicious 79 + benign 225) + gadget variants 115 (all malicious).

Each tool's cell judgment (1=malicious detected / 0=benign / n/a=inconclusive) is finalized with the
**same rules** as rq3_xlsx.py and stored. If the corpus is re-adjusted, the confusion matrix can be
re-aggregated from this file alone.

Judgment rules (original pipeline)
  GT            eff_label: T=malicious, F=benign (1-C is F, though absent in the RQ3 corpus)
  RoPS(main)    rops_warn (warn-or-above = unsafe+review)
  RoPS(confirm) rops_confirm (unsafe)
  picklescan/modelscan  tools.verdict. But if **unreached** (status ok · or_globals>0 · saw 0) then n/a
  fickling(loose)  severity idx >= SUSPICIOUS,  fickling(strict) >= LIKELY_OVERTLY_MALICIOUS
  weights-only(main) wo.verdict (Unsupported global blocked=True),  (auxiliary) all rejections (incl. parse failure)
  inconclusive (n/a): if GT=malicious counted into FN, if GT=benign excluded from denominator (prevents free TN)
Usage: python3 build_rq3_final.py --res rq3_redesign.jsonl --out rq3_final.jsonl
"""
import argparse, json, os

FO = ['LIKELY_SAFE', 'POSSIBLY_UNSAFE', 'SUSPICIOUS', 'LIKELY_UNSAFE',
      'LIKELY_OVERTLY_MALICIOUS', 'OVERTLY_MALICIOUS']
STRICT, LOOSE = 'LIKELY_OVERTLY_MALICIOUS', 'SUSPICIOUS'
NA = 'n/a'
ASSIGN_BENIGN_TIERS = {'1-C'}


def cell(v):
    return NA if v is None else (1 if v else 0)


def eff_label(r):
    if r.get('label') in ('T', 'F'):
        return r['label']
    return 'F' if r.get('tier') in ASSIGN_BENIGN_TIERS else r.get('label', '')


def unreached(tool, d, rec):
    if (d or {}).get('status') != 'ok':
        return False
    if int(rec.get('or_globals') or 0) <= 0:
        return False
    if tool == 'ps':
        return int(d.get('globals') or 0) == 0
    if tool == 'ms':
        ts = d.get('total_scanned')
        return ts is not None and int(ts) == 0
    return False


def tool_cell(tool, rec):
    d = (rec.get('tools') or {}).get(tool) or {}
    if unreached(tool, d, rec):
        return NA
    return cell(d.get('verdict'))


def fk_verdict(d, thr):
    if (d or {}).get('status') != 'ok':
        return None
    return d.get('idx', -1) >= FO.index(thr)


def load_blob_verdicts(blobs_path, extra_path):
    """sid -> {'loose':1/0/None, 'strict':1/0/None, 'status':..} — fickling(blob) judgment.
    Result of running fickling on each blob RoPS carved (removes the file-input constraint).
    verdict_loose(severity>=SUSPICIOUS) / verdict_strict(>=LIKELY_OVERTLY_MAL) become the cell.
    """
    def cellv(v):
        return NA if v is None else (1 if v else 0)
    out = {}
    if blobs_path and os.path.exists(blobs_path):
        for l in open(blobs_path, encoding='utf-8'):
            if not l.strip():
                continue
            r = json.loads(l)
            out[r['sample_id']] = {'loose': cellv(r.get('verdict_loose')),
                                   'strict': cellv(r.get('verdict_strict')),
                                   'n_blobs': r.get('n_blobs', 0), 'status': r.get('status', '')}
    if extra_path and os.path.exists(extra_path):
        for r in json.load(open(extra_path, encoding='utf-8')):   # supplement of 12 new samples
            out[r['sample_id']] = {'loose': cellv(r.get('verdict_loose')),
                                   'strict': cellv(r.get('verdict_strict')),
                                   'n_blobs': r.get('n_blobs', 0), 'status': r.get('status', '')}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--res', required=True, help='rq3_redesign.jsonl (419, wo-12 combined)')
    ap.add_argument('--blobs', default='', help='rq3_fickling_blobs.jsonl (fickling x RoPS blob)')
    ap.add_argument('--blobs-extra', default='', help='new-file blob supplement json')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    R = [json.loads(l) for l in open(a.res, encoding='utf-8') if l.strip()]
    BV = load_blob_verdicts(a.blobs, getattr(a, 'blobs_extra', '') or a.__dict__.get('blobs_extra', ''))

    out = open(a.out, 'w', encoding='utf-8')
    n = 0
    for r in sorted(R, key=lambda x: x['sample_id']):
        t = r.get('tools') or {}
        wo = t.get('wo') or {}
        # all rejections (auxiliary): incl. parse failure — if status is not error/None, treat as refused
        ref = None if wo.get('status') in ('error', 'child_failed', None) else bool(wo.get('refused'))
        gt = eff_label(r)
        rec = {
            'sample_id': r['sample_id'],
            'tier': r['tier'],
            'label': gt,                      # GT: T/F (empty string = excluded from grading)
            'group': r.get('group', 'main'),  # Real-world / gadget variants
            'origin': r.get('origin', ''),
            'format': r.get('format', ''),
            'size': r.get('size', 0),
            'metric_role': r.get('metric_role', ''),
            # main-table cells (1/0/n\/a)
            'RoPS': cell(r.get('rops_warn')),
            'picklescan': tool_cell('ps', r),
            'modelscan': tool_cell('ms', r),
            'fickling_loose': cell(fk_verdict(t.get('fk'), LOOSE)),
            'weights_only': cell(wo.get('verdict')),
            # auxiliary (alternate cutoffs)
            'RoPS_confirm': cell(r.get('rops_confirm')),
            'fickling_strict': cell(fk_verdict(t.get('fk'), STRICT)),
            'weights_only_refuse_all': cell(ref),
            # fickling(blob): fickling on RoPS-carved blobs. If no data, na (unmeasured)
            'fickling_blob_loose': (BV.get(r['sample_id'], {}).get('loose', NA)),
            'fickling_blob_strict': (BV.get(r['sample_id'], {}).get('strict', NA)),
            'fickling_blob_status': (BV.get(r['sample_id'], {}).get('status', 'no_data')),
            'fickling_blob_n': (BV.get(r['sample_id'], {}).get('n_blobs', 0)),
            'has_blob_data': (r['sample_id'] in BV),
            # raw data (for reproduce / re-cut)
            'rops_warn': bool(r.get('rops_warn')),
            'rops_confirm': bool(r.get('rops_confirm')),
            'rops_low': r.get('rops_low', 0),
            'or_globals': r.get('or_globals', 0),
            'ps_status': (t.get('ps') or {}).get('status', ''),
            'ps_globals': (t.get('ps') or {}).get('globals', ''),
            'ms_status': (t.get('ms') or {}).get('status', ''),
            'ms_scanned': (t.get('ms') or {}).get('total_scanned', ''),
            'fk_status': (t.get('fk') or {}).get('status', ''),
            'fk_severity': (t.get('fk') or {}).get('severity', ''),
            'fk_idx': (t.get('fk') or {}).get('idx', ''),
            'wo_status': wo.get('status', ''),
            'wo_verdict': wo.get('verdict'),
            'wo_blocked': wo.get('blocked', ''),
        }
        out.write(json.dumps(rec, ensure_ascii=False) + '\n')
        n += 1
    out.close()

    import collections
    recs = [json.loads(l) for l in open(a.out, encoding='utf-8') if l.strip()]
    g = collections.Counter(r['group'] for r in recs)
    gt = collections.Counter(r['label'] for r in recs)
    print(f'rq3_final.jsonl: {n} records -> {a.out}')
    print('group:', dict(g), '| GT:', dict(gt))


if __name__ == '__main__':
    main()
