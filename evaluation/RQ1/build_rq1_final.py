#!/usr/bin/env python3
"""Build the RQ1 final integrated jsonl — self-contained.

Inputs
    --trace   trace_252.jsonl   (harness oracle + picklescan/modelscan reachability)
    --rfp     rfp.jsonl         (RoPS RFP re-extraction: terminal class + RoPS reachability)
    --ledger  master_ledger.csv (public corpus ledger)
Output
    --out     rq1_final.jsonl

One record = one file. Holds all raw data needed so the table can be
re-aggregated from this file alone, no matter how the corpus is re-sliced.

RQ1 corpus (redesigned 252) = the ledger rows whose used_in_RQ includes 1:
    loading-path probe (Craft Loading Path) + repo-collected benign
    (Public Artifact Benign) + repo-collected malicious (Public Artifact Malicious).
    Prior-study (pickleball) benign is excluded.

Path-chain class (mutually exclusive): reduce each stream chain to Container/Streaming hops.
    raw -> no hop (terminal only), zip/tar/npz -> Container, gz/zlib/bz2/xz/lz4/npy/zstd -> Streaming
Terminal (rfp): Serialization / Opaque(PGW). If there is no hop, label = terminal name.
"""
import argparse, json, os, csv

CONT = {'zip', 'tar', 'npz'}
STRM = {'gz', 'gzip', 'zlib', 'bz2', 'xz', 'lzma', 'lz4', 'npy', 'zstd'}


def viaseq(chain):
    out = []
    for t in (chain or '').split('>'):
        if t in CONT:
            out.append('Container')
        elif t in STRM:
            out.append('Streaming')
    return out


def load(p):
    if not p or not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]


def tier_of(sid):
    """Derive the tier code from the sample_id, e.g. '2-2-B-00001' -> '2-B'."""
    p = sid.split('-')
    return '%s-%s' % (p[1], p[2]) if len(p) >= 3 else ''


def used_in_rq(row, q):
    return str(q) in (row.get('used_in_RQ') or '').split(';')


def in_rq1(row):
    return used_in_rq(row, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--trace', required=True)
    ap.add_argument('--rfp', required=True)
    ap.add_argument('--ledger', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    led = {r['sample_id']: r for r in csv.DictReader(open(a.ledger, encoding='utf-8'))}
    # Evaluation population = files actually executed in trace_252 that qualify for RQ1.
    # (Slicing by ledger alone would pull in unevaluated duplicate/unsampled records.)
    tr = {r['sample_id']: r for r in load(a.trace)
          if r['sample_id'] in led and in_rq1(led[r['sample_id']])}
    corpus = set(tr)
    rf = {r['sample_id']: r for r in load(a.rfp) if r['sample_id'] in corpus}

    # rfp stream terminal: (sample_id, sha) -> final_cls / kind / found
    def rfp_streams(sid):
        r = rf.get(sid)
        return {s['sha']: s for s in (r.get('streams') or [])} if r else {}

    out = open(a.out, 'w', encoding='utf-8')
    n = 0
    for sid in sorted(corpus):
        L = led[sid]
        T = tr.get(sid)
        Rf = rf.get(sid)
        oracle = (T.get('oracle') or []) if T else []
        rfmap = rfp_streams(sid)

        # per-stream integration
        streams = []
        seqs = set()
        term_opaque = False
        term_seen = False
        for s in oracle:
            vs = viaseq(s['chain'])
            seqs.add(tuple(vs))
            rs = rfmap.get(s['sha'])
            fc = (rs.get('final_cls') if rs else None)
            if fc:
                term_seen = True
                if fc.lower() == 'opaque':
                    term_opaque = True
            streams.append({
                'sha': s['sha'],
                'chain': s['chain'],
                'offset': s.get('offset'),
                'via': vs,                       # ['Container', ...] order preserved
                'depth': len([t for t in (s['chain'] or '').split('>') if t]),
                'final_cls': fc,                 # Serialization / Opaque / None
                'rops_found_sha': bool(rs and rs.get('found')),
            })

        n_oracle = len(oracle)
        # path-chain label (mutually exclusive)
        if n_oracle == 0:
            chain_label = 'No stream'
        elif len(seqs) > 1:
            chain_label = 'Mixed'
        else:
            seq = list(next(iter(seqs)))
            if not seq:
                chain_label = 'Opaque (PGW)' if term_opaque else 'Serialization'
            else:
                chain_label = '→'.join(seq) + ('→opaque' if term_opaque else '')

        # RoPS reachability (from rfp)
        if Rf is None:
            rops_measured = False
            rops_reached = None          # not measured (A5 probe, etc.)
            rops_stream_cover = None
            n_rops = None
        else:
            rops_measured = True
            n_rops = Rf.get('n_rops', 0)
            need = n_oracle                       # from trace (fresh)
            # RoPS stream cover: count-complete if extracted blob count >= oracle stream count
            rops_stream_cover = 1.0 if (need == 0 or n_rops >= need) else round(n_rops / need, 4)
            rops_reached = bool(n_rops >= 1) if need > 0 else (n_rops >= 1)

        # picklescan / modelscan reachability (from trace, against oracle sha)
        ps_hit = set(T.get('ps_hit') or []) if T else set()
        ms_hit = set(T.get('ms_hit') or []) if T else set()
        osha = [s['sha'] for s in oracle]
        ps_reached = sum(1 for h in osha if h in ps_hit)
        ms_reached = sum(1 for h in osha if h in ms_hit)

        tier = tier_of(sid)
        rec = {
            'sample_id': sid,
            'tier': tier,
            'origin': L.get('origin', ''),
            'label': L.get('label', ''),
            'format': L.get('format', ''),
            'size': int(L.get('size_bytes') or 0),
            'path': L.get('path', ''),
            'rq1_role': ('probe' if tier == '1-C'
                         else 'benign' if L.get('label') in ('F', 'na') and tier in ('2-A', '2-B')
                         else 'malicious' if tier == '3-D' else L.get('label', '')),
            'chain_label': chain_label,          # table row = this value
            'n_oracle': n_oracle,                 # number of pickle streams found by the harness
            'term_opaque': term_opaque,           # does the terminal include Opaque(PGW)?
            'streams': streams,                   # per-stream raw data
            # reachability raw data (for numerator/denominator re-aggregation)
            'rops_measured': rops_measured,
            'n_rops': n_rops,
            'rops_reached': rops_reached,         # file-level reachability (>=1 blob)
            'rops_stream_cover': rops_stream_cover,
            'ps_reached': ps_reached,             # picklescan-reached count among oracle sha
            'ms_reached': ms_reached,             # modelscan-reached count among oracle sha
            'ps_err': (T.get('ps_err') if T else '') or '',
            'ms_err': (T.get('ms_err') if T else '') or '',
        }
        out.write(json.dumps(rec, ensure_ascii=False) + '\n')
        n += 1
    out.close()

    # summary
    import collections
    recs = load(a.out)
    C = collections.Counter(r['chain_label'] for r in recs)
    print(f'rq1_final.jsonl: {n} records  -> {a.out}')
    print('Path-chain class:', dict(C), '| Total', sum(C.values()))
    print('rops not measured:', [r['sample_id'] for r in recs if not r['rops_measured']])
    print('files containing Opaque(PGW):', sum(1 for r in recs if r['term_opaque']))


if __name__ == '__main__':
    main()
