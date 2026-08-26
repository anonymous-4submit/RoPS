# RQ2 — Gadget Discrimination

**Claim.** Functions that retrieve attributes by string name (e.g.
`builtins.getattr`) have both benign uses (model restoration) and malicious uses
(indirection gadgets). A denylist therefore either flags benign models or misses
attacks that use an omitted function. RoPS moves the basis of judgment onto the
reconstructed **argument**, detecting attacks composed only of benign-listed
functions without flagging benign uses of the same functions. → **Paper Tables
3–4.**

## Reproduce

**Tier 0 — table from frozen results (seconds):**

```bash
python3 rq2_table.py --final rq2_final.jsonl --out RQ2_denylist.xlsx
# or: docker compose run --rm rq2-table
```

**Tier 1 — re-run RoPS over the dataset (minutes; needs the dataset mounted):**

```bash
docker compose run --rm rq2
```

**Expected result.** Of the 467-file corpus, 294 files use at least one denylisted
global (149 benign + 145 malicious) and are reviewed. Each file is attributed to a
single denylisted item (rarest item first), so table rows sum to file totals.

**Table A — denylisted globals that benign models actually use** (Table 3):

| Denylisted item | Benign | Malicious | FP (Review) | FP (Unsafe) | TP (Review) | TP (Unsafe) |
|---|--:|--:|--|--|--|--|
| `builtins.getattr` | 131 | 10 | 3/131 | 0/131 | 10/10 | 10/10 |
| `socket.*` | 15 | 0 | 0/15 | 0/15 | — | — |
| `functools.partial` | 2 | 0 | 0/2 | 0/2 | — | — |
| `subprocess.*` | 1 | 4 | 0/1 | 0/1 | 4/4 | 4/4 |
| **Total** | **149** | **14** | **5/149** | **0/149** | **14/14** | **14/14** |

RoPS produces **0 unsafe false positives** across 149 benign files (5 at review
level only) and judges all 14 malicious files unsafe. The `socket.*` benign cases
(15, crafted 2-C) are globals referenced by name but never invoked, which appear
only in the harness trace's globals — a core false-positive case for name-based
tools.

**Table B — malicious-only denylisted globals (zero benign use)** (Table 4): 21
items over 131 malicious files; TP review 130/131, TP unsafe 129/131. One file is
not reported at review level and one remains at review rather than unsafe — the
two cases that lack a discriminating literal (the case study in the paper).

**FP/TP definitions.** FP (Review) = benign ∧ warned (H1); FP (Unsafe) = benign ∧
`n_unsafe ≥ 1`; TP (Review) = malicious ∧ warned; TP (Unsafe) = malicious ∧
`n_unsafe ≥ 1`.

## Corpus (467)

`in_main`: `status=ok`, `scope=in`, excluding 3-E (dev gadget catalog) and 1-C
(loading probes), including all crafted 2-C. This matches the seven checked rows
of the corpus table (the table's printed total of 467 reflects an hf-benign
row displayed as 205 vs. the 204 used in that count; the RQ2 population is 467
files with 294 touching a denylisted global).

## Files

| File | Description |
|---|---|
| `rq2_final.jsonl` | integrated results, one record per file — re-aggregates the tables under any corpus re-slice |
| `RQ2_denylist.xlsx` | Table A (main) / Table B (full) / File attribution |
| `build_rq2_final.py` | `rq2_results` + denylist-axis attribution → `rq2_final.jsonl` |
| `rq2_table.py` | `rq2_final.jsonl` → `RQ2_denylist.xlsx` |
| `run_rq2.py` | driver (rebuild then table) |
| `data/rq2_results.jsonl` | RoPS judgments (raw) |
| `data/sota_denylist.json` | public denylist (picklescan ∪ modelscan) |
