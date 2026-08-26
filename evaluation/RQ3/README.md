# RQ3 — Baseline Comparison

**Claim.** Under one corpus and one ground-truth criterion, how far do RoPS and
existing defense tools reduce the burden imposed by benign inputs while
maintaining detection? RoPS achieves the best overall balance. → **Paper Table
5.**

## Reproduce

**Tier 0 — table from frozen results (seconds):**

```bash
python3 rq3_table.py --final rq3_final.jsonl --out RQ3_results.xlsx
# or: docker compose run --rm rq3-table
```

**Tier 1 — re-run RoPS over the dataset (minutes; needs the dataset mounted):**

```bash
docker compose run --rm rq3
```

**Expected result** (Table 5, main table — 304 real-world files: 79 malicious,
225 benign):

| Tool | T | F | TP | FN | FP | TN | Recall | FNR | FPR | Prec. | F1 | Acc. | Inc. |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| **RoPS** (warn-or-above) | 82 | 222 | 75 | 4 | 7 | 218 | **0.949** | 0.051 | **0.031** | 0.915 | **0.932** | 0.964 | 0 |
| picklescan 1.0.4 | 197 | 105 | 73 | 6 | 124 | 99 | 0.924 | 0.076 | 0.556 | 0.371 | 0.529 | 0.570 | 2 |
| modelscan 0.8.6 | 194 | 108 | 70 | 9 | 124 | 99 | 0.886 | 0.114 | 0.556 | 0.361 | 0.513 | 0.560 | 2 |
| fickling 0.1.12 | 27 | 4 | 26 | 53 | 1 | 3 | 0.329 | 0.671 | 0.250 | 0.963 | 0.491 | 0.349 | 273 |
| fickling (blob) | 298 | 0 | 78 | 1 | 220 | 0 | 0.987 | 0.013 | 1.000 | 0.262 | 0.414 | 0.261 | 6 |
| weights-only 2.8.0 | 231 | 13 | 48 | 31 | 183 | 13 | 0.608 | 0.392 | 0.934 | 0.208 | 0.310 | 0.222 | 60 |

RoPS gives the best F1 (0.932) with the lowest FPR (0.031) and no inconclusive
results. In review-burden terms, RoPS requires review of **7 of 225** benign files
(3.1%), versus 126 (56.0%) each for picklescan and modelscan, 212 (94.2%) for
weights-only, and 222 (98.7%) for direct fickling.

## Tools and decision rules

Main table: **RoPS** (warn-or-above = unsafe + review) · **picklescan 1.0.4** ·
**modelscan 0.8.6** · **fickling** (severity ≥ SUSPICIOUS) · **weights-only**
(Unsupported-global block). Auxiliary rows use RoPS unsafe-only, fickling ≥
LIKELY_OVERTLY_MALICIOUS, and weights-only all-rejections.

`fickling` reads its input as a single pickle stream and does not handle
model-file containers, producing 273 inconclusive results; feeding it the pickle
blobs RoPS carves (**fickling (blob)**) reduces that to 6 and raises recall from
0.329 to 0.987 — but FPR rises to 1.000 (all benign flagged). RoPS's carving
improves reachability but does not, by itself, improve discrimination.

## Corpus

| Group | Composition | n |
|---|---|--:|
| Real-world (main table) | repository malicious 79 + benign 225 | **304** |
| Gadget variants (auxiliary table 1) | crafted gadget variants (all malicious) | **115** |
| **Combined (auxiliary table 2)** | | **419** |

The 304 real-world files are the main comparison target. The development-only
gadget catalog (picklecloak, 154) is excluded. Auxiliary gadget recall for RoPS
is 1.000.

## Files

| File | Description |
|---|---|
| `rq3_final.jsonl` | integrated results (419), one record per file |
| `RQ3_results.xlsx` | main table + auxiliary tables + fickling(blob) sheet + metric-definition sheet |
| `build_rq3_final.py` | `rq3_redesign` + baseline verdicts → `rq3_final.jsonl` |
| `rq3_table.py` | `rq3_final.jsonl` → `RQ3_results.xlsx` |
| `run_rq3.py` | driver (rebuild then table) |
| `data/rq3_redesign.jsonl` | integrated per-file RoPS + baseline verdicts (raw) |

## Metrics

Rows = tool, columns = Judged T · Judged F · Inc · TP · FN · FP · TN · Recall ·
FNR · FPR · Precision · F1 · Accuracy. Each block has a ground-truth (GT) row
(total T/F), and Judged T + Judged F + Inc = GT T + F as a checksum. A malicious
inconclusive counts as FN; a benign inconclusive is excluded from the denominator
(neither FP nor TN). RoPS produced no inconclusive results, so this convention
affects the baseline scores rather than RoPS. The `[Metric definitions]` sheet
records each tool's decision rule, the confusion-matrix definitions, and the six
metric formulas.
