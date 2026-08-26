# Evaluation

RoPS is evaluated on three research questions. Each has a self-contained reproduction package under `RQ1/`, `RQ2/`, `RQ3/`.

| RQ | Name | Corpus | Paper table | Headline |
|---|---|---|---|---|
| RQ1 | Stream Reachability | 252 files / 359 streams | Table 2 | RoPS reaches 1.000 / 1.000 (file / stream); picklescan 0.943 / 0.724, modelscan 0.915 / 0.652 |
| RQ2 | Gadget Discrimination | 467 files | Tables 3–4 | 0 unsafe false positives across 149 benign files using denylisted globals; all malicious uses judged malicious |
| RQ3 | Baseline Comparison | 304 real-world files | Table 5 | RoPS F1 0.932, recall 0.949, FPR 0.031 — best overall vs 4 SOTA tools |

## Dataset scope

The paper assembles 846 artifacts; after deduplication and excluding development-only artifacts, **509** remain (304 real-world from prior studies and repositories + 205 crafted). The RQ subsets are chosen by purpose and overlap:

- **RQ1 (252)** = 210 repository artifacts + 42 crafted loading-path probes.
- **RQ2 (467)** = 304 real-world + 163 crafted callable and gadget variants.
- **RQ3 (304)** = the 304 real-world artifacts only.

The public dataset additionally ships 154 development-only Public-PoC artifacts (the public gadget catalog), for 663 total; those are excluded from every RQ. Provenance (`origin`) and per-RQ membership (`used_in_RQ`) are recorded in `../data/master_ledger.csv`.

## Reproduction tiers

Every RQ package supports two tiers. Each `*_final.jsonl` is the single source of truth: one record per file, carrying everything needed to re-aggregate the tables under any corpus re-slicing.

**Tier 0 — tables from frozen results (seconds).** Regenerate the result spreadsheet directly from the shipped `*_final.jsonl`. Needs only Python + `openpyxl`.

```bash
python3 RQ1/rq1_table.py --final RQ1/rq1_final.jsonl --out RQ1/RQ1_results.xlsx
python3 RQ2/rq2_table.py --final RQ2/rq2_final.jsonl --out RQ2/RQ2_denylist.xlsx
python3 RQ3/rq3_table.py --final RQ3/rq3_final.jsonl --out RQ3/RQ3_results.xlsx
```

**Tier 1 — re-run RoPS over the dataset (minutes).** `run_rqN.py --remeasure
--dataset /data` re-executes the RoPS pipeline (`../RoPS/src/pipeline.py`) over
each model file in the RQ corpus (resolved from `../data/master_ledger.csv`),
overlays RoPS's fresh measurements onto the frozen baseline verdicts and RQ1
loading oracle, then rebuilds `*_final.jsonl` and the table. RoPS is static and
never loads a model, so this executes no payload. `rops_remeasure.py` performs
the scan and `remeasure_overlay.py` the overlay. Without `--remeasure`,
`run_rqN.py` rebuilds from the frozen RoPS outputs (no dataset needed).

Baseline tools (picklescan, modelscan, fickling, weights-only) are not re-run in either tier; their verdicts are shipped inside the raw inputs. Full baseline re-measurement is documented in `../docs/REPRODUCE.md`.

## Package contents

Shared (in `evaluation/`):

| File | Role |
|---|---|
| `rops_remeasure.py` | re-execute RoPS over the dataset → per-file RoPS measurements |
| `remeasure_overlay.py` | overlay re-measured RoPS fields onto the frozen raw inputs |

Per RQ (in `RQ1/`, `RQ2/`, `RQ3/`):

| File | Role |
|---|---|
| `README.md` | claim → reproduce command → expected result → explanation |
| `*_final.jsonl` | frozen integrated results, one record per file (source of truth) |
| `run_*.py` | driver: `--remeasure` re-runs RoPS then rebuilds; plain rebuild otherwise |
| `build_*_final.py` | raw inputs + `../../data/master_ledger.csv` → `*_final.jsonl` |
| `*_table.py` | `*_final.jsonl` → results spreadsheet |
| `data/` | raw inputs (baseline verdicts, RQ1 loading oracle, RoPS outputs) |
