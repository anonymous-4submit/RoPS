# Reproduction guide

This guide covers the two supported reproduction tiers and the optional full re-measurement. All commands run from the repository root unless noted.

## 0. Prerequisites

- Docker and Docker Compose.
- Build the image once:

  ```bash
  docker compose build rops
  ```

Without Docker, the Tier 0 steps also run directly with Python 3.11 and
`pip install openpyxl`.

## Tier 0 — result tables from frozen records (seconds, no dataset)

Each `evaluation/RQ*/‌*_final.jsonl` is the single source of truth: one record per file, carrying everything needed to re-aggregate the tables. Regenerate the spreadsheets:

```bash
docker compose run --rm rq1-table   # → evaluation/RQ1/RQ1_results.xlsx   (Table 2)
docker compose run --rm rq2-table   # → evaluation/RQ2/RQ2_denylist.xlsx  (Tables 3–4)
docker compose run --rm rq3-table   # → evaluation/RQ3/RQ3_results.xlsx   (Table 5)
```

Check the regenerated numbers against the paper:

- **RQ1 (Table 2):** RoPS file/stream reachability 1.000 / 1.000; picklescan 0.943 / 0.724; modelscan 0.915 / 0.652 (252 files, 359 streams).
- **RQ2 (Tables 3–4):** Table A totals — 149 benign, 14 malicious; 0 unsafe false positives on benign; `builtins.getattr` 131 / 10, `socket.*` 15 / 0, `functools.partial` 2 / 0, `subprocess.*` 1 / 4.
- **RQ3 (Table 5):** RoPS recall 0.949, FPR 0.031, F1 0.932 (TP 75, FN 4, FP 7, TN 218) on 304 real-world files.

## Tier 1 — re-run RoPS over the dataset (minutes)

1. Restore and verify the dataset (see `data/DATASET.md`), then set `ROPS_DATASET`:

   ```bash
   cp .env.example .env        # edit ROPS_DATASET=/path/to/rops_dataset
   docker compose run --rm verify-dataset      # expect: errors : 0
   ```

2. Re-run RoPS and rebuild each RQ:

   ```bash
   docker compose run --rm rq1
   docker compose run --rm rq2
   docker compose run --rm rq3
   ```

Each `run_rqN.py --remeasure --dataset /data` runs `evaluation/rops_remeasure.py`, which re-executes the RoPS pipeline (`RoPS/src/pipeline.py`) over every model file in the RQ corpus (resolved from `data/master_ledger.csv`) and records RoPS's own measurements: the carved-blob SHA-256s and terminal classes (reachability, RQ1) and the per-file three-valued verdict counts (RQ2, RQ3). `remeasure_overlay.py` then overlays these onto the frozen baseline verdicts and RQ1 loading oracle in `evaluation/RQ*/data/`, and the RQ builder + table regenerate the results. The RoPS numbers should match Tier 0.

RoPS is static and never loads a model, so re-running it over the malicious artifacts executes no payload.

### Rebuild without re-running RoPS (no dataset)

To re-aggregate from the frozen RoPS outputs — verifying the aggregation without the dataset — omit `--remeasure` (the `rq*-rebuild` services):

```bash
docker compose run --rm rq1-rebuild
docker compose run --rm rq2-rebuild
docker compose run --rm rq3-rebuild
```

## Optional — full baseline / oracle re-measurement (advanced)

The reproduction above reuses two kinds of frozen inputs so that a plain checkout regenerates every published number: the **baseline verdicts** (picklescan 1.0.4, modelscan 0.8.6, fickling 0.1.12, PyTorch weights-only 2.8.0) and the **RQ1 loading-harness oracle**. To regenerate these from scratch:

- **Baselines.** Install each tool at the pinned version and run it over the dataset, writing per-file verdicts in the schema used by `evaluation/RQ*/data/`. Because these tools load or deeply parse artifacts, run them in a disposable container or VM.
- **RQ1 oracle.** `data/trace_252.jsonl` records the byte regions consumed during normal model loading. Regenerating it **executes model loads**, including malicious ones. Do this only inside an isolated VM with no network and no host mounts. Then re-run Tier 1.

These steps are outside the containerized flow because they require model-loading environments and payload isolation that the static RoPS image deliberately omits.

## Troubleshooting

- `ROPS_DATASET` unset: the Tier 1 and verify services fail fast with a message; Tier 0 services do not need it.
- yara compile errors: rebuild the image (`docker compose build --no-cache rops`).
- Table numbers differ: confirm you are reading the regenerated `evaluation/RQ*/*.xlsx`, not a stale copy, and that `*_final.jsonl` is the
  shipped one.
