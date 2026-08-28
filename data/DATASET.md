# Dataset

The 663 model-serialization samples are hosted externally (they are several GB and include malicious artifacts). This directory ships only the ledger and the verification/restore scripts; the model files are downloaded separately.

- `master_ledger.csv` — 663 rows, one per sample, the single source of truth.
- `verify_dataset.py` — check a restored dataset against the ledger (SHA-256).
- `build_public_dataset.py` — author-side tool used to lay out the release from
  the internal tree; most users do not need it.
- `README.md` — dataset composition and ledger column reference.

## Download

> [Download Link to Zenodo](https://doi.org/10.5281/zenodo.22144637)

The archive extracts into a directory that contains `data/<origin>/<sample_id>.<ext>`, matching the `path` column of the ledger. Benign and malicious samples are split into separate archives; the malicious archive is clearly marked.

```bash
mkdir -p ~/rops_dataset && cd ~/rops_dataset
# wget <benign archive URL>
# wget <malicious archive URL>
tar xzf rops_dataset_benign.tar.gz
tar xzf rops_dataset_malicious.tar.gz   # !!contains malicious pickle artifacts!!
```

## Verify

```bash
python3 verify_dataset.py --root ~/rops_dataset            # full SHA-256 check
python3 verify_dataset.py --root ~/rops_dataset --quick    # presence + size only
# or, from the repo root:
ROPS_DATASET=~/rops_dataset docker compose run --rm verify-dataset
```

A clean run prints `errors : 0`.

## Point the reproduction at it

Set the dataset root in `.env` at the repository root:

```bash
cp ../.env.example ../.env
# edit ../.env:  ROPS_DATASET=/home/you/rops_dataset
```

The Tier 1 services (`rq1`, `rq2`, `rq3`) mount it read-only at `/data`.

## Safety

RoPS is a static analyzer and never loads models, so scanning these files with RoPS does not execute any payload. The malicious archive nonetheless contains real attack artifacts — do **not** open them with ordinary loaders (`torch.load`, `pickle.load`, `joblib.load`, …). If you regenerate the RQ1 loading-harness oracle (which does load models), do so only in an isolated VM.

## Composition (663)

| origin | count | label | used in RQ |
|---|--:|---|---|
| Craft Benign | 45 | F | 2 |
| Craft Malicious | 3 | F | 2 |
| Craft Loading Path | 42 | na | 1 |
| Craft Public-PoC Variants | 115 | T | 2 |
| Public-PoC | 154 | T | — (development only) |
| Prior-study Malicious | 74 | T | 2, 3 |
| Prior-study Benign | 20 | F | 2, 3 |
| Public Artifact Malicious | 5 | T | 1, 2, 3 |
| Public Artifact Benign | 205 | F | 1, 2, 3 |

Per-RQ totals: RQ1 = 252, RQ2 = 467, RQ3 = 304. `origin` records provenance and is independent of `label`; see `README.md` for the full column reference.
