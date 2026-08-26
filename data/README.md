# RoPS Evaluation Dataset

663 model-serialization samples used to evaluate RoPS, drawn from crafted corpora, prior-study corpora, and real Hugging Face artifacts. This directory holds the ledger and the verification/restore scripts; the model files are hosted externally (see `DATASET.md`).

## Composition (663 samples)

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

Per-RQ totals: **RQ1 = 252, RQ2 = 467, RQ3 = 304**. The evaluation uses 509 samples (304 real-world + 205 crafted); the 154 development-only Public-PoC samples are shipped for completeness but excluded from every RQ.

`origin` records the sample's *provenance* (which generation campaign or source it came from), which is independent of `label`. In particular the three `Craft Malicious` control samples are `label=F`: they are benign negative controls produced inside the malicious-crafting campaign.

## Ledger columns (`master_ledger.csv`)

| column | meaning |
|---|---|
| `sample_id` | unique identifier and file stem (e.g. `2-2-B-00001`) |
| `origin` | provenance group (one of the nine above) |
| `path` | location within the release, `data/<origin-slug>/<sample_id>.<ext>` |
| `sha256` | SHA-256 of the file |
| `size_bytes` | file size in bytes |
| `format` | file extension / container type (`pkl`, `pt`, `bin`, `zip`, …) |
| `label` | ground truth: `T` malicious, `F` benign, `na` not applicable (loading-path reachability samples) |
| `serializer` | serialization library (`pickle`, `joblib`, `dill`, `cloudpickle`, `numpy_allow_pickle`) |
| `container_chain` | outer-container decode chain, when the pickle is nested inside an archive |
| `Inner_pickle_path` | path to the pickle stream inside the container, when applicable |
| `repo_id` | source Hugging Face repo, for artifacts collected from the Hub |
| `used_in_RQ` | research questions the sample appears in, `;`-separated (`1;2;3`); empty for development-only samples |

Label distribution: `T` 348 · `F` 273 · `na` 42. Formats: `pkl` 309 · `bin` 139 ·
`pt` 131 · `pth` 18 · `zip` 15 · `gz` 11 · others 40.

## Scripts

- `verify_dataset.py` — verify a restored dataset against the ledger (SHA-256 / size). See `DATASET.md`.
- `build_public_dataset.py` — author-side tool that materializes the release from an internal source tree, renaming each file to `<sample_id>.<ext>` and verifying the copy. Most users do not need it.
