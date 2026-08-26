# RoPS — ROtten-Pickle Slicer

Reproduction artifact for *"Beyond Dangerous Names: Uncovering Hidden Execution
in AI Model Artifacts with ROtten-Pickle Slicer."*

Pickle-based model artifacts can execute arbitrary code because a pickle is an opcode program for the unpickling machine, not passive data. Malicious artifacts can stay specification-compliant while hiding intent in invocation *arguments*, which name-based scanners (denylists) miss. **RoPS** recursively carves pickle streams from layered artifacts, reconstructs call sites by simulating the unpickling machine, interprets each literal by its argument role, and assigns a three-valued judgment.

This repository contains the RoPS source, the evaluation dataset ledger, and the per-research-question reproduction packages.

## The tool in one picture

RoPS is a **static** analyzer with a single per-file entry point (`RoPS/src/pipeline.py`) and three phases:

| Phase | Package | What it does |
|---|---|---|
| **1. Pickle Carving** | `extractor/` | Recursive Format Peeling (RFP) recurses over container/streaming/serialization layers; the Pickle Grammar Walker (PGW) recovers pickle blobs from opaque residues without header magic. |
| **2. Call Site Slicing** | `detector/` | Simulates the unpickling machine (no execution) to reconstruct each call site as a triple `(callable c, argument tuple a, invocation point i)`. |
| **3. Behavior Classification** | `classifier/` | Recovers each literal's type and argument role (Value / Name / Code), selects the applicable indicator vocabulary, and emits a three-valued judgment: **Unsafe**, **Review**, or **Low**. |

RoPS **does not load or execute** models; it inspects bytes and simulates opcode
stack state. Analyzing malicious artifacts with RoPS therefore does not run their
payloads (see [Safety](#safety)).

## Research questions and claims

Each research question maps to a table in the paper. Numbers below are the paper's evaluation-section results, which the reproduction regenerates.

| RQ | Claim | Paper | Headline result |
|---|---|---|---|
| **RQ1 — Stream Reachability** | RoPS reaches every loader-consumed pickle stream regardless of nesting/compression; SOTA scanners degrade with depth. | Table 2 | RoPS file/stream reachability **1.000 / 1.000** vs picklescan 0.943 / 0.724, modelscan 0.915 / 0.652 (252 files, 359 streams). |
| **RQ2 — Gadget Discrimination** | RoPS detects attacks built only from benign-listed functions without flagging benign uses of the same functions. | Tables 3–4 | Across 149 benign files using denylisted globals, **0** unsafe false positives; all malicious uses judged malicious. |
| **RQ3 — Baseline Comparison** | Under one corpus and ground truth, RoPS reduces benign-input burden while keeping detection. | Table 5 | On 304 real-world files: **F1 0.932, recall 0.949, FPR 0.031**, best overall vs picklescan / modelscan / fickling / weights-only. |

## Repository layout

```
.
├─ README.md                 ← you are here
├─ RoPS/src/                 ← the tool (extractor / detector / classifier / pipeline.py)
├─ data/                     ← dataset ledger + restore script (models hosted externally)
│  ├─ master_ledger.csv         663-sample ledger (single source of truth)
│  ├─ build_public_dataset.py   restore data/<origin>/<sample_id>.<ext> from a source tree
│  └─ DATASET.md                download, verify (SHA-256), and mount the dataset
├─ evaluation/               ← per-RQ reproduction packages
│  ├─ README.md
│  ├─ rops_remeasure.py         re-execute RoPS over the dataset → per-file measurements
│  ├─ remeasure_overlay.py      overlay re-measured RoPS fields onto the frozen raw inputs
│  ├─ RQ1/  RQ2/  RQ3/          each: README, run_*.py, build_*_final.py, *_table.py,
│  │                                  *_final.jsonl (frozen results), data/ (raw inputs)
├─ docker/                   ← Dockerfile.rops + entrypoint
├─ docker-compose.yml        ← reproduction services
├─ .env.example              ← ROPS_DATASET path variable
└─ docs/REPRODUCE.md         ← full reproduction guide
```

## Quick start

Two reproduction tiers. **Tier 0** needs nothing but this repository and Docker; **Tier 1** additionally needs the dataset (see `data/DATASET.md`).

```bash
# build the single RoPS image
docker compose build rops

# Tier 0 — regenerate result tables from the frozen result records (seconds)
docker compose run --rm rq1-table     # → evaluation/RQ1/RQ1_results.xlsx
docker compose run --rm rq2-table     # → evaluation/RQ2/RQ2_denylist.xlsx
docker compose run --rm rq3-table     # → evaluation/RQ3/RQ3_results.xlsx

# Tier 1 — re-run RoPS over the dataset, then rebuild results (needs the dataset)
cp .env.example .env                  # set ROPS_DATASET=/path/to/restored/dataset
docker compose run --rm rq1
docker compose run --rm rq2
docker compose run --rm rq3
```

Tier 1 re-executes RoPS (`RoPS/src/pipeline.py`) over the mounted dataset to regenerate its own measurements, overlays them on the frozen baseline verdicts and RQ1 loading oracle, and rebuilds `*_final.jsonl` and the table. RoPS is static and never loads a model, so this executes no payload. The corpus and all metadata come from `data/master_ledger.csv`. Baseline tools (picklescan, modelscan, fickling, weights-only) are **not** re-run — their verdicts are shipped inside `evaluation/RQ*/data/`; full baseline re-measurement is described in `docs/REPRODUCE.md`. To rebuild from the frozen RoPS outputs without the dataset, use the `rq*-rebuild` services.

## Dataset

The evaluation uses 509 artifacts (304 real-world + 205 crafted). The public release additionally ships 154 development-only Public-PoC artifacts, for **663** total; these dev artifacts are excluded from every RQ (`used_in_RQ` empty). The model files are hosted externally and restored from `data/master_ledger.csv`; see `data/DATASET.md`.

## Safety

RoPS is static and never loads models, so scanning the malicious artifacts with RoPS does not execute their payloads. The **only** step that executes a model is regenerating the RQ1 ground-truth oracle (a loading harness); that oracle is shipped frozen (`evaluation/RQ1/data/trace_252.jsonl`) and is **not** part of the containerized reproduction. If you choose to regenerate it (see `docs/REPRODUCE.md`), do so only inside an isolated VM. Malicious archives in the dataset are marked as such; do not load them with ordinary loaders.

## Requirements

- Docker and Docker Compose.
- RoPS dependencies (baked into the image): `yara-python`, `pyyaml`, `numpy`,
  `lz4` (see `RoPS/src/requirements.txt`); `openpyxl` for table generation.
- RoPS is pure static analysis — no PyTorch or ML libraries are needed to run it.

## Citation

See the paper. A `CITATION.cff` / BibTeX entry will accompany the camera-ready release.
