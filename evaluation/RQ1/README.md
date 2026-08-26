# RQ1 — Stream Reachability

**Claim.** For arbitrary model artifacts, does RoPS (and do existing tools) reach
every pickle stream the actual loader consumes — including streams behind
compression, multilayer containers, and concatenation? RoPS reaches all of them
regardless of nesting depth; picklescan and modelscan degrade as nesting deepens.
→ **Paper Table 2.**

## Reproduce

**Tier 0 — table from frozen results (seconds):**

```bash
python3 rq1_table.py --final rq1_final.jsonl --out RQ1_results.xlsx
# or: docker compose run --rm rq1-table
```

**Tier 1 — re-run RoPS over the dataset (minutes; needs the dataset mounted):**

```bash
docker compose run --rm rq1        # rebuilds rq1_final.jsonl, then the table
```

**Expected result** (Table 2, over the 247 files / 359 streams that contain a
loader-consumed stream; 5 files contain none and are excluded from the rates):

| Class | File | Stream | RoPS file/stream | picklescan file/stream | modelscan file/stream |
|---|--:|--:|--|--|--|
| Serialization | 20 | 20 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 |
| Opaque (PGW) | 10 | 37 | 1.000 / 1.000 | 0.900 / 0.973 | 0.200 / 0.270 |
| Container | 204 | 204 | 1.000 / 1.000 | 0.985 / 0.985 | 0.985 / 0.985 |
| Container→Streaming | 3 | 3 | 1.000 / 1.000 | 0.667 / 0.667 | 0.667 / 0.667 |
| Container→Container | 5 | 90 | 1.000 / 1.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| Streaming | 4 | 4 | 1.000 / 1.000 | 0.250 / 0.250 | 0.250 / 0.250 |
| Streaming→Streaming | 1 | 1 | 1.000 / 1.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| **Total** | **252** | **359** | **1.000 / 1.000** | **0.943 / 0.724** | **0.915 / 0.652** |

## Corpus (252)

| Group | tier / origin | n | Role |
|---|---|--:|---|
| Loading-path probes | 1-C (crafted) | 42 | carving-robustness probes |
| Public repository, benign | 2-B (hf_top benign) | 172 | benign baseline |
| Public repository, hard benign | 2-A / hf_hard_benign | 33 | obfuscated / borderline benign |
| Public repository, malicious | 3-D (hf_top malicious) | 5 | real-world malicious |
| **Total** | | **252** | |

Prior-study artifacts (pickleball) are excluded from RQ1: reachability is already
covered by the probes and the repository collection. Each file is assigned to
exactly one **path-chain class** (mutually exclusive), so the `File` column sums
to the corpus.

**Path-chain classes.** Each stream's `chain` is reduced to hops:
`zip/tar/npz` → Container, `gz/zlib/bz2/xz/lz4/npy/zstd` → Streaming, `raw` → no
hop. The terminal is split by RoPS's Recursive Format Peeling `final_cls` into
Serialization vs. Opaque (PGW).

## Reachability definitions

- **File-level** = the tool reached **all** oracle streams of that file
  (completeness).
- **Stream-level** = fraction of oracle streams reached (sum / sum).
- **RoPS** = stream cover from Recursive Format Peeling (opaque residues are
  preserved as PGW blobs); **ps/ms** = picklescan / modelscan reach over the same
  oracle stream SHAs. Files whose RoPS reachability was not measured (2 A5 probes,
  measured separately by running `extract_pickles` directly — both reached) are
  excluded from the RoPS denominator and footnoted.

## Files

| File | Description |
|---|---|
| `rq1_final.jsonl` | integrated results (252), one record per file — re-aggregates the table under any corpus re-slice |
| `RQ1_results.xlsx` | results table (by path-chain class) + analysis sheet |
| `build_rq1_final.py` | trace + rfp + ledger → `rq1_final.jsonl` |
| `rq1_table.py` | `rq1_final.jsonl` → `RQ1_results.xlsx` |
| `run_rq1.py` | driver (rebuild then table) |
| `data/trace_252.jsonl` | loading-harness oracle streams + picklescan/modelscan reach (raw) |
| `data/rfp.jsonl` | RoPS Recursive Format Peeling re-extraction: terminal class + RoPS reach (raw) |

### `rq1_final.jsonl` record schema

```
sample_id, tier, origin, label, format, size, path, rq1_role
chain_label        path-chain class (table row); mutually exclusive
n_oracle           number of loader-consumed pickle streams the harness found
term_opaque        whether the terminal includes Opaque (PGW)
streams[]          {sha, chain, offset, via[], depth, final_cls, rops_found_sha}
rops_measured      whether RoPS reach was measured (2 A5 probes: false)
n_rops             number of blobs RoPS extracted
rops_reached       file-level RoPS reach (>= 1 blob)
rops_stream_cover  RoPS stream cover (count basis; 1.0 when n_rops >= oracle)
ps_reached         oracle SHAs reached by picklescan
ms_reached         oracle SHAs reached by modelscan
```

To re-slice the corpus, filter `rq1_final.jsonl` on any condition (tier / origin /
label) and re-aggregate these fields; `rq1_table.py` performs that aggregation.
