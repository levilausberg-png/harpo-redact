# SOTA verification of Harpo hardening-3

The question: does the frozen hardening-3 build hold the top score on ProwlBench, OpenPII (ai4privacy) and
Nemotron-PII when each is measured by the exact public metric that ranks competing systems? This pass only
measures. Nothing in Harpo was changed, nothing was tuned, and no earlier result in `bench/external/results/` or
`docs/EXTERNAL_BENCHMARKS.md` was replaced. Checked 2026-10-20.

## Verdict

| Benchmark | Harpo metric | Harpo score | Best comparable public score | Delta | Rank | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ProwlBench 2.0, reproducible rows | ProwlBench F1 (`run_prowlbench.py`) | 0.941 | 0.883, Prowl shipped cascade | +0.058 | 1 of 7 | VERIFIED #1 reproducible |
| ProwlBench 2.0, all published rows | ProwlBench F1 | 0.941 | 0.962, Prowl 3-way (research-only) | -0.021 | 2 of 9 | NOT #1 overall |
| OpenPII / ai4privacy-en | PIIMB masking F2 | not measured | 0.978, OpenMed/privacy-filter-nemotron-v2 | n/a | n/a | CANNOT VERIFY |
| OpenPII / ai4privacy-multi | PIIMB masking F2 | not measured | 0.976, OpenMed/privacy-filter-nemotron-v2 | n/a | n/a | CANNOT VERIFY |
| PIIMB English Avg F2 | PIIMB Avg F2 (4 tasks) | not measured | 0.918, OpenMed/privacy-filter-multilingual-v2 | n/a | n/a | CANNOT VERIFY |
| PIIMB Multilingual Avg F2 | PIIMB Avg F2 (2 tasks) | not measured | 0.743, hivetrace/gliner-guard-omni | n/a | n/a | CANNOT VERIFY |
| Nemotron-PII (PIIMB nemotron-pii) | PIIMB masking F2 | not measured | 0.972, OpenMed/OpenMed-PII-SuperClinical-Small-44M-v1 | n/a | n/a | CANNOT VERIFY |

**Why OpenPII and Nemotron-PII could not be scored natively.** The benchmark that ranks models on both is PIIMB
(the PII Masking Benchmark): character-level, label-agnostic masking F2 on its own random samples (5,000 documents
per task, no published seed), run on its pre-split `sentences` subset. Its scorer (`src/piimb/metrics.py`) and the
samples (`data/test_sentences.jsonl`) exist only in the Hugging Face repository
`datasets/piimb/pii-masking-benchmark`, and this workspace cannot download from Hugging Face. The samples cannot be
rebuilt from the files at hand: PIIMB draws OpenPII from the 1M set, these files are the micro-100k set. With that
repository (and `piimb/pii-masking-benchmark-results` for the exact published numbers), `piimb_harpo.py official`
runs the native scoring as written.

**What the indication says (not the native score).** The same metric, re-implemented from PIIMB's published
definition (`piimb_harpo.py indicative`), on the local files: F2 0.682 on OpenPII micro-100k validation (10,000
documents; precision 0.792, recall 0.659) and 0.603 on the Nemotron-PII test file (100,000 documents; precision
0.810, recall 0.567). Other samples, whole documents instead of sentences, and OpenPII micro instead of OpenPII 1M,
so these numbers are not comparable with the leaderboard and are not Harpo's PIIMB scores. They do show where the
gap is, and it is wide: the per-task leaders score 0.97 to 0.98. PIIMB counts every gold entity whatever its label,
dates, ages, genders, job titles and URLs included, which Harpo's default policy keeps (dates) or does not look
for at all (most of the rest): on these files, 28% of OpenPII's gold values and 38% of Nemotron-PII's carry a label
outside Harpo's scope (`bench/external/scope.py`).

## Claims

- **A. "Harpo is #1 on ProwlBench among reproducible systems."** Defensible. F1 0.941 (precision 0.946, recall
  0.936, accuracy 0.921; holdout half 0.939) with ProwlBench's own `run_prowlbench.py` at commit `53d6fc1`, the
  upstream `HEAD` on the day; nearest competitor Prowl (shipped binary, cascade) at F1 0.883, from the same
  README table. Caveat: Harpo has not been submitted, and its row comes from an adapter that adds it to the runner
  (`prowl_native.py`); the control, gitleaks 8.30.1 through the same run, reproduces the published gitleaks row
  exactly, every per-tier, per-language and per-source value included.
- **B. "Harpo is #1 overall on ProwlBench."** Not defensible: the README's research-only Prowl 3-way row scores
  F1 0.962 (with a disclosed ~5% train/test leakage and models not in a clean checkout). Harpo is second of all
  published rows, ahead of the research-only Prowl cascade ∪ LR (0.905).
- **C. "Harpo is SOTA on OpenPII / ai4privacy under PIIMB masking F2."** Not verified (no native run).
- **D. "Harpo is SOTA on Nemotron-PII under PIIMB masking F2."** Not verified (no native run).
- **E. "Harpo currently holds three external benchmark SOTAs."** Not defensible: OpenPII and Nemotron-PII block it.

## Files

| File | What it is |
| --- | --- |
| `environment/provenance.json` | the build (package sha256, wheel and release archive digests), Python, every dependency, models, configuration, dataset and scorer hashes |
| `prowl_native.py` | adds Harpo to ProwlBench's own runner, unchanged, and runs gitleaks as the control |
| `prowl_result.json` | the runner's own output for Harpo and gitleaks, Harpo by half, and the gitleaks control |
| `piimb_harpo.py` | the PIIMB adapter: Harpo's redactions as character spans, scored by PIIMB's `metrics.py` (official mode) or a re-implementation (indicative mode) |
| `openpii_native_result.json`, `nemotron_native_result.json` | the status of the native run, and the indication kept apart from it |
| `leaderboard_snapshot.md` | both leaderboards as checked, with sources and commits |
| `commands.txt` | every command of this pass |

Harpo's raw predictions hold offsets into benchmark text; they stay outside the repository, recorded by sha256 in
the result files. ProwlBench's data (PolyForm Noncommercial) and PIIMB's (CC BY-NC 4.0) are not copied here. The
machine's scratch folder is written as `$S` in `commands.txt` and `environment/provenance.json` (replaced for the
2.5.0 release; nothing else in either file changed).
