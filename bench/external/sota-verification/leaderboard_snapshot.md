# Leaderboard snapshot

Checked 2026-10-20 (21:00 to 22:00 UTC). Each leaderboard is kept with its own metric; numbers from different
protocols are never put in one ranking.

## ProwlBench 2.0

Source: [github.com/Lercas/prowlbench](https://github.com/Lercas/prowlbench), `README.md` section 5 and
`prowlbench_leaderboard.json` at commit `53d6fc1e2006185c0fadd5cd761af3f1aacfd025` (tag `v1.0.0`, 2026-06-23). That
commit is the repository's `HEAD`, `main` and only tag on the day of the check (`git ls-remote`), so the leaderboard
is current. Metric: the benchmark's own, from `run_prowlbench.py` (`prf`): a snippet counts as detected when a tool
flags at least one secret in it; precision, recall, F1 and accuracy over the 24,603 snippets.

Harpo's row was produced by `run_prowlbench.py` itself, with Harpo added as a tool by `prowl_native.py`; Harpo has
not been submitted to the leaderboard.

**A. Reproducible rows** (the README's "clean checkout" table: a clean checkout plus `run_prowlbench.py` gives them)

| Rank | Tool | Precision | Recall | F1 | Accuracy |
| --- | --- | --- | --- | --- | --- |
| 1 | **Harpo hardening-3** (measured here, not submitted) | 0.946 | 0.936 | 0.941 | 0.921 |
| 2 | Prowl (shipped binary, cascade) | 0.951 | 0.823 | 0.883 | 0.853 |
| 3 | DeepPass2 | 0.893 | 0.567 | 0.694 | 0.663 |
| 4 | gitleaks | 0.931 | 0.413 | 0.573 | 0.585 |
| 5 | detect-secrets | 0.848 | 0.423 | 0.564 | 0.561 |
| 6 | DeepSecrets | 0.921 | 0.309 | 0.462 | 0.517 |
| 7 | TruffleHog | 0.940 | 0.303 | 0.458 | 0.518 |

**B. All published rows**, including the README's research-only rows ("NOT in a clean checkout", "need the
gitignored LR + encoder", "numbers are from research runs and vary by encoder version", and carrying the disclosed
~5% train/test leakage)

| Rank | Tool | Precision | Recall | F1 | Accuracy |
| --- | --- | --- | --- | --- | --- |
| 1 | Prowl 3-way (+ multilingual encoder), research-only | 0.936 | 0.989 | 0.962 | 0.947 |
| 2 | **Harpo hardening-3** (measured here, not submitted) | 0.946 | 0.936 | 0.941 | 0.921 |
| 3 | Prowl (cascade ∪ LR), research-only | 0.940 | 0.872 | 0.905 | 0.876 |
| 4 | Prowl (shipped binary, cascade) | 0.951 | 0.823 | 0.883 | 0.853 |
| 5 | DeepPass2 | 0.893 | 0.567 | 0.694 | 0.663 |
| 6 | gitleaks | 0.931 | 0.413 | 0.573 | 0.585 |
| 7 | detect-secrets | 0.848 | 0.423 | 0.564 | 0.561 |
| 8 | DeepSecrets | 0.921 | 0.309 | 0.462 | 0.517 |
| 9 | TruffleHog | 0.940 | 0.303 | 0.458 | 0.518 |

The research-only accuracies are from `prowlbench_leaderboard.json` (`prowl-lr`, `prowl-3way`); the README gives
precision, recall and F1 for them. The Prowl repository's own README ([github.com/Lercas/prowl](https://github.com/Lercas/prowl))
renders the same reproducible table and says a 3-model ensemble reaches "roughly 0.97 to 0.99 recall" in research
runs, without an F1. No other published ProwlBench result was found (a web search; one later repository,
mhingston/safetynet, plans a ProwlBench run but reports no numbers).

## PIIMB, the PII Masking Benchmark (OpenPII / ai4privacy and Nemotron-PII)

The benchmark that ranks PII models on OpenPII (ai4privacy) and Nemotron-PII with one native scorer:
[huggingface.co/datasets/piimb/pii-masking-benchmark](https://huggingface.co/datasets/piimb/pii-masking-benchmark)
(code and data, latest commit `7d797b9fc8dc1942cef60fbe532e7d1a0e31b655`, package `piimb` 0.3.0 of 2026-07-05),
results in [piimb/pii-masking-benchmark-results](https://huggingface.co/datasets/piimb/pii-masking-benchmark-results)
(commit `e0a5b75aa26adcf2476617b0a2b415b098ea64b9`, 35 model folders), shown by the Space
[piimb/pii-masking-benchmark-leaderboard](https://huggingface.co/spaces/piimb/pii-masking-benchmark-leaderboard)
(commit `c7d1e80fb711751d3a7f6c015298d29094be370b`).

- **Metric (ranking): masking F2**, character-level and label-agnostic: per text, gold and predicted spans are
  merged when they overlap or touch; intersection, gold and predicted characters are pooled over every text of a
  task (micro); F2 with beta = 2. Also reported: precision, recall, F1, FPR over non-PII characters, and nervaluate
  NER scores (not used for ranking). Every gold entity counts whatever its label, dates and ages included.
- **Tasks:** `ai4privacy-en` (OpenPII 1M validation, 5,000 documents), `ai4privacy-multi` (OpenPII 1M validation,
  4,991 documents, 23 languages, stratified by language), `nemotron-pii` (Nemotron-PII test, 5,000 documents),
  `gretel`, `privy`, `mapa-eur-lex`. Every model runs on the `sentences` subset (SaT `sat-12l-sm` splitting, gold
  clipped at sentence boundaries). Documents were sampled at random; no seed is published, so the sample cannot be
  rebuilt from the original datasets: only the benchmark's own `data/test_sentences.jsonl` gives it.
- **Leaderboards:** English (Avg F2 over ai4privacy-en, gretel, nemotron-pii, privy) and multilingual (Avg F2 over
  ai4privacy-multi, mapa-eur-lex).

The rows below are the live leaderboard as the Space served it (its Gradio `/config`, read through a web fetch;
the workspace itself cannot reach Hugging Face). Four values were checked against the raw result files and agree:
OpenMed-PII-SuperClinical-Large-434M ai4privacy-en F2 0.94433, privacy-filter-nemotron-v2 ai4privacy-en 0.97841 and
ai4privacy-multi 0.97634, OpenMed-PII-SuperClinical-Small-44M nemotron-pii 0.97166.

**Best per task (the comparisons that matter here)**

| Task | Best model | F2 | Second | F2 |
| --- | --- | --- | --- | --- |
| ai4privacy-en | OpenMed/privacy-filter-nemotron-v2 | 0.978 | OpenMed/privacy-filter-multilingual-v2 | 0.975 |
| ai4privacy-multi | OpenMed/privacy-filter-nemotron-v2 | 0.976 | OpenMed/privacy-filter-multilingual-v2 | 0.970 |
| nemotron-pii | OpenMed/OpenMed-PII-SuperClinical-Small-44M-v1 | 0.972 | antoniogr7/pii-identifier-v0.1 | 0.970 |
| English Avg F2 | OpenMed/privacy-filter-multilingual-v2 | 0.918 | knowledgator/gliner-stream-pii-v1.0 | 0.908 |
| Multilingual Avg F2 | hivetrace/gliner-guard-omni | 0.743 | fastino/gliner2-privacy-filter-PII-multi | 0.725 |

**English leaderboard** (rank by Avg F2)

| Rank | Model | Avg F2 | AI4Privacy EN F2 | Gretel F2 | Nemotron-PII F2 | Privy F2 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | privacy-filter-multilingual-v2 | 0.918 | 0.975 | 0.973 | 0.907 | 0.818 |
| 2 | gliner-stream-pii-v1.0 | 0.908 | 0.957 | 0.939 | 0.833 | 0.904 |
| 3 | stirling-minimo-pii-10m | 0.904 | 0.917 | 0.979 | 0.930 | 0.792 |
| 4 | OpenMed-PII-SuperClinical-Large-434M-v1 | 0.897 | 0.944 | 0.945 | 0.963 | 0.734 |
| 5 | pii-identifier-v0.1 | 0.895 | 0.945 | 0.939 | 0.970 | 0.726 |
| 6 | OpenMed-PII-SuperClinical-Small-44M-v1 | 0.883 | 0.949 | 0.953 | 0.972 | 0.659 |
| 7 | privacy-filter-nemotron-v2 | 0.874 | 0.978 | 0.983 | 0.941 | 0.593 |
| 8 | ettin-32m-nemotron-pii | 0.860 | 0.911 | 0.917 | 0.932 | 0.680 |
| 9 | ettin-68m-nemotron-pii | 0.860 | 0.919 | 0.918 | 0.938 | 0.663 |
| 10 | bert-small-pii-detection | 0.849 | 0.900 | 0.818 | 0.693 | 0.987 |
| 11 | gliner-PII | 0.838 | 0.945 | 0.920 | 0.772 | 0.714 |
| 12 | gliner2-privacy-filter-PII-multi | 0.837 | 0.914 | 0.936 | 0.854 | 0.646 |
| 13 | privacy-filter-nemotron | 0.821 | 0.889 | 0.888 | 0.957 | 0.549 |
| 14 | gliner-pii-large-v1.0 | 0.820 | 0.910 | 0.951 | 0.839 | 0.581 |
| 15 | gliner2-multi-v1 | 0.815 | 0.903 | 0.870 | 0.828 | 0.661 |
| 16 | gliner-guard-omni | 0.810 | 0.955 | 0.891 | 0.759 | 0.636 |
| 17 | gliner2-large-v1 | 0.800 | 0.868 | 0.872 | 0.857 | 0.602 |
| 18 | ettin-17m-nemotron-pii | 0.795 | 0.865 | 0.868 | 0.895 | 0.553 |
| 19 | privacy-filter-multilingual | 0.760 | 0.942 | 0.864 | 0.766 | 0.468 |
| 20 | gliner-pii-base-v1.0 | 0.753 | 0.795 | 0.894 | 0.777 | 0.546 |
| 21 | eu-pii-anonimization-multilang | 0.753 | 0.831 | 0.890 | 0.715 | 0.575 |
| 22 | deberta_finetuned_pii | 0.734 | 0.960 | 0.930 | 0.742 | 0.306 |
| 23 | gliner2-base-v1 | 0.720 | 0.749 | 0.891 | 0.739 | 0.499 |
| 24 | privacy-filter | 0.714 | 0.843 | 0.869 | 0.607 | 0.536 |
| 25 | gliner_multi_pii-v1 | 0.704 | 0.735 | 0.795 | 0.731 | 0.555 |
| 26 | gretel-gliner-bi-small-v1.0 | 0.704 | 0.715 | 0.975 | 0.719 | 0.404 |
| 27 | eu-pii-safeguard | 0.702 | 0.805 | 0.848 | 0.610 | 0.545 |
| 28 | en_core_web_lg (Presidio) | 0.685 | 0.734 | 0.758 | 0.729 | 0.518 |
| 29 | pii-ner-nemotron | 0.675 | 0.820 | 0.741 | 0.578 | 0.561 |
| 30 | LFM2.5-Encoder-350M-PII-Detector | 0.669 | 0.819 | 0.811 | 0.500 | 0.545 |
| 31 | gretel-gliner-bi-base-v1.0 | 0.665 | 0.624 | 0.978 | 0.703 | 0.356 |
| 32 | rampart (quantised, own pipeline) | 0.622 | 0.798 | 0.794 | 0.456 | 0.439 |
| 33 | hikmaai-distilbert-pii | 0.547 | 0.805 | 0.591 | 0.393 | 0.401 |
| 34 | llama-ai4privacy-multilingual-categorical-anonymiser-openpii | 0.542 | 0.699 | 0.689 | 0.441 | 0.338 |
| 35 | piiranha-v1-detect-personal-information | 0.535 | 0.803 | 0.607 | 0.360 | 0.369 |
| 36 | llama-ai4privacy-multilingual-anonymiser-openpii | 0.437 | 0.562 | 0.576 | 0.339 | 0.272 |

**Multilingual leaderboard** (rank by Avg F2)

| Rank | Model | Avg F2 | AI4Privacy Multi F2 | MAPA EUR-Lex F2 |
| --- | --- | --- | --- | --- |
| 1 | gliner-guard-omni | 0.743 | 0.926 | 0.559 |
| 2 | gliner2-privacy-filter-PII-multi | 0.725 | 0.904 | 0.545 |
| 3 | gliner2-multi-v1 | 0.723 | 0.878 | 0.569 |
| 4 | gliner-PII | 0.722 | 0.913 | 0.531 |
| 5 | OpenMed-PII-SuperClinical-Large-434M-v1 | 0.712 | 0.899 | 0.525 |
| 6 | gliner-pii-large-v1.0 | 0.698 | 0.879 | 0.517 |
| 7 | pii-ner-nemotron | 0.689 | 0.806 | 0.573 |
| 8 | OpenMed-PII-SuperClinical-Small-44M-v1 | 0.683 | 0.888 | 0.478 |
| 9 | privacy-filter-nemotron-v2 | 0.680 | 0.976 | 0.384 |
| 10 | privacy-filter-multilingual-v2 | 0.671 | 0.970 | 0.373 |
| 11 | gliner-stream-pii-v1.0 | 0.666 | 0.921 | 0.411 |
| 12 | gliner2-large-v1 | 0.636 | 0.798 | 0.474 |
| 13 | ettin-68m-nemotron-pii | 0.613 | 0.845 | 0.382 |
| 14 | pii-identifier-v0.1 | 0.597 | 0.814 | 0.380 |
| 15 | gliner_multi_pii-v1 | 0.593 | 0.762 | 0.424 |
| 16 | privacy-filter-multilingual | 0.583 | 0.844 | 0.321 |
| 17 | privacy-filter | 0.559 | 0.805 | 0.313 |
| 18 | eu-pii-anonimization-multilang | 0.549 | 0.843 | 0.254 |
| 19 | ettin-32m-nemotron-pii | 0.544 | 0.794 | 0.294 |
| 20 | gliner-pii-base-v1.0 | 0.530 | 0.727 | 0.332 |
| 21 | gliner2-base-v1 | 0.508 | 0.723 | 0.292 |
| 22 | bert-small-pii-detection | 0.501 | 0.729 | 0.273 |
| 23 | stirling-minimo-pii-10m | 0.489 | 0.776 | 0.202 |
| 24 | eu-pii-safeguard | 0.488 | 0.833 | 0.144 |
| 25 | rampart (quantised, own pipeline) | 0.481 | 0.810 | 0.151 |
| 26 | piiranha-v1-detect-personal-information | 0.479 | 0.813 | 0.146 |
| 27 | gretel-gliner-bi-small-v1.0 | 0.478 | 0.644 | 0.312 |
| 28 | ettin-17m-nemotron-pii | 0.478 | 0.723 | 0.234 |
| 29 | gretel-gliner-bi-base-v1.0 | 0.478 | 0.596 | 0.359 |
| 30 | privacy-filter-nemotron | 0.474 | 0.719 | 0.228 |
| 31 | hikmaai-distilbert-pii | 0.464 | 0.788 | 0.140 |
| 32 | LFM2.5-Encoder-350M-PII-Detector | 0.453 | 0.808 | 0.099 |
| 33 | deberta_finetuned_pii | 0.408 | 0.682 | 0.133 |
| 34 | en_core_web_lg (Presidio) | 0.388 | 0.622 | 0.154 |
| 35 | llama-ai4privacy-multilingual-categorical-anonymiser-openpii | 0.291 | 0.520 | 0.063 |
| 36 | llama-ai4privacy-multilingual-anonymiser-openpii | 0.277 | 0.488 | 0.067 |

Other results checked and kept apart, because their protocols differ: an older copy of this leaderboard on
[benchmarklist.com](https://benchmarklist.com/benchmarks/pii_masking_benchmark/) (last updated 2026-05-06, PIIMB
0.2.x, four tasks, superseded by the live board), and
[arXiv 2608.02616](https://arxiv.org/html/2608.02616v1) (span-level exact-offset F1 on its own samples of
ai4privacy pii-masking-300k and Nemotron-PII). Neither changes any ranking above.
