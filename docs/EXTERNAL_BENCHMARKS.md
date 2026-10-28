# External benchmarks

Harpo measured on public datasets it was not built against: ProwlBench, Nemotron-PII, OpenPII and RedactionBench, with
a fifth, Gretel PII masking, prepared but not run ([Deferred evaluations](#deferred-evaluations)). LeakBench
([LEAKBENCH.md](LEAKBENCH.md)) tests known attacks on a corpus written for Harpo; these test what other people wrote,
in their formats, with their labels.

This page starts with the baseline: Harpo 2.4.0 exactly as released, run blind, before anything was changed because
of these datasets. Later runs are added next to it, never over it: `hardening-1` is the first round of fixes, made on
ProwlBench's dev half, `hardening-2` the second, made on the dev halves of OpenPII, Nemotron-PII and RedactionBench,
and `hardening-3` the third, made on the dev halves of OpenPII and RedactionBench and on the dev templates of
[RegionBench](#regionbench), Harpo's own benchmark for Dutch, US and EU identifiers. Gretel's files could not be
fetched in the benchmark environment, so it was not run. How to run them:
[bench/external/README.md](../bench/external/README.md).

## Protocol

**The build.** Harpo 2.4.0 as released (`harpo-redact-2.4.0.zip`, sha256
`1204e0fc2e240daba74dbe1b3fad4348f594a62620f0064e60fe7027b7c99103`), installed on its own and not in editable mode.
Each result file carries a sha256 over every file of the installed package, with the model and Python versions.
`hardening-1`, `hardening-2` and `hardening-3` are frozen pre-release builds of this repository, made while 2.5.0 was
developed, after its first, second and third round of fixes. They keep the identity they were recorded with: they call
themselves 2.4.0, and their package digests tell the four builds apart and remain the authority for their results.
Each was built as a wheel and installed into a copy of the baseline's environment, so every dependency and model is
the same. `hardening-3`'s detection is the basis of Harpo 2.5.0.

**The configuration.** What the Docker image runs: the deterministic layers plus spaCy NER (`en_core_web_sm`, with
`de_core_news_sm` for German and `xx_ent_wiki_sm` for every other language), result cache off. Each document goes
through `Pipeline.scan_sync`, the path a request takes.

**Blind.** Nothing in Harpo was changed for these runs. Which labels count was fixed in
[bench/external/scope.py](../bench/external/scope.py) before any result was seen: a label is *in scope* when Harpo
has a detector for that kind of value and its default policy redacts it. Every label is reported either way; the
scope only decides which labels make up the headline, so it cannot hide a failure. A label the scope file does not
name is reported as *unmapped* and gets an entry by the same rule, never by its result. The PII datasets' labels and
halves were added to `scope.py` and `corpora.py` after ProwlBench's first two runs, which is why those carry other
scope and harness digests; scored with today's harness, `hardening-1` gives ProwlBench's dev half the same numbers to
the last digit.

**What counts.** A gold value is *fully removed* when every letter and digit in it was inside a redaction, or the
request was blocked; *partly removed* when some were; *leaked* when none were. Punctuation and blanks are not
counted: "+31 (0)6-1234 5678" is removed when its digits are. Any Harpo type counts, since a phone number redacted as
an account number has still not left. *Collateral* is the share of letters and digits outside every gold value that
were redacted. The datasets do not label everything Harpo protects (most leave out organisations, for one), so
collateral is an upper bound on over-redaction, not a precision.

**ProwlBench's own metric.** ProwlBench asks a different question: is a secret flagged in the snippet. Its numbers
are computed exactly as its `run_prowlbench.py` computes them, with a snippet flagged when Harpo redacted at least one
`SECRET` or `PRIVATE_KEY` in it. To check the scorer, gitleaks 8.30.1 is run through it the way ProwlBench's runner
runs it (one file per case, with the extension its source implies), and it reproduces gitleaks' published row to
the last digit.

**Held-out data.** Fixes are developed on data that is never reported as the result.

- Every file scored here is cut into a *dev* and a *holdout* half by a salted hash of the case id (`half_of` in
  [corpora.py](../bench/external/corpora.py), salt `harpo-external-v1`). Failures are studied on the dev half only;
  the holdout half is only ever counted. RedactionBench and ProwlBench publish one split each. OpenPII and
  Nemotron-PII also publish training data, but only their validation and test files could be fetched for this page,
  so they are cut the same way. The halves of ProwlBench were fixed after its baseline totals were recorded and
  before any single case was looked at; those of the other three before their baselines were run.
- Nemotron-PII's test file holds each document id twice, a US and an international version of the document. Both
  copies fall in the same half, and the runner tells them apart with a `#2` suffix.
- Gretel, if it is run: developed on its train split, reported on test.

The two halves of a dataset come from the same generator and share its templates, so the holdout half guards
against tuning to particular values, not to particular phrasings. Fixes are therefore written as general rules,
tested on phrasings of our own, and re-run on every external dataset here and on LeakBench.

**The data.** None of it is in this repository. ProwlBench is licensed PolyForm Noncommercial 1.0.0 and is used
for evaluation only. The per-document details file (`run.py --details`) holds dataset text and stays outside the
repository.

## Datasets

| Dataset | Publisher and license | File scored | What is scored |
| --- | --- | --- | --- |
| OpenPII | ai4privacy, CC BY 4.0 | `openpii-masking-micro-100k`, `data/validation.jsonl` | character spans, many languages |
| Nemotron-PII | NVIDIA, CC BY 4.0 | `data/test-00000-of-00001.parquet` | character spans, English, 55+ categories |
| Gretel PII masking | Gretel, Apache-2.0 | `gretel-pii-masking-en-v1`, `data/test-00000-of-00001.parquet` | values without offsets: every occurrence of a value is a span; values not found in their text are counted, not scored |
| RedactionBench | CC BY 4.0 | `data/test-00000-of-00001.parquet` | *mandatory* spans must go; *contextual* spans may, with no penalty either way |
| ProwlBench 2.0 | Lercas/prowlbench at `53d6fc1`, PolyForm Noncommercial 1.0.0 | `prowlbench.jsonl`, 24,603 cases | its own metric; where a positive marks its secret (9,110 of 16,552 do), also whether the value was removed |

## Results

<!-- results 2.4.0-baseline hardening-1 hardening-2 hardening-3 -->
### Summary

| Dataset | Run | File | Documents | Values in scope | Fully removed | Any part removed | Leaked | Partly removed | Collateral | p50 / p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenPII (ai4privacy) | 2.4.0-baseline | `validation.jsonl` | 10,000 | 51,953 | 50.2% | 53.9% | 23,952 | 1,936 | 13.2% | 9.15 / 23.4 |
| OpenPII (ai4privacy) | hardening-1 | `validation.jsonl` | 10,000 | 51,953 | 50.1% | 53.8% | 24,003 | 1,936 | 13.1% | 9.04 / 23.24 |
| OpenPII (ai4privacy) | hardening-2 | `validation.jsonl` | 10,000 | 51,953 | 74.5% | 76.9% | 12,005 | 1,246 | 13.2% | 14.41 / 36.0 |
| OpenPII (ai4privacy) | hardening-3 | `validation.jsonl` | 10,000 | 51,953 | 76.8% | 79.1% | 10,870 | 1,203 | 5.1% | 14.32 / 36.13 |
| Nemotron-PII (NVIDIA) | 2.4.0-baseline | `test-00000-of-00001.parquet` | 100,000 | 524,291 | 79.2% | 80.8% | 100,741 | 8,160 | 4.0% | 19.73 / 46.91 |
| Nemotron-PII (NVIDIA) | hardening-1 | `test-00000-of-00001.parquet` | 100,000 | 524,291 | 79.6% | 81.2% | 98,788 | 8,152 | 3.9% | 20.53 / 52.53 |
| Nemotron-PII (NVIDIA) | hardening-2 | `test-00000-of-00001.parquet` | 100,000 | 524,291 | 94.6% | 95.2% | 24,927 | 3,159 | 4.1% | 30.18 / 80.81 |
| Nemotron-PII (NVIDIA) | hardening-3 | `test-00000-of-00001.parquet` | 100,000 | 524,291 | 94.8% | 95.3% | 24,619 | 2,663 | 2.3% | 27.88 / 75.83 |
| Gretel PII masking | not run yet |  |  |  |  |  |  |  |  |  |
| RedactionBench | 2.4.0-baseline | `test-00000-of-00001.parquet` | 200 | 16,988 | 74.0% | 74.5% | 4,329 | 96 | 9.5% | 151.44 / 800.88 |
| RedactionBench | hardening-1 | `test-00000-of-00001.parquet` | 200 | 16,988 | 74.0% | 74.6% | 4,309 | 109 | 8.9% | 165.84 / 814.12 |
| RedactionBench | hardening-2 | `test-00000-of-00001.parquet` | 200 | 16,988 | 88.1% | 88.7% | 1,916 | 108 | 9.1% | 238.77 / 1361.29 |
| RedactionBench | hardening-3 | `test-00000-of-00001.parquet` | 200 | 16,988 | 88.0% | 88.6% | 1,941 | 105 | 3.6% | 272.65 / 1466.19 |
| ProwlBench | 2.4.0-baseline | `prowlbench.jsonl` | 24,603 | 9,110 | 65.8% | 77.9% | 2,015 | 1,098 | 17.3% | 5.45 / 19.66 |
| ProwlBench | hardening-1 | `prowlbench.jsonl` | 24,603 | 9,110 | 83.9% | 94.3% | 521 | 945 | 18.5% | 5.74 / 20.88 |
| ProwlBench | hardening-2 | `prowlbench.jsonl` | 24,603 | 9,110 | 85.2% | 95.5% | 406 | 944 | 19.5% | 9.57 / 32.52 |
| ProwlBench | hardening-3 | `prowlbench.jsonl` | 24,603 | 9,110 | 85.8% | 96.2% | 351 | 943 | 18.0% | 9.23 / 32.34 |

Run identity (the full digests are in the result files):

| Run | Result | Harpo | Package sha256 | Data file sha256 | Scope sha256 | Harness sha256 | Python | Models | Date |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2.4.0-baseline | nemotron | 2.4.0 | `8f55a57e33859c11` | `1a4b0512ecb5370f` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-14 |
| 2.4.0-baseline | openpii | 2.4.0 | `8f55a57e33859c11` | `c2175f3146a8afd6` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-13 |
| 2.4.0-baseline | prowlbench | 2.4.0 | `8f55a57e33859c11` | `0a66fc09b180261e` | `5c6697f4ca2c` | `cb165cf050a6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-13 |
| 2.4.0-baseline | redactionbench | 2.4.0 | `8f55a57e33859c11` | `17ea0b577344917c` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-13 |
| hardening-1 | nemotron | 2.4.0 | `d30eaffe84a1e917` | `1a4b0512ecb5370f` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-14 |
| hardening-1 | openpii | 2.4.0 | `d30eaffe84a1e917` | `c2175f3146a8afd6` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-13 |
| hardening-1 | prowlbench | 2.4.0 | `d30eaffe84a1e917` | `0a66fc09b180261e` | `5c6697f4ca2c` | `cb165cf050a6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-13 |
| hardening-1 | redactionbench | 2.4.0 | `d30eaffe84a1e917` | `17ea0b577344917c` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-14 |
| hardening-2 | nemotron | 2.4.0 | `e00f4dddcd51d4fe` | `1a4b0512ecb5370f` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-19 |
| hardening-2 | openpii | 2.4.0 | `e00f4dddcd51d4fe` | `c2175f3146a8afd6` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-19 |
| hardening-2 | prowlbench | 2.4.0 | `e00f4dddcd51d4fe` | `0a66fc09b180261e` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-19 |
| hardening-2 | redactionbench | 2.4.0 | `e00f4dddcd51d4fe` | `17ea0b577344917c` | `e4f5161128b4` | `640bc588a6fe` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-19 |
| hardening-3 | nemotron | 2.4.0 | `81600d74853bdeda` | `1a4b0512ecb5370f` | `e4f5161128b4` | `ce86f04686e6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-20 |
| hardening-3 | openpii | 2.4.0 | `81600d74853bdeda` | `c2175f3146a8afd6` | `e4f5161128b4` | `ce86f04686e6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-20 |
| hardening-3 | prowlbench | 2.4.0 | `81600d74853bdeda` | `0a66fc09b180261e` | `e4f5161128b4` | `ce86f04686e6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-20 |
| hardening-3 | redactionbench | 2.4.0 | `81600d74853bdeda` | `17ea0b577344917c` | `e4f5161128b4` | `ce86f04686e6` | 3.12.13 | en_core_web_sm 3.8.0, de_core_news_sm 3.8.0, xx_ent_wiki_sm 3.8.0, spacy 3.8.16 | 2026-10-20 |

ProwlBench's leaderboard with Harpo's runs (its published rows are those a clean checkout
reproduces; Harpo has not been submitted):

| Tool | Precision | Recall | F1 | Accuracy | Source |
| --- | --- | --- | --- | --- | --- |
| **Harpo, hardening-3, all cases** | 0.946 | 0.936 | 0.941 | 0.921 | measured here |
| **Harpo, hardening-3, holdout half** | 0.945 | 0.932 | 0.939 | 0.918 | measured here |
| **Harpo, hardening-2, all cases** | 0.945 | 0.931 | 0.938 | 0.917 | measured here |
| **Harpo, hardening-2, holdout half** | 0.945 | 0.926 | 0.935 | 0.914 | measured here |
| **Harpo, hardening-1, all cases** | 0.946 | 0.921 | 0.934 | 0.912 | measured here |
| **Harpo, hardening-1, holdout half** | 0.946 | 0.916 | 0.931 | 0.908 | measured here |
| Prowl (shipped binary, cascade) | 0.951 | 0.823 | 0.883 | 0.853 | published |
| **Harpo, 2.4.0-baseline, all cases** | 0.935 | 0.753 | 0.834 | 0.799 | measured here |
| **Harpo, 2.4.0-baseline, holdout half** | 0.934 | 0.743 | 0.828 | 0.791 | measured here |
| DeepPass2 | 0.893 | 0.567 | 0.694 | 0.663 | published |
| gitleaks | 0.931 | 0.413 | 0.573 | 0.585 | published |
| detect-secrets | 0.848 | 0.423 | 0.564 | 0.561 | published |
| DeepSecrets | 0.921 | 0.309 | 0.462 | 0.517 | published |
| TruffleHog | 0.940 | 0.303 | 0.458 | 0.518 | published |

RedactionBench's own metric, the R-Score (bench/external/rscore.py, from the paper's definition; the
authors' scorer is not released yet), with the published rows:

| System | Mean | P50 | P20 | Unstructured mean | Dev half | Holdout half | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| claude-opus-4-6 (agentic, tool calls) | 0.710 |  |  |  |  |  | published |
| gpt-5.4 (agentic, tool calls) | 0.660 |  |  |  |  |  | published |
| Qwen3.5-397B-A17B | 0.590 |  |  |  |  |  | published |
| openai/privacy-filter | 0.580 |  |  |  |  |  | published |
| zai-org/GLM-5.1 | 0.560 |  |  |  |  |  | published |
| gretelai/gretel-gliner-bi-large-v1.0 | 0.470 |  |  |  |  |  | published |
| OpenMed-PII-SuperClinical-Large-434M-v1 | 0.460 |  |  |  |  |  | published |
| **Harpo, hardening-3** | 0.460 | 0.467 | 0.231 | 0.424 | 0.478 | 0.442 | measured here |
| nvidia/gliner-PII | 0.420 |  |  |  |  |  | published |
| jakobhuss/pii-extractor-gemma-3-270m-it | 0.400 |  |  |  |  |  | published |
| iiiorg/piiranha-v1-detect-personal-information | 0.340 |  |  |  |  |  | published |
| urchade/gliner_multi_pii-v1 | 0.330 |  |  |  |  |  | published |
| **Harpo, hardening-2** | 0.311 | 0.295 | 0.090 | 0.296 | 0.315 | 0.308 | measured here |
| **Harpo, hardening-1** | 0.277 | 0.253 | 0.077 | 0.264 | 0.270 | 0.284 | measured here |
| **Harpo, 2.4.0-baseline** | 0.272 | 0.253 | 0.073 | 0.263 | 0.262 | 0.282 | measured here |

What the R-Score is made of, summed over the 200 documents:

| Run | Mandatory entities | Covered (sum) | Contextual attempted | Contextual penalty | False-positive runs | Whole gaps |
| --- | --- | --- | --- | --- | --- | --- |
| 2.4.0-baseline | 7,692 | 5,143 | 4,844 | 798 | 19,431 | 14 |
| hardening-1 | 7,692 | 5,161 | 4,761 | 794 | 18,648 | 18 |
| hardening-2 | 7,692 | 6,191 | 5,190 | 878 | 19,048 | 23 |
| hardening-3 | 7,692 | 6,284 | 4,385 | 297 | 4,477 | 27 |

#### OpenPII (ai4privacy), 2.4.0-baseline: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `AGE` | out | 3,566 | 0.2% | 0.2% | 3,559 | 0 |
| `AMOUNT` | out | 1 | 0.0% | 0.0% | 1 | 0 |
| `BANKNAME` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `BUILDINGNUM` | in | 3,450 | 13.0% | 13.5% | 2,985 | 17 |
| `CITY` | in | 5,075 | 64.2% | 76.5% | 1,192 | 625 |
| `COUNTRY` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `CREDITCARDNUMBER` | in | 2,267 | 8.7% | 8.7% | 2,070 | 0 |
| `DATE` | out | 8,572 | 3.6% | 5.0% | 8,144 | 119 |
| `DRIVERLICENSENUM` | in | 2,001 | 12.7% | 13.6% | 1,729 | 18 |
| `EMAIL` | in | 5,427 | 99.1% | 99.8% | 10 | 39 |
| `GENDER` | out | 1,903 | 42.2% | 44.1% | 1,063 | 37 |
| `GIVENNAME` | in | 8,489 | 75.2% | 77.9% | 1,874 | 232 |
| `IDCARDNUM` | in | 2,337 | 9.3% | 9.4% | 2,118 | 1 |
| `ORGANISATION` | in | 3 | 33.3% | 33.3% | 2 | 0 |
| `PASSPORTNUM` | in | 1,391 | 14.4% | 14.4% | 1,190 | 0 |
| `SEX` | out | 1,773 | 20.2% | 20.2% | 1,415 | 0 |
| `SOCIALNUM` | in | 1,745 | 27.4% | 28.4% | 1,250 | 17 |
| `STREET` | in | 3,486 | 46.7% | 63.6% | 1,267 | 592 |
| `SURNAME` | in | 7,287 | 77.2% | 80.2% | 1,442 | 216 |
| `TAXNUM` | in | 1,850 | 22.7% | 23.0% | 1,425 | 6 |
| `TELEPHONENUM` | in | 3,998 | 30.8% | 35.0% | 2,597 | 170 |
| `TIME` | out | 124 | 0.0% | 2.4% | 121 | 3 |
| `TITLE` | out | 4,705 | 56.2% | 56.3% | 2,055 | 6 |
| `ZIPCODE` | in | 3,145 | 10.9% | 11.0% | 2,799 | 3 |

Out of scope, all labels: 20,644 values, 20.0% fully removed, 20.8% any part.

OpenPII (ai4privacy), 2.4.0-baseline: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| bg | 1,489 | 45.1% | 51.1% | 728 | 90 |
| cs | 1,340 | 46.0% | 51.6% | 649 | 74 |
| da | 1,385 | 49.4% | 51.7% | 669 | 32 |
| de | 3,444 | 56.4% | 59.3% | 1,402 | 101 |
| el | 1,430 | 40.5% | 43.0% | 815 | 36 |
| en | 7,137 | 58.9% | 62.0% | 2,715 | 219 |
| es | 2,806 | 56.0% | 58.2% | 1,174 | 60 |
| et | 1,491 | 44.0% | 49.8% | 748 | 87 |
| fi | 1,488 | 52.8% | 55.9% | 656 | 46 |
| fr | 4,272 | 54.3% | 56.3% | 1,866 | 88 |
| hr | 1,406 | 50.1% | 57.2% | 601 | 100 |
| hu | 1,330 | 43.5% | 50.8% | 654 | 97 |
| id | 911 | 48.0% | 52.6% | 432 | 42 |
| it | 2,966 | 48.2% | 51.7% | 1,433 | 103 |
| ja | 832 | 15.6% | 16.8% | 692 | 10 |
| ko | 771 | 18.3% | 18.9% | 625 | 5 |
| lt | 1,420 | 50.6% | 57.2% | 607 | 94 |
| lv | 1,433 | 47.2% | 54.9% | 647 | 109 |
| ms | 834 | 44.5% | 50.1% | 416 | 47 |
| nl | 1,477 | 63.4% | 65.3% | 513 | 27 |
| pl | 1,475 | 52.9% | 56.1% | 648 | 46 |
| pt | 1,417 | 50.5% | 52.6% | 671 | 31 |
| ro | 1,395 | 50.2% | 53.8% | 644 | 51 |
| sk | 1,428 | 48.9% | 51.7% | 689 | 40 |
| sl | 1,431 | 43.9% | 51.9% | 688 | 115 |
| sr | 1,353 | 52.2% | 55.6% | 600 | 46 |
| sv | 1,312 | 48.3% | 51.4% | 638 | 40 |
| tl | 885 | 56.6% | 59.8% | 356 | 28 |
| vi | 885 | 44.9% | 51.7% | 427 | 61 |
| zh | 710 | 21.1% | 22.7% | 549 | 11 |

OpenPII (ai4privacy), 2.4.0-baseline: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 26,070 | 50.2% | 53.8% | 12,033 | 951 |
| holdout | 25,883 | 50.1% | 53.9% | 11,919 | 985 |

Collateral: 271,049 of 2,047,459 letters and digits outside the gold values were redacted (13.2%); by type: PERSON 172,382, ORGANIZATION 63,036, LOCATION 32,868, EMAIL 2,412, ADDRESS 271, PHONE 35, DEVICE_ID 13, ACCOUNT_ID 10.

#### OpenPII (ai4privacy), hardening-1: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `AGE` | out | 3,566 | 0.2% | 0.2% | 3,560 | 0 |
| `AMOUNT` | out | 1 | 0.0% | 0.0% | 1 | 0 |
| `BANKNAME` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `BUILDINGNUM` | in | 3,450 | 13.0% | 13.5% | 2,985 | 17 |
| `CITY` | in | 5,075 | 63.9% | 76.3% | 1,205 | 626 |
| `COUNTRY` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `CREDITCARDNUMBER` | in | 2,267 | 8.8% | 8.8% | 2,068 | 0 |
| `DATE` | out | 8,572 | 3.6% | 5.0% | 8,144 | 119 |
| `DRIVERLICENSENUM` | in | 2,001 | 12.8% | 13.7% | 1,727 | 18 |
| `EMAIL` | in | 5,427 | 99.0% | 99.8% | 11 | 41 |
| `GENDER` | out | 1,903 | 42.0% | 43.9% | 1,067 | 37 |
| `GIVENNAME` | in | 8,489 | 75.0% | 77.7% | 1,893 | 231 |
| `IDCARDNUM` | in | 2,337 | 9.4% | 9.4% | 2,117 | 1 |
| `ORGANISATION` | in | 3 | 33.3% | 33.3% | 2 | 0 |
| `PASSPORTNUM` | in | 1,391 | 14.4% | 14.4% | 1,190 | 0 |
| `SEX` | out | 1,773 | 20.0% | 20.0% | 1,419 | 0 |
| `SOCIALNUM` | in | 1,745 | 27.4% | 28.4% | 1,250 | 17 |
| `STREET` | in | 3,486 | 46.6% | 63.6% | 1,268 | 592 |
| `SURNAME` | in | 7,287 | 77.0% | 79.9% | 1,463 | 214 |
| `TAXNUM` | in | 1,850 | 22.7% | 23.0% | 1,425 | 6 |
| `TELEPHONENUM` | in | 3,998 | 30.8% | 35.0% | 2,597 | 170 |
| `TIME` | out | 124 | 0.0% | 2.4% | 121 | 3 |
| `TITLE` | out | 4,705 | 55.9% | 56.0% | 2,068 | 6 |
| `ZIPCODE` | in | 3,145 | 10.9% | 11.0% | 2,800 | 3 |

Out of scope, all labels: 20,644 values, 19.9% fully removed, 20.6% any part.

OpenPII (ai4privacy), hardening-1: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| bg | 1,489 | 45.0% | 51.0% | 729 | 90 |
| cs | 1,340 | 45.9% | 51.4% | 651 | 74 |
| da | 1,385 | 49.2% | 51.6% | 670 | 33 |
| de | 3,444 | 56.2% | 59.2% | 1,404 | 103 |
| el | 1,430 | 40.6% | 43.1% | 813 | 36 |
| en | 7,137 | 58.9% | 61.9% | 2,719 | 218 |
| es | 2,806 | 56.0% | 58.1% | 1,175 | 60 |
| et | 1,491 | 43.8% | 49.6% | 751 | 87 |
| fi | 1,488 | 52.7% | 55.8% | 658 | 46 |
| fr | 4,272 | 54.1% | 56.2% | 1,873 | 87 |
| hr | 1,406 | 50.1% | 57.2% | 601 | 100 |
| hu | 1,330 | 43.5% | 50.7% | 655 | 97 |
| id | 911 | 48.0% | 52.6% | 432 | 42 |
| it | 2,966 | 47.7% | 51.2% | 1,447 | 103 |
| ja | 832 | 15.5% | 16.7% | 693 | 10 |
| ko | 771 | 18.3% | 18.9% | 625 | 5 |
| lt | 1,420 | 50.6% | 57.2% | 607 | 95 |
| lv | 1,433 | 47.2% | 54.9% | 647 | 109 |
| ms | 834 | 44.4% | 50.0% | 417 | 47 |
| nl | 1,477 | 63.4% | 65.3% | 513 | 27 |
| pl | 1,475 | 52.9% | 56.1% | 648 | 46 |
| pt | 1,417 | 50.5% | 52.6% | 671 | 31 |
| ro | 1,395 | 50.0% | 53.7% | 646 | 51 |
| sk | 1,428 | 48.9% | 51.7% | 689 | 40 |
| sl | 1,431 | 43.9% | 51.9% | 688 | 115 |
| sr | 1,353 | 51.8% | 55.2% | 606 | 46 |
| sv | 1,312 | 48.2% | 51.3% | 639 | 40 |
| tl | 885 | 56.6% | 59.8% | 356 | 28 |
| vi | 885 | 44.9% | 51.6% | 428 | 60 |
| zh | 710 | 20.8% | 22.2% | 552 | 10 |

OpenPII (ai4privacy), hardening-1: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 26,070 | 50.1% | 53.7% | 12,063 | 948 |
| holdout | 25,883 | 50.0% | 53.9% | 11,940 | 988 |

Collateral: 268,729 of 2,047,459 letters and digits outside the gold values were redacted (13.1%); by type: PERSON 171,809, ORGANIZATION 62,572, LOCATION 32,653, EMAIL 1,345, ADDRESS 269, PHONE 35, DEVICE_ID 13, ACCOUNT_ID 10.

#### OpenPII (ai4privacy), hardening-2: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `AGE` | out | 3,566 | 0.3% | 0.3% | 3,554 | 0 |
| `AMOUNT` | out | 1 | 0.0% | 0.0% | 1 | 0 |
| `BANKNAME` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `BUILDINGNUM` | in | 3,450 | 57.2% | 57.7% | 1,459 | 18 |
| `CITY` | in | 5,075 | 73.4% | 83.7% | 828 | 520 |
| `COUNTRY` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `CREDITCARDNUMBER` | in | 2,267 | 45.8% | 45.9% | 1,227 | 1 |
| `DATE` | out | 8,572 | 3.7% | 5.3% | 8,119 | 134 |
| `DRIVERLICENSENUM` | in | 2,001 | 51.2% | 52.4% | 952 | 24 |
| `EMAIL` | in | 5,427 | 99.0% | 99.8% | 11 | 41 |
| `GENDER` | out | 1,903 | 42.0% | 44.0% | 1,066 | 38 |
| `GIVENNAME` | in | 8,489 | 86.3% | 87.6% | 1,050 | 113 |
| `IDCARDNUM` | in | 2,337 | 47.6% | 47.7% | 1,222 | 2 |
| `ORGANISATION` | in | 3 | 33.3% | 33.3% | 2 | 0 |
| `PASSPORTNUM` | in | 1,391 | 50.9% | 51.1% | 680 | 3 |
| `SEX` | out | 1,773 | 20.0% | 20.0% | 1,419 | 0 |
| `SOCIALNUM` | in | 1,745 | 58.0% | 59.2% | 712 | 21 |
| `STREET` | in | 3,486 | 73.4% | 82.4% | 613 | 315 |
| `SURNAME` | in | 7,287 | 88.2% | 89.9% | 734 | 127 |
| `TAXNUM` | in | 1,850 | 63.6% | 63.6% | 673 | 1 |
| `TELEPHONENUM` | in | 3,998 | 78.8% | 80.0% | 798 | 48 |
| `TIME` | out | 124 | 0.0% | 2.4% | 121 | 3 |
| `TITLE` | out | 4,705 | 48.8% | 49.3% | 2,385 | 23 |
| `ZIPCODE` | in | 3,145 | 66.5% | 66.9% | 1,042 | 12 |

Out of scope, all labels: 20,644 values, 18.3% fully removed, 19.3% any part.

OpenPII (ai4privacy), hardening-2: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| bg | 1,489 | 68.0% | 72.5% | 409 | 67 |
| cs | 1,340 | 74.6% | 78.4% | 290 | 50 |
| da | 1,385 | 75.1% | 76.1% | 331 | 14 |
| de | 3,444 | 78.7% | 80.6% | 667 | 66 |
| el | 1,430 | 67.5% | 69.2% | 441 | 24 |
| en | 7,137 | 77.8% | 79.8% | 1,444 | 139 |
| es | 2,806 | 85.3% | 86.7% | 373 | 40 |
| et | 1,491 | 70.6% | 74.1% | 386 | 52 |
| fi | 1,488 | 77.5% | 79.3% | 308 | 27 |
| fr | 4,272 | 79.8% | 80.8% | 821 | 42 |
| hr | 1,406 | 77.1% | 80.9% | 268 | 54 |
| hu | 1,330 | 67.8% | 71.6% | 378 | 50 |
| id | 911 | 81.2% | 84.0% | 146 | 25 |
| it | 2,966 | 75.5% | 77.9% | 655 | 72 |
| ja | 832 | 28.7% | 31.7% | 568 | 25 |
| ko | 771 | 39.8% | 41.6% | 450 | 14 |
| lt | 1,420 | 72.7% | 76.5% | 333 | 55 |
| lv | 1,433 | 67.3% | 73.0% | 387 | 82 |
| ms | 834 | 73.9% | 76.6% | 195 | 23 |
| nl | 1,477 | 79.0% | 80.6% | 287 | 23 |
| pl | 1,475 | 79.2% | 81.0% | 281 | 25 |
| pt | 1,417 | 78.8% | 80.2% | 281 | 19 |
| ro | 1,395 | 80.7% | 82.9% | 239 | 31 |
| sk | 1,428 | 75.5% | 77.2% | 326 | 24 |
| sl | 1,431 | 69.0% | 74.0% | 372 | 71 |
| sr | 1,353 | 74.1% | 76.0% | 325 | 26 |
| sv | 1,312 | 73.9% | 76.2% | 312 | 30 |
| tl | 885 | 74.6% | 77.1% | 203 | 22 |
| vi | 885 | 78.0% | 82.7% | 153 | 42 |
| zh | 710 | 45.4% | 47.0% | 376 | 12 |

OpenPII (ai4privacy), hardening-2: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 26,070 | 74.6% | 76.9% | 6,019 | 598 |
| holdout | 25,883 | 74.4% | 76.9% | 5,986 | 648 |

Collateral: 270,957 of 2,047,459 letters and digits outside the gold values were redacted (13.2%); by type: PERSON 169,368, ORGANIZATION 61,651, LOCATION 32,171, ADDRESS 5,484, EMAIL 1,860, PHONE 145, ID_DOCUMENT 122, ACCOUNT_ID 79.

#### OpenPII (ai4privacy), hardening-3: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `AGE` | out | 3,566 | 0.2% | 0.2% | 3,559 | 0 |
| `AMOUNT` | out | 1 | 0.0% | 0.0% | 1 | 0 |
| `BANKNAME` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `BUILDINGNUM` | in | 3,450 | 60.3% | 60.9% | 1,349 | 21 |
| `CITY` | in | 5,075 | 76.2% | 86.7% | 673 | 534 |
| `COUNTRY` | in | 1 | 0.0% | 0.0% | 1 | 0 |
| `CREDITCARDNUMBER` | in | 2,267 | 46.5% | 46.5% | 1,213 | 1 |
| `DATE` | out | 8,572 | 6.6% | 8.7% | 7,830 | 173 |
| `DRIVERLICENSENUM` | in | 2,001 | 58.3% | 59.2% | 816 | 18 |
| `EMAIL` | in | 5,427 | 98.1% | 100.0% | 2 | 102 |
| `GENDER` | out | 1,903 | 41.7% | 43.4% | 1,078 | 31 |
| `GIVENNAME` | in | 8,489 | 88.4% | 89.6% | 880 | 108 |
| `IDCARDNUM` | in | 2,337 | 54.7% | 54.7% | 1,058 | 1 |
| `ORGANISATION` | in | 3 | 33.3% | 33.3% | 2 | 0 |
| `PASSPORTNUM` | in | 1,391 | 51.3% | 51.4% | 676 | 2 |
| `SEX` | out | 1,773 | 19.9% | 19.9% | 1,421 | 0 |
| `SOCIALNUM` | in | 1,745 | 59.0% | 60.0% | 698 | 18 |
| `STREET` | in | 3,486 | 77.1% | 83.5% | 575 | 223 |
| `SURNAME` | in | 7,287 | 90.3% | 91.9% | 588 | 120 |
| `TAXNUM` | in | 1,850 | 66.3% | 66.4% | 622 | 1 |
| `TELEPHONENUM` | in | 3,998 | 80.4% | 81.6% | 735 | 48 |
| `TIME` | out | 124 | 0.0% | 2.4% | 121 | 3 |
| `TITLE` | out | 4,705 | 49.4% | 49.9% | 2,357 | 24 |
| `ZIPCODE` | in | 3,145 | 68.6% | 68.8% | 981 | 6 |

Out of scope, all labels: 20,644 values, 19.6% fully removed, 20.7% any part.

OpenPII (ai4privacy), hardening-3: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| bg | 1,489 | 68.2% | 72.7% | 407 | 66 |
| cs | 1,340 | 75.4% | 78.8% | 284 | 46 |
| da | 1,385 | 75.5% | 76.5% | 325 | 14 |
| de | 3,444 | 79.6% | 81.5% | 638 | 66 |
| el | 1,430 | 68.4% | 70.0% | 429 | 23 |
| en | 7,137 | 79.5% | 81.3% | 1,337 | 128 |
| es | 2,806 | 87.0% | 88.4% | 326 | 40 |
| et | 1,491 | 71.9% | 75.1% | 371 | 48 |
| fi | 1,488 | 78.9% | 80.7% | 288 | 26 |
| fr | 4,272 | 80.2% | 81.3% | 800 | 44 |
| hr | 1,406 | 77.8% | 81.2% | 265 | 47 |
| hu | 1,330 | 69.4% | 71.9% | 374 | 33 |
| id | 911 | 81.8% | 84.6% | 140 | 26 |
| it | 2,966 | 76.1% | 78.3% | 642 | 66 |
| ja | 832 | 59.0% | 67.3% | 272 | 69 |
| ko | 771 | 68.1% | 71.0% | 224 | 22 |
| lt | 1,420 | 74.6% | 77.4% | 321 | 40 |
| lv | 1,433 | 69.1% | 73.1% | 385 | 58 |
| ms | 834 | 74.6% | 77.3% | 189 | 23 |
| nl | 1,477 | 81.2% | 82.3% | 262 | 15 |
| pl | 1,475 | 80.0% | 81.7% | 270 | 25 |
| pt | 1,417 | 79.3% | 80.6% | 275 | 18 |
| ro | 1,395 | 80.7% | 82.9% | 238 | 31 |
| sk | 1,428 | 76.5% | 78.1% | 313 | 22 |
| sl | 1,431 | 70.4% | 74.6% | 364 | 59 |
| sr | 1,353 | 74.9% | 76.8% | 314 | 25 |
| sv | 1,312 | 74.9% | 77.1% | 300 | 29 |
| tl | 885 | 77.0% | 79.4% | 182 | 22 |
| vi | 885 | 78.8% | 83.3% | 148 | 40 |
| zh | 710 | 69.2% | 73.7% | 187 | 32 |

OpenPII (ai4privacy), hardening-3: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 26,070 | 77.0% | 79.1% | 5,435 | 573 |
| holdout | 25,883 | 76.6% | 79.0% | 5,435 | 630 |

Collateral: 103,842 of 2,047,459 letters and digits outside the gold values were redacted (5.1%); by type: PERSON 56,459, ORGANIZATION 25,415, LOCATION 14,865, ADDRESS 5,585, EMAIL 979, ACCOUNT_ID 173, PHONE 142, ID_DOCUMENT 122.

#### Nemotron-PII (NVIDIA), 2.4.0-baseline: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `account_number` | in | 16,693 | 74.3% | 80.6% | 3,235 | 1,052 |
| `age` | out | 7,167 | 0.0% | 0.0% | 7,167 | 0 |
| `api_key` | in | 4,667 | 70.5% | 70.6% | 1,371 | 5 |
| `bank_routing_number` | in | 8,354 | 26.7% | 26.7% | 6,122 | 0 |
| `biometric_identifier` | out | 11,379 | 0.5% | 0.5% | 11,318 | 0 |
| `blood_type` | out | 5,539 | 0.9% | 1.2% | 5,475 | 16 |
| `certificate_license_number` | in | 3,002 | 7.1% | 8.8% | 2,739 | 50 |
| `city` | in | 18,347 | 85.0% | 85.5% | 2,661 | 98 |
| `company_name` | in | 54,837 | 74.7% | 76.5% | 12,905 | 961 |
| `coordinate` | out | 7,659 | 0.1% | 3.6% | 7,383 | 266 |
| `country` | in | 23,475 | 89.0% | 89.0% | 2,573 | 8 |
| `county` | in | 8,314 | 91.5% | 93.0% | 578 | 131 |
| `credit_debit_card` | in | 12,867 | 11.9% | 12.5% | 11,259 | 81 |
| `customer_id` | in | 20,502 | 73.6% | 73.6% | 5,413 | 1 |
| `cvv` | out | 4,843 | 0.1% | 0.1% | 4,840 | 0 |
| `date` | out | 73,156 | 0.5% | 1.0% | 72,452 | 330 |
| `date_of_birth` | in | 18,079 | 83.3% | 83.3% | 3,015 | 0 |
| `date_time` | out | 13,221 | 0.1% | 1.0% | 13,089 | 118 |
| `device_identifier` | in | 2,507 | 1.8% | 1.9% | 2,458 | 3 |
| `education_level` | out | 9,378 | 1.2% | 2.2% | 9,169 | 95 |
| `email` | in | 53,927 | 99.5% | 99.5% | 251 | 25 |
| `employee_id` | out | 8,878 | 0.2% | 1.2% | 8,767 | 93 |
| `employment_status` | out | 11,018 | 0.7% | 0.8% | 10,926 | 10 |
| `fax_number` | in | 6,423 | 92.5% | 92.7% | 472 | 7 |
| `first_name` | in | 84,043 | 93.9% | 94.0% | 5,062 | 56 |
| `gender` | out | 7,645 | 0.7% | 0.7% | 7,590 | 0 |
| `health_plan_beneficiary_number` | in | 10,558 | 9.3% | 11.4% | 9,356 | 222 |
| `http_cookie` | out | 4,892 | 0.1% | 72.7% | 1,337 | 3,548 |
| `ipv4` | in | 6,078 | 99.9% | 99.9% | 6 | 0 |
| `ipv6` | in | 3,139 | 90.5% | 90.6% | 296 | 1 |
| `language` | out | 8,643 | 10.1% | 10.2% | 7,764 | 10 |
| `last_name` | in | 59,596 | 94.7% | 94.7% | 3,150 | 27 |
| `license_plate` | out | 4,078 | 0.2% | 11.3% | 3,619 | 450 |
| `mac_address` | in | 4,250 | 99.9% | 99.9% | 4 | 0 |
| `medical_record_number` | in | 11,098 | 77.8% | 80.9% | 2,118 | 347 |
| `national_id` | in | 2,847 | 54.4% | 64.7% | 1,004 | 295 |
| `occupation` | out | 36,884 | 9.7% | 12.7% | 32,215 | 1,085 |
| `password` | in | 6,980 | 56.3% | 56.4% | 3,041 | 7 |
| `phone_number` | in | 23,930 | 91.0% | 91.1% | 2,119 | 30 |
| `pin` | in | 6,456 | 33.4% | 33.5% | 4,296 | 1 |
| `political_view` | out | 6,402 | 34.7% | 47.4% | 3,369 | 811 |
| `postcode` | in | 6,270 | 12.2% | 12.4% | 5,494 | 8 |
| `race_ethnicity` | out | 9,248 | 24.1% | 24.7% | 6,965 | 53 |
| `religious_belief` | out | 6,257 | 30.9% | 33.4% | 4,169 | 158 |
| `sexuality` | out | 3,312 | 1.9% | 1.9% | 3,249 | 0 |
| `ssn` | in | 6,062 | 99.7% | 99.7% | 18 | 1 |
| `state` | in | 18,279 | 81.4% | 82.4% | 3,216 | 178 |
| `street_address` | in | 16,848 | 58.5% | 85.5% | 2,444 | 4,541 |
| `swift_bic` | out | 5,559 | 3.9% | 4.0% | 5,339 | 2 |
| `tax_id` | in | 1,302 | 57.2% | 59.1% | 533 | 24 |
| `time` | out | 24,489 | 0.1% | 1.0% | 24,241 | 213 |
| `unique_id` | out | 1,777 | 8.6% | 9.4% | 1,609 | 15 |
| `url` | out | 37,847 | 3.8% | 13.8% | 32,633 | 3,766 |
| `user_name` | out | 15,800 | 17.1% | 18.5% | 12,876 | 220 |
| `vehicle_identifier` | in | 4,561 | 22.6% | 22.6% | 3,532 | 0 |

Out of scope, all labels: 325,071 values, 5.0% fully removed, 8.5% any part.

Nemotron-PII (NVIDIA), 2.4.0-baseline: in-scope values by domain

| Domain | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| Access Control Systems | 16,679 | 80.1% | 81.4% | 3,109 | 209 |
| Advertising | 15,897 | 79.5% | 80.5% | 3,095 | 164 |
| Automobile | 10,130 | 62.4% | 62.9% | 3,758 | 53 |
| Banking | 20,652 | 66.8% | 68.9% | 6,414 | 445 |
| Brokerage | 20,783 | 81.3% | 82.8% | 3,572 | 311 |
| Casualty | 20,341 | 81.2% | 82.5% | 3,567 | 253 |
| Consulting | 18,318 | 82.2% | 83.2% | 3,077 | 193 |
| Credit | 20,066 | 68.8% | 70.9% | 5,831 | 435 |
| Disability | 21,876 | 81.1% | 82.4% | 3,856 | 270 |
| Elections | 20,413 | 83.4% | 85.5% | 2,971 | 415 |
| Environmental | 16,888 | 79.8% | 81.2% | 3,168 | 237 |
| Fitness | 11,675 | 85.5% | 85.9% | 1,647 | 46 |
| Health | 22,003 | 81.2% | 82.1% | 3,943 | 199 |
| Healthcare Providers | 18,943 | 78.4% | 79.9% | 3,810 | 279 |
| Human Resources | 15,813 | 80.6% | 81.7% | 2,893 | 169 |
| Information Technology | 15,578 | 76.1% | 76.4% | 3,668 | 56 |
| Insurance | 16,695 | 75.5% | 76.6% | 3,900 | 188 |
| Investment | 17,449 | 81.7% | 83.1% | 2,945 | 255 |
| Life | 20,952 | 82.0% | 83.6% | 3,427 | 354 |
| Marketing | 19,974 | 81.9% | 83.5% | 3,301 | 319 |
| Mortgage | 24,130 | 77.9% | 82.6% | 4,190 | 1,150 |
| Product | 17,348 | 85.2% | 85.6% | 2,497 | 79 |
| Property | 18,072 | 74.8% | 80.3% | 3,555 | 1,002 |
| Public Safety | 14,306 | 76.3% | 78.3% | 3,110 | 283 |
| Services | 18,597 | 82.1% | 83.0% | 3,156 | 170 |
| Social Science | 16,516 | 85.0% | 85.7% | 2,356 | 114 |
| Sports | 17,952 | 84.9% | 85.8% | 2,549 | 163 |
| Travel | 18,951 | 80.6% | 81.2% | 3,565 | 106 |
| User Account and Transaction Services | 17,294 | 76.6% | 78.0% | 3,811 | 243 |

Nemotron-PII (NVIDIA), 2.4.0-baseline: in-scope values by document format

| Document format | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| structured | 284,191 | 76.1% | 77.6% | 63,518 | 4,455 |
| unstructured | 240,100 | 83.0% | 84.5% | 37,223 | 3,705 |

Nemotron-PII (NVIDIA), 2.4.0-baseline: in-scope values by locale

| Locale | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| intl | 261,673 | 78.8% | 80.8% | 50,211 | 5,393 |
| us | 262,618 | 79.7% | 80.8% | 50,530 | 2,767 |

Nemotron-PII (NVIDIA), 2.4.0-baseline: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 259,214 | 79.1% | 80.7% | 49,957 | 4,083 |
| holdout | 265,077 | 79.3% | 80.8% | 50,784 | 4,077 |

Collateral: 2,387,299 of 60,434,228 letters and digits outside the gold values were redacted (4.0%); by type: ORGANIZATION 1,263,598, PERSON 1,016,354, LOCATION 79,400, SECRET 9,473, ACCOUNT_ID 6,820, US_SSN 3,880, IP_ADDRESS 2,242, EMAIL 1,871.

#### Nemotron-PII (NVIDIA), hardening-1: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `account_number` | in | 16,693 | 74.3% | 80.6% | 3,234 | 1,052 |
| `age` | out | 7,167 | 0.0% | 0.0% | 7,167 | 0 |
| `api_key` | in | 4,667 | 87.4% | 87.5% | 582 | 4 |
| `bank_routing_number` | in | 8,354 | 26.7% | 26.7% | 6,122 | 0 |
| `biometric_identifier` | out | 11,379 | 0.5% | 0.5% | 11,319 | 0 |
| `blood_type` | out | 5,539 | 0.6% | 0.9% | 5,490 | 16 |
| `certificate_license_number` | in | 3,002 | 7.1% | 8.8% | 2,739 | 50 |
| `city` | in | 18,347 | 84.9% | 85.5% | 2,670 | 98 |
| `company_name` | in | 54,837 | 74.7% | 76.4% | 12,925 | 963 |
| `coordinate` | out | 7,659 | 0.1% | 3.6% | 7,383 | 266 |
| `country` | in | 23,475 | 89.0% | 89.0% | 2,576 | 8 |
| `county` | in | 8,314 | 91.5% | 93.0% | 578 | 131 |
| `credit_debit_card` | in | 12,867 | 11.9% | 12.5% | 11,258 | 82 |
| `customer_id` | in | 20,502 | 73.6% | 73.6% | 5,413 | 1 |
| `cvv` | out | 4,843 | 0.1% | 0.1% | 4,840 | 0 |
| `date` | out | 73,156 | 0.5% | 0.9% | 72,459 | 327 |
| `date_of_birth` | in | 18,079 | 83.3% | 83.3% | 3,015 | 0 |
| `date_time` | out | 13,221 | 0.1% | 1.0% | 13,085 | 119 |
| `device_identifier` | in | 2,507 | 1.8% | 1.9% | 2,459 | 3 |
| `education_level` | out | 9,378 | 1.1% | 2.2% | 9,174 | 96 |
| `email` | in | 53,927 | 99.5% | 99.5% | 254 | 25 |
| `employee_id` | out | 8,878 | 0.2% | 1.2% | 8,767 | 93 |
| `employment_status` | out | 11,018 | 0.7% | 0.8% | 10,930 | 10 |
| `fax_number` | in | 6,423 | 92.5% | 92.7% | 472 | 7 |
| `first_name` | in | 84,043 | 93.6% | 93.7% | 5,315 | 56 |
| `gender` | out | 7,645 | 0.7% | 0.7% | 7,594 | 0 |
| `health_plan_beneficiary_number` | in | 10,558 | 9.3% | 11.4% | 9,356 | 222 |
| `http_cookie` | out | 4,892 | 0.4% | 52.4% | 2,328 | 2,546 |
| `ipv4` | in | 6,078 | 99.9% | 99.9% | 6 | 0 |
| `ipv6` | in | 3,139 | 90.5% | 90.6% | 296 | 1 |
| `language` | out | 8,643 | 10.0% | 10.2% | 7,766 | 10 |
| `last_name` | in | 59,596 | 94.4% | 94.5% | 3,292 | 27 |
| `license_plate` | out | 4,078 | 0.2% | 11.3% | 3,619 | 450 |
| `mac_address` | in | 4,250 | 99.9% | 99.9% | 4 | 0 |
| `medical_record_number` | in | 11,098 | 77.8% | 80.9% | 2,118 | 347 |
| `national_id` | in | 2,847 | 54.4% | 64.7% | 1,005 | 294 |
| `occupation` | out | 36,884 | 9.6% | 12.5% | 32,278 | 1,083 |
| `password` | in | 6,980 | 79.3% | 79.4% | 1,438 | 4 |
| `phone_number` | in | 23,930 | 91.0% | 91.1% | 2,119 | 30 |
| `pin` | in | 6,456 | 33.5% | 33.5% | 4,294 | 1 |
| `political_view` | out | 6,402 | 34.7% | 47.4% | 3,369 | 812 |
| `postcode` | in | 6,270 | 12.2% | 12.4% | 5,494 | 8 |
| `race_ethnicity` | out | 9,248 | 24.1% | 24.6% | 6,968 | 52 |
| `religious_belief` | out | 6,257 | 30.9% | 33.4% | 4,169 | 158 |
| `sexuality` | out | 3,312 | 1.9% | 1.9% | 3,249 | 0 |
| `ssn` | in | 6,062 | 99.7% | 99.7% | 18 | 1 |
| `state` | in | 18,279 | 81.4% | 82.4% | 3,221 | 178 |
| `street_address` | in | 16,848 | 58.5% | 85.5% | 2,450 | 4,535 |
| `swift_bic` | out | 5,559 | 3.9% | 4.0% | 5,339 | 2 |
| `tax_id` | in | 1,302 | 57.2% | 59.1% | 533 | 24 |
| `time` | out | 24,489 | 0.1% | 1.0% | 24,250 | 209 |
| `unique_id` | out | 1,777 | 9.0% | 9.8% | 1,602 | 15 |
| `url` | out | 37,847 | 0.1% | 9.8% | 34,126 | 3,699 |
| `user_name` | out | 15,800 | 11.3% | 12.8% | 13,784 | 226 |
| `vehicle_identifier` | in | 4,561 | 22.6% | 22.6% | 3,532 | 0 |

Out of scope, all labels: 325,071 values, 4.2% fully removed, 7.4% any part.

Nemotron-PII (NVIDIA), hardening-1: in-scope values by domain

| Domain | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| Access Control Systems | 16,679 | 81.9% | 83.2% | 2,811 | 208 |
| Advertising | 15,897 | 79.7% | 80.7% | 3,062 | 166 |
| Automobile | 10,130 | 62.4% | 62.9% | 3,761 | 53 |
| Banking | 20,652 | 67.0% | 69.2% | 6,362 | 445 |
| Brokerage | 20,783 | 81.5% | 83.0% | 3,524 | 311 |
| Casualty | 20,341 | 81.3% | 82.5% | 3,557 | 253 |
| Consulting | 18,318 | 82.4% | 83.5% | 3,023 | 194 |
| Credit | 20,066 | 68.8% | 71.0% | 5,817 | 434 |
| Disability | 21,876 | 81.2% | 82.4% | 3,852 | 270 |
| Elections | 20,413 | 83.3% | 85.3% | 2,999 | 413 |
| Environmental | 16,888 | 79.8% | 81.2% | 3,170 | 237 |
| Fitness | 11,675 | 85.8% | 86.2% | 1,615 | 46 |
| Health | 22,003 | 81.2% | 82.1% | 3,940 | 199 |
| Healthcare Providers | 18,943 | 78.4% | 79.8% | 3,820 | 278 |
| Human Resources | 15,813 | 80.5% | 81.6% | 2,910 | 169 |
| Information Technology | 15,578 | 80.8% | 81.2% | 2,936 | 54 |
| Insurance | 16,695 | 75.6% | 76.7% | 3,891 | 188 |
| Investment | 17,449 | 81.8% | 83.3% | 2,921 | 255 |
| Life | 20,952 | 82.0% | 83.7% | 3,426 | 354 |
| Marketing | 19,974 | 82.1% | 83.7% | 3,264 | 318 |
| Mortgage | 24,130 | 77.9% | 82.7% | 4,183 | 1,150 |
| Product | 17,348 | 86.0% | 86.5% | 2,351 | 79 |
| Property | 18,072 | 74.8% | 80.3% | 3,555 | 999 |
| Public Safety | 14,306 | 76.3% | 78.3% | 3,106 | 283 |
| Services | 18,597 | 82.4% | 83.3% | 3,103 | 170 |
| Social Science | 16,516 | 85.2% | 85.9% | 2,326 | 114 |
| Sports | 17,952 | 84.9% | 85.8% | 2,548 | 163 |
| Travel | 18,951 | 80.8% | 81.4% | 3,525 | 106 |
| User Account and Transaction Services | 17,294 | 78.8% | 80.2% | 3,430 | 243 |

Nemotron-PII (NVIDIA), hardening-1: in-scope values by document format

| Document format | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| structured | 284,191 | 76.4% | 78.0% | 62,638 | 4,447 |
| unstructured | 240,100 | 83.4% | 84.9% | 36,150 | 3,705 |

Nemotron-PII (NVIDIA), hardening-1: in-scope values by locale

| Locale | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| intl | 261,673 | 79.1% | 81.2% | 49,206 | 5,384 |
| us | 262,618 | 80.1% | 81.1% | 49,582 | 2,768 |

Nemotron-PII (NVIDIA), hardening-1: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 259,214 | 79.5% | 81.1% | 49,018 | 4,081 |
| holdout | 265,077 | 79.7% | 81.2% | 49,770 | 4,071 |

Collateral: 2,343,494 of 60,434,228 letters and digits outside the gold values were redacted (3.9%); by type: ORGANIZATION 1,235,370, PERSON 1,001,238, LOCATION 78,554, SECRET 10,257, ACCOUNT_ID 6,820, US_SSN 3,880, IP_ADDRESS 2,242, EMAIL 1,626.

#### Nemotron-PII (NVIDIA), hardening-2: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `account_number` | in | 16,693 | 98.4% | 98.6% | 239 | 25 |
| `age` | out | 7,167 | 0.2% | 0.2% | 7,151 | 0 |
| `api_key` | in | 4,667 | 94.4% | 94.5% | 257 | 3 |
| `bank_routing_number` | in | 8,354 | 98.4% | 98.4% | 134 | 0 |
| `biometric_identifier` | out | 11,379 | 3.4% | 3.5% | 10,985 | 8 |
| `blood_type` | out | 5,539 | 0.7% | 1.0% | 5,485 | 16 |
| `certificate_license_number` | in | 3,002 | 96.9% | 96.9% | 92 | 1 |
| `city` | in | 18,347 | 94.3% | 94.6% | 987 | 67 |
| `company_name` | in | 54,837 | 77.6% | 79.8% | 11,096 | 1,188 |
| `coordinate` | out | 7,659 | 3.4% | 6.8% | 7,138 | 260 |
| `country` | in | 23,475 | 95.3% | 95.3% | 1,100 | 8 |
| `county` | in | 8,314 | 93.0% | 94.3% | 477 | 108 |
| `credit_debit_card` | in | 12,867 | 96.9% | 97.0% | 388 | 7 |
| `customer_id` | in | 20,502 | 96.9% | 96.9% | 635 | 2 |
| `cvv` | out | 4,843 | 77.6% | 77.6% | 1,083 | 0 |
| `date` | out | 73,156 | 0.7% | 1.2% | 72,290 | 340 |
| `date_of_birth` | in | 18,079 | 97.8% | 97.8% | 404 | 0 |
| `date_time` | out | 13,221 | 0.2% | 2.8% | 12,848 | 345 |
| `device_identifier` | in | 2,507 | 84.4% | 84.4% | 392 | 0 |
| `education_level` | out | 9,378 | 1.3% | 2.4% | 9,156 | 99 |
| `email` | in | 53,927 | 99.5% | 99.5% | 254 | 25 |
| `employee_id` | out | 8,878 | 91.3% | 91.6% | 749 | 25 |
| `employment_status` | out | 11,018 | 1.0% | 1.1% | 10,896 | 11 |
| `fax_number` | in | 6,423 | 99.5% | 99.6% | 28 | 4 |
| `first_name` | in | 84,043 | 97.6% | 97.7% | 1,957 | 47 |
| `gender` | out | 7,645 | 0.7% | 0.7% | 7,589 | 0 |
| `health_plan_beneficiary_number` | in | 10,558 | 97.2% | 97.3% | 283 | 9 |
| `http_cookie` | out | 4,892 | 0.4% | 52.5% | 2,324 | 2,549 |
| `ipv4` | in | 6,078 | 99.9% | 99.9% | 6 | 0 |
| `ipv6` | in | 3,139 | 90.6% | 90.6% | 294 | 1 |
| `language` | out | 8,643 | 10.2% | 10.3% | 7,750 | 10 |
| `last_name` | in | 59,596 | 98.3% | 98.3% | 1,008 | 17 |
| `license_plate` | out | 4,078 | 91.1% | 93.2% | 278 | 85 |
| `mac_address` | in | 4,250 | 99.9% | 99.9% | 3 | 0 |
| `medical_record_number` | in | 11,098 | 96.0% | 99.1% | 96 | 354 |
| `national_id` | in | 2,847 | 93.9% | 97.3% | 78 | 96 |
| `occupation` | out | 36,884 | 9.8% | 12.8% | 32,159 | 1,095 |
| `password` | in | 6,980 | 89.6% | 89.7% | 717 | 8 |
| `phone_number` | in | 23,930 | 98.7% | 98.7% | 307 | 9 |
| `pin` | in | 6,456 | 90.1% | 90.1% | 637 | 1 |
| `political_view` | out | 6,402 | 34.9% | 47.5% | 3,362 | 808 |
| `postcode` | in | 6,270 | 90.6% | 91.0% | 567 | 20 |
| `race_ethnicity` | out | 9,248 | 24.4% | 24.9% | 6,943 | 52 |
| `religious_belief` | out | 6,257 | 31.1% | 33.5% | 4,160 | 154 |
| `sexuality` | out | 3,312 | 2.0% | 2.0% | 3,245 | 0 |
| `ssn` | in | 6,062 | 100.0% | 100.0% | 1 | 0 |
| `state` | in | 18,279 | 89.3% | 90.2% | 1,794 | 159 |
| `street_address` | in | 16,848 | 91.0% | 96.7% | 560 | 963 |
| `swift_bic` | out | 5,559 | 6.1% | 6.1% | 5,219 | 2 |
| `tax_id` | in | 1,302 | 97.9% | 98.4% | 21 | 7 |
| `time` | out | 24,489 | 0.2% | 1.1% | 24,224 | 211 |
| `unique_id` | out | 1,777 | 30.2% | 30.2% | 1,240 | 1 |
| `url` | out | 37,847 | 0.1% | 10.4% | 33,918 | 3,907 |
| `user_name` | out | 15,800 | 26.2% | 27.4% | 11,465 | 199 |
| `vehicle_identifier` | in | 4,561 | 96.8% | 97.5% | 115 | 30 |

Out of scope, all labels: 325,071 values, 10.2% fully removed, 13.4% any part.

Nemotron-PII (NVIDIA), hardening-2: in-scope values by domain

| Domain | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| Access Control Systems | 16,679 | 96.8% | 97.1% | 484 | 47 |
| Advertising | 15,897 | 89.9% | 90.7% | 1,477 | 128 |
| Automobile | 10,130 | 95.3% | 95.7% | 433 | 43 |
| Banking | 20,652 | 96.2% | 96.5% | 730 | 55 |
| Brokerage | 20,783 | 94.9% | 95.2% | 1,007 | 56 |
| Casualty | 20,341 | 96.5% | 97.1% | 591 | 119 |
| Consulting | 18,318 | 92.8% | 93.6% | 1,176 | 137 |
| Credit | 20,066 | 97.3% | 97.5% | 493 | 41 |
| Disability | 21,876 | 97.9% | 98.5% | 328 | 126 |
| Elections | 20,413 | 95.1% | 95.7% | 886 | 123 |
| Environmental | 16,888 | 88.2% | 89.1% | 1,842 | 151 |
| Fitness | 11,675 | 96.9% | 97.0% | 349 | 17 |
| Health | 22,003 | 97.7% | 98.3% | 370 | 130 |
| Healthcare Providers | 18,943 | 95.9% | 96.8% | 603 | 169 |
| Human Resources | 15,813 | 90.4% | 91.4% | 1,359 | 156 |
| Information Technology | 15,578 | 92.7% | 93.0% | 1,087 | 51 |
| Insurance | 16,695 | 94.4% | 94.8% | 870 | 66 |
| Investment | 17,449 | 95.1% | 95.5% | 793 | 63 |
| Life | 20,952 | 97.9% | 98.2% | 368 | 69 |
| Marketing | 19,974 | 90.0% | 91.4% | 1,711 | 291 |
| Mortgage | 24,130 | 93.8% | 94.8% | 1,252 | 244 |
| Product | 17,348 | 94.9% | 95.1% | 843 | 38 |
| Property | 18,072 | 94.1% | 95.7% | 786 | 275 |
| Public Safety | 14,306 | 92.7% | 93.8% | 893 | 157 |
| Services | 18,597 | 94.0% | 94.8% | 969 | 144 |
| Social Science | 16,516 | 94.4% | 94.8% | 851 | 67 |
| Sports | 17,952 | 93.8% | 94.3% | 1,020 | 99 |
| Travel | 18,951 | 96.0% | 96.2% | 715 | 40 |
| User Account and Transaction Services | 17,294 | 96.0% | 96.3% | 641 | 57 |

Nemotron-PII (NVIDIA), hardening-2: in-scope values by document format

| Document format | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| structured | 284,191 | 94.0% | 94.7% | 15,056 | 1,988 |
| unstructured | 240,100 | 95.4% | 95.9% | 9,871 | 1,171 |

Nemotron-PII (NVIDIA), hardening-2: in-scope values by locale

| Locale | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| intl | 261,673 | 94.4% | 95.2% | 12,654 | 1,995 |
| us | 262,618 | 94.9% | 95.3% | 12,273 | 1,164 |

Nemotron-PII (NVIDIA), hardening-2: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 259,214 | 94.7% | 95.3% | 12,274 | 1,539 |
| holdout | 265,077 | 94.6% | 95.2% | 12,653 | 1,620 |

Collateral: 2,460,352 of 60,434,228 letters and digits outside the gold values were redacted (4.1%); by type: ORGANIZATION 1,225,668, PERSON 1,039,506, LOCATION 77,837, ADDRESS 58,348, ACCOUNT_ID 29,758, SECRET 11,021, US_SSN 4,791, PHONE 3,141.

#### Nemotron-PII (NVIDIA), hardening-3: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `account_number` | in | 16,693 | 98.6% | 98.7% | 219 | 12 |
| `age` | out | 7,167 | 0.3% | 0.3% | 7,148 | 0 |
| `api_key` | in | 4,667 | 94.5% | 94.6% | 254 | 4 |
| `bank_routing_number` | in | 8,354 | 97.8% | 97.8% | 183 | 0 |
| `biometric_identifier` | out | 11,379 | 77.1% | 77.1% | 2,607 | 2 |
| `blood_type` | out | 5,539 | 0.4% | 0.4% | 5,514 | 3 |
| `certificate_license_number` | in | 3,002 | 96.9% | 96.9% | 92 | 1 |
| `city` | in | 18,347 | 94.2% | 94.6% | 996 | 65 |
| `company_name` | in | 54,837 | 77.8% | 79.9% | 11,013 | 1,136 |
| `coordinate` | out | 7,659 | 3.5% | 6.8% | 7,136 | 259 |
| `country` | in | 23,475 | 95.2% | 95.2% | 1,122 | 6 |
| `county` | in | 8,314 | 92.5% | 93.7% | 524 | 100 |
| `credit_debit_card` | in | 12,867 | 96.8% | 96.8% | 406 | 7 |
| `customer_id` | in | 20,502 | 97.1% | 97.1% | 602 | 1 |
| `cvv` | out | 4,843 | 88.8% | 88.8% | 542 | 0 |
| `date` | out | 73,156 | 0.5% | 0.6% | 72,733 | 45 |
| `date_of_birth` | in | 18,079 | 97.8% | 97.8% | 403 | 1 |
| `date_time` | out | 13,221 | 0.2% | 3.5% | 12,762 | 434 |
| `device_identifier` | in | 2,507 | 89.0% | 89.0% | 276 | 0 |
| `education_level` | out | 9,378 | 1.1% | 1.9% | 9,204 | 73 |
| `email` | in | 53,927 | 99.5% | 99.5% | 277 | 7 |
| `employee_id` | out | 8,878 | 91.5% | 91.6% | 747 | 9 |
| `employment_status` | out | 11,018 | 0.6% | 0.6% | 10,949 | 6 |
| `fax_number` | in | 6,423 | 99.5% | 99.6% | 28 | 4 |
| `first_name` | in | 84,043 | 97.7% | 97.8% | 1,874 | 33 |
| `gender` | out | 7,645 | 0.5% | 0.5% | 7,607 | 0 |
| `health_plan_beneficiary_number` | in | 10,558 | 97.3% | 97.4% | 276 | 9 |
| `http_cookie` | out | 4,892 | 0.4% | 30.5% | 3,399 | 1,476 |
| `ipv4` | in | 6,078 | 99.9% | 99.9% | 6 | 0 |
| `ipv6` | in | 3,139 | 90.6% | 90.6% | 295 | 0 |
| `language` | out | 8,643 | 10.2% | 10.3% | 7,754 | 10 |
| `last_name` | in | 59,596 | 98.4% | 98.4% | 938 | 14 |
| `license_plate` | out | 4,078 | 95.8% | 97.0% | 122 | 51 |
| `mac_address` | in | 4,250 | 99.9% | 99.9% | 3 | 0 |
| `medical_record_number` | in | 11,098 | 97.8% | 99.1% | 95 | 154 |
| `national_id` | in | 2,847 | 93.3% | 97.3% | 77 | 114 |
| `occupation` | out | 36,884 | 6.9% | 8.5% | 33,745 | 594 |
| `password` | in | 6,980 | 89.5% | 89.6% | 725 | 7 |
| `phone_number` | in | 23,930 | 98.7% | 98.7% | 307 | 9 |
| `pin` | in | 6,456 | 90.0% | 90.0% | 645 | 1 |
| `political_view` | out | 6,402 | 33.7% | 43.6% | 3,612 | 631 |
| `postcode` | in | 6,270 | 91.2% | 91.4% | 539 | 10 |
| `race_ethnicity` | out | 9,248 | 24.3% | 24.8% | 6,951 | 51 |
| `religious_belief` | out | 6,257 | 31.1% | 33.6% | 4,157 | 154 |
| `sexuality` | out | 3,312 | 0.5% | 0.5% | 3,295 | 0 |
| `ssn` | in | 6,062 | 100.0% | 100.0% | 1 | 0 |
| `state` | in | 18,279 | 89.1% | 89.9% | 1,853 | 137 |
| `street_address` | in | 16,848 | 92.5% | 97.2% | 481 | 789 |
| `swift_bic` | out | 5,559 | 80.8% | 80.8% | 1,065 | 3 |
| `tax_id` | in | 1,302 | 97.5% | 98.4% | 21 | 12 |
| `time` | out | 24,489 | 0.2% | 0.3% | 24,422 | 16 |
| `unique_id` | out | 1,777 | 35.1% | 35.1% | 1,153 | 1 |
| `url` | out | 37,847 | 0.1% | 10.3% | 33,940 | 3,885 |
| `user_name` | out | 15,800 | 21.2% | 22.9% | 12,174 | 280 |
| `vehicle_identifier` | in | 4,561 | 97.4% | 98.1% | 88 | 30 |

Out of scope, all labels: 325,071 values, 13.6% fully removed, 16.1% any part.

Nemotron-PII (NVIDIA), hardening-3: in-scope values by domain

| Domain | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| Access Control Systems | 16,679 | 97.1% | 97.3% | 450 | 34 |
| Advertising | 15,897 | 90.0% | 90.5% | 1,504 | 94 |
| Automobile | 10,130 | 95.6% | 96.0% | 410 | 40 |
| Banking | 20,652 | 96.2% | 96.4% | 750 | 42 |
| Brokerage | 20,783 | 95.0% | 95.3% | 973 | 59 |
| Casualty | 20,341 | 96.8% | 97.3% | 544 | 100 |
| Consulting | 18,318 | 92.8% | 93.5% | 1,199 | 118 |
| Credit | 20,066 | 97.4% | 97.6% | 474 | 40 |
| Disability | 21,876 | 98.2% | 98.6% | 305 | 77 |
| Elections | 20,413 | 95.0% | 95.6% | 902 | 108 |
| Environmental | 16,888 | 88.2% | 89.0% | 1,851 | 147 |
| Fitness | 11,675 | 96.8% | 97.0% | 353 | 17 |
| Health | 22,003 | 98.1% | 98.4% | 359 | 56 |
| Healthcare Providers | 18,943 | 96.2% | 96.9% | 587 | 129 |
| Human Resources | 15,813 | 90.2% | 91.3% | 1,382 | 162 |
| Information Technology | 15,578 | 93.1% | 93.4% | 1,033 | 48 |
| Insurance | 16,695 | 94.5% | 94.8% | 869 | 57 |
| Investment | 17,449 | 95.0% | 95.3% | 811 | 60 |
| Life | 20,952 | 97.9% | 98.2% | 379 | 52 |
| Marketing | 19,974 | 90.0% | 91.4% | 1,721 | 278 |
| Mortgage | 24,130 | 94.4% | 95.0% | 1,196 | 165 |
| Product | 17,348 | 94.9% | 95.1% | 845 | 37 |
| Property | 18,072 | 95.0% | 96.2% | 686 | 218 |
| Public Safety | 14,306 | 93.1% | 94.1% | 844 | 140 |
| Services | 18,597 | 94.1% | 94.8% | 957 | 146 |
| Social Science | 16,516 | 94.2% | 94.6% | 898 | 69 |
| Sports | 17,952 | 93.7% | 94.2% | 1,039 | 91 |
| Travel | 18,951 | 96.0% | 96.2% | 728 | 28 |
| User Account and Transaction Services | 17,294 | 96.4% | 96.7% | 570 | 51 |

Nemotron-PII (NVIDIA), hardening-3: in-scope values by document format

| Document format | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| structured | 284,191 | 94.2% | 94.8% | 14,809 | 1,568 |
| unstructured | 240,100 | 95.5% | 95.9% | 9,810 | 1,095 |

Nemotron-PII (NVIDIA), hardening-3: in-scope values by locale

| Locale | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| intl | 261,673 | 94.6% | 95.2% | 12,483 | 1,762 |
| us | 262,618 | 95.0% | 95.4% | 12,136 | 901 |

Nemotron-PII (NVIDIA), hardening-3: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 259,214 | 94.8% | 95.3% | 12,136 | 1,293 |
| holdout | 265,077 | 94.8% | 95.3% | 12,483 | 1,370 |

Collateral: 1,416,179 of 60,434,228 letters and digits outside the gold values were redacted (2.3%); by type: ORGANIZATION 770,938, PERSON 477,511, ADDRESS 58,731, LOCATION 43,845, ACCOUNT_ID 35,716, SECRET 10,949, US_SSN 4,804, PHONE 3,181.

#### RedactionBench, 2.4.0-baseline: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `contextual` | out | 15,982 | 39.5% | 45.3% | 8,737 | 936 |
| `mandatory` | in | 16,988 | 74.0% | 74.5% | 4,329 | 96 |

Out of scope, all labels: 15,982 values, 39.5% fully removed, 45.3% any part.

RedactionBench, 2.4.0-baseline: in-scope values by category

| Category | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| academic | 272 | 77.9% | 78.3% | 59 | 1 |
| code | 270 | 59.6% | 61.5% | 104 | 5 |
| emails | 482 | 69.7% | 69.7% | 146 | 0 |
| files | 4,360 | 65.0% | 65.7% | 1,497 | 28 |
| financial | 596 | 69.0% | 69.3% | 183 | 2 |
| government | 744 | 71.9% | 72.5% | 205 | 4 |
| legal | 607 | 81.9% | 82.7% | 105 | 5 |
| logs | 8,339 | 78.4% | 78.9% | 1,756 | 47 |
| medical | 308 | 79.2% | 79.2% | 64 | 0 |
| operations | 328 | 75.3% | 75.9% | 79 | 2 |
| terminal | 682 | 80.5% | 80.8% | 131 | 2 |

RedactionBench, 2.4.0-baseline: in-scope values by synthetic or real

| Synthetic or real | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| False | 2,858 | 75.1% | 75.6% | 698 | 14 |
| True | 14,130 | 73.7% | 74.3% | 3,631 | 82 |

RedactionBench, 2.4.0-baseline: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 9,599 | 69.0% | 69.1% | 2,964 | 15 |
| holdout | 7,389 | 80.4% | 81.5% | 1,365 | 81 |

Collateral: 150,741 of 1,584,856 letters and digits outside the gold values were redacted (9.5%); by type: ORGANIZATION 70,340, PERSON 59,205, LOCATION 10,134, EMAIL 5,987, SECRET 2,822, PHONE 874, ACCOUNT_ID 581, IP_ADDRESS 458.

#### RedactionBench, hardening-1: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `contextual` | out | 15,982 | 38.9% | 44.7% | 8,839 | 931 |
| `mandatory` | in | 16,988 | 74.0% | 74.6% | 4,309 | 109 |

Out of scope, all labels: 15,982 values, 38.9% fully removed, 44.7% any part.

RedactionBench, hardening-1: in-scope values by category

| Category | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| academic | 272 | 77.9% | 78.3% | 59 | 1 |
| code | 270 | 61.5% | 63.3% | 99 | 5 |
| emails | 482 | 69.9% | 69.9% | 145 | 0 |
| files | 4,360 | 65.0% | 65.6% | 1,500 | 26 |
| financial | 596 | 69.0% | 69.3% | 183 | 2 |
| government | 744 | 71.9% | 72.5% | 205 | 4 |
| legal | 607 | 81.9% | 82.7% | 105 | 5 |
| logs | 8,339 | 78.3% | 79.1% | 1,745 | 63 |
| medical | 308 | 79.2% | 79.2% | 64 | 0 |
| operations | 328 | 75.3% | 75.9% | 79 | 2 |
| terminal | 682 | 81.5% | 81.7% | 125 | 1 |

RedactionBench, hardening-1: in-scope values by synthetic or real

| Synthetic or real | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| False | 2,858 | 75.1% | 75.6% | 698 | 14 |
| True | 14,130 | 73.8% | 74.4% | 3,611 | 95 |

RedactionBench, hardening-1: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 9,599 | 69.3% | 69.4% | 2,933 | 14 |
| holdout | 7,389 | 80.1% | 81.4% | 1,376 | 95 |

Collateral: 140,626 of 1,584,856 letters and digits outside the gold values were redacted (8.9%); by type: ORGANIZATION 64,710, PERSON 53,813, LOCATION 9,414, EMAIL 5,972, SECRET 4,464, PHONE 874, ACCOUNT_ID 581, IP_ADDRESS 458.

#### RedactionBench, hardening-2: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `contextual` | out | 15,982 | 41.3% | 47.5% | 8,386 | 1,002 |
| `mandatory` | in | 16,988 | 88.1% | 88.7% | 1,916 | 108 |

Out of scope, all labels: 15,982 values, 41.3% fully removed, 47.5% any part.

RedactionBench, hardening-2: in-scope values by category

| Category | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| academic | 272 | 92.7% | 93.0% | 19 | 1 |
| code | 270 | 63.3% | 65.2% | 94 | 5 |
| emails | 482 | 75.5% | 75.5% | 118 | 0 |
| files | 4,360 | 80.1% | 80.7% | 842 | 25 |
| financial | 596 | 79.4% | 79.9% | 120 | 3 |
| government | 744 | 79.7% | 80.2% | 147 | 4 |
| legal | 607 | 86.2% | 87.0% | 79 | 5 |
| logs | 8,339 | 95.7% | 96.4% | 300 | 63 |
| medical | 308 | 83.8% | 83.8% | 50 | 0 |
| operations | 328 | 79.6% | 79.9% | 66 | 1 |
| terminal | 682 | 88.0% | 88.1% | 81 | 1 |

RedactionBench, hardening-2: in-scope values by synthetic or real

| Synthetic or real | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| False | 2,858 | 82.6% | 83.1% | 484 | 14 |
| True | 14,130 | 89.2% | 89.9% | 1,432 | 94 |

RedactionBench, hardening-2: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 9,599 | 91.5% | 91.6% | 808 | 11 |
| holdout | 7,389 | 83.7% | 85.0% | 1,108 | 97 |

Collateral: 144,914 of 1,584,856 letters and digits outside the gold values were redacted (9.1%); by type: ORGANIZATION 63,912, PERSON 54,657, LOCATION 9,372, EMAIL 5,333, ACCOUNT_ID 5,096, SECRET 4,629, PHONE 882, IP_ADDRESS 458.

#### RedactionBench, hardening-3: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `contextual` | out | 15,982 | 40.2% | 42.5% | 9,186 | 363 |
| `mandatory` | in | 16,988 | 88.0% | 88.6% | 1,941 | 105 |

Out of scope, all labels: 15,982 values, 40.2% fully removed, 42.5% any part.

RedactionBench, hardening-3: in-scope values by category

| Category | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| academic | 272 | 92.7% | 92.7% | 20 | 0 |
| code | 270 | 63.3% | 65.2% | 94 | 5 |
| emails | 482 | 76.8% | 76.8% | 112 | 0 |
| files | 4,360 | 81.8% | 82.4% | 769 | 25 |
| financial | 596 | 83.0% | 83.2% | 100 | 1 |
| government | 744 | 82.3% | 82.7% | 129 | 3 |
| legal | 607 | 87.5% | 88.3% | 71 | 5 |
| logs | 8,339 | 93.3% | 94.0% | 496 | 64 |
| medical | 308 | 89.6% | 89.6% | 32 | 0 |
| operations | 328 | 79.3% | 79.6% | 67 | 1 |
| terminal | 682 | 92.4% | 92.5% | 51 | 1 |

RedactionBench, hardening-3: in-scope values by synthetic or real

| Synthetic or real | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| False | 2,858 | 84.9% | 85.2% | 422 | 10 |
| True | 14,130 | 88.6% | 89.2% | 1,519 | 95 |

RedactionBench, hardening-3: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 9,599 | 93.0% | 93.2% | 658 | 10 |
| holdout | 7,389 | 81.3% | 82.6% | 1,283 | 95 |

Collateral: 56,891 of 1,584,856 letters and digits outside the gold values were redacted (3.6%); by type: ORGANIZATION 25,987, PERSON 10,226, EMAIL 5,621, ACCOUNT_ID 5,464, SECRET 3,927, LOCATION 3,659, PHONE 873, IP_ADDRESS 458.

#### ProwlBench, 2.4.0-baseline: its own metric (a snippet counts as detected when a secret is flagged in it)

| Tool | Precision | Recall | F1 | Accuracy | T1 recall | T2 recall | T3 recall | T4 false-alarm rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Harpo, all cases | 0.935 | 0.753 | 0.834 | 0.799 | 0.873 | 0.691 | 0.649 | 0.107 |
| Harpo, dev half | 0.936 | 0.763 | 0.841 | 0.806 | 0.879 | 0.706 | 0.661 | 0.106 |
| Harpo, holdout half | 0.934 | 0.743 | 0.828 | 0.791 | 0.866 | 0.677 | 0.637 | 0.108 |
| gitleaks 8.30.1 (run here) | 0.931 | 0.413 | 0.573 | 0.585 | 0.653 | 0.355 | 0.167 | 0.063 |

Recall by language and by source (Harpo, all cases):

| de | en | es | fr | it | ja | non-en | ru | zh |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.527 (408) | 0.756 (11,430) | 0.798 (387) | 0.706 (1,536) | 0.887 (151) | 0.766 (688) | 0.878 (654) | 0.802 (663) | 0.707 (635) |

| code | confluence | jira | log | slack |
| --- | --- | --- | --- | --- |
| 0.747 (6,693) | 0.708 (2,643) | 0.764 (2,990) | 0.770 (2,458) | 0.800 (1,768) |

False alarms on the hard negatives, by whether the snippet assigns a value to a credential-named field:

| Negatives | Cases | False-alarm rate |
| --- | --- | --- |
| credential named | 541 | 0.664 |
| other | 7,510 | 0.067 |

<details><summary>Recall per secret type, false-alarm rate per negative type</summary>

| Secret type | Cases | Recall |
| --- | --- | --- |
| anthropic_api_key | 244 | 1.000 |
| aws_access_key_id | 280 | 0.946 |
| aws_secret_access_key | 200 | 0.710 |
| azure_storage_key | 286 | 0.951 |
| basic_auth_header | 660 | 0.859 |
| datadog_api_key | 288 | 0.583 |
| db_connection_string | 1,143 | 0.998 |
| digitalocean_token | 264 | 0.917 |
| discord_bot_token | 275 | 0.393 |
| gcp_api_key | 294 | 0.976 |
| gcp_service_account | 265 | 1.000 |
| generic_api_key | 3,236 | 0.693 |
| generic_high_entropy | 1,138 | 0.421 |
| generic_password | 3,342 | 0.567 |
| github_pat_classic | 268 | 1.000 |
| github_pat_fine_grained | 195 | 1.000 |
| github_token_oauth | 270 | 1.000 |
| gitlab_pat | 297 | 1.000 |
| huggingface_token | 285 | 0.456 |
| jwt | 298 | 0.977 |
| npm_token | 282 | 0.879 |
| openai_api_key | 300 | 1.000 |
| private_key_pem | 277 | 0.989 |
| pypi_token | 141 | 1.000 |
| sendgrid_api_key | 300 | 0.930 |
| shopify_token | 276 | 1.000 |
| slack_token | 285 | 1.000 |
| slack_webhook | 293 | 1.000 |
| stripe_secret_key | 302 | 1.000 |
| telegram_bot_token | 294 | 0.316 |
| twilio_api_key | 274 | 0.734 |

| Negative type | Cases | False-alarm rate |
| --- | --- | --- |
| base64_data | 1 | 0.000 |
| bcrypt | 1 | 0.000 |
| ci_ref | 1 | 0.000 |
| cli_flag | 1 | 0.000 |
| config | 3 | 0.000 |
| correlation_id | 1 | 0.000 |
| credit_card | 1 | 0.000 |
| data_uri | 1 | 0.000 |
| env_ref | 2 | 0.000 |
| example_key | 1 | 1.000 |
| fingerprint | 1 | 0.000 |
| git_sha | 1 | 0.000 |
| hex_color | 1 | 0.000 |
| hex_colors | 1 | 0.000 |
| iban | 1 | 0.000 |
| k8s_ref | 1 | 0.000 |
| md5 | 2 | 0.000 |
| near_miss_aws | 1 | 0.000 |
| near_miss_github | 1 | 0.000 |
| near_miss_jwt | 1 | 0.000 |
| neg_aws_arn | 360 | 0.000 |
| neg_base64_data | 451 | 0.024 |
| neg_data_blob | 360 | 0.000 |
| neg_data_uri | 300 | 0.000 |
| neg_env_interp | 54 | 0.278 |
| neg_example_key | 9 | 0.667 |
| neg_git_sha | 603 | 0.050 |
| neg_hash | 534 | 0.124 |
| neg_hash_id | 420 | 0.000 |
| neg_hex_color | 567 | 0.120 |
| neg_jwt_shaped | 180 | 0.167 |
| neg_k8s_id | 480 | 0.000 |
| neg_localhost_dsn | 180 | 0.733 |
| neg_multilingual_prose | 56 | 0.000 |
| neg_natural_token | 441 | 0.066 |
| neg_near_miss | 551 | 0.447 |
| neg_pii | 360 | 0.042 |
| neg_placeholder | 27 | 0.370 |
| neg_pw_hash | 180 | 0.183 |
| neg_sri_integrity | 180 | 0.000 |
| neg_ssh_pubkey | 540 | 0.000 |
| neg_uuid | 573 | 0.234 |
| neg_version_or_id | 594 | 0.054 |
| number | 4 | 0.000 |
| objectid | 1 | 0.000 |
| pii_email | 1 | 0.000 |
| pii_name | 1 | 0.000 |
| pii_phone | 1 | 0.000 |
| pii_ssn | 1 | 0.000 |
| placeholder | 4 | 0.250 |
| placeholder_dsn | 1 | 1.000 |
| region | 1 | 0.000 |
| sha256 | 2 | 0.000 |
| sha512 | 1 | 0.000 |
| ssh_pubkey | 2 | 0.000 |
| template_id | 1 | 0.000 |
| ulid | 1 | 0.000 |
| uuid | 2 | 0.000 |
| vault_ref | 1 | 0.000 |
| version | 1 | 0.000 |
| weak_etag | 1 | 0.000 |

</details>

#### ProwlBench, 2.4.0-baseline: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `secret` | in | 9,110 | 65.8% | 77.9% | 2,015 | 1,098 |

ProwlBench, 2.4.0-baseline: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 4,553 | 67.0% | 79.0% | 958 | 543 |
| holdout | 4,557 | 64.6% | 76.8% | 1,057 | 555 |

ProwlBench, 2.4.0-baseline: in-scope values by tier

| Tier | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| T1_structured | 5,728 | 77.8% | 87.8% | 699 | 570 |
| T3_freeform_multilingual | 3,382 | 45.5% | 61.1% | 1,316 | 528 |

ProwlBench, 2.4.0-baseline: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| de | 408 | 49.8% | 56.6% | 177 | 28 |
| en | 4,222 | 68.4% | 82.0% | 758 | 578 |
| es | 386 | 67.6% | 81.1% | 73 | 52 |
| fr | 1,535 | 62.7% | 72.1% | 428 | 145 |
| it | 151 | 78.8% | 88.7% | 17 | 15 |
| ja | 688 | 66.1% | 76.9% | 159 | 74 |
| non-en | 436 | 62.8% | 79.4% | 90 | 72 |
| ru | 662 | 70.4% | 79.9% | 133 | 63 |
| zh | 622 | 59.7% | 71.1% | 180 | 71 |

ProwlBench, 2.4.0-baseline: in-scope values by source

| Source | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| code | 1,376 | 66.2% | 93.8% | 85 | 380 |
| confluence | 1,478 | 66.4% | 77.7% | 329 | 168 |
| jira | 2,031 | 61.5% | 70.0% | 609 | 174 |
| log | 2,457 | 66.5% | 74.2% | 634 | 189 |
| slack | 1,768 | 69.2% | 79.8% | 358 | 187 |

ProwlBench, 2.4.0-baseline: in-scope values by origin

| Origin | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| augmented | 6,432 | 68.1% | 81.3% | 1,204 | 850 |
| real | 1,619 | 56.6% | 56.8% | 700 | 3 |
| synthetic | 1,059 | 66.4% | 89.5% | 111 | 245 |

Collateral: 489,108 of 2,832,088 letters and digits outside the gold values were redacted (17.3%); by type: SECRET 296,730, PERSON 52,330, PRIVATE_KEY 42,897, ORGANIZATION 40,930, IP_ADDRESS 17,434, EMAIL 17,054, LOCATION 10,572, DEVICE_ID 2,865.

#### ProwlBench, hardening-1: its own metric (a snippet counts as detected when a secret is flagged in it)

| Tool | Precision | Recall | F1 | Accuracy | T1 recall | T2 recall | T3 recall | T4 false-alarm rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Harpo, all cases | 0.946 | 0.921 | 0.934 | 0.912 | 0.989 | 0.882 | 0.866 | 0.107 |
| Harpo, dev half | 0.947 | 0.927 | 0.937 | 0.916 | 0.991 | 0.895 | 0.871 | 0.106 |
| Harpo, holdout half | 0.946 | 0.916 | 0.931 | 0.908 | 0.987 | 0.869 | 0.861 | 0.109 |
| gitleaks 8.30.1 (run here) | 0.931 | 0.413 | 0.573 | 0.585 | 0.653 | 0.355 | 0.167 | 0.063 |

Recall by language and by source (Harpo, all cases):

| de | en | es | fr | it | ja | non-en | ru | zh |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.826 (408) | 0.904 (11,430) | 1.000 (387) | 0.928 (1,536) | 1.000 (151) | 1.000 (688) | 0.977 (654) | 0.999 (663) | 0.998 (635) |

| code | confluence | jira | log | slack |
| --- | --- | --- | --- | --- |
| 0.876 (6,693) | 0.994 (2,643) | 0.900 (2,990) | 0.941 (2,458) | 0.993 (1,768) |

False alarms on the hard negatives, by whether the snippet assigns a value to a credential-named field:

| Negatives | Cases | False-alarm rate |
| --- | --- | --- |
| credential named | 541 | 0.676 |
| other | 7,510 | 0.066 |

<details><summary>Recall per secret type, false-alarm rate per negative type</summary>

| Secret type | Cases | Recall |
| --- | --- | --- |
| anthropic_api_key | 244 | 1.000 |
| aws_access_key_id | 280 | 0.946 |
| aws_secret_access_key | 200 | 0.995 |
| azure_storage_key | 286 | 1.000 |
| basic_auth_header | 660 | 0.996 |
| datadog_api_key | 288 | 0.983 |
| db_connection_string | 1,143 | 0.998 |
| digitalocean_token | 264 | 0.996 |
| discord_bot_token | 275 | 1.000 |
| gcp_api_key | 294 | 0.976 |
| gcp_service_account | 265 | 1.000 |
| generic_api_key | 3,236 | 0.907 |
| generic_high_entropy | 1,138 | 0.690 |
| generic_password | 3,342 | 0.832 |
| github_pat_classic | 268 | 1.000 |
| github_pat_fine_grained | 195 | 1.000 |
| github_token_oauth | 270 | 1.000 |
| gitlab_pat | 297 | 1.000 |
| huggingface_token | 285 | 1.000 |
| jwt | 298 | 0.977 |
| npm_token | 282 | 1.000 |
| openai_api_key | 300 | 1.000 |
| private_key_pem | 277 | 0.996 |
| pypi_token | 141 | 1.000 |
| sendgrid_api_key | 300 | 1.000 |
| shopify_token | 276 | 1.000 |
| slack_token | 285 | 1.000 |
| slack_webhook | 293 | 1.000 |
| stripe_secret_key | 302 | 1.000 |
| telegram_bot_token | 294 | 1.000 |
| twilio_api_key | 274 | 0.850 |

| Negative type | Cases | False-alarm rate |
| --- | --- | --- |
| base64_data | 1 | 0.000 |
| bcrypt | 1 | 0.000 |
| ci_ref | 1 | 0.000 |
| cli_flag | 1 | 0.000 |
| config | 3 | 0.000 |
| correlation_id | 1 | 0.000 |
| credit_card | 1 | 0.000 |
| data_uri | 1 | 0.000 |
| env_ref | 2 | 0.000 |
| example_key | 1 | 1.000 |
| fingerprint | 1 | 0.000 |
| git_sha | 1 | 0.000 |
| hex_color | 1 | 0.000 |
| hex_colors | 1 | 0.000 |
| iban | 1 | 0.000 |
| k8s_ref | 1 | 0.000 |
| md5 | 2 | 0.000 |
| near_miss_aws | 1 | 0.000 |
| near_miss_github | 1 | 0.000 |
| near_miss_jwt | 1 | 0.000 |
| neg_aws_arn | 360 | 0.000 |
| neg_base64_data | 451 | 0.135 |
| neg_data_blob | 360 | 0.000 |
| neg_data_uri | 300 | 0.000 |
| neg_env_interp | 54 | 0.204 |
| neg_example_key | 9 | 0.778 |
| neg_git_sha | 603 | 0.129 |
| neg_hash | 534 | 0.165 |
| neg_hash_id | 420 | 0.000 |
| neg_hex_color | 567 | 0.116 |
| neg_jwt_shaped | 180 | 0.000 |
| neg_k8s_id | 480 | 0.000 |
| neg_localhost_dsn | 180 | 0.000 |
| neg_multilingual_prose | 56 | 0.000 |
| neg_natural_token | 441 | 0.091 |
| neg_near_miss | 551 | 0.485 |
| neg_pii | 360 | 0.064 |
| neg_placeholder | 27 | 0.185 |
| neg_pw_hash | 180 | 0.000 |
| neg_sri_integrity | 180 | 0.000 |
| neg_ssh_pubkey | 540 | 0.000 |
| neg_uuid | 573 | 0.300 |
| neg_version_or_id | 594 | 0.077 |
| number | 4 | 0.000 |
| objectid | 1 | 0.000 |
| pii_email | 1 | 0.000 |
| pii_name | 1 | 0.000 |
| pii_phone | 1 | 0.000 |
| pii_ssn | 1 | 0.000 |
| placeholder | 4 | 0.000 |
| placeholder_dsn | 1 | 0.000 |
| region | 1 | 0.000 |
| sha256 | 2 | 0.000 |
| sha512 | 1 | 0.000 |
| ssh_pubkey | 2 | 0.000 |
| template_id | 1 | 0.000 |
| ulid | 1 | 0.000 |
| uuid | 2 | 0.000 |
| vault_ref | 1 | 0.000 |
| version | 1 | 0.000 |
| weak_etag | 1 | 0.000 |

</details>

#### ProwlBench, hardening-1: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `secret` | in | 9,110 | 83.9% | 94.3% | 521 | 945 |

ProwlBench, hardening-1: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 4,553 | 84.1% | 94.4% | 254 | 471 |
| holdout | 4,557 | 83.7% | 94.1% | 267 | 474 |

ProwlBench, hardening-1: in-scope values by tier

| Tier | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| T1_structured | 5,728 | 92.4% | 99.7% | 18 | 419 |
| T3_freeform_multilingual | 3,382 | 69.6% | 85.1% | 503 | 526 |

ProwlBench, hardening-1: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| de | 408 | 80.4% | 84.8% | 62 | 18 |
| en | 4,222 | 79.9% | 92.3% | 323 | 526 |
| es | 386 | 90.2% | 100.0% | 0 | 38 |
| fr | 1,535 | 85.7% | 93.3% | 103 | 116 |
| it | 151 | 92.7% | 100.0% | 0 | 11 |
| ja | 688 | 90.5% | 100.0% | 0 | 65 |
| non-en | 436 | 78.2% | 93.3% | 29 | 66 |
| ru | 662 | 92.3% | 99.4% | 4 | 47 |
| zh | 622 | 90.7% | 100.0% | 0 | 58 |

ProwlBench, hardening-1: in-scope values by source

| Source | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| code | 1,376 | 73.2% | 99.5% | 7 | 362 |
| confluence | 1,478 | 89.2% | 98.4% | 24 | 136 |
| jira | 2,031 | 79.3% | 86.3% | 278 | 143 |
| log | 2,457 | 86.1% | 92.5% | 185 | 157 |
| slack | 1,768 | 90.2% | 98.5% | 27 | 147 |

ProwlBench, hardening-1: in-scope values by origin

| Origin | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| augmented | 6,432 | 88.9% | 99.9% | 7 | 704 |
| real | 1,619 | 72.5% | 72.6% | 444 | 2 |
| synthetic | 1,059 | 70.8% | 93.4% | 70 | 239 |

Collateral: 524,232 of 2,832,088 letters and digits outside the gold values were redacted (18.5%); by type: SECRET 341,556, PERSON 48,142, PRIVATE_KEY 42,678, ORGANIZATION 36,813, IP_ADDRESS 17,428, EMAIL 17,054, LOCATION 9,508, DEVICE_ID 2,865.

#### ProwlBench, hardening-2: its own metric (a snippet counts as detected when a secret is flagged in it)

| Tool | Precision | Recall | F1 | Accuracy | T1 recall | T2 recall | T3 recall | T4 false-alarm rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Harpo, all cases | 0.945 | 0.931 | 0.938 | 0.917 | 0.989 | 0.901 | 0.880 | 0.111 |
| Harpo, dev half | 0.946 | 0.936 | 0.941 | 0.921 | 0.991 | 0.911 | 0.886 | 0.109 |
| Harpo, holdout half | 0.945 | 0.926 | 0.935 | 0.914 | 0.987 | 0.893 | 0.875 | 0.112 |
| gitleaks 8.30.1 (run here) | 0.931 | 0.413 | 0.573 | 0.585 | 0.653 | 0.355 | 0.167 | 0.063 |

Recall by language and by source (Harpo, all cases):

| de | en | es | fr | it | ja | non-en | ru | zh |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.828 (408) | 0.917 (11,430) | 1.000 (387) | 0.929 (1,536) | 1.000 (151) | 1.000 (688) | 0.977 (654) | 0.999 (663) | 0.998 (635) |

| code | confluence | jira | log | slack |
| --- | --- | --- | --- | --- |
| 0.886 (6,693) | 0.994 (2,643) | 0.903 (2,990) | 0.973 (2,458) | 0.993 (1,768) |

False alarms on the hard negatives, by whether the snippet assigns a value to a credential-named field:

| Negatives | Cases | False-alarm rate |
| --- | --- | --- |
| credential named | 541 | 0.676 |
| other | 7,510 | 0.070 |

<details><summary>Recall per secret type, false-alarm rate per negative type</summary>

| Secret type | Cases | Recall |
| --- | --- | --- |
| anthropic_api_key | 244 | 1.000 |
| aws_access_key_id | 280 | 0.946 |
| aws_secret_access_key | 200 | 0.995 |
| azure_storage_key | 286 | 1.000 |
| basic_auth_header | 660 | 0.996 |
| datadog_api_key | 288 | 0.983 |
| db_connection_string | 1,143 | 0.998 |
| digitalocean_token | 264 | 0.996 |
| discord_bot_token | 275 | 1.000 |
| gcp_api_key | 294 | 0.976 |
| gcp_service_account | 265 | 1.000 |
| generic_api_key | 3,236 | 0.935 |
| generic_high_entropy | 1,138 | 0.690 |
| generic_password | 3,342 | 0.851 |
| github_pat_classic | 268 | 1.000 |
| github_pat_fine_grained | 195 | 1.000 |
| github_token_oauth | 270 | 1.000 |
| gitlab_pat | 297 | 1.000 |
| huggingface_token | 285 | 1.000 |
| jwt | 298 | 0.977 |
| npm_token | 282 | 1.000 |
| openai_api_key | 300 | 1.000 |
| private_key_pem | 277 | 0.996 |
| pypi_token | 141 | 1.000 |
| sendgrid_api_key | 300 | 1.000 |
| shopify_token | 276 | 1.000 |
| slack_token | 285 | 1.000 |
| slack_webhook | 293 | 1.000 |
| stripe_secret_key | 302 | 1.000 |
| telegram_bot_token | 294 | 1.000 |
| twilio_api_key | 274 | 0.850 |

| Negative type | Cases | False-alarm rate |
| --- | --- | --- |
| base64_data | 1 | 0.000 |
| bcrypt | 1 | 0.000 |
| ci_ref | 1 | 0.000 |
| cli_flag | 1 | 0.000 |
| config | 3 | 0.000 |
| correlation_id | 1 | 0.000 |
| credit_card | 1 | 0.000 |
| data_uri | 1 | 0.000 |
| env_ref | 2 | 0.000 |
| example_key | 1 | 1.000 |
| fingerprint | 1 | 0.000 |
| git_sha | 1 | 0.000 |
| hex_color | 1 | 0.000 |
| hex_colors | 1 | 0.000 |
| iban | 1 | 0.000 |
| k8s_ref | 1 | 0.000 |
| md5 | 2 | 0.000 |
| near_miss_aws | 1 | 0.000 |
| near_miss_github | 1 | 0.000 |
| near_miss_jwt | 1 | 0.000 |
| neg_aws_arn | 360 | 0.000 |
| neg_base64_data | 451 | 0.135 |
| neg_data_blob | 360 | 0.000 |
| neg_data_uri | 300 | 0.000 |
| neg_env_interp | 54 | 0.204 |
| neg_example_key | 9 | 0.778 |
| neg_git_sha | 603 | 0.129 |
| neg_hash | 534 | 0.172 |
| neg_hash_id | 420 | 0.000 |
| neg_hex_color | 567 | 0.116 |
| neg_jwt_shaped | 180 | 0.000 |
| neg_k8s_id | 480 | 0.000 |
| neg_localhost_dsn | 180 | 0.000 |
| neg_multilingual_prose | 56 | 0.000 |
| neg_natural_token | 441 | 0.091 |
| neg_near_miss | 551 | 0.486 |
| neg_pii | 360 | 0.114 |
| neg_placeholder | 27 | 0.185 |
| neg_pw_hash | 180 | 0.000 |
| neg_sri_integrity | 180 | 0.000 |
| neg_ssh_pubkey | 540 | 0.002 |
| neg_uuid | 573 | 0.300 |
| neg_version_or_id | 594 | 0.079 |
| number | 4 | 0.000 |
| objectid | 1 | 0.000 |
| pii_email | 1 | 0.000 |
| pii_name | 1 | 0.000 |
| pii_phone | 1 | 0.000 |
| pii_ssn | 1 | 0.000 |
| placeholder | 4 | 0.000 |
| placeholder_dsn | 1 | 0.000 |
| region | 1 | 0.000 |
| sha256 | 2 | 0.000 |
| sha512 | 1 | 0.000 |
| ssh_pubkey | 2 | 0.000 |
| template_id | 1 | 0.000 |
| ulid | 1 | 0.000 |
| uuid | 2 | 0.000 |
| vault_ref | 1 | 0.000 |
| version | 1 | 0.000 |
| weak_etag | 1 | 0.000 |

</details>

#### ProwlBench, hardening-2: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `secret` | in | 9,110 | 85.2% | 95.5% | 406 | 944 |

ProwlBench, hardening-2: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 4,553 | 85.3% | 95.6% | 199 | 470 |
| holdout | 4,557 | 85.1% | 95.5% | 207 | 474 |

ProwlBench, hardening-2: in-scope values by tier

| Tier | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| T1_structured | 5,728 | 92.4% | 99.7% | 17 | 417 |
| T3_freeform_multilingual | 3,382 | 72.9% | 88.5% | 389 | 527 |

ProwlBench, hardening-2: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| de | 408 | 80.9% | 85.3% | 60 | 18 |
| en | 4,222 | 82.3% | 94.8% | 219 | 526 |
| es | 386 | 90.2% | 100.0% | 0 | 38 |
| fr | 1,535 | 86.1% | 93.6% | 98 | 116 |
| it | 151 | 92.7% | 100.0% | 0 | 11 |
| ja | 688 | 90.5% | 100.0% | 0 | 65 |
| non-en | 436 | 79.4% | 94.3% | 25 | 65 |
| ru | 662 | 92.3% | 99.4% | 4 | 47 |
| zh | 622 | 90.7% | 100.0% | 0 | 58 |

ProwlBench, hardening-2: in-scope values by source

| Source | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| code | 1,376 | 73.3% | 99.6% | 6 | 362 |
| confluence | 1,478 | 89.5% | 98.7% | 19 | 136 |
| jira | 2,031 | 79.8% | 86.9% | 267 | 143 |
| log | 2,457 | 90.0% | 96.4% | 89 | 157 |
| slack | 1,768 | 90.3% | 98.6% | 25 | 146 |

ProwlBench, hardening-2: in-scope values by origin

| Origin | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| augmented | 6,432 | 88.9% | 99.9% | 7 | 704 |
| real | 1,619 | 78.9% | 79.1% | 338 | 3 |
| synthetic | 1,059 | 71.9% | 94.2% | 61 | 237 |

Collateral: 553,063 of 2,832,088 letters and digits outside the gold values were redacted (19.5%); by type: SECRET 348,405, PERSON 51,147, PRIVATE_KEY 42,678, ORGANIZATION 36,083, IP_ADDRESS 17,312, EMAIL 16,697, ACCOUNT_ID 13,392, LOCATION 9,070.

#### ProwlBench, hardening-3: its own metric (a snippet counts as detected when a secret is flagged in it)

| Tool | Precision | Recall | F1 | Accuracy | T1 recall | T2 recall | T3 recall | T4 false-alarm rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Harpo, all cases | 0.946 | 0.936 | 0.941 | 0.921 | 0.989 | 0.902 | 0.894 | 0.111 |
| Harpo, dev half | 0.947 | 0.940 | 0.943 | 0.924 | 0.991 | 0.911 | 0.897 | 0.109 |
| Harpo, holdout half | 0.945 | 0.932 | 0.939 | 0.918 | 0.987 | 0.894 | 0.891 | 0.113 |
| gitleaks 8.30.1 (run here) | 0.931 | 0.413 | 0.573 | 0.585 | 0.653 | 0.355 | 0.167 | 0.063 |

Recall by language and by source (Harpo, all cases):

| de | en | es | fr | it | ja | non-en | ru | zh |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.855 (408) | 0.921 (11,430) | 1.000 (387) | 0.951 (1,536) | 1.000 (151) | 1.000 (688) | 0.979 (654) | 0.999 (663) | 0.998 (635) |

| code | confluence | jira | log | slack |
| --- | --- | --- | --- | --- |
| 0.888 (6,693) | 0.994 (2,643) | 0.928 (2,990) | 0.973 (2,458) | 0.993 (1,768) |

False alarms on the hard negatives, by whether the snippet assigns a value to a credential-named field:

| Negatives | Cases | False-alarm rate |
| --- | --- | --- |
| credential named | 541 | 0.676 |
| other | 7,510 | 0.070 |

<details><summary>Recall per secret type, false-alarm rate per negative type</summary>

| Secret type | Cases | Recall |
| --- | --- | --- |
| anthropic_api_key | 244 | 1.000 |
| aws_access_key_id | 280 | 0.946 |
| aws_secret_access_key | 200 | 0.995 |
| azure_storage_key | 286 | 1.000 |
| basic_auth_header | 660 | 0.996 |
| datadog_api_key | 288 | 0.983 |
| db_connection_string | 1,143 | 0.998 |
| digitalocean_token | 264 | 0.996 |
| discord_bot_token | 275 | 1.000 |
| gcp_api_key | 294 | 0.976 |
| gcp_service_account | 265 | 1.000 |
| generic_api_key | 3,236 | 0.935 |
| generic_high_entropy | 1,138 | 0.698 |
| generic_password | 3,342 | 0.874 |
| github_pat_classic | 268 | 1.000 |
| github_pat_fine_grained | 195 | 1.000 |
| github_token_oauth | 270 | 1.000 |
| gitlab_pat | 297 | 1.000 |
| huggingface_token | 285 | 1.000 |
| jwt | 298 | 0.977 |
| npm_token | 282 | 1.000 |
| openai_api_key | 300 | 1.000 |
| private_key_pem | 277 | 0.996 |
| pypi_token | 141 | 1.000 |
| sendgrid_api_key | 300 | 1.000 |
| shopify_token | 276 | 1.000 |
| slack_token | 285 | 1.000 |
| slack_webhook | 293 | 1.000 |
| stripe_secret_key | 302 | 1.000 |
| telegram_bot_token | 294 | 1.000 |
| twilio_api_key | 274 | 0.850 |

| Negative type | Cases | False-alarm rate |
| --- | --- | --- |
| base64_data | 1 | 0.000 |
| bcrypt | 1 | 0.000 |
| ci_ref | 1 | 0.000 |
| cli_flag | 1 | 0.000 |
| config | 3 | 0.000 |
| correlation_id | 1 | 0.000 |
| credit_card | 1 | 0.000 |
| data_uri | 1 | 0.000 |
| env_ref | 2 | 0.000 |
| example_key | 1 | 1.000 |
| fingerprint | 1 | 0.000 |
| git_sha | 1 | 0.000 |
| hex_color | 1 | 0.000 |
| hex_colors | 1 | 0.000 |
| iban | 1 | 0.000 |
| k8s_ref | 1 | 0.000 |
| md5 | 2 | 0.000 |
| near_miss_aws | 1 | 0.000 |
| near_miss_github | 1 | 0.000 |
| near_miss_jwt | 1 | 0.000 |
| neg_aws_arn | 360 | 0.000 |
| neg_base64_data | 451 | 0.135 |
| neg_data_blob | 360 | 0.000 |
| neg_data_uri | 300 | 0.000 |
| neg_env_interp | 54 | 0.204 |
| neg_example_key | 9 | 0.778 |
| neg_git_sha | 603 | 0.129 |
| neg_hash | 534 | 0.172 |
| neg_hash_id | 420 | 0.000 |
| neg_hex_color | 567 | 0.116 |
| neg_jwt_shaped | 180 | 0.000 |
| neg_k8s_id | 480 | 0.000 |
| neg_localhost_dsn | 180 | 0.000 |
| neg_multilingual_prose | 56 | 0.000 |
| neg_natural_token | 441 | 0.091 |
| neg_near_miss | 551 | 0.486 |
| neg_pii | 360 | 0.117 |
| neg_placeholder | 27 | 0.185 |
| neg_pw_hash | 180 | 0.000 |
| neg_sri_integrity | 180 | 0.000 |
| neg_ssh_pubkey | 540 | 0.002 |
| neg_uuid | 573 | 0.300 |
| neg_version_or_id | 594 | 0.079 |
| number | 4 | 0.000 |
| objectid | 1 | 0.000 |
| pii_email | 1 | 0.000 |
| pii_name | 1 | 0.000 |
| pii_phone | 1 | 0.000 |
| pii_ssn | 1 | 0.000 |
| placeholder | 4 | 0.000 |
| placeholder_dsn | 1 | 0.000 |
| region | 1 | 0.000 |
| sha256 | 2 | 0.000 |
| sha512 | 1 | 0.000 |
| ssh_pubkey | 2 | 0.000 |
| template_id | 1 | 0.000 |
| ulid | 1 | 0.000 |
| uuid | 2 | 0.000 |
| vault_ref | 1 | 0.000 |
| version | 1 | 0.000 |
| weak_etag | 1 | 0.000 |

</details>

#### ProwlBench, hardening-3: values removed, per label

| Label | Scope | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- | --- |
| `secret` | in | 9,110 | 85.8% | 96.2% | 351 | 943 |

ProwlBench, hardening-3: in-scope values by half

| Half | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| dev | 4,553 | 85.9% | 96.2% | 174 | 470 |
| holdout | 4,557 | 85.7% | 96.1% | 177 | 473 |

ProwlBench, hardening-3: in-scope values by tier

| Tier | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| T1_structured | 5,728 | 92.4% | 99.7% | 17 | 417 |
| T3_freeform_multilingual | 3,382 | 74.6% | 90.1% | 334 | 526 |

ProwlBench, hardening-3: in-scope values by language

| Language | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| de | 408 | 82.6% | 87.0% | 53 | 18 |
| en | 4,222 | 82.9% | 95.3% | 197 | 525 |
| es | 386 | 90.2% | 100.0% | 0 | 38 |
| fr | 1,535 | 87.7% | 95.2% | 73 | 116 |
| it | 151 | 92.7% | 100.0% | 0 | 11 |
| ja | 688 | 90.5% | 100.0% | 0 | 65 |
| non-en | 436 | 79.6% | 94.5% | 24 | 65 |
| ru | 662 | 92.3% | 99.4% | 4 | 47 |
| zh | 622 | 90.7% | 100.0% | 0 | 58 |

ProwlBench, hardening-3: in-scope values by source

| Source | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| code | 1,376 | 73.3% | 99.6% | 6 | 362 |
| confluence | 1,478 | 89.5% | 98.7% | 19 | 136 |
| jira | 2,031 | 82.6% | 89.6% | 211 | 143 |
| log | 2,457 | 90.0% | 96.3% | 90 | 156 |
| slack | 1,768 | 90.3% | 98.6% | 25 | 146 |

ProwlBench, hardening-3: in-scope values by origin

| Origin | Values | Fully removed | Any part removed | Leaked | Partly removed |
| --- | --- | --- | --- | --- | --- |
| augmented | 6,432 | 88.9% | 99.9% | 7 | 704 |
| real | 1,619 | 82.4% | 82.5% | 283 | 2 |
| synthetic | 1,059 | 71.9% | 94.2% | 61 | 237 |

Collateral: 510,873 of 2,832,088 letters and digits outside the gold values were redacted (18.0%); by type: SECRET 348,348, PRIVATE_KEY 42,678, PERSON 24,268, ORGANIZATION 20,913, IP_ADDRESS 17,272, ACCOUNT_ID 16,654, EMAIL 16,652, DEVICE_ID 8,139.
<!-- /results -->

## RegionBench

None of the public datasets covers the Dutch, US and EU identifiers of [REGIONS.md](REGIONS.md), so Harpo has its own
measure for them: 62 templates of everyday documents (letters, forms, invoices, chats, JSON records, CSV and Markdown
tables, YAML, logs), in Dutch, English, German, French, Spanish, Italian, Polish and Portuguese, each written 40 times
with values drawn at random: 2,480 documents, 14,764 values. Values with a check digit pass it; none belongs to
anyone. Every document also marks its *keeps*, 4,353 in all: phrases with nothing personal in them and the look-alikes
that must come through unchanged (order and invoice numbers, amounts, dates of events, versions, article numbers). A
value counts as removed when every letter and digit of it was redacted; a keep counts as damaged when any of it was.

The templates were split once, before any build was run on them, into a dev set (40 templates) and a holdout set
(22). Round 3's fixes were made looking at the dev templates only; the holdout templates were only ever counted, so
their number says whether a fix carries over to documents it was not written against. RegionBench was written in
round 3, so the earlier builds never saw it either. Configuration as above; `python bench/regionbench/run.py run`.

<!-- regionbench 2.4.0-baseline hardening-2 hardening-3 -->
| Build | Values | Removed | nl, dev | nl, holdout | us, dev | us, holdout | eu, dev | eu, holdout | Keeps damaged |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2.4.0-baseline | 14,764 | 65.2% | 61.7% | 70.0% | 74.7% | 71.3% | 54.2% | 48.3% | 18.1% (788 of 4,353) |
| hardening-2 | 14,764 | 80.5% | 73.2% | 79.2% | 86.0% | 83.6% | 88.1% | 79.4% | 18.2% (793 of 4,353) |
| hardening-3 | 14,764 | 99.1% | 99.9% | 98.2% | 100.0% | 96.4% | 100.0% | 96.7% | 5.5% (238 of 4,353) |

The kinds of value hardening-3 removes least often, over both splits:

| Kind | Values | Removed | Partly | Leaked |
| --- | --- | --- | --- | --- |
| us.rx | 80 | 50.0% | 0 | 40 |
| nl.dossiernummer | 40 | 62.5% | 0 | 15 |
| us.group_number | 80 | 80.0% | 0 | 16 |
| nl.first_name | 80 | 85.0% | 0 | 12 |
| eu.national | 360 | 94.7% | 0 | 19 |
| eu.postcode_city | 320 | 97.8% | 0 | 7 |
| eu.street | 320 | 97.8% | 0 | 7 |
| us.name | 880 | 99.0% | 7 | 2 |
| nl.street | 440 | 99.1% | 1 | 3 |
| eu.name | 600 | 99.3% | 2 | 2 |
| nl.name | 1,168 | 99.6% | 2 | 3 |
| eu.bic | 80 | 100.0% | 0 | 0 |
<!-- /regionbench -->

## What the baseline shows

### ProwlBench

**Score.** F1 0.834: second among the leaderboard's reproducible rows, behind Prowl's own cascade (0.883), with
precision in line with the field (0.935) and recall below Prowl's (0.753 against 0.823). Strongest on structured
tokens (T1, 0.873), weakest on free-form and multilingual text (T3, 0.649) and on German (0.527). The dev half
(F1 0.841) and holdout half (0.828) agree within sampling noise.

The causes below were found on the dev half: 8,237 positives, 1,951 missed; 4,026 negatives, 426 flagged.

**Where recall goes.**

- *Real-world snippets*, 1,084 of the 1,951 misses (ProwlBench's CredData and Hugging Face origins; 752 of them do
  not mark where the secret is). Generic passwords and keys in code and documents: a password-named field given a
  plain lowercase value (`Password = "…"`), names Harpo does not read as credentials (`PASS=`, `hexpass`), credential
  tables. Some of these labels are hard to defend: UUID-shaped values in id fields count as secrets here, while
  ProwlBench's own UUID negatives say the opposite.
- *Generated snippets in other languages*, 496. Harpo ties a credential's name to its value through `=`, `:`, "is",
  "ist" or "est", and knows the word for password in English, Dutch, German, French and Spanish. Other ways of
  saying "is" ("è", "es", "é", "lautet", "是", "です") and other words for password ("senha", "пароль", "パスワード",
  "密码") are missing: "L'attuale API_KEY è …", "Его пароль: …", "他的密码是 …". So are names such as `HF_TOKEN` or
  `NPM_TOKEN` in a sentence, in any language.
- *Generated snippets in English*, 371, of two kinds. Phrasings Harpo does not read as naming a credential: "set
  apiKey to …", "Set the environment variable `api_key` to `…`", a table row `| passwd | … |`, a bold name
  `- **apiKey**: …`, a value in brackets after its name. And provider tokens written differently from the real
  format: Telegram bot tokens whose secret part does not start with `AA`, Hugging Face tokens with digits in them,
  Discord bot tokens. Harpo's rules for these providers come from gitleaks and encode the real formats, so they miss
  these, as gitleaks does on the leaderboard.
- One cause runs through all three groups and hits real-format tokens too. The gitleaks patterns end a token at a
  quote, a blank or a semicolon, as in code. In a sentence a token often ends with a full stop or a bracket, and
  then even a real-format token is missed: "The NPM_TOKEN is npm_…." leaks where "The NPM_TOKEN is npm_… now" does
  not. Of the 933 dev misses that mark their value, 573 have punctuation right after it, though not every one of
  them is missed for that reason.

**Partly removed values** are mostly ProwlBench's span convention. It marks a whole connection string, Azure
connection string, service-account JSON or `Authorization: Basic …` header; Harpo removes the password, account key,
private key or credential inside it and leaves the user name, host, key id and header name. On the dev half, 516 of
538 such values had the secret itself removed. The other 22 are real leaks: 21 Telegram tokens whose bot id was
redacted as a phone number or national id while the secret part after the colon stayed, and one Basic header where
only a word next to the credential was redacted.

**False alarms.** Harpo flags 10.7% of the hard negatives; gitleaks, run here, 6.3%, and Prowl's cascade 7 to 9%
by its README.

- 541 of the 8,051 hard negatives assign a value of six or more characters to a credential-named field, or say "the
  secret is …": `API_KEY=` followed by a UUID, `password = ` followed by a hex colour, "the staging access_key is …",
  `Password:` in a login email, a bearer token in a log line. Harpo flags 66% of these, and they are 359 of its 860
  false alarms; on the other 7,510 negatives its rate is 6.7%. ProwlBench's datasheet says negatives with a
  high-entropy value in a secret-named assignment were left out because flagging them is defensible; this looser
  pattern remains. Harpo redacts such values on purpose: a redaction in flight costs one placeholder, and a
  credential that has left cannot be called back. This stays.
- The rest is noise worth fixing: a command or interpolation taken as the value (`$(vault kv get …)`, `!ENV ${…}`),
  placeholders (`change-me-please`, `dummytoken`), hash and digest fields whose names contain a credential word
  (`libapi_hash` contains "api"), file paths containing "key", values too short for a key or token (a three-digit
  "access key"), names that are not credentials (`cache_key`), and default passwords in local connection strings
  (`postgres://app:dev@localhost:5432/test`).
- Not in ProwlBench's numbers, but in the collateral: the NER layer reads code and non-English text as names.
  Identifiers (`Data.Text`, a `std::env::set_var(…)` call) and ordinary words ("Напоминание", "qualcuno",
  "rotacionar") were redacted as people and organisations. (Most of ProwlBench's collateral is `SECRET`, and most of
  that is no over-redaction at all: the secrets of the 7,442 positives that do not mark a span count as outside
  every gold value.)

### OpenPII, Nemotron-PII and RedactionBench

**Scores.** Of the values in scope, 2.4.0 fully removed 50.2% on OpenPII, 79.2% on Nemotron-PII and 74.0% on
RedactionBench. The first hardening round was about secrets and left these where they were (50.1%, 79.6%, 74.0%).
The dev and holdout halves agree on OpenPII (50.2% and 50.1%) and Nemotron-PII (79.2% and 79.3%). RedactionBench's
200 documents differ widely in length and kind, and its halves do not (69.0% and 80.4%), so its holdout number moves
more with chance than the others do.

The causes below were found on the dev halves.

**Where recall goes.**

- *Identifiers that no validator accepts.* Harpo 2.4.0 took a number as an identifier only when it could check it:
  a checksum, a country's pattern, a card number that passes Luhn. Both PII sets are synthetic, so most of their
  numbers fail their checksums, come from a country without a validator, or are written with separators no pattern
  expects. On OpenPII, ID card numbers were 9.3% removed, card numbers 8.7%, driving licences 12.7%, passports 14.4%,
  tax numbers 22.7% and social security numbers 27.4%; on Nemotron-PII, device identifiers 1.8%, licence and
  certificate numbers 7.1%, health plan numbers 9.3%, card numbers 11.9%, vehicle numbers 22.6% and bank routing
  numbers 26.7%. Nearly every one of them comes after a word that says what it is: "Steuernummer", "numéro de
  permis", "health plan beneficiary number", "nomor pajak", in some thirty languages.
- *Phone numbers outside the numbering plans* (OpenPII 30.8%): "0199 520 616", "+33.139 907.8509", "(967) 759-3756",
  numbers no country's plan accepts, or written in groups the phone library does not read.
- *Addresses in their local grammar.* A street word before or after the name or glued to it ("Aleksanterinkatu"),
  house-number markers ("nº", "č.", "szám"), postcode and town in either order. OpenPII's streets were 46.7%
  removed, its building numbers 13.0% and postcodes 10.9%; Nemotron-PII's street addresses 58.5% and postcodes 12.2%.
- *Names and places in other languages.* NER removed three quarters of OpenPII's given names and surnames, and much
  less in Chinese, Japanese and Korean text, where 21.1%, 15.6% and 18.3% of all values were removed (63.4% in
  Dutch). Greetings, honorifics and name labels outside English, Dutch and German ("Szanowna Pani", "Prénom :",
  "氏名：") were no cue.
- *Credentials in personal records.* PINs (33.4% on Nemotron-PII) and passwords (56.3%) stated in a sentence ("his
  password River45!") or in a table cell.
- *Machine formats that hold people*, mostly in RedactionBench's longer documents: HL7 messages, the machine-readable
  zone of a passport, AWS identities, user names in paths, LDAP names and Windows events, and tables whose column
  header says what a cell holds.

**Collateral** was 13.2% on OpenPII, 4.0% on Nemotron-PII and 9.5% on RedactionBench, nearly all of it from NER:
people, organisations and places in words that are none. OpenPII labels no organisations, so part of its share is not
over-redaction.

**Out of scope.** Dates (Harpo keeps them by policy, birth dates excepted), ages, genders, job titles, URLs and times
are in the tables above but not in the headline.

### Gretel PII masking

Not run: its files are published on Hugging Face, which the machine that recorded these runs could not reach, and no
copy could be provided by hand, so it has no baseline here ([Deferred evaluations](#deferred-evaluations)).

## Hardening, round 1 (ProwlBench)

Every fix was made looking at the dev half only, and every one is a general rule with tests in phrasings of our own
(80 of them, in `tests/test_secret_prose.py`), not a pattern for ProwlBench's templates. The holdout half was run once,
at the end.

**What changed.**

- *A layer for credentials stated in words* ([detectors/statements.py](../src/harpo_redact/detectors/statements.py)).
  A credential-named identifier (`HF_TOKEN`, `apiKey`, `DB_PASS`, `client_secret`) and its value, linked by a sign,
  by "is" in seventeen languages ("ist", "lautet", "est", "es", "è", "é", "это", "是", "は"), by brackets, a dash or a
  YAML tag; the words for password, key and token in some twenty-five languages, Chinese, Japanese and Korean written
  without blanks; "set X to Y", table rows, bold names, XML elements, SQL's `PASSWORD '…'`, a name and value handed to
  a call together (`define('DD_API_KEY', '…')`) and a literal in a wrapper (`Some("…")`, `SecretStr("…")`). After a
  word of prose a value must look generated; a password-named field in code may hold a plain word.
- *Provider tokens in prose.* The gitleaks rules also run on a view in which the end of a sentence is a blank, so a
  token before a full stop or Chinese punctuation is found. New rules for Telegram bot tokens (the whole token, also
  inside a Bot API URL), Hugging Face tokens with digits, Discord bot tokens and Azure account keys, and PGP private
  key blocks are private keys now.
- *HTTP Basic credentials* without the header's name in front: any `Basic <base64>` that decodes to readable
  `user:password`.
- *Fewer false alarms.* Commands, interpolations and YAML tags are not values (`$(vault kv get …)`, `!ENV ${…}`);
  placeholders written together or made of words with a marker are placeholders (`dummytoken`, `notarealkey`,
  `fake_key_for_testing`); gitleaks' generic rule needs a credential word in the name, not inside another word
  (`libapi_hash`), and not a name about a credential (an id, a hash, a URL, a version), a key that holds no secret (a
  cache key) or a file path; keys and tokens need eight characters; password hashes in modular crypt format and
  version numbers are neither; a well-known default password on a local host (`postgres://app:dev@localhost/test`)
  is not a secret; code is not a value (`request.form["password"]`); and an adjective after "password is" in six
  more languages ("Das Passwort ist falsch") is not a password, as it already was not in English. The NER layer no
  longer reads code (`std::env::set_var(`, `Data.Text`) as names.

**What it did.** The tables above have every number. On the holdout half, F1 went from 0.828 to 0.931, recall from
0.743 to 0.916, and precision from 0.934 to 0.946, while the false-alarm rate on the hard negatives stayed where it
was (0.108, now 0.109). On all cases F1 is 0.934, ahead of every reproducible row on ProwlBench's leaderboard, the
best of which is Prowl's own cascade at 0.883. Every tier rose (T1 0.989, T2 0.882, T3 0.866) and so did every
language: German, the lowest, from 0.527 to 0.826, and Spanish, Italian, Japanese, Russian and Chinese to 0.99 or
more. Where a positive marks its secret, the value was fully removed in 83.9% of cases against 65.8%, and 521 values
leaked against 2,015. The dev half (0.937) and the holdout half (0.931) are as close as they were at the baseline: no
sign that the fixes fit the cases they were made on.

Elsewhere nothing moved: LeakBench gives the same escapes and false-positive rate in all four configurations, and the
full test suite passes. The scan costs a little more: 20.9 ms per ProwlBench case at the 95th
percentile, against 19.7.

Two things to know when reading these numbers. The halves share ProwlBench's generator templates, so the holdout half
guards against fitting particular values more than particular phrasings; that is why each rule is general and tested
on our own phrasings. And ProwlBench's research-only rows, which need models that a clean checkout does not have and
which it says carry about 5% train/test leakage, score higher (its cascade with a logistic regression 0.905, with a
multilingual encoder 0.962); they are not in the table.

**What is left.**

- *False alarms*, still 10.7% of the hard negatives. On the dev half, 41% of them are on negatives that assign a
  value to a credential-named field (the pattern counted above), 24% on a credential slot written another way ("set
  password to …", "| token | … |", "rotate the token (…)") holding a hash, a UUID or base64, and 28% on a token in a
  provider's format: ProwlBench's near misses with a broken checksum, and real-format tokens its text calls rotated
  or an example. Harpo redacts all three on purpose: a placeholder costs little, and a credential that leaves cannot
  be called back. The other 7% are noise still to fix.
- *Real-world snippets* account for most of the remaining misses: a secret in a sentence with no cue for it ("a strong
  password might be …", "use the … given"), UUIDs in id fields labelled as secrets, `Key = <hex>` with no other word,
  and obfuscated values with blanks in them.
- *The PII datasets*, which this round did not look at: they are round 2's.

## Hardening, round 2 (OpenPII, Nemotron-PII, RedactionBench)

Made on the dev halves of the three PII datasets, with the same rule as round 1: every fix is a general rule, written
for how people and programs write a kind of value in any language and tested on phrasings of our own (294 new
tests), never a pattern for one dataset's templates. The datasets only showed where the gaps were. The holdout halves
were run once, at the end, together with ProwlBench and LeakBench.

**What changed.**

- *Values named by the word in front of them* ([detectors/cued.py](../src/harpo_redact/detectors/cued.py)). The
  words that introduce phone numbers, card numbers, national and tax numbers, identity documents, postcodes, account
  and membership numbers, bank codes, IBANs, vehicles, devices and PINs, in some thirty languages, Chinese, Japanese
  and Korean included. Case and accents are folded, inflections and compounds read ("telefonu", "kortelės",
  "Sozialversicherungsnummer", but not "Telefonkonferenz"), field names split ("phoneNumber", "device_id"), and a
  number word on either side counts ("Steuer-Nr.", "numer klienta", "nomor pajak"). Between the word and its value:
  up to four words, signs, asides and markup, never the end of a sentence; the nearest cue decides, and a value ends
  where the next label begins. After a cue, the shape is enough: a value that fails its checksum or comes from a
  country without a validator is protected all the same, since a number one digit off still points to a person.
  Dates, times, IP addresses, versions and amounts (a decimal part, thousands set off by commas, a currency next to
  it) are not taken. Words that name a person ("customer", "patient") name a number only right after them, words
  that name an amount as often as a number ("claim", "policy") ask for a number word or a code, and a bare "ID"
  counts only as a field's label. Without a cue the validators still decide: an international phone number in
  groups counts when its country's plan has it, a card number in its network's grouping when its Luhn digit is
  right, a vehicle identification number by its shape.
- *Addresses in their local grammar* ([detectors/addresses.py](../src/harpo_redact/detectors/addresses.py)): street
  words before or after the name in some twenty-five languages and glued to it, house-number markers, the postcode
  and town after a street, a US state and ZIP code, address labels and phrases ("Anschrift:", "住所：", "wohnhaft
  in", "residing at"), Chinese, Japanese and Korean addresses, and region and country labels ("State: IL"; not
  "State: Running").
- *Names in other languages* ([detectors/names.py](../src/harpo_redact/detectors/names.py)): greetings, honorifics
  and name labels in some twenty-five languages, speakers in a chat log, "I, <name>, hereby", `/s/` signatures,
  titles written after the name ("Kovács Péter úr", "Tanaka-san"), and Chinese, Japanese and Korean names with an
  honorific.
- *Tables* ([detectors/fields.py](../src/harpo_redact/detectors/fields.py)): a column header or row label in any
  language the cue words know types the cells under it by shape, and a label for a person's name, an address or a
  place types a cell that holds one whole. A bare "Name" column or a "State" column counts only in a table about
  people.
- *Machine formats that hold people* ([detectors/formats.py](../src/harpo_redact/detectors/formats.py)): HL7 v2
  segments field by field, the machine-readable zones of passports and identity cards, AWS account ids, ARNs and
  principal ids, user names where formats put them (home directories, `uid=`, LDAP names, Windows events, URL user
  info, shell prompts), MAC chains in firewall logs, typed credentials (`whsec_…`, `sk_live_…`-style keys), WIF keys,
  and bech32 addresses whose checksum is off after a word that names them.
- *Credentials in prose and records*: PINs, CVVs and door codes are secrets; the word for password straight before
  its value ("his password River45!") or after "such as", "like", "include" or "of"; "I changed my password to …";
  command-line flags, environment variables as a name and a value, Redis `AUTH` and `SET`, `net use … /user:`; and
  `Key = <hex>` when the value is random.
- *Two things outside the detectors.* A custom type the user defined names a value that a cue word only suggests
  ("badge EMP-123456" is `[EMPLOYEE_ID_1]`, not `[ACCOUNT_ID_1]`), and egress verification counts each value once,
  not once per rule that finds it.

**What it did.** The tables above have every number. On the holdout halves, the share of values fully removed went from
50.1% to 74.4% on OpenPII, from 79.3% to 94.6% on Nemotron-PII and from 80.4% to 83.7% on RedactionBench. On OpenPII the
dev half (74.6%) and the holdout half (74.4%) are as close as they were at the baseline, and so are Nemotron-PII's
(94.7% and 94.6%): no sign that the rules fit the documents they were made on. RedactionBench's are not: its dev half
rose from 69.0% to 91.5% and its holdout half from 80.4% to 83.7%. Its 200 documents are each of a kind (an HL7 feed, a
passport's machine-readable zone, a CloudTrail log, an employee CSV), and most of the formats fixed on the dev half do
not occur in the holdout half. What the holdout half still misses was not looked at, as the protocol says, so it is the
number to read.

Per label, on all of OpenPII: phone numbers from 30.8% to 78.8%, streets from 46.7% to 73.4%, building numbers from
13.0% to 57.2%, postcodes from 10.9% to 66.5%, ID cards from 9.3% to 47.6%, card numbers from 8.7% to 45.8%, driving
licences from 12.7% to 51.2%, passports from 14.4% to 50.9%, tax numbers from 22.7% to 63.6%, social security numbers
from 27.4% to 58.0%, given names from 75.2% to 86.3% and surnames from 77.2% to 88.2%. Every language rose: Chinese from
21% to 45%, Korean from 18% to 40%, Japanese from 16% to 29%, the others to between 67% and 85%. On Nemotron-PII every
label rose or stayed, the identifiers most: device identifiers from 1.8% to 84.4%, licence and certificate numbers from
7.1% to 96.9%, health plan numbers from 9.3% to 97.2%, card numbers from 11.9% to 96.9%, postcodes from 12.2% to 90.6%,
vehicle numbers from 22.6% to 96.8%, bank routing numbers from 26.7% to 98.4%, PINs from 33.4% to 90.1%, national ids
from 54.4% to 93.9%, passwords from 56.3% to 89.6% and street addresses from 58.5% to 91.0%. Company names, which are
NER's to find, moved least (74.7% to 77.6%).

Collateral stayed where it was: 13.2% on OpenPII (13.2% before), 4.1% on Nemotron-PII (4.0%) and 9.1% on RedactionBench
(8.9% after round 1, 9.5% at the baseline). The new layers add little of it next to NER's: on OpenPII, 5,484 letters and
digits redacted as addresses outside a gold value, against 263,190 as people, organisations and places.

ProwlBench moved a little: F1 0.938 on all cases (0.934 after round 1) and 0.935 on the holdout half (0.931), recall
0.931 (0.922), precision 0.945 (0.946). Harpo flags 890 of the 8,051 hard negatives, 25 more than after round 1 (11.1%
against 10.7%). Of the ten new ones on the dev half, seven are PINs, CVVs and a password in snippets that ProwlBench
counts as negatives because they are about personal data ("the CVV is 531", "our password River77!"), one is a password
in a chat ("logged into the console with the team pw Orange3568$"), and two are counting sequences after `Key =`
("e0e1e2e3…"). Harpo redacts the first eight on purpose; the last two are left to fix. On the dev half no positive found
after round 1 was lost. LeakBench gives the same escapes, false positives and false blocks in all four configurations,
and the full test suite passes.

The latencies in the tables are not comparable across runs: the machine that recorded `hardening-2` ran slower on the
day than when it recorded the other two. Back to back on one machine, one process and the configuration above, on 600
Nemotron-PII and 600 OpenPII documents and 40 RedactionBench documents (each scanned twice), `hardening-2` took 7%
longer than `hardening-1` on Nemotron-PII and OpenPII and 9% longer on RedactionBench; per document at the 95th
percentile, 62 ms against 58, 36 ms against 33 and 1.12 s against 1.09 s.

**What is left.**

- *Values no word names.* On OpenPII's dev half, 91% of the identifiers still missed (2,961 of 3,247) have no cue
  word in the 60 characters before them: its generator puts the value where the noun would be ("a valid YS9583800
  will be required at check-in", "bring your 796399850577"). Without a cue a value has to pass its format's check,
  and these do not.
- *Chinese, Japanese and Korean* stay the weakest languages on OpenPII (29% to 45%): names without an honorific and
  addresses without the markers the rules read.
- *Company names*, 44% of what Nemotron-PII's dev half still misses (6,089 of 13,813 values): organisations are
  NER's to find, and the small models find three in four. Places (states, cities, countries, counties) are another
  17%.
- *RedactionBench's mandatory spans that Harpo does not treat as personal data*: dates (kept by policy, birth dates
  excepted), event and request ids, instance ids, role names and password hashes.
- *Gretel PII masking*, not run: its files could not be fetched.

## Hardening, round 3 (Asian scripts, precision, and the Dutch, US and EU library)

Made on the dev halves of OpenPII and RedactionBench and on RegionBench's dev templates, with the rule of the rounds
before: every fix is a general rule about how a kind of value is written, tested on phrasings of our own (186 new
tests), never a pattern for one dataset's templates. Nemotron-PII and ProwlBench were not studied this round; they
were run to see that nothing they measure got worse. The holdout halves were run once, at the end.

**What changed.**

- *Chinese, Japanese and Korean* ([detectors/cjk.py](../src/harpo_redact/detectors/cjk.py)), read by the structure
  the scripts give an address or a name, since no blank sets a word off. Japanese: the 47 prefectures (都, 道, 府,
  県), the municipality chain (市, 区, 町, 村, 郡) and the block numbers after it (3丁目4番5号, 3-11-30番地),
  postcodes with or without 〒, and names before an honorific, after a closing or led by a common family name.
  Korean: the provinces and metropolitan cities, the city, district and neighbourhood chain, road-name addresses (a
  road ending in 로 or 길, then its building number) and lot numbers, and names before 님 or 씨 or after a title,
  checked against the common family names (김, 이, 박, 최, 정...). Chinese: the administrative hierarchy (省, 市, 区,
  县, 镇, 乡, 街道), roads with their numbers, a place after "located at", and two- or three-character names led by a
  single or compound family name (王, 李, 欧阳, 东方) after a title, a verb that takes a person (由...签署, 致电,
  联系) or written apart as transliterated text has them. A unit word alone is never enough where it is also an
  everyday word (超市 is a supermarket, 친구 a friend). Values that run straight into the script without a blank
  ("4111111111111111で", "jane@corp.example宛に", "07 5871 2555で", "请携带FXJPIUZXKH") are read in a view with a
  blank at each seam, and Korean resident registration numbers and Chinese resident identity numbers by the birth
  date inside them.
- *Opaque codes* ([detectors/opaque.py](../src/harpo_redact/detectors/opaque.py), a new family): values that no
  language writes, standing in a sentence with no word to name them. Words, names, acronyms and the identifiers of
  code are told from generated codes by the letter pairs they use (the pairs of words in some twenty languages) and
  by where their case changes: a code in capitals is an identifier, random letters in both cases a password; hashes,
  masks, test strings and quoted data are left alone. The same test lets a cue word name a code in capitals alone,
  and a password word name random letters a few words on.
- *Precision* ([detectors/ner.py](../src/harpo_redact/detectors/ner.py)). The NER models' tags pass a filter: words
  the text also writes in lower case, terms a document defines for itself and abbreviations it spells out, field
  labels, table headers, acronyms, code names, user agents, document titles and instruction verbs are not people or
  organisations, and a name found once is spread to its other mentions only where it could be one. The filter keeps
  a full name written in lower case to slip past and a name in leetspeak. Elsewhere: dates are not phone numbers, a
  version in a product token is not an IP address, well-known Windows and service accounts are not people, and the
  name of a constant or a hash scheme is not a password.
- *Found in more places*: user and account ids in URL paths, parameters and store keys, meeting links, the machine
  in a shell prompt, customer IAM roles, HL7 fields by their shape, forms laid out as "Label   value" and form lines
  after an item number, codes with a lower-case prefix ("usr-..."), digit groups written with " - ", transaction,
  acquirer-reference and meeting cues, grouped passcodes, driving licences that open with the surname, and SSH public
  keys checked by the key type encoded in them.
- *The Dutch, US and EU library* ([REGIONS.md](REGIONS.md)): region packs for formats with a check
  (btw-identificatienummer, loonheffingennummer; masked SSNs and their last four, ATIN, the Medicare MBI, USCIS
  receipt and A-Numbers, I-94; the VAT numbers of every member state, the BIC, EU COVID certificate ids) and cue
  words for the rest of each region's identifiers, measured by [RegionBench](#regionbench).
- *The library* ([LIBRARY.md](LIBRARY.md)): every detector under the kind of data it protects, each family with one
  switch, live on the console's Policy page.

**What it did.** The tables above have every number.

On OpenPII's holdout half the values fully removed rose from 74.4% to 76.6% (the dev half from 74.6% to 77.0%), and
collateral fell from 13.2% to 5.1%: the precision filter takes away most of what NER redacted outside a gold value.
The three languages round 2 left weakest gained most. On all of OpenPII, Japanese rose from 28.7% to 59.0%, Korean
from 39.8% to 68.1% and Chinese from 45.4% to 69.2%; the others a little (Dutch 79.0% to 81.3%, English 77.8% to
79.5%).

RedactionBench's own score, the R-Score, rose from 0.311 to 0.460 (dev half 0.315 to 0.478, holdout half 0.308 to
0.442; median document 0.295 to 0.467): a little more of each mandatory entity is covered, and the false-positive
runs the score counts fell from 19,048 to 4,477 (collateral 9.1% to 3.6%). On the published table that puts Harpo,
which runs on a CPU with small NER models, level with OpenMed's 434M-parameter model (0.46) and above NVIDIA's
GLiNER-PII (0.42) and the models below it; Gretel's GLiNER (0.47), OpenAI's privacy filter (0.58) and the LLMs score
higher. The share of mandatory values fully removed rose on the dev half (91.5% to 93.0%) and fell on the holdout
half (83.7% to 81.3%).
That loss sits in one kind of document: counted by category and shape, without reading them, 212 of the 227 values
the holdout half no longer removes are digit runs in log documents, while every other category rose. The dev half's
log documents lost nothing (every digit run hardening-2 redacted there, hardening-3 redacts too), so the cause is in
a log format only the holdout half has. As the protocol says, those documents were not studied, and the number
stands.

Nemotron-PII, not studied this round, rose a little: 94.6% to 94.8% fully removed on the holdout half (the dev half
94.7% to 94.8%), with collateral down from 4.1% to 2.3%. Street addresses (91.0% to 92.5%), medical record numbers
(96.0% to 97.8%) and device identifiers (84.4% to 89.0%) gained most; bank routing numbers lost 49 of 8,354 values
(98.4% to 97.8%), and counties, states and countries a few dozen each.

ProwlBench, not studied this round either, rose a little: F1 0.941 on all cases (0.938) and 0.939 on the holdout half
(0.935), recall 0.936 (0.931), precision 0.946 (0.945), free-form and multilingual snippets 0.894 (0.880).
Harpo flags one more of the 8,051 hard negatives (891 against 890). LeakBench gives the same escapes in the
deterministic and default configurations (116 and 25) and one fewer with English NER alone (34), with fewer false
positives in every configuration that runs a model (default 0.18% against 0.29%, all languages 0.14% against 0.25%).
The full test suite passes.

On [RegionBench](#regionbench)'s holdout templates, the documents no fix was written against, hardening-3 removes
98.2% of the Dutch values, 96.4% of the US values and 96.7% of the EU values, against 79.2%, 83.6% and 79.4% for
hardening-2 and 70.0%, 71.3% and 48.3% for 2.4.0; on the dev templates 99.9%, 100% and 100%. It damages 5.5% of the
keeps, against 18.2% for hardening-2. What it removes least often are US prescription numbers (50%), Dutch case-file
numbers (62.5%) and US insurance group numbers (80%).

**Speed.** The latencies in the tables come from runs on different days and are not comparable across them. Back to
back on one machine and one interpreter, each build installed into a copy of the same environment, on 600
Nemotron-PII and 600 OpenPII documents and 40 RedactionBench documents (CPU time, best of two passes, two rounds),
hardening-3 with the configuration above takes 1% longer than hardening-2 on Nemotron-PII, 6% longer on OpenPII and
4% longer on RedactionBench (hardening-2 took 10% to 11% longer than 2.4.0). The deterministic layers alone, where
most of the new rules run, take 8%, 18% and 7% longer than hardening-2's; Chinese, Japanese and Korean text, which
OpenPII has much of, costs most. On LeakBench's short prompts the default configuration takes 8.5 ms on average
against 7.8 ms (p95 14.3 against 12.7 ms on that machine) and the deterministic layers 2.6 ms against 2.1 ms. Each
new family can be switched off in the [library](LIBRARY.md) where speed matters more than what it finds.

**What is left.**

- *RedactionBench's holdout log documents*, above: to study them they would have to become dev data, and the R-Score
  would need another held-out set.
- *Identifiers and address parts no word names* on OpenPII: building numbers, card, ID card, licence, passport, social
  security and tax numbers and postcodes are most of what its dev half still leaks. Japanese (59%) is the lowest
  language now; Korean and Chinese (68% and 69%) sit with Bulgarian, Greek, Latvian and Hungarian, below the 70% to
  87% of the others.
- *Company names* on Nemotron-PII, NER's to find, and *RegionBench's weakest kinds*: US prescription and insurance
  group numbers and Dutch case-file numbers.
- *RedactionBench's mandatory spans that Harpo does not treat as personal data*: dates (kept by policy, birth dates
  excepted), event and request ids, instance ids and role names.
- *Gretel PII masking*, not run: its files could not be fetched.

## Deferred evaluations

Gretel PII masking was not run: its dataset could not be fetched in the benchmark environment.

No benchmark-driven hardening was done after `hardening-3`; Harpo 2.5.0 was released on its detection.

Evaluations run later are recorded separately, next to these, and do not change the frozen evidence of the 2.4.0
baseline, `hardening-1`, `hardening-2` and `hardening-3`.
