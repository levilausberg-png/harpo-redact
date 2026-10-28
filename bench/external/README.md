# External benchmarks

Scores Harpo on public datasets it was not built against: five are supported, four have been run (Gretel PII masking
was not: its files could not be fetched). The protocol, the recorded results and what they show:
[docs/EXTERNAL_BENCHMARKS.md](../../docs/EXTERNAL_BENCHMARKS.md).

| File | What it does |
| --- | --- |
| `corpora.py` | reads each dataset as its publisher ships it; cuts single-split datasets into dev and holdout halves |
| `scope.py` | which labels count toward the headline, fixed before any result was seen |
| `harness.py` | runs every document through the pipeline and scores what was removed, partly removed or leaked |
| `rscore.py` | RedactionBench's own document score, the R-Score (its paper's section 3.3), reported with every run |
| `run.py` | the command line: one dataset, one file, one result file |
| `report.py` | writes the tables in docs/EXTERNAL_BENCHMARKS.md from the result files, RegionBench's included |
| `results/<run>/` | the recorded results: totals only, no dataset text |

## Get the data

Download each file from its publisher into a folder outside this repository. None of it is committed here.

| Dataset | Where | File |
| --- | --- | --- |
| `openpii` | huggingface.co/datasets/ai4privacy/openpii-masking-micro-100k (or the 1.5M set) | `data/validation.jsonl` |
| `nemotron` | huggingface.co/datasets/nvidia/Nemotron-PII | `data/test-00000-of-00001.parquet` |
| `gretel` | huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1 | `data/test-00000-of-00001.parquet` |
| `redactionbench` | huggingface.co/datasets/RedactionBench/RedactionBench | `data/test-00000-of-00001.parquet` |
| `prowlbench` | github.com/Lercas/prowlbench | `prowlbench.jsonl` |

ProwlBench is licensed PolyForm Noncommercial 1.0.0: use it to evaluate, do not copy it into this repository.

## Run

Install the Harpo build to measure into its own environment, not in editable mode, with the language models from
`requirements-models.lock` and `pyarrow` for the parquet files. Then, from that environment:

```sh
python bench/external/run.py prowlbench ~/data/prowlbench/prowlbench.jsonl --out bench/external/results/2.4.0-baseline --gitleaks "$(command -v gitleaks)"
python bench/external/run.py openpii ~/data/openpii/validation.jsonl --out bench/external/results/2.4.0-baseline
python bench/external/run.py nemotron ~/data/nemotron/test-00000-of-00001.parquet --out bench/external/results/2.4.0-baseline
python bench/external/run.py gretel ~/data/gretel/test-00000-of-00001.parquet --out bench/external/results/2.4.0-baseline
python bench/external/run.py redactionbench ~/data/redactionbench/test-00000-of-00001.parquet --out bench/external/results/2.4.0-baseline
python bench/external/report.py
```

`--config deterministic` measures the deterministic layers without NER, `--workers` sets the processes (each loads
its own models), `--limit` scores the first N documents, and `--half dev` scores the dev half alone, for work on
fixes. `--details FILE` writes every document's misses with their context, for studying failures; it holds dataset
text, so keep it outside the repository. `report.py` shows the result folders named in the doc's
`<!-- results ... -->` line; `report.py --check` tells whether the doc is current, and the test suite checks the same.

RegionBench, for the Dutch, US and EU identifiers no public dataset covers, lives in `bench/regionbench/` and needs no
download: `python bench/regionbench/run.py run --save <run>` scores the build of the interpreter that runs it and
writes `results-<run>.json`, which `report.py` puts in the doc's `<!-- regionbench ... -->` table.

## Rules

- A run is recorded before anything is changed because of it. A later build gets a new results folder; a folder is
  never overwritten with another build's numbers.
- Failures are studied on training data and dev halves only: `--details` on a train split, or the cases whose
  `half` is `dev`. Test, validation and holdout data are only ever counted.
- A label that turns up unmapped gets a scope entry by the rule in `scope.py`, never by its result.
