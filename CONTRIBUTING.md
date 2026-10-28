# Contributing

Set up the same environment CI uses (Python 3.12, every package and model hash-pinned):

```bash
python -m pip install --require-hashes --no-deps -r requirements.lock -r requirements-dev.lock -r requirements-models.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m playwright install chromium        # the console's browser tests; LibreOffice renders redacted Office files
```

Before a change is merged:

- `ruff check`, `ruff format --check`, `mypy` (strict) and `bandit -r src -c pyproject.toml` pass.
- `pytest` passes. It includes the adapter conformance suite (`tests/test_conformance.py`), the named invariants
  (`tests/test_invariants.py`) and the LeakBench regression gate (`tests/test_leakbench.py`). Without Chromium,
  LibreOffice or the language models, the tests that need them skip on your machine; CI sets
  `HARPO_REQUIRE=browser,libreoffice,models`, so there they must run (`HARPO_REQUIRE` works locally too).
- A change to the Dockerfile or the Compose files passes `python tools/docker_smoke.py` (CI's `docker` job).
- A detection change comes with tests for the attack and for its benign look-alike, and with a LeakBench run:
  `python bench/leakbench.py run --config multilingual`. Escapes and the false-positive rate may not go up. If the
  corpus changes, regenerate `bench/leakbench/baseline.json` in the same commit and say why.
- A new provider adapter declares its surfaces in `adapters.py` and passes `conformance.run` with realistic samples
  that exercise every declared surface (`test_every_declared_surface_is_exercised_by_the_samples`).
- No request content in logs or errors: codes, counts and field paths only.

Dependencies are pinned by hash in `requirements.lock`, compiled for Linux (CI and the image) with
`uv pip compile pyproject.toml --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28
--no-header -o requirements.lock` (`--upgrade-package NAME` moves one package and keeps the rest). Then run
`pip-audit -r requirements.lock --require-hashes`, `python tools/third_party.py` (the licence table) and
`python tools/make_sbom.py > sbom.cdx.json`. The test tools (`requirements-dev.lock`) and the build tools
(`requirements-build.lock`) are compiled from their `.in` files, as each lock's header says. GitHub Actions are pinned
to commit SHAs and the base image to a digest; Dependabot proposes updates for all of them.

A way past a protection that should have held is a security report, not an issue or a pull request: report it
privately ([SECURITY.md](SECURITY.md)). A detection miss with invented values is welcome as an issue.

How a version is released (the `release` workflow, and what a maintainer does around it): [docs/RELEASING.md](docs/RELEASING.md).

Contributions are licensed under Apache-2.0, the project's licence (section 5 of the licence).
