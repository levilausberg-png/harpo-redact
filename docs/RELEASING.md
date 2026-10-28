# Releasing Harpo

How a version gets from `main` to a GitHub release, a container image on GHCR and checksummed files. The `release`
workflow does the publishing and refuses to publish anything it has not verified; this page is what a maintainer does
around it.

## Once, before the first public release

- **Security contact.** `SECURITY.md` and `CODE_OF_CONDUCT.md` name it (Security.Harpo@gmail.com, set with
  `python tools/set_repo.py --contact`). `python tools/set_repo.py --check` prints `no placeholders left` and exits 0;
  the release workflow runs it too.

- **Repository settings the files rely on:** private vulnerability reporting (`SECURITY.md` and the issue chooser
  link to `security/advisories/new`), Discussions (the issue chooser links there), and the `ci` checks `test`,
  `secrets` and `docker` required on `main`.
- **The first green `ci` run.** It is the first run of the Docker smoke test, the browser tests and the LibreOffice
  rendering tests on GitHub's runners, and the `secrets` job scans the whole git history with gitleaks. If gitleaks
  flags invented test data at an old path, add the path to `.gitleaks.toml`; if it flags a real key, revoke the key
  and clean the history before the repository goes public.

## Every release

1. **One version, three places.** `version` in `pyproject.toml`, `__version__` in `src/harpo_redact/__init__.py` and
   a `## X.Y.Z` heading in `docs/CHANGELOG.md`. The workflow stops if the tag and these disagree.
2. **Dependencies.** If a lock changed: `pip-audit -r requirements.lock --require-hashes`,
   `python tools/third_party.py` (the licence table; `--check` compares) and
   `python tools/make_sbom.py > sbom.cdx.json` ([CONTRIBUTING.md](../CONTRIBUTING.md) has the lock commands).
3. **The gates CI runs**, locally if you like: `ruff check src tests bench tools`,
   `ruff format --check src tests bench tools`, `mypy`, `bandit -q -r src -c pyproject.toml`, `pytest -q -rs` with
   `HARPO_REQUIRE=browser,libreoffice,models`, gitleaks over the tree and the history, and
   `python tools/docker_smoke.py`. A detection change also needs its LeakBench run
   (`python bench/leakbench.py run --config multilingual`).
4. **Release.** Actions → `release` → Run workflow on `main` with the version (`2.5.0`), or push the tag `v2.5.0`.
   The workflow:
   - runs the whole `ci` workflow again on that commit (`verify`);
   - checks that the tag, `pyproject.toml`, `harpo_redact.__version__` and the changelog agree, and that
     `tools/set_repo.py --check` finds no placeholder (`preflight`);
   - builds the image for linux/amd64 and linux/arm64 and pushes it to `ghcr.io/levilausberg-png/harpo-redact` with
     provenance and an SBOM (`image`);
   - pulls that image back by digest and puts it through `tools/docker_smoke.py --no-build` (`published`);
   - builds the wheel and the sdist with the hash-pinned build tools, writes `sbom.cdx.json` and `SHA256SUMS`, and
     creates the GitHub release with all four (`dist`). Started from the Actions tab, it also creates the tag, on the
     commit it verified.
5. **After the first release:** make the container public (your profile → Packages → `harpo-redact` → Package
   settings → Change visibility); GHCR starts every package private.
6. **Release notes.** The workflow attaches GitHub's generated notes; replace them with the written notes for the
   version, which start from its changelog entry.
7. **Check what was published:** download the release files and run `sha256sum -c SHA256SUMS`; `docker pull` the
   image from a machine that is not logged in to GHCR.

Optional: the `provider-smoke` workflow (or `python tools/provider_smoke.py --start --openai-model gpt-5-mini
--anthropic-model claude-haiku-5-5` with the keys in your environment) sends a request, a stream, a tool call and its
result, a provider error and a cancelled stream to the real providers, for a few cents. The tests only ever talk to
mocks of the providers' wire formats.

PyPI publishing is not automated, and 2.5.0 is not on PyPI. The README installs from the release tag
(`pip install "harpo-redact @ git+https://github.com/levilausberg-png/harpo-redact@v2.5.0"`) or from a clone
(`python -m pip install .`), so it is not needed for a release; to publish later, upload the wheel and the sdist from
the GitHub release after checking them against `SHA256SUMS`.
