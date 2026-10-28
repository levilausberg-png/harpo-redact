## What and why

## Checklist
- [ ] `ruff check`, `ruff format --check`, `mypy` and `pytest` pass (the suite includes the conformance suite, the invariants and the LeakBench gate)
- [ ] Detection change: a test for the attack *and* for its benign look-alike, and a LeakBench run (escapes and false positives may not go up)
- [ ] New request surface: declared in `adapters.py` and exercised by the conformance samples
- [ ] No request content in logs, errors or tests' fixtures beyond made-up values
- [ ] Docs and `docs/CHANGELOG.md` updated
