"""LeakBench as a regression gate: a change that lets more through, or damages more text, fails here."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from .conftest import needs

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "bench" / "leakbench" / "baseline.json").read_text())


def leakbench():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("leakbench", ROOT / "bench" / "leakbench.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("config", ["deterministic", "multilingual"])
def test_no_more_escapes_or_false_positives_than_the_baseline(config: str) -> None:
    if config == "multilingual" and not all(
        importlib.util.find_spec(m)
        for m in ("nl_core_news_sm", "de_core_news_sm", "fr_core_news_sm", "es_core_news_sm")
    ):
        needs("models", "language models not installed")
    result = leakbench().run(config, None, None)
    base = BASELINE[config]
    assert result["corpus"]["sha256"] == base["corpus_sha256"], "corpus changed: regenerate the baseline deliberately"
    assert result["raw_identifier_escapes"] <= base["raw_identifier_escapes"]
    assert result["false_positive_rate"] <= base["false_positive_rate"]
    worse = {
        k: v["escapes"]
        for k, v in result["by_category"].items()
        if v["escapes"] > base["escapes_by_category"].get(k, 0)
    }
    assert worse == {}
