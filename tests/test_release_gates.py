"""What stands between a commit and a release: evidence that may not skip in CI, actions pinned to commits, a release
that waits for the whole CI workflow, images pinned, and the Docker smoke test's own expectations."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from harpo_redact.config import load_settings
from harpo_redact.pipeline import Pipeline
from harpo_redact.presets import MODEL_WHEELS

from . import conftest
from .conftest import make_settings

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow(name: str) -> dict[str, Any]:
    data = yaml.safe_load((WORKFLOWS / name).read_text())
    data["on"] = data.pop(True, data.get("on"))  # YAML 1.1 reads the key `on` as True
    return data  # type: ignore[no-any-return]


def smoke() -> ModuleType:
    spec = importlib.util.spec_from_file_location("docker_smoke", ROOT / "tools" / "docker_smoke.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_tools_skip_locally_and_fail_where_required(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(conftest, "REQUIRED", frozenset())
    with pytest.raises(pytest.skip.Exception):
        conftest.needs("libreoffice", "LibreOffice is not installed")
    monkeypatch.setattr(conftest, "REQUIRED", frozenset({"libreoffice"}))
    with pytest.raises(pytest.fail.Exception, match="HARPO_REQUIRE includes libreoffice"):
        conftest.needs("libreoffice", "LibreOffice is not installed")


def test_ci_requires_every_tool_and_installs_it() -> None:
    test = workflow("ci.yml")["jobs"]["test"]
    assert set(test["env"]["HARPO_REQUIRE"].split(",")) == conftest.CAPABILITIES
    script = "\n".join(step.get("run", "") for step in test["steps"])
    assert "playwright install --with-deps chromium" in script and "libreoffice-writer" in script
    assert "requirements-models.lock" in script and "--require-hashes" in script
    assert re.search(r"^\s*pytest\b", script, re.M)


def test_every_action_is_pinned_to_a_commit() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for line in path.read_text().splitlines():
            ref = re.search(r"uses:\s*(\S+)", line)
            if not ref or ref.group(1).startswith("./"):
                continue
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref.group(1)), f"{path.name}: {line.strip()}"
            assert re.search(r"#\s*v\d+\.\d+\.\d+\s*$", line), f"{path.name}: say which release: {line.strip()}"


def test_a_release_publishes_only_after_the_whole_ci_workflow_passes() -> None:
    assert "workflow_call" in workflow("ci.yml")["on"]
    release = workflow("release.yml")
    jobs = release["jobs"]
    assert release["permissions"] == {} and jobs["verify"]["uses"] == "./.github/workflows/ci.yml"

    def upstream(name: str) -> set[str]:
        needs = jobs[name].get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        return set(needs).union(*(upstream(n) for n in needs))

    publishing = [name for name, job in jobs.items() if "write" in (job.get("permissions") or {}).values()]
    assert sorted(publishing) == ["dist", "image"]
    for name in publishing:
        assert {"verify", "preflight"} <= upstream(name), name
    assert "published" in upstream("dist")  # the GitHub release waits until the pushed image passed the smoke test
    preflight = "\n".join(step.get("run", "") for step in jobs["preflight"]["steps"])
    assert "tools/set_repo.py --check" in preflight and '"$tag" != "v$version"' in preflight
    assert jobs["image"]["permissions"] == {"contents": "read", "packages": "write"}
    # Started from the Actions tab, the release creates its tag only at the end, on the commit it verified.
    assert "version" in release["on"]["workflow_dispatch"]["inputs"]
    final = jobs["dist"]["steps"][-1]["with"]
    assert (
        final["tag_name"] == "${{ needs.preflight.outputs.tag }}" and final["target_commitish"] == "${{ github.sha }}"
    )


def test_provider_keys_reach_only_a_run_started_by_hand() -> None:
    """The provider-smoke workflow holds real API keys: it runs only from Run workflow, never on a push or a pull
    request (where a fork could reach it), and the keys reach one step, as environment variables."""
    smoke = workflow("provider-smoke.yml")
    assert list(smoke["on"]) == ["workflow_dispatch"] and smoke["permissions"] == {"contents": "read"}
    text = (WORKFLOWS / "provider-smoke.yml").read_text()
    assert text.count("secrets.") == 2
    steps = smoke["jobs"]["smoke"]["steps"]
    assert [s for s in steps if "secrets." in str(s.get("env", ""))] == [steps[-1]]
    assert "${{" not in steps[-1]["run"]  # inputs reach the script as environment variables, never pasted into it


def test_compose_files_run_the_image_this_version_builds() -> None:
    version = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)[1]  # type: ignore[index]
    for name in ("docker-compose.yml", "docker-compose.demo.yml"):
        own = re.findall(r"^\s*image:\s*harpo-redact:(\S+)", (ROOT / name).read_text(), re.M)
        assert own == [version], (name, own)


def test_images_are_pinned_and_compose_starts_without_optional_variables() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.12-slim-bookworm@sha256:[0-9a-f]{64} AS python-base$", dockerfile, re.M)
    for name in ("docker-compose.yml", "docker-compose.demo.yml"):
        text = (ROOT / name).read_text()
        for image in re.findall(r"^\s*image:\s*(\S+)", text, re.M):
            assert re.search(r":(v?\d+\.\d+\.\d+)$", image) or "@sha256:" in image, f"{name}: {image}"
        # Compose resolves every service's variables, also in profiles that are not started: a required one
        # (${VAR:?message}) in an optional service stops `docker compose up` for everything.
        code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        assert ":?" not in code, name


def test_model_pins_agree_everywhere() -> None:
    lock = dict(
        re.findall(r"@ (\S+) \\\n\s+--hash=sha256:([0-9a-f]{64})", (ROOT / "requirements-models.lock").read_text())
    )
    dockerfile = (ROOT / "Dockerfile").read_text()
    for url, digest in MODEL_WHEELS.values():
        assert lock.get(url) == digest, url
        assert digest in dockerfile, url
    assert len(lock) == 6


def test_the_smoke_configuration_loads(tmp_path: Path) -> None:
    module = smoke()
    path = tmp_path / "harpo.yaml"
    path.write_text(module.smoke_config("mock", "a" * 64, "b" * 64))
    settings = load_settings(str(path))
    assert settings.auth.enabled and [k.admin for k in settings.auth.keys] == [False, True]
    assert [u.base_url for u in settings.upstreams] == ["http://mock:9100/v1", "http://mock:9100"]
    assert settings.server.workers == 2


def test_the_smoke_prompt_is_fully_redacted() -> None:
    """The Docker smoke test expects one placeholder per kind; this fails first, and faster, if detection changes."""
    module = smoke()
    text = Pipeline(make_settings()).scan_sync([module.PROMPT]).texts[0]
    assert not [value for value in module.VALUES if value in text], text
    kinds = set(re.findall(r"\[([A-Z_]+?)_\d+\]", text))
    assert set(module.VALUES.values()) <= kinds, text


def test_the_dev_extra_and_the_dev_lock_input_pin_the_same_tools() -> None:
    """pyproject.toml's dev extra (pip install -e ".[dev]") and requirements-dev.in (compiled into the hash-pinned
    requirements-dev.lock) name the same versions, so the two ways in never test with different tools."""
    import tomllib

    extra = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]["dev"]
    lock_input = [
        line.strip()
        for line in (ROOT / "requirements-dev.in").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert sorted(extra) == sorted(lock_input)


def test_the_package_ships_its_type_information() -> None:
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert "py.typed" in data["tool"]["setuptools"]["package-data"]["harpo_redact"]
    assert (ROOT / "src/harpo_redact/py.typed").is_file()
    assert "Typing :: Typed" in data["project"]["classifiers"]
