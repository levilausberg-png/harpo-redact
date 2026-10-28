"""The SDK examples in examples/python/sdk run unchanged, as a user runs them, and print what they promise."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from .test_sdk import _models_or_skip, fresh_environment

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/python/sdk"
# Invented values in the examples: none may come out of an example that redacts them.
RAW = ["maria.jansen@northwind.example", "4111 1111 1111 1111", "AKIAZ4X7Q2LMWN3RT5PJ", "priya.raman@corp.example",
       "lars.eriksen@corp.example", "Qz7vL2mX9pR4tW8k", "NL91 ABNA 0417 1643 00", "+31 20 794 6095"]  # fmt: skip
EXPECT = {
    "scan_text.py": ["risk: yellow", "Customer [PERSON_1] ([EMAIL_1], [PHONE_1])", "AWS key [SECRET_1]."],
    "redact_or_block.py": ["Send the contract to [EMAIL_1] by Friday.", "types: ('US_SSN',)"],
    "custom_policy.py": ["Ask about [EMPLOYEE_ID_1] and the [PROJECT_1] roadmap", "blocked:      ('EMAIL',)"],
    "redact_document.py": ["verified before release: True", "[PERSON_1]\t[EMAIL_1]\t[PHONE_1]"],
    "async_engine.py": ["DATABASE_PASSWORD=[SECRET_1]", "refund to IBAN [IBAN_1]"],
}


def run(name: str, tmp_path: Path, env: dict[str, str] | None = None) -> str:
    out = subprocess.run(
        [sys.executable, str(EXAMPLES / name)],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=tmp_path,
        env={**fresh_environment(), **(env or {})},
        check=False,
    )
    assert out.returncode == 0, out.stderr[-3000:]
    return out.stdout


def test_every_example_is_tested() -> None:
    assert {p.name for p in EXAMPLES.glob("*.py")} == {*EXPECT, "gateway_client.py"}


@pytest.mark.parametrize("name", sorted(EXPECT))
def test_engine_examples(name: str, tmp_path: Path) -> None:
    _models_or_skip()
    out = run(name, tmp_path)
    for expected in EXPECT[name]:
        assert expected in out, f"{name}: {expected!r} not in\n{out}"
    assert not [raw for raw in RAW if raw in out]


@pytest.fixture(scope="module")
def live_gateway() -> Iterator[str]:
    """A gateway with a fake provider, as `harpo demo` runs it, on a free port."""
    import uvicorn

    from harpo_redact.api import create_app
    from harpo_redact.config import Settings
    from harpo_redact.mock_upstream import create_mock_app

    _models_or_skip()
    settings = Settings(
        environment="development",
        auth={"enabled": False},
        upstreams=[{"name": "demo", "style": "openai", "base_url": "http://mock.provider/v1", "models": ["demo-gpt"]}],
    )
    app = create_app(settings, upstream_transport=httpx.ASGITransport(app=create_mock_app()))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(300):
        try:
            if httpx.get(f"{url}/readyz", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    yield url
    server.should_exit = True
    thread.join(10)


def test_the_gateway_example(live_gateway: str, tmp_path: Path) -> None:
    out = run("gateway_client.py", tmp_path, {"HARPO_URL": live_gateway, "HARPO_KEY": ""})
    assert "gateway 2.5.0 | ready: True" in out
    assert "Mail [EMAIL_1] about card [CREDIT_CARD_1]" in out
    assert "provider saw only placeholders" in out and "Call [PERSON_1] on [PHONE_1]" in out
    assert "always redacted: ('PRIVATE_KEY', 'SECRET')" in out
    assert not [raw for raw in [*RAW, "jane.doe@acme.example", "Jane Doe"] if raw in out]
