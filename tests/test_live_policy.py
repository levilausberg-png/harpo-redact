"""Live policy: the console's Policy page changes actions and custom types without a restart.

Saved to policy.live_file, laid over the configuration, watched by every worker. Admin keys only; keys stay
redacted; the audit log names what changed, never terms or patterns.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from harpo_redact import live_policy
from harpo_redact.api import create_app
from harpo_redact.observability import JsonFormatter

from .conftest import AUTH, KEY, UPSTREAM_KEY, SpyTransport, chat, make_settings

TEAM = {"authorization": "Bearer team-key-123456"}
EMPLOYEE = {"name": "EMPLOYEE_ID", "patterns": [r"\bEMP-\d{6}\b"], "terms": ["Wilhelmina Badge"]}


def auth() -> dict[str, Any]:
    sha = lambda k: hashlib.sha256(k.encode()).hexdigest()  # noqa: E731
    return {
        "keys": [{"id": "owner", "sha256": sha(KEY), "admin": True}, {"id": "team", "sha256": sha("team-key-123456")}]
    }


def live_gateway(gateway, path: Any, **policy: Any):  # type: ignore[no-untyped-def]
    return gateway(auth=auth(), detection={"ner": {"enabled": False}}, policy={"live_file": str(path), **policy})


def sent(client: TestClient, spy: SpyTransport, text: str) -> tuple[int, str | None]:
    before = len(spy.bodies)
    r = client.post("/v1/chat/completions", headers=AUTH, json=chat(text))
    body = json.loads(spy.bodies[-1])["messages"][0]["content"] if len(spy.bodies) > before else None
    return r.status_code, body


def test_a_change_applies_to_the_next_request_and_is_saved(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "policy.live.yaml"
    client, spy = live_gateway(gateway, path)
    assert sent(client, spy, "mail jane@corp.example about EMP-123456") == (200, "mail [EMAIL_1] about EMP-123456")
    r = client.put(
        "/v1/policy/live",
        headers=AUTH,
        json={"entities": {"EMAIL": "allow", "PHONE": "block"}, "custom_types": [EMPLOYEE]},
    )
    assert r.status_code == 200 and r.json()["updated_by"] == "owner"
    assert sent(client, spy, "mail jane@corp.example about EMP-123456") == (
        200,
        "mail jane@corp.example about [EMPLOYEE_ID_1]",
    )
    assert sent(client, spy, "call +31 20 794 6095")[0] == 403
    saved = live_policy.load(str(path))
    assert saved is not None and saved.entities == {"EMAIL": "allow", "PHONE": "block"}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    changed = {t["type"]: t for t in r.json()["types"] if t["changed"]}
    assert set(changed) == {"EMAIL", "PHONE"} and changed["EMAIL"]["configured"] == "redact"


def test_going_back_removes_the_file_and_the_change(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "policy.live.yaml"
    client, spy = live_gateway(gateway, path)
    client.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "allow"}})
    r = client.delete("/v1/policy/live", headers=AUTH)
    assert r.status_code == 200 and not path.exists() and r.json()["updated_at"] is None
    assert sent(client, spy, "mail jane@corp.example") == (200, "mail [EMAIL_1]")


def test_keys_and_critical_types_cannot_be_changed(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client, _ = live_gateway(gateway, tmp_path / "p.yaml")
    for body, message in (
        ({"entities": {"SECRET": "block"}}, "always redacted"),
        ({"entities": {"PRIVATE_KEY": "allow"}}, "always redacted"),
        ({"entities": {"ENCODED_DATA": "allow"}}, "cannot be set to allow"),
        ({"custom_types": [{"name": "EMAIL_ID", "terms": ["e1"]}]}, "would read as EMAIL"),
    ):
        r = client.put("/v1/policy/live", headers=AUTH, json=body)
        assert r.status_code == 422 and message in json.dumps(r.json()["error"]["harpo"]["errors"])
    assert client.put("/v1/policy/live", headers=AUTH, json={"entities": {}, "extra": 1}).status_code == 400
    assert not (tmp_path / "p.yaml").exists()
    locked = [t["type"] for t in client.get("/v1/policy/live", headers=AUTH).json()["types"] if t["locked"]]
    assert locked == ["PRIVATE_KEY", "SECRET"]


@pytest.mark.parametrize(("method", "path"), [("get", "/v1/policy/live"), ("put", "/v1/policy/live"),
                                              ("delete", "/v1/policy/live"), ("post", "/v1/policy/preview")])  # fmt: skip
def test_only_admin_keys_may_see_or_change_it(gateway, tmp_path, method: str, path: str) -> None:  # type: ignore[no-untyped-def]
    client, _ = live_gateway(gateway, tmp_path / "p.yaml")
    kwargs = {"json": {"text": "x"}} if method in ("put", "post") else {}
    r = getattr(client, method)(path, headers=TEAM, **kwargs)
    assert r.status_code == 403 and r.json()["error"]["type"] == "permission_error"


def test_without_a_live_file_the_policy_is_read_only_and_the_yaml_is_offered(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(auth=auth(), detection={"ner": {"enabled": False}})
    view = client.get("/v1/policy/live", headers=AUTH).json()
    assert view["editable"] is False and "policy.live_file is not set" in view["reason"]
    r = client.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "block"}, "custom_types": [EMPLOYEE]})
    info = r.json()["error"]["harpo"]
    assert r.status_code == 409 and "EMAIL: block" in info["yaml"]
    assert (
        "policy:\n  entities:\n    EMAIL:\n      action: block" in info["config_yaml"]
        and "custom_types" in info["config_yaml"]
    )


def test_a_read_only_folder_is_reported_not_crashed(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    folder = tmp_path / "ro"
    folder.mkdir()
    folder.chmod(0o500)
    try:
        client, _ = live_gateway(gateway, folder / "p.yaml")
        if os.access(folder, os.W_OK):
            pytest.skip("running as a user that can write anywhere")
        r = client.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "block"}})
        assert r.status_code == 409 and "read-only" in r.json()["error"]["message"]
    finally:
        folder.chmod(0o700)


def test_preview_runs_a_draft_without_saving_it(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "p.yaml"
    client, _ = live_gateway(gateway, path)
    draft = {"entities": {"EMAIL": "block"}, "custom_types": [EMPLOYEE]}
    r = client.post(
        "/v1/policy/preview", headers=AUTH, json={"text": "EMP-123456 jane@corp.example", "policy": draft}
    ).json()
    assert r["blocked"] and r["text"] == "[EMPLOYEE_ID_1] [EMAIL_1]" and r["counts"] == {"EMPLOYEE_ID": 1, "EMAIL": 1}
    assert not path.exists()
    now = client.post("/v1/policy/preview", headers=AUTH, json={"text": "EMP-123456 jane@corp.example"}).json()
    assert not now["blocked"] and now["text"] == "EMP-123456 [EMAIL_1]"


def test_the_audit_log_names_changes_but_never_terms_or_patterns(gateway, tmp_path, caplog) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.INFO)
    client, _ = live_gateway(gateway, tmp_path / "p.yaml")
    client.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "allow"}, "custom_types": [EMPLOYEE]})
    lines = [json.loads(JsonFormatter().format(r)) for r in caplog.records if r.name == "harpo.audit"]
    change = next(line for line in lines if line.get("event") == "policy_changed")
    assert change["key_id"] == "owner" and change["changes"]["entities"] == {"EMAIL": "allow"}
    assert change["changes"]["custom_types"] == {"EMPLOYEE_ID": "redact"}
    logs = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    assert "Wilhelmina" not in logs and "EMP-" not in logs


def test_another_worker_picks_up_the_change(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TEST_UPSTREAM_KEY", UPSTREAM_KEY)
    path = tmp_path / "policy.live.yaml"
    settings = make_settings(auth=auth(), detection={"ner": {"enabled": False}}, policy={"live_file": str(path)})
    spy_a, spy_b = SpyTransport(), SpyTransport()
    with (
        TestClient(create_app(settings, upstream_transport=spy_a)) as a,
        TestClient(create_app(settings, upstream_transport=spy_b)) as b,
    ):
        assert sent(b, spy_b, "mail jane@corp.example") == (200, "mail [EMAIL_1]")
        assert a.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "allow"}}).status_code == 200
        deadline = time.monotonic() + 10
        while sent(b, spy_b, "mail jane@corp.example")[1] != "mail jane@corp.example":
            assert time.monotonic() < deadline, "worker b never picked up the change"
            time.sleep(0.2)


def test_a_broken_file_keeps_the_running_policy_and_says_why(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "p.yaml"
    client, spy = live_gateway(gateway, path)
    client.put("/v1/policy/live", headers=AUTH, json={"entities": {"EMAIL": "allow"}})
    time.sleep(0.01)
    path.write_text("version: 1\nentities: {SECRET: allow}\n")
    view = client.get("/v1/policy/live", headers=AUTH).json()
    assert view["error"] and "always redacted" in view["error"]
    assert sent(client, spy, "mail jane@corp.example") == (200, "mail jane@corp.example")  # previous policy stays


def test_a_saved_policy_applies_at_startup_and_a_broken_one_stops_it(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TEST_UPSTREAM_KEY", UPSTREAM_KEY)
    path = tmp_path / "p.yaml"
    live_policy.save(str(path), live_policy.LivePolicy.model_validate({"entities": {"EMAIL": "allow"}}))
    settings = make_settings(detection={"ner": {"enabled": False}}, policy={"live_file": str(path)})
    spy = SpyTransport()
    with TestClient(create_app(settings, upstream_transport=spy)) as client:
        assert sent(client, spy, "mail jane@corp.example") == (200, "mail jane@corp.example")
    path.write_text("entities: {EMAIL: sometimes}\n")
    with pytest.raises(RuntimeError, match=r"policy\.live_file .* is not valid"), TestClient(create_app(settings)):
        pass


def test_a_relative_live_file_sits_next_to_the_config(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.config import load_settings

    config = tmp_path / "harpo.yaml"
    config.write_text("environment: development\npolicy: {live_file: policy.live.yaml}\n")
    assert load_settings(str(config)).policy.live_file == str(tmp_path / "policy.live.yaml")


def test_check_config_validates_the_live_file(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    from harpo_redact.__main__ import main

    config = tmp_path / "harpo.yaml"
    config.write_text(
        "environment: development\npolicy: {live_file: policy.live.yaml}\ndetection: {ner: {enabled: false}}\n"
    )
    assert main(["check-config", "--config", str(config)]) == 0
    (tmp_path / "policy.live.yaml").write_text("entities: {PRIVATE_KEY: allow}\n")
    assert main(["check-config", "--config", str(config)]) == 2
    assert "always redacted" in capsys.readouterr().out


def test_a_save_records_its_own_file_not_one_that_lands_right_after(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Two workers save at once. A save records the state of the file it wrote, taken before its rename, so when the
    other worker's rename lands right after, the watcher sees a different file and loads it."""
    path = tmp_path / "policy.live.yaml"
    real = os.replace

    def then_another_worker(src: str, dst: str) -> None:
        real(src, dst)
        other = tmp_path / ".policy.other.tmp"
        other.write_text("entities:\n  EMAIL: block\n")
        real(other, dst)

    monkeypatch.setattr(live_policy.os, "replace", then_another_worker)
    mine = live_policy.save(str(path), live_policy.LivePolicy.model_validate({"entities": {"EMAIL": "allow"}}))
    monkeypatch.undo()
    assert mine != live_policy.file_state(str(path))  # so this worker reloads
    loaded = live_policy.load(str(path))
    assert loaded is not None and {str(k): v for k, v in loaded.entities.items()} == {"EMAIL": "block"}
