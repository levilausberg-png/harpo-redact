"""The detection library: every detector under the kind of data it protects, and a switch that does what it says.

Each family the live policy can switch is tried on a value only it finds, on and off. Credentials stay on whatever is
switched (INV-11), and the switches reach the console, /v1/system, check-config and the configuration snippet.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from harpo_redact import library, live_policy
from harpo_redact.__main__ import main
from harpo_redact.config import Settings
from harpo_redact.pipeline import Pipeline

from .conftest import AUTH, KEY, chat

BASE = Settings(environment="development", detection={"ner": {"enabled": False}})

# family -> (text, a source tag only that family adds, whether the value is then not redacted at all)
PROBES: dict[str, tuple[str, str, bool]] = {
    "identifiers.national_ids": ("Le NIR 1 84 12 76 451 089 46 est valide", "identifier:fr.nir", False),
    "identifiers.cued_numbers": ("Passport number X1234567 issued", "cue:document", True),
    "identifiers.opaque_codes": ("Please bring your MKWBOOYWMV and the signed form.", "opaque:code", True),
    "identifiers.regions.nl": ("loonheffingennummer 123456782L01", "region:nl.loonheffing", False),
    "identifiers.regions.us": ("SSN ending in 4820", "region:us.ssn-last4", True),
    "identifiers.regions.eu": ("Pay DE89370400440532013000 BIC COBADEFFXXX now", "region:eu.bic", False),
    "identifiers.table_fields": (
        "first_name,last_name,city\nJan,Smit,Utrecht\nPiet,Bakker,Zwolle\n",
        "field:person",
        True,
    ),
    "identifiers.addresses": ("Ship it to Keizersgracht 123, 1015 CJ Amsterdam", "address:street", True),
    "identifiers.devices": ("router MAC 00:1A:2B:3C:4D:5E in the hall", "identifier:mac", True),
    "identifiers.machine_formats": (
        "P<NLDDE<BRUIJN<<WILLEKE<LISELOTTE<<<<<<<<<<<\nSPECI20142NLD6503101F2403096999999990<<<<<84",
        "format:mrz",
        True,
    ),
    "identifiers.crypto": ("wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "identifier:btc", True),
    "identifiers.spoken_emails": ("write to jane at corp dot example please", "identifier:spoken-email", True),
    "ner.name_rules": ("Dear Mr. Pieterse,\nthanks", "name-rule", True),
    "ner.propagate": ("Dear Mr. Pieterse,\nPieterse will call.", "propagated", False),
}


def scan(flags: dict[str, bool], text: str, base: Settings = BASE) -> tuple[str, set[str]]:
    settings = live_policy.apply(base, live_policy.LivePolicy.model_validate({"detectors": flags}))
    out = Pipeline(settings).scan_sync([text])
    sources = {src for f in out.findings[0] for src in f.to_dict().get("sources") or ()}
    return out.texts[0], sources


def test_every_family_sits_under_one_umbrella_with_a_real_setting() -> None:
    ids = [f.id for f in library.FAMILIES]
    assert len(ids) == len(set(ids))
    assert {f.group for f in library.FAMILIES} == set(library.GROUPS)
    for family in library.FAMILIES:
        if family.setting is not None:
            assert isinstance(library.setting_of(BASE, family), bool), family.id
        assert family.locked or family.setting, f"{family.id} can neither be switched nor says why"
    for family_id in library.LIVE_IDS:
        family = library.BY_ID[family_id]
        assert family.setting and not family.locked and family.method == "deterministic"
    credentials = [f for f in library.FAMILIES if f.group == "Credentials"]
    assert credentials and all(f.locked and f.id not in library.LIVE_IDS for f in credentials)


def test_every_live_family_has_a_probe() -> None:
    # ner.precision_filter needs the model: tested in test_the_precision_filter_is_a_live_switch below.
    assert set(PROBES) | {"ner.precision_filter"} == set(library.LIVE_IDS)


@pytest.mark.parametrize("family_id", sorted(PROBES))
def test_switching_a_family_off_stops_exactly_that_detector(family_id: str) -> None:
    text, source, whole = PROBES[family_id]
    redacted_on, sources_on = scan({}, text)
    redacted_off, sources_off = scan({family_id: False}, text)
    assert source in sources_on and redacted_on != text
    assert source not in sources_off
    if whole:  # nothing else finds this value
        assert redacted_off == text
    # switched back on, it is as before
    assert scan({family_id: True}, text) == (redacted_on, sources_on)


def test_keys_stay_redacted_with_every_switch_off() -> None:
    off = dict.fromkeys(library.LIVE_IDS, False)
    text = "DATABASE_PASSWORD=Qz7vL2mX9pR4tW8k and sk_live_51HcQ2eKx8vB3nR7tY4mP9wZ2"
    redacted, _ = scan(off, text)
    assert "Qz7vL2mX9pR4tW8k" not in redacted and "sk_live_51HcQ2eKx8vB3nR7tY4mP9wZ2" not in redacted
    always = (
        "secrets.library",
        "secrets.natural_language",
        "secrets.seed_phrases",
        "identifiers.decode_escapes",
        "encoded",
    )
    for family_id in (*always, "core.email", "views"):
        with pytest.raises(ValidationError):
            live_policy.LivePolicy.model_validate({"detectors": {family_id: False}})
    with pytest.raises(ValidationError, match="not a detector family"):
        live_policy.LivePolicy.model_validate({"detectors": {"identifiers.everything": False}})
    with pytest.raises(ValidationError, match="restart"):
        live_policy.LivePolicy.model_validate({"detectors": {"ner.enabled": False}})


def test_describe_summary_and_the_configuration_snippet() -> None:
    live = live_policy.LivePolicy.model_validate(
        {"detectors": {"identifiers.addresses": False, "ner.propagate": False}}
    )
    effective = live_policy.apply(BASE, live)
    view = library.describe(effective, configured=BASE)
    rows = {f["id"]: f for g in view["groups"] for f in g["families"]}
    assert set(rows) == {f.id for f in library.FAMILIES}
    assert rows["identifiers.addresses"]["enabled"] is False and rows["identifiers.addresses"]["configured"] is True
    assert rows["identifiers.addresses"]["setting"] == "detection.identifiers.addresses"
    assert rows["secrets.library"]["locked"] and not rows["secrets.library"]["live"]
    lines = library.summary_lines(effective)
    assert len(lines) == len(library.GROUPS)
    assert any(line.startswith("Addresses and places: nothing (off: Addresses and places)") for line in lines)
    snippet = yaml.safe_load(live_policy.config_snippet(live))
    assert snippet == {"detection": {"identifiers": {"addresses": False}, "ner": {"propagate": False}}}
    # The snippet means the same in the configuration file as on the live policy.
    data = BASE.model_dump()
    data["detection"]["identifiers"]["addresses"] = False
    data["detection"]["ner"]["propagate"] = False
    assert Settings.model_validate(data).detection == effective.detection


def _auth() -> dict[str, Any]:
    return {"keys": [{"id": "owner", "sha256": hashlib.sha256(KEY.encode()).hexdigest(), "admin": True}]}


def test_the_live_policy_switches_a_family_on_every_route(gateway, tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "policy.live.yaml"
    client, spy = gateway(auth=_auth(), detection={"ner": {"enabled": False}}, policy={"live_file": str(path)})
    text = "router MAC 00:1A:2B:3C:4D:5E in the hall"

    def sent() -> str:
        r = client.post("/v1/chat/completions", headers=AUTH, json=chat(text))
        assert r.status_code == 200
        return str(json.loads(spy.bodies[-1])["messages"][0]["content"])

    assert sent() == "router MAC [DEVICE_ID_1] in the hall"
    preview = client.post(
        "/v1/policy/preview", headers=AUTH, json={"text": text, "policy": {"detectors": {"identifiers.devices": False}}}
    )
    assert preview.status_code == 200 and preview.json()["text"] == text
    assert sent() == "router MAC [DEVICE_ID_1] in the hall"  # a preview changes nothing
    r = client.put("/v1/policy/live", headers=AUTH, json={"detectors": {"identifiers.devices": False}})
    assert r.status_code == 200
    rows = {f["id"]: f for g in r.json()["library"]["groups"] for f in g["families"]}
    assert rows["identifiers.devices"]["enabled"] is False and rows["identifiers.devices"]["configured"] is True
    assert sent() == text
    system = client.get("/v1/system", headers=AUTH).json()["detection"]
    shown = {f["id"]: f["enabled"] for g in system["library"]["groups"] for f in g["families"]}
    assert shown["identifiers.devices"] is False and system["identifiers"]["devices"] is False
    saved = live_policy.load(str(path))
    assert saved is not None and saved.detectors == {"identifiers.devices": False}
    bad = client.put("/v1/policy/live", headers=AUTH, json={"detectors": {"secrets.library": False}})
    assert bad.status_code == 422
    assert client.delete("/v1/policy/live", headers=AUTH).status_code == 200
    assert sent() == "router MAC [DEVICE_ID_1] in the hall"


def test_check_config_prints_the_library(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    live = tmp_path / "policy.live.yaml"
    config = tmp_path / "harpo.yaml"
    settings = {
        "environment": "development",
        "detection": {"ner": {"enabled": False}},
        "policy": {"live_file": str(live)},
    }
    config.write_text(yaml.safe_dump(settings))
    assert main(["check-config", "--config", str(config)]) == 0
    out = capsys.readouterr().out
    assert "detection library:" in out and "  Credentials: Credential library" in out
    live.write_text(
        live_policy.to_yaml(live_policy.LivePolicy.model_validate({"detectors": {"identifiers.crypto": False}}))
    )
    assert main(["check-config", "--config", str(config)]) == 0
    out = capsys.readouterr().out
    assert (
        "detection library (with the live policy):" in out and "Crypto: nothing (off: Crypto wallet addresses)" in out
    )


def test_the_precision_filter_is_a_live_switch() -> None:
    from harpo_redact.api import load_ner

    settings = Settings(environment="development")
    ner = load_ner(settings.detection.ner)
    text = "Status: Pending\nthe status is pending until Monday"
    strict = ner.detect_many([text])[0]
    loose = ner.detect_many([text], precision_filter=False)[0]
    assert {(s.start, s.end) for s in strict} <= {(s.start, s.end) for s in loose}
    # The same model serves both: switching the filter loads nothing.
    assert load_ner(live_policy.apply(settings, live_policy.LivePolicy(detectors={"ner.precision_filter": False}))
                    .detection.ner) is ner  # fmt: skip


def test_the_library_reference_names_every_family() -> None:
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "docs" / "LIBRARY.md").read_text(encoding="utf-8")
    missing = [f.id for f in library.FAMILIES if f"`{f.id}`" not in doc]
    assert missing == [], f"docs/LIBRARY.md does not list {missing}"
    assert all(f"### {group}" in doc for group in library.GROUPS)


def test_the_example_configuration_names_every_switch() -> None:
    from pathlib import Path

    data = yaml.safe_load((Path(__file__).resolve().parents[1] / "config" / "harpo.example.yaml").read_text())
    for family_id in sorted(library.LIVE_IDS):
        node = data["detection"]
        for part in library.BY_ID[family_id].setting or ():
            node = node[part]
        assert node is True, family_id
