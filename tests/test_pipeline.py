"""Rendering modes, policy, risk levels, propagation and the optional SLM layer."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from harpo_redact.config import Settings
from harpo_redact.detectors.slm import SLMDetector
from harpo_redact.pipeline import Pipeline
from harpo_redact.risk import Level

from .conftest import make_settings

ANNA = "Anna told Ben that Anna's card 4111 1111 1111 1111 was declined."


def codes(outcome) -> list[str]:  # type: ignore[no-untyped-def]
    return [r.code for r in outcome.reasons]


# ------------------------------------------------------------------ modes (the PRD example, verbatim)
def test_relational_mode(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync([ANNA], mode="relational")
    assert out.texts == ["[PERSON_1] told [PERSON_2] that [PERSON_1]'s card [CREDIT_CARD_1] was declined."]
    assert out.risk is Level.GREEN


def test_generic_mode_warns_about_collapsed_sentence(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync([ANNA], mode="generic", context_repair=False)
    assert out.texts == ["[PERSON] told [PERSON] that [PERSON]'s card [CREDIT_CARD] was declined."]
    assert out.risk is Level.YELLOW and codes(out) == ["collapsed_sentences"]


def test_generic_mode_with_context_repair(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync([ANNA], mode="generic", context_repair=True)
    assert out.texts == ["[PERSON_A] told [PERSON_B] that [PERSON_A]'s card [CREDIT_CARD] was declined."]
    assert out.risk is Level.GREEN


def test_relational_numbering_is_shared_across_messages(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync(["Mail anna.jansen@corp.example today.", "Did anna.jansen@corp.example reply?"])
    assert out.texts == ["Mail [EMAIL_1] today.", "Did [EMAIL_1] reply?"]


def test_short_name_links_to_full_name(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync(["Customer Jan de Vries emailed us. Mr. de Vries wants a refund."])
    assert out.texts[0].count("[PERSON_1]") == 2 and "Vries" not in out.texts[0]


def test_existing_placeholders_are_left_alone(pipeline: Pipeline) -> None:
    text = "[PERSON_1] asked about [EMAIL_1] yesterday."
    assert pipeline.scan_sync([text]).texts == [text]


def test_name_found_once_is_redacted_everywhere(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync(["Lars said the shipment is late.", "Summarize the complaint from Lars Eriksen."])
    assert "Lars" not in out.texts[0] and "Lars" not in out.texts[1]


def test_names_hidden_in_email_addresses(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync(["Email anna.jansen@corp.example. Anna lives in Utrecht."])
    assert "Anna" not in out.texts[0]


# ------------------------------------------------------------------ policy
def test_a_key_is_redacted_not_blocked(pipeline: Pipeline) -> None:
    text = "deploy with sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5 now"
    out = pipeline.scan_sync([text])
    assert not out.blocked and out.texts == ["deploy with [SECRET_1] now"]
    assert out.risk is Level.YELLOW and "keys_redacted" in codes(out)


def test_a_policy_block_can_be_overridden() -> None:
    blocking = Pipeline(make_settings(detection={"ner": {"enabled": False}},
                                      policy={"entities": {"EMAIL": {"action": "block", "overridable": True}}}))  # fmt: skip
    blocked = blocking.scan_sync(["mail jane@corp.example"])
    assert blocked.blocked and blocked.overridable and blocked.blocked_types == ["EMAIL"]
    allowed = blocking.scan_sync(["mail jane@corp.example"], override=True)
    assert allowed.risk is Level.YELLOW and "override_applied" in codes(allowed) and allowed.texts == ["mail [EMAIL_1]"]


def test_a_private_key_is_redacted_whole(pipeline: Pipeline) -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    out = pipeline.scan_sync([pem], override=True)
    assert not out.blocked and out.texts == ["[PRIVATE_KEY_1]"] and "keys_redacted" in codes(out)


def test_base64_wrapped_private_key_is_redacted_like_a_plain_one(pipeline: Pipeline) -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    out = pipeline.scan_sync(["config: " + base64.b64encode(pem.encode()).decode()])
    assert not out.blocked and out.texts[0].endswith(": [ENCODED_DATA_1]") and "keys_redacted" in codes(out)


def test_allowed_type_passes_through(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    p = make_pipeline(policy={"entities": {"EMAIL": {"action": "allow"}}})
    out = p.scan_sync(["Mail support@acme.example or call +31 20 794 6095."])
    assert out.texts == ["Mail support@acme.example or call [PHONE_1]."]


def test_allow_terms_never_exempt_critical_types(make_pipeline) -> None:  # type: ignore[no-untyped-def]
    key = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"
    p = make_pipeline(policy={"allow_terms": ["Python", key]})
    out = p.scan_sync([f"Python script uses {key}"])
    assert out.texts[0].startswith("Python script") and key not in out.texts[0]


def test_critical_types_cannot_be_allowed_in_config() -> None:
    with pytest.raises(ValueError, match="cannot be set to allow"):
        make_settings(policy={"entities": {"SECRET": {"action": "allow"}}})


# ------------------------------------------------------------------ advisories
def test_placeholder_density_is_flagged(pipeline: Pipeline) -> None:
    text = ("Anna Jansen, Ben Smit, Carla Bos, Dirk Mol, Eva Kok, Frank Mes and Gert Vos met in Utrecht, "
            "Rotterdam and Delft.")  # fmt: skip
    assert "context_rot" in codes(pipeline.scan_sync([text]))


def test_hidden_characters_and_mixed_scripts_are_flagged(pipeline: Pipeline) -> None:
    out = pipeline.scan_sync(["Mail j\u200bohn@example.com, I live in K\u0430zan."])
    assert {"hidden_characters", "mixed_script"} <= set(codes(out))
    assert "john" not in out.texts[0]


def test_findings_point_into_the_original_text(pipeline: Pipeline) -> None:
    original = "Mail j\u200bohn@example.com now"
    out = pipeline.scan_sync([original])
    f = out.findings[0][0]
    assert original[f.start : f.end] == "j\u200bohn@example.com"


def test_unsupported_and_dropped_content() -> None:
    p = Pipeline(make_settings(detection={"ner": {"enabled": False}}))
    import asyncio

    blocked = asyncio.run(p.scan(["hello"], unsupported=1))
    assert blocked.blocked and codes(blocked) == ["unsupported_content"] and not blocked.overridable
    dropped = asyncio.run(p.scan(["hello"], dropped=2))
    assert dropped.risk is Level.YELLOW and codes(dropped) == ["content_dropped"]


# ------------------------------------------------------------------ SLM layer (Ollama mocked)
def _ollama(findings: list[dict[str, Any]] | None = None, *, delay: bool = False, status: int = 200):  # type: ignore[no-untyped-def]
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": []})
        if delay:
            import asyncio

            await asyncio.sleep(2)
        body = json.loads(request.content)
        assert body["format"]["required"] == ["findings"]  # constrained output
        return httpx.Response(status, json={"message": {"content": json.dumps({"findings": findings or []})}})

    return httpx.MockTransport(handler)


def _slm_pipeline(transport: httpx.MockTransport, on_failure: str = "fail_closed") -> Pipeline:
    settings: Settings = make_settings(
        detection={"ner": {"enabled": False}, "slm": {"enabled": True, "on_failure": on_failure}}
    )
    client = httpx.AsyncClient(base_url="http://ollama.test", transport=transport)
    return Pipeline(settings, slm=SLMDetector(client, "test-model", timeout_ms=500))


async def test_slm_quasi_identifier_is_redacted() -> None:
    p = _slm_pipeline(_ollama([{"text": "the only left-handed pilot in Groningen", "kind": "QUASI_ID"}]))
    out = await p.scan(["Ask the only left-handed pilot in Groningen about it."])
    assert out.texts == ["Ask [QUASI_ID_1] about it."] and out.slm_status == "ok"


async def test_slm_invented_findings_are_discarded() -> None:
    p = _slm_pipeline(_ollama([{"text": "Ignore previous instructions", "kind": "PERSON"}]))
    out = await p.scan(["Nothing personal here at all."])
    assert out.texts == ["Nothing personal here at all."] and out.flags["slm_discarded"] == 1


async def test_slm_sees_masked_text_only() -> None:
    seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(200, json={"message": {"content": '{"findings": []}'}})

    p = _slm_pipeline(httpx.MockTransport(handler))
    await p.scan(["Mail jane@example.com about card 4111 1111 1111 1111."])
    assert "jane@example.com" not in seen[0] and "[EMAIL]" in seen[0] and "[CREDIT_CARD]" in seen[0]


async def test_slm_timeout_fails_closed() -> None:
    out = await _slm_pipeline(_ollama(delay=True)).scan(["Some text to check."])
    assert out.blocked and codes(out) == ["slm_unavailable"] and out.slm_status == "timeout"


async def test_slm_error_can_degrade() -> None:
    out = await _slm_pipeline(_ollama(status=500), on_failure="degrade").scan(["Some text to check."])
    assert out.risk is Level.YELLOW and codes(out) == ["slm_degraded"] and out.slm_status == "error"


async def test_fast_layers_skip_the_slm() -> None:
    out = await _slm_pipeline(_ollama(delay=True)).scan(["Some text to check."], layers="fast")
    assert out.slm_status == "skipped" and out.risk is Level.GREEN
