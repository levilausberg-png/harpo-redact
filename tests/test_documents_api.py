"""The document endpoint, files in chat requests, the audit trail and the command line."""

from __future__ import annotations

import base64
import io
import json
import logging
import zipfile
from typing import Any
from urllib.parse import quote

import pytest

from harpo_redact.__main__ import main
from harpo_redact.observability import JsonFormatter

from . import doc_fixtures as fx
from .conftest import AUTH, KEY, READONLY, chat

DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SECRET = "sk-proj-7Hq2LmV9xRt4KpZ8wNc3YbF6dJs1GaE5"


def post(
    client: Any, data: bytes, name: str = "report.docx", *, headers: dict[str, str] | None = None, params: str = ""
) -> Any:
    """The file name goes in a header (percent-encoded), never in the URL."""
    query = "?" + params.lstrip("&") if params else ""
    return client.post(
        f"/v1/documents/redact{query}",
        content=data,
        headers={
            **AUTH,
            "content-type": "application/octet-stream",
            "X-Harpo-Filename": quote(name),
            **(headers or {}),
        },
    )


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# =========================================================================== the endpoint
def test_a_docx_comes_back_redacted_with_a_summary_in_the_headers(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    r = post(client, fx.make_docx())
    assert r.status_code == 200 and r.headers["content-type"] == DOCX
    assert r.headers["content-disposition"].startswith('attachment; filename="report.redacted.docx"')
    assert r.headers["x-harpo-verified"] == "true" and int(r.headers["x-harpo-redactions"]) > 5
    assert r.headers["x-harpo-risk"] == "green" and r.headers["x-harpo-document"] == "docx"
    assert fx.canaries_in_package(r.content) == []
    assert "[PERSON_1]" in fx.docx_text(r.content)["texts"][0]


def test_json_response_carries_text_counts_and_the_file(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    r = post(client, fx.make_xlsx(), "customers.xlsx", params="&response=json")
    body = r.json()
    assert r.status_code == 200 and body["kind"] == "xlsx" and body["verified"] is True
    assert body["counts"]["EMAIL"] >= 2 and "[sheet Customers]" in body["text"] and "priya" not in body["text"].lower()
    assert body["file"]["filename"] == "customers.redacted.xlsx" and body["file"]["content_type"] == XLSX
    assert fx.canaries_in_package(base64.b64decode(body["file"]["base64"])) == []
    text_only = post(client, fx.make_xlsx(), "customers.xlsx", params="&response=json&file=false").json()
    assert text_only["file"] is None and text_only["verified"] is False and text_only["text"]


def test_a_pdf_and_a_csv_go_through_the_same_endpoint(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    pdf = post(client, fx.make_pdf(), "invoice.pdf")
    assert (
        pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF-")
    )
    csv = post(
        client, f"Name,Email\r\nPriya Raman,{fx.EMAIL}\r\n".encode(), "people.csv", headers={"content-type": "text/csv"}
    )
    assert csv.status_code == 200 and csv.headers["content-type"].startswith("text/csv")
    assert csv.content == b"Name,Email\r\n[PERSON_1],[EMAIL_1]\r\n"


def test_authentication_is_required_and_the_policy_lists_documents(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    assert client.post("/v1/documents/redact", content=b"hi").status_code == 401
    policy = client.get("/v1/policy", headers=AUTH).json()["documents"]
    assert (
        policy["enabled"] is True
        and policy["in_chat"] is False
        and "pdf" in policy["formats"]
        and policy["images"] == "block"
    )


def test_disabled_endpoint(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(documents={"enabled": False})
    assert post(client, b"hello", "a.txt").status_code == 404


def test_keys_are_redacted_in_a_document_and_override_is_a_key_permission(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(policy={"entities": {"IBAN": {"action": "block", "overridable": True}}})
    config = f"DEBUG=1\nOPENAI_API_KEY={SECRET}\n".encode()
    redacted = post(client, config, ".env")
    assert redacted.status_code == 200 and SECRET.encode() not in redacted.content and b"[SECRET_1]" in redacted.content
    refund = f"DEBUG=1\nREFUND_IBAN={fx.IBAN}\n".encode()
    blocked = post(client, refund, ".env")
    assert blocked.status_code == 403 and blocked.json()["error"]["type"] == "privacy_block"
    assert blocked.json()["error"]["harpo"]["overridable"] is True and fx.IBAN not in blocked.text
    allowed = post(client, refund, ".env", headers={"X-Harpo-Override": "true"})
    assert allowed.status_code == 200 and fx.IBAN.encode() not in allowed.content and b"[IBAN_1]" in allowed.content
    denied = post(client, refund, ".env", headers={**READONLY, "X-Harpo-Override": "true"})
    assert denied.status_code == 403 and denied.json()["error"]["harpo"]["override_permitted"] is False


@pytest.mark.parametrize("stream", [False, True])
def test_the_size_limit_holds_with_and_without_a_content_length(gateway, stream: bool) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway(documents={"max_bytes": 1_000})
    data = b"x" * 5_000
    content: Any = (
        (data[i : i + 500] for i in range(0, len(data), 500)) if stream else data
    )  # a generator has no length
    r = client.post("/v1/documents/redact", content=content, headers={**AUTH, "X-Harpo-Filename": "a.txt"})
    assert r.status_code == 413


def test_refusals_have_stable_codes_and_never_echo_content(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    cases = [
        (fx.make_docx(picture=True), "a.docx", 422, "images_present"),
        (b"MZ\x90\x00 executable", "a.exe", 415, "unsupported_format"),
        (b"\xd0\xcf\x11\xe0" + b"\x00" * 600, "old.doc", 415, "legacy_office"),
        (b"PK\x03\x04junk", "a.docx", 422, "corrupt"),
        (b"abc\x00def", "a.txt", 422, "binary_content"),
    ]
    for data, name, status, code in cases:
        r = post(client, data, name)
        assert r.status_code == status and r.json()["error"]["harpo"]["code"] == code, (name, r.text)
    assert post(client, b"", "a.txt").status_code == 400


def test_non_ascii_file_names(gateway) -> None:  # type: ignore[no-untyped-def]
    client, _ = gateway()
    r = post(client, b"Mail me.", "Rapport été.txt")
    assert r.status_code == 200
    assert "filename*=UTF-8''Rapport%20%C3%A9t%C3%A9.redacted.txt" in r.headers["content-disposition"]
    assert 'filename="Rapport _t_.redacted.txt"' in r.headers["content-disposition"]


def test_the_audit_log_never_holds_content_or_file_names(gateway, caplog) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.DEBUG)
    client, _ = gateway()
    post(client, f"Contact Priya Raman at {fx.EMAIL}, secret {SECRET}".encode(), "Quarterly-Payroll-Priya.txt")
    post(client, b"junk\x00", "Another-Private-Name.txt")
    text = "\n".join(JsonFormatter().format(r) for r in caplog.records)
    for value in ("Priya", "Raman", fx.EMAIL, SECRET, "Quarterly", "Payroll", "Another-Private-Name"):
        assert value not in text, value
    audits = [json.loads(JsonFormatter().format(r)) for r in caplog.records if r.name == "harpo.audit"]
    assert any(a.get("document") == "text" for a in audits) or any(a["decision"] == "blocked" for a in audits)


# =========================================================================== files in chat requests
def openai_body(data: bytes, name: str, mime: str, question: str = "Summarize the attached file.") -> dict[str, Any]:
    body = chat(question)
    body["messages"][0]["content"] = [
        {"type": "text", "text": question},
        {"type": "file", "file": {"filename": name, "file_data": f"data:{mime};base64,{b64(data)}"}},
    ]
    return body


def anthropic_body(data: bytes, mime: str, question: str) -> dict[str, Any]:
    return {
        "model": "claude-test",
        "max_tokens": 64,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "title": "notes",
                        "source": {"type": "base64", "media_type": mime, "data": b64(data)},
                    },
                    {"type": "text", "text": question},
                ],
            }
        ],
    }


def test_files_in_chat_are_still_blocked_by_default(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway()
    r = client.post("/v1/chat/completions", headers=AUTH, json=openai_body(fx.make_docx(), "a.docx", DOCX))
    assert r.status_code == 403 and not spy.requests  # unchanged behaviour: an attachment is not inspectable


def test_an_attached_docx_is_redacted_and_sent_as_text(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True})
    body = openai_body(fx.make_docx(), "Priya Raman CV.docx", DOCX, "Is Priya Raman reliable?")
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 200
    sent = spy.last_json()["messages"][0]["content"]
    assert [p["type"] for p in sent] == ["text", "text"]  # the file part became text
    assert sent[0]["text"] == "Is [PERSON_1] reliable?"  # one person, one placeholder, across message and attachment
    assert (
        sent[1]["text"].startswith("[Attached file: ")
        and "[PERSON_1]" in sent[1]["text"]
        and "[EMAIL_1]" in sent[1]["text"]
    )
    raw = spy.bodies[-1].decode()
    for value in [*fx.CANARIES, "file_data", "base64"]:
        assert value not in raw, value


def test_an_attached_spreadsheet_keeps_its_column_headers(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True})
    r = client.post("/v1/chat/completions", headers=AUTH, json=openai_body(fx.make_xlsx(), "customers.xlsx", XLSX))
    assert r.status_code == 200
    text = spy.last_json()["messages"][0]["content"][1]["text"]
    assert "Name: [PERSON_" in text and "Email: [EMAIL_" in text and "BSN: [NL_BSN_1]" in text and " | " in text
    assert fx.CANARIES[0] not in text and "Priya" not in text


def test_an_anthropic_document_block_is_converted_too(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True})
    body = anthropic_body(fx.make_pdf(), "application/pdf", "Who wrote this?")
    # a PDF whose text we cannot lose: the page has images? no - plain text pdf
    r = client.post("/v1/messages", headers={"x-api-key": KEY}, json=body)
    assert r.status_code == 200, r.text
    blocks = spy.last_json()["messages"][0]["content"]
    assert [b["type"] for b in blocks] == ["text", "text"] and blocks[0]["text"].startswith("[Attached file: notes]")
    assert "priya" not in spy.bodies[-1].decode().lower() and "[EMAIL_1]" in blocks[0]["text"]


def test_a_blocked_value_inside_an_attachment_blocks_the_whole_request(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True}, policy={"entities": {"IBAN": {"action": "block"}}})
    body = openai_body(f"refund to {fx.IBAN}\n".encode(), "refund.txt", "text/plain")
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)
    assert r.status_code == 403 and r.json()["error"]["type"] == "privacy_block" and not spy.requests
    body = openai_body(f"token = {SECRET}\n".encode(), "config.txt", "text/plain")
    r = client.post("/v1/chat/completions", headers=AUTH, json=body)  # keys are redacted, the request goes on
    assert r.status_code == 200 and SECRET not in spy.bodies[-1].decode() and "[SECRET_1]" in spy.bodies[-1].decode()


def test_an_attachment_that_cannot_be_inspected_fails_the_request(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True})
    for data, name, mime, code in (
        (fx.make_docx(picture=True), "a.docx", DOCX, "images_present"),
        (b"%PDF-1.4 broken", "a.pdf", "application/pdf", "corrupt"),
    ):
        r = client.post("/v1/chat/completions", headers=AUTH, json=openai_body(data, name, mime))
        assert r.status_code == 422 and r.json()["error"]["harpo"]["code"] == code, r.text
    broken = openai_body(b"x", "a.txt", "text/plain")
    broken["messages"][0]["content"][1]["file"]["file_data"] = "data:text/plain;base64,@@@not base64@@@"
    assert (
        client.post("/v1/chat/completions", headers=AUTH, json=broken).json()["error"]["harpo"]["code"]
        == "bad_encoding"
    )
    assert not spy.requests  # nothing was forwarded


def test_a_provider_side_file_id_is_still_not_inspectable(gateway) -> None:  # type: ignore[no-untyped-def]
    client, spy = gateway(documents={"in_chat": True})
    body = chat("Summarize.")
    body["messages"][0]["content"] = [
        {"type": "text", "text": "Summarize."},
        {"type": "file", "file": {"file_id": "file-abc123"}},
    ]
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 403 and not spy.requests


def test_the_chat_body_limit_grows_only_when_documents_in_chat_are_on(gateway) -> None:  # type: ignore[no-untyped-def]
    data = (b"filler words go here. " * 200_000)[:3_000_000]  # a 3 MB text file, 4 MB as base64
    body = openai_body(data, "big.txt", "text/plain")
    client, _ = gateway(server={"max_body_bytes": 100_000})
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 413
    client, spy = gateway(server={"max_body_bytes": 100_000}, documents={"in_chat": True, "max_chars": 4_000_000})
    assert client.post("/v1/chat/completions", headers=AUTH, json=body).status_code == 200
    assert len(spy.last_json()["messages"][0]["content"][1]["text"]) > 2_900_000


# =========================================================================== the command line
@pytest.fixture
def cli_config(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    path = tmp_path / "harpo.yaml"
    path.write_text(
        "environment: development\nauth: {enabled: false}\n"
        "upstreams:\n  - {name: mock, style: openai, base_url: 'http://mock/v1', models: ['mock-*']}\n"
        "detection: {ner: {enabled: false}}\n"
    )
    return str(path)


def test_cli_redacts_a_file(cli_config, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "notes.docx"
    source.write_bytes(fx.make_docx(hidden=False))
    assert main(["redact-file", str(source), "--config", cli_config]) == 0
    summary = json.loads(capsys.readouterr().err)
    redacted = tmp_path / "notes.redacted.docx"
    assert summary["verified"] is True and summary["output"] == str(redacted) and summary["counts"]["EMAIL"] >= 2
    assert (
        fx.canaries_in_package(redacted.read_bytes(), [fx.EMAIL, fx.EMAIL2, "794 6095", "4111", fx.IBAN, fx.BSN]) == []
    )
    with zipfile.ZipFile(io.BytesIO(redacted.read_bytes())) as z:
        assert z.testzip() is None


def test_cli_text_mode_blocked_and_refused_exit_codes(cli_config, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    notes = tmp_path / "notes.txt"
    notes.write_text(f"Mail {fx.EMAIL}")
    assert main(["redact-file", str(notes), "--text", "--config", cli_config]) == 0
    assert capsys.readouterr().out.strip() == "Mail [EMAIL_1]"
    env = tmp_path / ".env"
    env.write_text(f"KEY={SECRET}\n")
    assert main(["redact-file", str(env), "--text", "--config", cli_config]) == 0  # keys are redacted
    assert capsys.readouterr().out.strip() == "KEY=[SECRET_1]"
    strict = tmp_path / "strict.yaml"
    strict.write_text((tmp_path / "harpo.yaml").read_text() + "policy: {entities: {IBAN: {action: block}}}\n")
    refund = tmp_path / "refund.txt"
    refund.write_text(f"Refund to {fx.IBAN}\n")
    assert main(["redact-file", str(refund), "--config", str(strict)]) == 1  # blocked
    capsys.readouterr()
    odd = tmp_path / "data.bin"
    odd.write_bytes(b"\x00\x01")
    assert main(["redact-file", str(odd), "--config", cli_config]) == 2  # refused
    assert "unsupported_format" in capsys.readouterr().err
