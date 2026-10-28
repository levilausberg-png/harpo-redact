"""The local engine: Harpo's own pipeline, policy and document handling in your process, without a server.

Every call goes through the code the gateway runs: ``Pipeline.scan`` for scans, the proxy's checks (a block stops
it, then egress verification on what would leave) for ``redact``, ``documents.service.redact_document`` for files.
Nothing here detects, decides or redacts on its own.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import threading
import weakref
from collections.abc import Coroutine, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import yaml
from pydantic import ValidationError

from .. import KEY_PREFIX, __version__
from . import _config, _convert
from ._errors import ConfigurationError, DocumentError, HarpoError, InvalidRequestError
from ._results import (
    ConfigFinding,
    ConfigIssue,
    CustomType,
    DocumentResult,
    EngineStatus,
    GatewayKey,
    PolicyView,
    ResponseScan,
    ScanResult,
    Trace,
    Verification,
)

if TYPE_CHECKING:
    import httpx

    from ..config import Settings
    from ..documents.runner import WorkerRunner
    from ..pipeline import Pipeline, ScanOutcome

Mode = Literal["relational", "generic"]
Layers = Literal["full", "fast"]
Action = Literal["redact", "block", "allow"]
_T = TypeVar("_T")
TextList = list[str] | tuple[str, ...]  # several texts (a str is one text)

_MODES = ("relational", "generic")
_LAYERS = ("full", "fast")
# The proxy's own words for its egress check (api.py, sanitize): a value still there after redaction stops it.
_EGRESS_MESSAGE = "The sanitized request still contained detectable data, so it was not sent."


# --------------------------------------------------------------------------- arguments
def _texts(value: str | Sequence[str]) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, bytes | bytearray) or not isinstance(value, Sequence):
        raise TypeError(f"text must be a str or a sequence of str, not {type(value).__name__}")
    texts = list(value)
    if not texts:
        raise InvalidRequestError("give at least one text")
    for i, text in enumerate(texts):
        if not isinstance(text, str):
            raise TypeError(f"texts[{i}] is {type(text).__name__}, not str")
    return texts


def _options(mode: str | None, layers: str = "full") -> None:
    if mode is not None and mode not in _MODES:
        raise InvalidRequestError("mode must be relational or generic")
    if layers not in _LAYERS:
        raise InvalidRequestError("layers must be full or fast")


def _document_input(source: bytes | str | os.PathLike[str], filename: str | None) -> tuple[bytes, str]:
    if isinstance(source, bytes | bytearray | memoryview):
        return bytes(source), filename or ""
    if isinstance(source, str | os.PathLike):
        path = Path(source)
        return path.read_bytes(), filename or path.name
    raise TypeError(f"source must be a path or the file's bytes, not {type(source).__name__}")


def _block_details(outcome: ScanOutcome, permitted: bool) -> dict[str, Any]:
    # The fields of the gateway's 403 (api.py, block_details).
    return {
        "risk": outcome.risk.value,
        "overridable": outcome.overridable and permitted,
        "override_permitted": permitted,
        "blocked_types": outcome.blocked_types,
        "reasons": [r.to_dict() for r in outcome.reasons],
    }


def _scan_payload(outcome: ScanOutcome, layers: str, permitted: bool) -> dict[str, Any]:
    # The body of the gateway's POST /v1/scan answer, built from the same outcome (api.py, scan).
    return {
        "risk": outcome.risk.value,
        "overridable": outcome.overridable and permitted,
        "reasons": [r.to_dict() for r in outcome.reasons],
        "mode": outcome.mode,
        "context_repair": outcome.context_repair,
        "layers": layers,
        "results": [
            {"redacted": text, "entities": [f.to_dict() for f in findings]}
            for text, findings in zip(outcome.texts, outcome.findings, strict=True)
        ],
        "counts": outcome.counts,
        "redactions": outcome.redactions,
        "rot_score": outcome.rot_score,
        "flags": outcome.flags,
        "slm": outcome.slm_status,
        "timings_ms": outcome.timings_ms,
    }


def _policy_payload(settings: Settings, permitted: bool) -> dict[str, Any]:
    # The policy part of GET /v1/policy (api.py, policy): actions, custom types by name and count, the switches.
    from ..entities import ALWAYS_REDACTED

    p = settings.policy
    return {
        "version": __version__,
        "environment": settings.environment,
        "default_mode": p.default_mode,
        "context_repair": p.context_repair,
        "client_may_choose_mode": p.client_may_choose_mode,
        "entities": {t.value: {"action": e.action, "overridable": e.overridable} for t, e in p.entities.items()},
        "always_redacted": sorted(t.value for t in ALWAYS_REDACTED),
        "custom_types": [
            {
                "name": c.name,
                "description": c.description,
                "action": c.action,
                "overridable": c.overridable,
                "terms": len(c.terms),
                "patterns": len(c.patterns),
            }
            for c in settings.detection.custom_types
        ],
        "rot_threshold": p.rot_threshold,
        "unsupported_content": p.unsupported_content,
        "override_permitted": permitted,
        "override": p.override,
        "unknown_fields": p.unknown_fields,
        "remote_mcp": p.remote_mcp,
        "egress_verification": p.egress_verification,
        "response_scan": p.response_scan,
        "ner": {"enabled": settings.detection.ner.enabled, "model": settings.detection.ner.model},
        "slm": {"enabled": settings.detection.slm.enabled, "on_failure": settings.detection.slm.on_failure},
    }


def _policy_overlay(
    settings: Settings,
    entities: Mapping[str, Action] | None,
    custom_types: Sequence[CustomType | Mapping[str, Any]] | None,
    detectors: Mapping[str, bool] | None,
) -> Settings:
    """The live-policy overlay the console applies (live_policy.apply), on this engine's configuration."""
    from .. import live_policy

    payload: dict[str, Any] = {}
    if entities is not None:
        payload["entities"] = {str(getattr(k, "value", k)): v for k, v in entities.items()}
    if custom_types is not None:
        payload["custom_types"] = [c.as_config() if isinstance(c, CustomType) else dict(c) for c in custom_types]
    if detectors is not None:
        payload["detectors"] = dict(detectors)
    try:
        return live_policy.apply(settings, live_policy.LivePolicy.model_validate(payload))
    except ValidationError as exc:
        issues = [ConfigIssue(".".join(str(p) for p in e.get("loc", ())), str(e.get("msg", ""))) for e in exc.errors()]
        shown = "; ".join(f"{i.path}: {i.message}" for i in issues[:5])
        raise ConfigurationError(f"the policy is not valid: {shown}", issues=issues) from None
    except ValueError as exc:
        raise ConfigurationError(f"the policy is not valid: {exc}", issues=[ConfigIssue("", str(exc))]) from None


def generate_key(
    key_id: str,
    *,
    admin: bool = False,
    can_override: bool = False,
    expires_at: datetime | str | None = None,
    requests_per_minute: int | None = None,
) -> GatewayKey:
    """A new gateway key, made as ``harpo hash-key`` and ``POST /v1/keys/generate`` make them: ``harpo_`` and 32
    random bytes. Nothing is stored: add ``yaml`` (the id and the key's SHA-256) to ``auth.keys`` in the
    configuration, and hand ``key`` to the client it is for."""
    from ..config import AuthKey

    key = KEY_PREFIX + secrets.token_urlsafe(32)
    try:
        entry = AuthKey(
            id=key_id,
            sha256=hashlib.sha256(key.encode()).hexdigest(),
            admin=admin,
            can_override=can_override,
            expires_at=expires_at,  # pydantic parses ISO 8601 strings
            requests_per_minute=requests_per_minute,
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise InvalidRequestError(f"invalid key setting {where}: {first['msg']}") from None
    snippet = yaml.safe_dump([entry.model_dump(mode="json", exclude_none=True)], sort_keys=False)
    return GatewayKey(id=entry.id, key=key, sha256=entry.sha256, yaml=snippet)


# --------------------------------------------------------------------------- the engine core
class _Core:
    """One engine: its configuration, the pipeline (spaCy models are loaded once per process), the document
    runner and the local SLM's client. Its coroutines run on one event loop for the life of the engine."""

    def __init__(self, settings: Settings, live: bool, warmup: bool) -> None:
        self.settings = settings
        self.live = live
        self.warmup = warmup
        self.closed = False
        self._pipeline: Pipeline | None = None
        self._runner: WorkerRunner | None = None
        self._slm_client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    @property
    def override_permitted(self) -> bool:
        # A caller in the same process holds no gateway key: the rule of a gateway without auth (api.py,
        # authenticate) applies, overrides unless the policy says never.
        return self.settings.policy.override != "never"

    def chosen(self, mode: str | None, context_repair: bool | None) -> tuple[Mode | None, bool | None]:
        # Like X-Harpo-Mode on the gateway: honoured only when the policy lets callers choose.
        if not self.settings.policy.client_may_choose_mode:
            return None, None
        return mode, context_repair  # type: ignore[return-value]  # checked by _options

    async def start(self) -> Pipeline:
        async with self._lock:
            if self.closed:
                raise HarpoError("this engine is closed")
            if self._pipeline is not None:
                return self._pipeline
            missing = _config.missing_models(self.settings)
            if missing:
                raise ConfigurationError("; ".join(missing), issues=[ConfigIssue("detection.ner", m) for m in missing])
            from ..api import load_ner  # the gateway's loader: one model per process and configuration
            from ..documents.runner import WorkerRunner
            from ..pipeline import Pipeline

            ner_cfg = self.settings.detection.ner
            ner = await asyncio.to_thread(load_ner, ner_cfg) if ner_cfg.enabled else None
            slm = None
            slm_cfg = self.settings.detection.slm
            if slm_cfg.enabled:  # built as the gateway builds it at startup (api.py, lifespan)
                import httpx

                from ..detectors.slm import SLMDetector

                self._slm_client = httpx.AsyncClient(
                    base_url=slm_cfg.base_url, timeout=slm_cfg.timeout_ms / 1000 + 1, follow_redirects=False
                )
                slm = SLMDetector(
                    self._slm_client, slm_cfg.model, slm_cfg.timeout_ms, slm_cfg.max_chunk_chars,
                    slm_cfg.max_concurrency, slm_cfg.keep_alive, max_input_chars=slm_cfg.max_input_chars,
                    model_digest=slm_cfg.model_digest,
                )  # fmt: skip
            pipeline = Pipeline(self.settings, ner=ner, slm=slm)
            if self.warmup:
                await asyncio.to_thread(pipeline.warmup)
            self._runner = WorkerRunner(self.settings.documents)
            self._pipeline = pipeline
            return pipeline

    async def close(self) -> None:
        async with self._lock:
            self.closed = True
            if self._slm_client is not None:
                await self._slm_client.aclose()
                self._slm_client = None

    async def _guarded(self, work: Coroutine[Any, Any, _T], keep: tuple[type[Exception], ...] = ()) -> _T:
        """Errors from inside the engine keep their type but not their message: a message may quote the text.
        ``keep`` are the engine's own errors with messages written to be shown (a document's refusal)."""
        try:
            return await work
        except Exception as exc:
            if isinstance(exc, (HarpoError, *keep)):
                raise
            error = HarpoError(
                f"internal error in Harpo's engine ({type(exc).__name__}); its message is withheld because it may "
                "quote the input. The original exception is on .original"
            )
            error.original = exc  # type: ignore[attr-defined]
            raise error from None

    async def scan(
        self, texts: list[str], mode: str | None, context_repair: bool | None, layers: Layers, override: bool
    ) -> dict[str, Any]:
        pipeline = await self.start()
        chosen_mode, repair = self.chosen(mode, context_repair)
        permitted = self.override_permitted
        outcome = await self._guarded(
            pipeline.scan(
                texts, mode=chosen_mode, context_repair=repair, layers=layers, override=override and permitted
            )
        )
        return _scan_payload(outcome, layers, permitted)

    async def redact(
        self, texts: list[str], mode: str | None, context_repair: bool | None, override: bool
    ) -> list[str]:
        """The proxy's sanitize path for plain texts: scan, stop on a block, then egress verification."""
        pipeline = await self.start()
        chosen_mode, repair = self.chosen(mode, context_repair)
        permitted = self.override_permitted
        outcome = await self._guarded(
            pipeline.scan(
                texts, mode=chosen_mode, context_repair=repair, layers="full", override=override and permitted
            )
        )
        if outcome.blocked:
            raise _convert.blocked("", _block_details(outcome, permitted))
        if self.settings.policy.egress_verification == "full":
            leftover = await self._guarded(pipeline.residual(list(outcome.texts)))
            if leftover:
                reason = {"code": "egress_verification", "level": "red", "message": _EGRESS_MESSAGE,
                          "entity_type": None, "count": sum(leftover.values()), "overridable": False}  # fmt: skip
                details = {"overridable": False, "override_permitted": permitted,
                           "blocked_types": sorted(leftover), "reasons": [reason]}  # fmt: skip
                raise _convert.blocked("", details)
        return list(outcome.texts)

    async def residual(self, texts: list[str]) -> dict[str, int]:
        pipeline = await self.start()
        return await self._guarded(pipeline.residual(texts))

    async def response(self, texts: list[str]) -> tuple[list[str], dict[str, int]]:
        pipeline = await self.start()
        return await self._guarded(pipeline.redact_deterministic(texts))

    async def document(
        self,
        data: bytes,
        filename: str,
        content_type: str | None,
        mode: str | None,
        context_repair: bool | None,
        override: bool,
        want_file: bool,
    ) -> DocumentResult:
        from ..documents.runner import DocumentError as CoreDocumentError
        from ..documents.service import clean_filename, redact_document

        pipeline = await self.start()
        runner = self._runner
        if runner is None:  # set by start()
            raise HarpoError("the engine did not start")
        chosen_mode, repair = self.chosen(mode, context_repair)
        permitted = self.override_permitted
        try:
            result = await self._guarded(
                redact_document(
                    pipeline, self.settings.documents, runner, data, clean_filename(filename), content_type,
                    mode=chosen_mode, context_repair=repair, override=override and permitted, want_file=want_file,
                ),
                keep=(CoreDocumentError,),
            )  # fmt: skip
        except CoreDocumentError as exc:
            raise DocumentError(exc.code, exc.message) from None
        outcome = result.scan
        if outcome.blocked:
            raise _convert.blocked("", _block_details(outcome, permitted))
        # The JSON answer of POST /v1/documents/redact (api.py, documents_redact), with the file as bytes.
        out_name = f"{result.filename}.redacted.{result.extension or 'txt'}" if result.data is not None else None
        payload = {
            "risk": outcome.risk.value,
            "kind": result.kind,
            "reasons": [r.to_dict() for r in outcome.reasons],
            "mode": outcome.mode,
            "counts": outcome.counts,
            "redactions": outcome.redactions,
            "segments": result.segments,
            "info": result.info,
            "text": result.text,
            "verified": result.verified,
            "file": {"filename": out_name, "content_type": result.content_type} if result.data is not None else None,
        }
        return _convert.document_result(payload, result.data)

    async def trace(self, text: str) -> dict[str, Any]:
        from ..lab import lab_run

        pipeline = await self.start()
        return await self._guarded(asyncio.to_thread(lab_run, pipeline, text))

    async def status(self) -> EngineStatus:
        pipeline = await self.start()
        ner = pipeline.ner
        models: tuple[str, ...] = ()
        if ner is not None:
            cfg = self.settings.detection.ner
            models = tuple(dict.fromkeys([cfg.model, *cfg.language_models.values()]))
        reachable = await pipeline.slm.ping() if pipeline.slm is not None else None
        return EngineStatus(
            version=__version__,
            environment=self.settings.environment,
            ner_models=models,
            slm=self.settings.detection.slm.model if pipeline.slm is not None else None,
            slm_reachable=reachable,
            secret_rules=pipeline.secret_rule_count,
            custom_types=tuple(c.name for c in self.settings.detection.custom_types),
            live_policy=self.live,
        )

    def policy(self) -> PolicyView:
        return _convert.policy_view(_policy_payload(self.settings, self.override_permitted))

    def analyze(self) -> tuple[ConfigFinding, ...]:
        from ..analysis import analyze

        return tuple(_convert.config_finding(f) for f in analyze(self.settings))

    def detection_library(self) -> dict[str, Any]:
        from .. import library

        return library.describe(self.settings)


# --------------------------------------------------------------------------- the synchronous engine
class _Portal:
    """An event loop on a thread of its own: every call of one synchronous engine runs on it, so the pipeline's
    semaphores, the document runner and the SLM client always share one loop, from any calling thread, inside a
    running event loop too."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._started = threading.Event()
        self._thread = threading.Thread(target=self._main, name="harpo-sdk", daemon=True)
        self._thread.start()
        self._started.wait()

    def _main(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.call_soon(self._started.set)
        try:
            self._loop.run_forever()
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
                self._loop.run_until_complete(self._loop.shutdown_default_executor())
            finally:
                self._loop.close()

    def call(self, work: Coroutine[Any, Any, _T]) -> _T:
        if threading.current_thread() is self._thread:
            work.close()
            raise RuntimeError("a Harpo engine cannot be called from its own event loop")
        if not self._thread.is_alive():
            work.close()
            raise HarpoError("this engine is closed")
        return asyncio.run_coroutine_threadsafe(work, self._loop).result()

    def stop(self) -> None:
        if self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join()


def _shutdown(portal: _Portal, core: _Core) -> None:
    try:
        portal.call(core.close())
    finally:
        portal.stop()


class Harpo:
    """Harpo in your process: the gateway's own detection, policy, redaction and document handling, no server.

    ::

        from harpo_redact.sdk import Harpo

        with Harpo() as harpo:                      # the default configuration
            safe = harpo.redact("Mail jane.doe@example.com about card 4111 1111 1111 1111")
            # 'Mail [EMAIL_1] about card [CREDIT_CARD_1]'

    ``config`` is ``None`` (the defaults), a mapping shaped like ``harpo.yaml``, or the path of a YAML file;
    ``HARPO_*`` environment variables apply on top, and ``policy.live_file`` is laid over it, as the gateway does.
    ``Harpo.from_env()`` reads what ``harpo serve`` reads. The language models the configuration names must be
    installed (``ConfigurationError`` says how); they are loaded once per process and shared by every engine.

    The engine is thread-safe. Close it (or use ``with``) to stop its event-loop thread."""

    _core: _Core
    _portal: _Portal
    _finalizer: weakref.finalize[[_Portal, _Core], Harpo]

    def __init__(self, config: _config.ConfigSource = None, *, warmup: bool = True) -> None:
        self._start(*_config.with_live_policy(_config.load(config)), warmup)

    @classmethod
    def from_env(cls, *, warmup: bool = True) -> Harpo:
        """The configuration ``harpo serve`` would run with: ``$HARPO_CONFIG``, or ./harpo.yaml, or
        ./config/harpo.yaml, plus ``HARPO_*`` variables and the live policy file."""
        engine = cls.__new__(cls)
        engine._start(*_config.with_live_policy(_config.from_environment()), warmup)
        return engine

    def _start(self, settings: Settings, live: bool, warmup: bool) -> None:
        core = _Core(settings, live, warmup)
        portal = _Portal()
        try:
            portal.call(core.start())
        except BaseException:
            portal.stop()
            raise
        self._core, self._portal = core, portal
        self._finalizer = weakref.finalize(self, _shutdown, portal, core)

    def _call(self, work: Coroutine[Any, Any, _T]) -> _T:
        if not self._finalizer.alive:
            work.close()
            raise HarpoError("this engine is closed")
        return self._portal.call(work)

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        """Stop the engine's event-loop thread and close its connections. Calling it again does nothing."""
        self._finalizer()

    def __enter__(self) -> Harpo:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if not self._finalizer.alive else "open"
        return f"<Harpo {__version__} {state}, mode={self._core.settings.policy.default_mode}>"

    # ------------------------------------------------------------------ text
    def scan(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        layers: Layers = "full",
        override: bool = False,
    ) -> ScanResult:
        """Find and replace what the policy protects, and judge the result, as ``POST /v1/scan`` does.

        Several texts are scanned together, so one value gets one placeholder across all of them. The result is
        returned even when the policy blocks: check ``result.blocked`` before using ``result.text``. ``mode`` and
        ``context_repair`` apply when the policy lets callers choose (``policy.client_may_choose_mode``);
        ``override=True`` sends overridable blocked types as placeholders, unless ``policy.override`` is never.
        ``layers="fast"`` leaves out the local SLM."""
        texts = _texts(text)
        _options(mode, layers)
        payload = self._call(self._core.scan(texts, mode, context_repair, layers, override))
        return _convert.scan_result(payload)

    @overload
    def redact(
        self, text: str, /, *, mode: Mode | None = None, context_repair: bool | None = None, override: bool = False
    ) -> str: ...

    @overload
    def redact(
        self,
        text: TextList,
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> list[str]: ...

    def redact(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> str | list[str]:
        """The text as the gateway would let it leave, or ``BlockedError``.

        The proxy's checks for a request, on plain text: the scan, a block stops it (``BlockedError`` with the
        reasons), and with ``policy.egress_verification: full`` (the default) the redacted text is scanned again,
        and anything still found stops it too. A list of texts returns a list."""
        texts = _texts(text)
        _options(mode)
        out = self._call(self._core.redact(texts, mode, context_repair, override))
        return out[0] if isinstance(text, str) else out

    def verify(self, text: str | Sequence[str], /) -> Verification:
        """What the deterministic layers still find: the egress check, on text you are about to send."""
        return Verification(self._call(self._core.residual(_texts(text))))

    def scan_response(self, text: str | Sequence[str], /) -> ResponseScan:
        """A provider's answer through the deterministic layers, with plain labels ([EMAIL]): what
        ``policy.response_scan`` does to answers on the gateway. No NER: an answer may name who you asked about."""
        texts, counts = self._call(self._core.response(_texts(text)))
        return ResponseScan(tuple(texts), counts)

    # ------------------------------------------------------------------ documents
    def redact_document(
        self,
        source: bytes | str | os.PathLike[str],
        /,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        file: bool = True,
    ) -> DocumentResult:
        """Redact a PDF, Word, Excel, PowerPoint or text file, as ``harpo redact-file`` and ``POST
        /v1/documents/redact`` do.

        ``source`` is a path or the file's bytes (then give ``filename``: its extension identifies text files).
        The file is parsed in a separate, limited worker process; the redacted file is opened again and scanned
        before it is returned. ``file=False`` returns the redacted text only. A blocked document raises
        ``BlockedError``; one that cannot be processed, ``DocumentError`` with a stable ``code``."""
        data, name = _document_input(source, filename)
        _options(mode)
        return self._call(self._core.document(data, name, content_type, mode, context_repair, override, file))

    # ------------------------------------------------------------------ policy and configuration
    @property
    def policy(self) -> PolicyView:
        """The policy this engine scans with: an action per type, the custom types and the switches."""
        return self._core.policy()

    def with_policy(
        self,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
        warmup: bool = True,
    ) -> Harpo:
        """A new engine with a policy laid over this one's, as the console's Policy page does: an action per type
        (``{"US_SSN": "block", "ORGANIZATION": "allow"}``), the custom types (they replace this engine's), and
        detector families switched on or off. The combination is checked as the gateway checks it: keys stay
        redacted, critical types are never allowed. The models are shared; close the new engine too."""
        settings = _policy_overlay(self._core.settings, entities, custom_types, detectors)
        engine = Harpo.__new__(Harpo)
        engine._start(settings, self._core.live, warmup)
        return engine

    def analyze(self) -> tuple[ConfigFinding, ...]:
        """Hardening findings on this configuration, each with its setting (the console's configuration analysis)."""
        return self._core.analyze()

    def detection_library(self) -> dict[str, Any]:
        """Every detector family under its umbrella, on or off here (``harpo check-config`` and LIBRARY.md)."""
        return self._core.detection_library()

    def status(self) -> EngineStatus:
        """What the engine runs with: models, the local SLM and whether it answers, credential rules, custom types."""
        return self._call(self._core.status())

    def trace(self, text: str, /) -> Trace:
        """One sample through the detection stages, each stage's findings apart (the console's detector lab).
        The trace holds your text: keep it out of logs."""
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, not {type(text).__name__}")
        return Trace(self._call(self._core.trace(text)))


# --------------------------------------------------------------------------- the asynchronous engine
class AsyncHarpo:
    """The engine for asyncio code: the same calls as :class:`Harpo`, as coroutines, on your event loop.

    ::

        async with AsyncHarpo() as harpo:
            result = await harpo.scan("Call +31 6 1234 5678")

    Models load in a worker thread when the engine starts (``async with``, ``await start()``, or the first call).
    An engine belongs to the event loop it started on."""

    def __init__(self, config: _config.ConfigSource = None, *, warmup: bool = True) -> None:
        settings, live = _config.with_live_policy(_config.load(config))
        self._core = _Core(settings, live, warmup)

    @classmethod
    def from_env(cls, *, warmup: bool = True) -> AsyncHarpo:
        """The configuration ``harpo serve`` would run with (see :meth:`Harpo.from_env`)."""
        engine = cls.__new__(cls)
        settings, live = _config.with_live_policy(_config.from_environment())
        engine._core = _Core(settings, live, warmup)
        return engine

    async def start(self) -> AsyncHarpo:
        """Load the models and warm up. Called by ``async with`` and, if needed, by the first call."""
        await self._core.start()
        return self

    async def aclose(self) -> None:
        await self._core.close()

    async def __aenter__(self) -> AsyncHarpo:
        return await self.start()

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        state = "closed" if self._core.closed else "open"
        return f"<AsyncHarpo {__version__} {state}, mode={self._core.settings.policy.default_mode}>"

    async def scan(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        layers: Layers = "full",
        override: bool = False,
    ) -> ScanResult:
        """See :meth:`Harpo.scan`."""
        texts = _texts(text)
        _options(mode, layers)
        payload = await self._core.scan(texts, mode, context_repair, layers, override)
        return _convert.scan_result(payload)

    @overload
    async def redact(
        self, text: str, /, *, mode: Mode | None = None, context_repair: bool | None = None, override: bool = False
    ) -> str: ...

    @overload
    async def redact(
        self,
        text: TextList,
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> list[str]: ...

    async def redact(
        self,
        text: str | Sequence[str],
        /,
        *,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
    ) -> str | list[str]:
        """See :meth:`Harpo.redact`."""
        texts = _texts(text)
        _options(mode)
        out = await self._core.redact(texts, mode, context_repair, override)
        return out[0] if isinstance(text, str) else out

    async def verify(self, text: str | Sequence[str], /) -> Verification:
        """See :meth:`Harpo.verify`."""
        return Verification(await self._core.residual(_texts(text)))

    async def scan_response(self, text: str | Sequence[str], /) -> ResponseScan:
        """See :meth:`Harpo.scan_response`."""
        texts, counts = await self._core.response(_texts(text))
        return ResponseScan(tuple(texts), counts)

    async def redact_document(
        self,
        source: bytes | str | os.PathLike[str],
        /,
        *,
        filename: str | None = None,
        content_type: str | None = None,
        mode: Mode | None = None,
        context_repair: bool | None = None,
        override: bool = False,
        file: bool = True,
    ) -> DocumentResult:
        """See :meth:`Harpo.redact_document`. A path is read in a worker thread."""
        if isinstance(source, str | os.PathLike):
            data, name = await asyncio.to_thread(_document_input, source, filename)
        else:
            data, name = _document_input(source, filename)
        _options(mode)
        return await self._core.document(data, name, content_type, mode, context_repair, override, file)

    @property
    def policy(self) -> PolicyView:
        """See :attr:`Harpo.policy`."""
        return self._core.policy()

    async def with_policy(
        self,
        *,
        entities: Mapping[str, Action] | None = None,
        custom_types: Sequence[CustomType | Mapping[str, Any]] | None = None,
        detectors: Mapping[str, bool] | None = None,
        warmup: bool = True,
    ) -> AsyncHarpo:
        """See :meth:`Harpo.with_policy`. The new engine is started; close it too."""
        settings = _policy_overlay(self._core.settings, entities, custom_types, detectors)
        engine = AsyncHarpo.__new__(AsyncHarpo)
        engine._core = _Core(settings, self._core.live, warmup)
        return await engine.start()

    def analyze(self) -> tuple[ConfigFinding, ...]:
        """See :meth:`Harpo.analyze`."""
        return self._core.analyze()

    def detection_library(self) -> dict[str, Any]:
        """See :meth:`Harpo.detection_library`."""
        return self._core.detection_library()

    async def status(self) -> EngineStatus:
        """See :meth:`Harpo.status`."""
        return await self._core.status()

    async def trace(self, text: str, /) -> Trace:
        """See :meth:`Harpo.trace`."""
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, not {type(text).__name__}")
        return Trace(await self._core.trace(text))
