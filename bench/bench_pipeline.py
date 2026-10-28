"""Latency benchmark: pipeline layers and the full proxy path (in-process, mock provider).

    python bench/bench_pipeline.py [--runs 200] [--json bench/results.json]

Numbers depend on the CPU. Run it on the hardware you deploy to.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import time

import httpx

from harpo_redact.api import create_app, load_ner
from harpo_redact.config import Settings
from harpo_redact.mock_upstream import create_mock_app
from harpo_redact.pipeline import Pipeline

PARAGRAPHS = [
    "Hi, I'm Priya Raman from Northwind Logistics in Rotterdam. Our customer Jan de Vries "
    "(jan.devries@example.nl, +31 6 12345678) was charged twice on card 4111 1111 1111 1111. ",
    "Please draft a reply explaining that the refund goes to NL91ABNA0417164300 within five working days, "
    "and copy the account manager on the thread so the history stays in one place. ",
    "The shipment for order 88213 left the warehouse on Tuesday and should arrive before the weekend; "
    "the carrier confirmed the delay was caused by a customs check at the border. ",
    "Ask Lars Eriksen whether the replacement pallet can be booked on the Thursday route instead. ",
]


def make_text(size: int) -> str:
    out, i = "", 0
    while len(out) < size:
        out += PARAGRAPHS[i % len(PARAGRAPHS)]
        i += 1
    return out[:size]


def pct(values: list[float], q: float) -> float:
    values = sorted(values)
    k = (len(values) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def measure(fn, runs: int) -> dict[str, float]:  # type: ignore[no-untyped-def]
    for _ in range(5):
        fn()
    samples = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000)
    return {
        "p50": round(pct(samples, 0.5), 2),
        "p95": round(pct(samples, 0.95), 2),
        "mean": round(statistics.fmean(samples), 2),
    }


async def proxy_latency(text: str, runs: int) -> dict[str, float]:
    settings = Settings(
        environment="development",
        auth={"enabled": False},
        detection={"ner": {"cache_entries": 0}},
        upstreams=[{"name": "mock", "style": "openai", "base_url": "http://mock/v1", "models": ["mock-provider"]}],
    )
    mock = httpx.ASGITransport(app=create_mock_app())
    app = create_app(settings, upstream_transport=mock)
    body = {"model": "mock-provider", "messages": [{"role": "user", "content": text}]}
    gw: list[float] = []
    up: list[float] = []
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as client,
        httpx.AsyncClient(transport=mock, base_url="http://mock") as direct,
    ):
        for i in range(runs + 5):
            t = time.perf_counter()
            r = await client.post("/v1/chat/completions", json=body)
            elapsed = (time.perf_counter() - t) * 1000
            t = time.perf_counter()
            await direct.post("/v1/chat/completions", json=body)
            direct_ms = (time.perf_counter() - t) * 1000
            assert r.status_code == 200, r.text
            if i >= 5:
                gw.append(elapsed)
                up.append(direct_ms)
    overhead = [g - u for g, u in zip(gw, up, strict=True)]
    return {
        "p50": round(pct(overhead, 0.5), 2),
        "p95": round(pct(overhead, 0.95), 2),
        "mean": round(statistics.fmean(overhead), 2),
    }


def conversation(seed: int, turns: int = 10) -> list[str]:
    """A chat whose messages are new for every seed, so runs never share cache entries."""
    return [f"{PARAGRAPHS[i % len(PARAGRAPHS)]}(ticket {seed}-{i})" for i in range(turns)]


def chat_turn_ms(pipeline: Pipeline, runs: int, *, replay_history: bool) -> dict[str, float]:
    """Time the 10th request of a chat: nine earlier messages plus a new one (about 4 KB in total)."""
    samples = []
    for seed in range(runs + 5):
        messages = conversation(seed)
        if replay_history:  # earlier turns were scanned when they were sent
            for k in range(1, len(messages)):
                pipeline.scan_sync(messages[:k])
        t = time.perf_counter()
        pipeline.scan_sync(messages)
        if seed >= 5:
            samples.append((time.perf_counter() - t) * 1000)
    return {
        "p50": round(pct(samples, 0.5), 2),
        "p95": round(pct(samples, 0.95), 2),
        "mean": round(statistics.fmean(samples), 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=200)
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    cold = Settings(environment="development", detection={"ner": {"cache_entries": 0}})
    cached = Settings(environment="development")
    deterministic = Pipeline(Settings(environment="development", detection={"ner": {"enabled": False}}))
    full = Pipeline(cold, ner=load_ner(cold.detection.ner))
    full_cached = Pipeline(cached, ner=load_ner(cached.detection.ner))
    for p in (deterministic, full, full_cached):
        p.warmup()

    results: dict[str, object] = {
        "machine": {"python": platform.python_version(), "cpu_count": os.cpu_count(), "platform": platform.platform()},
        "runs": args.runs,
        "rows": [],
    }
    print(f"{'size':>6}  {'layers':<26} {'p50 ms':>8} {'p95 ms':>8}")
    for size in (1024, 4096, 16384):
        text = make_text(size)
        for label, fn in (
            ("deterministic only", lambda t=text: deterministic.scan_sync([t])),
            ("deterministic + NER (sm)", lambda t=text: full.scan_sync([t])),
        ):
            stats = measure(fn, args.runs)
            results["rows"].append({"size": size, "layers": label, **stats})  # type: ignore[union-attr]
            print(f"{size:>6}  {label:<26} {stats['p50']:>8} {stats['p95']:>8}")
        overhead = asyncio.run(proxy_latency(text, max(50, args.runs // 4)))
        results["rows"].append({"size": size, "layers": "proxy overhead (full path)", **overhead})  # type: ignore[union-attr]
        print(f"{size:>6}  {'proxy overhead (full path)':<26} {overhead['p50']:>8} {overhead['p95']:>8}")
    chat_runs = max(40, args.runs // 4)
    for label, pipeline, replay in (
        ("10-turn chat, no cache", full, False),
        ("10-turn chat, NER cache", full_cached, True),
    ):
        stats = chat_turn_ms(pipeline, chat_runs, replay_history=replay)
        results["rows"].append({"size": 4096, "layers": label, **stats})  # type: ignore[union-attr]
        print(f"{'chat':>6}  {label:<26} {stats['p50']:>8} {stats['p95']:>8}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)


if __name__ == "__main__":
    main()
