"""Harpo LeakBench v1: an adversarial privacy benchmark (roadmap 14-18).

    python bench/leakbench.py generate                      # writes bench/leakbench/corpus.jsonl (deterministic)
    python bench/leakbench.py run --config deterministic    # or: ner, slm (needs --slm-url)
    python bench/leakbench.py report                        # docs/LEAKBENCH.md from bench/leakbench/results-*.json

Each case is a text with labelled sensitive values ("secrets", with the exact surface written into the text) and
"keep" phrases that must survive unchanged. A secret *escapes* when its surface is still in the redacted output.
A keep phrase that does not survive is a false positive. A trap case has no secrets: blocking it is a false block.

The corpus is synthetic. It measures behaviour under known transformations, not how often real text looks like
this, so recall here is not recall in the wild.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import resource
import statistics
import string
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent
DIR = ROOT / "leakbench"
CORPUS = DIR / "corpus.jsonl"
SEED = 20261006
MULTILINGUAL = {"nl": "nl_core_news_sm", "de": "de_core_news_sm", "fr": "fr_core_news_sm", "es": "es_core_news_sm"}
CONFIGS = ["deterministic", "ner", "default-image", "multilingual", "slm"]

# --------------------------------------------------------------------------- synthetic values
FIRST = {
    "en": ["Emily", "James", "Olivia", "Noah"], "nl": ["Sanne", "Daan", "Fleur", "Jeroen"],
    "de": ["Lukas", "Hannah", "Jürgen", "Katrin"], "fr": ["Élodie", "Mathieu", "Camille", "Théo"],
    "es": ["Lucía", "Mateo", "Carmen", "Iker"], "other": ["Priya", "Chinedu", "Elif", "Wang", "Zofia", "Omar"],
}  # fmt: skip
LAST = {
    "en": ["Thompson", "Hughes", "Walker", "Bennett"], "nl": ["de Vries", "Bakker", "Visser", "van Dijk"],
    "de": ["Müller", "Schneider", "Becker", "Hoffmann"], "fr": ["Martin", "Lefèvre", "Dubois", "Moreau"],
    "es": ["García", "Fernández", "López", "Martínez"], "other": ["Raman", "Okafor", "Yılmaz", "Wei", "Kowalska", "Haddad"],
}  # fmt: skip
TEMPLATES = {
    "en": "Please ask {who} to check the file. {value} was in the notes. Thanks for checking the report.",
    "nl": "Wil je {who} vragen het dossier te controleren? {value} stond in de notities. Bedankt voor het rapport.",
    "de": "Bitte {who} bitten, die Akte zu prüfen. {value} stand in den Notizen. Danke für den Bericht.",
    "fr": "Merci de demander à {who} de vérifier le dossier. {value} figurait dans les notes. Merci pour le rapport.",
    "es": "Pide a {who} que revise el expediente. {value} aparecía en las notas. Gracias por el informe.",
}  # fmt: skip
KEEP = {
    "en": ["check the file", "Thanks for checking the report"], "nl": ["het dossier te controleren", "Bedankt voor het rapport"],
    "de": ["die Akte zu prüfen", "Danke für den Bericht"], "fr": ["vérifier le dossier", "Merci pour le rapport"],
    "es": ["revise el expediente", "Gracias por el informe"],
}  # fmt: skip
IBANS = [
    "NL91ABNA0417164300",
    "DE89370400440532013000",
    "GB29NWBK60161331926819",
    "FR1420041010050500013M02606",
    "ES9121000418450200051332",
]
WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]


def luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return str((10 - total % 10) % 10)


def card_grouped(rng: random.Random) -> str:
    while True:
        prefix = rng.choice(["4", "51", "55"])
        body = prefix + "".join(rng.choice(string.digits) for _ in range(15 - len(prefix)))
        d = body + luhn_digit(body)
        return " ".join(d[i : i + 4] for i in range(0, 16, 4))


def bsn(rng: random.Random) -> str:
    while True:
        d = [rng.randint(0, 9) for _ in range(8)]
        total = sum(v * w for v, w in zip(d, range(9, 1, -1), strict=True))
        last = total % 11
        if last < 10 and d[0] != 0:
            return "".join(map(str, d)) + str(last)


def ssn(rng: random.Random) -> str:
    return f"{rng.randint(100, 665):03d}-{rng.randint(10, 99):02d}-{rng.randint(1000, 9999):04d}"


def phone(rng: random.Random) -> str:
    """Only numbers libphonenumber accepts: an invalid "number" is not a leak (corpus v1 had 8 such labels)."""
    import phonenumbers

    while True:
        candidate = rng.choice(
            [f"+31 6 {rng.randint(1000, 9999)} {rng.randint(1000, 9999)}", f"+44 20 7{rng.randint(100, 999)} {rng.randint(1000, 9999)}",
             f"+49 30 {rng.randint(100000, 999999)}", f"+1 415 {rng.randint(200, 999)} {rng.randint(1000, 9999)}",
             f"+33 6 {rng.randint(10, 99)} {rng.randint(10, 99)} {rng.randint(10, 99)} {rng.randint(10, 99)}"]
        )  # fmt: skip
        if phonenumbers.is_valid_number(phonenumbers.parse(candidate, None)):
            return candidate


def email(rng: random.Random, first: str, last: str) -> str:
    local = f"{first}.{last}".lower().replace(" ", "")
    local = "".join(c for c in local if c.isascii() and (c.isalnum() or c == "."))
    return f"{local}{rng.randint(1, 99)}@{rng.choice(['example.com', 'corp.example', 'mail.example.org'])}"


def secrets_from_fixture() -> list[str]:
    data = json.loads((ROOT.parent / "tests" / "data" / "secret_samples.json").read_text())
    keep = []
    for rule in (
        "github-pat",
        "gitlab-pat",
        "slack-bot-token",
        "stripe-access-token",
        "npm-access-token",
        "jwt",
        "gcp-api-key",
    ):
        if rule in data["samples"]:
            keep.append(data["samples"][rule]["secret"])  # noqa: PERF401 (an ordered, filtered pick)
    return keep


SEED_PHRASE = "legal winner thank year wave sausage worth useful legal winner thank yellow"


# --------------------------------------------------------------------------- attacks
def zero_width(v: str) -> str:
    return "\u200b".join(v)


def fullwidth(v: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else c for c in v)


def homoglyph(v: str) -> str:
    table = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}  # Cyrillic look-alikes
    return "".join(table.get(c, c) for c in v)


def b64(v: str) -> str:
    return base64.b64encode(v.encode()).decode()


def b64x2(v: str) -> str:
    return b64(b64(v))


def b64url(v: str) -> str:
    return base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")


def url_encoded(v: str) -> str:
    return quote(v, safe="")


def html_entities(v: str) -> str:
    return "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in v)


def json_escape(v: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if not c.isalnum() else c for c in v)


def spoken(v: str) -> str:
    return v.replace("@", " at ").replace(".", " dot ")


def spelled(v: str) -> str:
    return " ".join(WORDS[int(c)] for c in v if c.isdigit())


def leet(v: str) -> str:
    return v.translate(str.maketrans({"a": "4", "e": "3", "o": "0", "i": "1"}))


def split_lines(v: str) -> str:
    half = len(v) // 2
    return v[:half] + "\n" + v[half:]


def spaced(v: str) -> str:
    return " ".join(v.replace(" ", ""))


def bidi(v: str) -> str:
    return "\u202e" + v + "\u202c"


ATTACKS: dict[str, Callable[[str], str]] = {
    "plain": lambda v: v, "zero_width": zero_width, "fullwidth": fullwidth, "homoglyph": homoglyph, "base64": b64,
    "base64x2": b64x2, "base64url": b64url, "url_encoded": url_encoded, "html_entity": html_entities,
    "json_escape": json_escape, "spoken": spoken, "spelled_out": spelled, "leetspeak": leet, "lowercase": str.lower,
    "uppercase": str.upper, "split_lines": split_lines, "spaced": spaced, "bidi": bidi,
}  # fmt: skip
APPLIES = {  # which attacks make sense for which category
    "email": ["plain", "zero_width", "homoglyph", "base64", "base64x2", "base64url", "url_encoded", "html_entity", "json_escape",
              "spoken", "leetspeak", "uppercase", "bidi"],
    "phone": ["plain", "zero_width", "fullwidth", "base64", "spelled_out", "spaced", "split_lines", "bidi"],
    "card": ["plain", "zero_width", "fullwidth", "base64", "base64x2", "spelled_out", "spaced", "split_lines", "bidi"],
    "iban": ["plain", "zero_width", "lowercase", "base64", "spaced", "split_lines", "bidi"],
    "bsn": ["plain", "zero_width", "fullwidth", "base64", "spelled_out", "spaced"],
    "ssn": ["plain", "zero_width", "fullwidth", "base64", "spelled_out"],
    "secret": ["plain", "zero_width", "base64", "base64x2", "base64url", "split_lines", "bidi"],
    "seed_phrase": ["plain", "uppercase", "base64"],
    "name": ["plain", "lowercase", "uppercase", "homoglyph", "leetspeak", "zero_width"],
}  # fmt: skip
CUES = {"bsn": {"en": "BSN", "nl": "BSN", "de": "BSN", "fr": "BSN", "es": "BSN"}, "ssn": {k: "SSN" for k in TEMPLATES}}
TRAPS = [
    "Request id 550e8400-e29b-41d4-a716-446655440000", "commit e83c5163316f89bfbde7d9ab23ca2e25604af290",
    "ISBN 978-3-16-148410-0", "order #100045678", "version 10.0.19045.3693", "invoice INV-2026-000123",
    "price $12,345.67", "meeting on 2026-03-14 at 09:30", "SKU-88213-XL", "room 1204, floor 12",
    "tracking 1Z999AA10123456784", "the Paris agreement", "model number 1234567890123", "CVE-2024-3094",
]  # fmt: skip


def generate() -> list[dict[str, Any]]:
    rng = random.Random(SEED)
    cases: list[dict[str, Any]] = []
    secrets_pool = secrets_from_fixture()
    makers: dict[str, Callable[[str, str, str], str]] = {
        "email": lambda lang, f, last: email(rng, f, last),
        "phone": lambda lang, f, last: phone(rng),
        "card": lambda lang, f, last: card_grouped(rng),
        "iban": lambda lang, f, last: rng.choice(IBANS),
        "bsn": lambda lang, f, last: bsn(rng),
        "ssn": lambda lang, f, last: ssn(rng),
        "secret": lambda lang, f, last: rng.choice(secrets_pool),
        "seed_phrase": lambda lang, f, last: SEED_PHRASE,
        "name": lambda lang, f, last: f"{f} {last}",
    }
    for category, attacks in APPLIES.items():
        for attack in attacks:
            for lang in TEMPLATES:
                for n in range(4):
                    pool = "other" if n == 3 else lang  # one in four names comes from outside the language
                    first, last = rng.choice(FIRST[pool]), rng.choice(LAST[pool])
                    value = makers[category](lang, first, last)
                    surface = ATTACKS[attack](value)
                    cue = CUES.get(category, {}).get(lang)
                    written = f"{cue} {surface}" if cue else surface
                    who = "the team" if category == "name" else f"{rng.choice(FIRST[lang])} {rng.choice(LAST[lang])}"
                    text = TEMPLATES[lang].format(who=who, value=written)
                    cases.append({
                        "id": f"{category}-{attack}-{lang}-{n}", "category": category, "attack": attack, "lang": lang,
                        "text": text, "secrets": [{"value": value, "surface": surface}], "keep": KEEP[lang],
                    })  # fmt: skip
    for i, trap in enumerate(TRAPS):
        for lang in TEMPLATES:
            text = TEMPLATES[lang].format(who="the team", value=trap)
            cases.append({"id": f"trap-{i}-{lang}", "category": "trap", "attack": "lookalike", "lang": lang, "text": text,
                          "secrets": [], "keep": [*KEEP[lang], trap]})  # fmt: skip
    return cases


# --------------------------------------------------------------------------- running
def pipeline_for(config: str, slm_url: str | None) -> Any:
    sys.path.insert(0, str(ROOT.parent / "src"))
    from harpo_redact.api import load_ner
    from harpo_redact.config import Settings
    from harpo_redact.pipeline import Pipeline

    if config == "deterministic":
        settings = Settings(environment="development", detection={"ner": {"enabled": False}})
        return Pipeline(settings)
    ner_cfg: dict[str, Any] = {"cache_entries": 0}  # "ner": the default, English model on all text
    if config in ("multilingual", "slm"):
        ner_cfg["language_models"] = MULTILINGUAL
    if config == "default-image":  # what the Docker image ships: MIT-licensed models only
        ner_cfg["language_models"] = {"de": "de_core_news_sm", "other": "xx_ent_wiki_sm"}
    settings = Settings(environment="development", detection={"ner": ner_cfg})
    ner = load_ner(settings.detection.ner)
    if config != "slm":
        return Pipeline(settings, ner=ner)
    import httpx

    from harpo_redact.detectors.slm import SLMDetector

    if not slm_url:
        raise SystemExit("the slm configuration needs --slm-url pointing at a local Ollama")
    client = httpx.AsyncClient(base_url=slm_url)
    return Pipeline(settings, ner=ner, slm=SLMDetector(client, settings.detection.slm.model, timeout_ms=30_000))


def run(config: str, slm_url: str | None, limit: int | None) -> dict[str, Any]:
    import asyncio

    cases = [json.loads(line) for line in CORPUS.read_text().splitlines()]
    cases = cases[:limit] if limit else cases
    pipeline = pipeline_for(config, slm_url)
    pipeline.warmup()
    latencies, escapes, fps, false_blocks = [], [], [], []
    per: dict[str, dict[str, list[int]]] = {"category": defaultdict(lambda: [0, 0]), "attack": defaultdict(lambda: [0, 0]),
                                            "lang": defaultdict(lambda: [0, 0])}  # fmt: skip
    keeps_total = 0
    cpu0 = time.process_time()
    wall0 = time.perf_counter()
    for case in cases:
        t = time.perf_counter()
        out = asyncio.run(pipeline.scan([case["text"]])) if config == "slm" else pipeline.scan_sync([case["text"]])
        latencies.append((time.perf_counter() - t) * 1000)
        redacted = out.texts[0]
        for s in case["secrets"]:
            escaped = (s["surface"] in redacted or s["value"] in redacted) and not out.blocked
            for dim in per:
                per[dim][case[dim]][0] += 1
                per[dim][case[dim]][1] += int(escaped)
            if escaped:
                escapes.append(case["id"])
        for phrase in case["keep"]:
            keeps_total += 1
            if not out.blocked and phrase not in redacted:
                fps.append(f"{case['id']}: {phrase}")
        if not case["secrets"] and out.blocked:
            false_blocks.append(case["id"])
    wall = time.perf_counter() - wall0
    total = sum(1 for c in cases for _ in c["secrets"])
    traps = sum(1 for c in cases if not c["secrets"])
    ordered = sorted(latencies)

    def pct(q: float) -> float:
        return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 2)

    def table(dim: str) -> dict[str, Any]:
        return {
            k: {"secrets": v[0], "escapes": v[1], "recall": round(1 - v[1] / v[0], 4)}
            for k, v in sorted(per[dim].items())
        }

    return {
        "config": config,
        "corpus": {"cases": len(cases), "secrets": total, "trap_cases": traps, "keep_phrases": keeps_total,
                   "sha256": hashlib.sha256(CORPUS.read_bytes()).hexdigest()[:16]},
        "raw_identifier_escapes": len(escapes),
        "recall": round(1 - len(escapes) / total, 4) if total else None,
        "false_positive_rate": round(len(fps) / keeps_total, 4),
        "false_block_rate": round(len(false_blocks) / traps, 4) if traps else None,
        "by_category": table("category"), "by_attack": table("attack"), "by_language": table("lang"),
        "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "mean": round(statistics.fmean(latencies), 2)},
        "throughput_cases_per_s": round(len(cases) / wall, 1),
        "cpu_s": round(time.process_time() - cpu0, 2),
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
        "escapes": escapes, "false_positives": fps, "false_blocks": false_blocks,
    }  # fmt: skip


def report() -> str:
    rows = []
    results = {}
    for name in CONFIGS:
        path = DIR / f"results-{name}.json"
        if path.exists():
            results[name] = json.loads(path.read_text())
    lines = [
        "# LeakBench results", "",
        "Generated by `python bench/leakbench.py report`. Regenerate the corpus with `generate`, measure with `run --config`.", "",
        "**What it measures.** Each case is a sentence in English, Dutch, German, French or Spanish holding one labelled",
        "value (a valid synthetic email, phone, card, IBAN, BSN, SSN, secret, seed phrase or name) written under one of 18",
        "transformations (zero-width characters, full-width digits, Cyrillic look-alikes, base64 and double base64,",
        "URL/HTML/JSON escapes, spoken and spelled-out forms, leetspeak, case changes, line splits, one-by-one spacing,",
        "bidi controls). A value *escapes* when its written form is still in the output. Two phrases per case, and 14",
        "look-alike traps (UUIDs, hashes, ISBNs, invoice numbers, prices, versions), must come out unchanged; a damaged",
        "one is a false positive. A blocked trap is a false block.", "",
        "**What it does not measure.** The corpus is synthetic: recall here is behaviour under known attacks, not recall",
        "on real traffic, and every attack family is weighted equally. Names are the hard part and the corpus has few of",
        "them. The SLM configuration needs a local Ollama and is not in this table unless it was run.", "",
        "| Configuration | Secrets | Raw escapes | Recall | False-positive rate | False blocks | p50 ms | p95 ms | p99 ms |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]  # fmt: skip
    for name, r in results.items():
        lines.append(f"| {name} | {r['corpus']['secrets']} | {r['raw_identifier_escapes']} | {r['recall']:.1%} | "
                     f"{r['false_positive_rate']:.2%} | {r['false_block_rate']:.1%} | {r['latency_ms']['p50']} | "
                     f"{r['latency_ms']['p95']} | {r['latency_ms']['p99']} |")  # fmt: skip
    for dim in ("by_category", "by_attack", "by_language"):
        lines += ["", f"## Escapes {dim.replace('_', ' ')}", "", "| " + dim[3:] + " | " + " | ".join(results) + " |",
                  "| --- | " + " | ".join("---" for _ in results) + " |"]  # fmt: skip
        keys = sorted({k for r in results.values() for k in r[dim]})
        for k in keys:
            cells = [f"{r[dim][k]['escapes']}/{r[dim][k]['secrets']}" if k in r[dim] else "-" for r in results.values()]
            lines.append(f"| {k} | " + " | ".join(cells) + " |")
    rows.append("\n".join(lines))
    return "\n".join(rows) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["generate", "run", "report"])
    parser.add_argument("--config", choices=CONFIGS, default="deterministic")
    parser.add_argument("--slm-url")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    DIR.mkdir(exist_ok=True)
    if args.command == "generate":
        cases = generate()
        CORPUS.write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases))
        print(f"{len(cases)} cases, {sum(len(c['secrets']) for c in cases)} labelled secrets -> {CORPUS}")
    elif args.command == "run":
        result = run(args.config, args.slm_url, args.limit)
        (DIR / f"results-{args.config}.json").write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n")
        summary = {
            k: result[k]
            for k in ("raw_identifier_escapes", "recall", "false_positive_rate", "false_block_rate", "latency_ms")
        }
        print(json.dumps(summary))
    else:
        out = ROOT.parent / "docs" / "LEAKBENCH.md"
        out.write_text(report())
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
