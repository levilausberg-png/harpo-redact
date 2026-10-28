"""Write a CycloneDX 1.5 SBOM (sbom.cdx.json) from requirements.lock and the model wheels in the Dockerfile.

python tools/make_sbom.py > sbom.cdx.json
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def components() -> list[dict[str, object]]:
    found: dict[str, dict[str, object]] = {}
    current: dict[str, object] | None = None
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\;]+)", line)
        if m:
            name, version = m.group(1).lower(), m.group(2)
            current = {"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name}@{version}",
                       "bom-ref": f"pkg:pypi/{name}@{version}", "hashes": []}  # fmt: skip
            found[name] = current
        for digest in re.findall(r"--hash=sha256:([0-9a-f]{64})", line):
            if current is not None:
                current["hashes"].append({"alg": "SHA-256", "content": digest})  # type: ignore[attr-defined]
    docker = (ROOT / "Dockerfile").read_text()
    models = re.findall(r"sha256:([0-9a-f]{64})\s+\$\{SPACY_BASE\}/([a-z_]+)-([0-9.]+)/", docker)
    en = re.search(r"SPACY_MODEL_SHA256=([0-9a-f]{64})", docker)
    if en:
        models.append((en.group(1), "en_core_web_sm", "3.8.0"))
    for digest, name, version in models:
        found[name] = {"type": "machine-learning-model", "name": name, "version": version, "bom-ref": f"spacy-model:{name}@{version}",
                       "hashes": [{"alg": "SHA-256", "content": digest}],
                       "externalReferences": [{"type": "distribution", "url": f"https://github.com/explosion/spacy-models/releases/tag/{name}-{version}"}]}  # fmt: skip
    return sorted(found.values(), key=lambda c: str(c["name"]))


def main() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "component": {"type": "application", "name": project["name"], "version": project["version"],
                                   "bom-ref": f"{project['name']}@{project['version']}"}},
        "components": components(),
    }  # fmt: skip
    json.dump(bom, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
