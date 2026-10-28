"""Redact a file: PDF, Word, Excel, PowerPoint or text. It is parsed in a separate worker process, rebuilt, then
opened again and scanned before it is handed back.

    python examples/python/sdk/redact_document.py [path]
"""

import sys
import tempfile
from pathlib import Path

from harpo_redact.sdk import DocumentError, Harpo

with tempfile.TemporaryDirectory() as folder:
    if len(sys.argv) > 1:
        source = Path(sys.argv[1])
    else:  # a small CSV of invented people
        source = Path(folder) / "customers.csv"
        source.write_text(
            "name,email,phone\nPriya Raman,priya.raman@corp.example,+31 20 794 6095\n"
            "Lars Eriksen,lars.eriksen@corp.example,+44 20 7946 0958\n"
        )
    with Harpo() as harpo:
        try:
            result = harpo.redact_document(source)
        except DocumentError as refused:
            sys.exit(f"refused ({refused.code}): {refused}")
        print(result)  # kind, size, verification and counts: never the content
        saved = result.save(folder)
        print("saved", saved.name, "| verified before release:", result.verified)
        print(result.text)
