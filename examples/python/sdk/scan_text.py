"""Scan a text with the engine in your process: what Harpo finds, the verdict, and the text that may leave.

python examples/python/sdk/scan_text.py
"""

from harpo_redact.sdk import Harpo

TEXT = (
    "Customer Maria Jansen (maria.jansen@northwind.example, +31 6 1234 5678) paid with card 4111 1111 1111 1111. "
    "The job uses AWS key AKIAZ4X7Q2LMWN3RT5PJ."
)  # every value is invented

with Harpo() as harpo:  # the default configuration; Harpo("harpo.yaml") reads a file
    result = harpo.scan(TEXT)

print(result)  # types, counts and the verdict: never the text
print("risk:", result.risk.value, "| blocked:", result.blocked)
for finding in result.findings:
    where = f"{finding.start}-{finding.end}"
    print(f"  {finding.type:<12} {finding.placeholder:<16} at {where:<8} ({', '.join(finding.sources)})")
for reason in result.reasons:
    print(f"  {reason.level.value}: {reason.message}")
print(result.text)
