"""Your own types and a stricter policy, as the console's Policy page would set them.

python examples/python/sdk/custom_policy.py
"""

from harpo_redact.sdk import BlockedError, CustomType, Harpo

TEXT = "Ask about EMP-204613 and the Bluefin roadmap, then mail lars.eriksen@corp.example."  # invented
CUSTOM = [
    CustomType("EMPLOYEE_ID", patterns=(r"\bEMP-\d{6}\b",)),  # RE2 expressions
    CustomType("PROJECT", terms=("Bluefin",)),  # exact words or phrases, any case
]

with Harpo() as harpo:
    print("default:     ", harpo.redact(TEXT))
    with harpo.with_policy(custom_types=CUSTOM) as mine:
        print("custom types:", mine.redact(TEXT))
    with harpo.with_policy(entities={"EMAIL": "block"}, custom_types=CUSTOM) as strict:
        try:
            strict.redact(TEXT)
        except BlockedError as blocked:
            print("blocked:     ", blocked.blocked_types)
        print("policy:      ", [(c.name, c.action, c.terms, c.patterns) for c in strict.policy.custom_types])
