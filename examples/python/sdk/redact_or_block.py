"""redact(): the text as the gateway would let it leave, or BlockedError when the policy says nothing may.

python examples/python/sdk/redact_or_block.py
"""

from harpo_redact.sdk import BlockedError, Harpo

# US Social Security numbers block the request; everything else is redacted (every value is invented).
CONFIG = {"policy": {"entities": {"US_SSN": {"action": "block"}}}}

with Harpo(CONFIG) as harpo:
    print(harpo.redact("Send the contract to priya.raman@corp.example by Friday."))
    try:
        harpo.redact("Her SSN is 536-90-4399, please update the record.")
    except BlockedError as blocked:
        print("blocked:", blocked)  # the reasons name types and counts, never values
        print("types:", blocked.blocked_types, "| reasons:", blocked.codes)
