"""The engine in asyncio code: AsyncHarpo runs the same pipeline on your event loop.

python examples/python/sdk/async_engine.py
"""

import asyncio

from harpo_redact.sdk import AsyncHarpo

TICKETS = [  # invented
    "Ticket 1: Anna Jansen cannot log in, her phone is +31 6 9876 5432.",
    "Ticket 2: refund to IBAN NL91 ABNA 0417 1643 00 for anna.jansen@mail.example.",
    "Ticket 3: the build log shows DATABASE_PASSWORD=Qz7vL2mX9pR4tW8k in plain text.",
]


async def main() -> None:
    async with AsyncHarpo() as harpo:
        results = await asyncio.gather(*(harpo.scan(ticket) for ticket in TICKETS))
        for result in results:
            print(result.risk.value, result.text)
        # One scan of several texts gives one value one placeholder across all of them.
        together = await harpo.scan(TICKETS)
        print(together.texts)


asyncio.run(main())
