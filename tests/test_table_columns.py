"""Table cells typed by their column header or row label (detectors/fields.py with the label words of
detectors/cued.py, names.py and addresses.py), in the languages people write. Every value is made up."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.fields import find_table_fields
from harpo_redact.entities import EntityType as E


def found(text: str) -> set[tuple[str, E]]:
    return {(text[s.start : s.end], s.type) for s in find_table_fields(text)}


def test_a_form_written_as_a_two_column_table() -> None:
    table = (
        "| Field | Value |\n|---|---|\n"
        "| First Name | Maartje |\n| Last Name | Verhoeven |\n| Insured's Last Name | Okafor |\n"
        "| **Policyholder Name** | Tamsin Achterberg |\n| Device ID | 864019057318264 |\n"
        "| Address | Kade 7, 2611 AB Delft |\n| City | Delft |\n| Mobile | +31 6 1234 5678 |\n"
    )
    hits = found(table)
    for value, etype in [
        ("Maartje", E.PERSON), ("Verhoeven", E.PERSON), ("Okafor", E.PERSON), ("Tamsin Achterberg", E.PERSON),
        ("864019057318264", E.DEVICE_ID), ("Kade 7, 2611 AB Delft", E.ADDRESS), ("Delft", E.LOCATION),
        ("+31 6 1234 5678", E.PHONE),
    ]:  # fmt: skip
        assert (value, etype) in hits, value


def test_column_headers_in_other_languages() -> None:
    table = (
        "Vorname;Nachname;Kundennummer;Telefonnummer;Ort\n"
        "Henrike;Albers;KD-4471209;0221 987654;Köln\n"
        "Jonas;Reiter;KD-4471388;0176 1234567;Frankfurt am Main\n"
    )
    hits = found(table)
    for value, etype in [
        ("Henrike", E.PERSON), ("Albers", E.PERSON), ("KD-4471209", E.ACCOUNT_ID), ("0221 987654", E.PHONE),
        ("Köln", E.LOCATION), ("Frankfurt am Main", E.LOCATION), ("KD-4471388", E.ACCOUNT_ID),
    ]:  # fmt: skip
        assert (value, etype) in hits, value


def test_a_blank_line_under_the_header_keeps_the_table() -> None:
    table = "id,first_name,phone\n\nE-17,Leila,+1 613 396 0112\nE-18,Nikhil,+1 613 810 0183\n"
    hits = found(table)
    assert ("+1 613 396 0112", E.PHONE) in hits and ("Nikhil", E.PERSON) in hits


def test_a_name_column_in_a_table_about_people() -> None:
    table = "| Name | E-mail |\n|---|---|\n| Ruben Achterberg | ruben@example.org |\n| Noor | noor@example.org |\n"
    hits = found(table)
    assert ("Ruben Achterberg", E.PERSON) in hits
    assert ("Noor", E.PERSON) not in hits  # one word under a bare "Name" could be anything


@pytest.mark.parametrize(
    "table",
    [
        "| Name | Price |\n|---|---|\n| Standard Plan | 10 |\n| Widget Pro | 20 |\n",  # products
        "| Ticket | Title | State |\n|---|---|---|\n| 12 | Fix login | Open |\n",  # a status, not a state
        "| Host | Address |\n|---|---|\n| db1 | 10.0.0.5 |\n| cache | 0x7ffd5a2c |\n",  # machines
        "| Email Address | Plan |\n|---|---|\n| a@example.org | Basic |\n",
        "| Claim | Status |\n|---|---|\n| 1500 | paid |\n",  # an amount under a word that also names numbers
        "| Card Type | Account Type |\n|---|---|\n| Visa | Savings |\n",
        "| First Name | Last Name |\n|---|---|\n| N/A | Unknown |\n",
    ],
)
def test_cells_that_are_not_what_a_label_suggests(table: str) -> None:
    assert found(table) == set()
