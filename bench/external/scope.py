"""Which labels of each external dataset Harpo claims to protect, fixed before any result was seen.

The rule: a label is in scope when Harpo has a detector for that kind of value and its default policy redacts it.
Everything else is out of scope, with the reason. Recall is reported for every label either way; the scope only
decides which labels make up the headline number, so it cannot hide a failure. A label that turns up without an
entry here is reported as unmapped, and gets an entry by the same rule, never by its result.
"""

from __future__ import annotations

# Harpo type that covers the label (any redaction counts: what matters is that the value did not leave).
OPENPII_IN = {
    "GIVENNAME": "PERSON",
    "SURNAME": "PERSON",
    "EMAIL": "EMAIL",
    "TELEPHONENUM": "PHONE",
    "CREDITCARDNUMBER": "CREDIT_CARD",
    "SOCIALNUM": "NATIONAL_ID",
    "TAXNUM": "NATIONAL_ID",
    "IDCARDNUM": "NATIONAL_ID",
    "DRIVERLICENSENUM": "ID_DOCUMENT",
    "PASSPORTNUM": "ID_DOCUMENT",
    "STREET": "ADDRESS",
    "BUILDINGNUM": "ADDRESS",
    "ZIPCODE": "ADDRESS",
    "CITY": "LOCATION",
    "COUNTRY": "LOCATION",
    # Found in the validation file without an entry; added by the rule above, before any result was seen.
    "ORGANISATION": "ORGANIZATION",
    "BANKNAME": "ORGANIZATION",
}
OPENPII_OUT = {
    "DATE": "dates are allowed by default (DATE: allow); a date of birth is redacted when its cue says so",
    "TIME": "a time of day is not personal data on its own; no detector",
    "AGE": "no detector",
    "SEX": "no detector",
    "GENDER": "no detector",
    "TITLE": "honorifics (Mr, Dr) are not redacted",
    "JOBTITLE": "no detector",
    "AMOUNT": "no detector (an amount of money)",
}

# Nemotron-PII and Gretel share one label vocabulary.
SHARED_IN = {
    "name": "PERSON",
    "first_name": "PERSON",
    "last_name": "PERSON",
    "email": "EMAIL",
    "phone_number": "PHONE",
    "fax_number": "PHONE",
    "ssn": "US_SSN",
    "national_id": "NATIONAL_ID",
    "tax_id": "NATIONAL_ID",
    "passport_number": "ID_DOCUMENT",
    "certificate_license_number": "ID_DOCUMENT",
    "driver_license_number": "ID_DOCUMENT",
    "credit_card_number": "CREDIT_CARD",
    "credit_debit_card": "CREDIT_CARD",
    "pin": "SECRET",
    "password": "SECRET",
    "api_key": "SECRET",
    "account_number": "ACCOUNT_ID",
    "bank_routing_number": "ACCOUNT_ID",
    "iban": "IBAN",
    "medical_record_number": "ACCOUNT_ID",
    "health_plan_beneficiary_number": "ACCOUNT_ID",
    "customer_id": "ACCOUNT_ID",
    "street_address": "ADDRESS",
    "address": "ADDRESS",
    "postcode": "ADDRESS",
    "city": "LOCATION",
    "county": "LOCATION",
    "state": "LOCATION",
    "country": "LOCATION",
    "company_name": "ORGANIZATION",
    "ipv4": "IP_ADDRESS",
    "ipv6": "IP_ADDRESS",
    "mac_address": "DEVICE_ID",
    "device_identifier": "DEVICE_ID",
    "vehicle_identifier": "DEVICE_ID",
    "date_of_birth": "DATE_OF_BIRTH",
}
SHARED_OUT = {
    "date": "dates are allowed by default (DATE: allow)",
    "time": "no detector; allowed with dates",
    "date_time": "allowed with dates",
    "age": "no detector",
    "gender": "no detector",
    "race_ethnicity": "special-category data: not detected yet (README, Known limitations)",
    "religious_belief": "special-category data: not detected yet",
    "political_view": "special-category data: not detected yet",
    "sexuality": "special-category data: not detected yet",
    "occupation": "no detector",
    "education_level": "no detector",
    "employment_status": "no detector",
    "blood_type": "no detector",
    "url": "URLs as identifiers: not detected yet (GUIDE, Known limits)",
    "coordinate": "no detector",
    "license_plate": "no detector",
    "user_name": "no detector",
    "biometric_identifier": "no detector",
    "unique_identifier": "an identifier with no cue: a custom type's job",
    "employee_id": "a custom type's job (the example configuration defines one)",
    "swift_bic": "no detector",
    "cvv": "no detector (a PIN or security code after its cue is caught; a CVV cue is not)",
    "http_cookie": "no detector",
    # Found in Nemotron-PII's file without an entry; added by the rule above, before any result was seen.
    "language": "no detector",
    "unique_id": "an identifier with no cue: a custom type's job",
}

# RedactionBench: mandatory spans must be redacted; contextual spans may be, without penalty either way.
REDACTIONBENCH_IN = {"mandatory": "any"}
REDACTIONBENCH_NEUTRAL = {"contextual"}

# ProwlBench: every positive is a credential, which Harpo always redacts (INV-11).
PROWLBENCH_IN = {"secret": "SECRET"}

SCOPES: dict[str, tuple[dict[str, str], dict[str, str]]] = {
    "openpii": (OPENPII_IN, OPENPII_OUT),
    "nemotron": (SHARED_IN, SHARED_OUT),
    "gretel": (SHARED_IN, SHARED_OUT),
    "redactionbench": (REDACTIONBENCH_IN, {}),
    "prowlbench": (PROWLBENCH_IN, {}),
}


def scope_of(dataset: str, labels: list[str]) -> str:
    """'in', 'out' or 'unmapped' for a gold span; a span with several labels is in scope when any of them is."""
    inside, outside = SCOPES[dataset]
    if any(label in inside for label in labels):
        return "in"
    if any(label in outside for label in labels) or (
        dataset == "redactionbench" and set(labels) & REDACTIONBENCH_NEUTRAL
    ):
        return "out"
    return "unmapped"
