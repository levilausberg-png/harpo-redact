"""Synthetic values for RegionBench: Dutch, US and EU identifiers and personal data, valid where a check exists.

Every generator takes a random.Random and returns a value as a person would write it. Values with a check digit
pass it (python-stdnum or the published algorithm); the rest have the length and alphabet of the real thing. None
of them belongs to anyone: names and streets are common ones, numbers are drawn at random.
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable

import phonenumbers
from stdnum import iban as std_iban
from stdnum import luhn

Gen = Callable[[random.Random], str]

DIGITS = string.digits
UPPER = string.ascii_uppercase


def _digits(rng: random.Random, n: int, first: str = "123456789") -> str:
    return rng.choice(first) + "".join(rng.choice(DIGITS) for _ in range(n - 1))


def _until(rng: random.Random, make: Callable[[], str], ok: Callable[[str], bool], tries: int = 20000) -> str:
    for _ in range(tries):
        value = make()
        if ok(value):
            return value
    raise RuntimeError("no valid value found")


def _stdnum_ok(module: str) -> Callable[[str], bool]:
    from importlib import import_module

    mod = import_module(f"stdnum.{module}")

    def ok(value: str) -> bool:
        try:
            return bool(mod.is_valid(value))
        except Exception:
            return False

    return ok


def _group(value: str, sizes: tuple[int, ...], sep: str = " ") -> str:
    out, i = [], 0
    for n in sizes:
        out.append(value[i : i + n])
        i += n
    if i < len(value):
        out.append(value[i:])
    return sep.join(p for p in out if p)


# --------------------------------------------------------------------------- the Netherlands
def eleven_check(body: str, last_weight: int = -1) -> bool:
    weights = [*range(len(body), 1, -1), last_weight]
    return sum(int(d) * w for d, w in zip(body, weights, strict=True)) % 11 == 0


def nl_bsn(rng: random.Random) -> str:
    return _until(rng, lambda: _digits(rng, 9, "1234567"), lambda v: eleven_check(v))


def nl_bsn_written(rng: random.Random) -> str:
    v = nl_bsn(rng)
    return rng.choice([v, v, f"{v[:4]}.{v[4:6]}.{v[6:]}", f"{v[:3]} {v[3:6]} {v[6:]}", f"{v[:3]}.{v[3:6]}.{v[6:]}"])


def nl_onderwijsnummer(rng: random.Random) -> str:
    return _until(rng, lambda: "10" + _digits(rng, 7, DIGITS), _stdnum_ok("nl.onderwijsnummer"))


def nl_rsin(rng: random.Random) -> str:
    return _until(rng, lambda: _digits(rng, 9, "8"), lambda v: eleven_check(v))


def nl_btw(rng: random.Random) -> str:
    if rng.random() < 0.5:  # the btw-identificatienummer since 2020: mod 97
        value = _until(rng, lambda: "NL" + _digits(rng, 9, "0") + "B" + _digits(rng, 2, "0123456789"),
                       _stdnum_ok("nl.btw"))  # fmt: skip
    else:  # the old btw-nummer: an RSIN, B, and the company's number
        value = "NL" + nl_rsin(rng) + "B" + rng.choice(["01", "01", "02", "03"])
    return rng.choice([value, value, f"{value[:2]} {value[2:6]}.{value[6:8]}.{value[8:11]}.{value[11:]}",
                       f"{value[:2]}{value[2:11]}.{value[11:]}"])  # fmt: skip


def nl_loonheffingennummer(rng: random.Random) -> str:
    return nl_rsin(rng) + "L" + rng.choice(["01", "01", "02"])


def nl_kvk(rng: random.Random) -> str:
    v = _digits(rng, 8)
    return rng.choice([v, v, f"{v[:4]} {v[4:]}", f"{v[:2]}{v[2:5]}{v[5:]}"])


def nl_vestigingsnummer(rng: random.Random) -> str:
    return "0000" + _digits(rng, 8) if rng.random() < 0.5 else _digits(rng, 12, "0")


def nl_a_nummer(rng: random.Random) -> str:
    def make() -> str:
        out = [rng.choice("123456789")]
        while len(out) < 10:
            d = rng.choice(DIGITS)
            if d != out[-1]:
                out.append(d)
        return "".join(out)

    return make()


def nl_v_nummer(rng: random.Random) -> str:
    return _digits(rng, 10)


def nl_document_number(rng: random.Random) -> str:
    alnum = "ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789"
    return (
        "".join(rng.choice("ABCDEFGHIJKLMNPRSTUVWXZ") for _ in range(2))
        + "".join(rng.choice(alnum) for _ in range(6))
        + rng.choice("123456789")
    )


def nl_rijbewijsnummer(rng: random.Random) -> str:
    return _digits(rng, 10, "45")


_KENTEKEN_LETTERS = "BDFGHJKLNPRSTVXZ"


def nl_kenteken(rng: random.Random) -> str:
    sidecode = rng.choice(["LL-DD-DD", "DD-LL-DD", "LL-DD-LL", "LL-LL-DD", "DD-LL-LL", "DD-LLL-D", "D-LLL-DD",
                           "LL-DDD-L", "L-DDD-LL", "LLL-DD-L", "D-LL-DDD", "DDD-LL-D"])  # fmt: skip
    return "".join(
        rng.choice(_KENTEKEN_LETTERS) if c == "L" else rng.choice(DIGITS) if c == "D" else c for c in sidecode
    )


def nl_agb(rng: random.Random) -> str:
    return rng.choice(["01", "02", "03", "04", "08", "22", "27"]) + _digits(rng, 6, DIGITS)


def nl_big(rng: random.Random) -> str:
    return _digits(rng, 11)


def nl_uzi(rng: random.Random) -> str:
    return _until(rng, lambda: _digits(rng, 9), lambda v: eleven_check(v))


def nl_ov_chipkaart(rng: random.Random) -> str:
    v = "3528" + _digits(rng, 12, DIGITS)
    return _group(v, (4, 4, 4, 4))


def nl_polisnummer(rng: random.Random) -> str:
    style = rng.choice(["digits", "letters", "dashed"])
    if style == "digits":
        return _digits(rng, rng.choice([8, 9, 10]))
    if style == "letters":
        return "".join(rng.choice(UPPER) for _ in range(2)) + _digits(rng, 7, DIGITS)
    return f"{_digits(rng, 3)}-{_digits(rng, 3, DIGITS)}-{_digits(rng, 3, DIGITS)}"


def nl_klantnummer(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 7), _digits(rng, 9), "K" + _digits(rng, 7, DIGITS), "KL-" + _digits(rng, 6)])


def nl_dossiernummer(rng: random.Random) -> str:
    return rng.choice([f"{rng.randint(2019, 2026)}/{_digits(rng, 5, DIGITS)}", "D" + _digits(rng, 8, DIGITS),
                       f"Z{rng.randint(2020, 2026)}-{_digits(rng, 6, DIGITS)}"])  # fmt: skip


def nl_parketnummer(rng: random.Random) -> str:
    return f"{rng.randint(1, 99):02d}/{_digits(rng, 6, DIGITS)}-{rng.randint(18, 26)}"


def nl_studentnummer(rng: random.Random) -> str:
    return rng.choice(["s" + _digits(rng, 7), _digits(rng, 7), "S" + _digits(rng, 7)])


def nl_personeelsnummer(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 6), "P" + _digits(rng, 6, DIGITS), "MW-" + _digits(rng, 5)])


def nl_iban(rng: random.Random) -> str:
    bank = rng.choice(["ABNA", "INGB", "RABO", "SNSB", "TRIO", "ASNB", "KNAB", "BUNQ", "RBRB"])
    body = bank + _digits(rng, 10, "0123456789")
    value = "NL" + std_iban.calc_check_digits("NL00" + body) + body
    return rng.choice([value, value, _group(value, (4, 4, 4, 4, 2))])


def _phone(rng: random.Random, region: str, make: Callable[[], str], style: int | None = None) -> str:
    raw = _until(rng, make, lambda v: phonenumbers.is_valid_number(phonenumbers.parse(v, region)))
    number = phonenumbers.parse(raw, region)
    formats = [phonenumbers.PhoneNumberFormat.NATIONAL, phonenumbers.PhoneNumberFormat.INTERNATIONAL]
    return phonenumbers.format_number(number, formats[style if style is not None else rng.randrange(2)])


def nl_mobile(rng: random.Random) -> str:
    raw = _until(rng, lambda: "06" + _digits(rng, 8, "123456789"),
                 lambda v: phonenumbers.is_valid_number(phonenumbers.parse(v, "NL")))  # fmt: skip
    style = rng.choice(["0612345678", "06-12345678", "06 1234 5678", "06 12 34 56 78", "+31 6 12345678",
                        "+31 (0)6 1234 5678", "+31612345678", "0031 6 12345678"])  # fmt: skip
    d = raw[2:]
    return {
        "0612345678": raw,
        "06-12345678": f"06-{d}",
        "06 1234 5678": f"06 {d[:4]} {d[4:]}",
        "06 12 34 56 78": f"06 {d[:2]} {d[2:4]} {d[4:6]} {d[6:]}",
        "+31 6 12345678": f"+31 6 {d}",
        "+31 (0)6 1234 5678": f"+31 (0)6 {d[:4]} {d[4:]}",
        "+31612345678": f"+316{d}",
        "0031 6 12345678": f"0031 6 {d}",
    }[style]


_NL_AREAS = ["10", "20", "30", "40", "50", "70", "71", "72", "73", "76", "79", "13", "15", "23", "24", "26", "33",
             "35", "36", "38", "43", "45", "46", "53", "55", "58", "74", "75", "77", "78"]  # fmt: skip


def nl_landline(rng: random.Random) -> str:
    def make() -> str:
        area = rng.choice(_NL_AREAS)
        return "0" + area + _digits(rng, 7 if len(area) == 2 else 6, "2345678")

    raw = _until(rng, make, lambda v: phonenumbers.is_valid_number(phonenumbers.parse(v, "NL")))
    area, rest = raw[1:3], raw[3:]
    return rng.choice([f"0{area}-{rest}", f"0{area} {rest[:3]} {rest[3:]}", f"+31 {area} {rest[:3]} {rest[3:]}",
                       f"(0{area}) {rest}", raw])  # fmt: skip


NL_FIRST = ["Jan", "Pieter", "Daan", "Sem", "Lucas", "Emma", "Julia", "Sophie", "Tess", "Anna", "Fleur", "Sanne",
            "Lotte", "Bram", "Thijs", "Ruben", "Joris", "Femke", "Marieke", "Willem", "Hendrik", "Johanna",
            "Cornelis", "Geert", "Annelies", "Wouter", "Kees", "Mieke", "Ingrid", "Henk", "Gerrit", "Ilse",
            "Maarten", "Noor", "Floor", "Jasper", "Esther", "Roel", "Wilma", "Bas", "Chantal", "Mohamed",
            "Fatima", "Yusuf", "Priya", "Rachid", "Saskia", "Joost", "Hanneke", "Teun"]  # fmt: skip
NL_LAST = ["de Jong", "Jansen", "de Vries", "van den Berg", "van Dijk", "Bakker", "Janssen", "Visser", "Smit",
           "Meijer", "de Boer", "Mulder", "de Groot", "Bos", "Vos", "Peters", "Hendriks", "van Leeuwen", "Dekker",
           "Brouwer", "de Wit", "Dijkstra", "Smits", "de Graaf", "van der Meer", "van der Linden", "Kok",
           "Jacobs", "de Haan", "Vermeulen", "van den Heuvel", "van der Veen", "van den Broek", "de Bruijn",
           "van der Heijden", "Schouten", "van Beek", "Willems", "van Vliet", "van de Ven", "Hoekstra", "Maas",
           "Verhoeven", "Koster", "van Dam", "van der Wal", "Prins", "Blom", "Huisman", "Kuipers", "Veenstra",
           "Kramer", "El Amrani", "Yilmaz", "Bouzid", "Ter Horst", "Wijnands", "Zandbergen", "Oosterhuis"]  # fmt: skip
NL_STREETS = ["Kerkstraat", "Dorpsstraat", "Molenweg", "Stationsweg", "Schoolstraat", "Julianastraat",
              "Wilhelminastraat", "Beatrixlaan", "Parallelweg", "Nieuwstraat", "Hoofdstraat", "Spoorstraat",
              "Kastanjelaan", "Eikenlaan", "Industrieweg", "Laan van Meerdervoort", "Burgemeester de Vlugtlaan",
              "Van Heemstraweg", "Prinsengracht", "Keizersgracht", "Oudegracht", "Coolsingel", "Lindengracht",
              "Brinkstraat", "Marktplein", "Havenkade", "Rijnkade", "Zeedijk", "Veldhovenring", "Bloemendaalseweg",
              "Amsterdamsestraatweg", "Professor Kochstraat", "Pieter Calandlaan", "Weteringschans", "Damrak",
              "Rokin", "Herengracht", "Vondelstraat", "Overtoom", "Lange Voorhout", "Sint Jansstraat",
              "Tolstraat", "Javastraat", "Hogeweg", "Burgwal", "Biltstraat", "Kanaalweg", "Brugstraat"]  # fmt: skip
NL_CITIES = ["Amsterdam", "Rotterdam", "Den Haag", "Utrecht", "Eindhoven", "Groningen", "Tilburg", "Almere",
             "Breda", "Nijmegen", "Apeldoorn", "Haarlem", "Arnhem", "Enschede", "Amersfoort", "Zaandam",
             "'s-Hertogenbosch", "Zwolle", "Leiden", "Maastricht", "Dordrecht", "Ede", "Alphen aan den Rijn",
             "Alkmaar", "Emmen", "Delft", "Venlo", "Deventer", "Helmond", "Oss", "Hilversum", "Heerlen", "Hengelo",
             "Purmerend", "Roosendaal", "Schiedam", "Leeuwarden", "Vlaardingen", "Almelo", "Lelystad", "Gouda",
             "Hoorn", "Assen", "Capelle aan den IJssel", "Veenendaal", "Bergen op Zoom", "Wageningen"]  # fmt: skip


def nl_postcode(rng: random.Random) -> str:
    letters = _until(rng, lambda: rng.choice(UPPER) + rng.choice(UPPER), lambda v: v not in ("SA", "SD", "SS"))
    return f"{rng.randint(1011, 9999)}{rng.choice([' ', ' ', ''])}{letters}"


def nl_house_number(rng: random.Random) -> str:
    n = str(rng.randint(1, 250))
    return rng.choice([n, n, n, n + rng.choice("abcd"), f"{n}-{rng.randint(1, 3)}", f"{n} {rng.choice(['A', 'B', 'hs', 'II'])}",
                       f"{n}bis"])  # fmt: skip


def nl_name(rng: random.Random, inverted: bool = False) -> str:
    """A Dutch name as written in running text: "Jan de Vries", "J.P. de Vries". ``inverted``: also as registers and
    forms list people, surname first with its particles last ("Vries, Jan de")."""
    first, last = rng.choice(NL_FIRST), rng.choice(NL_LAST)
    style = rng.random()
    if style < 0.65 or (style >= 0.85 and not inverted):
        return f"{first} {last}"
    if style < 0.85:
        initials = "".join(f"{c}." for c in rng.sample("ABCDEFGHJKLMNPRSTW", rng.choice([1, 2])))
        return f"{initials} {last}"
    if " " not in last:
        return f"{last}, {first}"
    *particles, surname = last.split(" ")
    return f"{surname}, {first} {' '.join(particles)}"


# --------------------------------------------------------------------------- the United States
def us_ssn(rng: random.Random) -> str:
    area = _until(rng, lambda: f"{rng.randint(1, 899):03d}", lambda v: v != "666")
    v = f"{area}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"
    return rng.choice([v, v, v, v.replace("-", " "), v.replace("-", "")])


def us_ssn_last4(rng: random.Random) -> str:
    return f"{rng.randint(1, 9999):04d}"


def us_itin(rng: random.Random) -> str:
    group = rng.choice(list(range(50, 66)) + list(range(70, 89)) + [90, 91, 92] + list(range(94, 100)))
    return f"9{rng.randint(0, 99):02d}-{group}-{rng.randint(0, 9999):04d}"


def us_atin(rng: random.Random) -> str:
    return f"9{rng.randint(0, 99):02d}-93-{rng.randint(0, 9999):04d}"


_EIN_PREFIXES = [1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 34,
                 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                 61, 62, 63, 64, 65, 66, 67, 68, 71, 72, 73, 74, 75, 76, 77, 80, 81, 82, 83, 84, 85, 86, 87, 88, 90,
                 91, 92, 93, 94, 95, 98, 99]  # fmt: skip


def us_ein(rng: random.Random) -> str:
    return f"{rng.choice(_EIN_PREFIXES):02d}-{rng.randint(0, 9999999):07d}"


def us_ptin(rng: random.Random) -> str:
    return rng.choice(["P", "P", "P-"]) + _digits(rng, 8, "0")


def us_passport(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 9, "12345"), rng.choice("ACDEFGHJKLMNPRSTUVWXYZ") + _digits(rng, 8, DIGITS)])


def us_passport_card(rng: random.Random) -> str:
    return "C" + _digits(rng, 8, "0123456789")


_DL_FORMATS = {
    "CA": lambda r: r.choice(UPPER) + _digits(r, 7, DIGITS),
    "NY": lambda r: _group(_digits(r, 9), (3, 3, 3)),
    "TX": lambda r: _digits(r, 8, "0123"),
    "FL": lambda r: (
        f"{r.choice(UPPER)}{_digits(r, 3, DIGITS)}-{_digits(r, 3, DIGITS)}-{_digits(r, 2, DIGITS)}-{_digits(r, 3, DIGITS)}-0"
    ),
    "IL": lambda r: f"{r.choice(UPPER)}{_digits(r, 3, DIGITS)}-{_digits(r, 4, DIGITS)}-{_digits(r, 4, DIGITS)}",
    "PA": lambda r: _group(_digits(r, 8), (2, 3, 3)),
    "WA": lambda r: "WDL" + "".join(r.choice(UPPER + DIGITS) for _ in range(9)),
    "NJ": lambda r: r.choice(UPPER) + _digits(r, 14, DIGITS),
    "OH": lambda r: "".join(r.choice(UPPER) for _ in range(2)) + _digits(r, 6, DIGITS),
    "MA": lambda r: "S" + _digits(r, 8, DIGITS),
    "MI": lambda r: r.choice(UPPER) + " " + _group(_digits(r, 12, DIGITS), (3, 3, 3, 3)),
    "GA": lambda r: _digits(r, 9, "0"),
}


def us_driver_license(rng: random.Random) -> str:
    return _DL_FORMATS[rng.choice(sorted(_DL_FORMATS))](rng)


_MBI_LETTERS = "ACDEFGHJKMNPQRTUVWXY"


def us_mbi(rng: random.Random) -> str:
    def a() -> str:
        return rng.choice(_MBI_LETTERS)

    def an() -> str:
        return rng.choice(_MBI_LETTERS + DIGITS)

    def n() -> str:
        return rng.choice(DIGITS)

    v = rng.choice("123456789") + a() + an() + n() + a() + an() + n() + a() + a() + n() + n()
    return rng.choice([v, v, f"{v[:4]}-{v[4:7]}-{v[7:]}"])


def us_npi(rng: random.Random) -> str:
    return _until(rng, lambda: rng.choice("12") + _digits(rng, 9, DIGITS), lambda v: luhn.is_valid("80840" + v))


def us_dea(rng: random.Random) -> str:
    first = rng.choice("ABCDEFGHJKLMPRSTUX")
    second = rng.choice(UPPER + "9")
    d = [rng.randrange(10) for _ in range(6)]
    check = (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10
    return first + second + "".join(map(str, d)) + str(check)


def us_routing(rng: random.Random) -> str:
    def ok(v: str) -> bool:
        w = (3, 7, 1) * 3
        return sum(int(c) * x for c, x in zip(v, w, strict=True)) % 10 == 0

    return _until(rng, lambda: rng.choice(["0", "1", "2", "3"]) + _digits(rng, 8, DIGITS), ok)


def us_bank_account(rng: random.Random) -> str:
    return _digits(rng, rng.choice([8, 9, 10, 11, 12]))


def credit_card(rng: random.Random) -> str:
    brand = rng.choice(["visa", "mc", "amex", "discover"])
    if brand == "amex":
        body = rng.choice(["34", "37"]) + _digits(rng, 12, DIGITS)
        num = body + luhn.calc_check_digit(body)
        return rng.choice([num, f"{num[:4]} {num[4:10]} {num[10:]}", f"{num[:4]}-{num[4:10]}-{num[10:]}"])
    prefix = {"visa": "4", "mc": rng.choice(["51", "52", "53", "54", "55"]), "discover": "6011"}[brand]
    body = prefix + _digits(rng, 15 - len(prefix), DIGITS)
    num = body + luhn.calc_check_digit(body)
    return rng.choice([num, _group(num, (4, 4, 4, 4)), _group(num, (4, 4, 4, 4), "-")])


def us_cvv(rng: random.Random) -> str:
    return _digits(rng, 3, DIGITS)


_US_AREAS = ["212", "312", "415", "617", "713", "206", "305", "404", "503", "602", "702", "801", "919", "214",
             "512", "646", "718", "773", "858", "971", "202", "303", "480", "612", "704", "813", "908", "347"]  # fmt: skip


def us_phone(rng: random.Random) -> str:
    def make() -> str:
        return rng.choice(_US_AREAS) + rng.choice("23456789") + _digits(rng, 2, DIGITS) + _digits(rng, 4, DIGITS)

    raw = _until(rng, make, lambda v: phonenumbers.is_valid_number(phonenumbers.parse(v, "US")) and v[3:6] != "555")
    a, b, c = raw[:3], raw[3:6], raw[6:]
    return rng.choice([f"({a}) {b}-{c}", f"{a}-{b}-{c}", f"{a}.{b}.{c}", f"+1 {a} {b} {c}", f"+1 ({a}) {b}-{c}",
                       f"1-{a}-{b}-{c}", f"{a} {b} {c}"])  # fmt: skip


US_FIRST = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth",
            "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Christopher",
            "Karen", "Daniel", "Lisa", "Matthew", "Nancy", "Anthony", "Betty", "Mark", "Sandra", "Donald",
            "Ashley", "Steven", "Kimberly", "Andrew", "Emily", "Joshua", "Donna", "Kevin", "Michelle", "Brian",
            "Carol", "DeShawn", "Maria", "Jose", "Luis", "Mei", "Wei", "Aisha", "Tyrone", "Keisha", "Raj"]  # fmt: skip
US_LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
           "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
           "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
           "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
           "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Okafor", "O'Brien",
           "McAllister", "Washington", "Kowalski"]  # fmt: skip
US_STREETS = ["Main St", "Oak Street", "Maple Avenue", "Cedar Lane", "Elm Street", "Pine Road", "Washington Blvd",
              "Lake Drive", "Hillcrest Drive", "Sunset Boulevard", "Park Avenue", "Willow Creek Road",
              "Jefferson Street", "Lincoln Avenue", "Madison Ave", "Highland Avenue", "Riverside Drive",
              "Peachtree St NE", "W 42nd Street", "N Michigan Ave", "Spring Valley Rd", "Old Mill Road",
              "Chestnut St", "Magnolia Drive", "Brookside Lane", "Forest Hills Drive", "Meadow Lane"]  # fmt: skip
US_PLACES = [("Springfield", "IL", "627"), ("Austin", "TX", "787"), ("Portland", "OR", "972"),
             ("Columbus", "OH", "432"), ("Denver", "CO", "802"), ("Atlanta", "GA", "303"), ("Seattle", "WA", "981"),
             ("Phoenix", "AZ", "850"), ("Boston", "MA", "021"), ("Nashville", "TN", "372"),
             ("Raleigh", "NC", "276"), ("Madison", "WI", "537"), ("Fresno", "CA", "937"), ("Tampa", "FL", "336"),
             ("Albany", "NY", "122"), ("Omaha", "NE", "681"), ("Richmond", "VA", "232"), ("Boise", "ID", "837"),
             ("Burlington", "VT", "054"), ("Santa Fe", "NM", "875")]  # fmt: skip


def us_zip(rng: random.Random, prefix: str | None = None) -> str:
    base = (prefix or _digits(rng, 3, "123456789")) + _digits(rng, 2, DIGITS)
    return base if rng.random() < 0.7 else f"{base}-{_digits(rng, 4, DIGITS)}"


def us_name(rng: random.Random) -> str:
    first, last = rng.choice(US_FIRST), rng.choice(US_LAST)
    style = rng.random()
    if style < 0.6:
        return f"{first} {last}"
    if style < 0.8:
        return f"{first} {rng.choice('ABCDEFGHJKLMNPRSTW')}. {last}"
    return f"{last}, {first}"


def us_a_number(rng: random.Random) -> str:
    d = _digits(rng, 9, "0123")
    return rng.choice([f"A{d}", f"A-{d[:3]}-{d[3:6]}-{d[6:]}", f"A# {d}", f"A{d[1:]}"])


def us_uscis_receipt(rng: random.Random) -> str:
    center = rng.choice(["EAC", "WAC", "LIN", "SRC", "NBC", "MSC", "IOE", "YSC", "TSC", "VSC", "NSC", "CSC"])
    d = f"{rng.randint(19, 26)}{_digits(rng, 8, DIGITS)}"
    return rng.choice([center + d, f"{center}-{d[:2]}-{d[2:5]}-{d[5:]}", f"{center} {d[:2]} {d[2:5]} {d[5:]}"])


def us_i94(rng: random.Random) -> str:
    return _digits(rng, 11)


def us_dod_id(rng: random.Random) -> str:
    return _digits(rng, 10, "1")


def us_va_file(rng: random.Random) -> str:
    return rng.choice(["C" + _digits(rng, 8, DIGITS), _digits(rng, 8), _digits(rng, 9)])


def us_mrn(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 8, "0123"), "MRN" + _digits(rng, 7, DIGITS), _digits(rng, 10)])


def us_member_id(rng: random.Random) -> str:
    return rng.choice(["".join(rng.choice(UPPER) for _ in range(3)) + _digits(rng, 9, DIGITS),
                       "W" + _digits(rng, 9, DIGITS), _digits(rng, 11)])  # fmt: skip


def us_group_number(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 5), _digits(rng, 6), "GRP-" + _digits(rng, 5)])


def us_medicaid(rng: random.Random) -> str:
    return rng.choice(["".join(rng.choice(UPPER) for _ in range(2)) + _digits(rng, 5, DIGITS) + rng.choice(UPPER),
                       _digits(rng, 10), _digits(rng, 12)])  # fmt: skip


def us_plate(rng: random.Random) -> str:
    return rng.choice([f"{rng.randint(1, 9)}{''.join(rng.choice(UPPER) for _ in range(3))}{_digits(rng, 3, DIGITS)}",
                       f"{''.join(rng.choice(UPPER) for _ in range(3))}-{_digits(rng, 4, DIGITS)}",
                       f"{''.join(rng.choice(UPPER) for _ in range(3))} {_digits(rng, 3, DIGITS)}"])  # fmt: skip


_VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"


def vin(rng: random.Random) -> str:
    values = {**{str(d): d for d in range(10)}, **dict(zip("ABCDEFGH", range(1, 9), strict=True)),
              **dict(zip("JKLMNPR", (1, 2, 3, 4, 5, 7, 9), strict=True)), **dict(zip("STUVWXYZ", range(2, 10), strict=True))}  # fmt: skip
    weights = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
    body = [rng.choice(_VIN_CHARS) for _ in range(17)]
    total = sum(values[c] * w for c, w in zip(body, weights, strict=True))
    body[8] = "X" if total % 11 == 10 else str(total % 11)
    return "".join(body)


def us_rx(rng: random.Random) -> str:
    return _digits(rng, 7)


def us_student_id(rng: random.Random) -> str:
    return rng.choice([_digits(rng, 9), "U" + _digits(rng, 8, DIGITS)])


def us_employee_id(rng: random.Random) -> str:
    return rng.choice(["E" + _digits(rng, 6, DIGITS), _digits(rng, 6), "EMP-" + _digits(rng, 5)])


# --------------------------------------------------------------------------- the European Union
EU_VAT_COUNTRIES = ["de", "fr", "be", "it", "es", "at", "pl", "pt", "ie", "se", "dk", "fi", "lu", "cz"]


def eu_vat(rng: random.Random, country: str | None = None) -> str:
    cc = country or rng.choice(EU_VAT_COUNTRIES)
    lengths = {"de": 9, "fr": 11, "be": 10, "it": 11, "es": 9, "at": 9, "pl": 10, "pt": 9, "ie": 8, "se": 12,
               "dk": 8, "fi": 8, "lu": 8, "cz": 9}  # fmt: skip
    prefix = {"at": "U", "be": "0", "ie": "", "es": ""}.get(cc, "")

    def make() -> str:
        n = lengths[cc] - len(prefix)
        if cc == "es":
            return "ES" + rng.choice("ABCDEFGHJ") + _digits(rng, 7, DIGITS) + rng.choice(DIGITS)
        if cc == "ie":
            return "IE" + _digits(rng, 7, DIGITS) + rng.choice("ABCDEFGHIJKLMNOPQRSTUVW")
        if cc == "se":
            return "SE" + _digits(rng, 10, DIGITS) + "01"
        return cc.upper() + prefix + _digits(rng, n, DIGITS)

    value = _until(rng, make, _stdnum_ok("eu.vat"))
    return rng.choice([value, value, value[:2] + " " + value[2:]])


def eu_iban(rng: random.Random) -> str:
    country, bank, length = rng.choice([("DE", "37040044", 10), ("FR", "2004101005", 13), ("BE", "310", 9),
                                        ("ES", "21000418", 12), ("IT", "X0542811101", 12), ("AT", "19043", 11),
                                        ("PL", "10901014", 16), ("PT", "00020123", 13), ("IE", "AIBK931152", 8),
                                        ("LU", "001", 13)])  # fmt: skip

    def make() -> str:
        body = bank + _digits(rng, length, DIGITS)
        if country == "BE":  # the account's own check: its first ten digits modulo 97
            body = body[:10] + f"{int(body[:10]) % 97 or 97:02d}"
        return country + std_iban.calc_check_digits(country + "00" + body) + body

    value = _until(rng, make, std_iban.is_valid)
    return rng.choice([value, _group(value, (4,) * 9)])


EU_BICS = ["DEUTDEFF", "COBADEFFXXX", "BNPAFRPP", "INGBNL2A", "ABNANL2A", "RABONL2U", "KREDBEBB", "GEBABEBB",
           "BBVAESMM", "CAIXESBBXXX", "UNCRITMM", "BCITITMM", "BKAUATWW", "PKOPPLPW", "CGDIPTPL", "AIBKIE2D",
           "BCEELULL", "SWEDSESS", "DABADKKK", "NDEAFIHH"]  # fmt: skip


def eu_bic(rng: random.Random) -> str:
    return rng.choice(EU_BICS)


def eu_eori(rng: random.Random) -> str:
    cc = rng.choice(["NL", "DE", "FR", "BE", "IT", "ES"])
    return cc + _digits(rng, {"NL": 9, "DE": 13, "FR": 14, "BE": 10, "IT": 11, "ES": 9}[cc], DIGITS)


def eu_ehic(rng: random.Random) -> str:
    return "80" + rng.choice(["528", "276", "250", "056", "380", "724"]) + _digits(rng, 15, DIGITS)


def _mrz_check(field: str) -> str:
    values = {**{str(d): d for d in range(10)}, **{c: i + 10 for i, c in enumerate(UPPER)}, "<": 0}
    return str(sum(values[c] * (7, 3, 1)[i % 3] for i, c in enumerate(field)) % 10)


def eu_mrz(rng: random.Random) -> str:
    """A TD3 passport machine-readable zone (two lines of 44), with valid check digits."""
    state = rng.choice(["NLD", "DEU", "FRA", "BEL", "ESP", "ITA"])
    surname = rng.choice(["DE<VRIES", "JANSEN", "MUELLER", "DUBOIS", "GARCIA<LOPEZ", "ROSSI", "PEETERS"])
    given = rng.choice(["ANNA<MARIA", "PIETER", "LUCAS", "SOPHIE", "MATEO", "GIULIA"])
    line1 = f"P<{state}{surname}<<{given}".ljust(44, "<")[:44]
    number = "".join(rng.choice(UPPER + DIGITS) for _ in range(9))
    birth = f"{rng.randint(50, 99):02d}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"
    expiry = f"{rng.randint(27, 34):02d}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"
    personal = "<" * 14
    line2 = (number + _mrz_check(number) + state + birth + _mrz_check(birth) + rng.choice("MF") + expiry
             + _mrz_check(expiry) + personal + _mrz_check(personal))  # fmt: skip
    composite = line2[0:10] + line2[13:20] + line2[21:43]
    return line1 + "\n" + line2 + _mrz_check(composite)


def eu_uvci(rng: random.Random) -> str:
    cc = rng.choice(["NL", "DE", "FR", "BE"])
    return f"URN:UVCI:01:{cc}:{''.join(rng.choice(UPPER + DIGITS) for _ in range(12))}#{rng.choice(UPPER + DIGITS)}"


_EU_PHONES = {"FR": ("+33", "1", 8), "BE": ("+32", "2", 7), "DE": ("+49", "30", 8), "ES": ("+34", "91", 7),
              "IT": ("+39", "06", 8), "AT": ("+43", "1", 7), "PL": ("+48", "22", 7), "PT": ("+351", "21", 7),
              "IE": ("+353", "1", 7), "SE": ("+46", "8", 7), "DK": ("+45", "3", 7)}  # fmt: skip


def eu_phone(rng: random.Random) -> str:
    region = rng.choice(sorted(_EU_PHONES))
    cc, area, n = _EU_PHONES[region]

    def make() -> str:
        return cc + area + _digits(rng, n, "2345678")

    raw = _until(rng, make, lambda v: phonenumbers.is_valid_number(phonenumbers.parse(v)))
    return phonenumbers.format_number(phonenumbers.parse(raw), phonenumbers.PhoneNumberFormat.INTERNATIONAL)


EU_ADDRESSES = {
    "de": (
        [
            "Hauptstraße",
            "Bahnhofstraße",
            "Gartenstraße",
            "Schillerstraße",
            "Goethestraße",
            "Lindenallee",
            "Am Markt",
            "Kirchweg",
        ],
        ["10115 Berlin", "80331 München", "20095 Hamburg", "50667 Köln", "60311 Frankfurt am Main", "70173 Stuttgart"],
        "{street} {num}",
    ),
    "fr": (
        ["rue de la Paix", "avenue Victor Hugo", "boulevard Saint-Michel", "rue des Lilas", "place de la République"],
        ["75008 Paris", "69002 Lyon", "13001 Marseille", "31000 Toulouse", "33000 Bordeaux"],
        "{num} {street}",
    ),
    "es": (
        ["Calle Mayor", "Avenida de la Constitución", "Calle de Alcalá", "Paseo de Gracia", "Calle Real"],
        ["28013 Madrid", "08008 Barcelona", "41004 Sevilla", "46002 Valencia"],
        "{street} {num}",
    ),
    "it": (
        ["Via Roma", "Corso Vittorio Emanuele", "Via Garibaldi", "Piazza Navona", "Via dei Mille"],
        ["00184 Roma", "20121 Milano", "50123 Firenze", "80133 Napoli"],
        "{street} {num}",
    ),
    "be": (
        ["Rue Neuve", "Meir", "Kerkstraat", "Avenue Louise", "Grote Markt"],
        ["1000 Bruxelles", "2000 Antwerpen", "9000 Gent", "4000 Liège"],
        "{street} {num}",
    ),
    "pl": (
        ["ul. Marszałkowska", "ul. Floriańska", "al. Jerozolimskie", "ul. Długa"],
        ["00-950 Warszawa", "31-019 Kraków", "80-831 Gdańsk"],
        "{street} {num}",
    ),
    "at": (
        ["Mariahilfer Straße", "Kärntner Straße", "Getreidegasse", "Landstraßer Hauptstraße"],
        ["1070 Wien", "5020 Salzburg", "8010 Graz"],
        "{street} {num}",
    ),
    "pt": (
        ["Rua Augusta", "Avenida da Liberdade", "Rua de Santa Catarina"],
        ["1100-053 Lisboa", "4000-447 Porto"],
        "{street}, {num}",
    ),
}


def eu_address(rng: random.Random, country: str | None = None) -> tuple[str, str]:
    cc = country or rng.choice(sorted(EU_ADDRESSES))
    streets, towns, fmt = EU_ADDRESSES[cc]
    return fmt.format(street=rng.choice(streets), num=rng.randint(1, 180)), rng.choice(towns)


EU_NAMES = {
    "de": (["Lukas", "Hannah", "Jürgen", "Katrin", "Maximilian", "Lea"], ["Müller", "Schneider", "Becker", "Hoffmann", "Weber"]),
    "fr": (["Élodie", "Mathieu", "Camille", "Théo", "Chloé"], ["Martin", "Lefèvre", "Dubois", "Moreau", "Girard"]),
    "es": (["Lucía", "Mateo", "Carmen", "Iker", "Sofía"], ["García", "Fernández", "López", "Martínez", "Sánchez"]),
    "it": (["Giulia", "Marco", "Francesca", "Alessandro"], ["Rossi", "Bianchi", "Romano", "Colombo", "Ricci"]),
    "pl": (["Zofia", "Jakub", "Katarzyna", "Piotr"], ["Kowalska", "Nowak", "Wiśniewski", "Wójcik"]),
    "pt": (["Inês", "João", "Beatriz", "Tiago"], ["Silva", "Santos", "Ferreira", "Pereira"]),
    "be": (["Lotte", "Arthur", "Louise", "Wout"], ["Peeters", "Janssens", "Maes", "Jacobs"]),
    "at": (["Florian", "Johanna", "Tobias"], ["Gruber", "Huber", "Bauer", "Wagner"]),
}  # fmt: skip


def eu_name(rng: random.Random, country: str | None = None) -> str:
    cc = country or rng.choice(sorted(EU_NAMES))
    first, last = EU_NAMES[cc]
    return f"{rng.choice(first)} {rng.choice(last)}"


def _national(module: str, make: Callable[[random.Random], str]) -> Gen:
    ok = _stdnum_ok(module)
    return lambda rng: _until(rng, lambda: make(rng), ok)


def _date_digits(rng: random.Random) -> tuple[int, int, int]:
    return rng.randint(1940, 2004), rng.randint(1, 12), rng.randint(1, 28)


def _pesel(rng: random.Random) -> str:
    y, m, d = _date_digits(rng)
    return f"{y % 100:02d}{m + (20 if y >= 2000 else 0):02d}{d:02d}" + _digits(rng, 5, DIGITS)


def _personnummer(rng: random.Random) -> str:
    y, m, d = _date_digits(rng)
    return f"{y % 100:02d}{m:02d}{d:02d}-" + _digits(rng, 4, DIGITS)


def _hetu(rng: random.Random) -> str:
    y, m, d = _date_digits(rng)
    return f"{d:02d}{m:02d}{y % 100:02d}{'-' if y < 2000 else 'A'}{_digits(rng, 3, DIGITS)}" + rng.choice(
        "0123456789ABCDEFHJKLMNPRSTUVWXY"
    )


def _cpr(rng: random.Random) -> str:
    y, m, d = _date_digits(rng)
    return f"{d:02d}{m:02d}{y % 100:02d}-" + _digits(rng, 4, DIGITS)


def _nir(rng: random.Random) -> str:
    y, m, _d = _date_digits(rng)
    body = f"{rng.choice('12')}{y % 100:02d}{m:02d}{rng.choice(['75', '69', '13', '33'])}{_digits(rng, 3, DIGITS)}{_digits(rng, 3, DIGITS)}"
    key = 97 - int(body) % 97
    return f"{body[0]} {body[1:3]} {body[3:5]} {body[5:7]} {body[7:10]} {body[10:13]} {key:02d}"


def _dni(rng: random.Random) -> str:
    n = rng.randint(10000000, 99999999)
    return f"{n}{'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23]}"


def _cnp(rng: random.Random) -> str:
    y, m, d = _date_digits(rng)
    return (
        f"{rng.choice('12') if y < 2000 else rng.choice('56')}{y % 100:02d}{m:02d}{d:02d}{rng.randint(1, 46):02d}{_digits(rng, 3, DIGITS)}"
        + rng.choice(DIGITS)
    )


EU_NATIONAL: dict[str, tuple[str, Gen]] = {
    "pl.pesel": ("PESEL", _national("pl.pesel", _pesel)),
    "se.personnummer": ("personnummer", _national("se.personnummer", _personnummer)),
    "fi.hetu": ("henkilötunnus", _national("fi.hetu", _hetu)),
    "dk.cpr": ("CPR-nummer", _national("dk.cpr", _cpr)),
    "fr.nir": ("numéro de sécurité sociale", _national("fr.nir", _nir)),
    "es.dni": ("DNI", _national("es.dni", _dni)),
    "ro.cnp": ("CNP", _national("ro.cnp", _cnp)),
    "pt.nif": ("NIF", _national("pt.nif", lambda r: r.choice("123") + _digits(r, 8, DIGITS))),
    "ie.pps": ("PPS number", _national("ie.pps", lambda r: _digits(r, 7, DIGITS) + r.choice(UPPER[:23]) + r.choice(["", "A", "W"]))),
    "be.nn": ("rijksregisternummer", _national("be.nn", lambda r: f"{r.randint(40, 99):02d}{r.randint(1, 12):02d}{r.randint(1, 28):02d}{_digits(r, 3, DIGITS)}{_digits(r, 2, DIGITS)}")),
    "de.idnr": ("Steuer-ID", _national("de.idnr", lambda r: _digits(r, 11))),
    "it.codicefiscale": ("codice fiscale", lambda r: _until(r, lambda: "RSSMRA" + f"{r.randint(40, 99):02d}" + r.choice("ABCDEHLMPRST") + f"{r.randint(1, 28):02d}" + r.choice(["H501", "F205", "D612", "A944"]) + r.choice(UPPER), _stdnum_ok("it.codicefiscale"))),
    "at.vnr": ("Sozialversicherungsnummer", _national("at.vnr", lambda r: _digits(r, 3, "123456789") + _digits(r, 1, DIGITS) + f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{r.randint(40, 99):02d}")),
    "cz.rc": ("rodné číslo", _national("cz.rc", lambda r: f"{r.randint(54, 99):02d}{r.choice([r.randint(1, 12), r.randint(51, 62)]):02d}{r.randint(1, 28):02d}/{_digits(r, 4, DIGITS)}")),
    "gr.amka": ("ΑΜΚΑ", _national("gr.amka", lambda r: f"{r.randint(1, 28):02d}{r.randint(1, 12):02d}{r.randint(40, 99):02d}" + _digits(r, 5, DIGITS))),
}  # fmt: skip


def eu_plate(rng: random.Random) -> tuple[str, str]:
    cc = rng.choice(["de", "fr", "es", "it", "be", "pl"])
    letters = "ABCDEFGHJKLMNPRSTVWXYZ"
    value = {
        "de": f"{rng.choice(['B', 'M', 'HH', 'K', 'F', 'S'])}-{''.join(rng.choice(letters) for _ in range(2))} {rng.randint(1, 9999)}",
        "fr": f"{''.join(rng.choice(letters) for _ in range(2))}-{_digits(rng, 3, DIGITS)}-{''.join(rng.choice(letters) for _ in range(2))}",
        "es": f"{_digits(rng, 4, DIGITS)} {''.join(rng.choice('BCDFGHJKLMNPRSTVWXYZ') for _ in range(3))}",
        "it": f"{''.join(rng.choice(letters) for _ in range(2))} {_digits(rng, 3, DIGITS)} {''.join(rng.choice(letters) for _ in range(2))}",
        "be": f"{rng.randint(1, 2)}-{''.join(rng.choice(letters) for _ in range(3))}-{_digits(rng, 3, DIGITS)}",
        "pl": f"W{rng.choice('AXYZ')} {_digits(rng, 5, DIGITS)}",
    }[cc]  # fmt: skip
    return cc, value
