"""Layer 2h: opaque codes, values that no language writes.

People write words, names and the identifiers of code; a generator writes "FXJPIUZXKH" and "BfnMnQaGjPdc". Such a
value standing in a sentence was given to someone: a licence or card number, a booking or voucher code, a password.
Two signs tell it from what people write, both read in one pass over its letters:

* letter pairs. Words in the languages Harpo reads are built from about 470 of the 676 pairs of Latin letters (the
  pairs of the BIP39 English word list and of a sample of words in twenty more languages and transliterations); a
  generator draws one of the others every third pair or so ("fx", "jp", "qw", "zx"). Four or more consonants in a row
  count as well ("WRDYDW").
* case. A word or an identifier changes case where one of its parts starts ("getElementById", "XMLHttpRequest",
  "McDonald"); a generator also leaves single small letters between capitals ("DVSqTIIx").

``opacity`` adds these signs up. Capitals with at most a few digits are an identifier (ACCOUNT_ID); random letters in
both cases a password (SECRET). After a cue word (cued.py) or a password word (statements.py) a value needs fewer
signs: the words before it already say what it is.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache
from importlib import resources
from itertools import pairwise

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "opaque"

# Words in other languages and transliterations, for the letter pairs their names, places and words use ("ij", "sz",
# "ngw", "zh"): a value made of those pairs is not opaque.
_MORE_WORDS = """
rijbewijs nieuw huis deur boek school nacht dwars zwart kwaliteit vertrouwelijk wachtwoord ijssel gezellig schip
strijd vrijdag woensdag donderdag zaterdag zondag januari februari maart augustus oktober geboortedatum handtekening
burgerservicenummer straat gemeente woonplaats verzekering aanvraag gegevens bedrijf uitkering huurtoeslag
apfel zwei katze strasse schweiz deutschland personalausweis fuehrerschein kennwort geheim achtung zeitung pflicht
knecht verwaltung schluessel versicherung anschrift geburtsdatum ausweis steuer nummer konto zwoelf pfund
chateau oiseau quatre gagner champagne mademoiselle bureau renseignements identite permis conduire numero oeuvre
nacionalidad espana ciudad direccion contrasena pasaporte licencia nino senor cuenta banco llave guerra
gnocchi famiglia ragazzo azzurro scienza codice fiscale patente carta identita sciopero
coracao irmao cidade endereco senha documento
przez szczecin wrzesien chwila pierwszy dowod osobisty prawo jazdy numer kowalczyk wojciechowski krzysztof bydgoszcz
zprava vzor jmeno prijmeni obcansky prukaz cislo rodne mesto ulice vsechno skvely ctvrtek stvrtok
gyors nyolc szep zsak csak tyuk lyuk szemelyi igazolvany jogositvany
kirkko lahtea tytto hyvaa kiitos henkilotunnus ajokortti
skjorta fjord kvinna sjukskoterska tjugo personnummer
nguyen nghia thanh truong phuong khanh giang quoc uyen thuong duong huynh
zhang xiaoming qing zhou guangzhou shenzhen chongqing xian jiang huang zhao zheng ouyang xue qiu
tsunami kyoto ryokan shimbun chiba tokyo saitama fukuoka shinjuku
seoul yeouido busan jeju gyeonggi chungcheong daegu kkachi ttok ppang ssal jjigae
llanelli eisteddfod ffordd rhyl cwm
tchaikovsky khrushchev dostojevskij zdravstvuyte vladimir zhytomyr kharkiv
mohammed abdullah ahmad hussein khalid tbilisi ljubljana
mbeki ngozi nkosi kwame oluwaseun adebayo mthunzi mpho tshabalala
"""

_VOWELS = frozenset("aeiouy")
_PART_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")
_SWITCH_RE = re.compile(r"(?<=[A-Z])[a-z](?=[A-Z])")


@cache
def _pairs() -> frozenset[str]:
    words = resources.files("harpo_redact").joinpath("data/bip39-english.txt").read_text().split()
    words += _MORE_WORDS.split()
    return frozenset(w[i : i + 2] for w in words for i in range(len(w) - 1))


def opacity(value: str) -> int:
    """How many signs say that no one wrote ``value`` as a word: letter pairs words do not use, consonants past the
    third in a row, and small letters alone between capitals. Words and names score 0 to 2, generated codes 4 and up."""
    pairs = _pairs()
    score = len(_SWITCH_RE.findall(value))
    for part in _PART_RE.findall(value):
        s = part.lower()
        score += sum(s[i : i + 2] not in pairs for i in range(len(s) - 1))
        run = best = 0
        for ch in s:
            run = 0 if ch in _VOWELS else run + 1
            best = max(best, run)
        score += max(0, best - 3)
    return score


def _sequence(value: str) -> bool:
    """A test value or a mask, typed rather than given: "ABCDEFGH", "12345678", "QWERTYUI", "XXXXXXXX"."""
    low = value.lower()
    if len(set(low)) < 5:
        return True
    steps = sum(ord(b) - ord(a) == 1 for a, b in pairwise(low))
    return steps >= 4 or any(row in low for row in ("qwert", "asdfg", "zxcvb", "yxcvb", "azert", "qwertz"))


_HEX = frozenset("0123456789ABCDEF")


def opaque_capitals(value: str, *, cued: bool = False) -> bool:
    """A code in capitals, with at most three digits, that no language writes: "FXJPIUZXKH", "H5U8VOVWPQ". After a
    cue word ("licence number", "číslo") a little less is asked."""
    if not value.isascii() or not value.isalnum() or any(c.islower() for c in value):
        return False
    letters = sum(c.isalpha() for c in value)
    if letters < 6 or len(value) - letters > 3 or (not cued and len(value) < 8):
        return False
    if set(value) <= _HEX or _sequence(value):
        return False  # a hash or a colour in capitals, a mask, the alphabet
    return opacity(value) >= (3 if cued else 4)


_RUN_RE = re.compile(r"[A-Z]+|[a-z]+")


def random_letters(value: str, *, cued: bool = False) -> bool:
    """Letters in both cases that change case the way a password generator does: "BfnMnQaGjPdc", "DVSqTIIxXPUq"; not
    "getElementById", "McDonald" or "XMLHttpRequest". After a password word a little less is asked."""
    if not value.isascii() or not value.isalnum() or len(value) < 8:
        return False
    if not any(c.isupper() for c in value) or not any(c.islower() for c in value):
        return False
    if sum(c.isdigit() for c in value) > 2 or _sequence(value):
        return False
    score = opacity(value)
    if len(value) <= 16:
        score += max(0, len(_RUN_RE.findall(value)) - 5)  # a short value that changes case at every other letter
    return score >= (4 if cued else 6)


# A value standing alone: not part of a path, a URL, an e-mail address, an identifier with underscores, base64, or a
# key=value. Chinese, Japanese and Korean write no blank between a word and the Latin letters next to it
# ("请携带ZDFV9P6BTG或..."): their characters end a value as a blank does. Only a value with a capital after its first
# character can be a code (the rest are words, capitalised words and numbers), and the pattern asks for one at once.
_CJK = "\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
_TOKEN_RE = re.compile(
    rf"(?<![^\W{_CJK}]|[\-./@#$%&+=\\])(?=[A-Za-z0-9][a-z0-9]*[A-Z])[A-Za-z0-9]{{8,40}}"
    rf"(?![^\W{_CJK}]|[\-/@\\+=]|[.:][A-Za-z0-9])"
)
_PROSE_RE = re.compile(rf"[a-z]{{3}}|[{_CJK}]{{2}}")
_LINE_REACH = 200


def _in_prose(text: str, start: int, end: int) -> bool:
    """Small letters on the value's line, near it, or words in a script without capitals (Chinese, Japanese,
    Korean): a sentence, not a heading or a constant in capitals."""
    lo, hi = max(0, start - _LINE_REACH), min(len(text), end + _LINE_REACH)
    newline = text.rfind("\n", lo, start)
    lo = newline + 1 if newline >= 0 else lo
    newline = text.find("\n", end, hi)
    hi = newline if newline >= 0 else hi
    return _PROSE_RE.search(text, lo, hi) is not None


def find_opaque_codes(text: str) -> Iterator[Span]:
    """Opaque codes: capitals standing in a line of prose (an all-capital line is a heading or a constant, a quoted
    value is data that its key names), and random letters in both cases anywhere, a quoted salt or "pass: '...'"
    included. Base64 of readable text ("page_token": "eyJwYWdl...") is decoded and judged by what it says
    (secrets.find_encoded)."""
    from .secrets import is_encoded_text

    for m in _TOKEN_RE.finditer(text):
        start, end = m.span()
        value = m.group()
        if opaque_capitals(value):
            quoted = start > 0 and end < len(text) and text[start - 1] in "\"'`" and text[end] == text[start - 1]
            if not quoted and _in_prose(text, start, end):
                yield make_span(start, end, E.ACCOUNT_ID, f"{SOURCE}:code", value, 0.6)
        elif random_letters(value) and not is_encoded_text(value):
            yield make_span(start, end, E.SECRET, f"{SOURCE}:random-letters", value, 0.6)
