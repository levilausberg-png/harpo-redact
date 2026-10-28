"""Which language a text is in, cheaply enough to run on every NER chunk.

A vote of common function words. Each language needs at least two hits and a clear lead over the
runner-up, otherwise the answer is "und" (undetermined) and callers keep their default behaviour.
Short or mixed texts are therefore mostly "und": that is the safe answer, not an error.
"""

from __future__ import annotations

import re

_WORD_RE = re.compile(r"[^\W\d_]+")
_STOPWORDS: dict[str, frozenset[str]] = {
    lang: frozenset(words.split())
    for lang, words in {
        "en": "the and of to is was for that with this you are have not be it on as at by from they we will "
              "would there their what which please thanks your our about",
        "nl": "het een van en dat niet is zijn voor met op aan ook als maar wordt worden bij naar dit deze "
              "wil je jij u uw kunt hebben heeft wat bedankt graag stond notities",
        "de": "der die das und ist nicht ein eine einen zu den dem mit sich auf für von im auch es bitte danke "
              "wir sie ihr sind wird werden haben hat stand oder aber wenn",
        "fr": "le la les et des est une un du que qui à pas pour dans sur au aux ce cette avec il elle nous vous "
              "merci sont été être avoir ont figurait",
        "es": "el la los las y es un una que del por para con no se al lo como pero su sus este esta gracias "
              "son fue ser hay pide revise aparecía",
    }.items()
}  # fmt: skip


def detect_language(text: str, *, sample_chars: int = 4_000) -> str:
    """ "en", "nl", "de", "fr", "es"; "xx" for text mostly in a non-Latin script; "und" when unsure."""
    sample = text[:sample_chars]
    letters = [c for c in sample if c.isalpha()]
    if len(letters) >= 8 and sum(c.isascii() or "\u00c0" <= c <= "\u024f" for c in letters) < len(letters) / 2:
        return "xx"
    votes = dict.fromkeys(_STOPWORDS, 0)
    for word in _WORD_RE.findall(sample.casefold()):
        for lang, words in _STOPWORDS.items():
            if word in words:
                votes[lang] += 1
    ranked = sorted(votes.items(), key=lambda kv: kv[1], reverse=True)
    (best, top), (_, second) = ranked[0], ranked[1]
    if top >= 2 and top >= 1.5 * second + 1:
        return best
    return "und"
