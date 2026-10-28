"""Layer 6: named-entity recognition with spaCy.

Only the tokenizer, ``tok2vec`` and ``ner`` components are loaded. Text is cut
into chunks of at most ``chunk_chars`` so memory stays bounded: spaCy needs
roughly 1 GB of working memory per 100k characters for full pipelines.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import os
import re
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Iterable, Mapping

from ..entities import EntityType, Span, make_span
from .addresses import _SUFFIX as _STREET_WORDS
from .language import detect_language
from .names import _ROLES, _STOP, DOCUMENT_WORDS, NAME_LABELS, strip_leading_cue

_EXCLUDE = ["parser", "tagger", "attribute_ruler", "lemmatizer", "morphologizer", "senter", "trainable_lemmatizer"]
_TRIM_CHARS = " \t\r\n.,;:!?\"'()[]{}<>“”‘’«»-–—"
_POSSESSIVE_RE = re.compile(r"(?:'s|’s|'|’)$")
_SPLIT_RE = re.compile(r"\n\s*\n|(?<=[.!?])\s+|\s+")
_CAMEL_RE = re.compile(r"[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+")
# snake_case identifiers: the model tags field names such as "date_of_birth" or "customer_id" as people and places.
_SNAKE_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
# Environment variables and constants ("DATABASE_PASSWORD", "OPENAI_API_KEY"): the model reads them as names, and
# coding agents send whole .env files. Mixed case ("Anna_de_Vries" in a file name) is still a name.
_SCREAMING_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
# Code: "std::env::set_var(", "Data.Text", "config[key]", "x = y". No name holds these; a dot inside a word
# ("Node.js", "Barnacle.Db") is a module or a host, while initials ("J.R.R. Tolkien") keep one letter per dot.
_CODE_SYNTAX_RE = re.compile(r"::|[(){}\[\]<>=;\"`\\|$]|\w\.\w{2,}")
_CAPS_RUN_RE = re.compile(r"(?<![^\W\d_])[^\W\d_a-zß]{2,}(?: [^\W\d_a-zß]{2,}){1,3}(?![^\W\d_])")

# --------------------------------------------------------------------------- what a name is not
# Small models tag the vocabulary of forms, logs and code as names, places and organisations: a field label
# ("Name", "Signature"), a role ("the Participant", "Sponsor"), a month ("Mar 15"), a time zone ("UTC"), a log level,
# a SQL or HTTP keyword ("SELECT", "LEFT JOIN", "POST"), a unit ("kB"). None of these is a name on its own, in any
# case, and redacting each one, and then every other place it occurs, buries a document in placeholders.
_FUNCTION_WORDS = frozenset(
    """the a an of and or for to in on at by with from as is are was were be into over under per via vs
    de het een der den des die das dem le la les l el los las lo du di del della dei da do dos das""".split()  # noqa: SIM905
)
_VOCABULARY = (
    frozenset(
        """feb mar apr jun jul aug sep sept oct nov dec mon tue tues wed thu thur thurs fri sat sun
    january february march april may june july august september october november december
    monday tuesday wednesday thursday friday saturday sunday
    utc gmt cet cest eet eest wet west bst ist est edt cst cdt mst mdt pst pdt akst akdt hst aest aedt acst awst
    jst kst nzst nzdt msk sgt hkt
    info warn warning error err debug trace fatal critical crit notice alert emerg verbose severe
    select from where join left right inner outer full cross on and or not null default insert into values update
    set delete create table index drop alter add primary key foreign references varchar char int integer bigint
    smallint text date datetime timestamp boolean bool float double decimal numeric serial order by group having
    limit offset desc asc distinct as in is like between case when then else end union all exists interval count
    sum avg min max unique constraint check view trigger procedure function returns begin commit rollback grant
    revoke schema database cascade truncate merge using natural
    get post put patch head options connect http https
    kb mb gb tb kib mib gib tib ms ns sec min hr hrs
    page section article clause schedule exhibit appendix annex figure form item items total subtotal amount
    number description status type notes comments information details summary signature address phone email
    enter submit complete required optional yes no none n/a
    invoice factuur rechnung facture fattura factura fatura quittung ricevuta recibo receipt kassabon order
    bestelling bestellung commande ordine pedido encomenda contract contrat contrato contratto vertrag overeenkomst
    agreement formulier formular formulaire modulo formulario application aanvraag antrag demande domanda solicitud
    request verzoek letter brief lettre lettera report rapport bericht verslag relazione informe statement
    afschrift kontoauszug relevé estratto extracto notice kennisgeving bescheid avis avviso aviso totaal summe
    gesamt montant importe importo valor netto bruto brutto net gross subtotaal zwischensumme bedrag betrag
    btw tva vat iva mwst ust gst hst nr no nº
    file files folder config configuration settings preferences usage namespace subsystem dashboard checkout
    deployment pipeline build release environment cluster node pod service server client endpoint module package
    library plugin template profile account accounts employer employee payee payer beneficiary sponsor university
    college school institute hospital clinic department ministry agency council committee board fund maker
    province state city county district region country sex gender birth age race ethnicity occupation
    nationality citizenship residence ii iii iv vi vii viii ix xi xii xiii xiv xv
    identification marital boxes box assessment assessments discharge medicare medicaid social security
    administration sessional cumulative timestamptz jsonb uuid bytea inet citext nvarchar tinyint longtext""".split()  # noqa: SIM905
    )
    | _STOP
    | frozenset(w for label in NAME_LABELS + tuple(_ROLES) for w in label.split())
)
_WORDS_RE = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)*")
# A word in running text, not a piece of an email address, a URL, a path, a file or a code name.
_PLAIN_WORD_RE = re.compile(r"(?<![\w.@/\\\-])[^\W\d_]+(?![\w@/\\\-]|\.\w)")


# A term a document defines for itself and then uses with "the": '("University")' ... "the University shall",
# '(the "Licensee")'. Contracts name roles this way; a name is not used with "the".
_DEFINED_RE = re.compile(
    r"\((?:the[ \t]+|hereinafter[ \t]+(?:referred[ \t]+to[ \t]+as[ \t]+)?(?:the[ \t]+)?)?[\"“”]"
    r"(?P<term>[A-Z][\w’'\-]{1,40}(?:[ \t][A-Z][\w’'\-]{1,40}){0,2})[\"“”]\)"
)
# An abbreviation a document spells out in lower case: "medical confinement facilities (MEDCONFAC)", "protected
# health information (PHI)". "World Health Organization (WHO)" is written with capitals and stays a name.
_ABBREVIATION_RE = re.compile(
    r"(?<![A-Za-z\-])(?P<phrase>(?:[a-z]{2,24}[ \-]){1,5}[a-z]{2,24})[ \t]*\((?P<abbr>[A-Z][A-Z0-9&]{1,14})\)"
)


def _abbreviates(phrase: str, abbr: str) -> bool:
    """Whether the letters of ``abbr`` appear in order in the end of ``phrase`` that starts with its first letter
    ("keeps protected health information (PHI)")."""
    words = phrase.replace("-", " ").split()
    for i, word in enumerate(words):
        if word[0] != abbr[0].lower():
            continue
        letters, pos = "".join(words[i:]), 0
        for ch in abbr.lower():
            if ch.isalpha():
                pos = letters.find(ch, pos)
                if pos < 0:
                    break
                pos += 1
        else:
            return True
    return False


def lowercase_words(text: str) -> frozenset[str]:
    """The words a text uses as common words: what it writes in lower case, the terms it defines for itself and uses
    with "the", and the abbreviations it spells out in lower case. A capitalised word that also appears in lower case
    ("Agreement" and "this agreement", "LOG" and "log rotation") is a common word written at the start of a line or as
    a heading, not a name: names keep their capital wherever they occur."""
    words = {w for w in _PLAIN_WORD_RE.findall(text) if w.islower()}
    if '"' in text or "“" in text:
        for m in _DEFINED_RE.finditer(text):
            term = m.group("term")
            if re.search(rf"(?<![\w])(?:the|The)[ \t]+{re.escape(term)}(?![\w])", text):
                words.update(w.casefold() for w in term.split())
    if "(" in text:
        for m in _ABBREVIATION_RE.finditer(text):
            if _abbreviates(m.group("phrase"), m.group("abbr")):
                words.add(m.group("abbr").casefold())
    return frozenset(words)


# A browser's user agent names software ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15
# (KHTML, like Gecko) Safari/605.1.15"): what a model tags inside one (Macintosh, KHTML, Gecko) is not a name.
_USER_AGENT_RE = re.compile(
    r"Mozilla/\d\.\d[ \t]?\([^()\n]{1,200}\)(?:[ \t]{1,3}[^\s\"'()]{1,80}(?:[ \t]?\([^()\n]{0,120}\))?){0,12}"
)


def software_ranges(text: str) -> list[tuple[int, int]]:
    """Where the text holds user agent strings."""
    return [m.span() for m in _USER_AGENT_RE.finditer(text)] if "Mozilla/" in text else []


_SAINT_BEFORE_RE = re.compile(r"(?<![\w.])(?:St|Ste|Sta|Mt|Ft|Pt)\.[ \t]$")


# A first name that is a verb at the start of an instruction: "Mark all that apply.", "// Mark as published".
_INSTRUCTION_NEXT = frozenset(
    "all the a an each every any one as this that these those here only if your it them yes no both either x".split()  # noqa: SIM905
)
_LINE_START_RE = re.compile(r"(?:^|[\n.!?]|//|#|\*|-|\d[.)])[ \t]*$")


def instruction_verb(text: str, start: int, end: int) -> bool:
    """A lone capitalised word that opens a sentence and is followed by a determiner: a verb, not a name."""
    if not _LINE_START_RE.search(text, max(0, start - 12), start):
        return False
    m = re.match(r"[ \t]+\(?([A-Za-z]+)\b", text[end : end + 16])
    return m is not None and m.group(1).casefold() in _INSTRUCTION_NEXT and (m.group(1).islower() or m.group(1) == "X")


# A setting in a log or config line: "PROTO=TCP", "IN=eth0", "user=anna".
_KEY_VALUE_RE = re.compile(r"(?<![\w.\-])[A-Za-z_][\w.\-]{0,30}=(?=[^\s=])")
_PARTICLE_WORDS = frozenset("van von de der den da di du del della le la ten ter bin ibn al dos das do op het".split())  # noqa: SIM905


def _code_name(surface: str) -> bool:
    """A name joined by underscores is a code name ("Last_errno", "user_Name") unless every part is a capitalised
    word or a particle: "Anna_de_Vries" in a file name is still a person."""
    if "_" not in surface:
        return False
    parts = [p for p in surface.replace(" ", "_").split("_") if p]
    return not all(p[0].isupper() or p.casefold() in _PARTICLE_WORDS for p in parts)


# A street word written after the name, in lower case ("Brīvības iela", "Petőfi utca", "Gedimino prospektas"): the
# model finds the name, the street word belongs to it.
# English street words are written with a capital, and in lower case most are everyday words ("close", "way").
_EVERYDAY = frozenset(
    """street road avenue lane boulevard terrace crescent close grove parade highway parkway court
    weg""".split()  # noqa: SIM905
)
_STREET_AFTER_RE = re.compile(
    r"[ \t]{1,2}(?:"
    + "|".join(sorted((w for w in _STREET_WORDS if len(w) >= 4 and w not in _EVERYDAY), key=len, reverse=True))
    + r")(?![^\W_])"
)


# A house number right after a place the model found, at the end of a clause: "naar Overtoom 194.", "Spui 21, ...".
_HOUSE_NUMBER_AFTER_RE = re.compile(
    r"[ \t](?!(?:19|20)\d\d(?!\d))\d{1,4}(?:[A-Za-z](?![A-Za-z])|[ \t]?(?:bis|hs)(?![A-Za-z]))?(?:[\-/]\d{1,4})?"
    r"(?:[ \t](?:I{1,3}|IV)(?![\w]))?(?=[ \t]*(?:[.,;)\n]|$))"
)


def _street_end(text: str, end: int) -> int:
    m = _STREET_AFTER_RE.match(text, end)
    return m.end() if m else end


def _house_number_end(text: str, end: int) -> int:
    m = _HOUSE_NUMBER_AFTER_RE.match(text, end)
    return m.end() if m else end


# US states and territories and the country codes written in running text: models read "FL" or "USA" as an
# organisation as often as a place. They are places, whatever the model said.
PLACE_CODES = frozenset(
    """AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR
    PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR GU VI AS MP USA U.S. U.S.A. UK U.K. UAE PRC""".split()  # noqa: SIM905
)


def _lowercase_full_name(words: list[str]) -> bool:
    """Two or more words, none a function, particle or vocabulary word: a person's full name written in lower case,
    the way someone hiding it would write it ("emily bennett was in the notes", "jeroen van dijk")."""
    content = [w for w in words if w.casefold() not in _FUNCTION_WORDS and w.casefold() not in _PARTICLE_WORDS]
    return len(content) >= 2 and all(w.isalpha() and len(w) >= 2 and w.casefold() not in _VOCABULARY for w in content)


_LEET_RE = re.compile(r"[^\W\d_][013457][^\W\d_]")


def _leetspeak(surface: str) -> bool:
    """A name in leetspeak ("El1f", "J0hn", "R4m4n"): digits for letters between letters, small letters around."""
    return any(c.islower() for c in surface) and _LEET_RE.search(surface) is not None


@functools.lru_cache(maxsize=2048)
def _settings_line(line: str) -> bool:
    """A line of settings: two or more "key=value" pairs ("IPTABLES DROP IN=eth0 OUT= PROTO=TCP")."""
    return len(_KEY_VALUE_RE.findall(line)) >= 2


def _document_title(content: list[str], words: list[str], line: str, *, person: bool, org: bool) -> bool:
    """A document's title read as a name: a person or a place that opens with a document word ("Verklaring van
    Geschiktheid"; "JOHN SMITH CONSENT FORM" holds a name before it), an organisation that opens with one before a
    function word ("Application to ...", not "Plan International"), and anything but a person in a heading in
    capitals that ends with one."""
    folded = [w.casefold() for w in content]
    if not org and folded[0] in DOCUMENT_WORDS:
        return True
    if org and len(words) > len(content) and folded[0] in DOCUMENT_WORDS:
        return True
    if person or not line or any(c.islower() for c in line):
        return False
    tail = line.split()
    return bool(tail) and tail[-1].strip(_TRIM_CHARS + "*_#").casefold() in DOCUMENT_WORDS


@functools.lru_cache(maxsize=2048)
def _header_line(line: str) -> bool:
    """A table's header row: three or more cells in capitals, apart by runs of blanks, no digits
    ("CRS CODE    TITLE    WGT   MRK  GRD  CRS AVG"). Column names are not names."""
    if any(c.isdigit() for c in line) or ("  " not in line and "\t" not in line):
        return False
    cells = [c for c in re.split(r"[ ]{2,}|\t+", line.strip()) if c]
    return len(cells) >= 3 and all(c.isupper() for c in cells if any(ch.isalpha() for ch in c))


def plausible_entity(
    surface: str,
    line: str,
    lowercase: frozenset[str],
    *,
    place: bool = False,
    person: bool = False,
    org: bool = False,
) -> bool:
    """Whether a surface the model tagged could be a name, place or organisation: at least one capitalised word
    (in a script with capitals), and one word that is not a function word, not a word of the vocabulary above and
    not a word this text also writes in lower case. A lone acronym of up to four capitals in a line of mixed case
    ("UTC", "LOG", "DD") is a code, not a name, unless it was tagged as a place ("USA", "UK", "CA"), and so are words
    in capitals in a line of settings ("IPTABLES DROP IN=eth0 OUT= PROTO=TCP") and a document's title ("Application to
    Register Permanent Residence", "NEW PATIENT INTAKE FORM")."""
    if surface in PLACE_CODES:
        return True
    words = _WORDS_RE.findall(surface)
    if not words or _code_name(surface):
        return False
    cased = [w for w in words if w[0].isupper() or w[0].islower()]
    if len(cased) == len(words) and not any(w[0].isupper() for w in cased):
        # "the", "config", "github": names are written with a capital (where the script has them), except a person's
        # full name lowered to slip past ("emily bennett"): the model still reads it as one.
        return person and _lowercase_full_name(words)
    content = [w for w in words if w.casefold() not in _FUNCTION_WORDS]
    if not content:
        return False
    if all(not (w[0].isupper() or w[0].islower()) for w in content):
        return True  # Chinese, Japanese, Korean, Arabic, Thai...: no capitals to read
    if all(
        w.casefold() in _VOCABULARY or w.casefold() in lowercase for w in content if w[0].isupper() or w[0].islower()
    ):
        return False
    if _document_title(content, words, line, person=person, org=org):
        return False
    single = len(content) == 1 and " " not in surface.strip()
    mixed_line = any(c.islower() for c in line)
    if single and surface.strip(".").isalpha() and content[0].isupper() and len(content[0]) <= 4 and mixed_line:
        return False  # an acronym ("UTC", "DD"); "DN9" or "E4" (a postcode district, a road) has a digit and stays
    if single and org and content[0].isupper() and mixed_line:
        return False  # an organisation in one word of capitals among lower case: an abbreviation ("MEDCONFAC", "GCMCA")
    if single and (org or person) and any(c.isdigit() for c in surface) and not _leetspeak(surface):
        return False  # names of people and organisations hold no digits: "HPV4", "PCV7", "EC2"
    if single and person and not content[0].isupper() and sum(c.isupper() for c in content[0][1:]) >= 2:
        return False  # "DatabaseDSN", "KafkaSASLUser": an identifier in code, not "McDonald" or "DeShawn"
    if _header_line(line):
        return False
    return not (all(w.isupper() for w in content) and _settings_line(line))


_CASE_REACH = 2000


def case_view(text: str) -> str:
    """Same length as ``text``: an all-caps run inside normally cased text ("call EMILY THOMPSON today") is
    shown to the model in title case, which small NER models read far better. All-caps lines (headings,
    shouting) are left alone."""
    if not any(c.isupper() for c in text):
        return text

    def fix(m: re.Match[str]) -> str:
        # the run's line, read at most _CASE_REACH characters either side: a long line costs no more per run
        lo, hi = max(0, m.start() - _CASE_REACH), min(len(text), m.end() + _CASE_REACH)
        line_start = text.rfind("\n", lo, m.start()) + 1 or lo
        line_end = text.find("\n", m.end(), hi)
        line = text[line_start : hi if line_end == -1 else line_end]
        if not any(c.islower() for c in line):
            return m.group()
        titled = " ".join(w.capitalize() for w in m.group().split(" "))
        return titled if len(titled) == len(m.group()) else m.group()

    return _CAPS_RUN_RE.sub(fix, text)


def chunk_text(text: str, limit: int) -> list[tuple[int, str]]:
    """Split ``text`` into (offset, chunk) pieces of at most ``limit`` chars,
    cutting at paragraph, sentence or word boundaries when possible."""
    if len(text) <= limit:
        return [(0, text)]
    chunks: list[tuple[int, str]] = []
    start = 0
    while start < len(text):
        end = min(start + limit, len(text))
        if end < len(text):
            window = text[start:end]
            cut = None
            for m in _SPLIT_RE.finditer(window):
                if m.end() > limit // 2:
                    cut = m.end()
            if cut:
                end = start + cut
        chunks.append((start, text[start:end]))
        start = end
    return chunks


class NERDetector:
    def __init__(
        self,
        model: str,
        label_map: Mapping[str, EntityType],
        chunk_chars: int = 10_000,
        ignore: Iterable[str] = (),
        cache_entries: int = 0,
        cache_ttl_s: int = 900,
        language_models: Mapping[str, str] | None = None,
        other_languages: str = "english",
    ) -> None:
        import spacy  # imported lazily: loading spaCy costs ~1 s

        self.model_name = model
        self._ignore = frozenset(t.casefold() for t in ignore)
        self._nlp = spacy.load(model, exclude=_EXCLUDE)
        self._nlp.max_length = max(self._nlp.max_length, chunk_chars * 2)
        # English (and undetermined) text goes to `model`; text in another language goes to its own model,
        # or to the "other" model, or is skipped: an English model on German text mostly finds nouns.
        self._models = {lang: spacy.load(name, exclude=_EXCLUDE) for lang, name in (language_models or {}).items()}
        for nlp in self._models.values():
            nlp.max_length = max(nlp.max_length, chunk_chars * 2)
        self._other = other_languages
        self.skipped_chunks = 0
        self._labels = dict(label_map)
        self._chunk_chars = chunk_chars
        # spaCy inference is not guaranteed thread-safe; scale with processes.
        self._lock = threading.Lock()
        # Chat clients resend the whole history on every turn, so most texts
        # were scanned before. Only offsets and types are kept, under an HMAC
        # key that never leaves this process: the cache holds no text.
        self._cache_entries = cache_entries
        self._cache_ttl = float(cache_ttl_s)
        self._cache_key = os.urandom(32)
        self._cache: OrderedDict[bytes, tuple[float, tuple[tuple[int, int, EntityType, bool], ...]]] = OrderedDict()
        self._cache_lock = threading.Lock()
        self.cache_hits = 0
        self.cache_misses = 0

    @property
    def pipe_names(self) -> list[str]:
        return list(self._nlp.pipe_names)

    def detect_many(self, texts: list[str], *, precision_filter: bool = True) -> list[list[Span]]:
        """The entities in each text. ``precision_filter`` drops what cannot be a name (``plausible_entity``): the
        cache keeps both kinds, so the filter can be switched on the live policy without reloading a model."""
        return [[span for span, ok in found if ok or not precision_filter] for found in self._detect_marked(texts)]

    def _detect_marked(self, texts: list[str]) -> list[list[tuple[Span, bool]]]:
        if self._cache_entries <= 0:
            return self._detect_uncached(texts)
        now = time.monotonic()
        keys = [hmac.new(self._cache_key, t.encode("utf-8", "surrogatepass"), hashlib.sha256).digest() for t in texts]
        results: list[list[tuple[Span, bool]] | None] = [None] * len(texts)
        misses: list[int] = []
        with self._cache_lock:
            for i, key in enumerate(keys):
                entry = self._cache.get(key)
                if entry is not None and now - entry[0] < self._cache_ttl:
                    self._cache.move_to_end(key)
                    text = texts[i]
                    results[i] = [
                        (make_span(s, e, etype, "ner", _canonical(text[s:e]), 0.85), ok) for s, e, etype, ok in entry[1]
                    ]
                else:
                    misses.append(i)
        if misses:
            fresh = self._detect_uncached([texts[i] for i in misses])
            with self._cache_lock:
                for i, marked in zip(misses, fresh, strict=True):
                    results[i] = marked
                    self._cache[keys[i]] = (now, tuple((sp.start, sp.end, sp.type, ok) for sp, ok in marked))
                    self._cache.move_to_end(keys[i])
                while len(self._cache) > self._cache_entries:
                    self._cache.popitem(last=False)
        self.cache_hits += len(texts) - len(misses)
        self.cache_misses += len(misses)
        return [r if r is not None else [] for r in results]

    def _model_for(self, chunk: str) -> tuple[object | None, bool]:
        """The model for a chunk, and whether it is that language's own model (not the multilingual fallback)."""
        lang = detect_language(chunk)
        if lang in ("en", "und"):
            return self._nlp, lang == "en"
        if lang == "xx":  # another script: an English model only adds noise there
            return self._models.get("other"), False
        if lang in self._models:
            return self._models[lang], lang != "other"
        if "other" in self._models:
            return self._models["other"], False
        return (self._nlp if self._other == "english" else None), False

    def _detect_uncached(self, texts: list[str]) -> list[list[tuple[Span, bool]]]:
        """Each entity with whether it passes the precision filter."""
        pieces: list[tuple[int, int, str]] = []
        for idx, text in enumerate(texts):
            if not any(c.isalpha() for c in text):
                continue
            for offset, chunk in chunk_text(text, self._chunk_chars):
                pieces.append((idx, offset, chunk))
        results: list[list[tuple[Span, bool]]] = [[] for _ in texts]
        if not pieces:
            return results
        groups: dict[int, tuple[object, list[tuple[int, int, str, bool]]]] = {}
        for idx, offset, chunk in pieces:
            nlp, native = self._model_for(chunk)
            if nlp is None:
                self.skipped_chunks += 1
                continue
            groups.setdefault(id(nlp), (nlp, []))[1].append((idx, offset, chunk, native))
        routed: list[tuple[tuple[int, int, str, bool], object]] = []
        with self._lock:
            for nlp, group in groups.values():
                docs = nlp.pipe((case_view(p[2]) for p in group), batch_size=32)  # type: ignore[attr-defined]
                routed.extend(zip(group, docs, strict=True))
        lowercase: dict[int, frozenset[str]] = {}
        counts: dict[int, Counter[str]] = {}
        folded: dict[int, str] = {}
        capitalised: dict[tuple[int, int], bool] = {}
        software = [software_ranges(t) for t in texts]
        for (idx, offset, chunk, native), doc in routed:
            for ent in doc.ents:  # type: ignore[attr-defined]
                etype = self._labels.get(ent.label_)
                if etype is None:
                    continue
                for line_start, line_end in _lines(chunk, ent.start_char, ent.end_char):
                    trimmed = _trim(chunk, line_start, line_end)
                    if trimmed is None:
                        continue
                    s, e = trimmed
                    if etype is EntityType.PERSON:
                        stripped = strip_leading_cue(chunk, s, e)
                        if stripped is None:
                            continue
                        s, e = stripped
                    surface = chunk[s:e]
                    if surface.casefold() in self._ignore or sum(c.isdigit() for c in surface) >= 2:
                        continue  # labels, and codes ("SKU-88213-XL"): names rarely carry two digits
                    if etype is EntityType.ORGANIZATION and _CAMEL_RE.fullmatch(surface):
                        continue  # code identifiers and product names ("AccessDenied", "PowerPoint"): not personal data
                    if _SNAKE_RE.fullmatch(surface) or _SCREAMING_RE.fullmatch(surface):
                        continue  # field names and variables ("date_of_birth", "DATABASE_PASSWORD"): not entities
                    if _CODE_SYNTAX_RE.search(surface):
                        continue  # code read as a name: "std::env::set_var(", "Data.Text"
                    if chunk[e : e + 1] == "=" or (surface.isupper() and chunk[s - 1 : s] in (":", "=") and s > 0):
                        continue  # a setting's key ("PROTO=TCP") or a value glued to it ("BEGIN:VEVENT")
                    if idx not in lowercase:
                        lowercase[idx] = lowercase_words(texts[idx])
                    line = line_around(chunk, s, e)
                    # A person's full name written all in lower case is kept only when each of its words occurs
                    # nowhere else in the text, and the model knows the language or the name opens a sentence in a
                    # text that opens its other sentences with a capital: a name lowered to slip past ("emily
                    # bennett was in the notes", "... rapport. sanne bakker stond in de notities"), not a phrase
                    # the model misread ("je mi", "votre adresse"). A model reading a language not its own may
                    # take such a name for an organisation.
                    person = etype is EntityType.PERSON
                    lowered = any(c.islower() for c in surface) and not any(c.isupper() for c in surface)
                    if lowered and (person or (etype is EntityType.ORGANIZATION and not native)):
                        if idx not in counts:
                            counts[idx] = Counter(w.casefold() for w in _WORDS_RE.findall(texts[idx]))
                            folded[idx] = texts[idx].casefold()
                        times = folded[idx].count(surface.casefold())
                        named = [w for w in _WORDS_RE.findall(surface) if w.casefold() not in _PARTICLE_WORDS]
                        unique = all(counts[idx][w.casefold()] <= times for w in named)
                        opening = None if native or not unique else _sentence_opening(chunk, s)
                        if opening is not None:
                            if (idx, offset) not in capitalised:
                                capitalised[(idx, offset)] = _capitalised_sentences(chunk)
                            unique = capitalised[(idx, offset)]
                            if unique:  # "iker lópez", read by the model as "lópez": the name opens the sentence
                                s, surface = opening, chunk[opening:e]
                        elif not native:
                            unique = False
                        if unique and etype is EntityType.ORGANIZATION:
                            etype = EntityType.PERSON
                        person = unique
                    elif person:
                        person = any(c.isupper() for c in surface)
                    ok = plausible_entity(
                        surface, line, lowercase[idx], place=etype is EntityType.LOCATION, person=person,
                        org=etype is EntityType.ORGANIZATION,
                    )  # fmt: skip
                    if ok and etype is EntityType.PERSON and " " not in surface and instruction_verb(chunk, s, e):
                        ok = False
                    if surface in PLACE_CODES:
                        etype = EntityType.LOCATION
                    if etype is not EntityType.PERSON and chunk.startswith(("the ", "The "), s) and e - s > 4:
                        s += 4  # "the Center for Accessibility": the article is not part of the name
                        surface = chunk[s:e]
                    saint = _SAINT_BEFORE_RE.search(chunk, max(0, s - 5), s)
                    if saint is not None:
                        s = saint.start()  # "St. Jude Children's Hospital", "Mt. Sinai"
                        surface = chunk[s:e]
                    street = _street_end(chunk, e)
                    if street > e:
                        e, etype, surface = street, EntityType.LOCATION, chunk[s:street]
                    if etype is EntityType.LOCATION:
                        numbered = _house_number_end(chunk, e)
                        if numbered > e:  # a street and its house number: an address
                            e, etype, surface = numbered, EntityType.ADDRESS, chunk[s:numbered]
                    if ok and any(a <= offset + s and offset + e <= b for a, b in software[idx]):
                        ok = False
                    span = make_span(offset + s, offset + e, etype, "ner", _canonical(surface), 0.85)
                    results[idx].append((span, ok))
        return results


_LINE_REACH = 1000
_SENTENCE_OPENING_RE = re.compile(r"(?:^|[.!?][ \t]+|\n[ \t]*)([^\W\d_])", re.MULTILINE)


def line_around(text: str, start: int, end: int) -> str:
    """The line an entity is on, read at most _LINE_REACH characters either side: a long line costs no more per
    entity."""
    lo, hi = max(0, start - _LINE_REACH), min(len(text), end + _LINE_REACH)
    newline = text.rfind("\n", lo, start)
    lo = newline + 1 if newline >= 0 else lo
    newline = text.find("\n", end, hi)
    return text[lo : newline if newline >= 0 else hi]


def _sentence_initial(text: str, start: int) -> bool:
    """Whether ``start`` opens a sentence: the text's start, a line after one that ended a sentence, or a blank
    after !, ? or a word's full stop."""
    j = start
    while j > 0 and start - j < 8 and text[j - 1] in " \t":
        j -= 1
    if j == 0:
        return True
    if text[j - 1] == "\n":  # a new line opens a sentence when the one before ended one ("Gene,\nafter" does not)
        k = j - 1
        while k > 0 and j - k < 16 and text[k - 1] in " \t\r\n":
            k -= 1
        return k == 0 or text[k - 1] in ".!?:"
    if j == start or text[j - 1] not in ".!?":
        return False  # "yahoo.com atau": no blank after the stop
    if text[j - 1] != ".":
        return True
    w = j - 1
    while w > 0 and j - 1 - w < 30 and text[w - 1].isalpha():
        w -= 1
    return j - 1 - w >= 5  # a full stop after a word, not after "19.", "ds." or "např."


def _sentence_opening(text: str, start: int) -> int | None:
    """Where the sentence opens when ``start`` is in its first two words and those are written in lower case."""
    j = start
    for _ in range(2):
        if _sentence_initial(text, j):
            return j
        k = j
        while k > 0 and j - k < 8 and text[k - 1] in " \t":
            k -= 1
        w = k
        while w > 0 and k - w < 30 and text[w - 1].isalpha():
            w -= 1
        if w == k or not text[w:k].islower():
            return None
        j = w
    return j if _sentence_initial(text, j) else None


def _capitalised_sentences(text: str) -> bool:
    """Whether a text opens its sentences with a capital, two or more times as often as with a small letter."""
    openings: list[str] = [m.group(1) for m in _SENTENCE_OPENING_RE.finditer(text)]
    upper = sum(1 for c in openings if c.isupper())
    return upper >= 2 and 2 * (len(openings) - upper) <= upper


def _lines(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Split an entity at line breaks: "Anna Jansen\\nNorthwind" is two values, not one."""
    if "\n" not in text[start:end]:
        return [(start, end)]
    parts = []
    cursor = start
    while cursor < end:
        nl = text.find("\n", cursor, end)
        stop = end if nl == -1 else nl
        if stop > cursor:
            parts.append((cursor, stop))
        cursor = stop + 1
    return parts


def _trim(text: str, start: int, end: int) -> tuple[int, int] | None:
    while start < end and text[start] in _TRIM_CHARS:
        start += 1
    while end > start and text[end - 1] in _TRIM_CHARS:
        end -= 1
    m = _POSSESSIVE_RE.search(text, start, end)
    if m and m.end() == end and m.start() > start:
        end = m.start()
    surface = text[start:end]
    alnum = sum(c.isalnum() for c in surface)
    if alnum < 2 or surface.replace(" ", "").isdigit():
        return None
    return start, end


def _canonical(surface: str) -> str:
    return " ".join(surface.split()).casefold()
