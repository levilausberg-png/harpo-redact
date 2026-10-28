"""Layer 2e: postal addresses as they are written across Europe, the Americas and Asia.

identifiers.find_addresses knows English, Dutch and German street names. This layer reads the grammar of a street
address in most European languages and in Indonesian, Malay, Vietnamese, Turkish, Chinese, Japanese and Korean:

* a street word before the name ("Via Valcittadella 418", "Rua Laura Alves, nº 12", "ul. Bryast №124",
  "Jalan Sudirman No. 5"), after it ("Poljanska ulica 19", "Brīvības iela 100", "Tilžės g. 7") or glued to it
  ("Aleksanterinkatu 1", "Kystværnsvej 190", "Stenåsvägen 32L"), with the house number;
* the house number first ("12 rue de la Paix", "84 Lorong Kismis");
* the postcode and town after a street ("..., 5000 Esbjerg", "..., 128 00 Brno", "..., Tartu 93810");
* a street name without a street word, when a postcode and town follow ("Golzern 858, 9116 Lohn-Ammannsegg");
* a US town before its state and ZIP code ("Malibu, CA 90265");
* what an address label introduces ("Adresse:", "Dirección:", "住所：") or an address phrase ("residing at",
  "à l'adresse", "na adrese"), when it holds a house number;
* Chinese, Japanese and Korean addresses by their units (路, 街, 号; 市, 区, 丁目, 番地; 로, 길, 번지);
* a town after a town label ("City:", "Ville :", "Město:"), as a location.

A street word alone is never enough: a house number has to come with it, and a lowercase street word that is also
an everyday word ("via", "place", "route") needs a house-number marker or a postcode after it. Every pattern is
bounded, so a scan is linear in the length of the text.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterator

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "address"

# --------------------------------------------------------------------------- vocabulary
# A house-number marker: "nº 34", "n. 1", "nr. 7", "č. 614", "br. 19", "№124", "No. 5", "sz. 12", "số 10".
_MARKER = (
    r"(?:[nN][º°o]\.?|[nN]\.|[nN][rR]\.?|[nN]ro\.?|[nN]o\.?|[nN]um\.?|[nN]úmero|[nN]umero|č\.(?:\s?p\.)?|čp\.?|br\.?"
    r"|broj|бр\.?|№|#|sz\.?|szám|số|[kK]at|[dD]aire)"
)
_NUMBER = (
    r"\d{1,5}(?:[A-Za-z](?![A-Za-z])|[ \t]?(?:bis|hs|huis)(?![A-Za-z]))?(?:\s?[/\-]\s?\d{1,5}[A-Za-z]?)?"
    r"(?:[ \t](?:I{1,3}|IV|[A-D]|hs|bis)(?![\w]))?"
)


def _letters(test: str) -> str:
    """A character class of every letter below U+10000 that passes ``test`` (Python's re has no \\p{Lu})."""
    ranges: list[str] = []
    start = prev = -2
    for cp in range(0x10000):
        if 0xD800 <= cp <= 0xDFFF or not getattr(chr(cp), test)():
            continue
        if cp != prev + 1:
            if start >= 0:
                ranges.append(_range(start, prev))
            start = cp
        prev = cp
    ranges.append(_range(start, prev))
    return "".join(ranges)


def _range(a: int, b: int) -> str:
    return re.escape(chr(a)) if a == b else f"{re.escape(chr(a))}-{re.escape(chr(b))}"


_UPPER = _letters("isupper")
# Words of a street name: capitalised words in any alphabet, initials, numbers ("Via 20 Settembre") and the small
# words between them ("de la", "do", "van der", "di").
_PARTICLES = """de del della delle dello dei degli di da do dos das du des la le les los las van von der den het of
    the al el e y i et und an am im zum zur sur sous lès sul sulla alla ao à na no nas nos pe din lui d
    l""".split()  # noqa: SIM905
_CAP = rf"(?:[{_UPPER}][^\W\d_]{{0,2}}\.(?![^\W\d_])|[{_UPPER}][^\W\d_]*(?:[\-'’][^\W\d_]+)*)"
# A number inside a name ("Via 20 Settembre", "Avenida 9 de Julio") has more of the name after it; a number before a
# comma is the house number.
_NAME_WORD = (
    rf"(?:{_CAP}|(?:{'|'.join(_PARTICLES)})(?![^\W\d_])"
    rf"|\d{{1,3}}(?:º|ª|°|st|nd|rd|th|\.)?(?=[ \t]{{1,2}}(?:[{_UPPER}]|de |di |of )))"
)
_NAME = rf"(?:(?:{'|'.join(_PARTICLES)})[ \t]{{1,2}}){{0,2}}{_CAP}(?:[ \t]{{1,2}}{_NAME_WORD}){{0,5}}"

# Street words written before the name, in French, Spanish, Italian, Portuguese, Romanian, Polish, Czech, Slovak,
# Slovenian, Croatian, Serbian, Bulgarian, Greek, Russian, Indonesian, Malay, Vietnamese and Tagalog. Ambiguous ones
# are everyday words too: lowercase, they need a house-number marker or a postcode after the number.
_PREFIX = frozenset(
    """rue avenue av boulevard bd bld chemin ch route rte allée impasse imp quai faubourg fbg promenade esplanade
    parvis hameau montée calle avenida avda paseo plaza pza camino carretera ctra ronda travesía glorieta
    callejón pasaje vía bulevar urbanización urb carrera cra calzada prolongación andador privada cerrada
    circuito viale piazza piazzale corso vicolo strada contrada lungomare lungotevere frazione fraz località
    vico traversa rua travessa praça praceta estrada alameda beco calçada rodovia viela ladeira bulevardul calea
    aleea șoseaua soseaua piața splaiul intrarea drumul str ulica ul aleja plac osiedle rondo náměstí nám třída
    nábřeží námestie nábrežie trg obala bulevar šetalište prilaz avenija naselje ул улица бул булевард площад
    проспект οδός οδ λεωφόρος λεωφ πλατεία jalan jl jln gang gg lorong lrg lebuh persiaran lintang taman kampung
    kg komplek perumahan đường phố ngõ ngách hẻm kalye""".split()  # noqa: SIM905
)
_PREFIX_AMBIGUOUS = frozenset(
    """via place pl route passage square cours largo borgo salita sentier voie lugar""".split()  # noqa: SIM905
)
# Two letters or fewer: an abbreviation, taken only with its dot or a marker ("ul. Bryast 124", not "ul 124").
# Street words written after the name, as a word of their own ("Poljanska ulica 19", "Tilžės g. 7"), English ones
# included: many addresses outside English-speaking countries are written "Rustaveli Avenue 23".
_SUFFIX = frozenset(
    """utca u út útja tér körút krt sétány köz fasor rakpart dűlő gatvė g prospektas aikštė alėja skg plentas takas
    kelias iela bulvāris bulv prospekts laukums gatve šoseja ceļš tänav tn puiestee pst maantee mnt väljak põik
    ulica ulice cesta třída nábřeží náměstí trg sokak sokağı sk sok cadde caddesi cad cd bulvarı blv mahallesi
    mah straße strasse str weg allee platz gasse damm ufer chaussee gade vej allé plads torv vei gata väg
    street road rd avenue ave lane ln boulevard blvd way court ct terrace
    crescent close grove parade highway hwy parkway""".split()  # noqa: SIM905
)
# Street words glued to the end of the name ("Aleksanterinkatu", "Kystværnsvej", "Stenåsvägen", "Hauptstraße").
_GLUED = tuple(
    sorted(
        """straße strasse str weg gasse allee platz damm ufer chaussee steig pfad stieg zeile straat laan plein
            gracht kade singel dijk dreef steeg gade vej vei veien allé plads plass torv torvet stræde strædet
            vænget gatan gata gaten vägen väg gränd torget allén stigen backen leden platsen katu tie kuja polku
            väylä tori aukio ranta kaari rinne raitti tänav puiestee""".split(),  # noqa: SIM905
        key=len,
        reverse=True,
    )
)
_SHORT_GLUED_MIN = 4  # "Canadavej", not "Ivej": a short ending needs a longer name before it
# A delimiter after the house number: where a street address ends. "Via Zoom 3 people" is not an address.
_END = r"(?=[ \t]*(?:[,;)\]\n\r–—-]|\.(?:\s|$)|$|[ \t]+(?:\d{2,}|[A-Z]{1,2}-?\d|szám|sz\.|számú|번지|号)))"
_AFTER_PREFIX_RE = re.compile(
    rf"\.?[ \t]{{1,2}}(?P<name>{_NAME})[ \t]*,?[ \t]{{0,2}}(?P<marker>{_MARKER}[ \t]{{0,2}})?(?P<num>{_NUMBER}){_END}"
)
_AFTER_NAME_RE = re.compile(
    rf"\.?[ \t]{{0,4}}(?:,[ \t]{{0,2}})?(?P<marker>{_MARKER}[ \t]{{0,2}})?(?P<num>{_NUMBER}){_END}"
)
_NUMBER_BEFORE_RE = re.compile(r"(?<![\w.,/-])\d{1,5}[A-Za-z]?[ \t]{0,2},?[ \t]{1,2}$")
_WORD_RE = re.compile(r"[^\W\d_]+(?:[\-'’][^\W\d_]+)*")
_CAP_WORD_RE = re.compile(rf"{_CAP}$")

# What may follow a street: the postcode and town, the town and postcode, or the town alone.
_POSTCODE = (
    r"(?:\d{4}[ \t]?[A-Z]{2}(?![\w])|\d{4,6}|\d{3}[ \t]\d{2}|\d{2}-\d{3}|\d{4}-\d{3}|\d{5}-\d{4}|[A-Z]{1,2}-\d{3,5})"
)
_TOWN = (
    rf"(?:['’]s-|['’]t[ \t])?{_CAP}(?:[ \t\-]{{1,2}}(?:{_CAP}|am|an|der|im|la|le|les|sur|di|de|del|do|da|na|nad|pod"
    rf"|aan|den|op|ter|ten|bij|upon|on|en)){{0,3}}"
)
_TAIL_RE = re.compile(
    rf"[ \t]{{0,4}}(?:[,–—-][ \t]{{0,2}})?(?:\n[ \t]{{0,8}})?"
    rf"(?:(?:{_POSTCODE})[ \t]{{1,2}}{_TOWN}(?:[ \t]\({_POSTCODE}\))?"
    rf"|{_TOWN}(?:[ \t]*[,–—-]?[ \t]{{0,2}}\(?{_POSTCODE}\)?(?![\w-]))?)"
)
_BARE_POSTCODE_RE = re.compile(rf"[ \t]*,[ \t]{{0,2}}(?P<pc>{_POSTCODE})(?=[ \t]*(?:$|[\n.,;)]|[ \t][a-z]))")
# No street word, but a postcode and town after the number: "Golzern 858, 9116 Lohn-Ammannsegg".
# The street and the postcode line may also be two lines of an address block, when the postcode is unmistakable
# (Dutch "1234 AB", or five digits): "Laan van Meerdervoort 2\n9453 EK Vlaardingen".
_BARE_RE = re.compile(
    rf"(?<![^\W_])(?P<name>{_CAP}(?:[ \t]{_NAME_WORD}){{0,3}})[ \t](?P<num>{_NUMBER})"
    rf"(?:,[ \t]{{0,2}}|[ \t]*\n[ \t]*(?=\d{{4}}[ \t]?[A-Z]{{2}}[ \t]|\d{{5}}[ \t]))"
    rf"(?:(?P<pc>{_POSTCODE})[ \t]{{1,2}}(?P<town>{_TOWN})"
    rf"|(?P<town2>{_TOWN})[ \t]{{1,2}}(?P<pc2>{_POSTCODE}))"
    r"(?![\w-])"
)
_NOT_A_STREET = frozenset(
    """chapter section page room article table figure fig version step level grade class group team item line part
        volume vol box floor suite unit apt apartment building block lot phase stage round week day year month
        question task issue ticket order invoice rule clause paragraph exhibit appendix annex schedule note slide
        episode season psalm verse book act scene track""".split()  # noqa: SIM905
)  # fmt: skip
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
_US_STATES = (
    "Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|"
    "Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|"
    "Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|"
    "Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|"
    "West Virginia|Wisconsin|Wyoming|District of Columbia|Puerto Rico|Guam"
)
# A ZIP code after its state, by name or postal abbreviation: "Austin, Texas 78757", "Silver Spring, MD, 20904".
_STATE_ZIP_RE = re.compile(
    rf"(?<![^\W_])(?:{_US_STATES}|AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV"
    r"|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR),?[ \t]{1,2}(?:USA?,?[ \t]{1,2})?"
    r"\d{5}(?:-\d{4})?(?![\w-])"
)
_FIVE_DIGITS_RE = re.compile(r"(?<!\d)\d{5}(?!\d)")
_US_TOWN_STATE_RE = re.compile(
    r"(?<![^\W_])[A-Z][a-z]+(?:[ \t-][A-Z][a-z]+){0,3},[ \t]{1,2}(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY"
    r"|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)"
    r"[ \t]{1,2}\d{5}(?:-\d{4})?\b"
)


# --------------------------------------------------------------------------- labels and phrases
_ADDRESS_LABELS = (
    "address|mailing address|home address|street address|billing address|shipping address|delivery address|"
    "postal address|residential address|permanent address|current address|registered address|address line \\d|"
    "residence|residence address|home|domicile|woonadres|huisadres|postadres|bezoekadres|correspondentieadres|"
    "postcode en woonplaats|postcode en plaats|postcode/woonplaats|postcode/plaats|postcode & plaats|zip/city|"
    "city/zip|zip code and city|postal code and city|plz/ort|plz und ort|plz ort|code postal et ville|cp/ville|"
    "factuuradres|afleveradres|vestigingsadres|privéadres|priveadres|meldeadresse|wohnanschrift|lieferadresse|"
    "rechnungsadresse|adresse de facturation|adresse de livraison|domicile|dirección postal|indirizzo di consegna|"
    "adresse|anschrift|wohnadresse|postanschrift|adres|adresa|adresas|adrese|aadress|osoite|katuosoite|dirección|"
    "direccion|domicilio|indirizzo|indirizzo di residenza|endereço|endereco|morada|cím|lakcím|διεύθυνση|адрес|адреса|"
    "alamat|địa chỉ|dia chi|tirahan|adresse postale|bostadsadress|gatuadress|bopælsadresse|street|straße|strasse|rue|"
    "calle|ulica|utca|iela|gatvė|stradă|strada|住所|地址|주소|居住地址|所在地"
)
_LABEL_RE = re.compile(
    rf"(?:^|(?<=[\n•*|;]))[ \t]*(?:[-*•][ \t]*)?(?:\d{{1,2}}[.)][ \t]*)?(?:\*\*)?(?P<label>{_ADDRESS_LABELS})"
    rf"(?:[ \t]*\([^()\n]{{0,30}}\))?(?:\*\*)?[ \t]*[:：](?:\*\*)?[ \t]*(?P<value>[^\n]{{3,140}})",
    re.IGNORECASE | re.MULTILINE,
)
_NOT_POSTAL = re.compile(
    r"(?i)(?:e-?mail|ip|mac|web|url|memory|wallet|contract|server|network|bitcoin|btc|eth(?:ereum)?|hardware|base|"
    r"bluetooth|ethernet|ipv[46]|proxy|gateway|host|return|jump|load|start|offset|pointer|reply-to|from|sender)"
    r"[ \t_\-]*$"
)
_PHRASE_RE = re.compile(
    r"(?i)(?<![^\W_])(?:resid(?:ing|es|e)|living|lives|located|situated|based|headquartered|domiciled|registered)"
    r"[ \t]+(?:at|in|on)|at the address|address is|(?:à|a) l['’]adresse|en la dirección|en el domicilio|"
    r"all['’]indirizzo|na morada|no endereço|na adrese|na adresi|na adresu|na adresie|pod adresem|a következő címen|"
    r"aadressil|adresinde|wohnhaft (?:in|an|am)|wohnt (?:in|an|am)|domiciliad[oa] en|residente (?:en|in|em|a)|"
    r"(?:woon|woont|wonen|woonde|woonden)(?: [a-z]{2,8}){0,2} (?:op|aan|in)|wonende (?:te|op|aan)|"
    r"woonachtig (?:te|op|aan|in)|"
    r"verblijvende te|"
    r"gevestigd (?:te|op|aan)|op het adres|naar het adres|verhuisd naar|"
    r"bor på|bor i|asuu osoitteessa|mieszka (?:przy|w|na)|bydlí (?:na|v)|býva (?:na|v)|živi (?:na|v|u)|lakik|"
    r"locuiește (?:pe|în|la)|живее (?:на|в)|μένει (?:στην|στο|στη)|gyvena|dzīvo|elab|tinggal di|sống tại|sống ở|"
    r"nakatira sa"
)
# Words one of the phrases above contains: a quick test before the phrase pattern runs.
_PHRASE_KEYS = (
    "woon",
    "wonen",
    "verblijv",
    "gevestigd",
    "verhuisd",
    "resid",
    "living",
    "lives",
    "locat",
    "situat",
    "based",
    "headquart",
    "domicil",
    "registered",
    "address",
    "adress",
    "indirizzo",
    "morada",
    "endereço",
    "adres",
    "wohn",
    "bor ",
    "asuu",
    "mieszka",
    "bydlí",
    "býva",
    "živi",
    "lakik",
    "locuie",
    "живее",
    "μένει",
    "gyvena",
    "dzīvo",
    "elab",
    "tinggal",
    "sống",
    "nakatira",
    "címen",
    "dirección",
    "domicilio",
)
_PHRASE_FIRST = frozenset(
    """woon woont wonen woonde wonende woonachtig verblijvende gevestigd op naar verhuisd
        residing resides reside living lives located situated based headquartered domiciled registered at address à
        a en all all'indirizzo na no pod aadressil adresinde wohnhaft wohnt domiciliado domiciliada residente bor
        asuu mieszka bydlí býva živi lakik locuiește живее μένει gyvena dzīvo elab tinggal sống nakatira""".split()  # noqa: SIM905
)
_CLAUSE_END_RE = re.compile(
    r"(?<![^\w][^\W\d_])(?<![^\w][^\W\d_]{2})\.(?=\s+[^\d\s]|\s*$)|[;\n!?]"
    r"|\s(?:and|und|et|y|e|i|och|og|en|to|for|from|on|with|until)\s"
)
_HOUSE_NUMBER_RE = re.compile(rf"(?<![\w.])(?:{_MARKER}[ \t]?)?\d{{1,5}}[A-Za-z]?(?:[/\-]\d{{1,5}})?(?![\w.]\d)")
_TOWN_LABELS = (
    "city|town|city or town|town/city|city/town|stadt|ort|wohnort|ville|ciudad|città|citta|cidade|stad|mesto|město|"
    "woonplaats|plaats|plaatsnaam|vestigingsplaats|geboorteplaats|geburtsort|lieu de naissance|commune|localidad|"
    "municipio|lugar de nacimiento|comune|luogo di nascita|localidade|naturalidade|city of residence|hometown|"
    "grad|miasto|miejscowość|város|település|oraș|oras|localitate|miestas|pilsēta|linn|kaupunki|paikkakunta|πόλη|"
    "град|город|kota|bandar|lungsod|thành phố|şehir|sehir|il|市区町村|城市|도시|居住地"
)
# Labels for a region or a country, in the languages above.
_REGION_LABELS = (
    "state|province|region|county|district|prefecture|territory|bundesland|kanton|canton|état|etat|département|"
    "departement|région|estado|provincia|comunidad autónoma|regione|provincie|fylke|län|landskap|maakunta|"
    "województwo|voivodeship|kraj|okres|megye|județ|judet|област|νομός|περιφέρεια|apskritis|novads|maakond|provinsi|"
    "negeri|lalawigan|tỉnh|ilçe|state or province|state/province|county or region|country|nation|land|pays|país|"
    "pais|paese|nazione|maa|země|krajina|država|ország|țară|tara|държава|χώρα|šalis|valsts|riik|negara|bansa|"
    "quốc gia|ülke|country of residence|country of birth|place of birth|birthplace|city of birth"
)
_TOWN_LABEL_RE = re.compile(
    rf"(?m)(?:^|(?<=[\n•*|;,]))[ \t]*(?:[-*•][ \t]*)?(?:\d{{1,2}}[.)][ \t]*)?(?:\*\*)?(?i:{_TOWN_LABELS})(?:\*\*)?"
    rf"[ \t]*[:：](?:\*\*)?[ \t]*(?P<value>{_TOWN}|[\u3040-\u30ff\u4e00-\u9fff\uac00-\ud7af]{{2,12}})"
)

# "State: IL", "**Country:** USA", "county: Worcester": a region or country after its label, up to the end of the line
# or the next field. "State" also names a status ("State: Running"): those values are left out (_NOT_A_PLACE).
_REGION_LABEL_RE = re.compile(
    rf"(?m)(?:^|(?<=[\n•*|;,]))[ \t]*(?:[-*•][ \t]*)?(?:\d{{1,2}}[.)][ \t]*)?(?:\*\*)?(?i:{_REGION_LABELS})(?:\*\*)?"
    rf"[ \t]*[:：](?:\*\*)?[ \t]*(?P<value>{_TOWN}|[A-Z]{{2,3}})(?:\*\*)?(?=[ \t]*(?:$|[,;|)\n]))"
)

# --------------------------------------------------------------------------- Chinese, Japanese, Korean
_HAN = "一-鿿"
_KANA = "぀-ヿ"
_HANGUL = "가-힯"
_CJK_STREET_RE = re.compile(
    rf"(?:[{_HAN}]{{1,6}}(?:省|市|区|區|县|縣|镇|鎮|乡|鄉)[ \t]?){{0,3}}[{_HAN}]{{1,8}}(?:路|街|大道|道|巷|弄|胡同|里)"
    rf"[ \t]?\d{{1,5}}(?:[-－]\d{{1,4}})?(?:号|號|弄|室|栋|棟|楼|樓)?"
)
# Place names are written in kanji and katakana; hiragana around them is grammar ("会場は京都市...").
_JP_NAME = rf"[{_HAN}゠-ヿ]"
_JP_ADDRESS_RE = re.compile(
    rf"(?:[{_HAN}]{{1,4}}(?:都|道|府|県))?(?:{_JP_NAME}{{1,6}}(?:市|区|町|村|郡)){{1,3}}(?:の)?"
    rf"{_JP_NAME}{{0,8}}[ \t]?\d{{1,4}}(?:[-－‐]\d{{1,4}}){{0,3}}(?:丁目|番地|番|号)?"
)
_JP_UNITS_RE = re.compile(rf"(?:[{_HAN}]{{1,4}}(?:都|道|府|県))?(?:{_JP_NAME}{{1,6}}(?:市|区|町|村|郡)){{2,3}}")
_KO_STREET_RE = re.compile(
    rf"(?:[{_HANGUL}]{{1,8}}(?:특별시|광역시|시|도|군|구)[ \t]){{0,3}}"
    rf"[{_HANGUL}\d]{{1,10}}(?:로|길|대로|번길)[ \t]?\d{{1,5}}"
    rf"(?:-\d{{1,4}})?(?:번지|번길|호)?"
)
_CJK_ANY_RE = re.compile(rf"[{_HAN}{_KANA}{_HANGUL}]")


def _has_number(value: str) -> bool:
    return _HOUSE_NUMBER_RE.search(value) is not None


def _span(start: int, end: int, text: str, kind: str = "street", etype: E = E.ADDRESS) -> Span:
    return make_span(start, end, etype, f"{SOURCE}:{kind}", " ".join(text[start:end].split()).casefold(), 0.85)


def _with_tail(text: str, end: int) -> int:
    """The street's end, moved past the postcode and town that follow it."""
    bare = _BARE_POSTCODE_RE.match(text, end)
    if bare is not None and not _YEAR_RE.fullmatch(bare.group("pc")) and _TAIL_RE.match(text, end) is None:
        return bare.end()
    tail = _TAIL_RE.match(text, end)
    if tail is None or tail.end() == end:
        return end
    piece = text[end : tail.end()]
    # A town alone after a comma is only taken when a postcode is in it or it ends the line: "Via Roma 1, Milano".
    if not re.search(r"\d", piece) and not re.match(r"[ \t]*(?:[\n\r]|$|[.;)])", text[tail.end() : tail.end() + 2]):
        return end
    return tail.end()


def _name_before(text: str, words: list[re.Match[str]], i: int) -> int:
    """Where the street name before word ``i`` starts: up to three capitalised words (or particles) right before it."""
    start = words[i].start()
    for k in range(i - 1, max(-1, i - 4), -1):
        w = words[k]
        if text[w.end() : start] not in (" ", "\t", "  "):
            break
        if not (_CAP_WORD_RE.match(w.group()) or w.group() in _PARTICLES):
            break
        start = w.start()
    return start


_DIGIT_RUN_RE = re.compile(r"\d+")


def _near_numbers(text: str) -> list[re.Match[str]]:
    """The words that can belong to a street: those up to 100 characters before a number or just after it."""
    words: list[re.Match[str]] = []
    last = 0
    for d in _DIGIT_RUN_RE.finditer(text):
        if d.end() - d.start() > 5 or (
            text[d.end() : d.end() + 1] in (":", ".") and text[d.end() + 1 : d.end() + 2].isdigit()
        ):
            continue  # not a house number: a long number, a time, an IP address or a version
        a, b = max(last, d.start() - 100), min(len(text), d.end() + 16)
        while a > last and text[a - 1].isalpha():
            a -= 1  # never start inside a word
        while b < len(text) and (text[b].isalpha() or text[b] in "-'’"):
            b += 1  # nor end inside one
        if a < b:
            words.extend(_WORD_RE.finditer(text, a, b))
        last = max(last, b)
    return words


def _streets(text: str) -> Iterator[tuple[int, int]]:
    words = _near_numbers(text)
    for i, w in enumerate(words):
        word = w.group()
        folded = word.casefold()
        if folded in _PREFIX or folded in _PREFIX_AMBIGUOUS:
            m = _AFTER_PREFIX_RE.match(text, w.end())
            if m is not None:
                dotted = text.startswith(".", w.end())
                marker = m.group("marker") is not None
                if len(folded) <= 2 and not (dotted or marker):
                    pass  # "c 12", "al 5": an abbreviation needs its dot or a marker
                elif (
                    folded in _PREFIX_AMBIGUOUS
                    and not word[0].isupper()
                    and not marker
                    and not re.match(rf"[ \t]*,?[ \t]{{0,2}}{_POSTCODE}[ \t]", text[m.end() : m.end() + 12])
                ):
                    pass  # "via email 12": an everyday word needs a marker or a postcode
                else:
                    yield w.start(), m.end()
            if len(folded) > 2 and folded in _PREFIX:
                before = _NUMBER_BEFORE_RE.search(text, max(0, w.start() - 12), w.start())
                after = re.compile(rf"\.?[ \t]{{1,2}}{_NAME}").match(text, w.end())
                if before is not None and after is not None:
                    yield before.start(), after.end()
        if folded in _SUFFIX and i > 0:
            if len(folded) == 1 and not text.startswith(".", w.end()):
                continue
            m = _AFTER_NAME_RE.match(text, w.end())
            start = _name_before(text, words, i)
            if m is not None and start < w.start():
                yield start, m.end()
        elif word[0].isupper() and folded.endswith(_GLUED):
            ending = next(g for g in _GLUED if folded.endswith(g))
            if len(ending) <= 4 and len(folded) - len(ending) < _SHORT_GLUED_MIN:
                continue
            m = _AFTER_NAME_RE.match(text, w.end())
            if m is not None:
                yield _name_before(text, words, i), m.end()


def find_street_addresses(text: str) -> Iterator[Span]:
    if not any(c.isdigit() for c in text):
        return
    for start, end in _streets(text):
        yield _span(start, _with_tail(text, end), text)
    for m in _BARE_RE.finditer(text):
        first = m.group("name").split()[0].casefold().rstrip(".")
        pc = m.group("pc") or m.group("pc2") or ""
        if first in _NOT_A_STREET or _YEAR_RE.fullmatch(pc):
            continue
        yield _span(m.start(), m.end(), text, "street-town")
    for m in _US_TOWN_STATE_RE.finditer(text):
        yield _span(m.start(), m.end(), text, "town-state")
    if _FIVE_DIGITS_RE.search(text):
        for m in _STATE_ZIP_RE.finditer(text):
            yield _span(m.start(), m.end(), text, "state-zip")
    if not text.isascii() and _CJK_ANY_RE.search(text):
        for pattern in (_CJK_STREET_RE, _JP_ADDRESS_RE, _KO_STREET_RE):
            for m in pattern.finditer(text):
                yield _span(m.start(), m.end(), text, "cjk")
        for m in _JP_UNITS_RE.finditer(text):
            yield _span(m.start(), m.end(), text, "cjk-units", E.LOCATION)


def _value_end(value: str) -> int:
    """Where a label's value ends: two spaces, a tab, a separator, or the next label ("City:", "PLZ / Ort:")."""
    m = re.search(r"\s{2,}|\t|[;|]|\s[A-ZÄÖÜÉ][\w/.\-]*(?: [\w/.\-]+){0,3}[:：]|\s\(\s*[A-Za-z]+\s*[:：]", value)
    return m.start() if m else len(value)


def find_labelled_addresses(text: str) -> Iterator[Span]:
    if ":" in text or "：" in text:
        for m in _LABEL_RE.finditer(text):
            before = text[max(0, m.start("label") - 16) : m.start("label")]
            if _NOT_POSTAL.search(before):
                continue
            value = m.group("value")
            cut = _value_end(value)
            value = value[:cut].rstrip(" \t.,*")
            if not value or "@" in value or "://" in value or re.fullmatch(r"(?:0x)?[0-9a-fA-F:.\-]+", value):
                continue
            cjk = _CJK_ANY_RE.search(value) is not None
            if not (_has_number(value) or cjk) or len(value) < 4:
                continue
            start = m.start("value")
            yield _span(start, start + len(value), text, "label")
        for m in _TOWN_LABEL_RE.finditer(text):
            value = m.group("value")
            yield make_span(m.start("value"), m.end("value"), E.LOCATION, f"{SOURCE}:town", value.casefold(), 0.8)
        for m in _REGION_LABEL_RE.finditer(text):
            value = m.group("value")
            if value.casefold() not in _NOT_A_PLACE:
                yield make_span(m.start("value"), m.end("value"), E.LOCATION, f"{SOURCE}:region", value.casefold(), 0.8)
    lowered = text.casefold()
    if not any(k in lowered for k in _PHRASE_KEYS):
        return
    for w in _WORD_RE.finditer(text):
        if w.group().casefold() not in _PHRASE_FIRST:
            continue
        phrase = _PHRASE_RE.match(text, w.start())
        if phrase is None:
            continue
        pos = phrase.end()
        while pos < len(text) and text[pos] in " \t:":
            pos += 1
        for article in ("the ", "The "):
            if text.startswith(article, pos):
                pos += len(article)
        if pos >= len(text) or not (text[pos].isupper() or text[pos].isdigit()):
            continue
        window = text[pos : pos + 100]
        stop = _CLAUSE_END_RE.search(window)
        value = window[: stop.start() if stop else len(window)].rstrip(" \t,")
        number = _HOUSE_NUMBER_RE.search(value)
        if number is None or number.start() > 60:
            continue
        # The number belongs to the address when a capitalised word or a comma is next to it, and it is not a year
        # after an ordinary word ("ik woon in Amsterdam sinds 2019").
        around = value[max(0, number.start() - 2) : number.end() + 2]
        near = value[max(0, number.start() - 24) : number.end() + 24]
        if not re.search(r"[^\W\d_a-z]", near) or not re.search(r"[, ]", around):
            continue
        word_before = _WORD_RE.findall(value[: number.start()])
        if re.fullmatch(r"(?:19|20)\d\d", number.group()) and word_before and word_before[-1].islower():
            continue
        yield _span(pos, pos + len(value), text, "phrase")


# --------------------------------------------------------------------------- table columns (detectors/fields.py)
_ADDRESS_LABEL_FULL_RE = re.compile(rf"(?:{_ADDRESS_LABELS})", re.IGNORECASE)
_ADDRESS_WORD_RE = re.compile(
    r"(?i)(?:address|adresse|anschrift|adres|adresa|adresas|adrese|aadress|osoite|dirección|direccion|domicilio"
    r"|indirizzo|endereço|endereco|morada|cím|διεύθυνση|адрес|alamat|địa chỉ|tirahan)$"
)
_PLACE_LABELS = frozenset(_TOWN_LABELS.split("|") + _REGION_LABELS.split("|"))
_LABEL_NOISE_RE = re.compile(r"\([^()]{0,40}\)|[*_#:`|]+")
_PLACE_CELL_RE = re.compile(rf"(?:{_TOWN}|[A-Z]{{2,3}})")
_NOT_A_PLACE = frozenset(
    """unknown none null n/a na tbd pending other various remote online virtual global worldwide international
    multiple all any same yes no open closed active inactive new done resolved draft approved rejected enabled
    disabled running stopped failed success complete completed cancelled canceled ok valid invalid waiting
    terminated starting ready idle queued processing paused blocked healthy unhealthy degraded offline up down live
    archived deleted published scheduled submitted received shipped delivered returned refunded expired locked
    unlocked verified confirmed true false on off high low medium critical normal warning error passed""".split()  # noqa: SIM905
)
_STREET_WORD_RE = re.compile(r"(?<![^\W_])[^\W\d_]{3,}(?![^\W_])")


@functools.lru_cache(maxsize=4096)
def _label_key(label: str) -> str:
    return " ".join(_LABEL_NOISE_RE.sub(" ", label).casefold().split())


# A column that holds the street's name alone, or the house number alone ("straat" and "huisnummer" in a Dutch
# export): parts of an address, typed as one.
_STREET_LABELS = frozenset(
    """straat straatnaam street streetname street name street_name straße strasse straßenname strassenname rue
    nom de rue calle nombre de la calle via rua ulica utca iela gatvė strada stradă street line address line 1
    adresregel""".replace("street name", "street_name").split()
) | {"street name", "nom de rue", "nombre de la calle", "address line 1"}
_NUMBER_LABELS = frozenset(
    {
        "huisnummer",
        "huisnr",
        "huisnummer toevoeging",
        "toevoeging",
        "huisletter",
        "house number",
        "house no",
        "housenumber",
        "house nr",
        "building number",
        "buildingnumber",
        "street number",
        "streetnumber",
        "hausnummer",
        "hausnr",
        "numéro de rue",
        "numero civico",
        "número exterior",
        "número de casa",
        "nº",
        "номер дома",
    }
)
_HOUSE_NUMBER_CELL_RE = re.compile(
    r"\d{1,5}(?:[ \t]?[A-Za-z]{1,3}|[ \t]?[\-/][ \t]?\d{1,4}[A-Za-z]?|[ \t](?:bis|hs|huis|I{1,3}|IV|rood|zw))?"
)


@functools.lru_cache(maxsize=4096)
def street_label(label: str) -> bool:
    return _label_key(label).replace("_", " ") in _STREET_LABELS or _label_key(label) in _STREET_LABELS


@functools.lru_cache(maxsize=4096)
def number_label(label: str) -> bool:
    return _label_key(label).replace("_", " ") in _NUMBER_LABELS


def table_street(text: str, start: int, end: int) -> bool:
    """A street's name alone: capitalised words, perhaps with small words between ("Laan van Meerdervoort")."""
    cell = text[start:end].strip()
    if not cell or len(cell) > 60 or any(c in cell for c in "@/:=") or cell.casefold() in _NOT_A_PLACE:
        return False
    return table_address(text, start, end) or bool(re.fullmatch(_NAME, cell))


def table_house_number(text: str, start: int, end: int) -> bool:
    return _HOUSE_NUMBER_CELL_RE.fullmatch(text[start:end].strip()) is not None


@functools.lru_cache(maxsize=4096)
def address_label(label: str) -> bool:
    """Whether a table column or row label names a postal address ("Address", "Mailing Address", "Anschrift"), and
    not an e-mail, IP or wallet address."""
    key = _label_key(label)
    if not key or len(key) > 40:
        return False
    if _ADDRESS_LABEL_FULL_RE.fullmatch(key):
        return True
    m = _ADDRESS_WORD_RE.search(key)
    return m is not None and len(key.split()) <= 4 and _NOT_POSTAL.search(key[: m.start()]) is None


@functools.lru_cache(maxsize=4096)
def place_label(label: str) -> bool:
    """Whether a table column or row label names a town, region or country."""
    return _label_key(label) in _PLACE_LABELS


def table_address(text: str, start: int, end: int) -> bool:
    """Whether a cell under an address label holds one: a number and words, not an e-mail, link or date."""
    cell = text[start:end]
    if not 5 <= len(cell) <= 160 or "@" in cell or "://" in cell:
        return False
    if _CJK_ANY_RE.search(cell) is not None:
        return True
    return _STREET_WORD_RE.search(cell) is not None and _has_number(cell)  # "0x7ffd5a2c" has no word in it


def table_place(text: str, start: int, end: int) -> bool:
    """Whether a cell under a place label holds a place name ("North Carolina", "Saint-Étienne", "NY")."""
    cell = text[start:end].strip(" .")
    if not cell or len(cell) > 50 or cell.casefold() in _NOT_A_PLACE:
        return False
    return _PLACE_CELL_RE.fullmatch(cell) is not None or (
        _CJK_ANY_RE.search(cell) is not None and len(cell) <= 12 and not any(c.isdigit() for c in cell)
    )
