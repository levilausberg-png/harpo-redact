"""Rule-based name cues that complement statistical NER.

Small NER models miss names in short instructions ("Write to Jan de Vries")
and glue the leading verb onto a name ("Email Anna" tagged as one PERSON).
These rules fix both with cheap, testable patterns:

- honorifics:        Dr. Emily Watson, Mrs Jansen, Herr Müller
- greetings/sign-off: Dear Anna, Hi Tom, Regards, Lars Eriksen
- person verbs:      email/call/text/ask/tell/remind/write to ... + Name
- name particles:    Jan de Vries, Ludwig van Beethoven, Ana dos Santos

Every candidate must be capitalised and not a common word, so lowercase text
("email support about it") never matches.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterator

from ..entities import EntityType, Span, make_span
from .cjk import find_cjk_names

SOURCE = "name-rule"
_LOWER = "".join(sorted({c for c in map(chr, range(0x250)) if c.islower()}))  # lower-case Latin letters

_TOKEN = r"[^\W\d_][\w'’\-]*"  # regex or label, not a credential  # noqa: S105  # nosec B105
_PARTICLES = ("van", "von", "de", "der", "den", "da", "di", "du", "del", "della", "le", "la", "ten", "ter",
              "bin", "ibn", "al", "dos", "das", "do", "op", "het")  # fmt: skip
_PARTICLE_RE = "(?:" + "|".join(_PARTICLES) + ")"
CUE_VERBS = ("t.a.v.", "t.a.v", "tav", "ter attentie van", "z.h.d.", "zu händen von", "zu händen", "z. hd.",
             "email", "e-mail", "call", "phone", "text", "ask", "tell", "message", "ping", "remind", "thank",
             "invite", "contact", "assist", "notify", "meet", "pay", "congratulate", "introduce", "interview",
             "onboard", "hire", "write to", "reply to", "respond to", "forward to", "send to", "talk to",
             "speak to", "speak with", "meet with", "on behalf of", "signed by", "my name is", "i'm", "i’m",
             "i am", "call me")  # fmt: skip
GREETINGS = ("hi", "hello", "hey", "dear", "hallo", "beste", "liebe", "lieber", "thanks", "thank you",
             "bedankt", "liebe/r", "lieber/liebe", "sehr geehrte/r", "sehr geehrte", "sehr geehrter", "geehrte/r",
             "estimado/a", "estimada", "estimado", "querido/a", "querida", "querido", "caro/a", "cara", "caro",
             "gentile", "egregio", "egregia", "gentilissimo", "gentilissima", "prezado/a", "prezada", "prezado",
             "cher", "chère", "chers", "chères", "bonjour", "bonsoir", "salut", "hola", "olá", "ciao", "buongiorno",
             "geachte", "kære", "hej", "hei", "moi", "hyvä", "szanowny", "szanowna", "szanowny/a", "drogi", "droga",
             "vážený", "vážená", "vážený/á", "milý", "milá", "spoštovani", "spoštovana", "dragi", "draga",
             "poštovani", "poštovana", "poštovani/a", "kedves", "tisztelt", "stimate", "stimată", "dragă",
             "уважаеми", "уважаема", "скъпи", "скъпа", "αγαπητέ", "αγαπητή", "αξιότιμε", "αξιότιμη", "gerbiamas",
             "gerbiamoji", "gerb.", "brangus", "brangioji", "cienījamais", "cienījamā", "dārgais", "dārgā",
             "lugupeetud", "kallis", "kepada", "yth.", "yang terhormat", "halo", "kính gửi", "xin chào", "chào",
             "sayın", "merhaba", "sevgili", "mahal na", "kumusta")  # fmt: skip
SIGN_OFFS = ("best regards", "kind regards", "warm regards", "regards", "best", "cheers", "sincerely",
             "groeten", "met vriendelijke groet", "mvg", "mfg")  # fmt: skip
HEADERS = ("from", "to", "cc", "bcc", "attn", "attention", "van", "aan", "name", "full name", "patient", "customer",
           "client", "employee", "applicant", "candidate", "contact person", "attendee", "guest", "first name",
           "given name", "given names", "last name", "surname", "family name", "middle name", "maiden name",
           "forename", "policy holder", "policyholder", "account holder", "cardholder", "card holder", "insured",
           "patient name", "nombre", "nombre completo", "apellido", "apellidos", "nom", "prénom", "nom de famille",
           "nom complet", "vorname", "nachname", "familienname", "vollständiger name", "nome", "nome completo",
           "cognome", "sobrenome", "apelido", "naam", "voornaam", "achternaam", "volledige naam", "navn", "fornavn",
           "efternavn", "mellemnavn", "fulde navn", "namn", "förnamn", "efternamn", "nimi", "etunimi", "sukunimi",
           "imię", "nazwisko", "imię i nazwisko", "jméno", "příjmení", "jméno a příjmení", "meno", "priezvisko",
           "ime", "priimek", "prezime", "ime i prezime", "név", "keresztnév", "vezetéknév", "teljes név", "nume",
           "prenume", "nume complet", "име", "фамилия", "презиме", "имена", "όνομα", "επώνυμο", "ονοματεπώνυμο",
           "vardas", "pavardė", "vardas pavardė", "vārds", "uzvārds", "vārds uzvārds", "eesnimi", "perekonnanimi",
           "nama", "nama lengkap", "pangalan", "buong pangalan", "họ tên", "họ và tên", "tên", "ad", "soyad",
           "ad soyad", "isim", "kontaktperson", "ansprechpartner", "ansprechpartnerin", "titular", "intestatario",
           "titulaire", "persona de contacto", "referente", "beneficiary", "signed", "signature", "cliente", "kunde",
           "klant", "klantnaam", "nome cliente", "nombre del cliente", "nom du client", "kundenname",
           # roles a form or a record names a person by, in the languages above
           "owner", "holder", "registered owner", "vehicle owner", "importer", "exporter", "consignee", "consignor",
           "shipper", "tenant", "landlord", "lessee", "lessor", "buyer", "seller", "purchaser", "borrower",
           "co-borrower", "guarantor", "debtor", "claimant", "subscriber", "member", "student", "worker", "veteran",
           "resident", "occupant", "driver", "passenger", "traveler", "traveller", "visitor", "requester",
           "reporting party", "complainant", "victim", "witness", "suspect", "defendant", "plaintiff", "petitioner",
           "respondent", "heir", "spouse", "parent", "guardian", "parent/guardian", "child", "dependent",
           "emergency contact", "next of kin", "prescriber", "physician", "referring physician", "attending physician",
           "doctor", "preparer", "signatory", "signer", "notary", "agent", "representative", "recipient", "sender",
           "aangever", "verdachte", "getuige", "slachtoffer", "betrokkene", "belanghebbende", "aanvrager", "huurder",
           "verhuurder", "koper", "verkoper", "eigenaar", "houder", "kentekenhouder", "werknemer", "medewerker",
           "behandelaar", "huisarts", "verwijzer", "patiënt", "cliënt", "leerling", "ouder", "verzorger",
           "ouder/verzorger", "voogd", "echtgenoot", "echtgenote", "contactpersoon", "gemachtigde", "ondergetekende",
           "debiteur", "verzekerde", "verzekeringnemer", "begunstigde", "erfgenaam", "deelnemer", "bewoner",
           "afzender", "geadresseerde", "ontvanger", "naam leerling", "naam ouder", "naam patiënt", "naam aanvrager",
           "naam werknemer", "naam huurder", "naam klant", "naam eigenaar", "naam ouder/verzorger", "mieter",
           "vermieter", "käufer", "verkäufer", "eigentümer", "halter", "fahrzeughalter", "antragsteller",
           "arbeitnehmer", "mitarbeiter", "versicherter", "versicherungsnehmer", "kontoinhaber", "inhaber",
           "schuldner", "zeuge", "geschädigter", "absender", "empfänger", "teilnehmer", "schüler",
           "erziehungsberechtigter", "ehepartner", "unterzeichner", "bevollmächtigter", "locataire", "bailleur",
           "propriétaire", "acheteur", "vendeur", "demandeur", "salarié", "employé", "assuré", "souscripteur",
           "bénéficiaire", "témoin", "victime", "expéditeur", "destinataire", "élève", "étudiant", "conjoint",
           "signataire", "mandataire", "arrendatario", "arrendador", "inquilino", "propietario", "comprador",
           "vendedor", "solicitante", "empleado", "trabajador", "paciente", "asegurado", "tomador", "beneficiario",
           "testigo", "remitente", "destinatario", "alumno", "estudiante", "cónyuge", "firmante", "apoderado",
           "conduttore", "locatore", "proprietario", "acquirente", "venditore", "richiedente", "dipendente",
           "assicurato", "contraente", "testimone", "mittente", "studente", "coniuge", "firmatario")  # fmt: skip
HONORIFICS = ("mr", "mrs", "ms", "mx", "miss", "dr", "prof", "sir", "dame", "madam", "mevrouw", "meneer",
              "dhr", "mevr", "de heer", "heer", "mej", "juffrouw", "drs", "herr", "frau", "mme", "mlle", "fräulein",
              "señor", "señora", "señorita", "doña",
              "signor", "signore", "signora", "signorina", "sig.ra", "sig.na", "dott", "dott.ssa", "prof.ssa",
              "monsieur", "madame", "mademoiselle", "maître", "senhor", "senhora", "gospod", "gospa", "gospodin",
              "gospođa", "gospođica", "gđa", "gđica", "panna", "slečna", "domnul", "doamna", "domnișoara",
              "господин", "госпожа", "госпожица", "г-н", "г-жа", "κύριος", "κυρία", "κος", "δεσποινίς", "ponas",
              "ponia", "panelė", "härra", "proua", "preili", "bapak", "saudara", "saudari", "encik", "puan",
              "tuan", "ginoong", "ginang", "binibini", "herra", "rouva", "neiti", "fröken", "frøken", "hölgy",
              "asszony", "frk", "hra", "prl", "spett.le", "gospodine", "gospođo", "gospođice", "gospodična",
              "gospa", "vážený pane", "vážená paní")  # fmt: skip
# Short titles that are also everyday words or codes ("HR", "pan", "me"): only as written, capitalised.
CASED_HONORIFICS = ("Hr", "Fr", "Fru", "Sr", "Sra", "Srta", "Sig", "M.", "Pan", "Pani", "Pán", "Paní", "G.", "Ga.",
                    "Úr", "Dl.", "Dna.", "Κα", "Pn", "Pnia", "Rva", "Nti", "Bpk.", "Ibu", "Sdr.", "Sdri.", "En.",
                    "Cik", "Tn.", "Gng.", "Bb.", "Ông", "Bà", "Anh", "Chị", "Dona", "Don", "Mw.", "Mej.",
                    "Hgy", "Asz", "Pane", "Panie")  # fmt: skip
# Labels that name a person, whose value may also stand in brackets: "Vorname (Hanna), Nachname (Sommer)".
NAME_LABELS = ("name", "full name", "first name", "given name", "given names", "last name", "surname",
               "family name", "middle name", "maiden name", "forename", "nombre", "apellido", "apellidos", "nom",
               "prénom", "vorname", "nachname", "familienname", "nome", "cognome", "sobrenome", "naam", "voornaam",
               "achternaam", "navn", "fornavn", "efternavn", "namn", "förnamn", "efternamn", "nimi", "etunimi",
               "sukunimi", "imię", "nazwisko", "jméno", "příjmení", "meno", "priezvisko", "ime", "priimek",
               "prezime", "név", "keresztnév", "vezetéknév", "nume", "prenume", "име", "фамилия", "όνομα", "επώνυμο",
               "vardas", "pavardė", "vārds", "uzvārds", "eesnimi", "perekonnanimi", "nama", "pangalan",
               "họ tên", "tên", "ad", "soyad")  # fmt: skip
# Titles written after the name: "Kovács Péter úr", "Bērziņa kundze", "Tanaka-san", "Ahmet Bey".
AFTER_NAME = ("úr", "asszony", "kisasszony", "kungs", "kundze", "san", "sama", "kun", "chan", "bey", "hanım",
              "efendi")  # fmt: skip

# Capitalised words that follow a cue but are not names.
_STOP = frozenset(
    w.casefold()
    for w in (
        "I", "The", "A", "An", "All", "Everyone", "Everybody", "Anyone", "Someone", "Team", "Teams", "Support",
        "Sales", "Customer", "Customers", "Client", "Clients", "Them", "Him", "Her", "Us", "Me", "It", "This",
        "That", "These", "Those", "My", "Our", "Your", "Their", "His", "Its", "Legal", "Finance", "Marketing",
        "Engineering", "Management", "Admin", "Today", "Tomorrow", "Yesterday", "Now", "Later", "Again",
        "Please", "Back", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
        "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
        "November", "December", "Mr", "Mrs", "Ms", "Dr", "Prof", "Sir", "Dear", "Hi", "Hello", "Thanks",
        "Regards", "Best", "Cheers", "Sincerely", "Help", "Info", "Office", "Desk", "Service", "Services",
        "Department", "Group", "Board", "Manager", "Managers", "Staff", "Users", "User", "Example", "Details",
        "Let", "Free", "More", "Each", "Every", "Both", "Some", "Any", "No", "Not", "And", "Or", "But", "If", "When",
        "Number", "Numbers", "Name", "Names", "Address", "Addresses", "Email", "Phone", "Date", "Dates", "Code",
        "Codes",
        "Account", "Accounts", "Type", "Status", "Information", "Contact", "Contacts", "Access", "Subject", "Message",
        "What", "Who", "How", "Why", "Where", "Which", "Here", "There", "Yes", "Ok", "Okay", "Note", "Notes",
        "Gmail", "Outlook", "Slack", "Teams", "Zoom", "Google", "Microsoft", "Apple", "Amazon", "Openai",
        "Anthropic", "Claude", "Chatgpt", "Gemini",
        # what a greeting addresses when it is not a person ("Liebe Grüße", "Sehr geehrte Damen und Herren")
        "Grüße", "Grüsse", "Gruß", "Gruss", "Damen", "Herren", "Kollegen", "Kolleginnen", "Kunden", "Kundinnen",
        "Kundin", "Kunde", "Freunde", "Leser", "Leserinnen", "Eltern", "Familie", "Mitglieder", "Teilnehmer",
        "Teilnehmende", "Mitarbeiter", "Mitarbeitende", "Kinder", "Studierende", "Gemeinde", "Nachbarn", "Gäste",
        "Interessierte", "Groeten", "Collega", "Collega's", "Klant", "Équipe", "Equipo", "Señores", "Clientes",
        "Cliente", "Amigos", "Amici", "Colleghi", "Signori", "Kolleger", "Venner", "Vänner", "Kollegor", "Valued",
        "Esteemed", "Colleagues", "Members", "Friends", "Parents", "Students", "Partners", "Applicant",
        "Candidate", "Hiring", "Reader", "Readers", "Sir/Madam", "Status", "Error", "Warning", "Info", "Debug",
        "Subject", "Re", "Fwd", "Date", "Time", "Total", "Result", "Output", "Input", "Response", "Request",
        "Assistant", "System", "Bot", "Agent", "Server", "Host", "Question", "Answer", "Summary", "Update",
        "Reminder", "Action", "Decision", "Agenda", "Location", "Topic", "Title", "Message", "Comment", "Reply",
        "Source", "Model", "Prompt", "Context", "Task", "Goal", "Example", "Step",
        # words that start a sentence after a greeting or a sign-off without being one ("Thanks! For ...")
        "For", "From", "With", "About", "After", "Before", "By", "On", "In", "At", "Of", "To", "As", "Into", "Over",
        "Under", "Than", "Then", "While", "Since", "Until", "Per", "Via", "Voor", "Met", "Over", "Na", "Uit", "Door",
        "Om", "Tot", "Für", "Mit", "Über", "Nach", "Bei", "Auf", "Aus", "Durch", "Um", "Zu", "Pour", "Avec", "Sans",
        "Dans", "Sur", "Para", "Con", "Sin", "Per", "Senza",
    )
)  # fmt: skip


# Words that name a kind of document, in the languages Harpo reads. A title ("Application to Register Permanent
# Residence", "Verklaring van Geschiktheid", "NEW PATIENT INTAKE FORM") is not a person, a place or an organisation.
DOCUMENT_WORDS = frozenset(
    """form forms application notice report statement invoice certificate agreement contract summary request
    declaration petition affidavit receipt registration renewal questionnaire checklist worksheet memorandum minutes
    transcript handbook waiver authorization authorisation disclosure intake
    formulier aanvraag verklaring aangifte factuur offerte overeenkomst rapport verslag besluit beschikking uittreksel
    attest akte opgave melding registratie machtiging toestemming
    formular antrag erklärung erklaerung bescheinigung rechnung vertrag vereinbarung protokoll bescheid nachweis
    urkunde anmeldung abmeldung vollmacht einwilligung
    formulaire demande déclaration declaration attestation facture contrat certificat relevé procuration
    formulario solicitud declaración certificado factura contrato informe
    modulo domanda dichiarazione certificato fattura contratto""".split()  # noqa: SIM905
)


def _alt(words: tuple[str, ...]) -> str:
    return "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in sorted(set(words), key=len, reverse=True))


def _first_letters(words: tuple[str, ...]) -> str:
    """A lookahead for the letters the words start with. In front of a case-insensitive list of words it rules out
    most positions with one test, where the list would try every word; it matches nothing the list would not."""
    return "(?=[" + "".join(sorted({re.escape(w[0].lower()) for w in words})) + "])"


_CUE_RE = re.compile(
    r"(?<![\w-])(?:"
    rf"(?P<hon>{_alt(HONORIFICS)})(?!\w)\.?"
    rf"|(?P<greet>{_alt(GREETINGS)})(?!\w)[,!:]?"
    rf"|(?P<signoff>{_alt(SIGN_OFFS)})(?!\w)[ \t]*[,!]"
    rf"|(?P<hdr>{_alt(HEADERS)})(?!\w)(?:[ \t]*\([^()\n]{{1,30}}\))?[*_]{{0,3}}[ \t]*[:：][*_]{{0,3}}"
    rf"|(?P<verb>{_alt(CUE_VERBS)})(?!\w):?"
    rf")[ \t]*(?:\n[ \t]*){{0,2}}[*_]{{0,3}}(?P<name>(?:[^\W\d_]\.[ \t]?){{0,4}}{_TOKEN}(?:\.?[ \t]+{_TOKEN}){{0,4}})",
    re.IGNORECASE,
)
_PARTICLE_NAME_RE = re.compile(
    rf"(?<![\w-])(?P<name>{_TOKEN}(?:[ \t]+{_PARTICLE_RE})+[ \t]+{_TOKEN}(?:[ \t]+{_TOKEN})?)"
)  # a name never runs over a line break
_WORD_RE = re.compile(_TOKEN)
_PARTICLE_SET = frozenset(_PARTICLES)
_LEADING_CUES = frozenset(w for w in CUE_VERBS + GREETINGS + HONORIFICS if " " not in w)
_TITLES = frozenset(h.casefold().rstrip(".") for h in HONORIFICS + CASED_HONORIFICS)


def _cased(word: str) -> str:
    return re.escape(word) + ("" if word.endswith(".") else r"(?!\w)\.?")


_CASED_HON_RE = re.compile(
    r"(?<![\w-])(?:" + "|".join(_cased(h) for h in sorted(CASED_HONORIFICS, key=len, reverse=True)) + r")"
    rf"[ \t]+(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,4}})"
)
# A chat transcript's speaker: "[10:42] Anna Weber: ...", "11:44 PM Anna: ...", or a name before a quote
# ('Anna Weber: "Sure."'). Field labels ("Status:", "Project Manager:") have neither.
_SPEAKER_RE = re.compile(
    r"(?m)^[ \t>*\-]*(?P<ts>\[?(?:\d{4}-\d{2}-\d{2}[ T])?\d{1,2}[:.]\d{2}(?::\d{2})?(?:[ \t]?[AaPp]\.?[Mm]\.?)?\]?"
    r"[ \t]*[-–]?[ \t]*)?"
    rf"(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,3}})[ \t]*:[ \t]+(?P<quote>[\"'“‘«„「『])?"
)
# What a quote holds when it is a value in code, not speech: one token in lower case or with underscores, closed at
# the end of the line ('Namespace: "ferropoint",', 'Subsystem: "event_ingestion",').
_CODE_VALUE_RE = re.compile(
    r"(?<=[\"'“‘«„])(?:[a-z0-9][\w.\-/]{0,80}|[A-Za-z]\w{0,40}_[\w.\-/]{0,80})[\"'][ \t]{0,4}[,;]?[ \t]{0,4}(?:\n|$)"
)
# A label after a cue is the next field, not the value: "Last Name(s):\nSex: ( ) Male", "EMAIL ADDRESS: ...".
_NEXT_LABEL_AFTER_RE = re.compile(r"(?<=\w)[ \t]{0,4}(?:\([^()\n]{1,6}\)[ \t]{0,4})?[:：]")
# "I, Anna Weber, hereby ...", "Ich, Anna Weber, geboren ...", "Je, soussigné(e) ..." is not a name.
_SELF_RE = re.compile(
    r"(?<!\w)(?:I|Ich|Je|Yo|Io|Eu|Ik|Jeg|Jag|Minä|Ja|Já|Jaz|Én|Aš|Es|Mina|Saya|Ako|Tôi|Ben|Εγώ|Аз|Я)[ \t]*,[ \t]*"
    rf"(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,5}})[ \t]*,"
)
_PRONOUNS = frozenset(
    "I Ich Je Yo Io Eu Ik Jeg Jag Minä Ja Já Jaz Én Aš Es Mina Saya Ako Tôi Ben Εγώ Аз Я We Wir Nous Wij".split()  # noqa: SIM905
)
_AFTER_NAME_RE = re.compile(r"(?<=[ \t\-])(?:" + "|".join(AFTER_NAME) + r"|Bey|Hanım|Efendi)(?![\w])")
# Chinese, Japanese and Korean names by the title after them: 田中さん, 王先生, 김민수 씨.
_HAN = "\u4e00-\u9fff"
_JA_NAME_RE = re.compile(
    rf"(?P<name>[{_HAN}]{{2,4}}(?:[ \u3000][{_HAN}]{{1,4}})?|[\u30a0-\u30ff]{{2,10}})"
    r"(?:さん|様|さま|くん|君|ちゃん|殿|氏)"
)
_ZH_NAME_RE = re.compile(rf"(?P<name>[{_HAN}]{{1,3}})(?:先生|女士|小姐|老师|老師|同学|同學|医生|醫生|教授|经理|經理)")
# A Korean name, its title, then at most a particle ("김민지 씨에게", "박준호 님께").
_KO_NAME_RE = re.compile(
    r"(?<![\uac00-\ud7af])(?P<name>[\uac00-\ud7af]{2,4})[ \t]?(?:씨|님)(?=[\uac00-\ud7af]{0,3}(?:[^\uac00-\ud7af]|$))"
)
# A chat message that ends with a sign-off and a first name, without the comma of a letter: "groetjes Tess",
# "xx Fleur", "thx Bram".
_CHAT_SIGNOFFS = (
    "groetjes", "groeten", "groet", "gr.", "liefs", "kusjes", "knuffels", "xx", "xoxo", "doei", "mvg", "mfg", "lg",
    "vg", "cheers", "thanks", "thx", "tnx", "bedankt", "dankjewel", "danke", "merci", "gracias", "grazie", "ciao",
    "tschüss",
)  # fmt: skip
_CHAT_SIGNOFF_RE = re.compile(
    _first_letters(_CHAT_SIGNOFFS)
    + r"(?<!\w)(?:groetjes|groeten|groet|gr\.|liefs|kusjes|knuffels|xx+|xoxo|doei|mvg|mfg|lg|vg|cheers|thanks|thx"
    r"|tnx|bedankt|dankjewel|danke|merci|gracias|grazie|ciao|tschüss)"
    rf"[ \t,!.]+(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN})?)[ \t.!]*$",
    re.IGNORECASE | re.MULTILINE,
)
# A name on the line above a postal address, as a letter or an invoice heads one: the name, then a street line with a
# house number, then the postcode and town ("Lukas Becker\nAm Markt 84\n70173 Stuttgart"; "John Smith\n12 Oak St\n
# Springfield, IL 62704").
_ADDRESS_BLOCK_RE = re.compile(
    rf"(?m)^[ \t]*(?P<name>{_TOKEN}\.?(?:[ \t]+{_TOKEN}\.?){{1,4}})[ \t]*\n"
    r"[ \t]*(?:[^\W\d_][^\n]{1,60}?[ \t]\d{1,5}[^\n]{0,12}|\d{1,6}[ \t]+[^\W\d_][^\n]{2,60})\n"
    r"[ \t]*(?:(?:[A-Z]{1,2}-)?\d{4,5}(?:-\d{3})?(?:[ \t]?[A-Z]{2})?[ \t]+[^\W\d_]"
    r"|[^\W\d_][^\n,]{1,40},[ \t]*[A-Z]{2}[ \t]+\d{5})"
)
# An electronic signature in a filing: "/s/ Jane Q. Public".
_SIGNED_RE = re.compile(rf"(?<!\S)/s/[ \t]+(?P<name>{_TOKEN}\.?(?:[ \t]+{_TOKEN}\.?){{0,4}})")
_BRACKET_LABEL_RE = re.compile(
    _first_letters(NAME_LABELS)
    + rf"(?<![\w-])(?:{_alt(NAME_LABELS)})[ \t]*\([ \t]*(?P<name>{_TOKEN}(?:[ \t]+{_TOKEN}){{0,4}})[ \t]*\)",
    re.IGNORECASE,
)
_CJK_LABEL_RE = re.compile(
    rf"(?:氏名|お名前|名前|姓名|名字|이름|성명)[ \t]*[:：][ \t]*(?P<name>[{_HAN}\u3040-\u30ff\uac00-\ud7af]{{1,6}}"
    rf"(?:[ \t\u3000][{_HAN}\u3040-\u30ff\uac00-\ud7af]{{1,6}})?)"
)
# Words before such a title that are not names: "皆様", "患者様", "这位先生", "고객님".
_CJK_NOT_NAMES = frozenset(
    """皆 お客 客 患者 社長 部長 課長 先生 生徒 学生 店長 会員 利用者 担当者 関係者 各位 運転手 奥 旦那 子供 お子
    家族 这位 那位 各位 诸位 该 此 某 老 小 大 男 女 年轻 一位 两位 这 那 每位 该位 本 고객 회원 선생 교수 사장
    부장 과장 대리 팀장 원장 실장 이사 대표 기사 여러분 손님 환자 학생 형 누나 언니 오빠 어머니 아버지 할머니
    할아버지 엄마 아빠 담당자 관리자 작가 의사 간호사 박사 목사 신부 수녀 스님 회장 총장 소장 국장 차장 주임 반장
    점장 매니저 선배 후배 동생 친구 아드님 따님 부모 남편 아내 사용자 이용자 구매자 판매자 신청자 참가자 여러분들
    아저 아가 아주머 하느 임금 부처 사모 시어머 장모 장인 교장 의원 대통령 장관 위원장 선교사 집사 권사
    장로 목자""".split()  # noqa: SIM905
)  # fmt: skip
# Chinese has no spaces: a name before 先生 or 女士 starts at a family name. The most common family names (about nine
# in ten people carry one of these).
_ZH_SURNAMES = frozenset(
    "王李张張刘劉陈陳杨楊黄黃赵趙吴吳周徐孙孫马馬朱胡郭何林罗羅高郑鄭梁谢謝宋唐许許韩韓冯馮邓鄧曹彭曾肖萧蕭田董潘袁蔡蒋蔣余于杜叶葉"
    "程魏苏蘇吕呂丁任卢盧姚沈钟鍾姜崔谭譚陆陸范汪廖石金韦韋贾賈夏付方邹鄒熊白孟秦邱侯江尹薛闫閆段雷龙龍黎史陶贺賀毛郝顾顧龚龔邵"
    "万萬覃武钱錢戴严嚴莫孔向常汤湯康易乔喬赖賴文施洪辛柯庄莊"
)


_CONTRACTION_RE = re.compile(r"['’](?:m|ve|ll|re|d|t)$", re.IGNORECASE)
_POSSESSIVE_END_RE = re.compile(r"['’]s$", re.IGNORECASE)


def _is_name_word(word: str) -> bool:
    core = word.rstrip("'’")
    if not core or _CONTRACTION_RE.search(core):  # I'm, We've, They'll, Don't
        return False
    base = _POSSESSIVE_END_RE.sub("", core)  # It's -> It, Anna's -> Anna
    if not base or any(c.isdigit() for c in base):  # "notify BUPERS-04M": a code, names hold no digits
        return False
    folded = base.casefold()
    short_caps = base.isupper() and len(base) <= 2
    return base[0].isupper() and folded not in _STOP and folded not in DOCUMENT_WORDS and not short_caps


def _name_extent(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Longest run of capitalised words (particles allowed between them). Titles in front are left out:
    "Sehr geehrte Frau Dr. Anna Weber" is "Anna Weber"."""
    words = [(m.start() + start, m.end() + start, m.group()) for m in _WORD_RE.finditer(text[start:end])]
    while len(words) > 1:
        if words[0][2].casefold().rstrip(".") in _TITLES:
            words = words[1:]
        elif len(words) > 2 and f"{words[0][2]} {words[1][2]}".casefold() in _TITLES:  # "de heer", "vážený pane"
            words = words[2:]
        else:
            break
    # Initials first ("J. de Boer", "R.J. van der Wal"): the name starts with them and its surname follows them.
    lead = 0
    while lead < len(words) and _initial(text, words[lead]):
        lead += 1
    first = lead
    while lead and first < len(words) - 1 and words[first][2].casefold() in _PARTICLE_SET:
        first += 1
    if lead and (first >= len(words) or not _is_name_word(words[first][2])):
        return None
    if not words or not _is_name_word(words[first][2]):
        return None
    last = first
    titled = not words[first][2].isupper()
    for i in range(first + 1, len(words)):
        word = words[i][2]
        between = text[words[i - 1][1] : words[i][0]]
        if "\t" in between or "  " in between or (between.startswith(".") and len(words[i - 1][2]) > 1):
            break  # a field ends at a tab or two blanks ("Dr. Mary Lopez  NPI 123"), a sentence at its full stop
        if titled and word.isupper() and len(word) > 1:
            break  # "Mary Lopez NPI": a code in capitals after a name written in title case
        if _is_name_word(word):
            last = i
        elif word.casefold() in _PARTICLE_SET and i + 1 < len(words):
            continue
        elif len(word) == 1 and word.isupper() and text[words[i][1] : words[i][1] + 1] == "." and i + 1 < len(words):
            continue  # a middle initial: "Thistle J. Arbuthnot"
        else:
            break
    first_start = words[0][0]
    last_end = words[last][1]
    # Drop a trailing possessive so "Anna's" redacts as "Anna".
    surface = text[first_start:last_end]
    for suffix in ("'s", "’s"):
        if surface.endswith(suffix):
            last_end -= len(suffix)
    return first_start, last_end


def _initial(text: str, word: tuple[int, int, str]) -> bool:
    """A capital letter with its full stop: "J.", the "R" and "J" of "R.J."."""
    return len(word[2]) == 1 and word[2].isupper() and text[word[1] : word[1] + 1] == "."


# "Lewis, Kevin", "Veen, Joost van der": a name written surname first, as registers and forms list people. Only
# after a label, and only up to the end of the field, so a list ("Smith, Jones and Brown") is not one.
_CAP_TOKEN = rf"(?=[^\W\d_])(?![{_LOWER}])[\w'’\-]+"
_INVERTED_RE = re.compile(
    rf",[ \t]+(?P<given>{_CAP_TOKEN}\.?(?:[ \t]+{_CAP_TOKEN}\.?){{0,2}})(?:[ \t]+{_PARTICLE_RE}){{0,3}}"
    r"(?=[ \t]*(?:[,;|\n]|$)|[ \t]{2}|\t)"
)
# A name that an identifier or a birth date follows, set off by a comma or a bracket: "Fleur Peters, BSN 156118907",
# "Veenstra, Joost, geb. 18-8-1940", "Jane Doe (DOB 03/14/1985)". Registers, letters and case notes write people so.
_APPOSITION_CUE = (
    r"(?i:bsn|ssn|sofi|dob|d\.o\.b\.?|geb\.|geboren|born|date of birth|n[ée]e? le|nato|nata|nacid[oa]|geburtsdatum|mrn"
    r"|patiëntnummer|patientnummer|patient id|pid|nino|nhs|pesel|nif|nie|dni|cpr)(?![\w])"
)
_APPOSITION_RE = re.compile(
    rf"(?<![\w.])(?P<name>{_CAP_TOKEN}(?:[ \t]+(?:{_PARTICLE_RE}[ \t]+)*{_CAP_TOKEN}){{0,3}}"
    rf"(?:,[ \t]+{_CAP_TOKEN}(?:[ \t]+{_CAP_TOKEN})?(?:[ \t]+{_PARTICLE_RE}){{0,3}})?)"
    rf"(?:,[ \t]*|[ \t]+\([ \t]*){_APPOSITION_CUE}"
)
# The comma or bracket and the word after it, looked for first: most text has none, and the full pattern tries every
# capitalised word.
_APPOSITION_CUE_RE = re.compile(rf"[,(][ \t]*{_APPOSITION_CUE}")


def _inverted_end(text: str, end: int) -> int:
    m = _INVERTED_RE.match(text, end)
    if m is None or not all(_is_name_word(w) or len(w.rstrip(".")) == 1 for w in m.group("given").split()):
        return end
    return m.end()


def _span(text: str, start: int, end: int, confidence: float) -> Span:
    surface = " ".join(text[start:end].split())
    return make_span(start, end, EntityType.PERSON, SOURCE, surface.casefold(), confidence)


def find_name_cues(text: str) -> Iterator[Span]:
    emitted: set[tuple[int, int]] = set()
    for span in _find_name_cues(text):
        if (span.start, span.end) not in emitted:
            emitted.add((span.start, span.end))
            yield span


def _extra_name_cues(text: str) -> Iterator[Span]:
    afters: list[re.Match[str]] = []
    for w in _WORD_RE.finditer(text):
        word = w.group()
        if word in _CASED_FIRST_WORDS:
            m = _CASED_HON_RE.match(text, w.start())
            if m is not None:
                extent = _name_extent(text, m.start("name"), m.end("name"))
                if extent is not None:
                    yield _span(text, extent[0], extent[1], 0.6)
        elif word in _AFTER_NAME_WORDS:
            m = _AFTER_NAME_RE.match(text, w.start())
            if m is not None:
                afters.append(m)
    if ":" in text:
        for m in _SPEAKER_RE.finditer(text):
            if m.group("ts") is None and m.group("quote") is None:
                continue
            if m.group("ts") is None and _CODE_VALUE_RE.match(text, m.end()):
                continue  # a field of a struct or a config file, not a line of a transcript
            parts = m.group("name").split()
            if not all(p[0].isupper() and not p.isupper() and p.casefold() not in _STOP for p in parts):
                continue
            yield _span(text, m.start("name"), m.end("name"), 0.6)
    if "," in text:
        for m in _SELF_RE.finditer(text):
            extent = _name_extent(text, m.start("name"), m.end("name"))
            if extent is not None and extent[1] == m.end("name"):
                yield _span(text, extent[0], extent[1], 0.6)
    if ("," in text or "(" in text) and _APPOSITION_CUE_RE.search(text):
        for m in _APPOSITION_RE.finditer(text):
            name_start, name_end = m.start("name"), m.end("name")
            extent = _name_extent(text, name_start, name_end)
            if extent is None:
                continue
            rest = text[extent[1] : name_end].replace(",", " ").split()
            if not all(w.casefold() in _PARTICLE_SET for w in rest):
                continue  # the name must fill the words before the comma
            first_word = text[extent[0] : name_end].replace(",", " ").split()[0]
            if first_word in _PRONOUNS:
                continue  # "Ich, Jonas Reiter, geboren ...": a declaration, read by _SELF_RE
            single = len(text[extent[0] : name_end].replace(",", " ").split()) == 1
            if single and not m.group().rstrip()[-3:].isupper():
                continue  # "Amsterdam, born 1985": a lone word before a birth date may be a place
            yield _span(text, extent[0], name_end, 0.6)
    if "\n" in text:
        for m in _ADDRESS_BLOCK_RE.finditer(text):
            extent = _name_extent(text, m.start("name"), m.end("name"))
            if extent is not None and extent[1] == m.end("name"):
                yield _span(text, extent[0], extent[1], 0.6)
    for m in _CHAT_SIGNOFF_RE.finditer(text):
        extent = _name_extent(text, m.start("name"), m.end("name"))
        if extent is not None and extent[1] == m.end("name"):
            yield _span(text, extent[0], extent[1], 0.6)
    if "/s/" in text:
        for m in _SIGNED_RE.finditer(text):
            extent = _name_extent(text, m.start("name"), m.end("name"))
            if extent is not None:
                yield _span(text, extent[0], extent[1], 0.6)
    if "(" in text:
        for m in _BRACKET_LABEL_RE.finditer(text):
            extent = _name_extent(text, m.start("name"), m.end("name"))
            if extent is not None:
                yield _span(text, extent[0], extent[1], 0.6)
    for m in afters:
        words = list(_WORD_RE.finditer(text, max(0, m.start() - 60), m.start()))
        start = None
        for w in reversed(words[-3:]):
            gap = text[w.end() : start if start is not None else m.start()]
            if not _is_name_word(w.group()) or gap.strip(" \t-"):
                break
            start = w.start()
        if start is not None:
            end = m.start()
            while end > start and text[end - 1] in " \t-":
                end -= 1
            yield _span(text, start, end, 0.6)
    if not text.isascii() and _CJK_TEXT_RE.search(text):
        for span in find_cjk_names(text):  # detectors/cjk.py: family names, honorifics, greetings, cue verbs
            yield _span(text, span.start, span.end, 0.6)
        for m in _CJK_LABEL_RE.finditer(text):
            yield _span(text, m.start("name"), m.end("name"), 0.6)
        for pattern in (_JA_NAME_RE, _KO_NAME_RE):
            for m in pattern.finditer(text):
                if m.group("name").replace("\u3000", " ").split()[0] not in _CJK_NOT_NAMES:
                    yield _span(text, m.start("name"), m.end("name"), 0.6)
        for m in _ZH_NAME_RE.finditer(text):
            name, start = m.group("name"), m.start("name")
            first = next((i for i, c in enumerate(name) if c in _ZH_SURNAMES), None)
            if first is not None and name[first:] not in _CJK_NOT_NAMES:
                yield _span(text, start + first, m.end("name"), 0.6)


_CJK_TEXT_RE = re.compile("[\u3040-\u30ff\u4e00-\u9fff\uac00-\ud7af]")


def _first_word(phrase: str) -> str:
    m = _WORD_RE.match(phrase)
    return (m.group() if m else phrase).casefold()


_CUE_FIRST_WORDS = frozenset(_first_word(p) for p in HONORIFICS + GREETINGS + SIGN_OFFS + HEADERS + CUE_VERBS)
_CASED_FIRST_WORDS = frozenset(_WORD_RE.match(h).group() for h in CASED_HONORIFICS)  # type: ignore[union-attr]
_AFTER_NAME_WORDS = frozenset((*AFTER_NAME, "Bey", "Hanım", "Efendi"))


def _find_name_cues(text: str) -> Iterator[Span]:
    yield from _extra_name_cues(text)
    resume = 0
    # The cue pattern is tried only where a word that can start a cue begins: a scan of hundreds of alternatives at
    # every position would cost more than the rest of the layer.
    for w in _WORD_RE.finditer(text):
        if w.start() < resume or w.group().casefold() not in _CUE_FIRST_WORDS:
            continue
        m = _CUE_RE.match(text, w.start())
        if m is None:
            continue
        extent = _name_extent(text, m.start("name"), m.end("name"))
        if extent is not None and (m.group("hdr") or m.group("verb")) and _NEXT_LABEL_AFTER_RE.match(text, extent[1]):
            extent = None  # "Last Name(s):\nSex: ( ) Male", "EMAIL ADDRESS:": an empty field, then the next label
        if extent is not None and m.group("hdr") == "name" and " " not in text[extent[0] : extent[1]].strip():
            extent = None  # "- name: Checkout": a config key in lower case names a step, a job or a service
        if extent is None:
            # The words after the cue may hold the next cue ("Hi team, email Anna").
            resume = m.start("name")
            continue
        end = _inverted_end(text, extent[1]) if m.group("hdr") else extent[1]
        yield _span(text, extent[0], end, 0.6)
        resume = end
    for m in _PARTICLE_NAME_RE.finditer(text):
        extent = _name_extent(text, m.start("name"), m.end("name"))
        if extent is None:
            continue
        surface = text[extent[0] : extent[1]]
        if any(w.casefold() in _PARTICLE_SET for w in surface.split()[1:-1]):
            yield _span(text, extent[0], extent[1], 0.6)


# --------------------------------------------------------------------------- table columns (detectors/fields.py)
# A table column or row label that holds a person's name: a name label ("Last Name", "Nachname"), a person's role
# ("Patient", "Policyholder") or both ("Insured's Last Name", "Emergency Contact Name"). A role alone may hold an id
# or a company, so it takes a full name. A bare English "Name" also heads columns of products and files: it takes a
# full name in a table that is about people (detectors/fields.py decides).
_NOT_ROLES = frozenset({"from", "to", "cc", "bcc", "attn", "attention", "van", "aan", "signed", "signature"})
_ROLES = frozenset(h for h in HEADERS if h not in _NOT_ROLES and h not in NAME_LABELS) | frozenset(
    """contact, emergency contact, member, subscriber, student, parent, guardian, spouse, partner, recipient, sender,
    physician, doctor, nurse, owner, holder, tenant, landlord, buyer, seller, passenger, participant, witness, signer,
    signatory, driver, manager, supervisor, representative, technician, inspector, officer, investigator, reviewer,
    approver, requester, assignee, reporter, claimant, plaintiff, defendant, borrower, lender, cosigner, co-signer,
    dependent, caregiver, primary insured, insured person, next of kin""".replace("\n", " ").split(", ")
)
_NAME_LABEL_SET = frozenset(NAME_LABELS)
_LABEL_NOISE_RE = re.compile(r"\([^()]{0,40}\)|['’]s\b|[*_#:`|]+")
# Cell contents that fill a name column without being a name.
_NOT_A_NAME = frozenset(
    "unknown none null nil tbd tba pending anonymous redacted withheld other self various n/a na nn".split()  # noqa: SIM905
)


@functools.lru_cache(maxsize=4096)
def person_label(label: str) -> tuple[int, bool] | None:
    """(the fewest words a name under this table label needs, whether the table must be about people), or None
    when the label does not name a person."""
    words = _LABEL_NOISE_RE.sub(" ", label).casefold().split()
    if not words or len(words) > 5:
        return None
    key = " ".join(words)
    if key == "name":
        return 2, True
    if key in _NAME_LABEL_SET:
        return 1, False
    if key in _ROLES:
        return 2, False
    for n in (3, 2, 1):
        if len(words) > n and " ".join(words[-n:]) in _NAME_LABEL_SET and " ".join(words[:-n]) in _ROLES:
            return 1, False
    return None


def table_name(text: str, start: int, end: int, least: int) -> bool:
    """Whether a table cell holds a person's name and nothing else: "Joshua", "Heather Buckner", "VERMEULEN"."""
    cell = text[start:end]
    if not cell or len(cell) > 60 or any(c.isdigit() for c in cell) or "@" in cell:
        return False
    extent = _name_extent(text, start, end)
    if extent is None:
        return False
    rest = text[extent[1] : end].strip(" .,'’")
    if rest and not all(w.casefold() in _PARTICLE_SET for w in rest.split()):
        return False  # "Vries, Jan de": the particles of a surname written first may close the cell
    words = text[extent[0] : extent[1]].replace(",", " ").split()
    return least <= len(words) <= 5 and not any(w.casefold().strip(".") in _NOT_A_NAME for w in words)


def strip_leading_cue(text: str, start: int, end: int) -> tuple[int, int] | None:
    """Remove a cue verb or greeting glued to the front of an NER person span."""
    m = _WORD_RE.match(text, start, end)
    if m is None or m.group().casefold() not in _LEADING_CUES:
        return start, end
    rest = m.end()
    while rest < end and text[rest] in " \t,":
        rest += 1
    return (rest, end) if rest < end else None
