"""RegionBench documents: Dutch, US and EU text with every sensitive value marked.

Each template writes one kind of document (a letter, a form, an invoice, a chat, a JSON record, a CSV export, a log)
the way people write it, and marks each value it puts in with its type. Words that must come through unchanged are
marked as keeps. Templates are split once, before any result was seen, into a dev set (failures are studied here)
and a holdout set (only ever counted): the holdout number says whether a fix generalises to phrasing it was not
written against.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from dataclasses import dataclass, field

import values as V


@dataclass
class Value:
    kind: str  # "nl.bsn", "us.ssn", "eu.vat"...
    start: int
    end: int


@dataclass
class B:
    """A document being written: text, the values in it and the phrases that must survive."""

    parts: list[str] = field(default_factory=list)
    values: list[Value] = field(default_factory=list)
    keeps: list[tuple[int, int]] = field(default_factory=list)

    @property
    def pos(self) -> int:
        return sum(len(p) for p in self.parts)

    def t(self, text: str) -> B:
        self.parts.append(text)
        return self

    def v(self, kind: str, value: str) -> B:
        start = self.pos
        self.parts.append(value)
        self.values.append(Value(kind, start, start + len(value)))
        return self

    def k(self, text: str) -> B:
        start = self.pos
        self.parts.append(text)
        self.keeps.append((start, start + len(text)))
        return self

    @property
    def text(self) -> str:
        return "".join(self.parts)


Template = Callable[[random.Random], B]
TEMPLATES: dict[str, tuple[str, str, Template]] = {}  # id -> (region, set, template)


def template(tid: str, region: str, split: str) -> Callable[[Template], Template]:
    def register(fn: Template) -> Template:
        TEMPLATES[tid] = (region, split, fn)
        return fn

    return register


def _nl_address(r: random.Random) -> tuple[str, str, str, str]:
    return r.choice(V.NL_STREETS), V.nl_house_number(r), V.nl_postcode(r), r.choice(V.NL_CITIES)


def _nl_dob(r: random.Random) -> str:
    y, m, d = r.randint(1940, 2006), r.randint(1, 12), r.randint(1, 28)
    months = ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober",
              "november", "december"]  # fmt: skip
    return r.choice([f"{d:02d}-{m:02d}-{y}", f"{d}-{m}-{y}", f"{d} {months[m - 1]} {y}", f"{d:02d}/{m:02d}/{y}",
                     f"{y}-{m:02d}-{d:02d}"])  # fmt: skip


def _us_dob(r: random.Random) -> str:
    y, m, d = r.randint(1940, 2006), r.randint(1, 12), r.randint(1, 28)
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
              "November", "December"]  # fmt: skip
    return r.choice([f"{m:02d}/{d:02d}/{y}", f"{m}/{d}/{y}", f"{months[m - 1]} {d}, {y}", f"{y}-{m:02d}-{d:02d}"])


def _email(r: random.Random, name: str, domains: list[str]) -> str:
    parts = [p for p in name.replace(",", "").replace(".", " ").split() if p[0].isupper() and len(p) > 1]
    first, last = (parts[0], parts[-1]) if len(parts) >= 2 else (parts[0] if parts else "info", "x")
    local = r.choice([f"{first}.{last}", f"{first[0]}.{last}", f"{first}{r.randint(1, 99)}", f"{last}.{first[0]}"])
    return f"{local.lower()}@{r.choice(domains)}"


NL_MAIL = ["ziggo.nl", "kpnmail.nl", "gmail.com", "hotmail.com", "outlook.com", "xs4all.nl", "planet.nl", "live.nl"]
US_MAIL = ["gmail.com", "yahoo.com", "outlook.com", "aol.com", "icloud.com", "comcast.net"]


# =========================================================================== the Netherlands, dev
@template("nl.gemeente_brief", "nl", "dev")
def nl_gemeente_brief(r: random.Random) -> B:
    name = V.nl_name(r)
    street, num, pc, city = _nl_address(r)
    b = B().t(f"Gemeente {city}\n").t("Afdeling Publiekszaken").t("\n\n")
    b.t(r.choice(["Geachte heer ", "Geachte mevrouw ", "Beste "])).v("nl.name", name).t(",\n\n")
    b.t("Uw aanvraag voor een ").k("parkeervergunning").t(
        " is in goede orde ontvangen. Wij hebben de volgende gegevens geregistreerd:\n\n"
    )
    b.t("Burgerservicenummer: ").v("nl.bsn", V.nl_bsn_written(r)).t("\n")
    b.t("Adres: ").v("nl.street", f"{street} {num}").t(", ").v("nl.postcode_city", f"{pc} {city}").t("\n")
    b.t("Kenteken: ").v("nl.kenteken", V.nl_kenteken(r)).t("\n")
    b.t("Telefoonnummer: ").v("nl.phone", V.nl_mobile(r)).t("\n\n")
    b.t("De vergunning is geldig tot en met 31 december. ").k("Heeft u vragen?").t(
        " Bel dan 14 020.\n\nMet vriendelijke groet,\n\n"
    )
    b.v("nl.name", V.nl_name(r)).t("\nMedewerker Publiekszaken\n")
    return b


@template("nl.zorgverzekeraar_mail", "nl", "dev")
def nl_zorgverzekeraar_mail(r: random.Random) -> B:
    name = V.nl_name(r)
    street, num, pc, city = _nl_address(r)
    b = B().t("Onderwerp: declaratie fysiotherapie\n\nBeste klantenservice,\n\n")
    b.t("Mijn polisnummer is ").v("nl.polisnummer", V.nl_polisnummer(r)).t(" en mijn BSN is ").v(
        "nl.bsn", V.nl_bsn_written(r)
    )
    b.t(". Ik ben geboren op ").v("nl.dob", _nl_dob(r)).t(" en woon sinds kort op ").v("nl.street", f"{street} {num}")
    b.t(" in ").v("nl.city", city).t(" (postcode ").v("nl.postcode", pc).t(").\n\n")
    b.t("Kunt u de rekening van mijn fysiotherapeut (AGB-code ").v("nl.agb", V.nl_agb(r)).t(
        ") terugbetalen op rekeningnummer "
    )
    b.v("nl.iban", V.nl_iban(r)).t(" t.n.v. ").v("nl.name", name).t("? ").k("De nota zit als bijlage bij deze mail.").t(
        "\n\n"
    )
    b.t(r.choice(["Groeten,\n", "Met vriendelijke groet,\n", "Mvg,\n"])).v("nl.name", name).t("\n").v(
        "nl.phone", V.nl_mobile(r)
    ).t("\n")
    return b


@template("nl.huurformulier", "nl", "dev")
def nl_huurformulier(r: random.Random) -> B:
    name = V.nl_name(r, inverted=True)
    street, num, pc, city = _nl_address(r)
    b = B().k("Inschrijfformulier huurwoning").t("\n\n")
    b.t("Naam: ").v("nl.name", name).t("\n")
    b.t("Geboortedatum: ").v("nl.dob", _nl_dob(r)).t("\n")
    b.t("E-mailadres: ").v("nl.email", _email(r, name, NL_MAIL)).t("\n")
    b.t("Telefoon: ").v("nl.phone", V.nl_landline(r) if r.random() < 0.4 else V.nl_mobile(r)).t("\n")
    b.t("Huidig adres: ").v("nl.street", f"{street} {num}").t("\n")
    b.t("Postcode en woonplaats: ").v("nl.postcode_city", f"{pc} {city}").t("\n")
    b.t("IBAN: ").v("nl.iban", V.nl_iban(r)).t("\n")
    b.t("Personeelsnummer werkgever: ").v("nl.personeelsnummer", V.nl_personeelsnummer(r)).t("\n")
    b.t("Bruto maandinkomen: ").k("€ 3.250,00").t("\n")
    b.t("Gewenste ingangsdatum: ").k("1 juni").t("\n")
    return b


@template("nl.crm_json", "nl", "dev")
def nl_crm_json(r: random.Random) -> B:
    name = V.nl_name(r)
    street, num, pc, city = _nl_address(r)
    b = (
        B()
        .t('{\n  "klantnummer": "')
        .v("nl.klantnummer", V.nl_klantnummer(r))
        .t('",\n  "naam": "')
        .v("nl.name", V.nl_name(r, inverted=True))
    )
    b.t('",\n  "bsn": "').v("nl.bsn", V.nl_bsn(r)).t('",\n  "geboortedatum": "').v("nl.dob", _nl_dob(r))
    b.t('",\n  "adres": {\n    "straat": "').v("nl.street_name", street).t('",\n    "huisnummer": "').v(
        "nl.house_number", num
    )
    b.t('",\n    "postcode": "').v("nl.postcode", pc).t('",\n    "woonplaats": "').v("nl.city", city)
    b.t('"\n  },\n  "telefoonnummer": "').v("nl.phone", V.nl_mobile(r)).t('",\n  "email": "').v(
        "nl.email", _email(r, name, NL_MAIL)
    )
    b.t('",\n  "iban": "').v("nl.iban", V.nl_iban(r)).t('",\n  "status": "').k("actief").t('",\n  "segment": "').k(
        "particulier"
    ).t('"\n}')
    return b


@template("nl.whatsapp", "nl", "dev")
def nl_whatsapp(r: random.Random) -> B:
    street, num, _pc, city = _nl_address(r)
    first = r.choice(V.NL_FIRST)
    b = B().t("hoi! ").k("mijn nieuwe nummer").t(" is ").v("nl.phone", V.nl_mobile(r)).t(" btw 😊 en we wonen nu op ")
    b.v("nl.street", f"{street} {num}").t(" in ").v("nl.city", city).t(". kun je die ").k("45 euro").t(
        " overmaken naar "
    )
    b.v("nl.iban", V.nl_iban(r)).t("? ").t(r.choice(["groetjes ", "xx ", "liefs, ", "doei "])).v("nl.first_name", first)
    return b


@template("nl.zzp_factuur", "nl", "dev")
def nl_zzp_factuur(r: random.Random) -> B:
    name = V.nl_name(r)
    street, num, pc, city = _nl_address(r)
    b = B().k("FACTUUR 2026-0142").t("\n\n").v("nl.name", name).t("\n").v("nl.street", f"{street} {num}").t("\n")
    b.v("nl.postcode_city", f"{pc} {city}").t("\n")
    b.t(r.choice(["KvK: ", "KvK-nummer: ", "Kamer van Koophandel nr. ", "KvK nr "])).v("nl.kvk", V.nl_kvk(r)).t("\n")
    b.t(r.choice(["BTW-id: ", "Btw-identificatienummer: ", "BTW nr: ", "Omzetbelastingnummer: "])).v(
        "nl.btw", V.nl_btw(r)
    ).t("\n")
    b.t("IBAN: ").v("nl.iban", V.nl_iban(r)).t("\n\n")
    b.t("Aan: Bakkerij De Zon").t("\n\nOmschrijving: ").k("Ontwerp website, 15 uur à € 100,00").t("\n")
    b.t("Subtotaal: € 1.500,00\nBtw 21%: € 315,00\n").k("Totaal: € 1.815,00").t(
        "\n\nGelieve binnen 30 dagen te betalen o.v.v. het factuurnummer.\n"
    )
    return b


@template("nl.aangifte", "nl", "dev")
def nl_aangifte(r: random.Random) -> B:
    name = V.nl_name(r, inverted=True)
    street, num, pc, city = _nl_address(r)
    b = (
        B()
        .k("Proces-verbaal van aangifte")
        .t("\n")
        .t("Parketnummer: ")
        .v("nl.parketnummer", V.nl_parketnummer(r))
        .t("\n\n")
    )
    b.t("Aangever: ").v("nl.name", name).t(", geboren op ").v("nl.dob", _nl_dob(r)).t(" te ").v(
        "nl.city", r.choice(V.NL_CITIES)
    )
    b.t(", wonende te ").v("nl.street", f"{street} {num}").t(", ").v("nl.postcode_city", f"{pc} {city}").t(".\n")
    b.t(r.choice(["Identiteitsbewijs: paspoort, documentnummer ", "Legitimatie: ID-kaart nummer ", "Paspoortnummer: "]))
    b.v("nl.document", V.nl_document_number(r)).t(".\n\n")
    b.t("De aangever verklaarde dat zijn auto, een grijze Volkswagen Golf met kenteken ").v(
        "nl.kenteken", V.nl_kenteken(r)
    )
    b.t(", ").k("in de nacht van zaterdag op zondag").t(" is opengebroken.\n")
    return b


@template("nl.ziekenhuisbrief", "nl", "dev")
def nl_ziekenhuisbrief(r: random.Random) -> B:
    b = (
        B()
        .t("Betreft: ")
        .v("nl.name", V.nl_name(r, inverted=True))
        .t(", BSN ")
        .v("nl.bsn", V.nl_bsn_written(r))
        .t(", geb. ")
        .v("nl.dob", _nl_dob(r))
        .t("\n")
    )
    b.t("Patiëntnummer: ").v("nl.patientnummer", V.nl_klantnummer(r)).t("\n\n")
    b.t("Geachte collega ").v("nl.name", V.nl_name(r)).t(",\n\n")
    b.t("Uw patiënt bezocht onze polikliniek in verband met ").k("aanhoudende rugklachten").t(". ")
    b.t("Wij adviseren fysiotherapie en een controle over zes weken.\n\nMet collegiale groet,\n\n")
    b.t("dr. ").v("nl.name", V.nl_name(r)).t(", orthopedisch chirurg\nBIG-nummer: ").v("nl.big", V.nl_big(r)).t("\n")
    return b


@template("nl.ind_brief", "nl", "dev")
def nl_ind_brief(r: random.Random) -> B:
    b = B().t("Immigratie- en Naturalisatiedienst").t("\n\nUw V-nummer: ").v("nl.v_nummer", V.nl_v_nummer(r)).t("\n")
    b.t("Uw A-nummer: ").v("nl.a_nummer", V.nl_a_nummer(r)).t("\n")
    b.t("Naam: ").v("nl.name", V.nl_name(r)).t("\n\n")
    b.t("Uw aanvraag voor een ").k("verblijfsvergunning regulier").t(
        " is toegewezen. Uw nieuwe verblijfsdocument heeft nummer "
    )
    b.v("nl.document", V.nl_document_number(r)).t(". U kunt het ophalen bij het IND-loket in Zwolle.\n")
    return b


@template("nl.loonstrook", "nl", "dev")
def nl_loonstrook(r: random.Random) -> B:
    b = B().k("Loonstrook maart").t("\n").t("Werkgever: Van Dalen Installatietechniek B.V.\nLoonheffingennummer: ")
    b.v("nl.loonheffingennummer", V.nl_loonheffingennummer(r)).t("\n")
    b.t("Werknemer: ").v("nl.name", V.nl_name(r, inverted=True)).t("\nBSN: ").v("nl.bsn", V.nl_bsn(r)).t("\n")
    b.t("Personeelsnr: ").v("nl.personeelsnummer", V.nl_personeelsnummer(r)).t("\n")
    b.t("Uitbetaald op rekening ").v("nl.iban", V.nl_iban(r)).t("\n")
    b.k("Bruto salaris 3.412,50").t("\nLoonheffing 812,33\n").k("Netto 2.600,17").t("\n")
    return b


@template("nl.ledenlijst_csv", "nl", "dev")
def nl_ledenlijst_csv(r: random.Random) -> B:
    b = B().t("naam;straat;huisnummer;postcode;plaats;telefoon;email;iban\n")
    for _ in range(r.randint(2, 4)):
        name = V.nl_name(r).replace(",", "")
        street, num, pc, city = _nl_address(r)
        b.v("nl.name", name).t(";").v("nl.street_name", street).t(";").v("nl.house_number", num).t(";").v(
            "nl.postcode", pc
        )
        b.t(";").v("nl.city", city).t(";").v("nl.phone", V.nl_mobile(r)).t(";").v("nl.email", _email(r, name, NL_MAIL))
        b.t(";").v("nl.iban", V.nl_iban(r)).t("\n")
    return b


@template("nl.systeemlog", "nl", "dev")
def nl_systeemlog(r: random.Random) -> B:
    b = B()
    for _ in range(r.randint(2, 3)):
        b.t(f"2026-03-{r.randint(10, 28)} 09:{r.randint(10, 59)}:{r.randint(10, 59)} INFO ").k(
            "klantgegevens gewijzigd"
        ).t(" klantnr=")
        b.v("nl.klantnummer", V.nl_klantnummer(r)).t(" tel=").v("nl.phone", V.nl_mobile(r).replace(" ", ""))
        b.t(" iban=").v("nl.iban", V.nl_iban(r).replace(" ", "")).t(" bsn=").v("nl.bsn", V.nl_bsn(r)).t("\n")
    return b


@template("nl.cbr_rijbewijs", "nl", "dev")
def nl_cbr_rijbewijs(r: random.Random) -> B:
    b = (
        B()
        .t("Beste ")
        .v("nl.name", V.nl_name(r))
        .t(",\n\nWij hebben uw ")
        .k("Verklaring van Geschiktheid")
        .t(" geregistreerd bij uw rijbewijs met nummer ")
    )
    b.v("nl.rijbewijs", V.nl_rijbewijsnummer(r)).t(". Uw ").k("rijbewijs B").t(" blijft geldig. ")
    b.t("Wij sturen de bevestiging naar ").v("nl.street", "{} {}".format(*_nl_address(r)[:2])).t(
        ".\n\nCBR Klantenservice\n"
    )
    return b


@template("nl.school_aanmelding", "nl", "dev")
def nl_school_aanmelding(r: random.Random) -> B:
    child = f"{r.choice(V.NL_FIRST)} {r.choice(V.NL_LAST)}"
    b = B().k("Aanmeldformulier groep 3").t("\n\nNaam leerling: ").v("nl.name", child).t("\n")
    b.t("Onderwijsnummer: ").v("nl.onderwijsnummer", V.nl_onderwijsnummer(r)).t("\n")
    b.t("Geboortedatum: ").v("nl.dob", _nl_dob(r)).t("\nNaam ouder/verzorger: ").v("nl.name", V.nl_name(r)).t("\n")
    b.t("Mobiel ouder: ").v("nl.phone", V.nl_mobile(r)).t("\nHuisarts: dr. ").v("nl.name", V.nl_name(r)).t("\n")
    return b


@template("nl.ov_klacht", "nl", "dev")
def nl_ov_klacht(r: random.Random) -> B:
    b = B().t("Goedemiddag,\n\nOp 12 maart is er ten onrechte ").k("€ 20,00").t(" van mijn OV-chipkaart afgeschreven. ")
    b.t("Het kaartnummer is ").v("nl.ov_chipkaart", V.nl_ov_chipkaart(r)).t(". Graag het bedrag terugstorten op ")
    b.v("nl.iban", V.nl_iban(r)).t(".\n\nMet vriendelijke groet,\n").v("nl.name", V.nl_name(r)).t("\n")
    return b


# =========================================================================== the Netherlands, holdout
@template("nl.belastingdienst", "nl", "holdout")
def nl_belastingdienst(r: random.Random) -> B:
    b = B().t("Belastingdienst").t("\n\nAan: ").v("nl.name", V.nl_name(r)).t("\n")
    street, num, pc, city = _nl_address(r)
    b.v("nl.street", f"{street} {num}").t("\n").v("nl.postcode_city", f"{pc} {city}").t("\n\n")
    b.t("Uw burgerservicenummer: ").v("nl.bsn", V.nl_bsn_written(r)).t("\nUw btw-identificatienummer: ").v(
        "nl.btw", V.nl_btw(r)
    ).t("\n\n")
    b.t("Wij hebben uw ").k("aangifte omzetbelasting over het eerste kwartaal").t(
        " ontvangen. U hoeft niets te doen.\n"
    )
    return b


@template("nl.verhuisbericht", "nl", "holdout")
def nl_verhuisbericht(r: random.Random) -> B:
    street, num, pc, city = _nl_address(r)
    b = (
        B()
        .t("Lieve familie en vrienden,\n\nPer 1 april wonen wij op een nieuw adres: ")
        .v("nl.street", f"{street} {num}")
        .t(", ")
    )
    b.v("nl.postcode_city", f"{pc} {city}").t(". Ons vaste nummer ").v("nl.phone", V.nl_landline(r)).t(
        " vervalt; je kunt ons bellen op "
    )
    b.v("nl.phone", V.nl_mobile(r)).t(".\n\n").k("Housewarming volgt!").t("\n\nHartelijke groet,\n").v(
        "nl.name", V.nl_name(r)
    )
    b.t(" en ").v("nl.first_name", r.choice(V.NL_FIRST)).t("\n")
    return b


@template("nl.verwijsbrief", "nl", "holdout")
def nl_verwijsbrief(r: random.Random) -> B:
    b = (
        B()
        .k("VERWIJSBRIEF")
        .t("\nNaam patiënt: ")
        .v("nl.name", V.nl_name(r))
        .t("\nGeboortedatum: ")
        .v("nl.dob", _nl_dob(r))
    )
    b.t("\nBSN: ").v("nl.bsn", V.nl_bsn_written(r)).t("\nZorgverzekeraar: CZ, polisnummer ").v(
        "nl.polisnummer", V.nl_polisnummer(r)
    )
    b.t("\nVerwijzer: huisarts ").v("nl.name", V.nl_name(r)).t(", AGB ").v("nl.agb", V.nl_agb(r)).t(", UZI-nummer ").v(
        "nl.uzi", V.nl_uzi(r)
    )
    b.t("\nReden van verwijzing: ").k("verdenking meniscusletsel links").t("\n")
    return b


@template("nl.sportclub_yaml", "nl", "holdout")
def nl_sportclub_yaml(r: random.Random) -> B:
    name = V.nl_name(r)
    street, num, pc, city = _nl_address(r)
    b = B().t("lid:\n  naam: ").v("nl.name", name).t("\n  geboren: ").v("nl.dob", _nl_dob(r)).t("\n  adres: ")
    b.v("nl.street", f"{street} {num}").t("\n  postcode: ").v("nl.postcode", pc).t("\n  plaats: ").v("nl.city", city)
    b.t("\n  mobiel: ").v("nl.phone", V.nl_mobile(r)).t("\n  mail: ").v("nl.email", _email(r, name, NL_MAIL))
    b.t("\n  rekening: ").v("nl.iban", V.nl_iban(r)).t("\n  team: ").k("JO13-2").t("\n  contributie: ").k("kwartaal").t(
        "\n"
    )
    return b


@template("nl.teams_bericht", "nl", "holdout")
def nl_teams_bericht(r: random.Random) -> B:
    b = (
        B()
        .t("@")
        .k("team-backoffice")
        .t(" klant ")
        .v("nl.name", V.nl_name(r))
        .t(" belde net (")
        .v("nl.phone", V.nl_mobile(r))
    )
    b.t(") over dossier ").v("nl.dossiernummer", V.nl_dossiernummer(r)).t(", zijn BSN is ").v("nl.bsn", V.nl_bsn(r))
    b.t(". Kan iemand ").k("vóór vrijdag").t(" terugbellen?")
    return b


@template("nl.kvk_uittreksel", "nl", "holdout")
def nl_kvk_uittreksel(r: random.Random) -> B:
    b = B().k("Uittreksel Handelsregister").t(" Kamer van Koophandel\n\nKvK-nummer ").v("nl.kvk", V.nl_kvk(r))
    b.t("\nVestigingsnummer ").v("nl.vestigingsnummer", V.nl_vestigingsnummer(r)).t("\nRechtsvorm ").k("Eenmanszaak")
    street, num, pc, city = _nl_address(r)
    b.t("\nBezoekadres ").v("nl.street", f"{street} {num}").t(", ").v("nl.postcode_city", f"{pc} {city}")
    b.t("\nEigenaar ").v("nl.name", V.nl_name(r, inverted=True)).t(", geboren ").v("nl.dob", _nl_dob(r)).t("\n")
    return b


@template("nl.inkomensverklaring_md", "nl", "holdout")
def nl_inkomensverklaring_md(r: random.Random) -> B:
    b = (
        B()
        .t("| Veld | Waarde |\n| --- | --- |\n| Naam | ")
        .v("nl.name", V.nl_name(r))
        .t(" |\n| BSN | ")
        .v("nl.bsn", V.nl_bsn(r))
    )
    b.t(" |\n| Werkgever | ").t("Gemeente Utrecht").t(" |\n| Loonheffingennummer | ").v(
        "nl.loonheffingennummer", V.nl_loonheffingennummer(r)
    )
    b.t(" |\n| Rekening | ").v("nl.iban", V.nl_iban(r)).t(" |\n| Jaar | ").k("2025").t(" |\n")
    return b


@template("nl.autoverkoop", "nl", "holdout")
def nl_autoverkoop(r: random.Random) -> B:
    b = B().t("Ik verkoop mijn Opel Corsa (").k("bouwjaar 2017").t("), kenteken ").v("nl.kenteken", V.nl_kenteken(r))
    b.t(", chassisnummer ").v("nl.vin", V.vin(r)).t(". Interesse? App naar ").v("nl.phone", V.nl_mobile(r)).t(
        " of mail "
    )
    name = V.nl_name(r)
    b.v("nl.email", _email(r, name, NL_MAIL)).t(". ").k("Vraagprijs 6.950 euro").t(".\n")
    return b


# =========================================================================== the United States, dev
def _us_address(r: random.Random) -> tuple[str, str, str]:
    city, state, zip3 = r.choice(V.US_PLACES)
    street = f"{r.randint(10, 9999)} {r.choice(V.US_STREETS)}"
    if r.random() < 0.3:
        street += r.choice([", Apt 4B", ", Unit 12", " #305", ", Suite 200"])
    return street, f"{city}, {state}", V.us_zip(r, zip3)


@template("us.patient_intake", "us", "dev")
def us_patient_intake(r: random.Random) -> B:
    name = V.us_name(r)
    street, city, z = _us_address(r)
    b = (
        B()
        .k("NEW PATIENT INTAKE FORM")
        .t("\n\nPatient Name: ")
        .v("us.name", name)
        .t("\nDate of Birth: ")
        .v("us.dob", _us_dob(r))
    )
    b.t("\nSSN: ").v("us.ssn", V.us_ssn(r)).t("\nAddress: ").v("us.street", street).t(", ").v("us.city_state", city).t(
        " "
    ).v("us.zip", z)
    b.t("\nHome Phone: ").v("us.phone", V.us_phone(r)).t("\nEmail: ").v("us.email", _email(r, name, US_MAIL))
    b.t("\nPrimary Insurance: Aetna  Member ID: ").v("us.member_id", V.us_member_id(r)).t("  Group #: ").v(
        "us.group_number", V.us_group_number(r)
    )
    b.t("\nMedicare MBI: ").v("us.mbi", V.us_mbi(r)).t("\nEmergency Contact: ").v("us.name", V.us_name(r)).t(
        " (spouse) "
    ).v("us.phone", V.us_phone(r))
    b.t("\nReason for visit: ").k("annual physical").t("\n")
    return b


@template("us.wire_email", "us", "dev")
def us_wire_email(r: random.Random) -> B:
    b = (
        B()
        .t("Hi ")
        .v("us.first_name", r.choice(V.US_FIRST))
        .t(",\n\nPlease wire the ")
        .k("$2,400 deposit")
        .t(" to my account:\n\n")
    )
    b.t("Bank: Chase\nRouting number: ").v("us.routing", V.us_routing(r)).t("\nAccount number: ").v(
        "us.bank_account", V.us_bank_account(r)
    )
    b.t("\nAccount holder: ").v("us.name", V.us_name(r)).t("\n\n").k("Let me know once it's sent.").t(
        "\n\nThanks,\n"
    ).v("us.name", V.us_name(r)).t("\n")
    return b


@template("us.w9", "us", "dev")
def us_w9(r: random.Random) -> B:
    street, city, z = _us_address(r)
    b = (
        B()
        .k("Form W-9 (Rev. March 2024)")
        .t("\n1 Name: ")
        .v("us.name", V.us_name(r))
        .t("\n2 Business name: ")
        .t("Blue Heron Consulting LLC")
    )
    b.t("\n5 Address: ").v("us.street", street).t("\n6 City, state, and ZIP code: ").v("us.city_state", city).t(" ").v(
        "us.zip", z
    )
    if r.random() < 0.5:
        b.t("\nPart I Taxpayer Identification Number\nSocial security number: ").v("us.ssn", V.us_ssn(r))
    else:
        b.t("\nPart I Taxpayer Identification Number\nEmployer identification number: ").v("us.ein", V.us_ein(r))
    b.t("\nPreparer PTIN: ").v("us.ptin", V.us_ptin(r)).t("\n")
    return b


@template("us.hr_json", "us", "dev")
def us_hr_json(r: random.Random) -> B:
    name = V.us_name(r).replace(",", "")
    street, city, z = _us_address(r)
    b = B().t('{"employee_id": "').v("us.employee_id", V.us_employee_id(r)).t('", "full_name": "').v("us.name", name)
    b.t('", "ssn": "').v("us.ssn", V.us_ssn(r)).t('", "dob": "').v("us.dob", _us_dob(r)).t('", "address": {"street": "')
    b.v("us.street", street).t('", "city": "').v("us.city", city.split(",")[0]).t('", "state": "').t(
        city.split(", ")[1]
    )
    b.t('", "zip": "').v("us.zip", z).t('"}, "phone": "').v("us.phone", V.us_phone(r)).t(
        '", "direct_deposit": {"routing": "'
    )
    b.v("us.routing", V.us_routing(r)).t('", "account": "').v("us.bank_account", V.us_bank_account(r)).t(
        '"}, "department": "'
    ).k("Engineering").t('"}')
    return b


@template("us.uscis_notice", "us", "dev")
def us_uscis_notice(r: random.Random) -> B:
    b = B().k("I-797C, Notice of Action").t("\n\nReceipt Number: ").v("us.uscis_receipt", V.us_uscis_receipt(r))
    b.t("\nCase Type: ").k("I-485, Application to Register Permanent Residence").t("\nApplicant: ").v(
        "us.name", V.us_name(r)
    )
    b.t("\nA-Number: ").v("us.a_number", V.us_a_number(r)).t("\nDate of Birth: ").v("us.dob", _us_dob(r))
    b.t("\n\nThe above application has been received. Please bring your passport (no. ").v(
        "us.passport", V.us_passport(r)
    )
    b.t(") and Form I-94 (admission number ").v("us.i94", V.us_i94(r)).t(") to your biometrics appointment.\n")
    return b


@template("us.pharmacy_label", "us", "dev")
def us_pharmacy_label(r: random.Random) -> B:
    b = (
        B()
        .t("Rx #")
        .v("us.rx", V.us_rx(r))
        .t("   ")
        .k("Atorvastatin 20 mg tablet")
        .t("\nPatient: ")
        .v("us.name", V.us_name(r))
    )
    b.t("   DOB: ").v("us.dob", _us_dob(r)).t("\nPrescriber: Dr. ").v("us.name", V.us_name(r)).t("  NPI ").v(
        "us.npi", V.us_npi(r)
    )
    b.t("  DEA ").v("us.dea", V.us_dea(r)).t("\nPhone: ").v("us.phone", V.us_phone(r)).t("\n").k(
        "Take one tablet by mouth daily."
    ).t("\n")
    return b


@template("us.dmv_record", "us", "dev")
def us_dmv_record(r: random.Random) -> B:
    street, city, z = _us_address(r)
    b = (
        B()
        .t("DMV vehicle registration\nOwner: ")
        .v("us.name", V.us_name(r))
        .t("\nDriver License #: ")
        .v("us.driver_license", V.us_driver_license(r))
    )
    b.t("\nResidence: ").v("us.street", street).t(", ").v("us.city_state", city).t(" ").v("us.zip", z)
    b.t("\nLicense Plate: ").v("us.plate", V.us_plate(r)).t("\nVIN: ").v("us.vin", V.vin(r)).t("\nMake/Model: ").t(
        "2019 Honda Civic"
    ).t("\n")
    return b


@template("us.chat_support", "us", "dev")
def us_chat_support(r: random.Random) -> B:
    b = B().t("customer: hey i need to update my card, the new one is ").v("us.credit_card", V.credit_card(r))
    b.t(" exp 08/29 cvv ").v("us.cvv", V.us_cvv(r)).t("\nagent: ").k("Thanks! For verification, can you confirm").t(
        " the last four of your social?\n"
    )
    b.t("customer: ").v("us.ssn_last4", V.us_ssn_last4(r)).t(
        "\nagent: and the best number to reach you?\ncustomer: "
    ).v("us.phone", V.us_phone(r)).t("\n")
    return b


@template("us.customers_csv", "us", "dev")
def us_customers_csv(r: random.Random) -> B:
    b = B().t("first_name,last_name,email,phone,street,city,state,zip\n")
    for _ in range(r.randint(2, 4)):
        first, last = r.choice(V.US_FIRST), r.choice(V.US_LAST)
        street, city, z = _us_address(r)
        b.v("us.first_name", first).t(",").v("us.last_name", last).t(",").v(
            "us.email", _email(r, f"{first} {last}", US_MAIL)
        ).t(",")
        b.v("us.phone", V.us_phone(r)).t(',"').v("us.street", street).t('",').v("us.city", city.split(",")[0]).t(",")
        b.t(city.split(", ")[1]).t(",").v("us.zip", z).t("\n")
    return b


@template("us.ssn_masked_letter", "us", "dev")
def us_ssn_masked_letter(r: random.Random) -> B:
    last4 = V.us_ssn_last4(r)
    b = (
        B()
        .t("Dear ")
        .v("us.name", V.us_name(r))
        .t(",\n\nWe received your request regarding ")
        .k("the change of mailing address")
        .t(". ")
    )
    b.t(
        r.choice(
            ["For your security, we have on file SSN: XXX-XX-", "Social Security Number: ***-**-", "SSN (last 4): "]
        )
    )
    b.v("us.ssn_last4", last4).t(". If this is not correct, call us at 1-800-555-0199.\n")
    return b


@template("us.military_va", "us", "dev")
def us_military_va(r: random.Random) -> B:
    b = B().t("Veteran: ").v("us.name", V.us_name(r)).t("\nDoD ID Number: ").v("us.dod_id", V.us_dod_id(r))
    b.t("\nVA File Number: ").v("us.va_file", V.us_va_file(r)).t("\nBranch: ").t("U.S. Army").t("\nPhone: ").v(
        "us.phone", V.us_phone(r)
    ).t("\n")
    return b


@template("us.app_log", "us", "dev")
def us_app_log(r: random.Random) -> B:
    b = B()
    for _ in range(r.randint(2, 3)):
        name = V.us_name(r).replace(",", "")
        b.t(f"2026-03-{r.randint(10, 28)}T14:{r.randint(10, 59)}:{r.randint(10, 59)}Z INFO ").k("checkout completed").t(
            " user_email="
        )
        b.v("us.email", _email(r, name, US_MAIL)).t(" phone=").v("us.phone", V.us_phone(r).replace(" ", "")).t(
            " card_last4="
        )
        b.k(str(r.randint(1000, 9999))).t(" ip=").v(
            "us.ip", f"{r.randint(23, 99)}.{r.randint(1, 254)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
        ).t("\n")
    return b


# =========================================================================== the United States, holdout
@template("us.claim_letter", "us", "holdout")
def us_claim_letter(r: random.Random) -> B:
    street, city, z = _us_address(r)
    b = (
        B()
        .v("us.name", V.us_name(r))
        .t("\n")
        .v("us.street", street)
        .t("\n")
        .v("us.city_state", city)
        .t(" ")
        .v("us.zip", z)
        .t("\n\n")
    )
    b.t("Re: Claim for ").k("emergency room visit").t("\nPolicy holder member number ").v(
        "us.member_id", V.us_member_id(r)
    )
    b.t(", group ").v("us.group_number", V.us_group_number(r)).t(
        "\n\nTo whom it may concern,\n\nMy Medicare number is "
    ).v("us.mbi", V.us_mbi(r))
    b.t(" and my Social Security number is ").v("us.ssn", V.us_ssn(r)).t(". I was born ").v("us.dob", _us_dob(r))
    b.t(". You can reach me at ").v("us.phone", V.us_phone(r)).t(".\n\nSincerely,\n").v("us.name", V.us_name(r)).t("\n")
    return b


@template("us.mortgage_md", "us", "holdout")
def us_mortgage_md(r: random.Random) -> B:
    b = (
        B()
        .t("| Field | Borrower |\n|---|---|\n| Name | ")
        .v("us.name", V.us_name(r))
        .t(" |\n| SSN | ")
        .v("us.ssn", V.us_ssn(r))
    )
    b.t(" |\n| Date of birth | ").v("us.dob", _us_dob(r)).t(" |\n| Driver's license | ").v(
        "us.driver_license", V.us_driver_license(r)
    )
    b.t(" |\n| Checking account | ").v("us.bank_account", V.us_bank_account(r)).t(" |\n| ABA routing | ").v(
        "us.routing", V.us_routing(r)
    )
    b.t(" |\n| Loan amount | ").k("$320,000").t(" |\n")
    return b


@template("us.voicemail", "us", "holdout")
def us_voicemail(r: random.Random) -> B:
    b = B().t('Voicemail transcript: "Hi, this is ').v("us.name", V.us_name(r)).t(" calling about my tax return. ")
    b.t("My ITIN is ").v("us.itin", V.us_itin(r)).t(", and my son's adoption tax ID is ").v("us.atin", V.us_atin(r))
    b.t(". Please call me back at ").v("us.phone", V.us_phone(r)).t(". ").k("Thanks, bye.").t('"\n')
    return b


@template("us.school_enrollment", "us", "holdout")
def us_school_enrollment(r: random.Random) -> B:
    street, city, z = _us_address(r)
    b = (
        B()
        .k("Student Enrollment Form")
        .t("\nStudent ID: ")
        .v("us.student_id", V.us_student_id(r))
        .t("\nStudent: ")
        .v("us.name", V.us_name(r))
    )
    b.t("\nBirthdate: ").v("us.dob", _us_dob(r)).t("\nParent/Guardian: ").v("us.name", V.us_name(r)).t("\nCell: ").v(
        "us.phone", V.us_phone(r)
    )
    b.t("\nHome address: ").v("us.street", street).t(", ").v("us.city_state", city).t(" ").v("us.zip", z).t(
        "\nGrade: "
    ).k("7th").t("\n")
    return b


@template("us.police_report", "us", "holdout")
def us_police_report(r: random.Random) -> B:
    b = (
        B()
        .t("Incident #")
        .k("2026-004417")
        .t(". Reporting party ")
        .v("us.name", V.us_name(r))
        .t(" (DOB ")
        .v("us.dob", _us_dob(r))
    )
    b.t(", DL ").v("us.driver_license", V.us_driver_license(r)).t(") stated that a vehicle bearing plate ").v(
        "us.plate", V.us_plate(r)
    )
    b.t(" struck his parked car. ").k("No injuries were reported.").t(" Contact: ").v("us.phone", V.us_phone(r)).t(
        ".\n"
    )
    return b


@template("us.travel_profile", "us", "holdout")
def us_travel_profile(r: random.Random) -> B:
    name = V.us_name(r).replace(",", "")
    b = B().t("traveler:\n  name: ").v("us.name", name).t("\n  passport_number: ").v("us.passport", V.us_passport(r))
    b.t("\n  passport_card: ").v("us.passport_card", V.us_passport_card(r)).t("\n  known_traveler_number: ").v(
        "us.ktn", V.us_dod_id(r)[:9]
    )
    b.t("\n  email: ").v("us.email", _email(r, name, US_MAIL)).t("\n  seat_preference: ").k("aisle").t("\n")
    return b


@template("us.pharmacy_chat", "us", "holdout")
def us_pharmacy_chat(r: random.Random) -> B:
    b = (
        B()
        .t("Pharmacist note: called Dr. ")
        .v("us.name", V.us_name(r))
        .t(" (NPI ")
        .v("us.npi", V.us_npi(r))
        .t(", DEA reg ")
    )
    b.v("us.dea", V.us_dea(r)).t(") to confirm prescription ").v("us.rx", V.us_rx(r)).t(" for patient ").v(
        "us.name", V.us_name(r)
    )
    b.t(", Medicaid ID ").v("us.medicaid", V.us_medicaid(r)).t(". ").k("Dose confirmed.").t("\n")
    return b


# =========================================================================== the European Union, dev
@template("eu.rechnung_de", "eu", "dev")
def eu_rechnung_de(r: random.Random) -> B:
    street, town = V.eu_address(r, "de")
    b = (
        B()
        .k("Rechnung Nr. 2026-311")
        .t("\n\n")
        .v("eu.name", V.eu_name(r, "de"))
        .t("\n")
        .v("eu.street", street)
        .t("\n")
        .v("eu.postcode_city", town)
    )
    b.t("\nUSt-IdNr.: ").v("eu.vat", V.eu_vat(r, "de")).t("\nIBAN: ").v("eu.iban", V.eu_iban(r)).t("\nBIC: ").v(
        "eu.bic", V.eu_bic(r)
    )
    b.t("\n\n").k("Zahlbar innerhalb von 14 Tagen ohne Abzug.").t("\n")
    return b


@template("eu.customs_eori", "eu", "dev")
def eu_customs_eori(r: random.Random) -> B:
    b = (
        B()
        .t("Customs declaration ")
        .k("H1 import")
        .t("\nImporter: ")
        .v("eu.name", V.eu_name(r))
        .t("\nEORI number: ")
        .v("eu.eori", V.eu_eori(r))
    )
    b.t("\nVAT number: ").v("eu.vat", V.eu_vat(r)).t("\nCommodity code: ").k("8471 30 00").t("\n")
    return b


@template("eu.travel_ehic", "eu", "dev")
def eu_travel_ehic(r: random.Random) -> B:
    b = (
        B()
        .t("Claim form travel insurance\nInsured person: ")
        .v("eu.name", V.eu_name(r))
        .t("\nEuropean Health Insurance Card (EHIC) number: ")
    )
    b.v("eu.ehic", V.eu_ehic(r)).t("\nPhone abroad: ").v("eu.phone", V.eu_phone(r)).t("\nIncident: ").k(
        "sprained ankle"
    ).t(" in Lisbon").t("\n")
    return b


@template("eu.passport_scan", "eu", "dev")
def eu_passport_scan(r: random.Random) -> B:
    b = B().t("OCR output of the passport page:\n\n").v("eu.mrz", V.eu_mrz(r)).t("\n\n").k("Scan quality: good").t("\n")
    return b


@template("eu.fr_salarie", "eu", "dev")
def eu_fr_salarie(r: random.Random) -> B:
    street, town = V.eu_address(r, "fr")
    _cue, gen = V.EU_NATIONAL["fr.nir"]
    b = (
        B()
        .t("Fiche salarié\nNom : ")
        .v("eu.name", V.eu_name(r, "fr"))
        .t("\nNuméro de sécurité sociale : ")
        .v("eu.national", gen(r))
    )
    b.t("\nAdresse : ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t("\nTéléphone : ").v(
        "eu.phone", V.eu_phone(r)
    )
    b.t("\nPoste : ").k("chef de projet").t("\n")
    return b


@template("eu.es_contrato", "eu", "dev")
def eu_es_contrato(r: random.Random) -> B:
    street, town = V.eu_address(r, "es")
    _cue, gen = V.EU_NATIONAL["es.dni"]
    b = (
        B()
        .t("CONTRATO DE ARRENDAMIENTO\n\nDe una parte, D. ")
        .v("eu.name", V.eu_name(r, "es"))
        .t(", mayor de edad, con DNI ")
    )
    b.v("eu.national", gen(r)).t(" y domicilio en ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t(".\n")
    b.t("La renta mensual será de ").k("850 euros").t(", pagadera en la cuenta ").v("eu.iban", V.eu_iban(r)).t(".\n")
    return b


@template("eu.it_ricevuta", "eu", "dev")
def eu_it_ricevuta(r: random.Random) -> B:
    street, town = V.eu_address(r, "it")
    _cue, gen = V.EU_NATIONAL["it.codicefiscale"]
    b = (
        B()
        .t("Ricevuta di pagamento\nCliente: ")
        .v("eu.name", V.eu_name(r, "it"))
        .t("\nCodice fiscale: ")
        .v("eu.national", gen(r))
    )
    b.t("\nResidente in ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t("\nPartita IVA fornitore: ").v(
        "eu.vat", V.eu_vat(r, "it")
    )
    b.t("\nImporto: ").k("€ 120,00").t("\n")
    return b


@template("eu.pl_wniosek", "eu", "dev")
def eu_pl_wniosek(r: random.Random) -> B:
    street, town = V.eu_address(r, "pl")
    _cue, gen = V.EU_NATIONAL["pl.pesel"]
    b = (
        B()
        .t("Wniosek o kartę parkingową\nImię i nazwisko: ")
        .v("eu.name", V.eu_name(r, "pl"))
        .t("\nPESEL: ")
        .v("eu.national", gen(r))
    )
    b.t("\nAdres: ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t("\nTelefon: ").v(
        "eu.phone", V.eu_phone(r)
    ).t("\n")
    return b


@template("eu.supplier_table", "eu", "dev")
def eu_supplier_table(r: random.Random) -> B:
    b = B().t("supplier,country,vat_id,iban\n")
    for _ in range(r.randint(2, 4)):
        b.t(r.choice(["Nordwind GmbH", "Ateliers Lumière SARL", "Tecnica Sud S.r.l.", "Bouwbedrijf Zuid B.V."])).t(",")
        b.t(r.choice(["DE", "FR", "IT", "NL"])).t(",").v("eu.vat", V.eu_vat(r)).t(",").v("eu.iban", V.eu_iban(r)).t(
            "\n"
        )
    return b


@template("eu.kennzeichen", "eu", "dev")
def eu_kennzeichen(r: random.Random) -> B:
    cc, plate = V.eu_plate(r)
    cue = {
        "de": "Kennzeichen",
        "fr": "Immatriculation",
        "es": "Matrícula",
        "it": "Targa",
        "be": "Nummerplaat",
        "pl": "Numer rejestracyjny",
    }[cc]
    b = (
        B()
        .t(f"{cue}: ")
        .v("eu.plate", plate)
        .t("\n")
        .k("Parking zone B")
        .t(", valid until 30/06\nOwner: ")
        .v("eu.name", V.eu_name(r))
        .t("\n")
    )
    return b


# =========================================================================== the European Union, holdout
@template("eu.be_huurcontract", "eu", "holdout")
def eu_be_huurcontract(r: random.Random) -> B:
    street, town = V.eu_address(r, "be")
    _cue, gen = V.EU_NATIONAL["be.nn"]
    b = (
        B()
        .t("Huurovereenkomst\nHuurder: ")
        .v("eu.name", V.eu_name(r, "be"))
        .t(", rijksregisternummer ")
        .v("eu.national", gen(r))
    )
    b.t(", wonende ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t(".\nGSM: ").v(
        "eu.phone", V.eu_phone(r)
    )
    b.t("\nHuurprijs: ").k("€ 950 per maand").t("\n")
    return b


@template("eu.at_meldezettel", "eu", "holdout")
def eu_at_meldezettel(r: random.Random) -> B:
    street, town = V.eu_address(r, "at")
    _cue, gen = V.EU_NATIONAL["at.vnr"]
    b = (
        B()
        .t("Meldezettel\nFamilienname, Vorname: ")
        .v("eu.name", V.eu_name(r, "at"))
        .t("\nSozialversicherungsnummer: ")
        .v("eu.national", gen(r))
    )
    b.t("\nUnterkunft: ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t("\n").k("Hauptwohnsitz: ja").t(
        "\n"
    )
    return b


@template("eu.pt_fatura", "eu", "holdout")
def eu_pt_fatura(r: random.Random) -> B:
    street, town = V.eu_address(r, "pt")
    _cue, gen = V.EU_NATIONAL["pt.nif"]
    b = B().t("Fatura simplificada\nCliente: ").v("eu.name", V.eu_name(r, "pt")).t(" NIF ").v("eu.national", gen(r))
    b.t("\nMorada: ").v("eu.street", street).t(", ").v("eu.postcode_city", town).t("\n").k("Total: 37,50 EUR").t("\n")
    return b


@template("eu.nordic_hr", "eu", "holdout")
def eu_nordic_hr(r: random.Random) -> B:
    key = r.choice(["se.personnummer", "dk.cpr", "fi.hetu"])
    cue, gen = V.EU_NATIONAL[key]
    b = (
        B()
        .t("Employee onboarding\nName: ")
        .v("eu.name", V.eu_name(r))
        .t(f"\n{cue.capitalize()}: ")
        .v("eu.national", gen(r))
    )
    b.t("\nBank account (IBAN): ").v("eu.iban", V.eu_iban(r)).t("\nStart date: ").k("1 September").t("\n")
    return b


@template("eu.cee_records_json", "eu", "holdout")
def eu_cee_records_json(r: random.Random) -> B:
    key = r.choice(["cz.rc", "ro.cnp", "gr.amka", "ie.pps", "de.idnr"])
    _cue, gen = V.EU_NATIONAL[key]
    field_name = {
        "cz.rc": "rodne_cislo",
        "ro.cnp": "cnp",
        "gr.amka": "amka",
        "ie.pps": "pps_number",
        "de.idnr": "steuer_id",
    }[key]
    b = B().t('{"name": "').v("eu.name", V.eu_name(r)).t(f'", "{field_name}": "').v("eu.national", gen(r))
    b.t('", "phone": "').v("eu.phone", V.eu_phone(r)).t('", "vat": "').v("eu.vat", V.eu_vat(r)).t('", "role": "').k(
        "analyst"
    ).t('"}')
    return b


@template("eu.vaccination", "eu", "holdout")
def eu_vaccination(r: random.Random) -> B:
    b = (
        B()
        .t("EU Digital COVID Certificate\nName: ")
        .v("eu.name", V.eu_name(r))
        .t("\nUnique certificate identifier: ")
        .v("eu.uvci", V.eu_uvci(r))
    )
    b.t("\n").k("Vaccine: Comirnaty").t("\n")
    return b


@template("eu.bank_details_mail", "eu", "holdout")
def eu_bank_details_mail(r: random.Random) -> B:
    b = (
        B()
        .t("Dear accounts team,\n\nPlease update our bank details: IBAN ")
        .v("eu.iban", V.eu_iban(r))
        .t(", SWIFT ")
        .v("eu.bic", V.eu_bic(r))
    )
    b.t(". Our VAT ID remains ").v("eu.vat", V.eu_vat(r)).t(" and our EORI ").v("eu.eori", V.eu_eori(r)).t(".\n\n")
    b.k("Kind regards from the finance office").t(",\n").v("eu.name", V.eu_name(r)).t("\n").v(
        "eu.phone", V.eu_phone(r)
    ).t("\n")
    return b


# =========================================================================== look-alikes that must pass
@template("nl.negatives", "nl", "dev")
def nl_negatives(r: random.Random) -> B:
    b = (
        B()
        .t("Op ")
        .k(f"{r.randint(1, 28)} maart 2026 om 14:30")
        .t(" is ")
        .k(f"factuur 2026-{r.randint(10, 99):04d}")
        .t(" verzonden (")
    )
    b.k(f"bedrag € {r.randint(1, 9)}.{r.randint(100, 999)},{r.randint(10, 99)}").t(", ").k("btw 21%").t("). Zie ").k(
        "artikel 7:610 BW"
    )
    b.t(" en ").k(f"versie {r.randint(1, 4)}.{r.randint(0, 9)}.{r.randint(0, 9)}").t(
        " van de handleiding. Het pakket weegt "
    ).k("3,5 kg")
    b.t(". ").k(f"Zaal {r.randint(1, 9)}.{r.randint(10, 40)}").t(" is gereserveerd voor ").k(
        f"{r.randint(10, 60)} personen"
    ).t(".\n")
    return b


@template("us.negatives", "us", "dev")
def us_negatives(r: random.Random) -> B:
    b = (
        B()
        .k(f"Order #A{r.randint(1000, 9999)}")
        .t(" shipped on ")
        .k(f"03/{r.randint(10, 28)}/2026 at 2:30 PM")
        .t(", total ")
    )
    b.k(f"${r.randint(1, 9)},{r.randint(100, 999)}.{r.randint(10, 99)}").t(" (").k("8.25% tax").t("). See ").k(
        f"Section {r.randint(1, 9)}.{r.randint(1, 9)}"
    )
    b.t(" and ").k("RFC 7231").t(". ").k(f"Version {r.randint(1, 4)}.{r.randint(0, 9)}.{r.randint(0, 9)}").t(
        " fixes the issue. "
    )
    b.k(f"Room {r.randint(100, 999)}").t(", ").k(f"Building {r.randint(1, 9)}").t(".\n")
    return b


@template("eu.negatives", "eu", "dev")
def eu_negatives(r: random.Random) -> B:
    b = B().k(f"Commande n° 2026-{r.randint(10, 99):04d}").t(" du ").k(f"{r.randint(10, 28)}/03/2026").t(", montant ")
    b.k(f"{r.randint(1, 9)} {r.randint(100, 999)},{r.randint(10, 99)} €").t(", ").k("TVA 20 %").t(". ").k(
        "Article L. 1234-5"
    )
    b.t(" du Code du travail. ").k(f"Bestellung {r.randint(10000, 99999)}").t(" vom ").k(
        f"{r.randint(10, 28)}.03.2026"
    ).t(", ")
    b.k(f"Betrag {r.randint(10, 999)},{r.randint(10, 99)} EUR").t(".\n")
    return b


def build(tid: str, rng: random.Random) -> dict[str, object]:
    region, split, fn = TEMPLATES[tid]
    b = fn(rng)
    text = b.text
    return {
        "template": tid,
        "region": region,
        "split": split,
        "text": text,
        "values": [
            {"kind": v.kind, "start": v.start, "end": v.end, "surface": text[v.start : v.end]} for v in b.values
        ],
        "keeps": [{"start": s, "end": e, "surface": text[s:e]} for s, e in b.keeps],
    }


def dump(record: dict[str, object]) -> str:
    return json.dumps(record, ensure_ascii=False)
