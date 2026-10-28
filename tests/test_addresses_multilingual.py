"""Postal addresses as they are written in many countries (detectors/addresses.py). Addresses are made up."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.addresses import find_labelled_addresses, find_street_addresses
from harpo_redact.entities import EntityType as E


def found(text: str, etype: E = E.ADDRESS) -> set[str]:
    spans = [*find_street_addresses(text), *find_labelled_addresses(text)]
    return {text[s.start : s.end] for s in spans if s.type is etype}


def covered(text: str, address: str) -> bool:
    """Some span holds the whole address and not much more (a city before a Chinese street is part of it)."""
    return any(address in f and len(f) <= len(address) + 16 for f in found(text))


@pytest.mark.parametrize(
    ("text", "address"),
    [
        ("We meet at Via Garibaldi 12, 20121 Milano tomorrow.", "Via Garibaldi 12, 20121 Milano"),
        ("Rua das Flores, nº 45, em Lisboa", "Rua das Flores, nº 45"),
        ("Calle de Alcalá 15, 28014 Madrid", "Calle de Alcalá 15, 28014 Madrid"),
        ("on habite au 8 rue de la Gare depuis", "8 rue de la Gare"),
        ("Bulevardul Unirii nr. 27, 030167 București.", "Bulevardul Unirii nr. 27, 030167 București"),
        ("ul. Długa 5, 00-238 Warszawa", "ul. Długa 5, 00-238 Warszawa"),
        ("Dobrinjska ulica 9, 10000 Zagreb", "Dobrinjska ulica 9, 10000 Zagreb"),
        ("Kossuth Lajos utca 12 szám alatt", "Kossuth Lajos utca 12"),
        ("Elizabetes iela 45, Rīga", "Elizabetes iela 45, Rīga"),
        ("Gedimino g. 9, Vilnius – 01103.", "Gedimino g. 9, Vilnius – 01103"),
        ("toimisto osoitteessa Mannerheimintie 10, 00100 Helsinki", "Mannerheimintie 10, 00100 Helsinki"),
        ("Nørregade 7, 1165 København K", "Nørregade 7, 1165 København K"),
        ("Drottninggatan 53, 111 21 Stockholm.", "Drottninggatan 53, 111 21 Stockholm"),
        ("Hauptstraße 5, 10115 Berlin", "Hauptstraße 5, 10115 Berlin"),
        ("Keizersgracht 123, 1015 CJ Amsterdam", "Keizersgracht 123, 1015 CJ Amsterdam"),
        ("tinggal di Jalan Merdeka No. 10, Bandung", "Jalan Merdeka No. 10, Bandung"),
        ("12 Lorong Ampas, Singapore", "12 Lorong Ampas, Singapore"),
        ("the office on Rustaveli Avenue 23, Tbilisi, 0108.", "Rustaveli Avenue 23, Tbilisi, 0108"),
        ("Sennhof 41, 8125 Zollikerberg", "Sennhof 41, 8125 Zollikerberg"),
        ("Springfield, IL 62704", "Springfield, IL 62704"),
        ("in Austin, Texas 78701 since", "Texas 78701"),
    ],
)
def test_street_addresses_in_their_local_grammar(text: str, address: str) -> None:
    assert covered(text, address), found(text)


@pytest.mark.parametrize(
    ("text", "address"),
    [
        ("Adresse: Lindenweg 4, 3011 Bern\nTelefon: 031 000 00 00", "Lindenweg 4, 3011 Bern"),
        ("Dirección: Av. Libertad 1450, Lima", "Av. Libertad 1450, Lima"),
        ("  • Indirizzo di residenza: Piazza Duomo 1, Firenze", "Piazza Duomo 1, Firenze"),
        ("Address line 1: 42 Harbour View    City: Dover", "42 Harbour View"),
        ("住所：東京都新宿区西新宿2-8-1", "東京都新宿区西新宿2-8-1"),
        ("residing at Flat 3, 18 Mill Road, Cambridge, here", "Flat 3, 18 Mill Road, Cambridge, here"),
        ("Nous vous attendons à l'adresse 14 avenue Foch, Paris.", "14 avenue Foch, Paris"),
        ("Sídlo firmy je na adrese Husova 12, 110 00 Praha", "Husova 12, 110 00 Praha"),
    ],
)
def test_labels_and_phrases_introduce_an_address(text: str, address: str) -> None:
    assert covered(text, address), found(text)


@pytest.mark.parametrize(
    ("text", "address"),
    [
        ("配送先は北京市朝阳区建国路 88号です", "建国路 88号"),
        ("会場は京都市中京区の烏丸通 2-30-7です", "京都市中京区の烏丸通 2-30-7"),
        ("주소: 테헤란로 152, 서울", "테헤란로 152"),
        ("배송지는 세종대로 110번지 입니다", "세종대로 110번지"),
    ],
)
def test_chinese_japanese_and_korean_addresses(text: str, address: str) -> None:
    assert covered(text, address), found(text)


def test_town_labels_name_a_place() -> None:
    assert found("City: Rotterdam\nCountry: NL", E.LOCATION) == {"Rotterdam", "NL"}
    assert found("Ville : Saint-Malo, France", E.LOCATION) == {"Saint-Malo"}


def test_region_and_country_labels_name_a_place() -> None:
    form = "- **City:** Tarrytown\n- **State:** NY\n- **County:** Westchester\n- **Country:** United States\n"
    assert found(form, E.LOCATION) == {"Tarrytown", "NY", "Westchester", "United States"}
    assert found("Bundesland: Thüringen; Land: Deutschland", E.LOCATION) == {"Thüringen", "Deutschland"}
    assert found("State:          Running\nReady: True\nState: Open", E.LOCATION) == set()  # a status


@pytest.mark.parametrize(
    "text",
    [
        "send it via email 12 times",
        "Via Zoom 3 people joined",
        "Spring 2024 semester",
        "Chapter 12, 2024 Edition",
        "Email address: someone",
        "IP address: 10.0.0.1",
        "Address: 0x7ffd5a2c",
        "Address: see below",
        "lives in Berlin with 2 kids",
        "Main page 2, 1999 Review",
    ],
)
def test_no_address_in_ordinary_text(text: str) -> None:
    assert found(text) == set()
