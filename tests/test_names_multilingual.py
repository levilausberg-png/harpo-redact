"""Names found by the words around them, in many languages (detectors/names.py). Names are made up."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.names import find_name_cues


def names(text: str) -> list[str]:
    return [text[s.start : s.end] for s in find_name_cues(text)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Sehr geehrte Frau Dr. Ilse Brandauer,", ["Ilse Brandauer"]),
        ("Liebe/r Tamsin Okoro,", ["Tamsin Okoro"]),
        ("Estimado/a Joaquín Ferrer:", ["Joaquín Ferrer"]),
        ("Gentile Signora Bianca Rossetti,", ["Bianca Rossetti"]),
        ("Kære Hr Magnus Holm,", ["Magnus Holm"]),
        ("Szanowna Pani Zofia Wrona,", ["Zofia Wrona"]),
        ("Poštovani gospodine Marko Babić,", ["Marko Babić"]),
        ("Αγαπητή κυρία Ελένη Παππά,", ["Ελένη Παππά"]),
        ("Уважаеми господин Петър Иванов,", ["Петър Иванов"]),
        ("Kính gửi Bà Trần Thị Mai,", ["Trần Thị Mai"]),
        ("Sig.na Chiara Lodi ha scritto", ["Chiara Lodi"]),
        ("M. Arnaud Petit est arrivé", ["Arnaud Petit"]),
    ],
)
def test_greetings_and_titles(text: str, expected: list[str]) -> None:
    assert names(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Vorname: Henrike\nNachname: Albers", ["Henrike", "Albers"]),
        ("Prénom : Odile\nNom : Garnier", ["Odile", "Garnier"]),
        ("Navn: Sigrid Dahl", ["Sigrid Dahl"]),
        ("Imię i nazwisko: Kacper Lis", ["Kacper Lis"]),
        ("Given Names: Tove Ingrid", ["Tove Ingrid"]),
        ("Vorname (Hanna), Nachname (Sommer)", ["Hanna", "Sommer"]),
        ("氏名：佐藤 花子", ["佐藤 花子"]),
        ("- **First Name:** Mirjam\n- **Last Name**: Kuipers", ["Mirjam", "Kuipers"]),
        ("Name: **Teun Hoekstra**", ["Teun Hoekstra"]),
        ("이름: 박서준", ["박서준"]),
    ],
)
def test_name_labels(text: str, expected: list[str]) -> None:
    assert names(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('[09:14] Ruben Achterberg: "Done, merged."', ["Ruben Achterberg"]),
        ("10:42 PM Noor: 'on my way'", ["Noor"]),
        ('Femke Visscher: "Sounds good."', ["Femke Visscher"]),
        ("I, Wilhelmina Kok, hereby declare", ["Wilhelmina Kok"]),
        ("Ich, Jonas Reiter, geboren am 1.1.1990", ["Jonas Reiter"]),
        ("Nagy Eszter asszony megérkezett", ["Nagy Eszter"]),
        ("田中さんに連絡してください", ["田中"]),
        ("请联系王先生", ["王"]),
        ("김민지 씨에게 전달해 주세요", ["김민지"]),
        ("X /s/ Gerrit J. Wolters", ["Gerrit J. Wolters"]),
    ],
)
def test_speakers_declarations_and_titles_after_the_name(text: str, expected: list[str]) -> None:
    assert names(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Liebe Grüße, bis bald",
        "Sehr geehrte Damen und Herren",
        "Status: ok",
        "12:00:01 ERROR: disk full",
        "User: what is the weather?",
        "Project Manager: tbd",
        "I, for one, agree",
        "HR Manager approved it",
        "这位先生请坐",
        "고객님 감사합니다",
        "皆様、こんにちは",
    ],
)
def test_no_names_in_ordinary_text(text: str) -> None:
    assert names(text) == []
