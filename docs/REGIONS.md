# Dutch, US and EU personal data: what there is, and how Harpo finds it

Harpo's main deployments are in the Netherlands and the United States, so this page lists, for those two and for the
European Union as a whole, every kind of value that identifies a person in everyday text, with its format, the check
that proves a value is one, and the part of the [detection library](LIBRARY.md) that finds it. RegionBench
(`bench/regionbench/`) measures the result on documents written the way people write them in each region.

The inventory was built from the legal definitions first, then from the identifiers each country issues:

- **EU, GDPR article 4(1).** Personal data is any information relating to an identifiable natural person, directly or
  indirectly, "in particular by reference to an identifier such as a name, an identification number, location data,
  an online identifier". Identification numbers are therefore in scope whatever their format, and so are online
  identifiers (user ids, account names, IP addresses).
- **US, HIPAA Safe Harbor (45 CFR 164.514(b)(2)).** The eighteen identifiers that must go before health data counts as
  de-identified: names; geographic subdivisions smaller than a state (street, city, county, ZIP code); all elements of
  dates except the year; telephone and fax numbers; e-mail addresses; Social Security numbers; medical record numbers;
  health plan beneficiary numbers; account numbers; certificate and licence numbers; vehicle identifiers and serial
  numbers, licence plates included; device identifiers and serial numbers; URLs; IP addresses; biometric identifiers;
  full-face photographs; any other unique identifying number, characteristic or code.
- **The Netherlands, Uitvoeringswet AVG and the BSN rules.** The burgerservicenummer may only be processed where a law
  allows it, which is why the Belastingdienst replaced the BSN-based btw-identificatienummer of sole traders in 2020
  after the Autoriteit Persoonsgegevens objected. The BSN and every number derived from it are treated as the most
  sensitive Dutch identifiers.

## How a value is found

Each identifier below is found in one or more of four ways, all deterministic:

| Way | What it means | Library family |
| --- | --- | --- |
| **Format** | The value is recognisable on its own and is checked (a check digit, a checksum, a date inside it), so it is found anywhere | core patterns, *Checked national and tax IDs*, the region packs |
| **Cue** | The value follows a word that names it, in 30+ languages ("BSN", "kenteken", "Social Security number", "passport no.") | *Values named by a cue word* |
| **Field** | The value is under a column, a form label or a JSON key that names it ("bsn", "Last Name", "zip_code") | *Form and table fields*, and the JSON leaf labels of the proxy |
| **Structure** | Addresses and names are read by their grammar (street, number, postcode, town; titles, sign-offs, particles), and the NER model finds the rest | *Addresses and places*, *Name rules*, *Named-entity model* |

A cue, a field or a structure finds values whose format alone would be ambiguous (a nine-digit number, a name). The
switches for each family are on the console's Policy page and under `detection.identifiers` in the configuration.

## The Netherlands

| Identifier | Format | What Harpo checks | Found by |
| --- | --- | --- | --- |
| Burgerservicenummer (BSN) | 9 digits | the eleven test (weights 9 to 2, and -1) | format after its cue ("BSN", "burgerservicenummer", "sofinummer"); field |
| RSIN | 9 digits | the shape after the cue | cue ("RSIN", "fiscaal nummer") |
| Btw-identificatienummer | `NL` + 9 digits + `B` + 2 digits | both checksums: the eleven test of the old, BSN-based number and mod 97 of the 2020 one | format (region pack NL, and the EU VAT check); cue |
| Loonheffingennummer | 9 digits + `L` + 2 digits | the eleven test on the first nine | format (region pack NL) |
| KvK-nummer, vestigingsnummer | 8 and 12 digits | the shape after the cue | cue ("KvK", "KvK-nummer", "vestigingsnummer") |
| Paspoort, ID-kaart | 9 characters, letters and digits | the shape after the cue; the zone's layout | cue ("paspoort", "identiteitskaart", "documentnummer"); machine-readable zone |
| Rijbewijsnummer | 10 digits | the shape after the cue | cue ("rijbewijs", "rijbewijsnummer") |
| Kenteken | the RDW side codes (XX-99-99 ... 9-XXX-99) | letters and digits, 4 to 10 | cue ("kenteken") |
| A-nummer (BRP) | 10 digits | the shape after the cue | cue ("A-nummer", "administratienummer") |
| V-nummer (IND) | 10 digits | the shape after the cue | cue ("V-nummer", "vreemdelingennummer") |
| Onderwijsnummer | 9 digits | the shape after the cue | cue ("onderwijsnummer") |
| AGB-code, BIG-nummer, UZI-nummer | 8, 11 and 9 digits | the shape after the cue | cue ("AGB", "BIG", "UZI") |
| Polis-, klant-, dossier-, parket-, personeels-, studentnummer | free form | a code with a digit after the cue | cue |
| OV-chipkaartnummer | 16 digits | the shape after the cue | cue ("OV-chipkaart") |
| IBAN | `NL` + 2 + 4 letters + 10 digits | mod 97 | format |
| Telefoonnummer | +31 / 0 with 9 digits | libphonenumber | format; cue ("tel", "mobiel", "bel") |
| Postcode | 4 digits + 2 letters | next to a town or a street | structure; cue |
| Adres | straat, huisnummer, toevoeging, postcode, woonplaats | a street word or a known street, and a number | structure, also in "wonende te", "woonachtig aan" phrasing |
| Naam | voornaam, tussenvoegsel, achternaam | capitals and particles (de, van, van der) | name rules (greetings, "de heer", sign-offs, "Achternaam, Voornaam"); NER |
| Geboortedatum | dates in Dutch | a real date | cue ("geboren op", "geboortedatum") |
| EHIC / EKVK | card numbers | the shape after the cue | cue |

## The United States

| Identifier | Format | What Harpo checks | Found by |
| --- | --- | --- | --- |
| Social Security number | AAA-GG-SSSS | area not 000, 666 or 9xx; group not 00; serial not 0000 | format with dashes or blanks; nine bare digits after its cue; field |
| SSN masked or last four | XXX-XX-1234, "SSN ending in 1234" | the masked shape or the words | region pack US |
| ITIN | 9XX-XX-XXXX, middle 50-65, 70-88, 90-92, 94-99 | range | format (national IDs) |
| ATIN | 9XX-93-XXXX | range | format (region pack US) |
| EIN | XX-XXXXXXX | valid prefix | format after its cue ("EIN", "FEIN", "tax ID") |
| PTIN | P + 8 digits | the shape after the cue | cue |
| Passport, passport card | 9 digits, or a letter and 8 digits; C + 8 digits | the shape after the cue; the zone's layout | cue; machine-readable zone |
| Driver's licence | per state | the shape after the cue | cue ("driver's license", "DL"); field |
| Medicare MBI | 11 characters, letters but S L O I B Z | position rules | format in its printed form (region pack US); cue ("MBI", "Medicare") |
| Medicaid, health plan member and group numbers | free form | a code with a digit after the cue | cue; field |
| Medical record number | free form | a code with a digit after the cue | cue ("MRN", "medical record"); HL7 fields |
| NPI, DEA number | 10 digits; 2 letters + 7 digits | the shape after the cue | cue |
| ABA routing number | 9 digits | the shape after the cue | cue ("routing", "ABA") |
| Bank account | 4 to 17 digits | the shape after the cue | cue ("account number", "acct"); field |
| Payment card | 13 to 19 digits | network prefix and Luhn | format |
| A-Number | A + 8 or 9 digits | its written forms | format in its own forms (A-123-456-789, A# 123456789) and after its cue (region pack US) |
| USCIS receipt number | service centre + 10 digits (EAC, WAC, LIN, SRC, IOE, ...) | prefix | format (region pack US) |
| I-94 admission number | 11 characters | the shape after the cue | after its cue (region pack US) |
| DoD ID (EDIPI), VA file number | 10 digits; free form | the shape after the cue | cue |
| Vehicle | VIN (17 characters), licence plate | VIN check digit | format (devices); cue ("license plate") |
| Telephone, fax | NANP | libphonenumber | format |
| Street address, city, state, ZIP | number, street, suffix, unit; ZIP and ZIP+4 | a street suffix and a number, a state code | structure; field; HL7 address fields |
| Name | given name, family name | capitals | name rules; NER |
| Date of birth | US and ISO dates | a real date | cue ("DOB", "date of birth", "born") |
| Online identifiers | user ids in URLs and keys, IP addresses, e-mail addresses | their shape | machine formats; core patterns |

HIPAA's list also names URLs, biometric identifiers and photographs. Harpo redacts what identifies a person inside a
URL (user ids in paths and parameters, credentials, e-mail addresses) rather than every URL, since an assistant needs
links to do its work; it does not read images or audio, and refuses or blanks them by policy (INV-10). Dates other than
birth dates are a type of their own (`DATE`), off by default and switched on in the policy.

## The European Union

| Identifier | Format | What Harpo checks | Found by |
| --- | --- | --- | --- |
| VAT identification number | country prefix (27 states and XI) + national part | each state's check digits | format (region pack EU) |
| IBAN | country + 2 check digits + national part | mod 97 | format |
| BIC (SWIFT) | 8 or 11 characters in capitals | ISO 9362 shape and country | after its cue (region pack EU) |
| EORI number | country prefix + up to 15 characters | the shape after the cue | cue ("EORI") |
| European Health Insurance Card | card and personal numbers | the shape after the cue | cue ("EHIC", "EKVK", "CEAM", "tarjeta sanitaria europea") |
| Passport and ID card (ICAO 9303) | machine-readable zone, TD1 and TD3 | the zone's layout | format (machine formats) |
| EU Digital COVID Certificate | `URN:UVCI:01:NL:...` | prefix | format (region pack EU) |
| National identity numbers | FR NIR, ES DNI and NIE, IT codice fiscale, BE national number, DE Steuer-ID | check digits | format (national IDs) |
| | PL PESEL, SE personnummer, FI HETU, DK CPR, RO CNP, CZ and SK rodné číslo, and the others | the shape after the cue | cue words in each language |
| Licence plates | national formats | letters and digits, 4 to 10 | cue in each language |
| Telephone | E.164 | libphonenumber validity | format |
| Addresses | street, number, postcode, town | a street word and a number | structure, in 30+ languages |

## Measured

RegionBench writes Dutch, US and EU documents (letters, forms, invoices, chats, JSON records, CSV exports, logs) from
templates split once into a dev and a holdout set, marks every value they hold, and marks the look-alikes that must
come through unchanged (order numbers, amounts, dates of events, versions). On the holdout templates, which no rule
was written against, Harpo removes the values whole in the default configuration as follows:

| Region | 2.4.0 | Round 2 | Now | Now, dev templates |
| --- | --- | --- | --- | --- |
| Netherlands | 70.0% | 79.2% | 98.2% | 99.9% |
| United States | 71.3% | 83.6% | 96.4% | 100% |
| European Union | 48.3% | 79.4% | 96.7% | 100% |
| Look-alikes damaged (all templates) | 18.1% | 18.2% | 5.5% | |

The values it removes least often are US prescription numbers, Dutch case-file numbers and US insurance group numbers.
Every number, and how RegionBench is built, is in [EXTERNAL_BENCHMARKS.md](EXTERNAL_BENCHMARKS.md#regionbench).

Sources: [GDPR article 4](https://gdpr.eu/eu-gdpr/), [HIPAA Safe Harbor identifiers](https://www.johndcook.com/blog/hipaa-identifiers-explained/),
[CMS, Understanding the MBI](https://www.hhs.gov/guidance/sites/default/files/hhs-guidance-documents/Understanding-the-MBI-052918.pdf),
[EORI structure (Tullverket)](https://tullverket.se/en/business/eorieconomicoperatorregistrationandidentification/howisaneorinumberstructured.4.7df61c5915510cfe9e7606f.html),
[AP and the btw-identificatienummer](https://www.taxlive.nl/nl/documenten/nieuws/nieuw-btw-nummer-voor-eenmanszaken/).
