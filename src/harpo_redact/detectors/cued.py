"""Layer 2d: values named by the words in front of them, in the languages people write.

"0199 520 616" alone could be anything. After "Telefon", "電話" or "telefonu" it is a phone number, whatever the
numbering plan of its country says; after "Steuernummer" or "davčna številka" it is a tax number, with a valid
checksum or not. Here the cue word decides what a value is, and a loose shape check decides where it ends, so values
that are made up, mistyped or from a country without a validator are protected as well as valid ones. The validated
layers (patterns.py, identifiers.py) still find the values that come without a cue.

* Cues are words, in some 30 languages. Case and accents are folded ("Téléphone" is "telephone"), a stem takes
  inflections and compounds ("telefonu", "Sozialversicherungsnummer", but not "Telefonkonferenz"), and field names
  are split ("phone_number", "phoneNumber"). Chinese, Japanese and Korean cues are matched as text.
* Between a cue and its value: up to four words ("number on file is", "ending in"), number words ("Nr.", "n°"),
  signs, quotes, brackets and markup, and a line break straight after the cue (a label on its own line). Another
  cue in between ends the search, so the nearest cue decides.
* A value can be followed by more of its kind: "Telefon 030 123456 oder 0171 2345678".
* Without any cue, a few shapes are distinctive enough on their own, when they pass the check their format has: an
  international number in groups that its country's numbering plan has ("+33.1.39.90.78.50"), an area code in
  brackets ("(967) 759-3756"), a card number in its network's grouping with the network's prefix and a valid Luhn
  digit, and a vehicle identification number. After a cue the shape is enough; without one, a failed check means a
  look-alike.

Every step is bounded, so a scan is linear in the length of the text.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, NamedTuple

import phonenumbers
from stdnum import luhn

from ..entities import EntityType as E
from ..entities import Span, make_span
from .opaque import opaque_capitals
from .patterns import card_brand_ok

SOURCE = "cue"

# --------------------------------------------------------------------------- the lexicon
# One entry per line or comma. Words are folded (case, accents) when compiled, so they are written as people write
# them. "word*" is a stem: it also matches the word with a short ending ("telefonu") or a number word glued on
# ("telefonnummer", "sozialversicherungsnummer"). "^ENTRY" must be written in capitals (an acronym: "^CAP" is a
# postcode, "cap" is not). "!entry" needs a number word, a sign or a long number before it counts ("pass" in
# Danish and Swedish is a passport, in English a verb), "!!entry" a number word or a code in capitals and digits
# ("claim" is an amount as often as a number). A number word before the cue counts too ("numer klienta", "nomor
# pajak"). "@entry" counts only as a field's label, at the start of a line or after a bracket or a separator
# ("ID: ...", "(ID: ...)"), and its value needs a code in capitals and digits or six digits.
# Entries in Chinese, Japanese or Korean are matched as text.
_LEXICON: dict[str, str] = {
    "phone": """
        phone*, telephone*, tel, mobile*, mob, cell, cellphone*, cellular, fax*, call, calling, dial, sms, whatsapp,
        landline*, hotline*, helpline*, contact number*, contact, contacts, reach, reachable
        erreichen, erreichbar, kontaktieren, kontakt, bereikbaar, bereiken, contacter, contactez, joignable, contactar
        contacte, contáctenos, contattare, contattaci, contatto, contatti, raggiungibile, contato, contacto, contatar
        kontakte, kontakta, kontaktuj*, skontaktuj*, kontaktujte, kontaktirajte, contactați, contactati, свържете
        επικοινωνήστε, susisiekite, sazinieties, liên hệ, iletişim
        telefon*, telefonisch, handy*, mobil*, mobilfunk*, rufnummer*, anrufen, festnetz*, durchwahl*
        telefoon*, mobiel*, bel, bellen
        @gsm, gsm nummer*, gsmnummer*, telnr, tel nr, vast nummer*
        téléphone*, téléphonique, portable, appelez, appeler, appelant, joindre, télécopie
        teléfono*, móvil*, celular*, llamar, llame, llamando
        telefono*, cellulare*, chiamare, chiamando, chiamate, chiami, recapito
        telefone*, telemóvel*, ligar, ligue
        tlf, ring, ringe, ringa, opkald
        puhelin*, puh, matkapuhelin*, soita, soittamalla
        komórka*, komórkowy, zadzwoń, dzwoń, faks
        zavolejte, volejte, zavolat, zavolajte, volajte, telefonicky
        pokličite, pokliči, mobilni*, mobitel*, nazovite, nazvati, pozovite, pozvati
        hívja, hívjon, hívás
        sunați, sună, apelați
        телефон*, тел, мобилен, обадете, позовите, звоните, моб
        τηλέφωνο*, τηλεφώνου, τηλ, κινητό*, καλέστε
        skambinkite, skambindami, skambinti
        tālrunis, tālruņa, tālr, zvaniet, zvanīt
        mobiil*, helista*
        telepon, telp, ponsel, handphone, hubungi
        telepono, tawagan
        điện thoại, sđt, di động, gọi
        cep telefonu, arayın
        電話, 電話番号, 携帯, 携帯電話, 連絡先, ファックス
        电话, 手机, 手機, 联系电话, 聯絡電話, 联系方式, 传真, 傳真, 座机
        전화, 전화번호, 휴대폰, 핸드폰, 연락처, 팩스
    """,
    "card": """
        credit card*, debit card*, card*, ^CC, ^PAN, visa, mastercard, amex, american express, payment card*
        payment method*
        bank card*, cardholder*
        kreditkarte*, karte*, debitkarte*, girocard, bankkarte*, ec karte*
        creditcard*, kaart*, betaalpas*, pinpas*, bankpas*
        carte*, ^CB
        tarjeta*
        carta*
        cartão*, cartao*
        kort, kortet, kortnummer, kreditkort*, betalkort*, dankort*
        kortti*, luottokortti*, pankkikortti*
        karta*, karty, kartou, kartą
        kartic*, kreditn* kartic*
        kártya*, hitelkártya*
        card de credit, cardul
        карта*, кредитна карта*
        κάρτα*, πιστωτική*
        kortelė*, kortelės, kortelę
        kredītkarte*, karte*
        kaart*, krediitkaart*, pangakaart*, kaardi, krediitkaardi, pangakaardi, kortin, luottokortin
        kartu, kartu kredit, kartu debit, kad kredit
        thẻ tín dụng, số thẻ, thẻ ngân hàng
        kredi kartı*
        カード, クレジットカード, カード番号
        信用卡, 银行卡, 銀行卡, 卡号, 卡號, 借记卡
        카드, 신용카드, 카드번호, 체크카드
    """,
    "national": """
        ^SSN, social security*, social insurance*, national insurance*, national id*, national identification*
        national identity*, national number, tax id*, tax identification*, tax number*, tax file*, tax code*, ^TFN
        taxpayer*, ^TIN, ^ITIN, ^EIN, ^FEIN, ^SIN, ^NINO, ^NIN, personal id*, personal number*, personal identity*
        personal code*, identity number*, id number*, identification number*, citizen id*, resident id*, ^VAT
        vat number*, vat id*, identification*, nationalt id*, nationellt id*, nasjonalt id*, nationale id*
        id nazionale, id national, id nacional, identificación*, identificação*, identificazione*, identifikation*
        identificatie*, identyfikacyjn*, identifikační*, identifikačné*, azonosító*, identificare*, identifikacij*
        identifikacijsk*, socialsikkerhed*, sociale zekerheid*, seguro social, impuesto*, ^PDV, số thuế
        steuer*, steueridentifikationsnummer, steuer identifikationsnummer, steuer identifikations*, steuer id*
        ^IDNR, identifikationsnummer*, sozialversicherung*, versicherungsnummer*, rentenversicherungsnummer*, ^AHV
        ^SVNR, umsatzsteuer*, ust id*
        ^BSN, burgerservicenummer*, sofinummer*, fiscaal nummer*, btw nummer*, ^RSIN, persoonsnummer*
        !btw*, btw identificatienummer*, btw id*, omzetbelastingnummer*, loonheffingennummer*, ^KVK, kvk*
        kamer van koophandel, handelsregister*, vestigingsnummer*, onderwijsnummer*, ^PGN, a nummer*
        administratienummer*, v nummer*, vreemdelingennummer*, ^EORI, eori*, ^PTIN, ^ATIN, ^EDIPI, dod id*
        dod identification*, dod benefits number*, known traveler*, known traveller*, ^KTN, redress number*
        sécurité sociale, ^NIR, ^INSEE, numéro fiscal, identification fiscale, ^SPI, assurance sociale, ^AVS
        numéro national, ^NIF
        ^DNI, ^NIE, ^CIF, ^NSS, seguridad social, número fiscal, identificación fiscal, ^RFC, ^CURP, ^CUIL, ^CUIT
        ^RUT, ^RUN, cédula*
        codice fiscale, partita iva, numero fiscale, previdenza sociale, tessera sanitaria, sicurezza sociale
        contribuinte, ^CPF, ^CNPJ, segurança social, ^NISS, número de utente, ^PIS
        ^CPR, cpr nummer*, personnummer*, fødselsnummer*, skattenummer*, skattekode*, skatte id*, sygesikring*
        samordningsnummer*
        henkilötunnus*, ^HETU, sotu, sosiaaliturvatunnus*, verotunnus*, veronumero*
        ^PESEL, ^NIP, ^REGON, numer ubezpieczenia, identyfikacji podatkowej, podatkowy*
        rodné číslo, daňové*, ^DIČ, číslo pojištěnce, sociálního pojištění, sociálneho poistenia
        ^EMŠO, davčn* številk*, ^ZZZS, številka zavarovanja
        ^OIB, ^JMBG, ^MBO, porezni broj, socijaln* osiguranj*, matični broj, ^PIB, ^LBO, ^ЈМБГ, ^ПИБ
        adóazonosító*, adószám*, ^TAJ, taj szám*, személyi szám*, társadalombiztosítási*
        ^CNP, cod numeric personal, ^CUI, cod fiscal, identificare fiscală, asigurar* social*
        ^ЕГН, ^ЛНЧ, данъчен номер, осигурителен номер, ^ИНН, ^СНИЛС
        ^ΑΦΜ, ^ΑΜΚΑ, φορολογικ*, κοινωνικ* ασφάλισ*
        asmens kod*, mokesčių*, socialin* draudim*, ^PVM
        personas kod*, nodokļu*, sociālās apdrošināšanas, ^PVN
        isikukood*, maksu*, maksukohustuslase*, registrikood*, kindlustus*
        ^NIK, ^NPWP, kependudukan, pajak, jaminan sosial, ^BPJS, ^NRIC, cukai, keselamatan sosial, ^PERKESO
        ^KWSP, ^EPF, ^SSS, philhealth, ^UMID
        ^CCCD, ^CMND, mã số thuế, bảo hiểm xã hội, căn cước
        tc kimlik*, kimlik numarası, vergi numarası, vergi kimlik*
        マイナンバー, 個人番号, 社会保障番号, 税番号, 納税者番号, 基礎年金番号
        身份证, 身份證, 社会保障号, 社保号, 社會安全號碼, 税号, 稅號, 纳税人识别号, 统一社会信用代码
        주민등록번호, 주민번호, 외국인등록번호, 사업자등록번호, 납세번호, 사회보장번호
    """,
    "document": """
        passport*, driver licen*, drivers licen*, driver s licen*, driving licen*, ^DL, license number*
        licence number*, id card*, identity card*, identification card*, residence permit*, residence card*
        permit number*, visa number*
        green card*, alien registration*, birth certificate*, certificat de naissance, acte de naissance
        geburtsurkunde*, partida de nacimiento, acta de nacimiento, certidão de nascimento, certificato di nascita
        akt urodzenia, rodný list, születési anyakönyvi kivonat, születési okirat*, certificat* de naștere
        fødselsattest*, födelsebevis*, syntymätodistus*, rojstni list, rodni list
        свидетелство за раждане, πιστοποιητικό γέννησης, gimimo liudijim*, dzimšanas apliecīb*, sünnitunnistus*
        akta kelahiran, sijil kelahiran, giấy khai sinh, 出生証明書, 出生证明, 出生證明, 출생증명서
        reisepass*, passnummer*, ausweis*, personalausweis*, führerschein*, fuehrerschein*, fahrerlaubnis*
        aufenthaltstitel*, aufenthaltserlaubnis*, identitätskarte*, id karte*
        paspoort*, rijbewijs*, identiteitskaart*, id kaart*, verblijfsvergunning*, id bewijs*, legitimatie*
        documentnummer*, verblijfsdocument*, verblijfspas*, identiteitsbewijs*, identiteitsdocument*
        passport card*, state id*, state identification*, ^DLN, ^CDL, operator s licen*, learner s permit*
        admission number*, i94 number*, visa foil*
        passeport*, permis de conduire, carte d identité, carte nationale d identité, titre de séjour, carte de séjour
        pièce d identité, ^CNI, !!permis
        pasaporte*, licencia de conducir, licencia de conducción, permiso de conducir, carnet de conducir
        documento de identidad, documento nacional de identidad, cédula de identidad, tarjeta de residencia
        carné de identidad
        passaporto*, patente*, patente di guida, carta d identità, permesso di soggiorno, documento di identità
        carta de condução, carteira de motorista, carteira de habilitação, ^CNH, carteira de identidade
        cartão de cidadão, bilhete de identidade, autorização de residência
        !pas, pasnummer*, kørekort*, førerkort*, id kort*, opholdstilladelse*
        !pass, körkort*, nationellt id kort*, uppehållstillstånd*
        passi, passin, passinumero*, ajokortti*, ajokortin, henkilökortti*, oleskelulupa*, id kortti*
        paszport*, prawo jazdy, prawa jazdy, dowód osobist*, dowodu osobist*, karta pobytu, dowód tożsamości
        dowodu tożsamości
        cestovní pas*, cestovn* pas*, řidičsk* průkaz*, občansk* průkaz*, vodičsk* preukaz*, občiansk* preukaz*
        potn* list*, vozniško dovoljenje, vozniškega dovoljenja, osebn* izkaznic*, osebn* dokument*
        putovnic*, vozačk* dozvol*, osobn* iskaznic*, pasoš*, ličn* kart*, ličn* dokument*
        пасош*, возачк* дозвол*, личн* карт*
        útlevél*, jogosítvány*, vezetői engedély*, személyi igazolvány*
        pașaport*, permis de conducere, permisul de conducere, carte de identitate, cartea de identitate
        buletin*, act de identitate, actul de identitate, actului de identitate, certificat* de ședere
        паспорт*, шофьорска книжка, свидетелство за управление, лична карта, водительск* удостоверени*
        удостоверени* личности
        διαβατήριο*, διαβατηρίου, δίπλωμα οδήγησης, άδεια οδήγησης, ταυτότητα*, ταυτότητας, δελτίο ταυτότητας
        pasas, !paso, vairuotojo pažymėjim*, asmens tapatybės kortel*, ^ATK
        pase*, vadītāja apliecīb*, personas apliecīb*, id karte*
        passi number*, juhilub*, juhiloa*, isikutunnistus*, id kaart*, id kaardi*, elamislub*, elamisloa*
        isikut tõendav*
        paspor, nomor sim, surat izin mengemudi, ^KTP, kartu tanda penduduk, ^KITAS, identitas, identifikasi
        pasport, lesen memandu, kad pengenalan, mykad, pasaporte, lisensya*
        hộ chiếu, giấy phép lái xe, bằng lái, căn cước công dân, chứng minh nhân dân
        pasaport*, ehliyet*, sürücü belgesi, kimlik kartı*
        パスポート, 旅券, 運転免許証, 運転免許, 免許証, 在留カード, 身分証, 身分証明書
        护照, 護照, 驾驶证, 駕駛證, 驾照, 駕照, 驾驶执照, 居留证, 居留證, 通行证
        여권, 운전면허증, 운전면허, 면허번호, 신분증, 외국인등록증
    """,
    "postcode": """
        postcode*, post code*, postal code*, ^ZIP, zip code*, zipcode*, zip
        ^PLZ, postleitzahl*
        code postal, ^CP, ^C P
        código postal, ^CAP, codice postale, codice di avviamento postale, ^CEP
        postnummer*, postnr, postinumero*, kod* pocztow*
        ^PSČ, poštovní směrovací číslo, poštové smerovacie číslo, poštn* številk*, poštansk* broj*
        irányítószám*, cod postal, codul poștal, пощенски код, ταχυδρομικ* κώδικ*, ^Τ Κ
        pašto kod*, pasta indeks*, postiindeks*, kode pos, poskod*, mã bưu điện, mã bưu chính, posta kodu
        почтовый индекс
        郵便番号, 〒, 邮编, 邮政编码, 郵遞區號, 郵政編碼, 우편번호
    """,
    "account": """
        account*, acct, bank account*
        !customer*, !client*, !member*, !membership*, !subscriber*, !beneficiary*, !!policy, !policyholder*, @^!!ID
        !!insurance, health plan*, group number*, !!claim, !patient*, medical record*, ^MRN, ^!MR, record number*
        !student*, !employee*, !staff*, !personnel*, !payroll*, matriculation*, enrolment number*, user id*
        enrollment number*, userid*, login id*, !loyalty*, !rewards*, frequent flyer*, frequent flier*, !mileage*
        skymiles
        !!booking, !!reservation, !!confirmation, record locator*, ^PNR, !!ticket, e ticket*, !!case, !!docket
        !!registration, !!certificate*, !!certification, !!license, !!licence, ^NPI, ^DEA, !!badge, voter id*
        voter registration*, library card*, !!contract, !!loan, !!mortgage, !!pension
        konto*, kontonummer*, !kunden*, !mitglied*, !versicherten*, matrikel*
        personalnummer*, !mitarbeiter*, !!vertrag*, !!police*, !!policen*, !!schaden*, !!buchung*, aktenzeichen*
        rekening*, !klant*, !!polis*, studentnummer*, personeelsnummer*, patiëntnummer*, dossiernummer*
        ^AGB, agb*, ^BIG, big nummer*, big registratie*, ^UZI, uzi nummer*, uzi pas*, ^URA, verzekerdennummer*
        relatienummer*, zaaknummer*, parketnummer*, !personeel*, werknemersnummer*, leerlingnummer*, ov chipkaart*
        ov chip*, zorgpas*, ^EHIC, ehic*, european health insurance card*, europese ziekteverzekeringskaart*
        europäische krankenversicherungskarte*, ^EKVK, carte européenne d assurance maladie, ^CEAM
        tarjeta sanitaria europea, tessera europea*, medicare*, ^MBI, ^HICN, medicaid*, !group*, !rx
        !!prescription*, accession*, !!encounter*, visit number*, chart number*, va file*, va claim*
        boekingsnummer*, reserveringsnummer*
        !identifier, !resident*, meeting id*, meeting number*, conference id*, transaction id*, !!transaction*
        acquirer reference*, ^ARN, retrieval reference*, ^RRN, authorization code*, approval code*
        compte*, ^RIB, !adhérent*, !membre*, !assuré*, !!dossier*, !étudiant*, matricule*, !employé*, !!contrat*
        cuenta*, !cliente*, !socio*, !afiliado*, !asegurado*, !!póliza*, !!expediente*, !estudiante*, !empleado*
        !!reserva*, !!contrato*, historia clínica
        conto, conti, conto corrente, !tessera*, !!polizza*, !!pratica*, matricola*, !dipendente*, !!prenotazione*
        !!contratto*
        cartella clinica
        conta, contas, da conta, !sócio*, !beneficiário*, !!apólice*, !!processo*, matrícula*, !funcionário*
        prontuário*
        !kunde*, !medlem*, !!sag*, studienummer*, !medarbejder*, !kund*, försäkringsnummer*
        !!ärende*, anställningsnummer*, !!bokning*
        tili*, !asiakas*, !jäsen*, !vakuutus*, !opiskelija*, !!varaus*
        rachun*, !klient*, !członk*, !legitymacj*, !pracownik*, !!rezerwacj*
        účet, účtu, !zákazník*, !zákaznick*, !pojištěnec*, !zaměstnan*, !zamestnan*, !!rezervac*
        račun*, !stranka*, !član*, !zavarovanc*, !zaposlen*, !klijent*, !korisnik*, !osiguranik*, !zaposlenik*
        рачун*
        számla*, !ügyfél*, !biztosítás*, !hallgató*, !dolgozó*, !!foglalás*
        cont, contul, contului, !membru*, !asigurat*, !!poliț*, !angajat*, !!rezervar*, !!dosar*
        сметка*, !клиент*, !член*, !!полица*
        λογαριασμ*, !πελάτ*, !ασφαλισμέν*
        sąskait*, !nari*, !darbuotoj*, !!rezervacij*
        konta, kontu, konts, !biedr*
        arveldus*, !kliendi*, !liikme*, !!broneering*
        !nasabah, !pelanggan, !anggota, !mahasiswa, !karyawan, !pegawai, akaun*, !ahli, !pelajar, !pekerja
        !miyembro, tài khoản, số tài khoản, !khách hàng, mã khách hàng, !thành viên
        口座番号, 口座, 顧客番号, 会員番号, お客様番号, 保険証番号, 社員番号, 学籍番号, 予約番号, 患者番号
        账号, 賬號, 账户, 帳戶, 客户号, 客户编号, 会员号, 會員號, 保单号, 员工号, 工号, 学号, 病历号
        계좌번호, 계좌, 고객번호, 회원번호, 보험번호, 사번, 학번, 예약번호
    """,
    "bank": """
        routing*, ^ABA, aba number*, ^RTN, sort code*, ^BSB, transit number*, ^IFSC, ^CLABE, ^BLZ, bankleitzahl*
        ^BIC, bic*, ^SWIFT, swift*
        clearingnummer*
    """,
    "iban": """
        ^IBAN, iban*
    """,
    "vehicle": """
        ^VIN, vin number*, vehicle identification*, vehicle identifier*, vehicle id*, chassis*, frame number*
        fahrgestellnummer*, fahrzeugidentifikationsnummer*, fahrzeug identifikationsnummer*, ^FIN, numéro de châssis
        numéro de série du véhicule, número de bastidor, número de chasis, número de identificación vehicular
        numero di telaio, telaio, número do chassi, chassi, chassisnummer*, chassinummer*, stelnummer*
        runkonumero*, numer nadwozia, numer vin, číslo karoserie, číslo podvozku, alvázszám*, numărul de șasiu
        αριθμός πλαισίου, kėbulo numeris, šasijas numurs, nomor rangka, nombor casis, số khung
        車台番号, 车架号, 車架號, 차대번호
    """,
    "plate": """
        license plate*, licence plate*, number plate*, registration plate*, plate number*, plate no*, plate
        tag number*, kenteken*, nummerplaat*, nummerbord*, kennzeichen*, nummernschild*, autokennzeichen*
        immatriculation, plaque d immatriculation, matrícula, placa*, targa, numer rejestracyjny*, rendszám*
        registreringsnummer*, rekisterinumero*, rekisterikilpi*, ^SPZ, evidenčn* čísl*, registarsk* tablic*
        registracijsk* oznak*, număr de înmatriculare, numărul de înmatriculare, регистрационен номер
        αριθμός κυκλοφορίας, valstybinis numeris, numurzīme*, registreerimisnumber*, plat nomor, nomor polisi
        biển số, plaka*, ナンバープレート, 车牌, 車牌, 번호판
    """,
    "device": """
        device id*, device identifier*, deviceid*, device serial*, device number*, ^IMEI, ^MEID, ^UDID, android id*
        advertising id*, ^IDFA, ^IDFV, ^GAID, hardware id*, ^HWID, machine id*, serial number*, serial no*
        seriennummer*, geräte id*, gerätenummer*, gerätekennung*, numéro de série, identifiant de l appareil
        número de serie, id del dispositivo, identificador del dispositivo, numero di serie, id dispositivo
        número de série, serienummer*, sarjanumero*, numer seryjny, sériové číslo, výrobní číslo
        serijska številka, serijski broj, sorozatszám*, numărul de serie, сериен номер, σειριακός αριθμός
        serijos numeris, sērijas numurs, seerianumber*, nomor seri, nombor siri, số sê ri
        シリアル番号, 製造番号, 端末ID, 序列号, 设备号, 设备ID, 機器番号, 시리얼 번호, 일련번호
    """,
    "pin": """
        pin, pin code*, pin number*, pincode*, personal identification number*, passcode*, security code*, ^CVV, puk*
        cvv, cvc, cvv2, cvc2, toegangscode*, beveiligingscode*
        puk code*, door code*, gate code*, alarm code*, entry code*, access code*, keypad code*, lock code*
        ^CVC, ^CVV2, ^CVC2, card verification*, pin koodi*, pin kod*, kod pin, code pin, código pin, codice pin
        暗証番号, 密码, 驗證碼, 验证码, 비밀번호
    """,
}
_KIND_TYPE = {
    "phone": E.PHONE,
    "card": E.CREDIT_CARD,
    "national": E.NATIONAL_ID,
    "document": E.ID_DOCUMENT,
    "postcode": E.ADDRESS,
    "account": E.ACCOUNT_ID,
    "bank": E.ACCOUNT_ID,
    "iban": E.IBAN,
    "pin": E.SECRET,
    "vehicle": E.DEVICE_ID,
    "plate": E.DEVICE_ID,
    "device": E.DEVICE_ID,
}
# Words that name a number ("number", "Nr.", "n°", "číslo", "αριθμός", "номер"). Between a cue and its value they
# are skipped without counting; glued to a stem they make a compound ("Telefonnummer").
_NUMBER_WORDS = frozenset(
    """number numbers num nr nro no nos nb n o numero numeros nummer nummern numer numeru numery cislo cisla cislem
        broj broja stevilka stevilko stevilke numar numarul numarului numurs numuru numura numeris numerio numerį
        numbri szam szama szamu szamot αριθμος αριθμο αριθμου номер номера номерът nomor nombor so ma id ids code
        codes kode kod kodas kodu kods koda kood koodi codigo codice cod tunnus tunniste identifier identifiant
        identificador identificativo identificatore identifikator identyfikator ref reference referencia riferimento
        referentie numret numren nummeret numrene numre numeron numerot numeroa numerem numerze broju brojem
        nomornya""".split()  # noqa: SIM905
)  # fmt: skip
_LINKS = ("", "s", "e", "n", "es", "en", "er", "o", "a", "i")  # Fugen-s and friends: "versicherungsnummer"
_INFLECTION = 4  # "telefonu", "kortelės", "dowodu": a stem's ending is at most this long
_LONG_STEM = 9

_CJK_RE = re.compile(r"[぀-ヿ㐀-䶿一-鿿가-힯　-〿]")
_FOLD = str.maketrans({"ø": "o", "Ø": "o", "æ": "ae", "Æ": "ae", "đ": "d", "Đ": "d", "ł": "l", "Ł": "l",
                       "ı": "i", "œ": "oe", "Œ": "oe", "ð": "d", "þ": "th"})  # fmt: skip


@lru_cache(maxsize=65536)
def fold(word: str) -> str:
    """Case and accents removed: 'Téléphone' -> 'telephone', 'Kørekort' -> 'korekort', 'ΑΦΜ' -> 'αφμ'."""
    decomposed = unicodedata.normalize("NFKD", word.translate(_FOLD))
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()


# Number words as folded text is compared, and those that also name a number before a cue ("numer klienta",
# "nomor pajak"); short ones ("no", "so") are other words there.
_NUMBER_WORDS = frozenset(fold(w) for w in _NUMBER_WORDS)
_NUMBER_BEFORE = frozenset(w for w in _NUMBER_WORDS if len(w) >= 3)


@dataclass(frozen=True, slots=True)
class _Cue:
    words: tuple[str, ...]
    stems: tuple[bool, ...]
    kind: str
    upper: bool  # written in capitals
    strict: int  # 1: a number word, a sign or a long number; 2: a number word or a code; 3: a code or six digits
    label: bool  # only as a field's label


def _compile() -> tuple[dict[str, list[_Cue]], dict[str, list[_Cue]], list[tuple[str, str, bool]]]:
    exact: dict[str, list[_Cue]] = {}
    stems: dict[str, list[_Cue]] = {}
    cjk: list[tuple[str, str, bool]] = []
    for kind, block in _LEXICON.items():
        for raw in re.split(r"[,\n]", block):
            entry = raw.strip()
            if not entry:
                continue
            if _CJK_RE.search(entry) or entry == "〒":
                cjk.append((entry, kind, any(w in entry for w in ("番号", "号码", "號碼", "号", "번호"))))
                continue
            marks = entry[: len(entry) - len(entry.lstrip("^!@"))]
            upper, strict, label = "^" in marks, marks.count("!"), "@" in marks
            if label:
                strict = 3
            entry = entry.lstrip("^!@")
            parts = entry.split()
            words = tuple(fold(p.rstrip("*")) for p in parts)
            cue = _Cue(words, tuple(p.endswith("*") for p in parts), kind, upper, strict, label)
            if cue.stems[0]:
                stems.setdefault(words[0][:3], []).append(cue)
            else:
                exact.setdefault(words[0], []).append(cue)
    return exact, stems, sorted(cjk, key=lambda c: -len(c[0]))


_EXACT, _STEMS, _CJK_CUES = _compile()
_CJK_CUE_RE = re.compile("|".join(re.escape(c[0]) for c in _CJK_CUES))
_CJK_KIND = {c[0]: (c[1], c[2]) for c in _CJK_CUES}


def _word_matches(token: str, word: str, stem: bool) -> tuple[bool, bool]:
    """(matches, carries a number word): 'telefonnummer' matches the stem 'telefon' and names a number."""
    if not stem:
        return token == word, False
    if not token.startswith(word):
        return False, False
    tail = token[len(word) :]
    if not tail:
        return True, False
    for link in _LINKS:
        if tail.startswith(link) and tail[len(link) :] in _NUMBER_WORDS:
            return True, True
    # A long stem keeps its meaning in any compound ("Kreditkarteninformation", "Postleitzahlregion"); a short one
    # does not ("Telefonkonferenz").
    return len(tail) <= _INFLECTION or len(word) >= _LONG_STEM, False


# --------------------------------------------------------------------------- tokens
_TOKEN_RE = re.compile(r"[^\W\d_]+")
_ALNUM_RE = re.compile(r"[^\W_]+(?:-[^\W_]+)?")  # a word with its digits: "base64", "sha-256", "utf-8"
_JOINT_RE = re.compile(
    r"[ \t\-_.'’/\u2010-\u2015\u2212]{0,3}"
)  # empty between camel-case parts  # between the words of one cue: "driver's license", "phone_number"


class _Token(NamedTuple):
    start: int
    end: int
    folded: str
    upper: bool


_DIGITS_RE = re.compile(r"\d+")
_REACH = 112  # a cue starts at most this far before its value: the cue itself, then the gap (_MAX_GAP)


_CAPITALS_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{6,20}(?![A-Za-z0-9])")


def _windows(text: str) -> list[tuple[int, int]]:
    """The stretches that can hold a cue: the text before each number, up to _REACH characters. Values hold a digit,
    or are a code in capitals that no language writes ("PEWRDYDWEI"), so prose far from both is never tokenised."""
    anchors = [m.start() for m in _DIGITS_RE.finditer(text)]
    codes = [m.start() for m in _CAPITALS_RE.finditer(text) if opaque_capitals(m.group(), cued=True)]
    if codes:
        anchors = sorted(anchors + codes)
    windows: list[tuple[int, int]] = []
    for start in anchors:
        a = max(0, start - _REACH)
        while a > 0 and text[a - 1].isalpha():
            a -= 1  # never start inside a word
        if windows and a <= windows[-1][1]:
            windows[-1] = (windows[-1][0], start)
        else:
            windows.append((a, start))
    return windows


def _tokens(text: str, windows: list[tuple[int, int]]) -> list[_Token]:
    """Words, with field names split: 'phoneNumber' -> phone, Number; 'phone_number' -> phone, number."""
    out: list[_Token] = []
    append = out.append
    for a, b in windows:
        _tokenise(text, a, b, append)
    return out


def _tokenise(text: str, a: int, b: int, append: Any) -> None:
    for m in _TOKEN_RE.finditer(text, a, b):
        word, base = m.group(), m.start()
        if (base and text[base - 1].isdigit()) or (word.isupper() and m.end() < len(text) and text[m.end()].isdigit()):
            continue  # letters inside a code ("EN1GPBE9DL", "MR03KE7Z3Q") are not a word; "phone1" still is
        if word.islower() or word.isupper() or word[1:].islower() or (len(word) <= 4 and word[0].isupper()):
            # whole words, and short acronyms in mixed case ("KvK", "BvD"): only longer ones are field names
            if not ("\u3040" <= word[0] <= "\ud7af"):  # Chinese, Japanese, Korean: matched as text
                append(_Token(base, m.end(), fold(word), word.isupper()))
            continue
        if _CJK_RE.match(word):
            continue
        cut = 0
        for i in range(1, len(word)):
            if word[i].isupper() and word[i - 1].islower():
                append(_Token(base + cut, base + i, fold(word[cut:i]), word[cut:i].isupper()))
                cut = i
        append(_Token(base + cut, base + len(word), fold(word[cut:]), word[cut:].isupper()))


@dataclass(frozen=True, slots=True)
class _Found:
    start: int
    end: int
    kind: str
    strict: int
    noun: bool  # the cue itself names a number ("Steuernummer", "番号")


_LINE_HEAD_RE = re.compile(r"[ \t]*(?:[-*•>][ \t]*|\d{1,2}[.)][ \t]*)?[*_]{0,2}")


def _starts_field(text: str, at: int) -> bool:
    """Whether a field's label can start at ``at``: only blanks, a bullet or a list number before it on its line, or
    a bracket, a table cell or a separator right before it ("(ID: ...)", "Name: X, ID: ...")."""
    head = text.rfind("\n", 0, at) + 1
    if at - head <= 12 and _LINE_HEAD_RE.fullmatch(text, head, at) is not None:
        return True
    before = text[max(head, at - 3) : at].rstrip(" \t")
    return before[-1:] in ("(", "[", "|", ";", ",")


_BETWEEN_RE = re.compile(r"[ \t\-'’]{1,3}")


def _number_before(text: str, tokens: list[_Token], i: int) -> bool:
    """A number word just before the cue at token ``i``, at most one word away: "numer klienta", "Nomor Identitas
    Pajak", "numéro de dossier"."""
    for j in (i - 1, i - 2):
        if j < 0 or not _BETWEEN_RE.fullmatch(text, tokens[j].end, tokens[j + 1].start):
            return False
        if tokens[j].folded in _NUMBER_BEFORE:
            return True
    return False


def _cues(text: str, tokens: list[_Token], windows: list[tuple[int, int]]) -> list[_Found]:
    found: list[_Found] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        best: tuple[int, _Cue, bool] | None = None
        for cue in (*_EXACT.get(tok.folded, ()), *_STEMS.get(tok.folded[:3], ())):
            if (cue.upper and not tok.upper) or (cue.label and not _starts_field(text, tok.start)):
                continue
            n = len(cue.words)
            if i + n > len(tokens):
                continue
            noun = False
            ok = True
            for k in range(n):
                t = tokens[i + k]
                if k and not _JOINT_RE.fullmatch(text, tokens[i + k - 1].end, t.start):
                    ok = False
                    break
                matched, named = _word_matches(t.folded, cue.words[k], cue.stems[k])
                if not matched or (cue.upper and not t.upper):
                    ok = False
                    break
                noun = noun or named
            if ok and (best is None or n > len(best[1].words)):
                best = (i + n - 1, cue, noun)
        if best is None:
            i += 1
            continue
        last, cue, noun = best
        noun = noun or (cue.strict > 0 and _number_before(text, tokens, i))
        found.append(_Found(tok.start, tokens[last].end, cue.kind, cue.strict, noun))
        i = last + 1
    if not text.isascii() and _CJK_RE.search(text):
        for a, b in windows:
            for m in _CJK_CUE_RE.finditer(text, a, b):
                kind, noun = _CJK_KIND[m.group()]
                found.append(_Found(m.start(), m.end(), kind, False, noun))
        found.sort(key=lambda f: f.start)
    return found


# --------------------------------------------------------------------------- values
# A run of letter-and-digit groups joined by single separators ("+45 05450-5504", "756.1121.4315.52", "CHE-230.278.000",
# "Z3 FRA 22 JJ 8543"). Each kind then keeps the groups it can hold.
# A value's characters and the single separators between its groups; also " - " between groups of digits, as forms
# print them ("482 - 55 - 9102", "714 - 892 - 4113").
_CHAIN_RE = re.compile(
    r"[+(]?[A-Za-z0-9](?:[A-Za-z0-9)]|[ .\-/\u2010-\u2015\u2212](?=[A-Za-z0-9(])|(?<=\d) [\-\u2013] (?=\d))*"
)
_GROUP_RE = re.compile(r"[A-Za-z0-9()+]+")
_DATE_PARTS_RE = re.compile(r"(\d{1,4})[./\-](\d{1,2})[./\-](\d{1,4})")
_YEAR_RANGE_RE = re.compile(r"(?:19|20)\d{2}[\-–/](?:19|20)?\d{2}")


def _looks_like_date(value: str) -> bool:
    """'14.03.2024', '03/14/24', '2024-03-14', '2023-2024': a date or a span of years, not an identifier."""
    if _YEAR_RANGE_RE.fullmatch(value):
        return True
    m = _DATE_PARTS_RE.fullmatch(value)
    if m is None:
        return False
    a, b, c = (int(x) for x in m.groups())
    if len(m.group(1)) == 4:
        return 1 <= b <= 12 and 1 <= c <= 31
    if len(m.group(3)) not in (2, 4):
        return False
    return 1 <= a <= 31 and 1 <= b <= 31 and min(a, b) <= 12


_TIME_SHAPE_RE = re.compile(r"\d{1,2}[:.]\d{2}(?:[:.]\d{2})?")
_IP_SHAPE_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2}|:\d{1,5})?")
# An amount. After an account cue, any grouping of thousands ("balance 1 250 000"). After other cues a decimal part,
# thousands set off by commas or apostrophes, or a single group of thousands ("12.345"): longer runs of groups set
# off by dots or blanks are how identifiers are written too ("60.171.843.668", "396 860 468"). A currency next to the
# value settles it either way (_after).
_AMOUNT_SHAPE_RE = re.compile(r"\d{1,3}(?:[.,' ]\d{3})+(?:[.,]\d{1,2})?|\d+[.,]\d{1,2}")
_SHORT_AMOUNT_RE = re.compile(
    r"\d{1,3}(?:[.,' ]\d{3})*[.,]\d{1,2}|\d+[.,]\d{1,2}|\d{1,3}(?:[,']\d{3})+|\d{1,3}[. ]\d{3}"
)
_CURRENCY_CODES = frozenset("EUR USD GBP CHF JPY CNY INR SEK NOK DKK PLN CZK HUF RON BGN".split())  # noqa: SIM905
_CURRENCY_BEFORE_RE = re.compile(rf"(?:[$€£¥₹₩₽¢]|\b(?:{'|'.join(sorted(_CURRENCY_CODES))}))[ \t]?$")
_CURRENCY_AFTER_RE = re.compile(rf"[ \t]?(?:[$€£¥₹₩₽¢]|(?:{'|'.join(sorted(_CURRENCY_CODES))}|kr|zł|Kč|Ft|lei|лв)\b)")
_IBAN_SHAPE_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{8,30}")
_IFSC_RE = re.compile(r"[A-Z]{4}0[A-Z0-9]{6}")
_BIC_RE = re.compile(r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?")  # "ABNANL2A", "COBADEFFXXX" (ISO 9362)
_VERSION_SHAPE_RE = re.compile(r"[vV]\d+(?:\.\d+)+|\d{1,3}(?:\.\d{1,3}){1,2}")  # "v2.4.0", "10.15.7"
_POSTCODE_RE = re.compile(
    r"\d{3} ?\d{2}|\d{4,6}|\d{2}-\d{3}|\d{3}-\d{4}|\d{4}-\d{3}|\d{5}-\d{3,4}|[A-Z]{1,2}-\d{3,5}"
    r"|[A-Z]\d[A-Z] ?\d[A-Z]\d"
    r"|[A-Z]{1,2}\d[A-Z\d]?(?: ?\d[A-Z]{2})?|\d{4} ?[A-Z]{2}|[A-Z]\d{2} ?[A-Z\d]{4}"
)
_LETTER_KINDS = frozenset({"national", "document", "postcode", "account", "bank", "iban", "vehicle", "plate", "device"})
# Kinds whose value may be a code of capitals alone, when no language writes it (opaque.py).
_OPAQUE_KINDS = frozenset({"national", "document", "account"})
_DIGITS_AFTER_RE = re.compile(r" \d{5}")


# The name of an encoding, digest or format: "account number (base64): ...", "key (sha256)" name how the value is
# written, and are never the value.
_FORMAT_WORD_RE = re.compile(
    r"(?i)base(?:64|32|58|85|36)|hex|sha-?(?:1|224|256|384|512)?|md5|crc-?32|utf-?(?:8|16|32)|ascii|latin-?1"
    r"|iso-?8859(?:-\d{1,2})?|x\.?509|pkcs-?#?\d{1,2}|aes-?\d{3}|rsa-?\d{4}|int(?:8|16|32|64)|u?int\d{1,2}|float(?:32|64)"
)


# A Windows security identifier that names a built-in account or group ("S-1-5-18" is LocalSystem, "S-1-5-32-544" the
# Administrators group, "S-1-1-0" Everyone): the same on every machine, so it identifies no one. Domain and Entra ID
# accounts ("S-1-5-21-...", "S-1-12-1-...") do.
_WELL_KNOWN_SID_RE = re.compile(r"S-1-(?!5-21-|12-1-)\d{1,2}(?:-\d{1,10}){1,3}", re.IGNORECASE)


def _shape_ok(kind: str, value: str) -> bool:
    if _FORMAT_WORD_RE.fullmatch(value) or _WELL_KNOWN_SID_RE.fullmatch(value):
        return False
    if kind in _OPAQUE_KINDS and value.isalpha() and opaque_capitals(value, cued=True):
        return True  # "driver's license number CLYAFCWFNSIMY"
    digits = sum(c.isdigit() for c in value)
    alnum = sum(c.isalnum() for c in value)
    ip = _IP_SHAPE_RE.fullmatch(value)
    if ip is not None and all(int(octet) <= 255 for octet in ip.group(1).split(".")):
        return False
    if _looks_like_date(value) or _TIME_SHAPE_RE.fullmatch(value):
        return False
    if kind == "phone":
        return 7 <= digits <= 15 and digits == alnum
    if kind == "card":
        return 13 <= digits <= 19 and digits == alnum
    if kind == "pin":
        return 3 <= digits <= 8 and alnum <= 10
    if kind == "postcode":
        upper = value.upper()
        return bool(_POSTCODE_RE.fullmatch(upper)) and (digits >= 2 or bool(re.fullmatch(r"[A-Z]{2}\d", upper)))
    if kind == "iban":
        return bool(_IBAN_SHAPE_RE.fullmatch(value.replace(" ", "").upper()))
    amount = _AMOUNT_SHAPE_RE if kind in ("account", "bank") else _SHORT_AMOUNT_RE
    if amount.fullmatch(value) or _VERSION_SHAPE_RE.fullmatch(value):
        return False
    if kind == "bank":
        upper = value.upper()
        return (6 <= digits <= 18 and digits == alnum) or bool(_IFSC_RE.fullmatch(upper) or _BIC_RE.fullmatch(upper))
    if kind == "national":
        # mostly digits ("123456782", "1 84 12 76 451 089 46"), or a code in capitals and digits the cue names
        # ("身份证号：VOFF2KYG3S", "Steuer-ID AB12CD34")
        return ((digits >= 5 or (digits >= 4 and alnum >= 6)) and alnum <= 32) or (_coded(value) and 6 <= alnum <= 20)
    if kind == "document":
        return digits >= 1 and 5 <= alnum <= 40
    if kind == "vehicle":
        return digits >= 2 and alnum - digits >= 1 and 6 <= alnum <= 17
    if kind == "plate":  # "FH-50-73", "B-AB 1234", "7ABC123", "2761 ZDB"
        return digits >= 1 and alnum - digits >= 1 and 4 <= alnum <= 10
    if kind == "device":
        return digits >= 2 and 8 <= alnum <= 64
    return digits >= 1 and 4 <= alnum <= 40  # account


_NEXT_LABEL_RE = re.compile(r"[ \t]*(?:[#№]|[:：=](?!//))")


def _take(text: str, pos: int, kind: str, stop: int | None = None) -> tuple[int, int] | None:
    """The value of ``kind`` that starts at ``pos``: its groups up to the first that does not belong, and never into
    the next cue (``stop``)."""
    m = _CHAIN_RE.match(text, pos, len(text) if stop is None else max(pos, stop))
    if m is None:
        return None
    end = pos
    count = 0
    limit = 26 if kind in ("phone", "card", "pin") else 44
    # Groups of capitals in front ("CHE-230.278.000", "LV-3007", "WA-ENG-872043", at most two, joined by a hyphen)
    # need digits after them.
    prefix = 0
    previous = ""
    for g in _GROUP_RE.finditer(text, pos, m.end()):
        group = re.sub(r"[()+]", "", g.group())
        gap = text[end : g.start()] if count else ""
        has_digit = any(c.isdigit() for c in group)
        if not count and not has_digit and kind in _OPAQUE_KINDS and opaque_capitals(group, cued=True):
            end = g.end()  # "řidičský průkaz číslo PEWRDYDWEI": a code in capitals alone, which no language writes
            count = 1
            break
        if count == prefix and not has_digit:
            # "CHE-230.278.000", "LV-3007"; a driving licence's five letters of surname ("MORGA 753116 SM9IJ"); and
            # the lower-case type prefix of an id: "usr-3nPqRvXmL7kT2zB"
            capitals = len(group) <= 4 or (
                len(group) == 5 and kind == "document" and _DIGITS_AFTER_RE.match(text, g.end())
            )
            short = (group.isupper() and bool(capitals) and (not count or gap == "-")) or (
                not count and group.islower() and len(group) <= 5 and text[g.end() : g.end() + 1] in ("-", "_")
            )
            if not short or prefix == 2 or kind in ("phone", "card", "pin"):
                return None
            prefix += 1
        if count:
            if len(gap) > 1 and not (gap in (" - ", " \u2013 ") and group.isdigit() and previous.isdigit()):
                break
            if kind in ("phone", "card", "pin") and not group.isdigit():
                break
            dutch = kind == "postcode" and count == 1 and len(group) == 2 and group.isupper() and previous.isdigit()
            letters_only = not any(c.isdigit() for c in group) and not (kind != "postcode" and group.isupper())
            if gap == " " and letters_only and not dutch:
                # "X1234567 and": a word after a space is not part of the value; "1012 AB" is one Dutch postcode,
                # "8000 Esbjerg" is a code and a town
                break
            if gap == " " and group in _CURRENCY_CODES:
                break  # "1.250.000 EUR": the currency is not part of the value, and says it is an amount
        if kind in ("phone", "card", "pin") and not group.isdigit():
            break
        if g.end() - pos > limit:
            break
        end = g.end()
        count += 1
        previous = group
        if kind == "postcode" and count == 2:
            break
    if end == pos:
        return None
    while _NEXT_LABEL_RE.match(text, end):  # a word before a sign is the next label: "884021943 MR #: ..."
        cut = text.rfind(" ", pos, end)
        if cut <= pos or any(c.isdigit() for c in text[cut + 1 : end]) or kind == "postcode":
            break
        end = cut
    while end > pos and text[end - 1] in "(+":
        end -= 1
    if text[pos] == "(" and ")" not in text[pos:end]:
        pos += 1
    if text[end - 1] == ")" and text.count("(", pos, end) < text.count(")", pos, end):
        end -= 1  # "(ED8095572)": the bracket closes the sentence's, not the value's
    if end <= pos or count <= prefix:
        return None
    value = text[pos:end]
    if kind == "postcode" and not _shape_ok(kind, value) and " " in value:
        end = pos + value.index(" ")  # "8000 Esbjerg"-style chains: the code alone
        value = text[pos:end]
    return (pos, end) if _shape_ok(kind, value) else None


# --------------------------------------------------------------------------- cue to value
_GAP_CHARS = frozenset(
    " \t\u00a0:\uff1a=-#\u2116)\uff09[]{}\"'\u00ab\u00bb\u201e\u201c\u201d\u201a\u2018\u2019`*|>,;/._"
    "\u00b7\u00b0\u00ba\u2010\u2011\u2012\u2013\u2014\u2015\u2212"
)
_SIGNS = frozenset(":：=#№")
_TAG_RE = re.compile(r"</?[A-Za-z][^<>\n]{0,40}>")
_ASIDE_RE = re.compile(r"[(\[\uff08][^()\[\]\uff08\uff09\n]{0,40}[)\]\uff09]")
_MAX_GAP = 48
_MAX_WORDS = 4
_CHAIN_JOIN_RE = re.compile(
    r"[ \t]{0,2}(?:[,/;&]|\b(?:or|and|oder|und|ou|et|o|y|e|of|en|eller|och|tai|ja|lub|i|a|nebo|alebo|ali|vagy|sau"
    r"|ili|или|и|ή|και|arba|ir|vai|un|või|atau|dan|hoặc|và|veya|ve)\b|或|和|または|및|또는)[ \t]{0,2}",
    re.IGNORECASE,
)
_CJK_GAP = frozenset("：:は是为為が을를은는이가의 　（）()「」『』【】#＃№号碼码番번호")


def _coded(value: str) -> bool:
    """A code in capitals and digits ("CLM-2024-00123", "Q7M2LP"): never an amount or a name."""
    return any(c.isdigit() for c in value) and any(c.isupper() for c in value) and not any(c.islower() for c in value)


def _priced(text: str, start: int, end: int) -> bool:
    """A currency next to the value: "EUR 1.250.000", "396 860 468 Ft"."""
    return bool(_CURRENCY_BEFORE_RE.search(text, max(0, start - 5), start) or _CURRENCY_AFTER_RE.match(text, end))


_LAST_WORD_RE = re.compile(r"[^\W\d_]+$")
_CATEGORY_WORDS = frozenset(
    """type types kind category categories class soort categorie typ typen art kategorie tipo tipos categoria
    categoría""".split()  # noqa: SIM905
)
_ABBREVIATED = ("nr", "no", "nro", "num", "nb", "tel", "mob", "fax")  # "Postnr.", "Kundennr.", "Mob."


def _sentence_ends(text: str, dot: int, word: str) -> bool:
    """Whether the full stop at ``dot``, after ``word``, ends a sentence: a whole word before it ("dossier. ISBN ..."),
    not an abbreviation ("Tel.", "Postnr. 4220")."""
    if len(word) <= 4 or fold(word).endswith(_ABBREVIATED):
        return False
    return dot + 1 >= len(text) or text[dot + 1].isspace()


def _after(text: str, cue: _Found, stop: int) -> tuple[int, int] | None:
    """The value a cue names: the first one within reach, past words, number words, signs and markup."""
    pos, limit = cue.end, min(len(text), cue.end + _MAX_GAP, stop)
    words, newline, sign, noun, wordy = 0, False, False, cue.noun, False
    cjk = bool(_CJK_RE.match(text, cue.start))
    last = _LAST_WORD_RE.search(text, cue.start, cue.end)
    last_word = last.group() if last else ""  # the word before a full stop: an abbreviation, or a sentence's end
    while pos < limit:
        ch = text[pos]
        if ch == "." and _sentence_ends(text, pos, last_word):
            return None  # "... vérifier le dossier. ISBN 978-3-16-148410-0": the next sentence is not the value
        if ch == "\n" or ch == "\r":
            if newline or words:
                return None
            newline = True
            pos += 1
            continue
        if ch in "([\uff08":
            aside = _ASIDE_RE.match(text, pos)
            inner = pos + 1
            while inner < limit and text[inner] in " \t":
                inner += 1
            starts = inner < len(text) and (text[inner].isalnum() or text[inner] == "+")
            opener = _TOKEN_RE.match(text, inner) if starts else None
            if opener is not None and fold(opener.group()) in _NUMBER_WORDS:
                pos = inner  # "passport (no. 354652981)": the value is inside, after its number word
                continue
            written = _ALNUM_RE.match(text, inner) if starts else None
            if written is not None and _FORMAT_WORD_RE.fullmatch(written.group()):
                return None  # "account number (base64): ...": what follows is encoded; the decoders read it
            if aside is not None and (not starts or _take(text, inner, cue.kind) is None):
                pos = aside.end()  # "(letzte 4 Ziffern)", "(as printed)", "(hvis relevant)"
                continue
            pos += 1
            continue
        if ch in _GAP_CHARS or (cjk and ch in _CJK_GAP):
            sign = sign or ch in _SIGNS
            pos += 1
            continue
        if ch == "<":
            tag = _TAG_RE.match(text, pos)
            if tag is None:
                return None
            pos = tag.end()
            continue
        if ch.isdigit() or ch == "+" or (ch.isascii() and ch.isalpha() and cue.kind in _LETTER_KINDS):
            hit = _take(text, pos, cue.kind, stop)
            if hit is not None and cue.kind not in ("phone", "card", "pin", "iban") and _priced(text, *hit):
                return None
            if hit is not None:
                value = text[hit[0] : hit[1]]
                digits = sum(c.isdigit() for c in value)
                if wordy:
                    return hit if cue.strict >= 2 and _coded(value) else None
                if (
                    not cue.strict
                    or noun
                    or (cue.strict == 1 and (sign or digits >= 6))
                    or (cue.strict == 3 and digits >= 6)
                    or _coded(value)
                ):
                    return hit
                return None
            if not ch.isalpha():
                return None
        word = _TOKEN_RE.match(text, pos)
        if word is None:
            return None
        folded = fold(word.group())
        last_word = word.group()
        if folded in _CATEGORY_WORDS:
            return None  # "Case Type: I-485", "Kartenart: VISA": a category, not the identifier
        if folded in _NUMBER_WORDS:
            noun = True
        else:
            # "customer file: IP address 81.204.36.12": words between a person word and a value make it name
            # something else. A word that names a record still names a code in capitals and digits after a few
            # words ("certificates such as QC-7741203").
            wordy = wordy or (cue.strict > 0 and not noun)
            words += 1
            if words > _MAX_WORDS:
                return None
        pos = word.end()
    return None


def find_cued_values(text: str) -> Iterator[Span]:
    windows = _windows(text)
    if not windows:
        return
    found = _cues(text, _tokens(text, windows), windows)
    for k, cue in enumerate(found):
        stop = found[k + 1].start if k + 1 < len(found) else len(text)
        hit = _after(text, cue, stop)
        chained = 0
        while hit is not None:
            start, end = hit
            yield make_span(start, end, _KIND_TYPE[cue.kind], f"{SOURCE}:{cue.kind}", text[start:end].upper(), 0.8)
            chained += 1
            join = _CHAIN_JOIN_RE.match(text, end)
            if chained > 3 or join is None or join.end() >= stop or join.end() == end:
                break
            nxt = join.end()
            hit = _take(text, nxt, cue.kind) if nxt < len(text) and (text[nxt].isalnum() or text[nxt] in "+(") else None


# --------------------------------------------------------------------------- table columns (detectors/fields.py)
@lru_cache(maxsize=4096)
def label_kind(label: str) -> tuple[str, int] | None:
    """What a table column or row label names ("Phone number", "Kundennummer", "Device ID", "電話番号") and how
    strict its value check stays. The label stands where a sign would ("Claim: ..."), so only a "!!" cue without a
    number word still asks for a code. Words after the cue other than number words make the label about something
    else ("Card Expiry", "Account Type")."""
    if not label or len(label) > 64:
        return None
    tokens: list[_Token] = []
    _tokenise(label, 0, len(label), tokens.append)
    found = _cues(label, tokens, [(0, len(label))])
    if not found:
        return None
    cue = found[-1]
    after = [t for t in tokens if t.start >= cue.end]
    if any(t.folded not in _NUMBER_WORDS for t in after):
        return None
    noun = cue.noun or bool(after)
    return cue.kind, (cue.strict if cue.strict >= 2 and not noun else 0)


def table_value(text: str, start: int, end: int, kind: str, strict: int) -> tuple[int, int] | None:
    """The value of ``kind`` that fills a table cell whole, or None."""
    pos = start
    while pos < end and not (text[pos].isalnum() or text[pos] in "+("):
        pos += 1
    if pos >= end or not (text[pos].isdigit() or text[pos] in "+(" or kind in _LETTER_KINDS):
        return None
    hit = _take(text, pos, kind, end)
    if hit is None or any(c.isalnum() for c in text[hit[1] : end]):
        return None
    value = text[hit[0] : hit[1]]
    if strict == 2 and not _coded(value):
        return None
    if strict == 3 and not (_coded(value) or sum(c.isdigit() for c in value) >= 6):
        return None
    return None if kind not in ("phone", "card", "pin", "iban") and _priced(text, *hit) else hit


# --------------------------------------------------------------------------- shapes without a cue
# "+33.1.39.90.78.50", "+44 20 0000 0000": groups the phone library's matcher may not read; numbers its plans do not
# have ("+33.139 907.8509") are left to cues, and so is "0041 44 668 18 00". Groups, not one run of digits: a bare
# "+12345678901" is the validated layer's (patterns.find_phones).
_INTL_PHONE_RE = re.compile(r"(?<![\w+.\-/])\+[1-9]\d{0,5}(?:[ .\-/]{1,2}\(?\d{1,6}\)?){2,6}(?![\w.\-/]?\d)")
# "(967) 759-3756", "(88)-1974 8058": an area code in brackets, then the number.
_BRACKET_PHONE_RE = re.compile(r"(?<![\w)\]])\(\d{2,5}\)[ .\-]{0,2}\d{2,8}(?:[ .\-]\d{2,8}){0,3}(?![\w.\-]?\d)")
_YEAR_RE = re.compile(r"\((?:19|20)\d{2}\)")
# The grouping cards are printed in: 4-4-4-4 (Visa, Mastercard, Discover...), 4-6-5 (Amex), 4-6-4 (Diners).
_GROUPED_CARD_RE = re.compile(
    r"(?<![\w.\-])(?:\d{4}([ \-])\d{4}\1\d{4}\1\d{4}(?:\1\d{3})?|\d{4}([ \-])\d{6}\2\d{4,5})(?![\w]|[.\-]\d)"
)


# A vehicle identification number (ISO 3779): 17 characters without I, O and Q, whose last four are digits. Not every
# country uses the check digit (identifiers.find_devices), so the shape is enough.
_VIN_SHAPE_RE = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{13}\d{4}(?![A-Za-z0-9])")


def _possible_phone(value: str) -> bool:
    """Whether an international number is one its country's numbering plan has: without a cue, a value must pass
    the check its format has ("+31 20 794 609" is a digit short). Separators the phone library's matcher does not
    read ("+33.1.39.90.78.50") are no reason to miss a valid number."""
    try:
        return phonenumbers.is_valid_number(phonenumbers.parse(re.sub(r"[^\d+]", "", value), None))
    except phonenumbers.NumberParseException:
        return False


def find_value_shapes(text: str) -> Iterator[Span]:
    for m in _VIN_SHAPE_RE.finditer(text):
        vin = m.group()
        if sum(c.isalpha() for c in vin) >= 2 and sum(c.isdigit() for c in vin) >= 5:
            yield make_span(m.start(), m.end(), E.DEVICE_ID, f"{SOURCE}:vin-shape", vin, 0.8)
    if "+" in text:
        for m in _INTL_PHONE_RE.finditer(text):
            value, end = m.group(), m.end()
            if value.endswith(")") and value.count(")") > value.count("("):
                value, end = value[:-1], end - 1  # "(..., +31 20 794 6095), IBAN": the bracket is the sentence's
            digits = sum(c.isdigit() for c in value)
            if 8 <= digits <= 15 and _possible_phone(value):
                yield make_span(m.start(), end, E.PHONE, f"{SOURCE}:phone-shape", value, 0.75)
    if "(" in text:
        for m in _BRACKET_PHONE_RE.finditer(text):
            digits = sum(c.isdigit() for c in m.group())
            if 9 <= digits <= 13 and not _YEAR_RE.match(m.group()):
                yield make_span(m.start(), m.end(), E.PHONE, f"{SOURCE}:phone-shape", m.group(), 0.75)
    for m in _GROUPED_CARD_RE.finditer(text):
        card = re.sub(r"\D", "", m.group())
        if card_brand_ok(card) and luhn.is_valid(card):
            yield make_span(m.start(), m.end(), E.CREDIT_CARD, f"{SOURCE}:card-shape", card, 0.8)
