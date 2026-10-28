"""Personal data in machine formats (detectors/formats.py): log chains, travel documents, HL7, AWS identities, user
names where formats put them, and typed credentials. Every value is made up."""

from __future__ import annotations

import pytest

from harpo_redact.detectors.formats import find_formats
from harpo_redact.entities import EntityType as E


def found(text: str) -> set[tuple[str, E]]:
    return {(text[s.start : s.end], s.type) for s in find_formats(text)}


def test_an_iptables_mac_chain_is_one_device_identifier() -> None:
    line = "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=02:42:ac:11:00:02:02:42:ac:11:00:01:08:00 SRC=198.51.100.7"
    assert found(line) == {("02:42:ac:11:00:02:02:42:ac:11:00:01:08:00", E.DEVICE_ID)}


def test_passport_machine_readable_zone() -> None:
    line1 = "P<NLDDE<BRUIJN<<WILLEMIJN<ANNA<<<<<<<<<<<<<<"
    line2 = "XN01234560NLD8501019F3001017999999990<<<<<08"
    assert len(line1) == len(line2) == 44
    assert found(f"MRZ:\n{line1}\n{line2}\n") == {(line1, E.ID_DOCUMENT), (line2, E.ID_DOCUMENT)}


def test_identity_card_line_two() -> None:
    line = "8501019F3001017NLD<<<<<<<<<<<6"
    assert len(line) == 30
    assert found(f"zone:\n{line}\n") == {(line, E.ID_DOCUMENT)}
    assert found("REFERENCE<<CODE") == set()  # filler alone is not a zone


def test_hl7_segments_by_field() -> None:
    message = (
        "MSH|^~\\&|LAB|CLINIC|EHR|HOSP|202401010930||ADT^A04|0001|P|2.5\n"
        "PID|1||MRN0042^^^CLINIC^MR||VERMEULEN^SANNE^J||19850101|F|||Kade 7^^Delft^ZH^2611AB^NL||(015)555-0101"
        "|||||ACC-77|123-45-6789\n"
        "NK1|1|VERMEULEN^PIETER|SPO|Kade 7^^Delft^ZH^2611AB^NL|(015)555-0102\n"
        "PV1|1|O|||||0451^Okafor^Chidi^^^Dr|"
    )
    hits = found(message)
    for value, etype in [
        ("MRN0042", E.ACCOUNT_ID), ("VERMEULEN", E.PERSON), ("SANNE", E.PERSON), ("J", E.PERSON),
        ("19850101", E.DATE_OF_BIRTH), ("Kade 7^^Delft^ZH^2611AB^NL", E.ADDRESS), ("(015)555-0101", E.PHONE),
        ("ACC-77", E.ACCOUNT_ID), ("123-45-6789", E.NATIONAL_ID), ("PIETER", E.PERSON), ("(015)555-0102", E.PHONE),
        ("0451", E.ACCOUNT_ID), ("Okafor", E.PERSON), ("Chidi", E.PERSON),
    ]:  # fmt: skip
        assert (value, etype) in hits, value
    assert not any(v in ("LAB", "CLINIC", "ADT", "2.5") for v, _ in hits)  # the header carries no person


def test_aws_identities() -> None:
    event = (
        '{"userIdentity":{"type":"IAMUser","principalId":"AIDAQ3EXAMPLE7HJ2K4LM",'
        '"arn":"arn:aws:iam::123456789012:user/jvandijk","accountId":"123456789012","userName":"jvandijk"}}'
    )
    hits = found(event)
    assert ("AIDAQ3EXAMPLE7HJ2K4LM", E.ACCOUNT_ID) in hits
    assert ("123456789012", E.ACCOUNT_ID) in hits
    assert ("jvandijk", E.ACCOUNT_ID) in hits
    assumed = "arn:aws:sts::123456789012:assumed-role/build-role/i-0abc123def4567890"
    assert found(assumed) == {("123456789012", E.ACCOUNT_ID)}  # an instance is not a person


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("member: uid=lvisser,ou=People,dc=example,dc=org", "lvisser"),
        ("uid=1001(mbakker) gid=1001(mbakker) groups=27(sudo)", "mbakker"),
        ('<Data Name="TargetUserName">s.jansen</Data>', "s.jansen"),
        ("username: p.devries / temporary password sent separately", "p.devries"),
        ("GET /login?user_name=rkoster&next=/home", "rkoster"),
        ("open /home/tdekker/projects/app/main.py", "tdekker"),
        ("C:\\Users\\annelies\\AppData\\Local", "annelies"),
        ("e.smit@build-box-02:~/repo$ make test", "e.smit"),
        ('<Data Name="TargetUserName">CORP\\k.mulder</Data>', "k.mulder"),
        ('<Data Name="MemberName">CN=f.bos,OU=Sales,DC=CORP</Data>', "f.bos"),
        ("net use Y: \\\\srv\\x /user:CORP\\j.peters *", "j.peters"),
        ("git clone https://w.verbeek:secret-token@git.example.org/repo.git", "w.verbeek"),
    ],
)
def test_user_names_where_formats_put_them(text: str, name: str) -> None:
    assert (name, E.ACCOUNT_ID) in found(text)


@pytest.mark.parametrize(
    "text",
    [
        "username = request.form['username']",  # code, not a value
        "Username: required",
        "cd /home/ubuntu/app && ls",  # a system account
        "root@server:/# ls",
        "/Users/Shared/data.csv",
        "uid=0(root) gid=0(root)",
    ],
)
def test_system_accounts_and_code_are_not_user_names(text: str) -> None:
    assert not any(t is E.ACCOUNT_ID for _, t in found(text))


def test_ldap_common_name_of_a_person() -> None:
    assert found("dn: cn=Lotte de Boer,ou=People,dc=example") == {("Lotte de Boer", E.PERSON)}
    assert found("dn: cn=Users,dc=example") == set()
    assert found("dn: cn=backup-operators,ou=Groups") == set()


def test_typed_credentials_and_wallets() -> None:
    webhook = "whsec_" + "Qm7Rt2ZpX9vLk4Nw8Bc3Hd6Fj1Gs5Ty0"
    session = "sess_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8"
    assert found(f"secret: {webhook}") == {(webhook, E.SECRET)}
    assert found(f"SET session:{session} EX 3600") == {(session, E.SECRET)}
    assert found("customer cus_J4nZ2xK9mQpL7rT1aB") == set()  # an object id is not a secret
    wif = "L" + "4mVCeXM7V3ZRmWKBqfDQkZvx9JMh3Nbk7sZRKp5eYQbdrRx2Nt"[:51]
    assert (wif, E.SECRET) in found(f"dumpprivkey result: {wif}")
    address = "bc1" + "q" * 2 + "w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"[:37]
    assert len(address) == 42
    assert (address, E.CRYPTO_ADDRESS) in found(f"pay to {address} now")


def test_hl7_name_fields_in_any_position() -> None:
    segment = "PV1|1|O|WARD^12^1^CLINIC|||JANSSEN^MAARTEN^K^^^MD|DIJKSTRA^EVA^^^^DR|MED|||"
    hits = found(segment)
    for value in ("JANSSEN", "MAARTEN", "K", "DIJKSTRA", "EVA"):
        assert (value, E.PERSON) in hits, value
    assert not any(v in ("MED", "WARD", "CLINIC") for v, _ in hits)
