import re

import pytest

from sieve.masking import LABEL_NAMES
from sieve.pipeline import clean, mask

SHOULD_MASK = [
    ("[EPOSTA]", "Mailim ali.veli+test@gmail.com, oradan yaz"),
    ("[EPOSTA]", "E-posta: AYSE_YILMAZ@firma.com.tr"),
    ("[EPOSTA]", "ali (at) gmail (dot) com"),
    ("[EPOSTA]", "veli[at]hotmail[nokta]com"),
    ("[KART]", "Kart numaram 4111 1111 1111 1111"),
    ("[KART]", "kart: 5555-5555-5555-4444"),
    ("[KART]", "Amex 3782 822463 10005"),
    ("[KART]", "4111111111111111"),
    ("[KART]", "Kart: 4III 1111 1111 1111"),
    ("[TELEFON]", "Telefonum 0532 111 22 33, beni ara"),
    ("[TELEFON]", "+90 (532) 111 22 33"),
    ("[TELEFON]", "0090 532 111 2233"),
    ("[TELEFON]", "cep: 5321112233"),
    ("[TELEFON]", "Ev telefonu 0212 555 12 12"),
    ("[TELEFON]", "sıfır beş üç iki bir bir bir iki iki üç üç"),
    ("[VKN]", "Vergi numaram 1234567890"),
    ("[VKN]", "VKN: 123 456 78 90"),
    ("[VKN]", "VKN: 547 428 4352"),  # starts with 5, so it used to be taken for a phone number
    ("[TELEFON]", "Numara O599 154 38 29"),
    ("[KART]", "Kart: 4\u03321\u03321\u03321\u0332 1111 1111 1111"),
    ("[CVV]", "Kart 4111 1111 1111 1111 12/27 123"),
    ("[CVV]", "kart: 4111111111111111, 08/2029, 1234"),
    ("[CVV]", "Son kullanma tarihi 12/27, CVV'si 456"),
    ("[CVV]", "cvv: bir iki üç"),
    ("[SKT]", "SKT: 08/29 güvenlik kodu 789"),
    ("[SKT]", "exp 1/30"),
]

SHOULD_NOT_MASK = [
    "Sipariş numarası 123456789012345678901234",
    "Sipariş no 5321112233445566",
    "Kart numaram 4111 1111 1111 1112",
    "Referans kodu 1234567890",
    "212 555 1212 numaralı dosya",
    "ali.veli@ nerede",
    "Toplam 3 elma ve 25 armut aldım",
    "Tarih 24.09.2026 saat 14:30",
]

# The card is masked; the date and amount next to it aren't an expiry date or CVV.
SHOULD_NOT_MASK_AS_CARD_DETAILS = [
    "4111 1111 1111 1111 numaralı kartımdan 12/10 tarihinde 250 TL çekildi",
    "Kart 4111 1111 1111 1111 12/10/2026 tarihinde",
    "CVV kodumu 3 kere yanlış girdim",
    "Faturam 12/27 TL",
    "Expected delivery 12/10, export 3/25",
]

LABELS = ["[EPOSTA]", "[KART]", "[TELEFON]", "[VKN]", "[SKT]", "[CVV]"]


@pytest.mark.parametrize("label, text", SHOULD_MASK)
def test_masks(label, text):
    result = mask(text)
    assert label in result and not any(c.isdigit() for c in result), result


@pytest.mark.parametrize("text", SHOULD_NOT_MASK)
def test_leaves_alone(text):
    result = mask(text)
    assert not any(label in result for label in LABELS), result


# Numbers are read in the pieces they're typed in. A window across two of them used to hide half of each,
# or none: the phone number after a TC needed its digit group to itself.
NEXT_TO_EACH_OTHER = [
    ("TC 10000001518 0599 326 27 05", ["[TC_KIMLIK]", "[TELEFON]"]),
    ("Tel: 0599 312 34 56\n4111 1157 9906 5937 08/28 123", ["[TELEFON]", "[KART]", "[SKT]", "[CVV]"]),
    ("10000004038 05993262705 numaralarım", ["[TC_KIMLIK]", "[TELEFON]"]),
    ("Telefon ve kart: 0599 284 61 07 5555 5565 9085 3809", ["[TELEFON]", "[KART]"]),
]


@pytest.mark.parametrize("text, labels", NEXT_TO_EACH_OTHER)
def test_numbers_next_to_each_other(text, labels):
    result = mask(text)
    assert re.findall(r"\[[A-Z_]+\]", result) == labels and not any(c.isdigit() for c in result), result


def test_a_number_ends_where_a_mark_is():
    result = mask("Link: https://ornekbank.com.tr/basvuru?tc=10000005646&adim=2")
    assert "?tc=[TC_KIMLIK]&adim=2" in result, result


# A run that only fits a checksum when cut out of a longer code isn't a number someone typed.
@pytest.mark.parametrize("text", ["Kargo takip numarası 1Z999AA10123456784",
                                  "SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
def test_numbers_inside_longer_codes_stay(text):
    assert mask(text) == text


@pytest.mark.parametrize("text", SHOULD_NOT_MASK_AS_CARD_DETAILS)
def test_leaves_card_details_alone(text):
    result = mask(text)
    assert "[SKT]" not in result and "[CVV]" not in result, result


def test_marks_on_latin_letters_are_removed():
    assert clean("t\u0337a\u0337l\u0337i\u0337m\u0337a\u0337t") == "talimat"


def test_marks_that_belong_to_the_script_are_kept():
    for text in ["مَرْحَبًا", "שָׁלוֹם", "Şöyle güzel bir gün"]:
        assert clean(text) == text


# output.py and siem.py read labels back from masked text; a label missing from LABEL_NAMES goes uncounted.
def test_every_label_is_listed():
    written = {label.strip("[]") for _, text in SHOULD_MASK for label in re.findall(r"\[[A-Z_]+\]", mask(text))}
    written |= {label.strip("[]") for label in re.findall(r"\[[A-Z_]+\]", mask(
        "IBAN TR33 0006 1005 1978 6457 8413 26, TC 10000000146, şifre: abc123!x, sk-ant-abcdefghijklmnopqrstuvwx"))}
    assert written <= set(LABEL_NAMES), written - set(LABEL_NAMES)
    assert {"IBAN", "TC_KIMLIK", "SIFRE", "GIZLI_ANAHTAR", "SKT", "CVV"} <= written
