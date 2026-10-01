import pytest

from sieve.pipeline import mask

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

LABELS = ["[EPOSTA]", "[KART]", "[TELEFON]", "[VKN]"]


@pytest.mark.parametrize("label, text", SHOULD_MASK)
def test_masks(label, text):
    result = mask(text)
    assert label in result and not any(c.isdigit() for c in result), result


@pytest.mark.parametrize("text", SHOULD_NOT_MASK)
def test_leaves_alone(text):
    result = mask(text)
    assert not any(label in result for label in LABELS), result
