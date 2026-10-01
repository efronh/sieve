import pytest

from sieve.pipeline import mask

SHOULD_MASK = [
    "TC kimlik numaram 10000000146",
    "numaram10000000146dir",
    "TC: 100-000-001-46",
    "TC: 1/0/0/0/0/0/0/0/1/4/6",
    "TC: 1 0 0 0 0 0 0 0 1 4 6",
    "TC: １０００００００１４６",
    "TC: 1000\u200b0000146",
    "TC: 1a0b0c0d0e0f0g0h1i4j6",
    "TC: 1OOOOOOO146",
    "TC: l2345678950",
    "bir sıfır sıfır sıfır sıfır sıfır sıfır sıfır bir dört altı",
    "BİR SIFIR SIFIR SIFIR SIFIR SIFIR SIFIR SIFIR BİR DÖRT ALTI",
    "one two three four five six seven eight nine five zero",
    "1 sıfır 0 zero 0 0 0 0 bir 4 6",
    "numaram\n100000\n00146",
    "tel 05321234567 tc 11111111110",
    "TC no: 12345678901",
    "KIMLIK NO: 12345678901",
]

SHOULD_NOT_MASK = [
    "Bol bol oyun oynadık, sonra iyi bir film izledik.",
    "Sipariş numarası 12345678901",
    "Toplam 3 elma ve 25 armut aldım",
    "bir iki üç dört",
    "Tarih 24.09.2026 saat 14:30",
]


@pytest.mark.parametrize("text", SHOULD_MASK)
def test_masks(text):
    assert "[TC_KIMLIK]" in mask(text)


@pytest.mark.parametrize("text", SHOULD_NOT_MASK)
def test_leaves_alone(text):
    assert "[TC_KIMLIK]" not in mask(text)
