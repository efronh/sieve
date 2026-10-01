import pytest

from sieve.pipeline import mask

LABEL = "[IBAN]"

SHOULD_MASK = [
    "IBAN: TR33 0006 1005 1978 6457 8413 26",
    "iban: tr330006100519786457841326",
    "IBAN: TR33-0006-1005-1978-6457-8413-26",
    "IBAN: T.R. 33/0006/1005/1978/6457/8413/26",
    "IBAN: T R 3 3 0 0 0 6 1 0 0 5 1 9 7 8 6 4 5 7 8 4 1 3 2 6",
    "hesabım330006100519786457841326dır",
    "IBAN: 33 0006 1005 1978 6457 8413 26",
    "IBAN: TR３３ ０００６ １００５ １９７８ ６４５７ ８４１３ ２６",
    "IBAN: TR33 0006\u200b 1005 1978 6457 8413 26",
    "IBAN: TR33a0b0c0d6e1f0g0h5i1j9k7m8n6p4q5r7t8u4v1w3x2y6",
    "IBAN: TR33 OOO6 1OO5 1978 6457 8413 26",
    "TR üç üç sıfır sıfır sıfır altı bir sıfır sıfır beş bir dokuz yedi sekiz altı dört beş yedi sekiz dört bir üç iki altı",
    "IBAN: TR33 0006 1005 1978 6457\n8413 26",
    "IBAN: TR11 1111 1111 1111 1111 1111 11",
    "DE89 3704 0044 0532 0130 00",
    "gb82 west 1234 5698 7654 32",
]

SHOULD_NOT_MASK = [
    "Bol bol oyun oynadık, sonra iyi bir film izledik.",
    "Sipariş numarası 123456789012345678901234",
    "Toplam 3 elma ve 25 armut aldım",
    "Tarih 24.09.2026 saat 14:30",
    "DE89 3704 0044 0532 0130 01",
]


@pytest.mark.parametrize("text", SHOULD_MASK)
def test_masks(text):
    result = mask(text)
    assert LABEL in result and not any(c.isdigit() for c in result), result


@pytest.mark.parametrize("text", SHOULD_NOT_MASK)
def test_leaves_alone(text):
    assert LABEL not in mask(text)
