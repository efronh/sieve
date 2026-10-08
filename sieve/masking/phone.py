import re

from sieve.masking.number_units import aligned_windows, apply_masks, find_units, split_into_groups, to_lower

LABEL = "[TELEFON]"
NATIONAL_LENGTH = 10
MIN_REAL_DIGITS = 9
PREFIXES = ("0090", "90", "0", "")
# Digits with each prefix, longest first, so a prefix stays with its number.
LENGTHS = (14, 12, 11, 10)
# Right before a number, a name for another kind: "Sipariş numaram 5522776315" is an order, not a mobile number.
# Only a bare 10 digits gives way; with 0 or +90 in front it's a phone whatever comes before.
OTHER_NUMBER = re.compile(r"\b(?:sipari[şs]|takip|kargo|referans|dekont|seri|[üu]r[üu]n)\w*(?:\s+(?:no|numara|kod)\w*)?\W*$")
KEYWORD_DISTANCE = 30


# Mobile 5xx with or without a prefix; landline 2xx-4xx only after 0 or 90.
def is_phone(number):
    for prefix in PREFIXES:
        rest = number[len(prefix):]
        if number.startswith(prefix) and len(rest) == NATIONAL_LENGTH:
            return rest[0] == "5" or (prefix != "" and rest[0] in "234")
    return False


def named_otherwise(start, lower):
    return OTHER_NUMBER.search(lower[max(0, start - KEYWORD_DISTANCE):start]) is not None


def include_opening(start, text):
    while start > 0 and text[start - 1] in "+(":
        start -= 1
    return start


# Whole pieces the writer typed, so a 10-digit run inside an order number stays, and a phone number next to
# another number ("TC 1000… 0599 …") is still found; it used to need its digit group to itself. lower: the text
# in lower case, for the keywords.
def phone_spans(units, text, lower):
    spans, taken = [], set()
    windows = {length: set(aligned_windows(units, length, text)) for length in LENGTHS}
    for i in range(len(units)):
        for length in LENGTHS:
            window = units[i:i + length]
            if (i in windows[length] and taken.isdisjoint(range(i, i + length))
                    and sum(u.real for u in window) >= MIN_REAL_DIGITS and is_phone("".join(u.digit for u in window))
                    and not (length == NATIONAL_LENGTH and named_otherwise(window[0].start, lower))):
                spans.append((include_opening(window[0].start, text), window[-1].end))
                taken.update(range(i, i + length))
                break
    return spans


class PhoneMaskingLayer:
    name = "phone_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            spans += phone_spans(group, text, lower) + phone_spans([u for u in group if u.real], text, lower)
        return apply_masks(text, spans, LABEL)
