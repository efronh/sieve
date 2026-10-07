import re

from sieve.masking.number_units import apply_masks, find_units, find_windows, keyword_window, split_into_groups, to_lower

LABEL = "[TC_KIMLIK]"
TC_LENGTH = 11
MIN_REAL_DIGITS = 3
KEYWORD_DISTANCE = 40

KEYWORDS = re.compile(r"\b(?:tc|t\.c|tckn|k[iı]ml[iı]k|vatandaşlık|[iı]dent[iı]ty)\b")


def is_valid_tc(number):
    if len(number) != TC_LENGTH or number[0] == "0":
        return False

    digits = [int(d) for d in number]
    odd_sum = sum(digits[0:9:2])
    even_sum = sum(digits[1:8:2])

    tenth = (odd_sum * 7 - even_sum) % 10
    eleventh = sum(digits[:10]) % 10

    return digits[9] == tenth and digits[10] == eleventh


class TCMaskingLayer:
    name = "tc_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            real_only = [u for u in group if u.real]

            spans += find_windows(group, TC_LENGTH, MIN_REAL_DIGITS, is_valid_tc, lower)
            spans += find_windows(real_only, TC_LENGTH, MIN_REAL_DIGITS, is_valid_tc, lower)
            # A TC number never starts with 0; the phone number after "TC 1000…, tel" does.
            spans += keyword_window(group, TC_LENGTH, lower, KEYWORDS, KEYWORD_DISTANCE, lambda n: n[0] != "0")

        return apply_masks(text, spans, LABEL)
