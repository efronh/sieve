from sieve.masking.number_units import apply_masks, find_units, find_windows, split_into_groups, to_lower

LABEL = "[KART]"
MIN_REAL_DIGITS = 12


def luhn(number):
    total = 0
    for i, c in enumerate(reversed(number)):
        n = int(c) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def is_card(number):
    if len(number) == 15:
        known_prefix = number[:2] in ("34", "37")  # Amex
    elif len(number) == 16:
        known_prefix = number[0] in "2456" or number.startswith("9792")  # Visa, MC, Troy, ...
    else:
        return False
    return known_prefix and luhn(number)


class CardMaskingLayer:
    name = "card_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            real_only = [u for u in group if u.real]

            for length in (16, 15):
                spans += find_windows(group, length, MIN_REAL_DIGITS, is_card, lower)
                spans += find_windows(real_only, length, length, is_card, lower)

        return apply_masks(text, spans, LABEL)
