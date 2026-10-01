from sieve.masking.number_units import apply_masks, find_units, split_into_groups, to_lower

LABEL = "[TELEFON]"
NATIONAL_LENGTH = 10
MIN_REAL_DIGITS = 9
PREFIXES = ("0090", "90", "0", "")


# Mobile 5xx with or without a prefix; landline 2xx-4xx only after 0 or 90.
def is_phone(number):
    for prefix in PREFIXES:
        rest = number[len(prefix):]
        if number.startswith(prefix) and len(rest) == NATIONAL_LENGTH:
            return rest[0] == "5" or (prefix != "" and rest[0] in "234")
    return False


def include_opening(start, text):
    while start > 0 and text[start - 1] in "+(":
        start -= 1
    return start


# Only whole digit groups, so a 10-digit run inside an order number stays.
class PhoneMaskingLayer:
    name = "phone_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            real_only = [u for u in group if u.real]

            for units in (real_only, group):
                if len(real_only) < MIN_REAL_DIGITS or not units:
                    continue
                if is_phone("".join(u.digit for u in units)):
                    spans.append((include_opening(units[0].start, text), units[-1].end))
                    break

        return apply_masks(text, spans, LABEL)
