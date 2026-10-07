import re

from sieve.masking.number_units import apply_masks, find_units, find_windows, keyword_window, split_into_groups, to_lower

LABEL = "[IBAN]"
TR_IBAN_DIGITS = 24
MIN_REAL_DIGITS = 6
KEYWORD_DISTANCE = 40
MIN_IBAN_LENGTH = 15
MAX_IBAN_LENGTH = 34

KEYWORDS = re.compile(r"\b[iı]ban\b")
TR_PREFIX = re.compile(r"(?<![a-zçğıöşü])t\W{0,3}r\W{0,3}$")
FOREIGN_START = re.compile(r"(?<![a-z0-9])(?!tr)[a-z]{2}\d{2}")
FOREIGN_CHAR = re.compile(r"[a-z0-9]")


def mod97(iban):
    moved = iban[4:] + iban[:4]
    as_number = "".join(str(int(c, 36)) for c in moved)
    return int(as_number) % 97 == 1


def is_valid_tr_iban(digits):
    return len(digits) == TR_IBAN_DIGITS and mod97("tr" + digits)


def include_tr_prefix(spans, text):
    result = []
    for start, end in spans:
        before = text[max(0, start - 8):start]
        prefix = TR_PREFIX.search(before)
        if prefix:
            start -= len(before) - prefix.start()
        result.append((start, end))
    return result


def find_foreign_ibans(text):
    spans = []

    for match in FOREIGN_START.finditer(text):
        chars = []
        position = match.start()

        while position < len(text) and len(chars) < MAX_IBAN_LENGTH:
            char_match = FOREIGN_CHAR.match(text, position)
            if char_match:
                chars.append((char_match.group(), position))
                position += 1
            elif text[position] in " -." and position + 1 < len(text):
                position += 1
            else:
                break

        for length in range(len(chars), MIN_IBAN_LENGTH - 1, -1):
            candidate = "".join(c for c, _ in chars[:length])
            if mod97(candidate):
                spans.append((match.start(), chars[length - 1][1] + 1))
                break

    return spans


class IBANMaskingLayer:
    name = "iban_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            real_only = [u for u in group if u.real]
            whole = {(units[0].start, units[-1].end) for units in (group, real_only) if units}
            windows = (find_windows(group, TR_IBAN_DIGITS, MIN_REAL_DIGITS, is_valid_tr_iban, lower)
                       + find_windows(real_only, TR_IBAN_DIGITS, MIN_REAL_DIGITS, is_valid_tr_iban, lower))
            # Without "TR" in front, 24 valid digits among other numbers are about as likely a stretch across
            # them (1 in 97 is valid), so they count only when nothing else is around them.
            for window, prefixed in zip(windows, include_tr_prefix(windows, lower)):
                if prefixed != window or window in whole:
                    spans.append(prefixed)
            spans += include_tr_prefix(keyword_window(group, TR_IBAN_DIGITS, lower, KEYWORDS, KEYWORD_DISTANCE), lower)

        spans += find_foreign_ibans(lower)

        return apply_masks(text, spans, LABEL)
