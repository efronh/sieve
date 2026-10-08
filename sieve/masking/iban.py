import re

from sieve.masking.number_units import apply_masks, find_units, find_windows, keyword_window, split_into_groups, to_lower

LABEL = "[IBAN]"
TR_IBAN_DIGITS = 24
MIN_REAL_DIGITS = 6
KEYWORD_DISTANCE = 40
# Each country's IBAN has one length (ISO 13616 registry). Trying every length from 15 to 34 found one that passed
# mod 97 for about one "two letters and two digits" in five, reading on through the next words: "Sipariş numaram
# BB789012 ve e-posta adresim" lost "BB789012 ve e-posta adresi".
IBAN_LENGTHS = {
    "ad": 24, "ae": 23, "al": 28, "at": 20, "az": 28, "ba": 20, "be": 16, "bg": 22, "bh": 22, "bi": 27, "br": 29,
    "by": 28, "ch": 21, "cr": 22, "cy": 28, "cz": 24, "de": 22, "dj": 27, "dk": 18, "do": 28, "ee": 20, "eg": 29,
    "es": 24, "fi": 18, "fk": 18, "fo": 18, "fr": 27, "gb": 22, "ge": 22, "gi": 23, "gl": 18, "gr": 27, "gt": 28,
    "hr": 21, "hu": 28, "ie": 22, "il": 23, "iq": 23, "is": 26, "it": 27, "jo": 30, "kw": 30, "kz": 20, "lb": 28,
    "lc": 32, "li": 21, "lt": 20, "lu": 20, "lv": 21, "ly": 25, "mc": 27, "md": 24, "me": 22, "mk": 19, "mn": 20,
    "mr": 27, "mt": 31, "mu": 30, "ni": 28, "nl": 18, "no": 15, "om": 23, "pk": 24, "pl": 28, "ps": 29, "pt": 25,
    "qa": 29, "ro": 24, "rs": 22, "ru": 33, "sa": 24, "sc": 31, "sd": 18, "se": 24, "si": 19, "sk": 24, "sm": 27,
    "so": 23, "st": 25, "sv": 28, "tl": 23, "tn": 24, "ua": 29, "va": 22, "vg": 24, "xk": 20, "ye": 30,
}

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


# A known country's code, exactly its length in letters and digits, and the end of a word after them.
def find_foreign_ibans(text):
    spans = []

    for match in FOREIGN_START.finditer(text):
        length = IBAN_LENGTHS.get(match.group()[:2])
        if length is None:
            continue
        chars = []
        position = match.start()

        while position < len(text) and len(chars) < length:
            char_match = FOREIGN_CHAR.match(text, position)
            if char_match:
                chars.append((char_match.group(), position))
                position += 1
            elif text[position] in " -." and position + 1 < len(text):
                position += 1
            else:
                break

        if (len(chars) == length and not FOREIGN_CHAR.match(text, position)
                and mod97("".join(c for c, _ in chars))):
            spans.append((match.start(), chars[-1][1] + 1))

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
