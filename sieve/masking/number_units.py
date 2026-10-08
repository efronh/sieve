import bisect
import re
from contextvars import ContextVar
from dataclasses import dataclass

MAX_GAP = 3

# OutputGuard sets a list here to collect what masking replaces, as (label, value); None otherwise.
REPLACED = ContextVar("replaced", default=None)

NUMBER_WORDS = {
    "sıfır": "0", "bir": "1", "iki": "2", "üç": "3", "dört": "4",
    "beş": "5", "altı": "6", "yedi": "7", "sekiz": "8", "dokuz": "9",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}

LOOKALIKES = {
    "o": "0", "ı": "1", "i": "1", "l": "1", "|": "1",
    "z": "2", "s": "5", "b": "8",
}

UNIT = re.compile(
    r"\b(?:" + "|".join(NUMBER_WORDS) + r")\b"
    r"|\d"
    r"|[" + re.escape("".join(LOOKALIKES)) + r"]"
)


# A word for look-alike letters ends at an apostrophe too, so the "i" in "462'dir" stays a letter.
WORD = re.compile(r"[^\s'’]+")


@dataclass
class Unit:
    digit: str
    start: int
    end: int
    real: bool


def to_lower(text):
    lower = text.replace("I", "ı").replace("İ", "i").lower()
    if len(lower) != len(text):
        return text.lower()
    return lower


# A lookalike counts as a digit only on its own or in a word with a real digit. Each word is looked at once
# per text: walking out to the word's ends again for every lookalike in it was quadratic, and 8,000 "ı"
# kept a check busy for over 20 seconds.
def lookalike_words(text):
    words = [(m.start(), len(m.group()) == 1 or any(c.isdigit() for c in m.group())) for m in WORD.finditer(text)]
    starts = [start for start, _ in words]
    return lambda index: words[bisect.bisect_right(starts, index) - 1][1]


def find_units(text):
    units = []
    counts_as_digit = None
    for match in UNIT.finditer(text):
        part = match.group()

        if part in NUMBER_WORDS:
            units.append(Unit(NUMBER_WORDS[part], match.start(), match.end(), True))
        elif part.isdigit():
            units.append(Unit(str(int(part)), match.start(), match.end(), True))
        else:
            counts_as_digit = counts_as_digit or lookalike_words(text)
            if counts_as_digit(match.start()):
                units.append(Unit(LOOKALIKES[part], match.start(), match.end(), False))

    return units


def split_into_groups(units):
    groups = []
    current = []

    for unit in units:
        if current and unit.start - current[-1].end > MAX_GAP:
            groups.append(current)
            current = []
        current.append(unit)

    if current:
        groups.append(current)
    return groups


# A gap the writer left between two units: a space or a mark ("0599 326", "…5646&adim=2"). Letters alone, as in
# "5f4e" in a hash, run on.
GAP = re.compile(r"[\W_]")


# Start indexes of the windows of length units that begin and end at such gaps: whole pieces the writer typed
# ("0599", "326", ...), never a stretch cut out of a longer run. Sliding through the group instead found a
# checksum-valid run across the end of a phone number and the start of a card, which hid half of each and
# left the card's expiry date and CVV in the clear.
def aligned_windows(units, length, text):
    edge = [True] + [GAP.search(text, a.end, b.start) is not None for a, b in zip(units, units[1:])] + [True]
    return [i for i in range(len(units) - length + 1) if edge[i] and edge[i + length]]


def find_windows(group, length, min_real, is_valid, text):
    spans, taken = [], set()
    for i in aligned_windows(group, length, text):
        window = group[i:i + length]
        if (taken.isdisjoint(range(i, i + length)) and sum(u.real for u in window) >= min_real
                and is_valid("".join(u.digit for u in window))):
            spans.append((window[0].start, window[-1].end))
            taken.update(range(i, i + length))
    return spans


# A group of exactly length real digits with a keyword in the distance characters before it, whose number fits
# even if its checksum doesn't: "TC: 12345678901" is a TC number someone mistyped. Without a checksum to go on,
# only a number on its own counts; one cut out of "TC +90 521 812 27 64" would take most of a phone number.
def keyword_window(group, length, text, keywords, distance, fits=lambda number: True):
    real = [u for u in group if u.real]
    if len(real) != length:
        return []
    start = real[0].start
    if keywords.search(text[max(0, start - distance):start]) and fits("".join(u.digit for u in real)):
        return [(start, real[-1].end)]
    return []


def apply_masks(text, spans, label):
    return apply_labeled_masks(text, [(start, end, label) for start, end in spans])


def apply_labeled_masks(text, spans):
    replaced = REPLACED.get()
    result = []
    last_end = 0

    for start, end, label in sorted(spans, key=lambda s: (s[0], -s[1])):
        if start < last_end:
            continue
        result.append(text[last_end:start])
        result.append(label)
        if replaced is not None:
            replaced.append((label, text[start:end]))
        last_end = end

    result.append(text[last_end:])
    return "".join(result)
