# Lettered labels for one conversation ([IBAN_A], [IBAN_B]): the model can tell two values of a kind apart and
# name the one a tool call needs, and the app turns the label back into the value. With plain labels, "eski
# e-postam X, yenisi Y" reached the model as two [EPOSTA], and a transfer to the IBAN the user typed couldn't be
# written at all (THREAT_MODEL TH-08, scripts/evaluate_masking_loss.py).
#   vault = Vault()
#   vault.mask("Annemin IBAN'ı TR33 0006 1005 1978 6457 8413 26")   # "Annemin IBAN'ı [IBAN_A]"
#   vault.entries["[IBAN_A]"]                                      # {"value": "TR33 ...", "sources": {"user"}}
# The vault holds the values themselves: it stays in the app's memory, never in a prompt, an event or a log.
# Letters, not digits: a digit in a label's word makes its look-alike letters ("l", "o" in TELEFON) count as
# digits, and masking the model's answer again could read a phone number into it.
import re
from collections import Counter, defaultdict

from sieve.masking import LABEL_NAMES
from sieve.masking.number_units import REPLACED
from sieve.output import PHONE_PREFIX, data_key
from sieve.pipeline import LAYERS, clean, mask

USER, DOCUMENT = "user", "document"
MAX_NESTING = 64  # deeper arguments are ToolGuard's to refuse
# Values a session keeps. Past it, a new value is still masked, with a label of its own that stands for nothing: a
# session sending value after value can't grow the vault without end.
MAX_VALUES = 1000
KINDS = "|".join(LABEL_NAMES)
PLAIN_LABEL = re.compile(rf"\[({KINDS})\]")
LETTERED_LABEL = re.compile(rf"\[(?:{KINDS})_[A-Z]+\]")
ANY_LABEL = re.compile(rf"\[(?:{KINDS})(?:_[A-Za-z0-9]+)?\]")
# A label is turned back only where it stands as a word: not in a URL, a link, an HTML tag or a domain name, where
# the value would leave with a click or a DNS lookup ("https://x.example/?i=[IBAN_A]", "[TELEFON_A].x.example").
# After it: closing punctuation and a space, or a suffix ("[IBAN_A]'ya").
STANDALONE = re.compile(r"(?<![^\s(\"“'‘])" + LETTERED_LABEL.pattern + r"(?=[.,;:!?)\"”'’]*(?:\s|$)|['’]\w)")
MARKUP = re.compile(r"<[^<>]*>|\]\([^()]*\)")  # an HTML tag, a Markdown link's target


def letters(n):  # 1 -> A, 26 -> Z, 27 -> AA
    result = ""
    while n:
        n, rest = divmod(n - 1, 26)
        result = chr(ord("A") + rest) + result
    return result


# One phone number written two ways (0532..., +90 532..., sıfır beş üç...) is one value; so is an IBAN with or
# without its spaces.
def value_key(kind, value):
    key = data_key(value)
    if kind == "TELEFON" and key.isdigit():
        key = PHONE_PREFIX.sub("", key, count=1)
    return key


# The value behind each label of the masked text, in order, or None when they can't be lined up. Each value
# masking replaced is a piece of the text it ran on, so the text is the masked one with each label read as one of
# the values replaced under it.
def values_in_order(text, masked, replaced):
    options = defaultdict(set)
    for label, value in replaced:
        options[label].add(value)
    parts, kinds, last = [], [], 0
    for m in PLAIN_LABEL.finditer(masked):
        values = sorted(options.get(m.group(), ()), key=len, reverse=True)
        if not values:
            return None
        parts += [re.escape(masked[last:m.start()]), "(" + "|".join(map(re.escape, values)) + ")"]
        kinds.append(m.group(1))
        last = m.end()
    parts.append(re.escape(masked[last:]))
    match = re.fullmatch("".join(parts), text, re.DOTALL)
    return list(zip(kinds, match.groups())) if match else None


def neutralize(text):
    return ANY_LABEL.sub(lambda m: f"({m.group()[1:-1]})", text)


class Vault:
    def __init__(self):
        self.labels = {}  # (kind, value key) -> label
        self.entries = {}  # label -> {"value": the value as first written, "sources": {"user", "document"}}
        self.counts = Counter()

    def label_for(self, kind, value, source):
        key = (kind, value_key(kind, value))
        label = self.labels.get(key)
        if label is None and len(self.entries) >= MAX_VALUES:
            return self.blank(kind)
        if label is None:
            self.counts[kind] += 1
            label = self.labels[key] = f"[{kind}_{letters(self.counts[kind])}]"
            self.entries[label] = {"value": value, "sources": set()}
        self.entries[label]["sources"].add(source)
        return label

    # The text masked as mask() does, with each label lettered. A label already in the text ("[IBAN_A]" typed by a
    # user or planted in a document) becomes "(IBAN_A)", so every label the model gets is the vault's. If the
    # labels can't be lined up with their values, each gets a letter of its own with no value behind it: the text
    # is as masked as ever, and a tool call naming such a label is refused.
    def mask(self, text, source=USER, layers=LAYERS):
        text = clean(neutralize(clean(text)))
        replaced = []
        token = REPLACED.set(replaced)
        try:
            masked = mask(text, layers)
        finally:
            REPLACED.reset(token)
        pairs = values_in_order(clean(text), masked, replaced)
        if pairs is None:
            pairs = [(m.group(1), None) for m in PLAIN_LABEL.finditer(masked)]
        labels = iter(self.label_for(kind, value, source) if value is not None else self.blank(kind)
                      for kind, value in pairs)
        return PLAIN_LABEL.sub(lambda m: next(labels), masked)

    def blank(self, kind):
        self.counts[kind] += 1
        return f"[{kind}_{letters(self.counts[kind])}]"

    # Tool arguments with every label turned back into its value, and what was wrong with them: a label nothing in
    # this conversation stands for ("unknown_label"), or a value only a document gave ("document_value"), which is
    # what an instruction planted in a document asks for ("send it to the IBAN in this e-mail").
    def resolve(self, args):
        problems = set()

        def back(m):
            entry = self.entries.get(m.group())
            if entry is None:
                problems.add("unknown_label")
                return m.group()
            if USER not in entry["sources"]:
                problems.add("document_value")
            return entry["value"]

        def walk(value, depth=0):
            if depth > MAX_NESTING:
                return value
            if isinstance(value, str):
                return LETTERED_LABEL.sub(back, value)
            if isinstance(value, dict):
                return {k: walk(v, depth + 1) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v, depth + 1) for v in value]
            return value

        return walk(args), problems

    # The text with every label that stands for one of these sources' values turned back into it, where it stands
    # as a word of its own; the rest stay labels.
    def reveal(self, text, sources=(USER,)):
        markup = [m.span() for m in MARKUP.finditer(text)]

        def back(m):
            entry = self.entries.get(m.group())
            if not entry or not entry["sources"] & set(sources) or any(s <= m.start() < e for s, e in markup):
                return m.group()
            return entry["value"]
        return STANDALONE.sub(back, text)
