import copy
import hashlib
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

from sieve.actions import ACTION_ORDER, BLOCK, REVIEW, Finding, error_finding, failed, worst_action
from sieve.checks.code_payloads import CodePayloadLayer
from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.checks.tampering import TamperingLayer
from sieve.checks.urls import URLCheckLayer
from sieve.masking.card import CardMaskingLayer
from sieve.masking.card_security import CardSecurityMaskingLayer
from sieve.masking.credentials import RandomTokenMaskingLayer, SecretMaskingLayer
from sieve.masking.email import EmailMaskingLayer
from sieve.masking.iban import IBANMaskingLayer
from sieve.masking.phone import PhoneMaskingLayer
from sieve.masking.tc import TCMaskingLayer
from sieve.masking.vkn import VKNMaskingLayer
from sieve.ml.injection import MLInjectionLayer, warn_without_ml
from sieve.timing import add, since

INVISIBLE_CHARS = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\ufe00-\ufe0f\U000e0100-\U000e01ef]"
)
ANSI_CODES = re.compile(r"(?:\x1b|\\x1b)\[[0-9;]*[a-zA-Z]")
# Letters drawn decoratively that NFKC leaves alone, or turns into "(a)": small capitals, parenthesized letters,
# negative circled and squared ones. A model reads them as the letters; the checks didn't.
DECORATED_LETTERS = str.maketrans(
    dict(zip("ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡʏᴢ", "abcdefghijklmnopqrstuvwyz"))
    | {0x249C + i: chr(ord("a") + i) for i in range(26)}
    | {0x1F110 + i: chr(ord("A") + i) for i in range(26)}
    | {0x1F150 + i: chr(ord("A") + i) for i in range(26)}
    | {0x1F170 + i: chr(ord("A") + i) for i in range(26)}
)
# What shows as a blank but isn't a space to the checks: Hangul fillers, the braille blank, the Ogham space mark
# (NFKC keeps them), and the line and paragraph separators.
BLANKS = str.maketrans({"\u115f": " ", "\u1160": " ", "\u3164": " ", "\uffa0": " ", "\u2800": " ", "\u1680": " ",
                        "\u2028": "\n", "\u2029": "\n"})
# A right-to-left override shows what follows it reversed, up to its pop or the line's end: "\u202e" + "yas kok"
# reads as "kok say". Turned around here, so the checks read what a reader sees.
RIGHT_TO_LEFT_OVERRIDE = re.compile(r"\u202e([^\u202c\u2069\n]*)")
TAG_FIRST, TAG_LAST = 0xE0020, 0xE007E
MAX_CHECK_CHARS = 8000
# A message is masked whole, since the model gets all of it; past this it's blocked unread. Masking costs up to about
# 5 µs a character (a long run of digits), so 1 MB kept a check busy for seconds, and a server with one worker stalled.
# A user tracked by the session limits can't send more in 10 minutes anyway (max_chars_per_window).
MAX_INPUT_CHARS = 50_000
# What this user may see (user_data), masked to be compared with an answer or a tool argument, is read this far.
MAX_USER_DATA_CHARS = 50_000
# The paid LLM injection check only runs when local layers are unsure (see needs_llm).
LLM_MIN_ML = 0.2
# The LLM reads the start and the end of a long message; local layers read up to MAX_CHECK_CHARS.
LLM_MAX_CHARS = 3000
CACHE_SIZE = 2048
# The layers that score how much of a text is an attack (the injection rules, ML) also read a message's sentences, on
# their own and two at a time up to SENTENCE_REACH apart. Read whole, an attack with ordinary sentences around it was
# scored with them: 800 characters on each side let 71 of the 79 attacks the plain check catches through, and so did
# four sentences between its halves. A document is read by sentence already (documents.py).
SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
MAX_SENTENCES = 200
SENTENCE_REACH = 3
# A window of a few words is noise to the ML layer: "Aslında tam olarak değil." alone scored 0.89, over its threshold.
MIN_WINDOW_WORDS = 5
# Runs of this many words, a run starting every WORD_STRIDE words: sentences need their full stops, and an attack
# written on after an ordinary sentence with none between them was read as part of it.
WINDOW_WORDS = (10, 20)
WORD_STRIDE = 5
WINDOW_SECOND_STAGE = 64

# Order matters: secrets first (a connection string looks like an e-mail),
# then longer, more specific numbers; expiry date and CVV right after the card,
# since they need [KART] as context; a tax number with its keyword, then a TC
# number with its checksum, before phones, which have neither: "5748 6794 88 6"
# is a TC number, not a phone number and a 6; random-looking tokens last.
LAYERS = [
    SecretMaskingLayer(),
    EmailMaskingLayer(),
    IBANMaskingLayer(),
    CardMaskingLayer(),
    CardSecurityMaskingLayer(),
    VKNMaskingLayer(),
    TCMaskingLayer(),
    PhoneMaskingLayer(),
    RandomTokenMaskingLayer(),
]


def default_check_layers():
    layers = [TamperingLayer(), PromptInjectionLayer(), CodePayloadLayer(), URLCheckLayer()]
    if MLInjectionLayer.is_available():
        layers.append(MLInjectionLayer())  # can review, never blocks on its own (BLOCK_AT)
    else:
        warn_without_ml()
    return layers


def reveal_tag_chars(text):
    result = []
    for c in text:
        code = ord(c)
        if TAG_FIRST <= code <= TAG_LAST:
            result.append(chr(code - 0xE0000))
        elif not 0xE0000 <= code <= 0xE007F:
            result.append(c)
    return "".join(result)


# Marks stacked on Latin, Greek or Cyrillic letters and on digits are obfuscation ("t̷a̷l̷i̷m̷a̷t", "1̲0̲0̲…");
# after NFKC, Turkish letters are single characters anyway. On Arabic or Hebrew letters the marks
# are part of the text (harakat, niqqud), so they stay in what the model gets.
FOLDED_SCRIPTS = ("LATIN", "GREEK", "CYRILLIC")


def strip_combining_marks(text):
    result = []
    keep_marks = False
    for c in text:
        if not unicodedata.combining(c):
            keep_marks = c.isalpha() and not unicodedata.name(c, "").startswith(FOLDED_SCRIPTS)
            result.append(c)
        elif keep_marks:
            result.append(c)
    return "".join(result)


def clean(text):
    text = reveal_tag_chars(text)
    text = RIGHT_TO_LEFT_OVERRIDE.sub(lambda m: m.group(1)[::-1], text)
    text = unicodedata.normalize("NFKC", text.translate(DECORATED_LETTERS)).translate(BLANKS)
    text = strip_combining_marks(text)
    text = ANSI_CODES.sub("", text)
    return INVISIBLE_CHARS.sub("", text)


# The first limit characters of texts, the last one cut where the limit falls. What's left out isn't known to be the
# user's own, which flags more, not less.
def first_chars(texts, limit=MAX_USER_DATA_CHARS):
    kept = []
    for text in texts:
        if limit <= 0:
            break
        kept.append(text[:limit])
        limit -= len(text)
    return kept


def mask(text, layers=LAYERS):
    text = clean(text)
    for layer in layers:
        text = layer.mask(text)
    return text


@dataclass
class GuardrailResult:
    text: str
    action: str
    findings: list = field(default_factory=list)
    llm_called: bool = False
    timings: dict = field(default_factory=dict)  # ms per stage: masking, each check layer by name, llm
    request_id: Optional[str] = None  # TenantGuardrail: the ID joining this request's SIEM events


def head_and_tail(text, limit=LLM_MAX_CHARS):
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n[...]\n{text[-half:]}"


# A message's sentences, pairs of them up to SENTENCE_REACH apart, and runs of words; nothing for a message short
# enough to be one of them.
def sentence_windows(text):
    sentences = [s.strip() for line in text.splitlines() for s in SENTENCE_END.split(line) if s.strip()]
    sentences = sentences[:MAX_SENTENCES]
    pairs = [f"{sentences[i]} {sentences[j]}" for i in range(len(sentences))
             for j in range(i + 1, min(i + SENTENCE_REACH + 1, len(sentences)))]
    words = text.split()
    runs = [" ".join(words[i:i + size]) for size in WINDOW_WORDS if len(words) > size
            for i in range(0, len(words) - size + WORD_STRIDE, WORD_STRIDE)]
    windows = (sentences if len(sentences) > 1 else []) + pairs + runs
    return list(dict.fromkeys(w for w in windows if len(w.split()) >= MIN_WINDOW_WORDS and w != text.strip()))


def read_windows(layer, windows):
    if hasattr(layer, "check_many"):  # the ML layer: one batch for its second stage
        return layer.check_many(windows, WINDOW_SECOND_STAGE)[0]
    return [layer.check(window) for window in windows]


# The layer's finding for the whole message, or for a window if that one says more: a worse action, or the same
# action with a higher score.
def strongest(whole, windows):
    found = [*whole, *(f for window in windows for f in window)]
    return [max(found, key=lambda f: (ACTION_ORDER[f.action], f.probability))] if found else whole


# Skip the LLM injection check when it can't change the outcome.
def needs_llm(findings, min_ml=LLM_MIN_ML):
    if min_ml is None:
        return True
    action = worst_action(findings)
    if action == BLOCK:
        return False
    ml = next((f for f in findings if f.check == MLInjectionLayer.name), None)
    return ml is None or action == REVIEW or ml.probability >= min_ml


class Guardrail:
    def __init__(self, masking_layers=LAYERS, check_layers=None, llm_layer=None, max_check_chars=MAX_CHECK_CHARS,
                 llm_min_ml=LLM_MIN_ML, llm_max_chars=LLM_MAX_CHARS, cache_size=CACHE_SIZE, max_input_chars=None):
        self.masking_layers = masking_layers
        self.check_layers = default_check_layers() if check_layers is None else check_layers
        self.llm_layer = llm_layer
        self.max_check_chars = max_check_chars
        self.max_input_chars = max(MAX_INPUT_CHARS, max_check_chars) if max_input_chars is None else max_input_chars
        self.llm_min_ml = llm_min_ml
        self.llm_max_chars = llm_max_chars
        self.cache_size = cache_size
        self.cache = OrderedDict()
        self.cache_lock = threading.Lock()  # the checks may run side by side; the cache's order can't

    def check(self, text):
        start = time.perf_counter()
        if len(text) > self.max_input_chars:
            return GuardrailResult("", BLOCK, [Finding("input_too_large", 1.0, BLOCK, [f"{len(text)} chars"])],
                                   timings={"masking": since(start)})
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self.cache_lock:
            cached = self.cache.get(key)
            if cached is not None:
                self.cache.move_to_end(key)
        if cached is not None:
            result = copy.deepcopy(cached)  # a copy, so a caller editing findings can't change the cache
            result.timings = {"cache": since(start)}
            return result

        result = self.run(text)
        # A failed check may work on the next try. A message longer than the checks read is rarely sent twice, and
        # 2,048 of 50,000 characters each would be hundreds of megabytes.
        if self.cache_size and not failed(result.findings) and len(text) <= self.max_check_chars:
            stored = copy.deepcopy(result)
            with self.cache_lock:
                self.cache[key] = stored
                if len(self.cache) > self.cache_size:
                    self.cache.popitem(last=False)
        return result

    def run(self, text):
        timings = {}
        start = time.perf_counter()
        try:
            cleaned = clean(text)
            masked = mask(cleaned, self.masking_layers)
        except Exception as e:
            # Without masked text there's nothing safe to pass on to the model.
            return GuardrailResult("", BLOCK, [error_finding("masking", e)], timings={"masking": since(start)})
        timings["masking"] = since(start)

        findings = []
        if len(cleaned) > self.max_check_chars:
            # Checks only read the start, so the rest can't be trusted: send to review.
            findings.append(Finding("input_length", 1.0, REVIEW, [f"{len(cleaned)} chars"]))

        # One layer failing doesn't stop the others, so the event still shows what they found.
        windows = sentence_windows(cleaned[:self.max_check_chars])
        for layer in self.check_layers:
            source = text if getattr(layer, "needs_raw_text", False) else cleaned
            start = time.perf_counter()
            try:
                found = layer.check(source[:self.max_check_chars])
                if windows and getattr(layer, "reads_sentences", False):
                    found = strongest(found, read_windows(layer, windows))
                findings += found
            except Exception as e:
                findings.append(error_finding(layer.name, e))
            add(timings, layer.name, start)
        llm_called = False
        if self.llm_layer is not None and worst_action(findings) != BLOCK:
            start = time.perf_counter()
            try:
                skip = set() if needs_llm(findings, self.llm_min_ml) else set(getattr(self.llm_layer, "gated_checks", ()))
                llm_findings = self.llm_layer.check(head_and_tail(masked, self.llm_max_chars), skip=skip)
                llm_called = bool(llm_findings)
                findings += llm_findings
            except Exception as e:
                findings.append(error_finding("llm", e))
            timings["llm"] = since(start)

        return GuardrailResult(masked, worst_action(findings), findings, llm_called, timings)


if __name__ == "__main__":
    print(mask("Merhaba, TC kimlik numaram 10000000146."))
