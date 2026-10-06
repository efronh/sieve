import copy
import hashlib
import re
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field

from sieve.actions import BLOCK, REVIEW, Finding, worst_action
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

INVISIBLE_CHARS = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\ufe00-\ufe0f\U000e0100-\U000e01ef]"
)
ANSI_CODES = re.compile(r"(?:\x1b|\\x1b)\[[0-9;]*[a-zA-Z]")
TAG_FIRST, TAG_LAST = 0xE0020, 0xE007E
MAX_CHECK_CHARS = 8000
# The paid LLM injection check only runs when local layers are unsure (see needs_llm).
LLM_MIN_ML = 0.2
# The LLM reads the start and the end of a long message; local layers read up to MAX_CHECK_CHARS.
LLM_MAX_CHARS = 3000
CACHE_SIZE = 2048

# Order matters: secrets first (a connection string looks like an e-mail),
# then longer, more specific numbers, so a card or phone number isn't
# partly eaten by the TC checksum; expiry date and CVV right after the card,
# since they need [KART] as context; random-looking tokens last.
LAYERS = [
    SecretMaskingLayer(),
    EmailMaskingLayer(),
    IBANMaskingLayer(),
    CardMaskingLayer(),
    CardSecurityMaskingLayer(),
    PhoneMaskingLayer(),
    TCMaskingLayer(),
    VKNMaskingLayer(),
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
    text = unicodedata.normalize("NFKC", text)
    text = strip_combining_marks(text)
    text = ANSI_CODES.sub("", text)
    return INVISIBLE_CHARS.sub("", text)


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


def head_and_tail(text, limit=LLM_MAX_CHARS):
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n[...]\n{text[-half:]}"


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
                 llm_min_ml=LLM_MIN_ML, llm_max_chars=LLM_MAX_CHARS, cache_size=CACHE_SIZE):
        self.masking_layers = masking_layers
        self.check_layers = default_check_layers() if check_layers is None else check_layers
        self.llm_layer = llm_layer
        self.max_check_chars = max_check_chars
        self.llm_min_ml = llm_min_ml
        self.llm_max_chars = llm_max_chars
        self.cache_size = cache_size
        self.cache = OrderedDict()

    def check(self, text):
        key = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if key in self.cache:
            self.cache.move_to_end(key)
            return copy.deepcopy(self.cache[key])  # a copy, so a caller editing findings can't change the cache

        result = self.run(text)
        if self.cache_size:
            self.cache[key] = copy.deepcopy(result)
            if len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)
        return result

    def run(self, text):
        cleaned = clean(text)
        masked = mask(cleaned, self.masking_layers)

        findings = []
        if len(cleaned) > self.max_check_chars:
            # Checks only read the start, so the rest can't be trusted: send to review.
            findings.append(Finding("input_length", 1.0, REVIEW, [f"{len(cleaned)} chars"]))

        for layer in self.check_layers:
            source = text if getattr(layer, "needs_raw_text", False) else cleaned
            findings += layer.check(source[:self.max_check_chars])
        llm_called = False
        if self.llm_layer is not None and worst_action(findings) != BLOCK:
            skip = set() if needs_llm(findings, self.llm_min_ml) else set(getattr(self.llm_layer, "gated_checks", ()))
            llm_findings = self.llm_layer.check(head_and_tail(masked, self.llm_max_chars), skip=skip)
            llm_called = bool(llm_findings)
            findings += llm_findings

        return GuardrailResult(masked, worst_action(findings), findings, llm_called)


if __name__ == "__main__":
    print(mask("Merhaba, TC kimlik numaram 10000000146."))
