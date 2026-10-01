import math
import re
from collections import Counter

KEY_LABEL = "[GIZLI_ANAHTAR]"
PASSWORD_LABEL = "[SIFRE]"

MIN_RANDOM_LENGTH = 32
MIN_RANDOM_ENTROPY = 4.3

KNOWN_KEYS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]

URL_PASSWORD = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@", re.IGNORECASE)

HAS_DIGIT_OR_SYMBOL = r"(?=[^\s\"',;]*[\d!@#$%^&*?.+\-_])"
PASSWORD_WITH_COLON = re.compile(
    r"\b(?:password|passwd|pwd|pass|parola|şifre|sifre|secret|api[_-]?key|token|pin)\b\s*[:=]\s*[\"']?"
    rf"{HAS_DIGIT_OR_SYMBOL}([^\s\"',;]{{4,}})",
    re.IGNORECASE,
)
PASSWORD_IN_SENTENCE = re.compile(
    rf"\b(?:şifrem|sifrem|parolam|pin(?:im|imi)?|şifremi|parolamı)\s+(?:de\s+|da\s+)?{HAS_DIGIT_OR_SYMBOL}([^\s\"',;]{{4,}})",
    re.IGNORECASE,
)

RANDOM_TOKEN = re.compile(rf"[A-Za-z0-9_\-+/=]{{{MIN_RANDOM_LENGTH},}}")


def entropy(text):
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def looks_random(token):
    has_mix = any(c.isdigit() for c in token) and any(c.isupper() for c in token) and any(c.islower() for c in token)
    return has_mix and entropy(token) >= MIN_RANDOM_ENTROPY


def apply_labeled_masks(text, spans):
    result = []
    last_end = 0

    for start, end, label in sorted(spans, key=lambda s: (s[0], -s[1])):
        if start < last_end:
            continue
        result.append(text[last_end:start])
        result.append(label)
        last_end = end

    result.append(text[last_end:])
    return "".join(result)


class SecretMaskingLayer:
    name = "secret_masking"

    def mask(self, text):
        spans = []

        for pattern in KNOWN_KEYS:
            spans += [(m.start(), m.end(), KEY_LABEL) for m in pattern.finditer(text)]

        for pattern in (URL_PASSWORD, PASSWORD_WITH_COLON, PASSWORD_IN_SENTENCE):
            spans += [(m.start(1), m.end(1), PASSWORD_LABEL) for m in pattern.finditer(text)]

        return apply_labeled_masks(text, spans)


# Runs last, so an obfuscated IBAN or TC gets its own label first.
class RandomTokenMaskingLayer:
    name = "random_token_masking"

    def mask(self, text):
        spans = [(m.start(), m.end(), KEY_LABEL) for m in RANDOM_TOKEN.finditer(text) if looks_random(m.group())]
        return apply_labeled_masks(text, spans)
