import re

from sieve.masking.number_units import apply_labeled_masks, find_units, split_into_groups, to_lower

EXPIRY_LABEL = "[SKT]"
CVV_LABEL = "[CVV]"
KEYWORD_DISTANCE = 25

# MM/YY or MM/YYYY, not part of a full date like 24.09.2026 or 12/10/2026.
EXPIRY = r"(?<![\d./-])(?:0?[1-9]|1[0-2])\s?[/.-]\s?(?:20)?\d{2}(?!\d|\s?[/.-]\s?\d)"
EXPIRY_AFTER_KEYWORD = re.compile(
    rf"\b(?:skt|son kullanma|son kul\.|exp(?:iry|iration)?|valid thru|ge[çc]erlilik)[^\d\n]{{0,{KEYWORD_DISTANCE}}}?({EXPIRY})"
)
CVV_KEYWORDS = re.compile(r"\b(?:cvv|cvc|cvn)2?|\bg[üu]venlik (?:kodu|numaras)|\bsecurity code")
# Pasted card details: "[KART] 12/27 123". Only separators in between, no words.
SEPARATORS = r"[\s,;:|/-]*"
EXPIRY_AFTER_CARD = re.compile(rf"\[kart\]{SEPARATORS}({EXPIRY})")
CVV_AFTER_EXPIRY = re.compile(rf"\[skt\]{SEPARATORS}(?<!\d)(\d{{3,4}})(?!\d)")


def cvv_spans(lower):
    groups = split_into_groups([u for u in find_units(lower) if u.real])  # no look-alike letters: "cvv o 123"
    spans = []
    for keyword in CVV_KEYWORDS.finditer(lower):
        group = next((g for g in groups if g[0].start >= keyword.end()), None)
        if group and group[0].start - keyword.end() <= KEYWORD_DISTANCE and len(group) in (3, 4):
            spans.append((group[0].start, group[-1].end, CVV_LABEL))
    return spans


# Runs after card masking: a card's expiry date and CVV only count next to [KART] or after a keyword,
# since "12/27" and "123" alone are just numbers.
class CardSecurityMaskingLayer:
    name = "card_security_masking"

    def mask(self, text):
        lower = to_lower(text)
        spans = [(m.start(1), m.end(1), EXPIRY_LABEL)
                 for pattern in (EXPIRY_AFTER_KEYWORD, EXPIRY_AFTER_CARD) for m in pattern.finditer(lower)]
        text = apply_labeled_masks(text, spans)

        lower = to_lower(text)
        spans = cvv_spans(lower) + [(m.start(1), m.end(1), CVV_LABEL) for m in CVV_AFTER_EXPIRY.finditer(lower)]
        return apply_labeled_masks(text, spans)
