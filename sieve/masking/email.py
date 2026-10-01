import re

from sieve.masking.number_units import apply_masks

LABEL = "[EPOSTA]"

AT = r"(?:@|\s*[\(\[]\s*(?:at|et)\s*[\)\]]\s*)"
DOT = r"(?:\.|\s*[\(\[]\s*(?:dot|nokta)\s*[\)\]]\s*)"
EMAIL = re.compile(rf"(?<![\w.+-])[\w.+-]+{AT}[\w-]+(?:{DOT}[\w-]+)+", re.IGNORECASE)


class EmailMaskingLayer:
    name = "email_masking"

    def mask(self, text):
        spans = [m.span() for m in EMAIL.finditer(text)]
        return apply_masks(text, spans, LABEL)
