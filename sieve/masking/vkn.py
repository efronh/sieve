import re

from sieve.masking.number_units import apply_masks, find_units, split_into_groups, to_lower

LABEL = "[VKN]"
VKN_LENGTH = 10
KEYWORD_DISTANCE = 40

KEYWORDS = re.compile(r"\b(?:vkn|vergi)\b")


# Needs a tax keyword: the checksum alone matches about 1 in 10 numbers.
class VKNMaskingLayer:
    name = "vkn_masking"

    def mask(self, text):
        lower = to_lower(text)

        spans = []
        for group in split_into_groups(find_units(lower)):
            real_units = [u for u in group if u.real]
            if len(real_units) != VKN_LENGTH:
                continue

            start = real_units[0].start
            if KEYWORDS.search(lower[max(0, start - KEYWORD_DISTANCE):start]):
                spans.append((start, real_units[-1].end))

        return apply_masks(text, spans, LABEL)
