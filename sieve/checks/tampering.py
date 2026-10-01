import re
import unicodedata

from sieve.actions import Finding, action_for

REVIEW_AT = 0.5
BLOCK_AT = 0.9
MANY_INVISIBLE = 3

INVISIBLE = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]")
DIRECTION_CONTROLS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
VARIATION_SELECTORS = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")
ANSI = re.compile(r"\x1b\[")
WORD = re.compile(r"\w+")
EMOJI = "\u2600-\u27bf\U0001f000-\U0001faff"
EMOJI_JOINER = re.compile(f"(?:(?<=[{EMOJI}])|(?<=[{EMOJI}]\ufe0f))\u200d(?=[{EMOJI}])")
# ❤️ is ❤ + U+FE0F, and 👨‍👩‍👧 is three emoji joined by U+200D.
EMOJI_STYLE = re.compile(f"(?<=[{EMOJI}])\ufe0f")

SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN")


def script_of(char):
    if not char.isalpha():
        return None
    name = unicodedata.name(char, "")
    return next((s for s in SCRIPTS if name.startswith(s)), None)


def mixed_script_words(text):
    found = []
    for word in WORD.findall(text):
        scripts = {script_of(c) for c in word} - {None}
        if len(scripts) > 1:
            found.append(word)
    return found


# Reads the raw text: clean() would remove the evidence.
class TamperingLayer:
    name = "tampering"
    needs_raw_text = True

    def check(self, text):
        matches = []

        if TAG_CHARS.search(text):
            matches.append(("hidden_tag_chars", 0.9))
        if DIRECTION_CONTROLS.search(text):
            matches.append(("direction_override", 0.5))
        if ANSI.search(text):
            matches.append(("terminal_escape", 0.5))
        if len(INVISIBLE.findall(EMOJI_JOINER.sub("", text))) >= MANY_INVISIBLE:
            matches.append(("many_invisible_chars", 0.5))
        if len(VARIATION_SELECTORS.findall(EMOJI_STYLE.sub("", text))) >= MANY_INVISIBLE:
            matches.append(("variation_selector_payload", 0.5))
        if mixed_script_words(text):
            matches.append(("mixed_alphabet_word", 0.6))

        score = min(1.0, sum(weight for _, weight in matches))
        names = [name for name, _ in matches]
        return [Finding(self.name, score, action_for(score, REVIEW_AT, BLOCK_AT), names)]
