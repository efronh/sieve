import base64
import binascii
import bisect
import codecs
import html
import quopri
import re
import unicodedata
import urllib.parse

from sieve.actions import Finding, action_for
from sieve.masking.number_units import to_lower

REVIEW_AT = 0.4
BLOCK_AT = 0.8
NEAR_DISTANCE = 60

TURKISH_TO_ASCII = str.maketrans("ışğüöç", "isguoc")
LEETSPEAK = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t"})
# Letters drawn like Latin ones, by case: lowercase Cyrillic н and в look like small capitals H and B, Greek ν like v
# but its capital Ν like N. Only for matching; the text the model gets keeps them.
HOMOGLYPHS_UPPER = str.maketrans("АВЕКМНОРСТХУІЈЅΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEKMHOPCTXYIJSABEZHIKMNOPTYX")
HOMOGLYPHS = str.maketrans("аеорсухіјѕвкмнтһԁӏѵԛԝαεικνορτυχγ", "aeopcyxijsbkmhthdlvqwaeikvoptuxy")
# Turkish written in another alphabet ("Өнджеки түм талиматлары йок сай"), read back for the checks: a model reads
# it, and nothing in the checks did. Longest first, so a digraph wins over its letters.
TRANSLITERATION = sorted({
    "дж": "c", "ч": "ç", "ш": "ş", "щ": "şç", "ғ": "ğ", "ө": "ö", "ү": "ü", "ы": "ı", "ә": "e", "ц": "ts", "ю": "yu",
    "я": "ya", "ё": "yo", "э": "e", "є": "ye", "ї": "yi", "ъ": "", "ь": "", "а": "a", "б": "b", "в": "v", "г": "g",
    "д": "d", "е": "e", "ж": "j", "з": "z", "и": "i", "й": "y", "і": "i", "к": "k", "л": "l", "м": "m", "н": "n",
    "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h",
    "ου": "u", "μπ": "b", "ντ": "d", "γκ": "g", "τζ": "c", "τσ": "ç", "γι": "y", "α": "a", "β": "v", "γ": "g",
    "δ": "d", "ε": "e", "ζ": "z", "η": "i", "θ": "th", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "n", "ξ": "ks",
    "ο": "o", "π": "p", "ρ": "r", "σ": "s", "ς": "s", "τ": "t", "υ": "i", "φ": "f", "χ": "h", "ψ": "ps", "ω": "o",
}.items(), key=lambda pair: -len(pair[0]))
TRANSLITERATED = re.compile("|".join(map(re.escape, (k for k, _ in TRANSLITERATION))))
TRANSLITERATION_MAP = dict(TRANSLITERATION)
OTHER_ALPHABET = re.compile(r"[Ͱ-ϿЀ-ӿ]")

SPACED_LETTERS = re.compile(r"(?:\b\w\b[\s._*-]){2,}\b\w\b")
REPEATED_CHARS = re.compile(r"(\w)\1{2,}")
# The URL-safe alphabet too ("-" and "_" for "+" and "/"): it split the token where they stood.
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
BASE32_TOKEN = re.compile(r"\b[A-Za-z2-7]{16,}=*")
HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){6,}\b")
HEX_SPACED = re.compile(r"\b[0-9a-fA-F]{2}(?:[ :][0-9a-fA-F]{2}){5,}\b")
HEX_ESCAPED = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
# Base64 broken into lines, as MIME does every 76 characters: each line alone cuts a letter in two and decodes to
# nothing. Lines start at a line's start, so a long line isn't rescanned from every character.
BASE64_LINES = re.compile(r"^(?:[A-Za-z0-9+/]{16,}+={0,2}\r?\n){2,}+[A-Za-z0-9+/]*+={0,2}", re.MULTILINE)
URL_ENCODED = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
HTML_ENTITIES = re.compile(r"(?:&#x?[0-9a-fA-F]+;){3,}")
MORSE_TOKEN = re.compile(r"(?:[.-]{1,6}[ /]+){3,}[.-]{1,6}")
ROT13_HINT = re.compile(r"\brot ?-?13\b", re.IGNORECASE)
REVERSED_HINT = re.compile(r"\b(?:revers\w*|backwards|tersten|ters çevr\w*)\b", re.IGNORECASE)
MIN_LETTER_SHARE = 0.3
DECODE_DEPTH = 2

MORSE_CODE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g",
    "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n",
    "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u",
    "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z",
}


def decode_base64(token):
    token = token.replace("-", "+").replace("_", "/")
    return base64.b64decode(token + "=" * (-len(token) % 4))


def decode_base32(token):
    token = token.rstrip("=").upper()
    return base64.b32decode(token + "=" * (-len(token) % 8))


def decode_morse(token):
    words = re.split(r"\s*/\s*", token.strip())
    return " ".join("".join(MORSE_CODE.get(letter, "") for letter in word.split()) for word in words)


TOKEN_DECODERS = [
    (BASE64_TOKEN, decode_base64),
    (BASE32_TOKEN, decode_base32),
    (HEX_TOKEN, bytes.fromhex),
    (HEX_SPACED, lambda token: bytes.fromhex(token.replace(":", " "))),
    (BASE64_LINES, lambda token: decode_base64("".join(token.split()))),
    (HEX_ESCAPED, lambda token: bytes.fromhex(token.replace("\\x", ""))),
    (URL_ENCODED, urllib.parse.unquote),
    (HTML_ENTITIES, html.unescape),
    (MORSE_TOKEN, decode_morse),
]

# "talimatımı" / "kurallarım" are the user's own (a payment order, their rules), not the assistant's.
NOT_FIRST_PERSON = r"(?!(?:lar)?[iu]m)"
RULE_OBJECTS = re.compile(
    rf"\b(?:talimat|kural|komut|yonerge|direktif|kisitlama|instruction|rule|guideline|prompt|directive){NOT_FIRST_PERSON}\w*"
)
IGNORE_VERBS_TR = re.compile(
    # TDK writes "yok saymak" as two words; "yoksay" is the common joined spelling.
    r"\b(?:unut(?:un|up|arak)?|yok ?say(?:in(?:iz)?|arak|ip)?|gormezden gel(?:in|erek)?|gecersiz say\w*"
    r"|devre disi birak\w*)\b"
    # Reported speech ("unut demiştin", "unut dedi", "unut diyorlar") is a quote, not an order.
    # Only second/third-person past or reported forms: "unut diye", "unut diyorum", "unut dedim" are still orders.
    r"(?!\s+(?:dedi(?:n|niz|ler)?|demis(?:ti(?:n|niz)?|ler)?|diyor(?:du|dun|lar|sun|sunuz)?)\b)"
)
# English puts the verb first ("ignore the rules"); "a rule to ignore node_modules" is the other way round.
# Either order still counts for a Turkish light verb ("rule'ları bypass et") or a pronoun ("ignore them").
IGNORE_VERBS_EN = re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\b")
IGNORE_VERBS_ANY_ORDER = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)(?:\s+(?:et|edin|ediniz|eder\s+mis[iu]n|yap)\b|\s+(?:them|those|these|it all)\b)"
)
SECRET_OBJECTS = re.compile(
    r"\b(?:sistem|system|gizli|hidden|ilk|initial|orijinal|original|baslangic)\s*"
    rf"(?:prompt|talimat|instruction|yonerge){NOT_FIRST_PERSON}\w*"
)
# Requests only ("göster", "yazar mısın", "söylemeni"), not "yazdım", "yazılım", "doktor", "printer".
REVEAL_VERBS = re.compile(
    r"\b(?:(?:goster|yazdir|yaz|soyle|paylas|tekrarla|dok)"
    r"(?:y?[iu]n(?:[iu]z)?|[aei]?r|y?[ae]bil[iu]r|m[ae]n[iu]?|m[ae]l[iu]s[iu]n|s[ae]n[ae])?"
    r"|(?:print|reveal|show|repeat|output|tell|leak|dump)(?:s|ed|n|ing)?)\b"
)
LIMIT_WORDS = re.compile(
    r"\b(?:kisitlama|filtre|sansur)(?:s[iu]z\w*|\w*\s+olmadan)"
    r"|\b(?:no|without) (?:restrictions|filters|rules|limits|censorship)\b|\b(?:unrestricted|uncensored|unfiltered)\b"
)
RESPONSE_WORDS = re.compile(
    r"\b(?:cevap\w*|yanit\w*|konus\w*|anlat\w*|soyle\w*|mod\w*|asistan\w*|yapay zeka|"
    r"answer\w*|respon\w*|repl\w*|talk\w*|assistant|ai|model)\b"
)

SINGLE_PATTERNS = [
    ("jailbreak_word", re.compile(r"\bjailbreak\w*"), 0.5),
    ("jailbreak_request", re.compile(
        r"\b(?:enable|activate|enter|switch to|turn on|ac|etkinlestir|gec|gir)\w*\s+(?:\w+\s+){0,2}jailbreak"
        r"|\bjailbreak\w*\s+mod\w*"), 0.9),
    ("do_anything_now", re.compile(r"\bdo anything now\b"), 0.9),
    ("bypass_safety", re.compile(r"\bbypass[\s_-]*(?:the\s+)?(?:filter|safety|guard|restriction|censor|security|filtre|guvenlik)\w*"), 0.5),
    ("special_mode", re.compile(r"\b(?:developer|gelistirici|debug|god|admin|yonetici)\s*mod\w*"), 0.3),
    ("fake_system_tag", re.compile(r"<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<</?sys>>"), 0.8),
    ("fake_system_line", re.compile(r"^[^\S\n]*(?:#{2,}[^\S\n]*)?(?:system|sistem)\s*:", re.MULTILINE), 0.3),
    ("new_task", re.compile(r"\b(?:yeni gorev|yeni talimat|yeni kural|new task|new instruction)\w*"), 0.3),
    ("new_identity", re.compile(r"\b(?:artik sen|bundan sonra sen)\b(?! d[ae]\b)|\b(?:you are now|from now on you)\b"), 0.4),
    ("role_play", re.compile(r"\b(?:act as|pretend (?:to be|you)|gibi davran|rol yap)\w*"), 0.3),
]


def join_spaced_letters(text):
    return SPACED_LETTERS.sub(lambda m: re.sub(r"[\s._*-]", "", m.group()), text)


def strip_accents(text):
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def normalize(text):
    text = to_lower(text.translate(HOMOGLYPHS_UPPER)).translate(HOMOGLYPHS)
    text = strip_accents(text.translate(TURKISH_TO_ASCII)).translate(LEETSPEAK)
    text = join_spaced_letters(text)
    return REPEATED_CHARS.sub(r"\1", text)


# Escapes mixed into readable text ("%C3%96nceki%20t%C3%BCm", "&Ouml;nceki t&uuml;m", "\\u00d6nceki", "=C3=96nceki"):
# no run of them is long enough to be a token, so the whole text is read with them undone, once three are there.
MIN_ESCAPES = 3
ESCAPES = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|(?:\\x[0-9a-fA-F]{2})+")
WHOLE_TEXT_DECODERS = [
    (re.compile(r"%[0-9a-fA-F]{2}"), urllib.parse.unquote),
    (re.compile(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);"), html.unescape),
    (ESCAPES, lambda text: ESCAPES.sub(unescape, text)),
    # Quoted-printable leaves ASCII as it is, so only a letter written as UTF-8 bytes ("=C3=96") or a line broken
    # mid-word ("=" at its end) counts: "fiyat=10" isn't.
    (re.compile(r"=[C-F][0-9A-F]=[89AB][0-9A-F]|=\r?\n"),
     lambda text: quopri.decodestring(text.encode("utf-8")).decode("utf-8", "replace")),
]


def unescape(match):
    escape = match.group()
    if escape.startswith("\\x"):  # bytes, as in "\\xc3\\x96"
        return bytes.fromhex(escape.replace("\\x", "")).decode("utf-8", "replace")
    return chr(min(int(escape[2:], 16), 0x10FFFF))


def transliterate(text):
    return TRANSLITERATED.sub(lambda m: TRANSLITERATION_MAP[m.group()], text.lower())


# numbers: a decoded run of digits counts as text, for the answer check, where a TC number in base64 is the leak;
# for instructions it's noise, as most random tokens that decode at all decode to digits and symbols.
def try_decode(decoder, token, numbers=False):
    try:
        value = decoder(token)
        if isinstance(value, bytes):
            value = value.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None

    # Line breaks are text too: a decoded "<|im_start|>system\n..." was thrown away as unprintable.
    letters = sum(c.isalpha() or c.isspace() or (numbers and c.isdigit()) for c in value)
    printable = all(c.isprintable() or c in "\n\r\t" for c in value)
    if value and printable and letters >= MIN_LETTER_SHARE * len(value):
        return value
    return None


def decode_hidden_parts(text, depth=DECODE_DEPTH, numbers=False):
    found = []

    # Undone over the whole text at the first level only: a copy of the text each, and none repeats itself.
    if depth == DECODE_DEPTH:
        for pattern, decoder in WHOLE_TEXT_DECODERS:
            if len(pattern.findall(text)) >= MIN_ESCAPES:
                try:
                    value = decoder(text)
                except (ValueError, UnicodeError):
                    continue
                if value != text:
                    found.append(value)
        if OTHER_ALPHABET.search(text):
            found.append(transliterate(text))

    for pattern, decoder in TOKEN_DECODERS:
        for token in pattern.findall(text):
            value = try_decode(decoder, token, numbers)
            if value and value != token:
                found.append(value)

    if ROT13_HINT.search(text):
        found.append(codecs.decode(text, "rot13"))
    if REVERSED_HINT.search(text):
        found.append(text[::-1])

    if depth > 0:
        for value in list(found):
            found += decode_hidden_parts(value, depth - 1, numbers)
    return found


def are_near(first, second, text):
    second_positions = [m.start() for m in second.finditer(text)]
    for m in first.finditer(text):
        i = bisect.bisect_left(second_positions, m.start() - NEAR_DISTANCE)
        if i < len(second_positions) and second_positions[i] <= m.start() + NEAR_DISTANCE:
            return True
    return False


QUESTION_ABOUT = re.compile(r"\b(?:nedir|ne demek|ne anlama gel\w*|acikla\w*|anlat\w*|what is|what does|explain)\b")
ONLY_A_TOPIC = {"jailbreak_word"}


def comes_before(first, second, text):
    second_positions = [m.start() for m in second.finditer(text)]
    for m in first.finditer(text):
        i = bisect.bisect_right(second_positions, m.start())
        if i < len(second_positions) and second_positions[i] <= m.start() + NEAR_DISTANCE:
            return True
    return False


def find_matches(text):
    matches = []

    if (are_near(RULE_OBJECTS, IGNORE_VERBS_TR, text) or are_near(RULE_OBJECTS, IGNORE_VERBS_ANY_ORDER, text)
            or comes_before(IGNORE_VERBS_EN, RULE_OBJECTS, text)):
        matches.append(("ignore_instructions", 0.9))
    if are_near(SECRET_OBJECTS, REVEAL_VERBS, text):
        matches.append(("reveal_system_prompt", 0.9))
    if are_near(LIMIT_WORDS, RESPONSE_WORDS, text):
        matches.append(("no_limits", 0.5))

    for name, pattern, weight in SINGLE_PATTERNS:
        if pattern.search(text):
            matches.append((name, weight))

    names = {name for name, _ in matches}
    if names and names <= ONLY_A_TOPIC and QUESTION_ABOUT.search(text):
        return []
    return matches


class PromptInjectionLayer:
    name = "prompt_injection_rules"

    def check(self, text):
        hidden = decode_hidden_parts(text)
        texts = [normalize(t) for t in [text] + hidden]

        matches = []
        for t in texts:
            matches += find_matches(t)
        if hidden and matches:
            matches.append(("hidden_encoded", 0.3))

        score = min(1.0, round(sum(weight for _, weight in matches), 6))
        names = sorted({name for name, _ in matches})

        return [Finding(self.name, score, action_for(score, REVIEW_AT, BLOCK_AT), names)]
