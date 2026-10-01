LEETSPEAK = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}
NO_TURKISH_CHARS = str.maketrans("ıİşŞğĞüÜöÖçÇ", "iIsSgGuUoOcC")
VOWELS = "aeıioöuü"

WRAPPERS = [
    ("Merhaba, ", ""),
    ("", " Teşekkürler."),
    ("Bir sorum var. ", ""),
    ("Kargom nerede? Bu arada ", ""),
    ("", " Cevabını bekliyorum."),
]


def replace_some(text, mapping, rng, rate=0.5):
    return "".join(mapping[c] if c in mapping and rng.random() < rate else c for c in text)


def leetspeak(text, rng):
    return replace_some(text, LEETSPEAK, rng)


def homoglyphs(text, rng):
    return replace_some(text, CYRILLIC, rng)


def no_turkish_chars(text, rng):
    return text.translate(NO_TURKISH_CHARS)


def spaced_word(text, rng):
    words = text.split()
    i = rng.randrange(len(words))
    words[i] = " ".join(words[i])
    return " ".join(words)


def stretched(text, rng):
    positions = [i for i, c in enumerate(text) if c in VOWELS]
    if not positions:
        return text
    i = rng.choice(positions)
    return text[:i] + text[i] * rng.randint(3, 6) + text[i + 1:]


def typo(text, rng):
    words = text.split()
    long_words = [i for i, w in enumerate(words) if len(w) > 3]
    if not long_words:
        return text
    i = rng.choice(long_words)
    w = words[i]
    j = rng.randrange(len(w) - 1)
    words[i] = w[:j] + w[j + 1] + w[j] + w[j + 2:]
    return " ".join(words)


def wrapped(text, rng):
    prefix, suffix = rng.choice(WRAPPERS)
    return prefix + text + suffix


def shouting(text, rng):
    return text.upper()


AUGMENTATIONS = [leetspeak, homoglyphs, no_turkish_chars, spaced_word, stretched, typo, wrapped, shouting]


def augment(text, rng, count=3):
    return [f(text, rng) for f in rng.sample(AUGMENTATIONS, count)]
