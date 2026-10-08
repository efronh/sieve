import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from sieve.actions import Finding, action_for
from sieve.masking import LABEL_NAMES

REVIEW_AT = 0.5
BLOCK_AT = 0.9
MAX_SUBDOMAINS = 4

# A "]" ends a URL ("[link http://a.example]"), except the one closing a bracketed host: "https://[2001:db8::1]/".
BRACKETED_HOST = r"(?:https?|ftp)://(?:[^\s<>\"'()\[\]/?#@]*@)?\[[^\s<>\"'()\[\]/?#]*\][^\s<>\"')\]]*"
URL = re.compile(r"\b(?:" + BRACKETED_HOST + r"|(?:https?|ftp)://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+)", re.IGNORECASE)
DANGEROUS_SCHEME = re.compile(r"\b(?:javascript|vbscript)\s*:|\bdata:(?:text/html|[^;,\s]*;base64)", re.IGNORECASE)
PUNYCODE = re.compile(r"(?:^|\.)xn--", re.IGNORECASE)
MASK_LABEL = re.compile(r"\[(" + "|".join(LABEL_NAMES) + r")(?:_[A-Z]+)?\]")  # plain or lettered (vault.py)

TRUSTED_BRANDS = ["google", "microsoft", "apple", "paypal", "turkiye", "edevlet", "garanti", "ziraat", "akbank", "isbank"]
# Official sites whose name contains a brand but isn't the bare brand.
OFFICIAL_NAMES = {"googleapis", "googleusercontent", "microsoftonline", "garantibbva", "ziraatbank", "akbanksanat"}
# "garanti.com.tr": the site name is the label before a two-part suffix like com.tr.
SECOND_LEVEL = {"com", "net", "org", "gov", "edu", "ac", "co", "bel", "k12", "gen", "biz", "info", "av", "tv", "web"}
LOOKALIKE_DIGITS = str.maketrans("0135", "oles")


# (parts, host, malformed). urlsplit raises on a host it can't read: "http://[ornekbank" (no "]"), "http://[ornekbank]"
# (no IP address in the brackets), or a full-width "／" or "＠" in it. Such a host is read without its brackets and
# after NFKC, so the other checks still see it, and it's malformed.
def host_of(url):
    if not url.lower().startswith(("http", "ftp")):
        url = "http://" + url
    try:
        parts, malformed = urlsplit(url), False
    except ValueError:
        parts, malformed = urlsplit(unicodedata.normalize("NFKC", url).replace("[", "").replace("]", "")), True
    return parts, (parts.hostname or ""), malformed


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def one_edit_apart(a, b):
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long = sorted((a, b), key=len)
    return any(long[:i] + long[i + 1:] == short for i in range(len(long)))


def site_name(host):
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else host


# Matches "paypa1-guvenlik", "e-devlet-giris", "googie"; not "pineapple".
def brand_lookalike(host):
    name = site_name(host)
    if name in TRUSTED_BRANDS or name in OFFICIAL_NAMES:
        return False

    parts = name.translate(LOOKALIKE_DIGITS).split("-")
    joined = ["".join(parts[i:]) for i in range(len(parts))]
    if any(j.startswith(brand) for j in joined for brand in TRUSTED_BRANDS):
        return True
    return any(one_edit_apart(part, brand) for part in parts for brand in TRUSTED_BRANDS if len(brand) >= 5)


def check_url(url):
    matches = []
    parts, host, malformed = host_of(url)

    # Scored like a raw IP: browsers refuse such a host, but a more lenient parser may read it as something else.
    if malformed:
        matches.append(("malformed_host", 0.5))
    if parts.username or "@" in parts.netloc:
        matches.append(("credentials_in_url", 0.6))
    if is_ip(host):
        matches.append(("ip_address_host", 0.5))
    if PUNYCODE.search(host):
        matches.append(("punycode_host", 0.5))
    if host.count(".") > MAX_SUBDOMAINS:
        matches.append(("many_subdomains", 0.3))
    if brand_lookalike(host):
        matches.append(("brand_lookalike", 0.5))
    return matches


class URLCheckLayer:
    name = "url_check"

    def __init__(self, allowed_hosts=()):
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    def check(self, text):
        matches = []

        if DANGEROUS_SCHEME.search(text):
            matches.append(("dangerous_scheme", 0.9))

        # A session's history is checked masked: "http://[EPOSTA]" is the address masking replaced, not a malformed
        # host, and the address itself was checked when its message came in.
        for url in URL.findall(MASK_LABEL.sub(r"\1", text)):
            _, host, malformed = host_of(url)
            if host.lower() in self.allowed_hosts and not malformed:
                continue
            matches += check_url(url)

        unique = dict(matches)
        score = min(1.0, sum(unique.values()))
        return [Finding(self.name, score, action_for(score, REVIEW_AT, BLOCK_AT), sorted(unique))]
