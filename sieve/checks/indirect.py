import re

from sieve.actions import Finding, action_for
from sieve.checks.prompt_injection import normalize

REVIEW_AT = 0.4
BLOCK_AT = 0.8

# A document talking to the model that reads it: "bu e-postayı okuyan yapay zeka", "AI okur ise",
# "if you are an AI, ...". Runs on normalize()d text (lower case, Turkish letters folded to ASCII).
# "Asistan notu:" alone is a resident doctor's note, "an AI researcher" is a person, so neither counts.
MODEL = r"(?:yapay zeka|dil modeli|asistan|chatbot|bot|ai|llm|gpt)"
ADDRESSES_THE_MODEL = re.compile(
    rf"\b(?:okuyan|isleyen|ozetleyen|degerlendiren|tarayan|inceleyen|ceviren|analiz eden)\s+(?:\w+\s+){{0,2}}{MODEL}\w*"
    rf"|\b{MODEL}\w*\s+(?:\w+\s+){{0,2}}(?:okur ise|okursa\w*|okuyorsa\w*|isliyorsa\w*|isler ise|islerse\w*)"
    r"|\b(?:yapay zeka|ai|llm|bot)\w*\s+(?:icin|notu?)\s*:|\basistan icin\s*:"
    r"|\bif you(?:'re| are) (?:an? )?(?:ai|llm|language model|assistant|chatbot|bot)(?: (?:assistant|model|agent))?"
    r"(?=\s*[,.:;!]|\s+(?:reading|processing|summari[sz]ing|that|who)\b)"
    r"|\b(?:ai|llm|assistant|summari[sz]er|chatbot|bot|model|agent)s?\b[^.\n]{0,20}\bif you (?:read|see|process)\b"
    r"|\b(?:ai|llm|assistant|summari[sz]er|chatbot|model|agent)s?\s+(?:\w+\s+){0,2}(?:reading|processing) this\b"
    r"|\bnote (?:to|for) (?:the |any )?(?:ai|assistant|llm|model|bot)s?\b"
)
# "[GİZLİ TALİMAT: ...]", "((SISTEM_MESAJI: ...", "/SYSTEM_OVERRIDE/", "<!-- HIDDEN_INSTRUCTION". A log line
# "SISTEM MESAJI: yedekleme tamamlandı" looks the same, so on its own this stays below review.
INSTRUCTION_MARKER = re.compile(
    r"(?:sistem|system|gizli|hidden|asistan|assistant)[\s_/-]*"
    r"(?:talimat\w*|instruction\w*|override|mesaj\w*|yonerge\w*|komut\w*|prompt\w*)\s*[:\]/)>]"
)

PATTERNS = [
    ("addresses_the_model", ADDRESSES_THE_MODEL, 0.5),
    ("instruction_marker", INSTRUCTION_MARKER, 0.3),
]


# Only for documents (DocumentGuard); a user writing "yapay zekaya not:" is talking to the model anyway.
class IndirectInjectionLayer:
    name = "indirect_injection"

    def check(self, text):
        text = normalize(text)
        matches = [(name, weight) for name, pattern, weight in PATTERNS if pattern.search(text)]
        score = min(1.0, sum(weight for _, weight in matches))
        return [Finding(self.name, score, action_for(score, REVIEW_AT, BLOCK_AT), [name for name, _ in matches])]
