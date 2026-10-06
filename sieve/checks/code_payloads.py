import re

from sieve.actions import Finding, action_for
from sieve.checks.prompt_injection import decode_hidden_parts

REVIEW_AT = 0.5
BLOCK_AT = 0.9

# {{ ... config ... }}: a keyword after a "{{" with no "}" between them, closed by "}}". Read stretch by
# stretch between "}"s; the pattern it replaces rescanned the rest of the text from every "{{".
class TemplateInjection:
    KEYWORD = re.compile(r"__class__|config|self|request", re.IGNORECASE)
    JNDI = re.compile(r"\$\{jndi:", re.IGNORECASE)
    STRETCH = re.compile(r"[^}]+")

    def search(self, text):
        for stretch in self.STRETCH.finditer(text):
            opening = text.find("{{", stretch.start(), stretch.end())
            if (opening >= 0 and self.KEYWORD.search(text, opening + 2, stretch.end())
                    and text.startswith("}}", stretch.end())):
                return True
        return self.JNDI.search(text) is not None


# Only searched for, never extracted, so each pattern starts at the last place it could: \w rather than \w+
# before a quote, the curl nearest the pipe. Starting earlier rescanned the same run from every start, and an
# 8,000-character argument of one letter took seconds (TH-11).
SIGNATURES = [
    ("sql_tautology", re.compile(r"['\"]\s*\)?\s*(?:or|and)\s+\(?\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.IGNORECASE), 0.6),
    # admin'-- cuts the rest of the query, so the comment ends the line; "'Kahve' -- fiyatı?" and "#hashtag" don't.
    ("sql_comment_bypass", re.compile(r"\w['\"]\s*(?:--|#|/\*)\s*$", re.MULTILINE), 0.6),
    ("sql_union_select", re.compile(r"(?:['\")]|\b\d+)\s*union\s+(?:all\s+)?select\b", re.IGNORECASE), 0.6),
    ("sql_stacked_query", re.compile(r";\s*(?:drop|delete|truncate|insert|update|exec|shutdown)\b", re.IGNORECASE), 0.6),
    ("sql_time_delay", re.compile(r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\d|\bwaitfor\s+delay\b", re.IGNORECASE), 0.6),
    ("shell_destroy", re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+(?:/|~|\*)", re.IGNORECASE), 0.6),
    ("shell_pipe_to_shell", re.compile(r"\b(?:curl|wget)\b(?:(?!\b(?:curl|wget)\b)[^\n|])*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"), 0.6),
    ("shell_chained_command", re.compile(r"(?:;|&&|\|\||\$\(|`)\s*(?:cat|curl|wget|nc|bash|sh|whoami|id)\b"), 0.5),
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f){2,}", re.IGNORECASE), 0.6),
    ("sensitive_file", re.compile(r"/etc/(?:passwd|shadow)\b|\bc:\\windows\\system32\b|\.ssh/id_rsa\b|\.env\b", re.IGNORECASE), 0.4),
    ("script_tag", re.compile(r"<\s*script\b|\bon(?:error|load|click|mouseover)\s*=|javascript\s*:", re.IGNORECASE), 0.6),
    ("template_injection", TemplateInjection(), 0.6),
]


def find_signatures(text):
    return [(name, weight) for name, pattern, weight in SIGNATURES if pattern.search(text)]


# One signature sends to review, two different ones in the same message block.
class CodePayloadLayer:
    name = "code_payloads"

    def check(self, text):
        matches = []
        for part in [text] + decode_hidden_parts(text):
            matches += find_signatures(part)

        unique = dict(matches)
        score = min(1.0, sum(unique.values()))
        return [Finding(self.name, score, action_for(score, REVIEW_AT, BLOCK_AT), sorted(unique))]
