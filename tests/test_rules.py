import csv

import test_deterministic_checks
import test_prompt_injection

from sieve.integrations.siem import fired
from sieve.paths import DATA
from sieve.pipeline import Guardrail
from sieve.rules import RULES, rule_ids


def all_texts():
    texts = []
    for path in sorted(DATA.glob("*.csv")):
        with open(path, encoding="utf-8") as f:
            texts += [row["text"] for row in csv.DictReader(f) if row.get("text")]
    texts += test_prompt_injection.SHOULD_BLOCK + test_prompt_injection.SHOULD_REVIEW_OR_BLOCK
    for groups in test_deterministic_checks.CASES.values():
        for group in groups.values():
            texts += group
    return texts


def test_every_fired_rule_is_catalogued():
    guard = Guardrail()
    seen = {}
    for text in all_texts():
        for finding in filter(fired, guard.check(text).findings):
            for rule_id, _ in rule_ids(finding):
                seen.setdefault(rule_id, text)

    missing = {rule_id: text[:60] for rule_id, text in seen.items() if rule_id not in RULES}
    assert not missing, f"rule IDs not in rules.py (with an example text): {missing}"
