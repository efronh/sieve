import csv

import test_deterministic_checks
import test_documents
import test_output_guard
import test_prompt_injection
import test_tools

from sieve.documents import DocumentGuard
from sieve.integrations.siem import fired
from sieve.output import OutputGuard
from sieve.paths import DATA
from sieve.pipeline import Guardrail
from sieve.rules import RULES, rule_ids
from sieve.tools import ToolGuard


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


def test_every_output_tool_and_document_rule_is_catalogued():
    out = OutputGuard(test_output_guard.SYSTEM, allowed_hosts=["ornekbank.com.tr"])
    findings = []
    for answer, *_ in test_output_guard.cases(out.canary).values():
        findings += out.check(answer, user_data=[test_output_guard.USER]).findings
    tools = ToolGuard(test_tools.TOOLS, allowed_hosts=["ornekbank.com.tr"])
    for name, args, *_ in test_tools.CALLS:
        findings += tools.check(name, args, user_data=[test_tools.USER]).findings
    docs = DocumentGuard()
    for document, *_ in test_documents.DOCUMENTS:
        findings += docs.check(document).findings

    seen = {rule_id for f in filter(fired, findings) for rule_id, _ in rule_ids(f)}
    assert seen - set(RULES) == set(), "rule IDs not in rules.py"
    assert {"output_links.dangerous_html", "tool_call.unknown_tool", "indirect_injection.hidden_instruction"} <= seen
