# The CI security report: a check whose output is missing is "not run", never clean, and a finding fails it.
import json

import pytest

from scripts import security_report


@pytest.fixture
def results(tmp_path, monkeypatch):
    monkeypatch.setattr(security_report, "RESULTS", tmp_path)
    monkeypatch.setattr(security_report, "REPORT", tmp_path / "security_report.md")
    return tmp_path


def write(results, name, data):
    (results / name).write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


CLEAN = {
    "pip_audit.json": {"dependencies": [{"name": "numpy", "version": "2.5.3", "vulns": []}]},
    "bandit.json": {"results": [], "metrics": {"_totals": {"loc": 100, "skipped_tests": 2}}},
    "gitleaks.json": [],
    "fuzz.txt": "patterns that grow faster than the text:\n  0 reported\n",
    "replay.json": {"split": "test", "config": {"cascade": False}, "summary": {"guardrail": {
        "attacks": 10, "flagged": 8, "benign": 5, "false_alarms": 0, "recall": 0.8, "precision": 1.0, "f1": 0.89,
        "ms": {"p95": 1.0}}}},
    "bypass.json": {"summary": {"encoding/base64": {"kept": 9, "lost": 1}}, "lost": {}},
}


def statuses(results):
    return {title: status for title, status, _ in security_report.build()[1]}


def test_nothing_run_is_not_clean(results):
    assert set(statuses(results).values()) == {security_report.MISSING}


def test_every_check_clean_passes(results):
    for name, data in CLEAN.items():
        write(results, name, data)
    assert set(statuses(results).values()) == {security_report.PASS}


@pytest.mark.parametrize("name, data, title", [
    ("pip_audit.json", {"dependencies": [{"name": "jinja2", "version": "3.1.2",
                                          "vulns": [{"id": "GHSA-h5c8-rqwp-cp95", "fix_versions": ["3.1.3"]}]}]},
     "Dependencies (pip-audit)"),
    ("bandit.json", {"results": [{"test_id": "B301", "test_name": "pickle", "issue_severity": "MEDIUM",
                                  "filename": "sieve/x.py", "line_number": 3}],
                     "metrics": {"_totals": {"loc": 100}}}, "Code (bandit)"),
    ("gitleaks.json", [{"RuleID": "github-pat", "File": "x.py", "StartLine": 1, "Commit": "abcdef1234"}],
     "Secrets (gitleaks)"),
    ("fuzz.txt", "patterns that grow faster than the text:\n  1 reported\n", "Slow patterns (fuzzer)"),
])
def test_a_finding_fails_its_check(results, name, data, title):
    for clean_name, clean_data in CLEAN.items():
        write(results, clean_name, clean_data)
    write(results, name, data)
    found = statuses(results)
    assert found[title] == security_report.FAIL
    assert [t for t, s in found.items() if s != security_report.PASS] == [title]
