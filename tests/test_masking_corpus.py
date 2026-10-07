import json

import pytest

from scripts import evaluate_masking
from scripts.evaluate_masking import BASELINE, check_baseline, evaluate, load, record_problems

RECORD = {"id": "PII-TC-900", "kind": "TC", "language": "tr", "source": "test", "split": "test",
          "text": "TC 10000001518", "pii": [{"value": "10000001518", "label": "[TC_KIMLIK]"}], "keep": []}


@pytest.fixture(scope="module")
def records():
    return load()


@pytest.fixture(scope="module")
def results(records):
    return evaluate(records)


@pytest.mark.parametrize("change, problem", [
    ({"kind": "PHONE"}, "unknown kind"),
    ({"id": "PII-IBAN-900"}, "doesn't name its kind"),
    ({"pii": [{"value": "10000001518", "label": "[TC]"}]}, "unknown label"),
    ({"pii": [{"value": "10000001519", "label": "[TC_KIMLIK]"}]}, "isn't in the text"),
    ({"keep": ["0599"]}, "isn't in the text"),
    ({"pii": []}, "benign records have no pii"),
    ({"extra": 1}, "unknown key"),
])
def test_a_typo_in_a_record_is_reported(change, problem):
    assert any(problem in p for p in record_problems(dict(RECORD, **change)))


def test_the_corpus_loads_and_counts_both_ways_to_the_model(records, results):
    assert len(records) > 100 and set(results) == {"message", "document"}
    assert len(results["message"]) == len(results["document"])


# Masking is deterministic: a value masked (or a number left alone) in the committed baseline must stay so.
def test_nothing_masked_in_the_baseline_is_missed_now(results):
    problems, _ = check_baseline(results, json.loads(BASELINE.read_text(encoding="utf-8")))
    assert not problems, "\n".join(problems)


def test_half_masked_doesnt_count(monkeypatch):
    # A window across a phone number and a card took half of each: neither appears whole, and neither is masked.
    record = dict(RECORD, kind="KART", id="PII-KART-900", text="Tel: 0599 312 34 56 4111 1157 9906 5937",
                  pii=[{"value": "4111 1157 9906 5937", "label": "[KART]"}])
    monkeypatch.setattr(evaluate_masking, "views",
                        lambda: {"message": lambda record, i: "Tel: 0599 312 34 5[KART]6 5937"})
    row = evaluate_masking.evaluate([record])["message"][0]
    assert not row["ok"] and row["partly"]
