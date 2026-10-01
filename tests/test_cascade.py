import joblib
import numpy as np
import pytest

from sieve.ml.injection import MLInjectionLayer, cascade_decision, prepare

pytest.importorskip("sentence_transformers")

LOW, HIGH, REVIEW_AT = 0.2, 0.8, 0.6
TFIDF = {"merhaba": 0.05, "belki": 0.5, "belki değil": 0.5, "saldırı": 0.95}


# Module-level so joblib can pickle them.
class FixedTfidf:
    def __init__(self, scores):
        self.scores = scores

    def predict_proba(self, texts):
        p = self.scores.get(texts[0], 0.0)
        return np.array([[1 - p, p]])


@pytest.fixture
def build(tmp_path):
    def build(second_scores, tfidf_scores=TFIDF, cascade=True):
        path = tmp_path / "model.joblib"
        joblib.dump({
            "model": FixedTfidf({prepare(k): v for k, v in tfidf_scores.items()}),
            "review_at": 0.9,
            "sklearn_version": None,
            "cascade": {"encoder": "unused", "prefix": "", "classifier": None, "low": LOW, "high": HIGH, "review_at": REVIEW_AT},
        }, path)
        layer = MLInjectionLayer(path, cascade=cascade)
        calls = []
        if layer.cascade:
            layer.stage.predict = lambda texts: calls.append(texts[0]) or np.array([second_scores.get(texts[0], 0.0)])
        return layer, calls
    return build


@pytest.fixture
def second():
    asked = []
    return asked, lambda: asked.append(1) or 0.9


def test_below_low_is_allowed_without_second_stage(second):
    asked, stage = second
    assert cascade_decision(0.1, LOW, HIGH, stage) == (0.1, False, False) and not asked


def test_above_high_is_flagged_without_second_stage(second):
    asked, stage = second
    assert cascade_decision(0.95, LOW, HIGH, stage) == (0.95, True, False) and not asked


def test_in_between_averages_the_two_scores(second):
    asked, stage = second
    p, flagged, used = cascade_decision(0.5, LOW, HIGH, stage)
    assert abs(p - 0.7) < 1e-9 and flagged is None and used and asked


@pytest.fixture
def results(build):
    layer, calls = build({"belki": 0.9, "belki değil": 0.1})
    return {text: layer.check(text)[0] for text in TFIDF}, calls


def test_clean_message_uses_tfidf_only(results):
    r = results[0]["merhaba"]
    assert r.action == "allow" and r.level == "tfidf"


def test_unsure_message_confirmed_by_second_stage_is_reviewed(results):
    r = results[0]["belki"]
    assert r.action == "review" and r.level == "tfidf+bert"


def test_unsure_message_cleared_by_second_stage_is_allowed(results):
    assert results[0]["belki değil"].action == "allow"


def test_clear_attack_is_reviewed_without_second_stage(results):
    r = results[0]["saldırı"]
    assert r.action == "review" and r.level == "tfidf"


def test_second_stage_runs_only_for_unsure_messages(results):
    assert sorted(results[1]) == ["belki", "belki değil"]


def test_ml_alone_never_blocks(results):
    assert all(f.action != "block" for f in results[0].values())


def test_cascade_off_uses_tfidf_with_its_own_threshold(build):
    layer, calls = build({}, cascade=False)
    assert layer.review_at == 0.9
    assert layer.check("saldırı")[0].action == "review"
    assert layer.check("belki")[0].action == "allow"
    assert not calls


def test_shadow_mode_keeps_the_would_be_action(build):
    layer, _ = build({"belki": 0.9})
    layer.shadow = True
    finding = layer.check("belki")[0]
    assert finding.action == "allow" and finding.matches == ["would_review"]
