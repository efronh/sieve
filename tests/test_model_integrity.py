import pickle
import shutil

import pytest

import sieve.ml.injection as injection
from scripts import compare_families, compare_models
from scripts.train_injection import pin_model_hash
from sieve.ml.injection import EMBEDDING_MODEL, MODEL_PATH, MODEL_SHA256, REVISIONS, MLInjectionLayer, file_sha256, load_bundle
from sieve.pipeline import Guardrail


def test_the_pinned_hash_is_the_shipped_models():
    assert file_sha256(MODEL_PATH) == MODEL_SHA256


class Planted:  # what a swapped model file could hold: code that runs as it's unpickled
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (open, (str(self.marker), "w"))


def test_a_file_that_doesnt_match_is_never_unpickled(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    planted = tmp_path / "prompt_injection_tr.joblib"
    planted.write_bytes(pickle.dumps(Planted(marker)))
    monkeypatch.setattr("joblib.load", lambda *a, **k: pytest.fail("unpickled a file that didn't match"))
    with pytest.raises(ValueError, match="pinned SHA-256"):
        load_bundle(planted, sha256=MODEL_SHA256)
    assert not marker.exists()


def test_the_shipped_path_is_always_checked(monkeypatch, tmp_path):
    changed = tmp_path / "copy.joblib"
    shutil.copy(MODEL_PATH, changed)
    with open(changed, "ab") as f:
        f.write(b"\0")
    monkeypatch.setattr(injection, "MODEL_PATH", changed)  # the shipped path, now holding a changed file
    with pytest.raises(ValueError, match="pinned SHA-256"):
        MLInjectionLayer(path=changed)


def test_a_changed_model_stops_the_guardrail_instead_of_running_without_it(monkeypatch):
    monkeypatch.setattr(injection, "MODEL_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="pinned SHA-256"):
        Guardrail()


def test_every_hugging_face_model_loaded_is_pinned():
    names = {EMBEDDING_MODEL, compare_families.BASELINE}
    names |= {name for name, _ in compare_models.EMBEDDING_MODELS.values()}
    names |= set(compare_models.FINE_TUNED_MODELS.values())
    names |= {name for name, _ in compare_models.ZERO_SHOT_MODELS.values()}
    assert names <= set(REVISIONS) and all(len(rev) == 40 for rev in REVISIONS.values())


def test_retraining_rewrites_the_pinned_hash_and_nothing_else(tmp_path):
    source = tmp_path / "injection.py"
    source.write_text(open(injection.__file__, encoding="utf-8").read(), encoding="utf-8")
    model = tmp_path / "model.joblib"
    model.write_bytes(b"a new model")
    digest = pin_model_hash(model, source)
    before = open(injection.__file__, encoding="utf-8").read().splitlines()
    after = source.read_text(encoding="utf-8").splitlines()
    assert [(a, b) for a, b in zip(before, after) if a != b] == [(f'MODEL_SHA256 = "{MODEL_SHA256}"', f'MODEL_SHA256 = "{digest}"')]
