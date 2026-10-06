import importlib.util
import logging
import os
import warnings
from pathlib import Path

from sieve.actions import ALLOW, Finding, action_for
from sieve.checks.prompt_injection import decode_hidden_parts, normalize
from sieve.paths import MODELS

MODEL_PATH = MODELS / "prompt_injection_tr.joblib"
DEFAULT_REVIEW_AT = 0.5
BLOCK_AT = 1.01  # ML alone never blocks
EMBEDDING_MODEL = "dbmdz/bert-base-turkish-cased"

logger = logging.getLogger("sieve")


def unavailable_reason(path=MODEL_PATH):
    if not Path(path).exists():
        return f"no model file at {path}"
    if importlib.util.find_spec("sklearn") is None:
        return "scikit-learn isn't installed"
    return None


# Running on without the main detector for attacks in the user's own words used to be silent (TH-15).
def warn_without_ml():
    logger.warning("running without prompt_injection_ml: %s", unavailable_reason() or "not available")


def prepare(text):
    parts = [text] + decode_hidden_parts(text)
    return "\n".join(normalize(p) for p in parts)


# Transformer tokenizers want natural text, so no ASCII folding; decoded hidden parts are appended.
def with_hidden(text):
    return "\n".join([text] + decode_hidden_parts(text))


def best_device():
    import torch

    return "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"


# Second stage: a Turkish BERT sentence vector with a linear classifier on top. The encoder
# loads on first use, so a guardrail that never meets an unsure message never pays for it.
class EmbeddingStage:
    def __init__(self, classifier=None, encoder_name=EMBEDDING_MODEL, prefix="", cache=False):
        self.classifier = classifier
        self.encoder_name = encoder_name
        self.prefix = prefix
        self.cache = {} if cache else None
        self._encoder = None

    @staticmethod
    def is_available():
        return importlib.util.find_spec("sentence_transformers") is not None

    def encoder(self):
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer

            self._encoder = SentenceTransformer(self.encoder_name, device=best_device())
        return self._encoder

    def embed(self, texts):
        import numpy as np

        if self.cache is None:
            return self.encoder().encode([self.prefix + with_hidden(t) for t in texts], normalize_embeddings=True,
                                         show_progress_bar=False)
        missing = [t for t in dict.fromkeys(texts) if t not in self.cache]
        if missing:
            vectors = self.encoder().encode([self.prefix + with_hidden(t) for t in missing], batch_size=64,
                                            normalize_embeddings=True, show_progress_bar=False)
            self.cache.update(zip(missing, vectors))
        return np.stack([self.cache[t] for t in texts])

    def predict(self, texts):
        return self.classifier.predict_proba(self.embed(texts))[:, 1]


# Below `low` the two stages together never flagged a message in cross-validation, above
# `high` they always did: only the messages in between need the slow second stage.
def cascade_decision(p1, low, high, second_stage):
    if p1 < low:
        return p1, False, False
    if p1 > high:
        return p1, True, False
    p = (p1 + second_stage()) / 2
    return p, None, True


def load_bundle(path):
    import joblib
    import sklearn

    bundle = joblib.load(path)
    if not isinstance(bundle, dict):  # old files hold the bare pipeline
        bundle = {"model": bundle, "review_at": DEFAULT_REVIEW_AT, "sklearn_version": None}

    trained_with = bundle.get("sklearn_version")
    if trained_with and trained_with != sklearn.__version__:
        warnings.warn(f"{Path(path).name} was trained with scikit-learn {trained_with}, "
                      f"running {sklearn.__version__}; retrain with train_injection.py")
    return bundle


# shadow=True reports what it would do but always allows.
class MLInjectionLayer:
    name = "prompt_injection_ml"

    # cascade=None: on unless SIEVE_CASCADE=0 (the tests set it).
    def __init__(self, path=MODEL_PATH, review_at=None, block_at=BLOCK_AT, shadow=False, cascade=None):
        bundle = load_bundle(path)
        self.model = bundle["model"]
        self.block_at = block_at
        self.shadow = shadow

        # The cascade needs sentence-transformers; without it, TF-IDF alone with its own threshold.
        if cascade is None:
            cascade = os.environ.get("SIEVE_CASCADE", "1") != "0"
        settings = bundle.get("cascade") if cascade and EmbeddingStage.is_available() else None
        self.cascade = settings
        if settings:
            self.stage = EmbeddingStage(settings["classifier"], settings["encoder"], settings["prefix"])
        default_review_at = settings["review_at"] if settings else bundle["review_at"]
        self.review_at = review_at if review_at is not None else default_review_at

    @staticmethod
    def is_available(path=MODEL_PATH):
        return unavailable_reason(path) is None

    def tfidf_probability(self, text):
        return float(self.model.predict_proba([prepare(text)])[0][1])

    # (score, action, which model answered)
    def decide(self, text):
        p1 = self.tfidf_probability(text)
        if not self.cascade:
            return p1, action_for(p1, self.review_at, self.block_at), "tfidf"

        c = self.cascade
        p, flagged, used_second = cascade_decision(p1, c["low"], c["high"], lambda: float(self.stage.predict([text])[0]))
        if flagged is None:
            action = action_for(p, self.review_at, self.block_at)
        else:
            action = action_for(max(p, self.review_at) if flagged else 0.0, self.review_at, self.block_at)
        return p, action, "tfidf+bert" if used_second else "tfidf"

    def probability(self, text):
        return self.decide(text)[0]

    def check(self, text):
        p, action, level = self.decide(text)

        if self.shadow:
            return [Finding(self.name, p, ALLOW, [f"would_{action}"], level=level, shadow=True)]
        return [Finding(self.name, p, action, level=level)]
