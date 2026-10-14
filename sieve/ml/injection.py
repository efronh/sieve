import hashlib
import importlib.util
import logging
import math
import os
import warnings
from collections import Counter
from pathlib import Path

from sieve.actions import ALLOW, Finding, action_for
from sieve.checks.prompt_injection import decode_hidden_parts, normalize
from sieve.paths import MODELS

MODEL_PATH = MODELS / "prompt_injection_tr.joblib"
# The shipped model file's SHA-256. joblib.load is pickle: a model file runs code as it loads. So the file is checked
# against this before it's opened, and one that doesn't match isn't opened at all. train_injection.py rewrites it.
MODEL_SHA256 = "7e8ad299b539a70c10d23706fbd3d3a89de79237132aabbc76395d3c8dbe5c93"
DEFAULT_REVIEW_AT = 0.5
BLOCK_AT = 1.01  # ML alone never blocks
EMBEDDING_MODEL = "dbmdz/bert-base-turkish-cased"
# Every Hugging Face model Sieve and its scripts load, pinned to the commit the results were measured with, so a model
# changed or replaced upstream isn't picked up quietly. A name missing here loads unpinned.
REVISIONS = {
    "dbmdz/bert-base-turkish-cased": "b6e1de16c983e0f2c70664591ea3f22810072608",
    "intfloat/multilingual-e5-small": "614241f622f53c4eeff9890bdc4f31cfecc418b3",
    "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2": "e8f8c211226b894fcb81acc59f3b34ba3efd5f42",
    "protectai/deberta-v3-base-prompt-injection-v2": "90c9989b1a342275dd0d1a95aad283c04e075671",
}

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


# What TF-IDF scores, the highest counting: the text with what was decoded from it, as trained, and each decoded part
# on its own. Joined, an instruction behind a long token was scored with the token's letters around it and fell under
# the threshold: 0.84 written plainly, 0.81 as base64.
def readings(text):
    parts = decode_hidden_parts(text)
    return ["\n".join(normalize(p) for p in [text] + parts)] + [normalize(p) for p in parts]


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

            self._encoder = SentenceTransformer(self.encoder_name, device=best_device(),
                                                revision=REVISIONS.get(self.encoder_name))
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


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# sha256: what the file must hash to before it's unpickled; the shipped model's own path checks MODEL_SHA256.
def load_bundle(path, sha256=None):
    import joblib
    import sklearn

    if sha256 is None and Path(path).resolve() == MODEL_PATH.resolve():
        sha256 = MODEL_SHA256
    if sha256 is not None and file_sha256(path) != sha256:
        raise ValueError(f"{Path(path).name} doesn't match its pinned SHA-256, so it isn't loaded: a model file is "
                         "pickle and runs code as it loads. If it was retrained, train_injection.py updates MODEL_SHA256")
    bundle = joblib.load(path)
    if not isinstance(bundle, dict):  # old files hold the bare pipeline
        bundle = {"model": bundle, "review_at": DEFAULT_REVIEW_AT, "sklearn_version": None}

    trained_with = bundle.get("sklearn_version")
    if trained_with and trained_with != sklearn.__version__:
        warnings.warn(f"{Path(path).name} was trained with scikit-learn {trained_with}, "
                      f"running {sklearn.__version__}; retrain with train_injection.py")
    return bundle


# The TF-IDF model is linear: its score is a weighted sum over the n-grams a text has, each vectorizer's part divided
# by that part's length. Summed directly, it's sklearn's predict_proba to within 1e-14 in an eighth of the time;
# most of sklearn's 0.4 ms a call goes to building sparse matrices for one short text.
class LinearScorer:
    def __init__(self, parts, intercept):
        self.parts = parts  # (analyzer, vocabulary, idf, weights, sublinear_tf) per vectorizer, in the union's order
        self.intercept = intercept

    def probability(self, text):
        z = self.intercept
        for analyzer, vocabulary, idf, weights, sublinear in self.parts:
            counts = Counter(i for i in map(vocabulary.get, analyzer(text)) if i is not None)
            dot = norm = 0.0
            for i, count in counts.items():
                value = idf[i] * (1.0 + math.log(count) if sublinear else count)
                norm += value * value
                dot += weights[i] * value
            if norm:
                z += dot / math.sqrt(norm)
        return 1.0 / (1.0 + math.exp(-z)) if z >= 0 else math.exp(z) / (1.0 + math.exp(z))


# A LinearScorer for a TF-IDF + logistic regression pipeline as train_injection.py builds it, or None for any other
# model (it then goes through sklearn).
def linear_scorer(model):
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    if not isinstance(model, Pipeline) or len(model.steps) != 2:
        return None
    features, classifier = model.steps[0][1], model.steps[1][1]
    if isinstance(features, FeatureUnion):
        if features.transformer_weights:
            return None
        vectorizers = [v for _, v in features.transformer_list]
    else:
        vectorizers = [features]
    if not all(isinstance(v, TfidfVectorizer) and v.norm == "l2" and v.use_idf and not v.binary and v.dtype == np.float64
               for v in vectorizers):
        return None
    if (not isinstance(classifier, LogisticRegression) or classifier.coef_.shape != (1, sum(len(v.vocabulary_) for v in vectorizers))
            or list(classifier.classes_) != [0, 1]):
        return None
    coef, parts, start = classifier.coef_[0].tolist(), [], 0
    for v in vectorizers:
        end = start + len(v.vocabulary_)
        parts.append((v.build_analyzer(), v.vocabulary_, v.idf_.tolist(), coef[start:end], v.sublinear_tf))
        start = end
    return LinearScorer(parts, float(classifier.intercept_[0]))


# shadow=True reports what it would do but always allows.
class MLInjectionLayer:
    name = "prompt_injection_ml"
    reads_sentences = True  # pipeline.Guardrail also reads a message's sentences with it

    # cascade=None: on unless SIEVE_CASCADE=0 (the tests set it).
    def __init__(self, path=MODEL_PATH, review_at=None, block_at=BLOCK_AT, shadow=False, cascade=None):
        bundle = load_bundle(path)
        self.model = bundle["model"]
        self.scorer = linear_scorer(self.model)
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
        texts = readings(text)
        if self.scorer is not None:
            return max(self.scorer.probability(t) for t in texts)
        return float(max(self.model.predict_proba(texts)[:, 1]))

    # (score, action, which model answered)
    def decide(self, text):
        p1 = self.tfidf_probability(text)
        if not self.cascade:
            return p1, action_for(p1, self.review_at, self.block_at), "tfidf"

        return self.cascade_action(p1, lambda: float(self.stage.predict([text])[0]))

    # (score, action, which model answered) for a TF-IDF score; second_stage gives BERTurk's when it's needed.
    def cascade_action(self, p1, second_stage):
        c = self.cascade
        p, flagged, used_second = cascade_decision(p1, c["low"], c["high"], second_stage)
        if flagged is None:
            action = action_for(p, self.review_at, self.block_at)
        else:
            action = action_for(max(p, self.review_at) if flagged else 0.0, self.review_at, self.block_at)
        return p, action, "tfidf+bert" if used_second else "tfidf"

    def probability(self, text):
        return self.decide(text)[0]

    def finding(self, p, action, level):
        if self.shadow:
            return Finding(self.name, p, ALLOW, [f"would_{action}"], level=level, shadow=True)
        return Finding(self.name, p, action, level=level)

    def check(self, text):
        return [self.finding(*self.decide(text))]

    # The findings for many texts (a document's parts), as check() gives them one by one, with the second stage run
    # once for all the texts it's needed for: one at a time it took 17-20 ms a text, and a 50,000-character document
    # of unsure sentences 28 seconds. At most limit texts get it (None: all); past that, TF-IDF alone decides them,
    # with the cascade's threshold. Returns (a list of findings per text, how many texts the second stage didn't read).
    def check_many(self, texts, limit=None):
        firsts = [self.tfidf_probability(t) for t in texts]
        if not self.cascade:
            return [[self.finding(p, action_for(p, self.review_at, self.block_at), "tfidf")] for p in firsts], 0

        c = self.cascade
        unsure = [i for i, p in enumerate(firsts) if c["low"] <= p <= c["high"]]
        read = unsure if limit is None else unsure[:limit]
        seconds = dict(zip(read, map(float, self.stage.predict([texts[i] for i in read])))) if read else {}
        unread = set(unsure) - set(seconds)
        results = [[self.finding(p1, action_for(p1, self.review_at, self.block_at), "tfidf") if i in unread
                    else self.finding(*self.cascade_action(p1, lambda: seconds[i]))] for i, p1 in enumerate(firsts)]
        return results, len(unread)
