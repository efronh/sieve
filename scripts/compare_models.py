# Same folds, 1% FPR threshold, obfuscation and TCPI holdout for every detector.
#   python -m scripts.compare_models [tfidf e5 ...]   -> results/compare_models.json
import json
import random
import sys
import time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

from scripts import train_injection as ti
from sieve.ml.augment import augment
from sieve.ml.injection import best_device, prepare, with_hidden
from sieve.paths import RESULTS
from sieve.pipeline import mask

RESULTS_PATH = RESULTS / "compare_models.json"
FALSE_ALARM_TARGETS = (0.01, 0.05)

EMBEDDING_MODELS = {
    "e5": ("intfloat/multilingual-e5-small", "query: "),
    "minilm": ("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2", ""),
    "berturk": ("dbmdz/bert-base-turkish-cased", ""),
}
FINE_TUNED_MODELS = {
    "berturk_ft": "dbmdz/bert-base-turkish-cased",
}
FINE_TUNE = {"epochs": 2, "batch_size": 32, "learning_rate": 3e-5, "max_length": 128, "augment": 1}
# The LLM layer as the guardrail runs it (LLMCheckLayer.from_model): its prompt_injection check
# on masked text. L0 needs no labels; L2 fits AnyJev's closed-form head in every fold.
LLM_MODELS = {
    "qwen1.7b_l0": ("Qwen/Qwen3-1.7B", "L0"),
    "qwen1.7b_l2": ("Qwen/Qwen3-1.7B", "L2"),
    "qwen4b_l0": ("Qwen/Qwen3-4B", "L0"),
    "qwen4b_l2": ("Qwen/Qwen3-4B", "L2"),
}
ZERO_SHOT_MODELS = {
    "deberta_en": ("protectai/deberta-v3-base-prompt-injection-v2", "INJECTION"),
}


class TfidfDetector:
    name = "tfidf"

    def fit(self, rows, rng):
        self.model = ti.fit(ti.build_model(), rows, rng)
        return self

    def predict(self, texts):
        return self.model.predict_proba([prepare(t) for t in texts])[:, 1]


class EmbeddingDetector:
    def __init__(self, key):
        from sentence_transformers import SentenceTransformer

        self.name = key
        model_name, self.prefix = EMBEDDING_MODELS[key]
        self.encoder = SentenceTransformer(model_name, device="mps")
        self.cache = {}

    def embed(self, texts):
        missing = [t for t in dict.fromkeys(texts) if t not in self.cache]
        if missing:
            vectors = self.encoder.encode([self.prefix + with_hidden(t) for t in missing], batch_size=64,
                                          normalize_embeddings=True, show_progress_bar=False)
            self.cache.update(zip(missing, vectors))
        return np.stack([self.cache[t] for t in texts])

    def fit(self, rows, rng):
        texts, labels = [], []
        for row in rows:
            for text in [row.text] + augment(row.text, rng, ti.AUGMENT_COUNT):
                texts.append(text)
                labels.append(row.label)
        self.model = LogisticRegression(class_weight="balanced", C=10.0, max_iter=5000)
        self.model.fit(self.embed(texts), labels)
        return self

    def predict(self, texts):
        return self.model.predict_proba(self.embed(texts))[:, 1]


# The whole transformer trained on our data (not just a classifier on a frozen vector).
# Attacks are the rarer class, so the loss weighs them up.
class FineTunedDetector:
    def __init__(self, key):
        from transformers import AutoTokenizer

        self.name = key
        self.model_name = FINE_TUNED_MODELS[key]
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.device = best_device()

    def batches(self, texts, labels=None, shuffle_rng=None):
        order = list(range(len(texts)))
        if shuffle_rng:
            shuffle_rng.shuffle(order)
        for start in range(0, len(order), FINE_TUNE["batch_size"]):
            idx = order[start:start + FINE_TUNE["batch_size"]]
            enc = self.tokenizer([with_hidden(texts[i]) for i in idx], padding=True, truncation=True,
                                 max_length=FINE_TUNE["max_length"], return_tensors="pt").to(self.device)
            yield enc, None if labels is None else [labels[i] for i in idx]

    def fit(self, rows, rng):
        import torch
        from transformers import AutoModelForSequenceClassification

        torch.manual_seed(ti.SEED)
        texts, labels = [], []
        for row in rows:
            for text in [row.text] + augment(row.text, rng, FINE_TUNE["augment"]):
                texts.append(text)
                labels.append(row.label)

        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2).to(self.device)
        attacks = sum(labels)
        weights = torch.tensor([len(labels) / (2 * (len(labels) - attacks)), len(labels) / (2 * attacks)],
                               dtype=torch.float32, device=self.device)
        loss_fn = torch.nn.CrossEntropyLoss(weight=weights)
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=FINE_TUNE["learning_rate"])

        self.model.train()
        for _ in range(FINE_TUNE["epochs"]):
            for enc, y in self.batches(texts, labels, random.Random(ti.SEED)):
                loss = loss_fn(self.model(**enc).logits, torch.tensor(y, device=self.device))
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
        self.model.eval()
        return self

    def predict(self, texts):
        import torch

        out = []
        with torch.no_grad():
            for enc, _ in self.batches(list(texts)):
                out.append(torch.softmax(self.model(**enc).logits, dim=-1)[:, 1].float().cpu().numpy())
        return np.concatenate(out)


_llm_layers = {}


class LLMDetector:
    def __init__(self, key):
        from sieve.llm.layer import LLMCheckLayer

        self.name = key
        model_name, self.level = LLM_MODELS[key]
        if model_name not in _llm_layers:
            _llm_layers[model_name] = LLMCheckLayer.from_model(model_name, device=best_device(), artifacts=None)
        self.decider = _llm_layers[model_name].decider
        self.question = _llm_layers[model_name].questions["prompt_injection"]
        n_blocks = int(self.decider.backend.n_layers)
        self.blocks = sorted({max(1, round(f * n_blocks)) for f in (0.5, 0.6, 0.7, 0.85, 1.0)})  # AnyJev's default
        self.cache = {}

    # Hidden states at the candidate blocks, once per masked text: every fold reuses them.
    def features(self, texts):
        masked = [mask(t) for t in texts]
        missing = [t for t in dict.fromkeys(masked) if t not in self.cache]
        for start in range(0, len(missing), 256):
            chunk = missing[start:start + 256]
            self.cache.update(zip(chunk, self.decider._features(self.question, chunk, self.blocks)))
        return np.stack([self.cache[t] for t in masked])

    def fit(self, rows, rng):
        if self.level == "L0":
            return self
        from anyjev.heads import fit_head

        features = self.features([r.text for r in rows])
        labels = [0 if r.label else 1 for r in rows]  # option 0 is the violation
        heads = []
        for kind in ("lda", "ridge"):
            try:
                heads.append(fit_head(features, labels, 2, kind=kind))
            except (ValueError, np.linalg.LinAlgError):
                continue
        self.head = min(heads, key=lambda h: h.cv["oof_nll"])
        return self

    def predict(self, texts):
        if self.level == "L2":
            features = self.features(texts)
            return self.head.probs(features[:, self.head.layer, :])[:, 0]
        decisions = self.decider.decide_batch([mask(t) for t in texts], self.question, level="L0")
        return np.array([d.distribution[self.question.options[0]] for d in decisions])


# An off-the-shelf English detector, used as is: nothing to fit.
class ZeroShotDetector:
    def __init__(self, key):
        from transformers import pipeline

        self.name = key
        model_name, self.positive = ZERO_SHOT_MODELS[key]
        self.pipe = pipeline("text-classification", model=model_name, device="mps", truncation=True, max_length=512)

    def fit(self, rows, rng):
        return self

    def predict(self, texts):
        out = self.pipe(list(texts), batch_size=32, top_k=None)
        return np.array([next(s["score"] for s in scores if s["label"] == self.positive) for scores in out])


def make_detector(key):
    if key == "tfidf":
        return TfidfDetector()
    if key in EMBEDDING_MODELS:
        return EmbeddingDetector(key)
    if key in FINE_TUNED_MODELS:
        return FineTunedDetector(key)
    if key in LLM_MODELS:
        return LLMDetector(key)
    return ZeroShotDetector(key)


# Out-of-fold probabilities for every row, plus each attack after obfuscation tricks
# (only attacks: the tricked score is a catch rate).
def out_of_fold(detector, rows):
    rng = random.Random(ti.SEED)
    splitter = StratifiedGroupKFold(n_splits=ti.FOLDS, shuffle=True, random_state=ti.SEED)
    clean = np.zeros(len(rows))
    tricked = np.zeros((len(rows), ti.AUGMENT_COUNT))

    for train_idx, test_idx in splitter.split(rows, [r.label for r in rows], [r.family for r in rows]):
        detector.fit([rows[i] for i in train_idx], rng)
        clean[test_idx] = detector.predict([rows[i].text for i in test_idx])
        attacks = [i for i in test_idx if rows[i].label == 1]
        variants = [v for i in attacks for v in augment(rows[i].text, random.Random(ti.SEED + int(i)), ti.AUGMENT_COUNT)]
        if attacks:
            tricked[attacks] = detector.predict(variants).reshape(len(attacks), ti.AUGMENT_COUNT)
    return clean, tricked


def threshold_for(scores, labels, target):
    normals = np.sort(scores[labels == 0])[::-1]
    return float(min(1.0, normals[int(target * len(normals))] + 1e-6))


def rates(scores, labels, threshold):
    flagged = scores >= threshold
    return float(flagged[labels == 1].mean()), float(flagged[labels == 0].mean())


def evaluate(key, clean, tricked, labels, holdout_scores, holdout_labels, latency_ms):
    summary = {
        "roc_auc": float(roc_auc_score(labels, clean)),
        "pr_auc": float(average_precision_score(labels, clean)),
        "latency_ms": latency_ms,
    }
    for target in FALSE_ALARM_TARGETS:
        threshold = threshold_for(clean, labels, target)
        recall, false_alarm = rates(clean, labels, threshold)
        tricked_recall = float((tricked[labels == 1] >= threshold).mean())
        entry = {"threshold": threshold, "recall": recall, "false_alarm": false_alarm, "tricked_recall": tricked_recall}
        if holdout_scores is not None:
            entry["holdout_recall"], entry["holdout_false_alarm"] = rates(holdout_scores, holdout_labels, threshold)
        summary[f"at_{int(target * 100)}pct"] = entry
    return summary


def print_table(results):
    print(f"\n{'detector':12} {'ROC-AUC':>8} {'PR-AUC':>7} | {'@1% FA: recall':>15} {'tricked':>8} {'holdout R/FA':>13} "
          f"| {'@5% FA: recall':>15} {'holdout R/FA':>13} | {'ms/msg':>7}")
    for key, s in results.items():
        a, b = s["at_1pct"], s["at_5pct"]
        hold_a = f"{a.get('holdout_recall', 0):.0%}/{a.get('holdout_false_alarm', 0):.0%}"
        hold_b = f"{b.get('holdout_recall', 0):.0%}/{b.get('holdout_false_alarm', 0):.0%}"
        print(f"{key:12} {s['roc_auc']:8.3f} {s['pr_auc']:7.3f} | {a['recall']:15.0%} {a['tricked_recall']:8.0%} {hold_a:>13} "
              f"| {b['recall']:15.0%} {hold_b:>13} | {s['latency_ms']:7.1f}")


def main(keys):
    rows = ti.load_rows()
    holdout = ti.load_rows(ti.HOLDOUT_PATHS)
    labels = np.array([r.label for r in rows])
    holdout_labels = np.array([r.label for r in holdout])
    print(f"{len(rows)} rows ({labels.sum()} attacks), holdout {len(holdout)} rows ({holdout_labels.sum()} attacks)")

    results = json.loads(RESULTS_PATH.read_text()) if RESULTS_PATH.exists() else {}
    oof = {}
    for key in keys:
        start = time.time()
        detector = make_detector(key)
        clean, tricked = out_of_fold(detector, rows)
        detector.fit(rows, random.Random(ti.SEED))
        holdout_scores = detector.predict([r.text for r in holdout]) if holdout else None

        # One message at a time, as in production; new texts so no embedding cache hits.
        t = time.perf_counter()
        for i, row in enumerate(rows[:50]):
            detector.predict([f"{row.text} ({i})"])
        latency_ms = (time.perf_counter() - t) / 50 * 1000

        results[key] = evaluate(key, clean, tricked, labels, holdout_scores, holdout_labels, latency_ms)
        oof[key] = (clean, tricked, holdout_scores)
        print(f"{key}: done in {time.time() - start:.0f} s")

    # Averaging two detectors that make different mistakes is often better than either.
    for first, second in [("tfidf", k) for k in keys if k != "tfidf" and "tfidf" in oof]:
        c1, t1, h1 = oof[first]
        c2, t2, h2 = oof[second]
        holdout_scores = (h1 + h2) / 2 if h1 is not None else None
        results[f"{first}+{second}"] = evaluate(None, (c1 + c2) / 2, (t1 + t2) / 2, labels, holdout_scores, holdout_labels,
                                                 results[first]["latency_ms"] + results[second]["latency_ms"])

    RESULTS_PATH.parent.mkdir(exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=1))
    print_table(results)


if __name__ == "__main__":
    main(sys.argv[1:] or ["tfidf", *EMBEDDING_MODELS, *ZERO_SHOT_MODELS])
