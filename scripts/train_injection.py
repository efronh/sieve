import csv
import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline, make_union

from sieve.ml.augment import augment
from sieve.ml.injection import EMBEDDING_MODEL, MODEL_PATH, EmbeddingStage, prepare
from sieve.pipeline import clean

DATA_PATHS = [
    "data/prompt_injection_tr.csv",
    "data/external_attacks.csv",
    "data/altaysec.csv",
    "data/benign_contrast_tr.csv",
    "data/short_benign_tr.csv",
    "data/tcpi_train.csv",
    "data/customer_service_tr.csv",
    "data/real_labeled.csv",
    "data/my_dataset_tr.csv",
]
# Never trained on: an independent exam written by someone else, plus the real messages set aside by add_labels.py.
HOLDOUT_PATHS = [
    "data/tcpi_test.csv",
    "data/real_holdout.csv",
    "data/my_holdout_tr.csv",
]
TARGET_FALSE_ALARM = 0.01
AUGMENT_COUNT = 3
FOLDS = 5
SEED = 42


@dataclass
class Row:
    text: str
    label: int
    category: str
    family: str
    language: str


def load_rows(paths=DATA_PATHS):
    rows = []
    for path in paths:
        if not Path(path).exists():
            continue
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append(Row(clean(r["text"]), int(r["label"]), r["category"], r["family"], r.get("language", "tr")))
    return rows


def build_model():
    return make_pipeline(
        make_union(
            TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True),
            TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True),
        ),
        LogisticRegression(class_weight="balanced", C=5.0, max_iter=2000),
    )


def fit(model, rows, rng):
    texts, labels = [], []
    for row in rows:
        for text in [row.text] + augment(row.text, rng, AUGMENT_COUNT):
            texts.append(prepare(text))
            labels.append(row.label)
    model.fit(texts, labels)
    return model


def probability(model, text):
    return model.predict_proba([prepare(text)])[0][1]


def cross_validate(rows):
    rng = random.Random(SEED)
    splitter = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    labels = [r.label for r in rows]
    groups = [r.family for r in rows]

    results = []
    for train_idx, test_idx in splitter.split(rows, labels, groups):
        model = fit(build_model(), [rows[i] for i in train_idx], rng)

        for i in test_idx:
            row = rows[i]
            score = probability(model, row.text)
            tricked = [probability(model, t) for t in augment(row.text, rng, AUGMENT_COUNT)]
            results.append((row, score, tricked))

    return results


# Lowest threshold whose out-of-fold false alarm rate stays within target.
def choose_threshold(results, target=TARGET_FALSE_ALARM):
    normals = sorted((p for r, p, _ in results if r.label == 0), reverse=True)
    allowed = int(target * len(normals))
    return float(min(1.0, normals[allowed] + 1e-6))


def report(results, review_at):
    by_category = defaultdict(lambda: {"count": 0, "flagged": 0, "tricked": 0, "tricked_flagged": 0})

    for row, score, tricked in results:
        stats = by_category[row.category]
        stats["count"] += 1
        stats["flagged"] += score >= review_at
        stats["tricked"] += len(tricked)
        stats["tricked_flagged"] += sum(p >= review_at for p in tricked)

    print(f"\nCross-validation ({FOLDS} folds, families never split), threshold {review_at:.2f}\n")
    print(f"{'category':22} {'label':>5} {'count':>6} {'flagged':>9} {'flagged (tricked)':>18}")

    for category, s in sorted(by_category.items()):
        label = next(r.label for r, _, _ in results if r.category == category)
        flagged = s["flagged"] / s["count"]
        tricked = s["tricked_flagged"] / s["tricked"]
        print(f"{category:22} {label:>5} {s['count']:>6} {flagged:>9.0%} {tricked:>18.0%}")

    attacks = [(r, p) for r, p, _ in results if r.label == 1]
    normals = [(r, p) for r, p, _ in results if r.label == 0]

    print(f"\n{'language':10} {'attacks caught':>15} {'false alarm':>12}")
    for language in ["all", "tr", "en"]:
        a = [p for r, p in attacks if language in ("all", r.language)]
        n = [p for r, p in normals if language in ("all", r.language)]
        recall = sum(p >= review_at for p in a) / len(a)
        false_alarm = sum(p >= review_at for p in n) / len(n)
        print(f"{language:10} {recall:>15.0%} {false_alarm:>12.0%}")

    print(f"\n{'threshold':10} {'attacks caught':>15} {'false alarm':>12}")
    for threshold in [0.5, 0.6, 0.7, 0.8, 0.9]:
        recall = sum(p >= threshold for _, p in attacks) / len(attacks)
        false_alarm = sum(p >= threshold for _, p in normals) / len(normals)
        print(f"{threshold:<10} {recall:>15.0%} {false_alarm:>12.0%}")

    print("\nMissed attacks:")
    for row, p in sorted(attacks, key=lambda x: x[1]):
        if p < review_at:
            print(f"  {p:.2f}  {row.language}  {row.category:18} {row.text[:70]}")

    print("\nFalse alarms:")
    for row, p in sorted(normals, key=lambda x: -x[1]):
        if p >= review_at:
            print(f"  {p:.2f}  {row.language}  {row.category:18} {row.text[:70]}")


def report_holdout(model, review_at, paths=HOLDOUT_PATHS):
    rows = load_rows(paths)
    if not rows:
        return

    by_category = defaultdict(list)
    for row in rows:
        by_category[row.category].append(probability(model, row.text))

    print(f"\nHoldout (never trained on), threshold {review_at:.2f}")
    print(f"{'category':26} {'label':>5} {'count':>6} {'flagged':>9} {'flagged @0.5':>13}")
    for category, ps in sorted(by_category.items()):
        label = next(r.label for r in rows if r.category == category)
        flagged = sum(p >= review_at for p in ps) / len(ps)
        at_half = sum(p >= 0.5 for p in ps) / len(ps)
        print(f"{category:26} {label:>5} {len(ps):>6} {flagged:>9.0%} {at_half:>13.0%}")


def fit_stage(stage, rows, rng):
    texts, labels = [], []
    for row in rows:
        for text in [row.text] + augment(row.text, rng, AUGMENT_COUNT):
            texts.append(text)
            labels.append(row.label)
    stage.classifier = LogisticRegression(class_weight="balanced", C=10.0, max_iter=5000).fit(stage.embed(texts), labels)
    return stage


# Both stages on the same folds, and the same obfuscated variants at test time for both.
def cross_validate_two_stages(rows, stage):
    rng = random.Random(SEED)
    splitter = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    variants = [augment(r.text, random.Random(SEED + i), AUGMENT_COUNT) for i, r in enumerate(rows)]
    p1, p2 = np.zeros(len(rows)), np.zeros(len(rows))
    t1, t2 = np.zeros((len(rows), AUGMENT_COUNT)), np.zeros((len(rows), AUGMENT_COUNT))

    for train_idx, test_idx in splitter.split(rows, [r.label for r in rows], [r.family for r in rows]):
        train = [rows[i] for i in train_idx]
        tfidf = fit(build_model(), train, rng)
        fit_stage(stage, train, rng)

        texts = [rows[i].text for i in test_idx]
        tricked = [v for i in test_idx for v in variants[i]]
        p1[test_idx] = tfidf.predict_proba([prepare(t) for t in texts])[:, 1]
        p2[test_idx] = stage.predict(texts)
        t1[test_idx] = tfidf.predict_proba([prepare(t) for t in tricked])[:, 1].reshape(-1, AUGMENT_COUNT)
        t2[test_idx] = stage.predict(tricked).reshape(-1, AUGMENT_COUNT)
    return p1, p2, t1, t2


def threshold_at(normal_scores, target=TARGET_FALSE_ALARM):
    normals = np.sort(normal_scores)[::-1]
    return float(min(1.0, normals[int(target * len(normals))] + 1e-6))


def cascade_flags(p1, p2, low, high, review_at):
    return np.where(p1 < low, False, np.where(p1 > high, True, (p1 + p2) / 2 >= review_at))


def train_cascade(rows, tfidf_model):
    stage = EmbeddingStage(encoder_name=EMBEDDING_MODEL, cache=True)
    labels = np.array([r.label for r in rows])
    p1, p2, t1, t2 = cross_validate_two_stages(rows, stage)

    ensemble = (p1 + p2) / 2
    review_at = threshold_at(ensemble[labels == 0])
    flagged = ensemble >= review_at
    low = float(p1[flagged].min()) - 1e-6
    high = float(p1[~flagged].max()) + 1e-6

    tfidf_at = threshold_at(p1[labels == 0])
    in_between = (p1 >= low) & (p1 <= high)
    cascade = cascade_flags(p1, p2, low, high, review_at)
    tricked = cascade_flags(t1, t2, low, high, review_at)
    customer = np.array([r.category.startswith("customer") for r in rows])

    print(f"\nCascade: TF-IDF on every message, {EMBEDDING_MODEL} only when {low:.3f} <= TF-IDF score <= {high:.3f}")
    print(f"{'':16} {'attacks caught':>15} {'tricked':>8} {'false alarm':>12}")
    print(f"{'TF-IDF only':16} {(p1[labels == 1] >= tfidf_at).mean():>15.0%} {(t1[labels == 1] >= tfidf_at).mean():>8.0%} "
          f"{(p1[labels == 0] >= tfidf_at).mean():>12.1%}")
    print(f"{'cascade':16} {cascade[labels == 1].mean():>15.0%} {tricked[labels == 1].mean():>8.0%} "
          f"{cascade[labels == 0].mean():>12.1%}")
    print(f"Second stage runs for {in_between.mean():.0%} of all messages, {in_between[labels == 0].mean():.0%} of normal ones"
          + (f", {in_between[customer].mean():.0%} of customer-service messages" if customer.any() else ""))

    fit_stage(stage, rows, random.Random(SEED))
    settings = {"encoder": EMBEDDING_MODEL, "prefix": "", "classifier": stage.classifier,
                "low": low, "high": high, "review_at": review_at}
    report_cascade_holdout(tfidf_model, stage, settings, tfidf_at)
    return settings


def report_cascade_holdout(tfidf_model, stage, settings, tfidf_at, paths=HOLDOUT_PATHS):
    rows = load_rows(paths)
    if not rows:
        return
    labels = np.array([r.label for r in rows])
    p1 = tfidf_model.predict_proba([prepare(r.text) for r in rows])[:, 1]
    p2 = stage.predict([r.text for r in rows])
    cascade = cascade_flags(p1, p2, settings["low"], settings["high"], settings["review_at"])
    print(f"Holdout: TF-IDF only {(p1[labels == 1] >= tfidf_at).mean():.0%} caught / "
          f"{(p1[labels == 0] >= tfidf_at).mean():.0%} false alarm, "
          f"cascade {cascade[labels == 1].mean():.0%} / {cascade[labels == 0].mean():.0%}")


def show_top_features(model, count=15):
    vectorizer, classifier = model.steps[0][1], model.steps[1][1]
    names = [n.split("__", 1)[1] for n in vectorizer.get_feature_names_out()]
    weights = classifier.coef_[0]
    order = weights.argsort()

    print("\nPieces that push towards ATTACK:")
    print("  " + ", ".join(repr(names[i]) for i in order[::-1][:count]))
    print("Pieces that push towards NORMAL:")
    print("  " + ", ".join(repr(names[i]) for i in order[:count]))


def main():
    rows = load_rows()
    print(f"{len(rows)} rows, {sum(r.label for r in rows)} attacks, {len({r.family for r in rows})} families, "
          f"{sum(r.language == 'tr' for r in rows)} Turkish")

    results = cross_validate(rows)
    review_at = choose_threshold(results)
    report(results, review_at)

    model = fit(build_model(), rows, random.Random(SEED))
    use_cascade = "--no-cascade" not in sys.argv and EmbeddingStage.is_available()
    cascade = train_cascade(rows, model) if use_cascade else None

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({
        "model": model,
        "review_at": review_at,
        "target_false_alarm": TARGET_FALSE_ALARM,
        "sklearn_version": sklearn.__version__,
        "cascade": cascade,
    }, MODEL_PATH)

    report_holdout(model, review_at)
    show_top_features(model)
    print(f"\nFinal model trained on all rows and saved to {MODEL_PATH.name} "
          f"(review_at {review_at:.2f}, target false alarm {TARGET_FALSE_ALARM:.0%})")


if __name__ == "__main__":
    main()
