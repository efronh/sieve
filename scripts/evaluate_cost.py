import csv

from sieve.actions import ALLOW
from sieve.pipeline import Guardrail, needs_llm

THRESHOLDS = [None, 0.05, 0.1, 0.2, 0.3, 0.5]
SETS = {
    "holdout (never trained on)": ["data/tcpi_test.csv"],
    "all training data (optimistic)": [
        "data/prompt_injection_tr.csv", "data/external_attacks.csv", "data/altaysec.csv",
        "data/benign_contrast_tr.csv", "data/short_benign_tr.csv", "data/tcpi_train.csv",
        "data/customer_service_tr.csv",
    ],
}


def load(paths):
    rows = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            rows += [(r["text"], int(r["label"])) for r in csv.DictReader(f)]
    return rows


def run():
    guard = Guardrail(cache_size=0)

    for name, paths in SETS.items():
        rows = load(paths)
        local = [(guard.check(text).findings, label) for text, label in rows]
        attacks = sum(label for _, label in local)

        print(f"\n{name}: {len(rows)} messages, {attacks} attacks")
        print(f"{'llm_min_ml':>10} {'LLM calls':>10} {'saved':>7} {'attacks never seen by LLM or local':>36}")
        for threshold in THRESHOLDS:
            calls = sum(needs_llm(findings, threshold) for findings, _ in local)
            unseen = sum(
                1 for findings, label in local
                if label == 1 and not needs_llm(findings, threshold)
                and all(f.action == ALLOW for f in findings)
            )
            label = "always" if threshold is None else threshold
            print(f"{label:>10} {calls / len(local):>10.0%} {1 - calls / len(local):>7.0%} "
                  f"{unseen:>6} ({unseen / attacks:.0%})")


if __name__ == "__main__":
    run()
