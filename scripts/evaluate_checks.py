import csv
from collections import defaultdict

from sieve.checks.code_payloads import CodePayloadLayer
from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.checks.tampering import TamperingLayer
from sieve.checks.urls import URLCheckLayer
from sieve.pipeline import clean

DATA_PATHS = [
    "data/prompt_injection_tr.csv",
    "data/external_attacks.csv",
    "data/altaysec.csv",
    "data/benign_contrast_tr.csv",
]

LAYERS = [TamperingLayer(), PromptInjectionLayer(), CodePayloadLayer(), URLCheckLayer()]


def load_rows():
    rows = []
    for path in DATA_PATHS:
        with open(path, encoding="utf-8") as f:
            rows += list(csv.DictReader(f))
    return rows


def run():
    rows = load_rows()
    attacks = [r for r in rows if r["label"] == "1"]
    normals = [r for r in rows if r["label"] == "0"]
    print(f"{len(attacks)} attacks, {len(normals)} normal messages\n")

    print(f"{'layer':24} {'attacks flagged':>16} {'false alarms':>13}")
    false_alarms = defaultdict(list)
    caught_by_category = defaultdict(lambda: defaultdict(int))

    for layer in LAYERS:
        def flagged(row):
            text = row["text"] if getattr(layer, "needs_raw_text", False) else clean(row["text"])
            return layer.check(text)[0].action != "allow"

        caught = 0
        for row in attacks:
            if flagged(row):
                caught += 1
                caught_by_category[row["category"]][layer.name] += 1

        for row in normals:
            if flagged(row):
                false_alarms[layer.name].append(row)

        print(f"{layer.name:24} {caught / len(attacks):>16.0%} {len(false_alarms[layer.name]) / len(normals):>13.1%}")

    print(f"\n{'category':34} " + " ".join(f"{layer.name[:12]:>12}" for layer in LAYERS))
    counts = defaultdict(int)
    for row in attacks:
        counts[row["category"]] += 1
    for category in sorted(counts):
        cells = " ".join(f"{caught_by_category[category][layer.name] / counts[category]:>12.0%}" for layer in LAYERS)
        print(f"{category:34} {cells}")

    print("\nFalse alarms:")
    for layer in LAYERS:
        for row in false_alarms[layer.name]:
            print(f"  {layer.name:22} {row['category']:20} {row['text'][:70]}")


if __name__ == "__main__":
    run()
