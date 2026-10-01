import argparse
import csv
import random

from sieve.llm.layer import HEADS_PATH, LLMCheckLayer
from sieve.pipeline import mask

DATA_PATHS = [
    "data/prompt_injection_tr.csv", "data/external_attacks.csv", "data/altaysec.csv",
    "data/benign_contrast_tr.csv", "data/short_benign_tr.csv", "data/tcpi_train.csv",
    "data/customer_service_tr.csv",
]
PER_CLASS = 300
SEED = 42


# Balanced sample: the head is a linear solve, so a class that dominates the sample dominates it.
def load_balanced(per_class=PER_CLASS, seed=SEED):
    rows = []
    for path in DATA_PATHS:
        with open(path, encoding="utf-8") as f:
            rows += [(mask(r["text"]), r["label"] == "1") for r in csv.DictReader(f)]
    rng = random.Random(seed)
    rng.shuffle(rows)
    attacks = [r for r in rows if r[1]][:per_class]
    normals = [r for r in rows if not r[1]][:per_class]
    return attacks + normals


def train(layer, rows, max_depth):
    texts = [text for text, _ in rows]
    violated = [label for _, label in rows]
    return layer.fit_head("prompt_injection", texts, violated, max_depth=max_depth)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="Qwen/Qwen3-8B")
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--max-depth", type=float, default=0.5)
    parser.add_argument("--per-class", type=int, default=PER_CLASS)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    layer = LLMCheckLayer.from_model(args.model, artifacts=None, device=args.device, compact=args.compact)
    artifact = train(layer, load_balanced(args.per_class), args.max_depth)
    layer.save(HEADS_PATH)
    print(f"prompt_injection head: block {artifact.get('layer')}, cv {artifact.get('cv')}; saved to {HEADS_PATH}")


if __name__ == "__main__":
    main()
