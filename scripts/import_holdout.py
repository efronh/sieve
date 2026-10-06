# The sealed held-out set: attacks and benign messages written by others, never trained on and never
# read by whoever changes the rules. Downloads them at pinned revisions and writes holdout/*.jsonl,
# printing only counts. Don't open those files: `python -m scripts.replay --holdout` reports them in
# aggregate. See holdout/README.md.
#   python -m scripts.import_holdout
import csv
import io
import json
import re
import urllib.request

import pyarrow.parquet as pq

from scripts.train_injection import DATA_PATHS, HOLDOUT_PATHS
from sieve.paths import DATA, ROOT

HOLDOUT = ROOT / "holdout"
CORPUS = ROOT / "corpus"
# A text sharing more than half its character 4-grams with a training or corpus text isn't independent.
NEAR_DUPLICATE = 0.5


def fetch(repo, revision, path):
    url = f"https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}"
    with urllib.request.urlopen(url) as response:
        return response.read()


def jsonl(data):
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


# (text, label, category, reference) for each source; label is "attack" or "benign".
def pi1k(repo, revision):
    table = pq.read_table(io.BytesIO(fetch(repo, revision, "data/test.parquet"))).to_pylist()
    return [(r["text"], "attack" if r["label"] == 1 else "benign", r["attack_family"], r["id"]) for r in table]


def deepset_tr(repo, revision):
    rows = []
    for split in ("train", "test"):
        rows += [(r["text"], "attack" if r["label"] == 1 else "benign", "", f"{split}:{i}")
                 for i, r in enumerate(jsonl(fetch(repo, revision, f"data/{split}.jsonl")))]
    return rows


def patterns_tr(repo, revision):
    return [(r["payload"], "attack", r["category"], r["id"])
            for r in jsonl(fetch(repo, revision, "prompt_injection_tr.jsonl"))]


# name -> (repository, revision, reader, license, note)
SOURCES = {
    "pi1k": ("3nesdeniz/turkish-prompt-injection-1k", "1cbd1152d9732f40148fbd5bb7cf0f58ddfe84c6", pi1k, "CC-BY-4.0",
             "test split; paired attacks and look-alike benign messages from templates"),
    "deepset_tr": ("beratcmn/turkish-prompt-injections", "c40c38f8ca632052fbfec19e90fab31fce33eda1", deepset_tr,
                   "Apache-2.0", "train and test; a Turkish translation of deepset/prompt-injections"),
    "patterns_tr": ("fevziegeyurtsevenler/turkish-prompt-injection", "fae488a1644a02bb8f377743e516db356b9a93c1",
                    patterns_tr, "CC-BY-4.0", "107 attack patterns with categories"),
}


def normalize(text):
    return re.sub(r"\W+", " ", text.lower()).strip()


def grams(text):
    text = normalize(text)
    return {text[i:i + 4] for i in range(len(text) - 3)}


def known_texts():
    texts = []
    for path in DATA_PATHS + HOLDOUT_PATHS:
        if (ROOT / path).exists():
            with open(ROOT / path, encoding="utf-8") as f:
                texts += [r["text"] for r in csv.DictReader(f)]
    with open(DATA / "altaysec_train.jsonl", encoding="utf-8") as f:
        texts += [json.loads(line)["prompt"] for line in f if line.strip()]
    for path in CORPUS.glob("*.jsonl"):
        with open(path, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                texts += [record.get("text", "")] + record.get("turns", [])
    return [g for g in (grams(t) for t in texts if t) if g]


def near_duplicate(g, known):
    return any(len(g & k) / len(g | k) > NEAR_DUPLICATE for k in known if k)


def run():
    HOLDOUT.mkdir(exist_ok=True)
    known = known_texts()
    seen = set()
    for name, (repo, revision, reader, license_, _) in SOURCES.items():
        records, dropped_copies, dropped_near = [], 0, 0
        for text, label, category, ref in reader(repo, revision):
            key = normalize(text)
            if not key or key in seen:
                dropped_copies += 1
                continue
            seen.add(key)
            if near_duplicate(grams(text), known):
                dropped_near += 1
                continue
            records.append({"id": f"HO-{name.upper()}-{len(records) + 1:04d}", "source": name, "source_ref": str(ref),
                            "label": label, "category": category, "text": text})
        with open(HOLDOUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
        attacks = sum(r["label"] == "attack" for r in records)
        print(f"{name:12} {repo}@{revision[:7]} ({license_}): kept {attacks} attacks, {len(records) - attacks} benign; "
              f"dropped {dropped_near} near copies of training or corpus texts, {dropped_copies} repeats")


if __name__ == "__main__":
    run()
