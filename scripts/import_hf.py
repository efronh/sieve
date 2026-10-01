import csv
import json
import random

import pyarrow.parquet as pq

from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.paths import DATA

RAW = DATA / "raw"

CUSTOMER_SERVICE_SAMPLE = 1500
SEED = 42

COLUMNS = ["text", "label", "category", "family", "language"]


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
    print(f"wrote {len(rows):>5} rows to {path.name}")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def tcpi_rows(splits):
    rows = []
    for split in splits:
        for r in read_jsonl(RAW / f"tcpi_{split}.jsonl"):
            family = f"tcpi_{r['pair_id'] or r['id']}"
            rows.append((r["text"], r["label"], f"tcpi_{r['category']}", family, "tr"))
    return rows


def customer_service_rows():
    table = pq.read_table(RAW / "customer_service.parquet").to_pylist()
    rules = PromptInjectionLayer()

    rows, seen, dropped = [], set(), []
    for number, conversation in enumerate(table):
        for message in conversation["messages"]:
            text = message["content"].strip()
            if message["role"] != "user" or not text or text in seen:
                continue
            seen.add(text)
            if rules.check(text)[0].action != "allow":
                dropped.append(text)
                continue
            rows.append((text, 0, "customer_service", f"cs_{number:05d}", "tr"))

    by_family = {}
    for row in rows:
        by_family.setdefault(row[3], []).append(row)
    families = sorted(by_family)
    random.Random(SEED).shuffle(families)

    sample = []
    for family in families:
        if len(sample) >= CUSTOMER_SERVICE_SAMPLE:
            break
        sample += by_family[family]

    print(f"customer service: {len(rows)} unique user messages, sampled {len(sample)} "
          f"from {len({r[3] for r in sample})} conversations, dropped {len(dropped)} flagged by rules")
    for text in dropped:
        print(f"  dropped: {text[:90]}")
    return sample


def main():
    write_csv(DATA / "tcpi_train.csv", tcpi_rows(["train", "validation"]))
    write_csv(DATA / "tcpi_test.csv", tcpi_rows(["test"]))
    write_csv(DATA / "customer_service_tr.csv", customer_service_rows())


if __name__ == "__main__":
    main()
