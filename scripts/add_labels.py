import csv
import hashlib
from pathlib import Path

from scripts.select_for_labeling import QUEUE_PATH, read_csv, write_queue
from sieve.paths import ROOT as REPO_ROOT

ROOT = REPO_ROOT
TRAIN_PATH = ROOT / "data" / "real_labeled.csv"
HOLDOUT_PATH = ROOT / "data" / "real_holdout.csv"
HOLDOUT_SHARE = 0.2

COLUMNS = ["text", "label", "category", "family", "language"]


# Whole sessions land on one side, and always the same one.
def goes_to_holdout(session):
    bucket = int(hashlib.sha256(session.encode("utf-8")).hexdigest(), 16) % 100
    return bucket < HOLDOUT_SHARE * 100


def append_rows(path, rows):
    new_file = not Path(path).exists()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(COLUMNS)
        writer.writerows(rows)


def main(queue_path=QUEUE_PATH, train_path=TRAIN_PATH, holdout_path=HOLDOUT_PATH):
    queue = read_csv(queue_path)
    labeled = [row for row in queue if row["label"] in ("0", "1")]
    waiting = [row for row in queue if row["label"] not in ("0", "1")]

    train, holdout = [], []
    for row in labeled:
        label = int(row["label"])
        category = "real_attack" if label else "real_normal"
        record = (row["text"], label, category, f"real_{row['session']}", "tr")
        (holdout if goes_to_holdout(row["session"]) else train).append(record)

    append_rows(train_path, train)
    append_rows(holdout_path, holdout)
    write_queue(queue_path, waiting)

    print(f"added {len(train)} rows to {Path(train_path).name}, {len(holdout)} to {Path(holdout_path).name}; "
          f"{len(waiting)} left in the queue")
    if labeled:
        print("retrain with: .venv/bin/python -m scripts.train_injection")


if __name__ == "__main__":
    main()
