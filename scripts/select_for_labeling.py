import csv
import json
import sys
from pathlib import Path

from sieve.integrations.traffic_log import LOG_PATH, message_id
from sieve.paths import ROOT as REPO_ROOT

ROOT = REPO_ROOT
QUEUE_PATH = ROOT / "labeling" / "queue.csv"
LABELED_PATHS = [ROOT / "data" / "real_labeled.csv", ROOT / "data" / "real_holdout.csv"]

QUEUE_COLUMNS = ["id", "session", "text", "reason", "ml_probability", "rules", "action", "label", "note"]
UNCERTAIN = (0.3, 0.9)
RANDOM_ALLOW_SHARE = 0.02

RULE_CHECKS = {"prompt_injection_rules", "tampering", "code_payloads", "url_check"}
ML_CHECK = "prompt_injection_ml"


def read_log(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def read_csv(path):
    if not Path(path).exists():
        return []
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_queue(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=QUEUE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def ml_flagged(finding):
    if finding.get("shadow"):
        return any(m in ("would_review", "would_block") for m in finding["matches"])
    return finding["action"] != "allow"


def reason_for(record):
    findings = record["findings"]
    ml = next((f for f in findings if f["check"] == ML_CHECK), None)
    rules_flag = any(f["action"] != "allow" for f in findings if f["check"] in RULE_CHECKS)
    ml_flag = ml is not None and ml_flagged(ml)

    if record["action"] != "allow":
        return "flagged"
    if ml is not None and rules_flag != ml_flag:
        return "layers_disagree"
    if ml is not None and UNCERTAIN[0] <= ml["probability"] <= UNCERTAIN[1]:
        return "ml_uncertain"
    if int(record["id"], 16) % 10_000 < RANDOM_ALLOW_SHARE * 10_000:
        return "random_allow"
    return None


def queue_row(record, reason):
    findings = record["findings"]
    ml = next((f for f in findings if f["check"] == ML_CHECK), None)
    rules = sorted({m for f in findings if f["check"] in RULE_CHECKS for m in f["matches"]})
    return {
        "id": record["id"],
        "session": record["session"],
        "text": record["text"],
        "reason": reason,
        "ml_probability": f"{ml['probability']:.2f}" if ml else "",
        "rules": " ".join(rules),
        "action": record["action"],
        "label": "",
        "note": "",
    }


def main(log_path=LOG_PATH, queue_path=QUEUE_PATH, labeled_paths=LABELED_PATHS):
    queue = read_csv(queue_path)
    known = {row["id"] for row in queue}
    for path in labeled_paths:
        known |= {message_id(row["text"]) for row in read_csv(path)}

    added = {}
    for record in read_log(log_path):
        if record["id"] in known:
            continue
        reason = reason_for(record)
        if reason:
            known.add(record["id"])
            queue.append(queue_row(record, reason))
            added[reason] = added.get(reason, 0) + 1

    write_queue(queue_path, queue)
    waiting = sum(1 for row in queue if not row["label"])
    print(f"added {sum(added.values())} messages to {Path(queue_path).name} {added}; {waiting} waiting for a label")


if __name__ == "__main__":
    main(*(Path(a) for a in sys.argv[1:2]))
