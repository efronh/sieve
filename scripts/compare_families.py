# Sieve against the off-the-shelf baseline (protectai's DeBERTa v3 prompt-injection detector), attack family by
# family, on the corpus's test records (dev ones were read while tuning Sieve, so they'd favour it). The baseline reads
# the text each boundary carries (a message, each turn of a conversation, a document, the string arguments of a tool
# call, an answer), long text in overlapping pieces so none of it is cut at 512 tokens; its score is the highest
# INJECTION score of the pieces. Both count a record as flagged when anything was flagged, as replay.py's detection
# does; for Sieve a tool call's confirmation alone doesn't count.
# Two baseline thresholds: 0.5, as it ships, and per entry point the one that flags as many benign records there as
# Sieve does. At 0.5 it flags most Turkish text, benign too, so only the second compares catch rates.
#   python -m scripts.compare_families      -> results/family_comparison.json and its chart (the model must be in the HF cache)
import json
import os

from scripts.charts import FAMILY_PATH, family_chart
from scripts.replay import ALLOW, FAMILIES, config, entry_points, expand, load, run, wilson
from sieve.documents import strings_in
from sieve.paths import RESULTS, ROOT

os.environ.setdefault("HF_HUB_OFFLINE", "1")  # the cached model only; nothing is fetched

RESULTS_PATH = RESULTS / "family_comparison.json"
BASELINE = "protectai/deberta-v3-base-prompt-injection-v2"
POSITIVE = "INJECTION"
THRESHOLD = 0.5
CHUNK, OVERLAP = 1200, 200  # characters: under 512 of its tokens for Turkish text


def chunks(text):
    if len(text) <= CHUNK:
        return [text]
    return [text[i:i + CHUNK] for i in range(0, len(text) - OVERLAP, CHUNK - OVERLAP)]


def baseline_texts(case):
    entry = case["entry"]
    if entry in ("guardrail", "document", "output"):
        return chunks(case["text"])
    if entry == "conversation":
        return [piece for turn in case["turns"] for piece in chunks(turn)]
    texts = chunks(case["text"]) if entry == "chain" else []
    for call in case["calls"]:
        texts += [piece for s in strings_in(call["args"])[0] for piece in chunks(s)]
    return texts


class Baseline:
    def __init__(self):
        from transformers import pipeline

        self.pipe = pipeline("text-classification", model=BASELINE, device="mps", truncation=True, max_length=512)
        self.scores = {}

    def score(self, texts):
        missing = [t for t in dict.fromkeys(texts) if t not in self.scores and t.strip()]
        if missing:
            out = self.pipe(missing, batch_size=32, top_k=None)
            self.scores.update({t: next(s["score"] for s in scores if s["label"] == POSITIVE) for t, scores in zip(missing, out)})
        return max((self.scores.get(t, 0.0) for t in texts), default=0.0)


def share(k, n):
    low, high = wilson(k, n)
    return {"flagged": k, "of": n, "rate": k / n if n else None, "ci": [low, high]}


# One row per test record: Sieve's flag and the baseline's score.
def score_rows(cases, sieve_rows, baseline):
    detected = {r["id"]: r["detected"] != ALLOW for r in sieve_rows}
    return [{"id": case["id"], "family": case["family"], "group": case.get("group") or case["id"], "entry": case["entry"],
             "sieve": detected[case["id"]], "score": baseline.score(baseline_texts(case))} for case in cases]


# Per entry point, the lowest threshold at which the baseline flags no more benign records than Sieve does: just above
# the score of the benign record that would be one too many. None where there are no benign records to match on.
def matched_thresholds(rows):
    thresholds = {}
    for entry in sorted({r["entry"] for r in rows}):
        benign = [r for r in rows if r["entry"] == entry and r["family"] == "BEN"]
        allowed = sum(r["sieve"] for r in benign)
        scores = sorted((r["score"] for r in benign), reverse=True)
        thresholds[entry] = None if not benign else (min(1.0, scores[allowed] + 1e-9) if allowed < len(scores) else 0.0)
    return thresholds


def summarize(rows):
    thresholds = matched_thresholds(rows)
    for r in rows:
        r["shipped"] = r["score"] >= THRESHOLD
        r["matched"] = None if thresholds[r["entry"]] is None else r["score"] >= thresholds[r["entry"]]

    def counts(group):
        found = {key: [r[key] for r in group if r[key] is not None] for key in ("sieve", "shipped", "matched")}
        return {key: share(sum(values), len(values)) for key, values in found.items()}

    families = {}
    for family in [f for f in FAMILIES if f != "BEN"]:
        group = [r for r in rows if r["family"] == family]
        if group:
            families[family] = {"threat": FAMILIES[family], "records": len(group),
                                "groups": len({r["group"] for r in group}),
                                "entries": sorted({r["entry"] for r in group})} | counts(group)
    false_alarms = {entry: counts([r for r in rows if r["entry"] == entry and r["family"] == "BEN"])
                    for entry in thresholds if any(r["entry"] == entry and r["family"] == "BEN" for r in rows)}
    return thresholds, families, false_alarms


def percent(x):
    return f"{x['flagged']:4}/{x['of']:<4} {x['rate']:5.0%}" if x["of"] else "n/a"


def report(thresholds, families, false_alarms):
    print(f"Attacks flagged, test records. Baseline {BASELINE}: as shipped (INJECTION >= {THRESHOLD}), and at the "
          "threshold that flags as many benign records as Sieve does at that entry point")
    print(f"  {'family':12} {'threat':6} {'groups':>6}   {'Sieve':>16}   {'shipped':>16}   {'matched':>16}")
    for family, r in families.items():
        print(f"  {family:12} {r['threat']:6} {r['groups']:6}   {percent(r['sieve']):>16}   {percent(r['shipped']):>16}   "
              f"{percent(r['matched']):>16}")
    print("\nBenign records flagged, by entry point (matched threshold in brackets)")
    for entry, r in false_alarms.items():
        print(f"  {entry:12} {thresholds[entry] or 0:6.4f} {'':6}   {percent(r['sieve']):>16}   {percent(r['shipped']):>16}   "
              f"{percent(r['matched']):>16}")


def main():
    records = [r for r in load() if r["split"] == "test"]
    cases = [c for c in expand(records) if c["split"] == "test"]
    checks, ml = entry_points()
    sieve_rows = run(cases, checks)
    rows = score_rows(cases, sieve_rows, Baseline())
    thresholds, families, false_alarms = summarize(rows)
    report(thresholds, families, false_alarms)
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"split": "test", "sieve": config(ml), "baseline": {"model": BASELINE, "label": POSITIVE,
                   "shipped_threshold": THRESHOLD, "matched_thresholds": thresholds},
                   "families": families, "false_alarms": false_alarms,
                   "rows": [{k: r[k] for k in ("id", "family", "group", "entry", "sieve", "score")} for r in rows]},
                  f, ensure_ascii=False, indent=1)
        f.write("\n")
    family_chart(families)
    print(f"\nwrote {RESULTS_PATH.relative_to(ROOT)}, {FAMILY_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
