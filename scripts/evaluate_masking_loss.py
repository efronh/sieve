# What masking takes from the text the model gets, besides the personal data it's there to take. Three
# measures, each against something known rather than a model's guess:
#   wrong masks:   every piece masked in benign text (customer-service messages, the benign corpus records), each
#                  reviewed by hand in corpus/pii/review/benign_masks.jsonl: right, mislabeled (personal data, but not what
#                  the label says, so the model is told the wrong thing) or not_personal (meaning lost for nothing);
#   merged values: a message or a conversation with two different values under one label, which the model
#                  can't tell apart ("from [IBAN] to [IBAN]");
#   needed values: tool-call arguments the user typed (or a document held), which the model never saw because
#                  masking took them, so it couldn't have written the call.
# What the answer loses, a model's view of it, needs an LLM and isn't measured here.
#   python -m scripts.evaluate_masking_loss          # the report, and results/masking_loss.json
# tests/test_masking_loss.py fails when a piece masked in benign text has no verdict, or a wrong one the test doesn't know.
import json
import re
from collections import Counter, defaultdict

from scripts.evaluate_documents import CONVERSATIONS_PATH, read
from scripts.evaluate_masking import CORPUS as PII_CORPUS
from scripts.evaluate_masking import load as load_pii
from scripts.replay import load as load_corpus
from sieve.documents import DocumentGuard
from sieve.masking.number_units import REPLACED
from sieve.paths import DATA, RESULTS, ROOT
from sieve.pipeline import LAYERS, clean, mask
from sieve.tools import given_by_user

REVIEW = PII_CORPUS / "review" / "benign_masks.jsonl"
RESULTS_PATH = RESULTS / "masking_loss.json"
BENIGN_FILES = ["short_benign_tr.csv", "benign_contrast_tr.csv", "benign_documents_tr.csv"]
EXAMPLES = 3
VERDICTS = ("right", "mislabeled", "not_personal")


# (the masked text, [(label, value)] for each piece masking replaced)
def masked_pieces(text, layers=LAYERS):
    replaced = []
    token = REPLACED.set(replaced)
    try:
        masked = mask(text, layers)
    finally:
        REPLACED.reset(token)
    return masked, [(label, value.strip()) for label, value in replaced]


# Spacing, case and a phone number's country code don't make another value.
def value_key(label, value):
    value = clean(value).lower()
    if label == "[TELEFON]":
        return re.sub(r"\D", "", value)[-10:]
    return re.sub(r"[\s\-.()/]", "", value)


# Benign texts by source, and the conversations they make up (lists of texts that reach one model in turn).
def benign_texts():
    rows = read(CONVERSATIONS_PATH)
    by_family = defaultdict(list)
    for row in rows:
        by_family[row["family"]].append(row["text"])
    texts = {"customer_service": [row["text"] for row in rows]}
    for name in BENIGN_FILES:
        texts[name.removesuffix("_tr.csv")] = [row["text"] for row in read(DATA / name)]

    corpus = [r for r in load_corpus() if r["family"] == "BEN"]
    texts["corpus_messages"] = [r["text"] for r in corpus if r["carrier"] == "plain_text"]
    texts["corpus_documents"] = [r["text"] for r in corpus if r["carrier"] in ("document", "tool_chain")]
    texts["corpus_answers"] = [r["text"] for r in corpus if r["carrier"] == "model_answer"]
    texts["corpus_conversations"] = [t for r in corpus for t in r.get("turns", ())]
    texts["corpus_tool_requests"] = [t for r in corpus if "calls" in r for t in r["user_data"]]
    conversations = {
        "customer_service": list(by_family.values()),
        "corpus_conversations": [r["turns"] for r in corpus if "turns" in r],
        "corpus_tool_requests": [r["user_data"] for r in corpus if "calls" in r],
        "pii_messages": [[r["text"]] for r in load_pii()],
    }
    return texts, conversations


def load_review(path=REVIEW):
    review = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                item = json.loads(line)
                if set(item) - {"label", "value", "verdict", "note"} or item.get("verdict") not in VERDICTS:
                    raise ValueError(f"{path.name}:{n}: needs label, value, verdict {VERDICTS}, optional note")
                review[(item["label"], item["value"])] = item
    return review


# Every masked piece of benign text, with its source and the text it was in.
def masked_in_benign(texts):
    found = []
    for source, items in texts.items():
        for text in items:
            for label, value in masked_pieces(text)[1]:
                found.append({"source": source, "label": label, "value": value, "text": text})
    return found


def verdict(review, piece):
    return review.get((piece["label"], piece["value"]), {}).get("verdict")


def wrong_masks(texts, review):
    found = masked_in_benign(texts)
    rows = {}
    for source, items in texts.items():
        pieces = [p for p in found if p["source"] == source]
        rows[source] = {"texts": len(items), "changed": sum(masked_pieces(t)[0] != clean(t) for t in items),
                        "masked": len(pieces)} | {v: sum(verdict(review, p) == v for p in pieces) for v in VERDICTS[1:]}
    unreviewed = sorted({(p["label"], p["value"]) for p in found} - set(review))
    wrong = [p | {"verdict": verdict(review, p)} for p in found if verdict(review, p) in VERDICTS[1:]]
    return rows, wrong, unreviewed


# Conversations (or messages) where one label stands for more than one value.
def merged_values(conversations):
    rows, examples = {}, []
    for source, items in conversations.items():
        with_mask = merged = 0
        for texts in items:
            values = defaultdict(set)
            for text in texts:
                for label, value in masked_pieces(text)[1]:
                    values[label].add(value_key(label, value))
            with_mask += bool(values)
            labels = sorted(label for label, keys in values.items() if len(keys) > 1)
            if labels:
                merged += 1
                if len(examples) < EXAMPLES * len(conversations):
                    examples.append({"source": source, "labels": labels, "text": " / ".join(texts)[:160]})
        rows[source] = {"conversations": len(items), "with_mask": with_mask, "merged": merged}
    return rows, examples


def model_view_of_document(documents, text):
    lines = documents.wrap(text).split("\n")[1:-1]
    return "\n".join(lines).replace(documents.mark, " ")


# For every string argument of every corpus tool call: did the user (or the document read before the call) give
# the value, and does it survive into what the model reads? A value that was given but doesn't survive is one the
# model couldn't have written. Benign calls and attacks are counted apart: for an attack, masking taking the value
# is a defence.
def needed_values():
    documents = DocumentGuard(use_ml=False)
    rows = {kind: Counter() for kind in ("benign", "attack")}
    examples = []
    for r in load_corpus():
        if "calls" not in r:
            continue
        kind = "benign" if r["family"] == "BEN" else "attack"
        user = r["user_data"]
        user_seen = [mask(t) for t in user]
        document = r.get("text") if r["carrier"] == "tool_chain" else None
        document_seen = [model_view_of_document(documents, document)] if document else []
        call_needs = call_hidden = False
        for call in r["calls"]:
            rows[kind]["calls"] += 1
            args = call["args"] if isinstance(call["args"], dict) else {}  # TOOL-SCHEMA sends some that aren't
            for key, value in args.items():
                if not isinstance(value, str):
                    continue
                rows[kind]["string_args"] += 1
                if given_by_user(value, user):
                    source, seen = "user", given_by_user(value, user_seen)
                elif document and given_by_user(value, [clean(document)]):
                    source, seen = "document", given_by_user(value, document_seen)
                else:
                    continue
                rows[kind][f"from_{source}"] += 1
                call_needs = True
                if not seen:
                    rows[kind][f"from_{source}_hidden"] += 1
                    call_hidden = True
                    if len(examples) < 2 * EXAMPLES:
                        examples.append({"id": r["id"], "kind": kind, "tool": call["tool"], "arg": key, "value": value})
        rows[kind]["records"] += 1
        rows[kind]["records_needing_a_value"] += call_needs
        rows[kind]["records_with_a_hidden_value"] += call_hidden
    return {kind: dict(counts) for kind, counts in rows.items()}, examples


def evaluate():
    texts, conversations = benign_texts()
    review = load_review()
    wrong_rows, wrong, unreviewed = wrong_masks(texts, review)
    merged_rows, merged_examples = merged_values(conversations)
    needed_rows, needed_examples = needed_values()
    return {
        "wrong_masks": {"by_source": wrong_rows,
                        "wrong": [{k: p[k] for k in ("source", "label", "value", "verdict")} for p in wrong],
                        "unreviewed": [list(u) for u in unreviewed]},
        "merged_values": {"by_source": merged_rows, "examples": merged_examples},
        "needed_values": {"by_kind": needed_rows, "examples": needed_examples},
    }, wrong


def report(results, wrong):
    print(f"Wrong masks: pieces of benign text masked under the wrong label, or that aren't personal data "
          f"({REVIEW.relative_to(ROOT)})")
    print(f"  {'source':22} {'texts':>6} {'changed':>8} {'masked':>7} {'mislabeled':>11} {'not personal':>13}")
    for source, r in results["wrong_masks"]["by_source"].items():
        print(f"  {source:22} {r['texts']:6} {r['changed']:8} {r['masked']:7} {r['mislabeled']:11} {r['not_personal']:13}")
    for p in wrong:
        print(f"    {p['verdict']}: {p['label']} {p['value']!r} in {p['text'][:90]!r}")
    for label, value in results["wrong_masks"]["unreviewed"]:
        print(f"    not reviewed: {label} {value!r}")

    print("\nMerged values: one label for two different values, in a message or a conversation")
    print(f"  {'source':22} {'units':>6} {'masked':>7} {'merged':>7}")
    for source, r in results["merged_values"]["by_source"].items():
        print(f"  {source:22} {r['conversations']:6} {r['with_mask']:7} {r['merged']:7}")
    for e in results["merged_values"]["examples"]:
        print(f"    {e['source']}: {', '.join(e['labels'])} in {e['text'][:110]!r}")

    print("\nNeeded values: tool-call arguments the user or a document gave, and that masking hides from the model")
    for kind, r in results["needed_values"]["by_kind"].items():
        print(f"  {kind}: {r.get('records', 0)} records, {r.get('calls', 0)} calls, {r.get('string_args', 0)} string args; "
              f"from the user {r.get('from_user', 0)} ({r.get('from_user_hidden', 0)} hidden), "
              f"from a document {r.get('from_document', 0)} ({r.get('from_document_hidden', 0)} hidden); "
              f"records needing a given value {r.get('records_needing_a_value', 0)}, "
              f"with one hidden {r.get('records_with_a_hidden_value', 0)}")
    for e in results["needed_values"]["examples"]:
        print(f"    {e['id']} ({e['kind']}): {e['tool']}.{e['arg']} = {e['value']!r}")


def main():
    results, wrong = evaluate()
    report(results, wrong)
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"\nwrote {RESULTS_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
