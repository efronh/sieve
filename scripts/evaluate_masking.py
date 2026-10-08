# Measures masking on corpus/pii/: personal data that must be gone before the model sees it, and numbers
# that must stay. Each record goes the two ways text reaches the model: as a message through mask() (the text
# Guardrail returns), and inside a support-ticket export through DocumentGuard.wrap().
#   python -m scripts.evaluate_masking                    # the report
#   python -m scripts.evaluate_masking --baseline check   # fails if a value masked or kept before isn't now
#   python -m scripts.evaluate_masking --baseline update  # after an intended change; commit corpus/pii/baseline.json
#   python -m scripts.evaluate_masking --random 6000      # valid numbers in random shapes, packed among others
# Masking is deterministic, so tests/test_masking_corpus.py runs the check on every test run.
import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from scripts.evaluate_documents import ticket_exports
from sieve.documents import DocumentGuard
from sieve.masking.card import luhn
from sieve.masking.number_units import REPLACED
from sieve.paths import ROOT
from sieve.pipeline import clean, mask

CORPUS = ROOT / "corpus" / "pii"
BASELINE = CORPUS / "baseline.json"
LABELS = {"[TC_KIMLIK]", "[IBAN]", "[KART]", "[SKT]", "[CVV]", "[TELEFON]", "[EPOSTA]", "[VKN]", "[GIZLI_ANAHTAR]",
          "[SIFRE]"}
KINDS = {"TC", "IBAN", "KART", "TELEFON", "EPOSTA", "VKN", "GIZLI", "MIXED", "BEN"}
FIELDS = {"id", "kind", "language", "source", "split", "text", "pii", "keep"}
OPTIONAL = {"note"}


def load(directory=CORPUS):
    records, problems = [], []
    for path in sorted(Path(directory).glob("*.jsonl")):
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if line.strip():
                    record = json.loads(line)
                    problems += [f"{path.name}:{n}: {p}" for p in record_problems(record)]
                    records.append(record)
    ids = [r.get("id") for r in records]
    problems += [f"duplicate id {i}" for i in sorted({i for i in ids if ids.count(i) > 1})]
    if problems:
        raise ValueError("\n".join(problems))
    return records


def record_problems(r):
    problems = [f"missing {k!r}" for k in sorted(FIELDS - r.keys())]
    problems += [f"unknown key {k!r}" for k in sorted(r.keys() - FIELDS - OPTIONAL)]
    if problems:
        return problems
    if r["kind"] not in KINDS:
        problems.append(f"unknown kind {r['kind']!r}")
    if not r["id"].startswith(f"PII-{r['kind']}-"):
        problems.append(f"id {r['id']} doesn't name its kind")
    if (r["kind"] == "BEN") == bool(r["pii"]):
        problems.append("benign records have no pii, the others have some")
    for item in r["pii"]:
        if item.get("label") not in LABELS:
            problems.append(f"unknown label {item.get('label')!r}")
        if item.get("value", "") not in r["text"]:
            problems.append(f"pii value {item.get('value')!r} isn't in the text")
    problems += [f"keep value {v!r} isn't in the text" for v in r["keep"] if v not in r["text"]]
    return problems


# What the model would get. A document's marks between words go back to spaces, so values can be looked for.
def views():
    documents = DocumentGuard(use_ml=False)
    exports = ticket_exports()

    def in_document(record, i):
        parts = exports[i % len(exports)]
        half = len(parts) // 2
        page = "\n\n".join(parts[:half] + [record["text"]] + parts[half:])
        return documents.wrap(page, source="destek").replace(documents.mark, " ")

    return {"message": lambda record, i: mask(record["text"]), "document": in_document}


# (what the model gets, the pieces masking replaced)
def seen_and_replaced(view, record, i):
    replaced = []
    token = REPLACED.set(replaced)
    try:
        return view(record, i), replaced
    finally:
        REPLACED.reset(token)


# A value is masked when one replaced piece holds all of it and its label is in the text: a window that takes
# the end of a phone number and the start of a card hides neither, though neither appears whole any more.
# Masked under another label is protected but misnamed, and counts as a miss. Other values are kept when they
# still appear.
def evaluate(records):
    results = {}
    for name, view in views().items():
        rows = []
        for i, r in enumerate(records):
            seen, replaced = seen_and_replaced(view, r, i)
            for n, item in enumerate(r["pii"]):
                value = clean(item["value"]).strip()
                gone = any(value in piece for _, piece in replaced)
                rows.append({"item": f"{r['id']}#{n}", "split": r["split"], "label": item["label"], "pii": True,
                             "ok": gone and item["label"] in seen, "gone": gone,
                             "partly": not gone and value not in seen, "note": r.get("note", "")})
            for n, value in enumerate(r["keep"]):
                rows.append({"item": f"{r['id']}~{n}", "split": r["split"], "label": None, "pii": False,
                             "ok": clean(value) in seen, "gone": clean(value) not in seen, "partly": False,
                             "note": r.get("note", "")})
        results[name] = rows
    return results


def share(rows):
    k, n = sum(r["ok"] for r in rows), len(rows)
    return f"{k:3}/{n:<3} ({k / max(n, 1):4.0%})"


def outcome(r):
    if not r["pii"]:
        return "masked"
    return "under another label" if r["gone"] else "partly masked" if r["partly"] else "not masked"


# Test records per entry; dev records (a masking rule was changed after reading them) on one line.
def report(results):
    for name, rows in results.items():
        test = [r for r in rows if r["split"] == "test"]
        pii, keep = [r for r in test if r["pii"]], [r for r in test if not r["pii"]]
        masked_wrong = sum(r["gone"] and not r["ok"] for r in pii)
        print(f"\n{name}, test: personal data masked {share(pii)}"
              + (f", {masked_wrong} under another label" if masked_wrong else "")
              + f"; other numbers left alone {share(keep)}")
        by_label = defaultdict(list)
        for r in pii:
            by_label[r["label"]].append(r)
        for label in sorted(by_label):
            print(f"    {label:16} {share(by_label[label])}")
        dev = [r for r in rows if r["split"] == "dev"]
        if dev:
            print(f"  dev: right {share(dev)}")
        missed = [r for r in test if not r["ok"]]
        if missed:
            print("  wrong in test:")
            for r in missed:
                print(f"    {r['item']:16} {outcome(r):20} {r['note']}")


# A stress test the corpus can't be: checksum-valid TC numbers, IBANs, cards and phone numbers, grouped at random
# and packed one to three in a message among other numbers and words; and reference numbers of random length,
# which should stay. Seeded, so the shares are the same on every run.
def random_number(rng, kind):
    digits = lambda n: "".join(rng.choice("0123456789") for _ in range(n))  # noqa: E731
    if kind == "tc":
        d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
        tenth = (sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10
        return "".join(map(str, d)) + str(tenth) + str((sum(d) + tenth) % 10)
    if kind == "iban":
        bban = digits(22)
        return f"TR{98 - int(''.join(str(int(c, 36)) for c in bban + 'tr00')) % 97:02d}{bban}"
    if kind == "card":
        body = (rng.choice(["4", "5", "9792"]) + digits(14))[:15]
        return next(body + c for c in "0123456789" if luhn(body + c))
    return rng.choice(["0", "+90 ", "", "0090 "]) + "5" + digits(9)


def shaped(rng, value):
    digits = value.replace(" ", "")
    size = rng.choice([0, 4, 3, None])
    if size == 0:
        return value
    if size:
        return rng.choice([" ", "-"]).join(digits[i:i + size] for i in range(0, len(digits), size))
    pieces, i = [], 0
    while i < len(digits):
        n = rng.randint(2, 5)
        pieces.append(digits[i:i + n])
        i += n
    return " ".join(pieces)


def random_shares(n, seed=42):
    rng = random.Random(seed)
    neighbours = ["", "", "Sipariş ", "no: ", "tel ", "ve ", "kart ", "IBAN ", "TC ", "12.450,75 TL ", "24.09.2026 ",
                  "1Z999AA101 ", "\n", "(", "#"]
    masked = total = 0
    for _ in range(n):
        values = [shaped(rng, random_number(rng, rng.choice(["tc", "iban", "card", "phone"])))
                  for _ in range(rng.randint(1, 3))]
        filler = [rng.choice(neighbours + ["".join(rng.choice("0123456789") for _ in range(rng.randint(2, 12))) + " "])
                  for _ in values]
        text = rng.choice([" ", ", ", "\n", " / "]).join(f + v for f, v in zip(filler, values))
        replaced = []
        token = REPLACED.set(replaced)
        try:
            mask(text + rng.choice(["", ".", " lütfen", "'dir"]))
        finally:
            REPLACED.reset(token)
        masked += sum(any(clean(v) in piece for _, piece in replaced) for v in values)
        total += len(values)
    wrongly = 0
    for _ in range(n):
        number = rng.choice("123456789") + "".join(rng.choice("0123456789") for _ in range(rng.choice([9, 10, 11, 13, 15, 17, 19, 23])))
        replaced = []
        token = REPLACED.set(replaced)
        try:
            mask(rng.choice(["Sipariş ", "Dekont ", "Ref: ", "Kargo ", ""]) + shaped(rng, number))
        finally:
            REPLACED.reset(token)
        wrongly += bool(replaced)
    return masked, total, wrongly, n


def write_baseline(results, path=BASELINE):
    data = {name: sorted(r["item"] for r in rows if r["ok"]) for name, rows in results.items()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
        f.write("\n")


# (problems: values right in the baseline and wrong now; notes: values wrong in the baseline and right now)
def check_baseline(results, baseline):
    problems, notes = [], []
    for name, rows in results.items():
        before = set(baseline.get(name, ()))
        for r in rows:
            if r["item"] in before and not r["ok"]:
                problems.append(f"{name}: {r['item']} {'no longer masked' if r['pii'] else 'now masked'} ({r['note']})")
            elif r["item"] not in before and r["ok"]:
                notes.append(f"{name}: {r['item']} {'now masked' if r['pii'] else 'now left alone'} ({r['note']})")
    return problems, notes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", choices=("check", "update"))
    parser.add_argument("--random", type=int, metavar="N", help="also N random messages, see random_shares")
    args = parser.parse_args()
    if args.random:
        masked, total, wrongly, n = random_shares(args.random)
        print(f"random: {masked}/{total} valid numbers masked whole ({masked / total:.1%}); "
              f"{wrongly}/{n} reference numbers masked ({wrongly / n:.1%})")
    records = load()
    results = evaluate(records)
    report(results)
    if args.baseline == "update":
        write_baseline(results)
        print(f"\nwrote {BASELINE.relative_to(ROOT)}")
    elif args.baseline == "check":
        with open(BASELINE, encoding="utf-8") as f:
            problems, notes = check_baseline(results, json.load(f))
        print(f"\nbaseline: {len(problems)} problems, {len(notes)} notes")
        for line in problems + notes:
            print(f"  {line}")
        if problems:
            sys.exit(1)


if __name__ == "__main__":
    main()
