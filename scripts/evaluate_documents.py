import csv
import json
import time
from collections import defaultdict

from sieve.documents import DocumentGuard
from sieve.pipeline import Guardrail

# Indirect prompt injection: the attack arrives inside a document the model reads (a web page,
# an e-mail, a tool result), not in the user's message.
#
# Test: the 30 TCPI test attacks (written by someone else, never trained on) hidden in support
# ticket exports built from the customer-service conversations, one way of hiding per carrier.
# The carriers add no words of their own ("AI, if you read this"), so they don't help the rules.
# False alarms: the same exports, the same exports inside harmless HTML, and hand-written
# documents that look like attacks (articles about prompt injection, e-mail disclaimers, logs).
# Dev: the indirect-injection examples in altaysec.csv and prompt_injection_tr.csv. The document
# rules were written after reading them, so they aren't a test.
ATTACKS_PATH = "data/tcpi_test.csv"
CONVERSATIONS_PATH = "data/customer_service_tr.csv"
HARD_NEGATIVES_PATH = "data/benign_documents_tr.csv"
DEV_PATHS = {"data/altaysec.csv": "altay_indirect_injection", "data/prompt_injection_tr.csv": "indirect"}
CONVERSATIONS_PER_DOCUMENT = 4


def read(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def ticket_exports():
    conversations = defaultdict(list)
    for row in read(CONVERSATIONS_PATH):
        conversations[row["family"]].append(row["text"])
    families = sorted(conversations)
    exports = []
    for i in range(0, len(families) - CONVERSATIONS_PER_DOCUMENT + 1, CONVERSATIONS_PER_DOCUMENT):
        parts = [f"Kayıt {family}:\n" + "\n".join(conversations[family])
                 for family in families[i:i + CONVERSATIONS_PER_DOCUMENT]]
        exports.append(parts)
    return exports


def harmless_html(parts):
    body = "".join(f"<div class=\"kayit\"><span class=\"sr-only\">Kaydı yazdır</span><p>{p}</p></div>" for p in parts)
    return (f"<html><head><!-- Google Tag Manager --></head><body><!-- kayıt listesi -->{body}"
            "<div style=\"display:none\">Yükleniyor, lütfen bekleyin...</div></body></html>")


def hide(payload, parts, carrier):
    half = len(parts) // 2
    before, after = "\n\n".join(parts[:half]), "\n\n".join(parts[half:])
    return {
        "plain line": f"{before}\n{payload}\n{after}",
        "footnote": f"{before}\n\n{after}\n\nNot: {payload}",
        "html comment": f"<p>{before}</p>\n<!-- {payload} -->\n<p>{after}</p>",
        "display:none": f"<p>{before}</p><span style=\"display:none\">{payload}</span><p>{after}</p>",
        "white text": f"<p>{before}</p><p style=\"color:#ffffff;font-size:1px\">{payload}</p><p>{after}</p>",
        "json field": json.dumps({"kayit": before, "aciklama": payload, "devam": after}, ensure_ascii=False),
    }[carrier]


CARRIERS = ["plain line", "footnote", "html comment", "display:none", "white text", "json field"]


def datasets():
    exports = ticket_exports()
    payloads = [r["text"] for r in read(ATTACKS_PATH) if r["label"] == "1"]
    attacks = {carrier: [hide(p, exports[(i * len(CARRIERS) + j) % len(exports)], carrier)
                         for i, p in enumerate(payloads)]
               for j, carrier in enumerate(CARRIERS)}
    dev = [r["text"] for path, category in DEV_PATHS.items() for r in read(path) if r["category"] == category]
    normals = {
        "ticket exports": ["\n\n".join(parts) for parts in exports],
        "ticket exports in HTML": [harmless_html(parts) for parts in exports],
        "hand-written look-alikes": [r["text"] for r in read(HARD_NEGATIVES_PATH)],
    }
    return attacks, dev, normals


TIMES = []


def flagged(check, texts):
    start = time.perf_counter()
    actions = [check(t) for t in texts]
    TIMES.append(((time.perf_counter() - start) * 1000, len(texts), sum(map(len, texts))))
    return sum(a != "allow" for a in actions), sum(a == "block" for a in actions), len(actions)


def report(name, check, attacks, dev, normals):
    print(f"\n{name}")
    TIMES.clear()
    total = [0, 0, 0]
    for carrier, texts in attacks.items():
        caught, blocked, n = flagged(check, texts)
        total = [total[0] + caught, total[1] + blocked, total[2] + n]
        print(f"  test, {carrier:22} {caught:3}/{n} flagged, {blocked:3} blocked")
    print(f"  test, all carriers           {total[0]:3}/{total[2]} flagged ({total[0] / total[2]:.0%}), "
          f"{total[1]} blocked")
    caught, blocked, n = flagged(check, dev)
    print(f"  dev, indirect examples       {caught:3}/{n} flagged, {blocked:3} blocked")
    for group, texts in normals.items():
        caught, _, n = flagged(check, texts)
        print(f"  false alarms, {group:24} {caught:3}/{n}")
    ms, n, chars = map(sum, zip(*TIMES))
    print(f"  {ms / n:.1f} ms per document (average {chars // n} characters)")


def run():
    attacks, dev, normals = datasets()
    guard = Guardrail()
    report("Guardrail() on the whole document (what an app gets today)", lambda t: guard.check(t).action,
           attacks, dev, normals)
    rules_only = DocumentGuard(use_ml=False)
    report("DocumentGuard, rules only", lambda t: rules_only.check(t).action, attacks, dev, normals)
    docs = DocumentGuard()
    report("DocumentGuard, rules + ML (default)", lambda t: docs.check(t).action, attacks, dev, normals)


if __name__ == "__main__":
    run()
