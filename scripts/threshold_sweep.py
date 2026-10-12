# What moving the ML layer's threshold does. A tenant moves it with [thresholds.prompt_injection_ml]: the policy then
# decides on the layer's score, TF-IDF's probability or, where TF-IDF was unsure and BERTurk ran, the average of the
# two. What the other layers flag stays flagged at any threshold.
# Each set runs once with the ML layer scoring but deciding nothing. A record is flagged at threshold t when another
# layer flagged it or its highest ML score is at least t, which is what the policy would do; blocked, the same with
# block_at = t. Documents get no block column: one whose hidden part is flagged is blocked at the layer's own
# threshold (docs/operations.md), not the policy's.
# Sets: the cross-validation the shipped threshold was chosen on (out-of-fold scores, train_injection.py's folds; the
# other layers run on the same messages), TCPI's test split, the sealed held-out set (counts only, per source; it's
# for reading, not for choosing a threshold, holdout/README.md), and the corpus's test records, messages and documents.
#   python -m scripts.threshold_sweep    -> results/threshold_sweep.json, results/threshold_sweep.svg (~5 min)
import json
import math
import sys
from html import escape

import numpy as np

from scripts.evaluate_pipeline import load as load_tcpi
from scripts.replay import ALLOW, BLOCK, config, expand, load, load_holdout, outcome, wilson
from scripts.train_injection import cross_validate_two_stages, load_rows
from sieve.documents import DocumentGuard
from sieve.ml.injection import EmbeddingStage, MLInjectionLayer
from sieve.paths import RESULTS, ROOT
from sieve.pipeline import Guardrail

RESULTS_PATH = RESULTS / "threshold_sweep.json"
PLOT_PATH = RESULTS / "threshold_sweep.svg"
GRID = [round(t, 2) for t in np.arange(0.01, 1.0, 0.01)] + [0.995, 0.999]
SHOWN = (0.3, 0.5, 0.6, 0.7, None, 0.8, 0.9, 0.95, 0.99)  # None: the shipped threshold
SEALED = {"sealed_close": ("pi1k", "patterns_tr"), "sealed_deepset": ("deepset_tr",), "sealed_user": ("user",)}
NAMES = {
    "cross_validation": "Cross-validation",
    "customer_service": "Customer service (in CV)",
    "tcpi_test": "TCPI test split",
    "sealed_close": "Sealed: pi1k + patterns_tr",
    "sealed_deepset": "Sealed: deepset_tr",
    "sealed_user": "Sealed: user",
    "corpus_messages": "Corpus test: messages",
    "corpus_documents": "Corpus test: documents",
}
COLORS = {"cross_validation": "#1f77b4", "customer_service": "#7f7f7f", "tcpi_test": "#2ca02c",
          "sealed_close": "#ff7f0e", "sealed_deepset": "#d62728", "sealed_user": "#bcbd22",
          "corpus_messages": "#9467bd", "corpus_documents": "#8c564b"}


# The shipped ML layer, scoring without deciding: the sweep decides afterwards.
class Scores:
    name = MLInjectionLayer.name

    def __init__(self, ml):
        self.ml = ml
        self.seen = []

    def check(self, text):
        self.seen.append(self.ml.probability(text))
        return []

    def take(self):
        top = max(self.seen, default=0.0)
        self.seen = []
        return top


# (attack, highest ML score, flagged by another layer, blocked by another layer) per record.
def through(check, scores, items):
    rows = []
    for text, attack in items:
        action, detected, _ = outcome(check(text))
        rows.append((attack, scores.take(), detected != ALLOW, action == BLOCK))
    return rows


def cross_validation(ml, others):
    rows = load_rows()
    p1, p2, _, _ = cross_validate_two_stages(rows, EmbeddingStage(encoder_name=ml.cascade["encoder"],
                                                                  prefix=ml.cascade["prefix"], cache=True))
    unsure = (p1 >= ml.cascade["low"]) & (p1 <= ml.cascade["high"])
    score = np.where(unsure, (p1 + p2) / 2, p1)
    found = [outcome(others.check(r.text).findings) for r in rows]
    records = [(r.label == 1, float(s), detected != ALLOW, action == BLOCK) for r, s, (action, detected, _) in
               zip(rows, score, found)]
    customer = [rec for r, rec in zip(rows, records) if r.category.startswith("customer") and r.label == 0]
    return records, customer


def curve(records, grid, blocks=True):
    attack = np.array([r[0] for r in records], dtype=bool)
    score = np.array([r[1] for r in records])
    other, other_block = np.array([r[2] for r in records], dtype=bool), np.array([r[3] for r in records], dtype=bool)
    points = []
    for t in grid:
        flagged, blocked = other | (score >= t), other_block | (score >= t)
        point = [t, int(flagged[attack].sum()), int(flagged[~attack].sum())]
        points.append(point + ([int(blocked[attack].sum()), int(blocked[~attack].sum())] if blocks else [None, None]))
    return {"attacks": int(attack.sum()), "benign": int((~attack).sum()),
            "other_layers": {"attacks": int(other[attack].sum()), "benign": int(other[~attack].sum())}
            | ({"attacks_blocked": int(other_block[attack].sum()), "benign_blocked": int(other_block[~attack].sum())}
               if blocks else {}),
            "curve": points}


def at(result, t):
    return next(p for p in result["curve"] if p[0] == t)


def percent(k, n):
    if not n:
        return "-"
    low, high = wilson(k, n)
    return f"{k / n:4.0%} ({low:.0%}-{high:.0%})"


def report(sets, shipped):
    for name, result in sets.items():
        other = result["other_layers"]
        blocked = f", block {other['attacks_blocked']} and {other['benign_blocked']}" if "attacks_blocked" in other else ""
        print(f"\n{NAMES[name]}: {result['attacks']} attacks, {result['benign']} normal; other layers alone flag "
              f"{other['attacks']} and {other['benign']}{blocked}")
        print(f"  {'threshold':>9}   {'attacks flagged':>18}   {'normal flagged':>18}   {'attacks blocked':>16}   "
              f"{'normal blocked':>16}")
        for t in [shipped if t is None else t for t in SHOWN]:
            _, a, b, ab, bb = at(result, t)
            mark = " (shipped)" if t == shipped else ""
            blocked = (f"{percent(ab, result['attacks']):>16}   {percent(bb, result['benign']):>16}" if ab is not None
                       else "")
            print(f"  {t:9.2f}   {percent(a, result['attacks']):>18}   {percent(b, result['benign']):>18}   {blocked}{mark}")


def svg_line(points, x, y, color, dash=""):
    path = " ".join(f"{x(t):.1f},{y(v):.1f}" for t, v in points)
    return f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="1.8"{dash}/>'


# Two panels against the threshold: attacks flagged, normal records flagged (cut at 30%, where documents and the
# look-alike messages go past it, so the messages' few percent stay readable). Hand-written SVG, no plotting library.
def plot(sets, shipped, path=PLOT_PATH):
    left, top, width, height, gap = 60, 44, 380, 260, 90
    panels = (("Attacks flagged", 1, "attacks", 1.0, 5), ("Normal records flagged", 2, "benign", 0.3, 6))
    legend_rows = math.ceil(len(sets) / 4)
    total_w, total_h = left + 2 * width + gap + 50, top + height + 50 + legend_rows * 20
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" '
           f'viewBox="0 0 {total_w} {total_h}" font-family="Helvetica, Arial, sans-serif" font-size="12">',
           f'<rect width="{total_w}" height="{total_h}" fill="#ffffff"/>']
    for i, (title, column, of, y_top, ticks) in enumerate(panels):
        x0 = left + i * (width + gap)

        def x(t, x0=x0):
            return x0 + t * width

        def y(v, y_top=y_top):
            return top + height - v / y_top * height

        out.append(f'<text x="{x0}" y="{top - 16}" font-size="14" font-weight="bold" fill="#222">{title}</text>')
        for k in range(ticks + 1):
            v = y_top * k / ticks
            out.append(f'<line x1="{x0}" y1="{y(v):.1f}" x2="{x0 + width}" y2="{y(v):.1f}" stroke="#e5e5e5"/>')
            out.append(f'<text x="{x0 - 6}" y="{y(v) + 4:.1f}" text-anchor="end" fill="#555">{v:.0%}</text>')
        for t in (0, 0.2, 0.4, 0.6, 0.8, 1.0):
            out.append(f'<text x="{x(t):.1f}" y="{top + height + 16}" text-anchor="middle" fill="#555">{t:.1f}</text>')
        out.append(f'<text x="{x0 + width / 2}" y="{top + height + 34}" text-anchor="middle" fill="#333">'
                   'ML threshold</text>')
        out.append(f'<line x1="{x(shipped):.1f}" y1="{top}" x2="{x(shipped):.1f}" y2="{top + height}" stroke="#333" '
                   'stroke-dasharray="4 3"/>')
        out.append(f'<text x="{x(shipped):.1f}" y="{top - 4}" text-anchor="middle" fill="#333">shipped {shipped:.2f}</text>')
        out.append(f'<rect x="{x0}" y="{top}" width="{width}" height="{height}" fill="none" stroke="#999"/>')
        for name, r in sets.items():
            if r[of]:
                points = [(p[0], min(p[column] / r[of], y_top)) for p in r["curve"]]
                out.append(svg_line(points, x, y, COLORS[name]))
    for i, name in enumerate(sets):
        lx, ly = left + (i % 4) * 235, top + height + 60 + (i // 4) * 20
        out.append(f'<line x1="{lx}" y1="{ly - 4}" x2="{lx + 22}" y2="{ly - 4}" stroke="{COLORS[name]}" '
                   'stroke-width="2.5"/>')
        out.append(f'<text x="{lx + 30}" y="{ly}" fill="#222">{escape(NAMES[name])}</text>')
    out.append("</svg>")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main():
    guard = Guardrail(cache_size=0)
    ml = next((layer for layer in guard.check_layers if layer.name == MLInjectionLayer.name), None)
    if ml is None or not ml.cascade:
        sys.exit("needs the ML model with its BERTurk stage (sentence-transformers installed, SIEVE_CASCADE not 0)")
    scores = Scores(ml)
    others = Guardrail(cache_size=0, check_layers=[layer for layer in guard.check_layers if layer is not ml])
    guard.check_layers = [scores if layer is ml else layer for layer in guard.check_layers]
    documents = DocumentGuard(ml_layer=scores)

    def message(text):
        return guard.check(text).findings

    def document(text):
        return documents.check(text).findings

    shipped = ml.review_at  # exact: a score just above it is flagged
    grid = sorted(set(GRID) | {shipped})
    sets = {}
    records, customer = cross_validation(ml, others)
    sets["cross_validation"], sets["customer_service"] = curve(records, grid), curve(customer, grid)
    sets["tcpi_test"] = curve(through(message, scores, load_tcpi()), grid)
    holdout = load_holdout()
    for name, sources in SEALED.items():
        mine = [(r["text"], r["label"] == "attack") for r in holdout if r["source"] in sources]
        if mine:
            sets[name] = curve(through(message, scores, mine), grid)
    cases = [c for c in expand([r for r in load() if r["split"] == "test"]) if c["split"] == "test"]
    for name, entry, check, blocks in (("corpus_messages", "guardrail", message, True),
                                       ("corpus_documents", "document", document, False)):
        mine = [(c["text"], c["family"] != "BEN") for c in cases if c["entry"] == entry]
        sets[name] = curve(through(check, scores, mine), grid, blocks)

    report(sets, shipped)
    plot(sets, shipped)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"sieve": config(ml), "shipped_review_at": shipped, "cascade_band": [ml.cascade["low"], ml.cascade["high"]],
                   "columns": ["threshold", "attacks_flagged", "benign_flagged", "attacks_blocked", "benign_blocked"],
                   "sets": {name: {"what": NAMES[name]} | result for name, result in sets.items()}},
                  f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"\nwrote {RESULTS_PATH.relative_to(ROOT)}, {PLOT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
