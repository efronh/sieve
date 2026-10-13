# The README's charts, as hand-written SVG (no plotting library), each in a light and a dark version: README shows
# the one that matches the reader's GitHub theme (<picture>). Colours are the reference data-viz palette, in its
# fixed order, checked for colour-blind separation and contrast in both modes; the light one's aqua and yellow are
# under 3:1 on the surface, so those charts carry direct labels and sit next to their table.
#   python -m scripts.charts    -> redraws results/family_comparison.svg and results/threshold_sweep.svg (and -dark)
#                                  from the saved results; compare_families.py and threshold_sweep.py draw them too
import json
from html import escape

from sieve.paths import RESULTS, ROOT

THEMES = {
    "light": {"surface": "#fcfcfb", "ink": "#0b0b0b", "secondary": "#52514e", "muted": "#898781", "grid": "#e1e0d9",
              "axis": "#c3c2b7", "series": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]},
    "dark": {"surface": "#1a1a19", "ink": "#ffffff", "secondary": "#c3c2b7", "muted": "#898781", "grid": "#2c2c2a",
             "axis": "#383835", "series": ["#3987e5", "#d95926", "#199e70", "#c98500"]},
}
FONT = 'system-ui, -apple-system, &quot;Segoe UI&quot;, sans-serif'
FAMILY_PATH, SWEEP_PATH = RESULTS / "family_comparison.svg", RESULTS / "threshold_sweep.svg"
# The threshold sweep's sets in the chart: the four in the README's table, so the table is the chart's text view.
SWEEP_SETS = {"cross_validation": "Cross-validation", "tcpi_test": "TCPI test split",
              "sealed_deepset": "Sealed deepset_tr", "corpus_documents": "Corpus documents"}


class Svg:
    def __init__(self, theme):
        self.theme, self.parts = theme, []

    def text(self, x, y, s, color="secondary", size=12, anchor="start", weight="normal"):
        self.parts.append(f'<text x="{x:.1f}" y="{y:.1f}" fill="{self.theme[color]}" font-size="{size}" '
                          f'text-anchor="{anchor}" font-weight="{weight}">{escape(s)}</text>')

    def line(self, x1, y1, x2, y2, color, width=1):
        self.parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
                          f'stroke-width="{width}" stroke-linecap="round"/>')

    def dot(self, x, y, color):
        self.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}" stroke="{self.theme["surface"]}" '
                          'stroke-width="2"/>')

    def polyline(self, points, color):
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        self.parts.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="2" '
                          'stroke-linejoin="round" stroke-linecap="round"/>')

    def key(self, x, y, color, label):
        self.dot(x + 5, y - 4, color)
        self.text(x + 15, y, label)

    def render(self, width, height, title):
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
                f'font-family="{FONT}" role="img" aria-label="{escape(title)}">\n'
                f'<title>{escape(title)}</title>\n<rect width="{width}" height="{height}" fill="{self.theme["surface"]}"/>\n'
                + "\n".join(self.parts) + "\n</svg>\n")


def save(path, draw):
    for mode, theme in THEMES.items():
        target = path if mode == "light" else path.with_name(f"{path.stem}-dark{path.suffix}")
        target.write_text(draw(theme), encoding="utf-8")


# Sieve and the baseline at Sieve's false-alarm rate, a dumbbell per family: two dots on one 0-100% scale.
def family_chart(families, path=FAMILY_PATH):
    rows, prefix = [], None
    for name, r in families.items():
        group = name.split("-")[0]
        rows.append((name, r["sieve"]["rate"], r["matched"]["rate"], group != prefix and prefix is not None))
        prefix = group
    left, plot_x, plot_w, top, step, gap = 16, 118, 540, 88, 20, 8
    height = top + len(rows) * step + gap * sum(new for *_, new in rows) + 44
    width = plot_x + plot_w + 24
    title = "Attacks caught, by family"

    def draw(theme):
        svg = Svg(theme)
        sieve, baseline = theme["series"][:2]
        svg.text(left, 26, title, color="ink", size=15, weight="600")
        svg.text(left, 46, "Test records. The baseline (protectai DeBERTa v3) set to flag as many normal records as Sieve does.")
        svg.key(left, 70, sieve, "Sieve")
        svg.key(left + 70, 70, baseline, "Baseline at Sieve's false-alarm rate")
        bottom = height - 44

        def x(rate):
            return plot_x + rate * plot_w

        for k in range(5):
            svg.line(x(k / 4), top - 8, x(k / 4), bottom, theme["grid"])
            svg.text(x(k / 4), bottom + 18, f"{k * 25}%", color="muted", anchor="middle")
        y = top
        for i, (name, ours, theirs, new_group) in enumerate(rows):
            y += gap if new_group else 0
            svg.text(plot_x - 12, y + 4, name, anchor="end")
            if theirs is None:
                svg.text(x(0) + 4, y + 4, "n/a: no normal chains to set it on", color="muted", size=11)
            else:
                svg.line(x(theirs), y, x(ours), y, theme["axis"], 2)
                svg.dot(x(theirs), y, baseline)
            svg.dot(x(ours), y, sieve)
            y += step
        return svg.render(width, height, title)

    save(path, draw)


def spread(wanted, gap):
    # Label positions as close to where they want to be as they can sit, gap apart, in the same order.
    order = sorted(range(len(wanted)), key=lambda i: wanted[i])
    placed = {}
    for i in order:
        placed[i] = max(wanted[i], max((placed[j] + gap for j in placed), default=wanted[i]))
    return [placed[i] for i in range(len(wanted))]


# Attacks caught and normal records flagged against the ML threshold, for the sets in the README's table.
def sweep_chart(sets, shipped, path=SWEEP_PATH):
    chosen = [(name, label, sets[name]) for name, label in SWEEP_SETS.items() if name in sets]
    left, top, width, height, gap, label_w = 56, 112, 330, 250, 70, 110
    total_w, total_h = left + 2 * width + gap + label_w + 24, top + height + 48
    title = "Moving the ML threshold"
    panels = (("Attacks caught", 1, "attacks", 1.0, 5), ("Normal records flagged (axis to 30%)", 2, "benign", 0.3, 6))

    def draw(theme):
        svg = Svg(theme)
        colors = {name: theme["series"][i] for i, (name, _, _) in enumerate(chosen)}
        svg.text(16, 26, title, color="ink", size=15, weight="600")
        svg.text(16, 46, "The default pipeline with [thresholds.prompt_injection_ml] moved; the other layers' flags stay.")
        key_x = 16
        for name, label, _ in chosen:
            svg.key(key_x, 70, colors[name], label)
            key_x += 22 + 7 * len(label)
        for i, (panel, column, of, y_top, ticks) in enumerate(panels):
            x0 = left + i * (width + gap + (label_w if i else 0))

            def x(t, x0=x0):
                return x0 + t * width

            def y(v, y_top=y_top):
                return top + height - min(v, y_top) / y_top * height

            svg.text(x0, top - 14, panel, color="ink", size=13, weight="600")
            for k in range(ticks + 1):
                v = y_top * k / ticks
                svg.line(x0, y(v), x0 + width, y(v), theme["grid"] if k else theme["axis"])
                svg.text(x0 - 6, y(v) + 4, f"{v:.0%}", color="muted", anchor="end")
            for t in (0, 0.2, 0.4, 0.6, 0.8, 1.0):
                svg.text(x(t), top + height + 18, f"{t:.1f}", color="muted", anchor="middle")
            svg.text(x0 + width / 2, top + height + 38, "ML threshold", color="muted", anchor="middle")
            svg.line(x(shipped), top, x(shipped), top + height, theme["secondary"])
            svg.text(x(shipped) + 4, top + 12, f"shipped {shipped:.2f}", color="secondary", size=11)
            ends = []
            for name, _, r in chosen:
                if r[of]:
                    points = [(x(p[0]), y(p[column] / r[of])) for p in r["curve"]]
                    svg.polyline(points, colors[name])
                    ends.append((name, points[-1]))
            if i == 0:  # direct labels at the right end of the attacks panel, nudged apart, with a leader line
                for (name, (ex, ey)), ly in zip(ends, spread([e[1][1] for e in ends], 15)):
                    svg.line(ex + 3, ey, ex + 12, ly, theme["axis"])
                    svg.text(ex + 15, ly + 4, SWEEP_SETS[name], size=11)
        return svg.render(total_w, total_h, title)

    save(path, draw)


def main():
    families = json.loads((RESULTS / "family_comparison.json").read_text(encoding="utf-8"))["families"]
    family_chart(families)
    sweep = json.loads((RESULTS / "threshold_sweep.json").read_text(encoding="utf-8"))
    sweep_chart(sweep["sets"], sweep["shipped_review_at"])
    for path in (FAMILY_PATH, SWEEP_PATH):
        print(f"wrote {path.relative_to(ROOT)} and its -dark version")


if __name__ == "__main__":
    main()
