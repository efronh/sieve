import xml.etree.ElementTree as ET

from scripts.charts import SWEEP_SETS, THEMES, family_chart, sweep_chart

NS = "{http://www.w3.org/2000/svg}"


def family(sieve, matched):
    return {"sieve": {"rate": sieve}, "matched": {"rate": matched}}


def parse(path):
    return ET.parse(path).getroot()


def test_the_family_chart_has_a_row_per_family_in_both_themes(tmp_path):
    families = {"PI-OVR": family(0.9, 0.1), "PI-ROLE": family(0.8, 0.0), "TOOL-CHAIN": family(1.0, None)}
    path = tmp_path / "families.svg"
    family_chart(families, path)
    for written in (path, tmp_path / "families-dark.svg"):
        root = parse(written)
        texts = [t.text for t in root.iter(f"{NS}text")]
        assert {"PI-OVR", "PI-ROLE", "TOOL-CHAIN"} <= set(texts)
        assert any(t.startswith("n/a") for t in texts)
        # two dots a row, one where the baseline has no threshold, and two in the legend
        assert len(list(root.iter(f"{NS}circle"))) == 2 + 2 + 1 + 2


def test_the_sweep_chart_draws_only_the_sets_in_the_readme_table(tmp_path):
    point = [[t, 5, 1, 4, 0] for t in (0.1, 0.5, 0.9)]
    sets = {name: {"attacks": 10, "benign": 10, "curve": point} for name in [*SWEEP_SETS, "customer_service"]}
    path = tmp_path / "sweep.svg"
    sweep_chart(sets, 0.76, path)
    root = parse(path)
    assert len(list(root.iter(f"{NS}polyline"))) == 2 * len(SWEEP_SETS)
    texts = [t.text for t in root.iter(f"{NS}text")]
    assert all(label in texts for label in SWEEP_SETS.values()) and "Customer service (in CV)" not in texts


def test_text_never_wears_a_series_colour(tmp_path):
    sets = {name: {"attacks": 10, "benign": 10, "curve": [[0.5, 5, 1, None, None]]} for name in SWEEP_SETS}
    sweep_chart(sets, 0.76, tmp_path / "sweep.svg")
    family_chart({"PI-OVR": family(0.9, 0.1)}, tmp_path / "families.svg")
    for mode, theme in THEMES.items():
        suffix = "" if mode == "light" else "-dark"
        for name in ("sweep", "families"):
            root = parse(tmp_path / f"{name}{suffix}.svg")
            assert not {t.get("fill") for t in root.iter(f"{NS}text")} & set(theme["series"])
