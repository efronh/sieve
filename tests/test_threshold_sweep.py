import xml.etree.ElementTree as ET

from scripts.threshold_sweep import Scores, curve, plot

GRID = [0.1, 0.5, 0.9]
RECORDS = [  # (attack, ML score, flagged by another layer, blocked by another layer)
    (True, 0.95, False, False),
    (True, 0.2, True, True),
    (True, 0.6, False, False),
    (False, 0.55, False, False),
    (False, 0.05, True, False),
]


def test_other_layers_stay_flagged_and_the_ml_score_moves_the_rest():
    result = curve(RECORDS, GRID)
    assert (result["attacks"], result["benign"]) == (3, 2)
    assert result["other_layers"] == {"attacks": 1, "benign": 1, "attacks_blocked": 1, "benign_blocked": 0}
    by_threshold = {p[0]: p[1:] for p in result["curve"]}
    assert by_threshold[0.1] == [3, 2, 3, 1]  # the benign one another layer only flagged isn't blocked
    assert by_threshold[0.5] == [3, 2, 3, 1]
    assert by_threshold[0.9] == [2, 1, 2, 0]


def test_documents_get_no_block_columns():
    result = curve(RECORDS, GRID, blocks=False)
    assert all(p[3:] == [None, None] for p in result["curve"]) and "attacks_blocked" not in result["other_layers"]


class Fixed:
    def __init__(self, scores):
        self.scores = iter(scores)

    def probability(self, text):
        return next(self.scores)


def test_scores_keep_the_highest_per_record_and_decide_nothing():
    scores = Scores(Fixed([0.3, 0.8, 0.1]))
    assert scores.check("a") == [] and scores.check("b") == []
    assert scores.take() == 0.8
    scores.check("c")
    assert scores.take() == 0.1 and scores.take() == 0.0


def test_the_plot_is_svg_with_a_line_per_set_and_panel(tmp_path):
    sets = {"tcpi_test": curve(RECORDS, GRID), "customer_service": curve([r for r in RECORDS if not r[0]], GRID)}
    path = tmp_path / "sweep.svg"
    plot(sets, 0.5, path)
    lines = ET.parse(path).getroot().findall("{http://www.w3.org/2000/svg}polyline")
    assert len(lines) == 3  # no attacks panel line for a set without attacks
