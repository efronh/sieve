# The version comparison's table: every version gets a row, and what a version's run didn't produce is a dash, not a
# crash or a zero (an older version may not run a newer script all the way).
from scripts.benchmark_versions import markdown

FULL = {
    "commit": "96259a2", "subject": "Add a CI security job",
    "entries": {"guardrail": {"attacks": 10, "flagged": 8, "benign": 5, "false_alarms": 0, "recall": 0.8, "fpr": 0.0},
                "tool": {"attacks": 4, "flagged": 4, "benign": 0, "false_alarms": 0, "recall": 1.0, "fpr": None}},
    "holdout": {"all": {"recall": 0.68, "fpr": 0.021, "f1": 0.80}, "deepset_tr": {"recall": 0.45}},
    "bypass": {"encoding": {"total": 100, "lost": 12}},
    "latency": {"normal messages": {"median": 0.53, "p95": 0.9}},
    "steps": {"replay": {"peak_mb": 210.0, "cpu_seconds": 20.0},
              "startup": {"peak_mb": 160.0, "cpu_seconds": 1.0, "import_s": 0.4, "build_s": 0.3, "ready_mb": 160.0}},
}
EMPTY = {"commit": "3085fc1", "subject": "Before", "entries": {}, "holdout": {}, "bypass": {}, "latency": {},
         "steps": {"startup": {"peak_mb": 150.0, "cpu_seconds": 1.0}}}


def test_every_version_gets_a_row_and_a_missing_number_is_a_dash():
    table = markdown([EMPTY, FULL], cascade=False)
    rows = [line for line in table.splitlines() if line.startswith("| `")]
    assert len(rows) == 6  # two versions in each of the three tables
    assert "| `3085fc1` Before | – | – | – | – | – | – | – |" in table
    assert "| 80% / 0% | – | 100% |" in table  # tool calls have no benign records here: recall alone
    assert "12 / 100" in table and "0.53 / 0.90" in table and "TF-IDF alone" in table
