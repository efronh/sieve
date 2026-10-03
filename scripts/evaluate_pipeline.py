import csv

from sieve.checks.code_payloads import CodePayloadLayer
from sieve.checks.prompt_injection import PromptInjectionLayer
from sieve.checks.tampering import TamperingLayer
from sieve.checks.urls import URLCheckLayer
from sieve.ml.injection import MLInjectionLayer
from sieve.pipeline import Guardrail

# The whole Guardrail() as a user gets it, on the held-out set it was never trained on.
HOLDOUT_PATH = "data/tcpi_test.csv"


def load(path=HOLDOUT_PATH):
    with open(path, encoding="utf-8") as f:
        return [(r["text"], r["label"] == "1") for r in csv.DictReader(f)]


def rules():
    return [TamperingLayer(), PromptInjectionLayer(), CodePayloadLayer(), URLCheckLayer()]


def score(guard, rows):
    attacks = [guard.check(t).action for t, is_attack in rows if is_attack]
    normals = [guard.check(t).action for t, is_attack in rows if not is_attack]
    flagged = sum(a != "allow" for a in attacks)
    return {
        "flagged": f"{flagged}/{len(attacks)} ({flagged / len(attacks):.0%})",
        "blocked": f"{sum(a == 'block' for a in attacks)}/{len(attacks)}",
        "false_alarms": f"{sum(a != 'allow' for a in normals)}/{len(normals)}",
    }


def run():
    rows = load()
    setups = {
        "rules only (old default, ML in shadow)": Guardrail(check_layers=rules() + [MLInjectionLayer(shadow=True)]),
        "default (rules + ML review)": Guardrail(),
    }
    for name, guard in setups.items():
        print(f"{name:42} {score(guard, rows)}")


if __name__ == "__main__":
    run()
