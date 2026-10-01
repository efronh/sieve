from pathlib import Path

# Repository root: models, data, policies, logs and results live next to the package.
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
MODELS = ROOT / "models"
POLICIES = ROOT / "policies"
LOGS = ROOT / "logs"
RESULTS = ROOT / "results"
