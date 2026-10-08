import hashlib
import json
import time
from pathlib import Path

from sieve.integrations.siem import pseudonym
from sieve.paths import LOGS
from sieve.pipeline import Guardrail

LOG_PATH = LOGS / "traffic.jsonl"


def message_id(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def to_record(result, session_id):
    return {
        "id": message_id(result.text),
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        # Keyed like the SIEM's (SIEVE_PSEUDONYM_KEY): a plain hash of a phone number or a customer number
        # used as the session ID can be reversed by hashing every candidate.
        "session": pseudonym(session_id, "traffic_log"),
        "text": result.text,
        "action": result.action,
        "findings": [
            {
                "check": f.check,
                "probability": round(float(f.probability), 4),
                "action": f.action,
                "matches": list(f.matches),
                "shadow": getattr(f, "shadow", False),
            }
            for f in result.findings
        ],
    }


# Only the masked text and a keyed pseudonym of the session ID are written to disk.
class LoggingGuardrail(Guardrail):
    def __init__(self, log_path=LOG_PATH, **kwargs):
        super().__init__(**kwargs)
        self.log_path = Path(log_path)

    def check(self, text, session_id="unknown"):
        result = super().check(text)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(to_record(result, session_id), ensure_ascii=False) + "\n")
        return result
