# One JSON/CEF event per decision. No raw text: hash of the masked text (same across
# tenants, usable as an IOC), pseudonymous ids, masked excerpt if the policy allows.
#   logging.getLogger("sieve.siem").addHandler(syslog_handler("siem.local", 514, "cef"))
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone

from sieve.actions import ACTION_ORDER, ALLOW
from sieve.masking import LABEL_NAMES
from sieve.rules import rule_ids, rule_info

SCHEMA_VERSION = 1
PRODUCT = "sieve"
EXCERPT_CHARS = 200
PSEUDONYM_KEY_ENV = "SIEVE_PSEUDONYM_KEY"
MASK_LABEL = re.compile(r"\[(" + "|".join(LABEL_NAMES) + r")\]")
CEF_SEVERITY = {ALLOW: 1, "review": 5, "block": 8}

logger = logging.getLogger("sieve.siem")


def message_hash(masked_text):
    return hashlib.sha256(masked_text.encode("utf-8")).hexdigest()[:16]


# Keyed hash, so a user ID (maybe a TC number) can't be brute-forced back.
# Set SIEVE_PSEUDONYM_KEY in production; without it the tenant name is the key.
def pseudonym(value, tenant):
    if value is None:
        return None
    key = os.environ.get(PSEUDONYM_KEY_ENV, "") + tenant
    return hmac.new(key.encode("utf-8"), str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]


# Labels the user typed themselves don't count.
def masked_counts(original, masked):
    added = Counter(MASK_LABEL.findall(masked)) - Counter(MASK_LABEL.findall(original))
    return dict(added)


def fired(finding):
    would = finding.would_action or ALLOW
    real_matches = [m for m in finding.matches if not m.startswith("would_")]
    return finding.action != ALLOW or would != ALLOW or bool(real_matches)


def to_rule_records(findings):
    records = []
    for f in findings:
        if not fired(f):
            continue
        for rule_id, detail in rule_ids(f):
            info = rule_info(rule_id)
            records.append({
                "rule_id": rule_id,
                "title": info.title,
                "owasp": info.owasp,
                "severity": info.severity,
                "layer": f.check,
                "score": round(float(f.probability), 4),
                "action": f.action,
                "would_action": f.would_action,
                "shadow": f.shadow,
                "suppressed": f.suppressed,
                "detail": detail,
            })
    return sorted(records, key=lambda r: -r["severity"])


def to_event(result, would_action, policy, *, original, session_id=None, user_id=None,
             direction="input", latency_ms=None):
    return {
        "schema": SCHEMA_VERSION,
        "product": PRODUCT,
        "event_id": str(uuid.uuid4()),
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "tenant": policy.tenant,
        "policy_version": policy.version,
        "mode": policy.mode,
        "direction": direction,
        "session": pseudonym(session_id, policy.tenant),
        "user": pseudonym(user_id, policy.tenant),
        "message_hash": message_hash(result.text),
        "action": result.action,
        "would_action": would_action,
        "latency_ms": None if latency_ms is None else round(latency_ms, 2),
        "masked": masked_counts(original, result.text),
        "scores": {f.check: round(float(f.probability), 4) for f in result.findings},
        "rules": to_rule_records(result.findings),
        "excerpt": result.text[:EXCERPT_CHARS] if policy.log_excerpt else None,
    }


def emit(event):
    level = logging.WARNING if ACTION_ORDER.get(event["would_action"], 0) > 0 else logging.INFO
    logger.log(level, event["action"], extra={"event": event})


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps(getattr(record, "event", {"message": record.getMessage()}), ensure_ascii=False)


def cef_header(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def cef_value(value):
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def to_cef(event):
    rules = event["rules"]
    top = rules[0] if rules else None
    severity = max([r["severity"] for r in rules], default=CEF_SEVERITY.get(event["would_action"], 1))
    extension = {
        "rt": int(datetime.fromisoformat(event["time"].replace("Z", "+00:00")).timestamp() * 1000),
        "act": event["action"],
        "outcome": event["would_action"],
        "externalId": event["message_hash"],
    }
    custom = [
        ("tenant", event["tenant"]),
        ("rules", ",".join(r["rule_id"] for r in rules)),
        ("session", event["session"]),
        ("owasp", ",".join(sorted({r["owasp"] for r in rules if r["owasp"]}))),
        ("policyVersion", event["policy_version"]),
        ("direction", event["direction"]),
    ]
    for i, (label, value) in enumerate(custom, start=1):
        if value:
            extension[f"cs{i}Label"] = label
            extension[f"cs{i}"] = value
    header = [
        "CEF:0", PRODUCT, PRODUCT, SCHEMA_VERSION,
        top["rule_id"] if top else "allow",
        top["title"] if top else "Allowed",
        severity,
    ]
    ext = " ".join(f"{k}={cef_value(v)}" for k, v in extension.items() if v not in (None, ""))
    return "|".join(cef_header(h) for h in header) + "|" + ext


class CefFormatter(logging.Formatter):
    def format(self, record):
        event = getattr(record, "event", None)
        return to_cef(event) if event else record.getMessage()


def syslog_handler(host="localhost", port=514, fmt="cef", tcp=False):
    import socket

    handler = logging.handlers.SysLogHandler(
        address=(host, port), socktype=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    handler.setFormatter(CefFormatter() if fmt == "cef" else JsonFormatter())
    return handler
