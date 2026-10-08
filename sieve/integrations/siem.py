# One JSON/CEF event per decision. No raw text: hash of the masked text (same across
# tenants, usable as an IOC), pseudonymous ids, masked excerpt if the policy allows.
#   logging.getLogger("sieve.siem").addHandler(syslog_handler("siem.local", 514, "cef"))
import hashlib
import hmac
import itertools
import json
import logging
import logging.handlers
import math
import os
import re
import socket
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

from sieve.actions import ACTION_ORDER, ALLOW
from sieve.masking import LABEL_NAMES
from sieve.pipeline import mask
from sieve.rules import rule_ids, rule_info

# 2: instance, seq, checked and request_id; in CEF suser, deviceExternalId, cn1-cn2, flexString1-2 and msg.
SCHEMA_VERSION = 2
PRODUCT = "sieve"
EXCERPT_CHARS = 200
PSEUDONYM_KEY_ENV = "SIEVE_PSEUDONYM_KEY"
MASK_LABEL = re.compile(r"\[(" + "|".join(LABEL_NAMES) + r")\]")
CEF_SEVERITY = {ALLOW: 1, "review": 5, "block": 8}
# One per process: session limits and tool totals are kept per process, so the SIEM needs to know which one spoke.
INSTANCE = uuid.uuid4().hex[:12]
# Numbered per process. seq counts the events sent, so a gap in it is an event lost on the way: UDP drops one without
# a word, and Python's logging writes a handler's error to stderr and goes on. checked counts every decision, sent or
# not, so a block rate can be worked out with log_allowed = false.
SEQUENCE = itertools.count(1)
DECISIONS = itertools.count(1)
# An ID the app made up (a UUID) is kept as it is, so the app's own logs can be joined to the event.
SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
# Logging is synchronous: a check waits while its event is sent. A connect or a send to the collector gets this long,
# and after a connect that failed the next one waits this long, so a collector that's gone costs one wait, not one
# per event. For no wait at all, put a logging.handlers.QueueHandler in front.
SEND_TIMEOUT = 2.0
RETRY_AFTER = 30.0

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


def count_decision():
    return next(DECISIONS)


# Anything else as a pseudonym: an app might use an e-mail address, a phone number or a TC number as its request ID.
def request_ref(request_id, tenant):
    if request_id is None:
        return None
    value = str(request_id)
    return value if SAFE_REQUEST_ID.fullmatch(value) and mask(value) == value else pseudonym(value, tenant)


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


# checked: count_decision() for this decision. seq is set when the event is sent (emit).
def to_event(result, would_action, policy, *, original, session_id=None, user_id=None,
             direction="input", latency_ms=None, timings=None, request_id=None, checked=None):
    return {
        "schema": SCHEMA_VERSION,
        "product": PRODUCT,
        "event_id": str(uuid.uuid4()),
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "instance": INSTANCE,
        "seq": None,
        "checked": checked,
        "request_id": request_ref(request_id, policy.tenant),
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
        # Each stage of the check: masking, every layer by name, session, policy. Where the time went when
        # latency_ms is high.
        "timings_ms": {stage: round(ms, 3) for stage, ms in (timings or {}).items()} or None,
        "masked": masked_counts(original, result.text),
        "scores": {f.check: round(float(f.probability), 4) for f in result.findings},
        "rules": to_rule_records(result.findings),
        "excerpt": result.text[:EXCERPT_CHARS] if policy.log_excerpt else None,
    }


def emit(event):
    event["seq"] = next(SEQUENCE)
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
        "suser": event["user"],
        "deviceExternalId": event.get("instance"),
    }
    labelled = [("cn1", "seq", event.get("seq")), ("cn2", "checked", event.get("checked")),
                ("flexString1", "requestId", event.get("request_id")), ("flexString2", "mode", event["mode"])]
    for key, label, value in labelled:
        if value is not None:
            extension[f"{key}Label"], extension[key] = label, value
    # What the custom fields can't hold: which rules were only shadowed or suppressed, and a failed layer's detail.
    notes = [f"{flag}: {','.join(r['rule_id'] for r in rules if r[flag])}" for flag in ("shadow", "suppressed")
             if any(r[flag] for r in rules)]
    notes += [f"{r['rule_id']}: {r['detail']}" for r in rules if r["detail"]]
    if notes:
        extension["msg"] = "; ".join(notes)
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


# SysLogHandler over TCP, made to survive the collector. As it comes, it raises at start when the collector is down,
# keeps a broken connection for good (every later event lost), has no timeout, and like any handler only writes a
# failure to stderr. Here a failure is counted (failures) and said on the "sieve" logger, the 1st, 10th, 100th...
# time; a broken connection is dropped so the next event connects again.
class SiemHandler(logging.handlers.SysLogHandler):
    def __init__(self, *args, **kwargs):
        self.failures, self.warning, self.error, self.retry_at = 0, False, None, 0.0
        super().__init__(*args, **kwargs)
        if self.socket is None:  # the collector is down: the app starts anyway, and the first event tries again
            self.count_failure()

    def createSocket(self):
        if isinstance(self.address, str) or self.socktype != socket.SOCK_STREAM:
            return super().createSocket()
        self.unixsocket, self.socket = False, None
        if time.monotonic() < self.retry_at:
            return
        try:
            self.socket = socket.create_connection(self.address, timeout=SEND_TIMEOUT)
        except OSError as e:
            self.error, self.retry_at = e, time.monotonic() + RETRY_AFTER

    def handleError(self, record):
        if self.socktype == socket.SOCK_STREAM and self.socket is not None:
            self.socket.close()
            self.socket = None
        self.count_failure(sys.exc_info()[1])

    def count_failure(self, error=None):
        self.failures += 1
        if not isinstance(error, OSError):  # no socket to send on: why the connect failed
            error = self.error
        if self.warning or not math.log10(self.failures).is_integer():
            return
        self.warning = True  # this handler may be on the logger the warning goes to
        try:
            logging.getLogger("sieve").warning("sieve: SIEM delivery failed (%d so far): %s", self.failures,
                                               type(error).__name__ if error else "no connection")
        finally:
            self.warning = False


# TCP by default: over UDP a lost event leaves no trace but a gap in seq, and a large one can be cut off. Each event
# ends with a NUL byte (SysLogHandler's append_nul): over TCP the collector has to split on it.
def syslog_handler(host="localhost", port=514, fmt="cef", tcp=True):
    handler = SiemHandler(address=(host, port), socktype=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    handler.setFormatter(CefFormatter() if fmt == "cef" else JsonFormatter())
    return handler
