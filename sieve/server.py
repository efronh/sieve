# Sieve over HTTP: one JSON request per check, at each boundary the app crosses (docs/api.md).
#   SIEVE_API_KEY=... python -m sieve.server --tenant example_bank --system-prompt prompt.txt --port 8080
# Standard library only: no web framework to trust (THREAT_MODEL TH-13). One check runs at a time per process, since
# a tenant's session state isn't thread-safe; for more, run more processes, and know session limits are per process.
# A check that runs out of time is answered with block and logged (fail closed); it finishes in the background.
# --ui also serves a page at / to try checks, watch the decisions and read the evaluation (sieve/ui/, docs/api.md).
import argparse
import hmac
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as CheckTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sieve.actions import ALLOW, BLOCK
from sieve.integrations.siem import PSEUDONYM_KEY_ENV, JsonFormatter, syslog_handler
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.output import SAFE_REPLY
from sieve.paths import RESULTS
from sieve.rules import rule_ids, rule_info

API_KEY_ENV = "SIEVE_API_KEY"  # the app's key; "new,old" while the app moves to a new one
UI_KEY_ENV = "SIEVE_UI_KEY"  # the page's key: checks and stats, not the prompt, and its sessions are its own
MIN_KEY_CHARS = 32  # python -c "import secrets; print(secrets.token_urlsafe(32))" gives 43
APP, UI = "app", "ui"
UI_PREFIX = "ui:"  # session and user IDs from the page's key, so they never reach an app user's limits or history
LOOPBACK = ("127.0.0.1", "localhost", "::1")
MAX_BODY = 1_000_000  # bytes: a document is read up to 200,000 characters
CHECK_TIMEOUT = 5.0  # s a check may take before the answer is block
MAX_PENDING = 64  # requests waiting or running; past it, 503 and the app's own fail-closed path
SOCKET_TIMEOUT = 10  # s for a client to send its request, so a slow one can't hold a thread

logger = logging.getLogger("sieve.server")

WHO = {"session_id": str, "user_id": str, "request_id": str}
OPTIONAL = WHO | {"detail": bool}  # detail: every finding with its score and rules, and the time each stage took
# path -> (required fields, optional fields), each with its type.
ENDPOINTS = {
    "/v1/check": ({"text": str}, OPTIONAL),
    "/v1/document": ({"text": str}, OPTIONAL | {"source": str}),
    "/v1/tool": ({"name": str, "args": dict}, OPTIONAL | {"user_data": list}),
    "/v1/output": ({"answer": str}, OPTIONAL | {"user_data": list}),
}
DIRECTIONS = {"/v1/check": "input", "/v1/document": "document", "/v1/tool": "tool", "/v1/output": "output"}
UI_DIR = Path(__file__).parent / "ui"
# What --ui serves without a key: a fixed list, so no path reaches any other file. The page holds no data; what it
# shows comes from the API with the key, and from results/, which is in the repository anyway.
UI_FILES = {"/": (UI_DIR / "index.html", "text/html; charset=utf-8"),
            "/ui/app.js": (UI_DIR / "app.js", "text/javascript; charset=utf-8"),
            "/ui/app.css": (UI_DIR / "app.css", "text/css; charset=utf-8")}
UI_FILES |= {f"/ui/{name}": (RESULTS / name, "image/svg+xml") for name in
             ("family_comparison.svg", "family_comparison-dark.svg", "threshold_sweep.svg", "threshold_sweep-dark.svg")}
# Nothing but the server's own files, no inline script, no framing: the page shows attack text, as text.
UI_HEADERS = {"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                                         "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
              "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}


class BadRequest(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code = status, code


# Names the field, never echoes the value: a message can hold personal data.
def validate(body, required, optional):
    if not isinstance(body, dict):
        raise BadRequest(400, "bad_request", "the body must be a JSON object")
    for name in body:
        if name not in required and name not in optional:
            raise BadRequest(400, "bad_request", f"unknown field {name!r}")
    for name, kind in required.items():
        if name not in body:
            raise BadRequest(400, "bad_request", f"missing field {name!r}")
    for name, kind in (required | optional).items():
        value = body.get(name)
        if name in body and (not isinstance(value, kind) or isinstance(value, bool) and kind is not bool):
            raise BadRequest(400, "bad_request", f"field {name!r} must be {kind.__name__}")
    if "user_data" in body and not all(isinstance(t, str) for t in body["user_data"]):
        raise BadRequest(400, "bad_request", "field 'user_data' must be a list of strings")
    return body


def flagged_rules(findings):
    return sorted({rule_id for f in findings if f.action != ALLOW for rule_id, _ in rule_ids(f)})


# With "detail": true, what each layer reported (allowed findings too, for the ML score) and how long each stage took.
# A layer that found nothing names no rule.
def detail(result):
    findings = [{"check": f.check, "score": round(float(f.probability), 4), "action": f.action,
                 "rules": [{"rule": rule_id, "title": rule_info(rule_id).title, "detail": extra}
                           for rule_id, extra in rule_ids(f)] if f.matches or f.action != ALLOW else []}
                for f in result.findings]
    return {"findings": findings, "timings_ms": {k: round(v, 3) for k, v in (result.timings or {}).items()}}


# What the server has decided since it started, for GET /v1/stats: counts, the rules that fired, the last decisions.
# No text, no user, session or request ID: the SIEM is where decisions are kept and joined.
class Stats:
    RECENT = 50

    def __init__(self, clock=time.time):
        self.clock, self.started = clock, clock()
        self.lock = threading.Lock()
        self.decisions, self.rules, self.timeouts = Counter(), Counter(), 0
        self.recent = deque(maxlen=self.RECENT)
        self.refused, self.warned_at = 0, None

    # A request with a missing or wrong key. Counted, and logged at most once a minute; never locked out, since that
    # would let anyone lock the app out with wrong keys, and a key of 32 random characters can't be guessed anyway.
    def refuse(self):
        with self.lock:
            self.refused += 1
            now = time.monotonic()
            if self.warned_at is None or now - self.warned_at >= 60:
                self.warned_at = now
                logger.warning("sieve: %d requests with a missing or wrong key so far", self.refused)

    def record(self, direction, action, rules, ms, timed_out=False):
        with self.lock:
            self.decisions[direction, action] += 1
            self.rules.update(rules)
            self.timeouts += timed_out
            self.recent.appendleft({"at": round(self.clock()), "direction": direction, "action": action,
                                    "rules": rules, "ms": round(ms, 1)})

    def snapshot(self):
        with self.lock:
            return {"since": round(self.started), "timeouts": self.timeouts, "refused": self.refused,
                    "decisions": [{"direction": d, "action": a, "count": n} for (d, a), n in sorted(self.decisions.items())],
                    "rules": [{"rule": r, "title": rule_info(r).title, "count": n} for r, n in self.rules.most_common(20)],
                    "recent": list(self.recent)}


# The evaluation's headline numbers from results/, for the page's evaluation tab: summaries only, never a record.
def evaluation(directory=RESULTS):
    def read(name):
        try:
            return json.loads((directory / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    out = {}
    if holdout := read("holdout.json"):
        out["sealed"] = {source: {k: r[k] for k in ("attacks", "flagged", "benign", "false_alarms", "blocked")}
                         for source, r in holdout["summary"].items()}
    if families := read("family_comparison.json"):
        out["families"] = {name: {"sieve": r["sieve"]["rate"], "baseline": r["matched"]["rate"],
                                  "shipped": r["shipped"]["rate"], "records": r["records"]}
                           for name, r in families["families"].items()}
        out["false_alarms"] = {entry: {key: r[key]["rate"] for key in ("sieve", "matched", "shipped")} | {"of": r["sieve"]["of"]}
                               for entry, r in families["false_alarms"].items()}
    if models := read("compare_models.json"):
        out["models"] = {name: {"recall": r["at_1pct"]["recall"], "holdout_recall": r["at_1pct"]["holdout_recall"],
                                "holdout_false_alarm": r["at_1pct"]["holdout_false_alarm"], "ms": r["latency_ms"]}
                         for name, r in models.items()}
    if latency := read("latency.json"):
        out["latency"] = {name: {"median": r["total"]["median"], "p99": r["total"]["p99"]}
                          for name, r in latency["summaries"].items()}
    if sweep := read("threshold_sweep.json"):
        out["shipped_threshold"] = sweep["shipped_review_at"]
    return out


class Service:
    # api_key: the app's key, or several while it moves to a new one; None runs without keys (local tests only).
    # ui_key: the page's own key, if any.
    def __init__(self, guard, api_key, check_timeout=CHECK_TIMEOUT, max_pending=MAX_PENDING, ui=False, ui_key=None):
        self.guard, self.ui = guard, ui
        self.app_keys = [k.encode() for k in ([api_key] if isinstance(api_key, str) else api_key or [])]
        self.ui_key = ui_key.encode() if ui_key else None
        self.check_timeout = check_timeout
        self.stats = Stats()
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sieve-check")
        self.slots = threading.BoundedSemaphore(max_pending)

    # Whose key the request carries: the app's, the page's, or nobody's (None, counted). Every key is compared, in
    # constant time, so how long it takes doesn't say which one was close.
    def role(self, header):
        if not self.app_keys:
            return APP
        scheme, _, token = (header or "").partition(" ")
        token = token.encode()
        app = any([hmac.compare_digest(token, key) for key in self.app_keys])
        ui = self.ui_key is not None and hmac.compare_digest(token, self.ui_key)
        if scheme == "Bearer" and (app or ui):
            return APP if app else UI
        self.stats.refuse()
        return None

    # Runs the check on the one worker, waiting at most check_timeout. A check that didn't finish is a failed check:
    # block, with a layer_error event that says timeout. One still queued is cancelled; one running finishes alone.
    def run(self, path, body):
        who = {k: body.get(k) for k in WHO}
        direction = DIRECTIONS[path]
        if direction == "input" and who["request_id"] is None:
            who["request_id"] = os.urandom(16).hex()
        start = time.perf_counter()
        future = self.worker.submit(self.check, path, body, who)
        try:
            answer, timed_out = future.result(timeout=self.check_timeout), False
        except CheckTimeout:
            future.cancel()
            failed = self.guard.failed(TimeoutError(), direction, who["session_id"], who["user_id"], who["request_id"],
                                       where="timeout")
            answer, timed_out = self.answer_failed(path, failed, who), True
        self.stats.record(direction, answer["action"], answer["rules"], (time.perf_counter() - start) * 1000, timed_out)
        return answer

    def check(self, path, body, who):
        guard = self.guard
        if path == "/v1/check":
            r = guard.check(body["text"], **who)
            # Nothing to send when it's blocked: an app that forgets to look at action has no text to pass on.
            text = "" if r.action == BLOCK else r.text
            answer = {"action": r.action, "text": text, "request_id": r.request_id, "rules": flagged_rules(r.findings)}
        elif path == "/v1/document":
            r = guard.check_document(body["text"], **who)
            wrapped = None if r.action == BLOCK else guard.wrap(body["text"], who["session_id"],
                                                                source=body.get("source", "belge"))
            answer = {"action": r.action, "wrapped": wrapped, "rules": flagged_rules(r.findings)}
        elif path == "/v1/tool":
            r = guard.check_tool(body["name"], body["args"], body.get("user_data"), **who)
            answer = {"action": r.action, "args": r.args, "reasons": r.reasons, "rules": flagged_rules(r.findings)}
        else:
            r = guard.check_output(body["answer"], body.get("user_data"), **who)
            answer = {"action": r.action, "text": r.text, "rules": flagged_rules(r.findings)}
        return answer | ({"detail": detail(r)} if body.get("detail") else {})

    @staticmethod
    def answer_failed(path, failed, who):
        rules = flagged_rules(failed.findings)
        return {
            "/v1/check": {"action": BLOCK, "text": "", "request_id": who["request_id"], "rules": rules},
            "/v1/document": {"action": BLOCK, "wrapped": None, "rules": rules},
            "/v1/tool": {"action": BLOCK, "args": None, "reasons": ["the check timed out"], "rules": rules},
            "/v1/output": {"action": BLOCK, "text": SAFE_REPLY, "rules": rules},
        }[path]

    def prompt(self):
        return {"system_prompt": self.guard.system_prompt, "document_instructions": self.guard.documents.instructions}

    def status(self):
        policy = self.guard.policy
        return {"tenant": policy.tenant, "policy_version": policy.version, "mode": policy.mode} | self.stats.snapshot()


class Handler(BaseHTTPRequestHandler):
    service = None  # set by make_server
    timeout = SOCKET_TIMEOUT
    server_version = "sieve"
    sys_version = ""

    def send_json(self, status, body, request_id=None):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if request_id:
            self.send_header("X-Request-ID", request_id)
        self.end_headers()
        self.wfile.write(data)

    def send_error_json(self, status, code, message, allow=None):
        data = json.dumps({"error": {"code": code, "message": message}}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path):
        file, content_type = UI_FILES[path]
        try:
            data = file.read_bytes()
        except OSError:
            return self.send_error_json(404, "not_found", "no such file")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        for name, value in UI_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # the request line, never a body or a query string
        logger.info("%s %s %s", self.command, self.path.split("?")[0], args[1] if len(args) > 1 else "")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send_json(200, {"status": "ok"})
        if self.service.ui and path in UI_FILES:
            return self.send_file(path)
        if self.service.ui and path == "/ui/results.json":
            return self.send_json(200, evaluation())
        if path in ENDPOINTS:
            return self.send_error_json(405, "method_not_allowed", "use POST", allow="POST")
        if path not in ("/v1/prompt", "/v1/stats"):
            return self.send_error_json(404, "not_found", "no such endpoint")
        role = self.service.role(self.headers.get("Authorization"))
        if role is None:
            return self.send_error_json(401, "unauthorized", "a valid API key is required")
        if path == "/v1/prompt" and role != APP:  # the prompt and its canary are the app's
            return self.send_error_json(403, "forbidden", "this key can't read the prompt")
        self.send_json(200, self.service.prompt() if path == "/v1/prompt" else self.service.status())

    def do_POST(self):
        path = self.path.split("?")[0]
        if path not in ENDPOINTS:
            allow = "GET" if path in ("/healthz", "/v1/prompt", "/v1/stats") else None
            return self.send_error_json(405 if allow else 404, "method_not_allowed" if allow else "not_found",
                                        "use GET" if allow else "no such endpoint", allow=allow)
        role = self.service.role(self.headers.get("Authorization"))
        if role is None:
            return self.send_error_json(401, "unauthorized", "a valid API key is required")
        try:
            body = validate(self.read_body(), *ENDPOINTS[path])
        except BadRequest as e:
            return self.send_error_json(e.status, e.code, str(e))
        if role == UI:
            body |= {k: UI_PREFIX + body[k] for k in ("session_id", "user_id") if body.get(k) is not None}
        if not self.service.slots.acquire(blocking=False):
            return self.send_error_json(503, "busy", "too many checks waiting; treat as block")
        try:
            answer = self.service.run(path, body)
        except Exception as e:  # the checks fail closed themselves; this is the server's own error
            logger.warning("sieve: request failed with %s", type(e).__name__)
            return self.send_error_json(500, "internal", "the check failed; treat as block")
        finally:
            self.service.slots.release()
        self.send_json(200, answer, answer.get("request_id"))

    def read_body(self):
        if self.headers.get_content_type() != "application/json":
            raise BadRequest(415, "unsupported_media_type", "send application/json")
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            raise BadRequest(411, "length_required", "send a Content-Length")
        if int(length) > MAX_BODY:
            raise BadRequest(413, "too_large", f"the body is limited to {MAX_BODY} bytes")
        try:
            return json.loads(self.rfile.read(int(length)).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BadRequest(400, "bad_json", "the body isn't valid UTF-8 JSON") from None


def make_server(guard, host="127.0.0.1", port=8080, api_key=None, check_timeout=CHECK_TIMEOUT, max_pending=MAX_PENDING,
                ui=False, ui_key=None):
    service = Service(guard, api_key, check_timeout, max_pending, ui, ui_key)
    handler = type("SieveHandler", (Handler,), {"service": service})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def siem_handler(target):
    if target == "stdout":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        return handler
    host, _, port = target.rpartition(":")
    return syslog_handler(host, int(port), "json")


# The keys from the environment, checked before anything listens. An error names the variable, never the key.
def keys(parser, insecure, host):
    app = [k.strip() for k in os.environ.get(API_KEY_ENV, "").split(",") if k.strip()]
    ui = os.environ.get(UI_KEY_ENV, "").strip() or None
    if insecure and host not in LOOPBACK:
        parser.error("--insecure-no-auth only listens on a loopback address (127.0.0.1, ::1)")
    if not app and not insecure:
        parser.error(f"set {API_KEY_ENV}, or pass --insecure-no-auth for a local test")
    for name, key in [(API_KEY_ENV, k) for k in app] + ([(UI_KEY_ENV, ui)] if ui else []):
        if len(key) < MIN_KEY_CHARS:
            parser.error(f"{name}: a key needs at least {MIN_KEY_CHARS} characters; make one with "
                         "python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    if ui and ui in app:
        parser.error(f"{UI_KEY_ENV} must differ from {API_KEY_ENV}: the page's key can't read the prompt")
    return app, ui


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m sieve.server")
    parser.add_argument("--tenant", default="default", help="policies/<tenant>.toml over policies/default.toml")
    parser.add_argument("--system-prompt", help="the operator's system prompt (a file); its canary is added")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=CHECK_TIMEOUT, help="seconds a check may take before block")
    parser.add_argument("--siem", default="stdout", help="stdout (JSON lines), host:port (syslog over TCP) or none")
    parser.add_argument("--insecure-no-auth", action="store_true", help="run without an API key (local tests only)")
    parser.add_argument("--ui", action="store_true", help="also serve a page at / to try checks and watch decisions")
    args = parser.parse_args(argv)

    app_keys, ui_key = keys(parser, args.insecure_no_auth, args.host)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s", stream=sys.stderr)
    events = logging.getLogger("sieve.siem")
    events.propagate = False
    events.setLevel(logging.INFO)
    events.handlers = [] if args.siem == "none" else [siem_handler(args.siem)]

    if not os.environ.get(PSEUDONYM_KEY_ENV):
        logger.warning("sieve: %s isn't set: user and session pseudonyms are keyed with the tenant name, which isn't "
                       "secret", PSEUDONYM_KEY_ENV)

    system_prompt = open(args.system_prompt, encoding="utf-8").read() if args.system_prompt else ""
    guard = TenantGuardrail(load_policy(args.tenant), system_prompt=system_prompt)
    if args.ui and app_keys and not ui_key:
        logger.warning("sieve: the page takes the app's key, which also reads the prompt; set %s to give it its own",
                       UI_KEY_ENV)
    server = make_server(guard, args.host, args.port, app_keys or None, args.timeout, ui=args.ui, ui_key=ui_key)
    # A service manager (systemd, Kubernetes, docker stop) stops it with SIGTERM: finish the check that's running and
    # exit cleanly. As PID 1 in a container there's no default handler at all, and it would be killed 10 seconds later.
    # shutdown() waits for serve_forever, so it can't run on that thread.
    signal.signal(signal.SIGTERM, lambda signum, frame: threading.Thread(target=server.shutdown).start())
    logger.info("sieve: serving tenant %r on %s:%d%s%s", args.tenant, args.host, server.server_address[1],
                "" if app_keys else " WITHOUT AUTHENTICATION", f", the page at http://{args.host}:{server.server_address[1]}/"
                if args.ui else "")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.RequestHandlerClass.service.worker.shutdown(wait=True, cancel_futures=True)  # the check running ends
        logger.info("sieve: stopped")


if __name__ == "__main__":
    main()
