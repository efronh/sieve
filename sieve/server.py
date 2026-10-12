# Sieve over HTTP: one JSON request per check, at each boundary the app crosses (docs/api.md).
#   SIEVE_API_KEY=... python -m sieve.server --tenant example_bank --system-prompt prompt.txt --port 8080
# Standard library only: no web framework to trust (THREAT_MODEL TH-13). One check runs at a time per process, since
# a tenant's session state isn't thread-safe; for more, run more processes, and know session limits are per process.
# A check that runs out of time is answered with block and logged (fail closed); it finishes in the background.
import argparse
import hmac
import json
import logging
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as CheckTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sieve.actions import ALLOW, BLOCK
from sieve.integrations.siem import PSEUDONYM_KEY_ENV, JsonFormatter, syslog_handler
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.output import SAFE_REPLY
from sieve.rules import rule_ids

API_KEY_ENV = "SIEVE_API_KEY"
MAX_BODY = 1_000_000  # bytes: a document is read up to 200,000 characters
CHECK_TIMEOUT = 5.0  # s a check may take before the answer is block
MAX_PENDING = 64  # requests waiting or running; past it, 503 and the app's own fail-closed path
SOCKET_TIMEOUT = 10  # s for a client to send its request, so a slow one can't hold a thread

logger = logging.getLogger("sieve.server")

WHO = {"session_id": str, "user_id": str, "request_id": str}
# path -> (required fields, optional fields), each with its type.
ENDPOINTS = {
    "/v1/check": ({"text": str}, WHO),
    "/v1/document": ({"text": str}, WHO | {"source": str}),
    "/v1/tool": ({"name": str, "args": dict}, WHO | {"user_data": list}),
    "/v1/output": ({"answer": str}, WHO | {"user_data": list}),
}


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


class Service:
    def __init__(self, guard, api_key, check_timeout=CHECK_TIMEOUT, max_pending=MAX_PENDING):
        self.guard, self.api_key = guard, api_key
        self.check_timeout = check_timeout
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sieve-check")
        self.slots = threading.BoundedSemaphore(max_pending)

    def authorized(self, header):
        if self.api_key is None:
            return True
        scheme, _, token = (header or "").partition(" ")
        return scheme == "Bearer" and hmac.compare_digest(token.encode(), self.api_key.encode())

    # Runs the check on the one worker, waiting at most check_timeout. A check that didn't finish is a failed check:
    # block, with a layer_error event that says timeout. One still queued is cancelled; one running finishes alone.
    def run(self, path, body):
        who = {k: body.get(k) for k in WHO}
        direction = {"/v1/check": "input", "/v1/document": "document", "/v1/tool": "tool", "/v1/output": "output"}[path]
        if direction == "input" and who["request_id"] is None:
            who["request_id"] = os.urandom(16).hex()
        future = self.worker.submit(self.check, path, body, who)
        try:
            return future.result(timeout=self.check_timeout)
        except CheckTimeout:
            future.cancel()
            failed = self.guard.failed(TimeoutError(), direction, who["session_id"], who["user_id"], who["request_id"],
                                       where="timeout")
            return self.answer_failed(path, failed, who)

    def check(self, path, body, who):
        guard = self.guard
        if path == "/v1/check":
            r = guard.check(body["text"], **who)
            # Nothing to send when it's blocked: an app that forgets to look at action has no text to pass on.
            text = "" if r.action == BLOCK else r.text
            return {"action": r.action, "text": text, "request_id": r.request_id, "rules": flagged_rules(r.findings)}
        if path == "/v1/document":
            r = guard.check_document(body["text"], **who)
            wrapped = None if r.action == BLOCK else guard.wrap(body["text"], who["session_id"],
                                                                source=body.get("source", "belge"))
            return {"action": r.action, "wrapped": wrapped, "rules": flagged_rules(r.findings)}
        if path == "/v1/tool":
            r = guard.check_tool(body["name"], body["args"], body.get("user_data"), **who)
            return {"action": r.action, "args": r.args, "reasons": r.reasons, "rules": flagged_rules(r.findings)}
        r = guard.check_output(body["answer"], body.get("user_data"), **who)
        return {"action": r.action, "text": r.text, "rules": flagged_rules(r.findings)}

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

    def log_message(self, format, *args):  # the request line, never a body or a query string
        logger.info("%s %s %s", self.command, self.path.split("?")[0], args[1] if len(args) > 1 else "")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send_json(200, {"status": "ok"})
        if path in ENDPOINTS:
            return self.send_error_json(405, "method_not_allowed", "use POST", allow="POST")
        if path != "/v1/prompt":
            return self.send_error_json(404, "not_found", "no such endpoint")
        if not self.service.authorized(self.headers.get("Authorization")):
            return self.send_error_json(401, "unauthorized", "a valid API key is required")
        self.send_json(200, self.service.prompt())

    def do_POST(self):
        path = self.path.split("?")[0]
        if path not in ENDPOINTS:
            allow = "GET" if path in ("/healthz", "/v1/prompt") else None
            return self.send_error_json(405 if allow else 404, "method_not_allowed" if allow else "not_found",
                                        "use GET" if allow else "no such endpoint", allow=allow)
        if not self.service.authorized(self.headers.get("Authorization")):
            return self.send_error_json(401, "unauthorized", "a valid API key is required")
        try:
            body = validate(self.read_body(), *ENDPOINTS[path])
        except BadRequest as e:
            return self.send_error_json(e.status, e.code, str(e))
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


def make_server(guard, host="127.0.0.1", port=8080, api_key=None, check_timeout=CHECK_TIMEOUT, max_pending=MAX_PENDING):
    service = Service(guard, api_key, check_timeout, max_pending)
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m sieve.server")
    parser.add_argument("--tenant", default="default", help="policies/<tenant>.toml over policies/default.toml")
    parser.add_argument("--system-prompt", help="the operator's system prompt (a file); its canary is added")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=CHECK_TIMEOUT, help="seconds a check may take before block")
    parser.add_argument("--siem", default="stdout", help="stdout (JSON lines), host:port (syslog over TCP) or none")
    parser.add_argument("--insecure-no-auth", action="store_true", help="run without an API key (local tests only)")
    args = parser.parse_args(argv)

    api_key = os.environ.get(API_KEY_ENV)
    if not api_key and not args.insecure_no_auth:
        parser.error(f"set {API_KEY_ENV}, or pass --insecure-no-auth for a local test")
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
    server = make_server(guard, args.host, args.port, api_key or None, args.timeout)
    # A service manager (systemd, Kubernetes, docker stop) stops it with SIGTERM: finish the check that's running and
    # exit cleanly. As PID 1 in a container there's no default handler at all, and it would be killed 10 seconds later.
    # shutdown() waits for serve_forever, so it can't run on that thread.
    signal.signal(signal.SIGTERM, lambda signum, frame: threading.Thread(target=server.shutdown).start())
    logger.info("sieve: serving tenant %r on %s:%d%s", args.tenant, args.host, server.server_address[1],
                "" if api_key else " WITHOUT AUTHENTICATION")
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
