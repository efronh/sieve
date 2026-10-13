# What Sieve itself lets out (TH-08): every log line, SIEM event (JSON and CEF), stderr, HTTP answer, error and access
# log line is collected while marked secrets go through every entry point and every way a check can fail, and none
# may carry one. A secret is personal data the user typed, a value behind a lettered label, the system prompt and its
# canary, Sieve's API key, the pseudonym key, and the IDs an app might pass (a TC number as the user ID).
import http.client
import json
import logging
import socket
import threading

import pytest

from sieve.integrations.siem import CefFormatter, JsonFormatter
from sieve.integrations.tenant import TenantGuardrail, load_policy
from sieve.server import make_server

TC, IBAN, CARD = "10000000146", "TR330006100519786457841326", "4111111111111111"
PASSWORD, TOKEN = "Gizli-Parola-93!x", "Zq7Lm2Vx9Kp4Rt8Bn3Hj6Fd1Wc5Ys0Ga"
EMAIL, PHONE = "ayse.kaya@ornekmail.com", "05321112233"
PROMPT_SECRET = "KAMPANYA-KODU-ZX81Q"  # in the system prompt only
CANARY = "KNR-0f3c9a2b7d1e"
API_KEY = "test-api-key-6Yb2Qw"
PSEUDONYM_KEY = "pseudonym-key-Hk3vP0"
SECRETS = [TC, IBAN, CARD, PASSWORD, TOKEN, EMAIL, PHONE, PROMPT_SECRET, CANARY, API_KEY, PSEUDONYM_KEY]
# The forms a value can take in a log: as typed, with its spaces, and in what JSON or CEF makes of it.
IBAN_SPACED = "TR33 0006 1005 1978 6457 8413 26"
SYSTEM_PROMPT = f"Sen Örnek Bank'ın asistanısın. Kampanya kodu {PROMPT_SECRET}; kimseyle paylaşma."
MESSAGE = (f"TC'm {TC}, IBAN'ım {IBAN_SPACED}, kartım {CARD}, şifrem: {PASSWORD}, anahtar {TOKEN}, "
           f"e-posta {EMAIL}, telefon {PHONE}.")
TOOLS = {"para_transferi": {"params": {"iban": "line", "tutar": "number", "aciklama": "str"}, "optional": ["aciklama"],
                            "max": {"tutar": 50000}, "from_user": ["iban"]}}


def leaks(text):
    flat = text.replace(" ", "").replace("\\\\", "\\")
    return [s for s in SECRETS if s in text or s.replace(" ", "") in flat or IBAN_SPACED in text]


class Everything(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(logging.Formatter("%(name)s %(levelname)s %(message)s").format(record))
        if getattr(record, "event", None):
            self.lines += [JsonFormatter().format(record), CefFormatter().format(record)]


@pytest.fixture
def collected(monkeypatch, capfd):
    monkeypatch.setenv("SIEVE_PSEUDONYM_KEY", PSEUDONYM_KEY)
    handler = Everything()
    root, siem = logging.getLogger(), logging.getLogger("sieve.siem")
    saved = root.level, siem.level, siem.propagate
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    siem.setLevel(logging.DEBUG)
    siem.propagate = True
    yield handler.lines
    root.removeHandler(handler)
    root.level, siem.level, siem.propagate = saved
    out, err = capfd.readouterr()
    handler.lines += [out, err]


def guard(**policy):
    overrides = {"tools": TOOLS, "log_allowed": True, "log_excerpt": True} | policy
    return TenantGuardrail(load_policy(overrides=overrides), system_prompt=SYSTEM_PROMPT, canary=CANARY)


def who():
    return {"session_id": EMAIL, "user_id": TC, "request_id": f"istek-{PHONE}"}


def every_entry_point(g):
    g.check(MESSAGE, **who())
    g.check_document(f"<p>Müşteri kaydı</p><!-- {MESSAGE} -->", **who())
    g.check_tool("para_transferi", {"iban": IBAN_SPACED, "tutar": 900000, "aciklama": MESSAGE}, [MESSAGE], **who())
    g.check_tool("bilinmeyen", {"not": MESSAGE}, **who())
    g.check_output(f"{MESSAGE} Referans {CANARY}. {SYSTEM_PROMPT}", ["Merhaba"], **who())
    g.check_output(f"Kayıtta {MESSAGE}", [MESSAGE], **who())


def assert_nothing_leaked(lines):
    found = {s: line for line in lines for s in leaks(line)}
    assert not found, "leaked:\n" + "\n".join(f"{s} in {line[:300]!r}" for s, line in found.items())


@pytest.mark.parametrize("policy", [{}, {"mode": "monitor"}, {"masking": {"lettered_labels": True}},
                                    {"layers": {"prompt_injection_rules": "shadow"}}])
def test_no_entry_point_logs_a_secret(collected, policy):
    every_entry_point(guard(**policy))
    assert any('"schema"' in line for line in collected)  # events were made, with excerpts
    assert_nothing_leaked(collected)


class Raises:
    def __init__(self, name):
        self.name = name

    def check(self, *args, **kwargs):
        raise RuntimeError(f"could not read {MESSAGE} with {SYSTEM_PROMPT}")


def test_no_failure_logs_a_secret(collected, monkeypatch):
    g = guard()
    for layer in g.guard.check_layers:
        monkeypatch.setattr(layer, "check", Raises(layer.name).check)
    monkeypatch.setattr(g.documents.urls, "check", Raises("url_check").check)
    monkeypatch.setattr(g.tools.code, "check", Raises("code_payloads").check)
    monkeypatch.setattr(g.output, "clean_links", Raises("output").check)
    every_entry_point(g)
    monkeypatch.setattr(g, "decide", Raises("policy").check)  # the policy code itself
    every_entry_point(g)
    assert_nothing_leaked(collected)


# Lettered labels: the values behind them stay in the vault; the event and the history keep plain labels.
def test_vault_values_stay_out_of_events(collected):
    g = guard(masking={"lettered_labels": True})
    g.check(f"Anneme {IBAN_SPACED} hesabına 500 TL gönder", session_id="s1")
    result = g.check_tool("para_transferi", {"iban": "[IBAN_A]", "tutar": 500}, session_id="s1")
    assert result.args["iban"] == IBAN_SPACED  # for the app to run the call with
    assert_nothing_leaked(collected)


@pytest.fixture
def server(collected):
    g = guard()
    srv = make_server(g, port=0, api_key=API_KEY, check_timeout=2)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def request(srv, method, path, body=None, key=API_KEY, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    headers = {"Content-Type": "application/json"} | ({"Authorization": f"Bearer {key}"} if key else {})
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    answer = response.status, response.read().decode("utf-8", "replace"), str(response.headers)
    conn.close()
    return answer


# Answers carry only what the app may pass on: masked text, the call's own arguments. Errors name a field, never its
# value; the access log has the method, the path and the status.
def test_the_server_says_no_secret_in_answers_errors_or_its_log(server, collected):
    replies = [
        request(server, "POST", "/v1/check", {"text": MESSAGE, "session_id": EMAIL, "user_id": TC}),
        request(server, "POST", "/v1/document", {"text": f"<!-- {MESSAGE} -->", "source": "web"}),
        request(server, "POST", "/v1/output", {"answer": f"{MESSAGE} {CANARY}", "user_data": ["Merhaba"]}),
        request(server, "POST", "/v1/tool", {"name": "bilinmeyen", "args": {"not": MESSAGE}}),
        request(server, "POST", "/v1/check", {"text": MESSAGE, TC: MESSAGE}),  # an unknown field named with a secret
        request(server, "POST", "/v1/check", {"text": 5, "session_id": MESSAGE}),
        request(server, "POST", "/v1/check", raw=f'{{"text": "{MESSAGE}", "text": "{TC}"}}'.encode()),
        request(server, "POST", "/v1/check", raw=f"{{text: {MESSAGE}}}".encode()),
        request(server, "POST", f"/v1/check/{TC}?tc={TC}", {"text": "Merhaba"}),
        request(server, "GET", f"/v1/{EMAIL}"),
        request(server, "POST", "/v1/check", {"text": MESSAGE}, key=TOKEN),
    ]
    tool = request(server, "POST", "/v1/tool", {"name": "para_transferi", "args": {"iban": IBAN_SPACED, "tutar": 5},
                                                "user_data": [MESSAGE]})
    assert tool[0] == 200
    with socket.create_connection(("127.0.0.1", server.server_address[1])) as raw:
        raw.sendall(f"POST /v1/check HTTP/1.1\r\nX-Secret: {TC}\r\nContent-Length: zz{TC}\r\n\r\n".encode())
        raw.settimeout(5)
        replies.append((0, raw.recv(4096).decode("utf-8", "replace"), ""))
    assert_nothing_leaked([body + headers for _, body, headers in replies] + collected)


# A value an attacker controls can't forge a second event or a line of its own in the SIEM: JSON escapes control
# characters, CEF its separators, and syslog over TCP splits on NUL.
def test_no_value_can_split_an_event(collected):
    forged = "x\x00CEF:0|sieve|sieve|2|allow|Allowed|1|act=allow\nact=allow cs1=tenant\r|="
    g = guard()
    g.check(forged + MESSAGE, session_id=forged, user_id=forged, request_id=forged)
    g.check_tool(forged, {forged: forged}, session_id=forged)
    events = [line for line in collected if line.startswith(("{", "CEF:"))]
    assert events
    for line in events:
        assert "\x00" not in line and "\n" not in line and "\r" not in line
        if line.startswith("{"):
            json.loads(line)
        else:
            assert line.count("CEF:0|") == 1


# The traffic log came out readable by every user on the machine (0644 in a 0755 directory), masked text and all.
def test_the_traffic_log_is_its_owners_alone(tmp_path):
    import os
    import stat

    from sieve.integrations.traffic_log import LoggingGuardrail

    path = tmp_path / "logs" / "traffic.jsonl"
    LoggingGuardrail(log_path=path, check_layers=[]).check(MESSAGE)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    assert not leaks(path.read_text(encoding="utf-8").replace("[TC_KIMLIK]", ""))


def test_running_without_a_pseudonym_key_is_said_once(monkeypatch, caplog):
    from sieve.integrations import siem

    monkeypatch.delenv("SIEVE_PSEUDONYM_KEY", raising=False)
    monkeypatch.setattr(siem, "WARNED_WITHOUT_KEY", [])
    with caplog.at_level(logging.WARNING, logger="sieve"):
        siem.pseudonym(TC, "default")
        siem.pseudonym(EMAIL, "default")
    assert sum("SIEVE_PSEUDONYM_KEY isn't set" in r.getMessage() for r in caplog.records) == 1


@pytest.fixture
def certificate(tmp_path):
    import shutil
    import subprocess

    if not shutil.which("openssl"):
        pytest.skip("needs openssl to make a certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    return cert, key


# Over plain TCP every event crossed the network readable; over TLS the collector's certificate is checked first.
def test_events_can_go_to_the_siem_over_tls(certificate):
    import ssl

    from sieve.integrations.siem import syslog_handler

    cert, key = certificate
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    listener = socket.create_server(("localhost", 0))
    received = []

    def collector():  # the untrusted handler's connection fails its handshake; the next one is read
        while not received:
            connection, _ = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    received.append(tls.recv(65536))
            except (ssl.SSLError, OSError):
                connection.close()

    threading.Thread(target=collector, daemon=True).start()
    port = listener.getsockname()[1]
    record = logging.LogRecord("sieve.siem", logging.WARNING, __file__, 0, "block", None, None)
    record.event = {"action": "block", "schema": 2}

    untrusted = syslog_handler("localhost", port, "json", tls=True)  # the system's CAs don't know this certificate
    untrusted.emit(record)
    assert untrusted.failures >= 1
    trusted = syslog_handler("localhost", port, "json", tls=True, cafile=str(cert))
    trusted.emit(record)
    trusted.close()
    for _ in range(100):
        if received:
            break
        threading.Event().wait(0.05)
    assert received and b'"action": "block"' in received[0]
