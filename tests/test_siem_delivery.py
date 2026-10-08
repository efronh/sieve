# Delivery to the SIEM over TCP: a collector that's down, gone or broken loses events, but never the app, and never
# without a trace. Python's SysLogHandler raised at start, kept a broken connection for good, and only wrote its
# failures to stderr.
import logging
import socket

import pytest

from sieve.integrations import siem


@pytest.fixture
def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture
def send(request):
    logger = logging.getLogger(f"sieve.siem.test.{request.node.name}")
    logger.propagate, logger.level = False, logging.INFO

    def send_with(handler, event):
        logger.handlers = [handler]
        logger.warning("event", extra={"event": event})
    yield send_with
    logger.handlers = []


def received(server):
    conn, _ = server.accept()
    conn.settimeout(2)
    return conn.recv(4096)


class BrokenConnection:
    def sendall(self, data):
        raise BrokenPipeError

    def close(self):
        pass


def test_tcp_is_the_default_and_the_app_starts_with_the_collector_down(free_port, send, caplog):
    handler = siem.syslog_handler("127.0.0.1", free_port, "json")
    assert handler.socktype == socket.SOCK_STREAM and handler.socket is None and handler.failures == 1
    assert "SIEM delivery failed (1 so far): ConnectionRefusedError" in caplog.text


def test_failures_are_counted_and_said_now_and_then(free_port, send, caplog, monkeypatch):
    monkeypatch.setattr(siem, "RETRY_AFTER", 0.0)
    handler = siem.syslog_handler("127.0.0.1", free_port, "json")
    for i in range(11):
        send(handler, {"n": i})
    assert handler.failures == 12
    assert [r.getMessage().split(" so far")[0] for r in caplog.records if r.name == "sieve"] == \
        ["sieve: SIEM delivery failed (1", "sieve: SIEM delivery failed (10"]


def test_events_go_through_once_the_collector_is_up_and_after_a_broken_connection(free_port, send, monkeypatch):
    monkeypatch.setattr(siem, "RETRY_AFTER", 0.0)
    handler = siem.syslog_handler("127.0.0.1", free_port, "json")
    with socket.create_server(("127.0.0.1", free_port)) as server:
        server.settimeout(2)
        send(handler, {"n": "up"})
        assert received(server) == b'<12>{"n": "up"}\x00'

        handler.socket = BrokenConnection()  # the collector restarted: the old connection is dead
        send(handler, {"n": "lost"})
        send(handler, {"n": "again"})
        assert received(server) == b'<12>{"n": "again"}\x00' and handler.failures == 2


# A collector that's gone costs one wait per RETRY_AFTER, not one per event: logging blocks the check while it waits.
def test_after_a_failed_connect_events_dont_wait_on_another(free_port, send, monkeypatch):
    attempts = []
    connect = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: attempts.append(1) or connect(*args, **kwargs))
    handler = siem.syslog_handler("127.0.0.1", free_port, "json")
    for i in range(5):
        send(handler, {"n": i})
    assert attempts == [1] and handler.failures == 6


def test_udp_still_works_when_asked_for(free_port, send):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as collector:
        collector.bind(("127.0.0.1", free_port))
        collector.settimeout(2)
        handler = siem.syslog_handler("127.0.0.1", free_port, "json", tcp=False)
        send(handler, {"n": 1})
        assert collector.recv(4096) == b'<12>{"n": 1}\x00' and handler.failures == 0
